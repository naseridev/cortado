use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cortado::config::ProxyConfig;
use cortado::socks;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn proxy_for(addr: SocketAddr) -> ProxyConfig {
    ProxyConfig {
        addr,
        username: None,
        password: None,
        connect_timeout: Duration::from_secs(10),
        tcp_nodelay: true,
    }
}

async fn handle_connect(mut stream: TcpStream, echo: bool) {
    let mut head = [0u8; 2];
    if stream.read_exact(&mut head).await.is_err() {
        return;
    }
    let mut methods = vec![0u8; head[1] as usize];
    let _ = stream.read_exact(&mut methods).await;
    let _ = stream.write_all(&[0x05, 0x00]).await;

    let mut req = [0u8; 4];
    if stream.read_exact(&mut req).await.is_err() {
        return;
    }
    let skip = match req[3] {
        0x01 => 6,
        0x04 => 18,
        _ => return,
    };
    let mut rest = vec![0u8; skip];
    let _ = stream.read_exact(&mut rest).await;
    let _ = stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await;

    if echo {
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

async fn spawn_mock(echo: bool, accepted: Arc<AtomicU64>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    accepted.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(handle_connect(stream, echo));
                }
                Err(_) => return,
            }
        }
    });
    addr
}

#[tokio::test]
async fn high_connection_count() {
    let accepted = Arc::new(AtomicU64::new(0));
    let addr = spawn_mock(true, Arc::clone(&accepted)).await;
    let proxy = Arc::new(proxy_for(addr));
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let mut handles = Vec::new();
    for i in 0..200u32 {
        let proxy = Arc::clone(&proxy);
        handles.push(tokio::spawn(async move {
            let mut stream = socks::tcp_connect(&proxy, target).await.unwrap();
            let payload = i.to_be_bytes();
            stream.write_all(&payload).await.unwrap();
            let mut got = [0u8; 4];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, payload);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(accepted.load(Ordering::Relaxed), 200);
}

#[tokio::test]
async fn rapid_connect_disconnect() {
    let accepted = Arc::new(AtomicU64::new(0));
    let addr = spawn_mock(true, Arc::clone(&accepted)).await;
    let proxy = Arc::new(proxy_for(addr));
    let target: SocketAddr = "10.1.2.3:443".parse().unwrap();

    for _ in 0..300u32 {
        let stream = socks::tcp_connect(&proxy, target).await.unwrap();
        drop(stream);
    }
    assert_eq!(accepted.load(Ordering::Relaxed), 300);
}

#[tokio::test]
async fn connect_failure_then_recovery() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let proxy_dead = proxy_for(dead_addr);
    let target: SocketAddr = "1.1.1.1:53".parse().unwrap();
    assert!(socks::tcp_connect(&proxy_dead, target).await.is_err());

    let accepted = Arc::new(AtomicU64::new(0));
    let good = spawn_mock(true, Arc::clone(&accepted)).await;
    let proxy_good = proxy_for(good);
    let mut stream = socks::tcp_connect(&proxy_good, target).await.unwrap();
    stream.write_all(b"ok").await.unwrap();
    let mut got = [0u8; 2];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ok");
}

#[tokio::test]
async fn handshake_rejection_is_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 2];
        let _ = stream.read_exact(&mut head).await;
        let mut methods = vec![0u8; head[1] as usize];
        let _ = stream.read_exact(&mut methods).await;
        let _ = stream.write_all(&[0x05, 0xFF]).await;
        let _ = stream.shutdown().await;
    });

    let proxy = proxy_for(addr);
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    assert!(socks::tcp_connect(&proxy, target).await.is_err());
}

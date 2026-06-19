use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cortado::config::ProxyConfig;
use cortado::dns::DnsPool;
use criterion::{Criterion, criterion_group, criterion_main};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

async fn mock_socks_dns(listener: TcpListener) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        tokio::spawn(async move {
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
            loop {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                if stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                let mut resp = Vec::with_capacity(len + 2);
                resp.extend_from_slice(&(len as u16).to_be_bytes());
                resp.extend_from_slice(&body);
                if stream.write_all(&resp).await.is_err() {
                    return;
                }
            }
        });
    }
}

fn dns_query(id: u16) -> Vec<u8> {
    let mut m = vec![0u8; 32];
    m[0..2].copy_from_slice(&id.to_be_bytes());
    m
}

fn bench_pooled_resolve(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let (pool, server) = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(mock_socks_dns(listener));
        let proxy = Arc::new(ProxyConfig {
            addr: proxy_addr,
            username: None,
            password: None,
            connect_timeout: Duration::from_secs(5),
            tcp_nodelay: true,
        });
        let pool = Arc::new(DnsPool::new(
            proxy,
            Duration::from_secs(5),
            Duration::from_secs(60),
        ));
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        pool.resolve(server, &dns_query(1)).await.unwrap();
        (pool, server)
    });

    let mut group = c.benchmark_group("dns");
    group.bench_function("pooled_resolve_sequential", |b| {
        b.to_async(&rt).iter(|| {
            let pool = Arc::clone(&pool);
            async move {
                let q = dns_query(7);
                pool.resolve(server, &q).await.unwrap();
            }
        });
    });
    group.bench_function("pooled_resolve_concurrent_16", |b| {
        b.to_async(&rt).iter(|| {
            let pool = Arc::clone(&pool);
            async move {
                let mut handles = Vec::with_capacity(16);
                for i in 0..16u16 {
                    let pool = Arc::clone(&pool);
                    handles.push(tokio::spawn(async move {
                        pool.resolve(server, &dns_query(i)).await.unwrap();
                    }));
                }
                for h in handles {
                    h.await.unwrap();
                }
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_pooled_resolve);
criterion_main!(benches);

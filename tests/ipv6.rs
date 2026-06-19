use std::net::SocketAddr;
use std::time::Duration;

use cortado::config::ProxyConfig;
use cortado::net::{RouteDecision, RouteTable};
use cortado::socks;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn proxy_for(addr: SocketAddr) -> ProxyConfig {
    ProxyConfig {
        addr,
        username: None,
        password: None,
        connect_timeout: Duration::from_secs(5),
        tcp_nodelay: true,
    }
}

async fn read_greeting(stream: &mut TcpStream) {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x05);
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await.unwrap();
    stream.write_all(&[0x05, 0x00]).await.unwrap();
}

async fn read_request(stream: &mut TcpStream) -> (u8, u8, SocketAddr) {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x05);
    let cmd = head[1];
    let atyp = head[3];
    let addr: SocketAddr = match atyp {
        0x01 => {
            let mut a = [0u8; 6];
            stream.read_exact(&mut a).await.unwrap();
            let ip = std::net::Ipv4Addr::new(a[0], a[1], a[2], a[3]);
            SocketAddr::new(ip.into(), u16::from_be_bytes([a[4], a[5]]))
        }
        0x04 => {
            let mut a = [0u8; 18];
            stream.read_exact(&mut a).await.unwrap();
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&a[0..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            SocketAddr::new(ip.into(), u16::from_be_bytes([a[16], a[17]]))
        }
        other => panic!("unexpected atyp {other}"),
    };
    (cmd, atyp, addr)
}

fn write_reply(buf: &mut Vec<u8>, bind: SocketAddr) {
    buf.extend_from_slice(&[0x05, 0x00, 0x00]);
    match bind {
        SocketAddr::V4(v4) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.ip().octets());
        }
    }
    buf.extend_from_slice(&bind.port().to_be_bytes());
}

#[tokio::test]
async fn tcp_connect_to_ipv6_destination() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let target: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_greeting(&mut stream).await;
        let (cmd, atyp, got) = read_request(&mut stream).await;
        assert_eq!(cmd, 0x01);
        assert_eq!(atyp, 0x04);
        assert_eq!(got, target);
        let mut reply = Vec::new();
        write_reply(&mut reply, "[::]:0".parse().unwrap());
        stream.write_all(&reply).await.unwrap();
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte[0], 0x7e);
    });

    let proxy = proxy_for(proxy_addr);
    let mut stream = socks::tcp_connect(&proxy, target).await.unwrap();
    stream.write_all(&[0x7e]).await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn udp_associate_relays_ipv6_datagram() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let relay = UdpSocket::bind("[::1]:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let target: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_greeting(&mut stream).await;
        let (cmd, _, _) = read_request(&mut stream).await;
        assert_eq!(cmd, 0x03);
        let mut reply = Vec::new();
        write_reply(&mut reply, relay_addr);
        stream.write_all(&reply).await.unwrap();

        let mut buf = [0u8; 1024];
        let (n, peer) = relay.recv_from(&mut buf).await.unwrap();
        let (got, payload) = socks::decode_udp(&buf[..n]).expect("valid udp request");
        assert_eq!(got, target);
        assert_eq!(payload, b"aaaa-query");

        let mut response = Vec::new();
        socks::encode_udp(target, b"aaaa-answer", &mut response);
        relay.send_to(&response, peer).await.unwrap();
        let mut hold = [0u8; 1];
        let _ = stream.read(&mut hold).await;
    });

    let proxy = proxy_for(proxy_addr);
    let (_control, relay_endpoint) = socks::udp_associate(&proxy).await.unwrap();
    assert!(relay_endpoint.is_ipv6());

    let client = UdpSocket::bind("[::]:0").await.unwrap();
    client.connect(relay_endpoint).await.unwrap();
    let mut req = Vec::new();
    socks::encode_udp(target, b"aaaa-query", &mut req);
    client.send(&req).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let (from, data) = socks::decode_udp(&buf[..n]).expect("valid udp response");
    assert_eq!(from, target);
    assert_eq!(data, b"aaaa-answer");

    drop(_control);
    let _ = server.await;
}

#[tokio::test]
async fn ipv6_proxy_with_ipv4_destination() {
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    assert!(proxy_addr.is_ipv6());
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_greeting(&mut stream).await;
        let (cmd, atyp, got) = read_request(&mut stream).await;
        assert_eq!(cmd, 0x01);
        assert_eq!(atyp, 0x01);
        assert_eq!(got, target);
        let mut reply = Vec::new();
        write_reply(&mut reply, "0.0.0.0:0".parse().unwrap());
        stream.write_all(&reply).await.unwrap();
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte[0], 0x33);
    });

    let proxy = proxy_for(proxy_addr);
    let mut stream = socks::tcp_connect(&proxy, target).await.unwrap();
    stream.write_all(&[0x33]).await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn dual_stack_route_classification() {
    let v4: std::net::IpAddr = "10.0.0.0".parse().unwrap();
    let v6: std::net::IpAddr = "fd00::".parse().unwrap();
    let table = RouteTable::new([(v4, 8), (v6, 8)]);
    assert_eq!(
        table.decide("10.1.2.3".parse().unwrap()),
        RouteDecision::Direct
    );
    assert_eq!(
        table.decide("fd00::1".parse().unwrap()),
        RouteDecision::Direct
    );
    assert_eq!(
        table.decide("8.8.8.8".parse().unwrap()),
        RouteDecision::Proxy
    );
    assert_eq!(
        table.decide("2606:4700:4700::1111".parse().unwrap()),
        RouteDecision::Proxy
    );
}

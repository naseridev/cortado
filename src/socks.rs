use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, Result, bail};
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_socks::tcp::Socks5Stream;

use crate::config::ProxyConfig;

const SOCKET_BUF_BYTES: usize = 512 * 1024;

fn tune_socket(stream: &TcpStream) {
    let sock = SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(SOCKET_BUF_BYTES);
    let _ = sock.set_send_buffer_size(SOCKET_BUF_BYTES);
}

pub async fn tcp_connect(proxy: &ProxyConfig, target: SocketAddr) -> Result<TcpStream> {
    let stream: TcpStream = match (&proxy.username, &proxy.password) {
        (Some(user), Some(pass)) => timeout(
            proxy.connect_timeout,
            Socks5Stream::connect_with_password(proxy.addr, target, user.as_str(), pass.as_str()),
        )
        .await
        .context("SOCKS5 authenticated connect timed out")?
        .context("SOCKS5 authenticated connect failed")?
        .into_inner(),
        _ => timeout(
            proxy.connect_timeout,
            Socks5Stream::connect(proxy.addr, target),
        )
        .await
        .context("SOCKS5 connect timed out")?
        .context("SOCKS5 connect failed")?
        .into_inner(),
    };

    if proxy.tcp_nodelay {
        stream
            .set_nodelay(true)
            .context("failed to set TCP_NODELAY on outbound socket")?;
    }
    tune_socket(&stream);
    Ok(stream)
}

async fn negotiate_auth(stream: &mut TcpStream, proxy: &ProxyConfig) -> Result<()> {
    let offer: &[u8] = if proxy.username.is_some() {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream
        .write_all(offer)
        .await
        .context("failed to send SOCKS5 method selection")?;

    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .context("failed to read SOCKS5 method selection reply")?;
    if resp[0] != 0x05 {
        bail!("invalid SOCKS5 version in method reply: {}", resp[0]);
    }

    match resp[1] {
        0x00 => Ok(()),
        0x02 => {
            let user = proxy
                .username
                .as_ref()
                .context("proxy requires username/password authentication")?;
            let pass = proxy
                .password
                .as_ref()
                .context("proxy requires username/password authentication")?;
            let mut buf = Vec::with_capacity(3 + user.len() + pass.len());
            buf.push(0x01);
            buf.push(user.len() as u8);
            buf.extend_from_slice(user.as_bytes());
            buf.push(pass.len() as u8);
            buf.extend_from_slice(pass.as_bytes());
            stream
                .write_all(&buf)
                .await
                .context("failed to send SOCKS5 credentials")?;
            let mut auth_resp = [0u8; 2];
            stream
                .read_exact(&mut auth_resp)
                .await
                .context("failed to read SOCKS5 auth reply")?;
            if auth_resp[1] != 0x00 {
                bail!("SOCKS5 authentication rejected by proxy");
            }
            Ok(())
        }
        0xFF => bail!("SOCKS5 proxy offered no acceptable authentication method"),
        other => bail!("SOCKS5 proxy selected unsupported auth method {}", other),
    }
}

async fn read_bind_address(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .context("failed to read SOCKS5 reply header")?;
    if head[0] != 0x05 {
        bail!("invalid SOCKS5 version in reply: {}", head[0]);
    }
    if head[1] != 0x00 {
        bail!("SOCKS5 request failed with reply code {}", head[1]);
    }

    let ip = match head[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream
                .read_exact(&mut octets)
                .await
                .context("failed to read SOCKS5 IPv4 bind address")?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream
                .read_exact(&mut octets)
                .await
                .context("failed to read SOCKS5 IPv6 bind address")?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .context("failed to read SOCKS5 domain length")?;
            let mut domain = vec![0u8; len[0] as usize];
            stream
                .read_exact(&mut domain)
                .await
                .context("failed to read SOCKS5 domain bind address")?;
            bail!("SOCKS5 proxy returned a domain bind address which is not supported for UDP");
        }
        other => bail!("SOCKS5 reply used unsupported address type {}", other),
    };

    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .context("failed to read SOCKS5 bind port")?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

fn normalize_relay(reply: SocketAddr, proxy: SocketAddr) -> SocketAddr {
    let unspecified = match reply.ip() {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    };
    if unspecified {
        SocketAddr::new(proxy.ip(), reply.port())
    } else {
        reply
    }
}

pub async fn udp_associate(proxy: &ProxyConfig) -> Result<(TcpStream, SocketAddr)> {
    let mut control = timeout(proxy.connect_timeout, TcpStream::connect(proxy.addr))
        .await
        .context("timed out connecting to SOCKS5 proxy for UDP associate")?
        .context("failed to connect to SOCKS5 proxy for UDP associate")?;
    control.set_nodelay(true).ok();

    timeout(proxy.connect_timeout, negotiate_auth(&mut control, proxy))
        .await
        .context("SOCKS5 UDP associate handshake timed out")??;

    let request = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    control
        .write_all(&request)
        .await
        .context("failed to send SOCKS5 UDP associate request")?;

    let reply = timeout(proxy.connect_timeout, read_bind_address(&mut control))
        .await
        .context("SOCKS5 UDP associate reply timed out")??;
    let relay = normalize_relay(reply, proxy.addr);
    Ok((control, relay))
}

pub fn encode_udp(target: SocketAddr, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.push(0x00);
    out.push(0x00);
    out.push(0x00);
    match target.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    out.extend_from_slice(payload);
}

pub fn decode_udp(buf: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    if buf[2] != 0x00 {
        return None;
    }
    let (ip, rest) = match buf[3] {
        0x01 => {
            if buf.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            (IpAddr::V4(ip), &buf[8..])
        }
        0x04 => {
            if buf.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            (IpAddr::V6(Ipv6Addr::from(octets)), &buf[20..])
        }
        _ => return None,
    };
    if rest.len() < 2 {
        return None;
    }
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Some((SocketAddr::new(ip, port), &rest[2..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn encode_decode_v4_roundtrip() {
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let payload = b"hello world";
        let mut buf = Vec::new();
        encode_udp(target, payload, &mut buf);
        assert_eq!(buf[0..3], [0, 0, 0]);
        assert_eq!(buf[3], 0x01);
        let (addr, data) = decode_udp(&buf).expect("decodes");
        assert_eq!(addr, target);
        assert_eq!(data, payload);
    }

    #[test]
    fn encode_decode_v6_roundtrip() {
        let target: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
        let payload = b"dual stack";
        let mut buf = Vec::new();
        encode_udp(target, payload, &mut buf);
        assert_eq!(buf[3], 0x04);
        let (addr, data) = decode_udp(&buf).expect("decodes");
        assert_eq!(addr, target);
        assert_eq!(data, payload);
    }

    #[test]
    fn encode_reuses_buffer() {
        let mut buf = Vec::new();
        encode_udp("1.1.1.1:53".parse().unwrap(), b"aaaa", &mut buf);
        let first_len = buf.len();
        encode_udp("1.1.1.1:53".parse().unwrap(), b"bb", &mut buf);
        assert!(buf.len() < first_len);
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(decode_udp(&[]).is_none());
        assert!(decode_udp(&[0, 0, 0]).is_none());
        assert!(decode_udp(&[0, 0, 0, 0x01, 1, 2, 3]).is_none());
        assert!(decode_udp(&[0, 0, 0, 0x04, 0, 0]).is_none());
    }

    #[test]
    fn decode_rejects_fragmented() {
        let frag = [0, 0, 0x01, 0x01, 8, 8, 8, 8, 0, 53];
        assert!(decode_udp(&frag).is_none());
    }

    #[test]
    fn decode_rejects_unknown_atyp() {
        let bad = [0, 0, 0, 0x09, 1, 2, 3, 4, 0, 53];
        assert!(decode_udp(&bad).is_none());
    }

    #[test]
    fn normalize_relay_substitutes_unspecified() {
        let proxy: SocketAddr = "203.0.113.5:1080".parse().unwrap();
        let reply: SocketAddr = "0.0.0.0:40000".parse().unwrap();
        let relay = normalize_relay(reply, proxy);
        assert_eq!(relay, "203.0.113.5:40000".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn normalize_relay_keeps_concrete() {
        let proxy: SocketAddr = "203.0.113.5:1080".parse().unwrap();
        let reply: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        assert_eq!(normalize_relay(reply, proxy), reply);
    }
}

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::logging::Logger;
use crate::stats;

fn metric(out: &mut String, name: &str, help: &str, kind: &str, value: u64) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

pub fn render() -> String {
    let mut out = String::with_capacity(2048);
    let counters: [(&str, &str, &stats::AtomicU64); 17] = [
        (
            "cortado_tcp_opened_total",
            "TCP connections opened",
            &stats::TCP_OPENED,
        ),
        (
            "cortado_tcp_closed_total",
            "TCP connections closed",
            &stats::TCP_CLOSED,
        ),
        (
            "cortado_tcp_errors_total",
            "TCP relay errors",
            &stats::TCP_ERRORS,
        ),
        (
            "cortado_udp_packets_total",
            "UDP packets ingested",
            &stats::UDP_PACKETS,
        ),
        (
            "cortado_udp_errors_total",
            "UDP relay errors",
            &stats::UDP_ERRORS,
        ),
        (
            "cortado_bytes_tx_total",
            "Bytes sent to proxy",
            &stats::BYTES_TX,
        ),
        (
            "cortado_bytes_rx_total",
            "Bytes received from proxy",
            &stats::BYTES_RX,
        ),
        (
            "cortado_bytes_ipv4_total",
            "Bytes relayed for IPv4 destinations",
            &stats::BYTES_V4,
        ),
        (
            "cortado_bytes_ipv6_total",
            "Bytes relayed for IPv6 destinations",
            &stats::BYTES_V6,
        ),
        (
            "cortado_dns_requests_total",
            "DNS requests handled",
            &stats::DNS_REQUESTS,
        ),
        (
            "cortado_dns_failures_total",
            "DNS requests that failed",
            &stats::DNS_FAILURES,
        ),
        (
            "cortado_dns_pool_hits_total",
            "DNS queries served by a reused connection",
            &stats::DNS_POOL_HITS,
        ),
        (
            "cortado_dns_pool_misses_total",
            "DNS queries that opened a new connection",
            &stats::DNS_POOL_MISSES,
        ),
        (
            "cortado_route_direct_total",
            "Flows classified as direct",
            &stats::ROUTE_DIRECT,
        ),
        (
            "cortado_route_proxy_total",
            "Flows classified as proxied",
            &stats::ROUTE_PROXY,
        ),
        (
            "cortado_conn_failures_total",
            "Outbound connection failures",
            &stats::CONN_FAILURES,
        ),
        (
            "cortado_socks_handshake_failures_total",
            "SOCKS5 handshake failures",
            &stats::SOCKS_HANDSHAKE_FAILURES,
        ),
    ];
    for (name, help, counter) in counters {
        metric(&mut out, name, help, "counter", stats::get(counter));
    }

    metric(
        &mut out,
        "cortado_config_reloads_total",
        "Configuration reloads applied",
        "counter",
        stats::get(&stats::CONFIG_RELOADS),
    );

    let gauges: [(&str, &str, &stats::AtomicU64); 2] = [
        (
            "cortado_tcp_sessions_active",
            "Active TCP sessions",
            &stats::TCP_ACTIVE,
        ),
        (
            "cortado_udp_sessions_active",
            "Active UDP sessions",
            &stats::UDP_ACTIVE,
        ),
    ];
    for (name, help, gauge) in gauges {
        metric(&mut out, name, help, "gauge", stats::get(gauge));
    }
    out
}

async fn handle_client(mut stream: tokio::net::TcpStream) {
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await;
    let body = render();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

pub async fn serve(addr: SocketAddr, log: Arc<Logger>) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            log.error(format!("failed to bind metrics endpoint {addr}: {e}"));
            return;
        }
    };
    log.info(format!("metrics endpoint listening on {addr}"));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_client(stream));
            }
            Err(e) => {
                log.warn(format!("metrics accept error: {e}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_all_metrics() {
        let text = render();
        for name in [
            "cortado_tcp_opened_total",
            "cortado_tcp_closed_total",
            "cortado_tcp_errors_total",
            "cortado_udp_packets_total",
            "cortado_udp_errors_total",
            "cortado_bytes_tx_total",
            "cortado_bytes_rx_total",
            "cortado_bytes_ipv4_total",
            "cortado_bytes_ipv6_total",
            "cortado_dns_requests_total",
            "cortado_dns_failures_total",
            "cortado_route_direct_total",
            "cortado_route_proxy_total",
            "cortado_conn_failures_total",
            "cortado_socks_handshake_failures_total",
            "cortado_tcp_sessions_active",
            "cortado_udp_sessions_active",
            "cortado_config_reloads_total",
        ] {
            assert!(text.contains(name), "missing metric {name}");
        }
        assert!(text.contains("# TYPE cortado_tcp_opened_total counter"));
        assert!(text.contains("# TYPE cortado_tcp_sessions_active gauge"));
    }

    #[test]
    fn gauges_reflect_active_sessions() {
        let before = render();
        assert!(before.contains("cortado_tcp_sessions_active"));
        let _g = stats::GaugeGuard::new(&stats::TCP_ACTIVE);
        let during = render();
        let line = during
            .lines()
            .find(|l| l.starts_with("cortado_tcp_sessions_active "))
            .unwrap();
        let value: u64 = line.rsplit(' ').next().unwrap().parse().unwrap();
        assert!(value >= 1);
    }
}

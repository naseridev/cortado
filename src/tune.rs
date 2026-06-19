use std::time::Duration;

const FALLBACK_MTU: u32 = 1500;
const MIN_MTU: u32 = 576;
const MAX_MTU: u32 = 65535;

const DEFAULT_MEMORY: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_FD_LIMIT: u64 = 1024;

const RELAY_BUF_PER_MTU: usize = 176;
const RELAY_BUF_MIN: usize = 128 * 1024;
const RELAY_BUF_MAX: usize = 4 * 1024 * 1024;

const COPY_BUF_PER_MTU: usize = 16;
const COPY_BUF_MIN: usize = 32 * 1024;
const COPY_BUF_MAX: usize = 256 * 1024;

const STACK_BUF_MIN: usize = 512;
const STACK_BUF_MAX: usize = 4096;
const STACK_BUF_PER_BYTES: u64 = 2 * 1024 * 1024;

const FD_RESERVE: u64 = 64;
const FDS_PER_CONN: u64 = 2;
const MEM_FRACTION_FOR_RELAY: u64 = 4;

const TCP_CONN_MIN: usize = 128;
const TCP_CONN_MAX: usize = 65536;
const UDP_PER_TCP: usize = 4;
const UDP_SESSION_MIN: usize = 64;
const UDP_SESSION_MAX: usize = 16384;

const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug)]
pub struct SystemProbe {
    pub link_mtu: Option<u32>,
    pub has_ipv6_gateway: bool,
    pub total_memory_bytes: Option<u64>,
    pub fd_limit: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct Tuning {
    pub mtu: u32,
    pub relay_buf_size: usize,
    pub relay_copy_buf_size: usize,
    pub stack_buf_size: usize,
    pub udp_idle_timeout: Duration,
    pub max_tcp_connections: usize,
    pub max_udp_sessions: usize,
    pub capture_ipv6: bool,
}

impl Tuning {
    pub fn compute(probe: &SystemProbe) -> Self {
        let mtu = probe
            .link_mtu
            .unwrap_or(FALLBACK_MTU)
            .clamp(MIN_MTU, MAX_MTU);
        let mtu_bytes = mtu as usize;

        let memory = probe.total_memory_bytes.unwrap_or(DEFAULT_MEMORY);
        let fds = probe.fd_limit.unwrap_or(DEFAULT_FD_LIMIT);

        let relay_buf_size = (mtu_bytes * RELAY_BUF_PER_MTU).clamp(RELAY_BUF_MIN, RELAY_BUF_MAX);
        let relay_copy_buf_size = (mtu_bytes * COPY_BUF_PER_MTU).clamp(COPY_BUF_MIN, COPY_BUF_MAX);
        let stack_buf_size =
            ((memory / STACK_BUF_PER_BYTES) as usize).clamp(STACK_BUF_MIN, STACK_BUF_MAX);

        let per_conn = (2 * relay_buf_size + relay_copy_buf_size) as u64;
        let mem_conns = (memory / MEM_FRACTION_FOR_RELAY / per_conn.max(1)).max(1) as usize;
        let fd_conns = (fds.saturating_sub(FD_RESERVE) / FDS_PER_CONN).max(1) as usize;
        let max_tcp_connections = mem_conns.min(fd_conns).clamp(TCP_CONN_MIN, TCP_CONN_MAX);
        let max_udp_sessions =
            (max_tcp_connections / UDP_PER_TCP).clamp(UDP_SESSION_MIN, UDP_SESSION_MAX);

        Self {
            mtu,
            relay_buf_size,
            relay_copy_buf_size,
            stack_buf_size,
            udp_idle_timeout: UDP_IDLE_TIMEOUT,
            max_tcp_connections,
            max_udp_sessions,
            capture_ipv6: probe.has_ipv6_gateway,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "auto-tuned: mtu={} relay_buf={} copy_buf={} stack_depth={} max_tcp={} max_udp={} udp_idle={}s capture_ipv6={}",
            self.mtu,
            self.relay_buf_size,
            self.relay_copy_buf_size,
            self.stack_buf_size,
            self.max_tcp_connections,
            self.max_udp_sessions,
            self.udp_idle_timeout.as_secs(),
            self.capture_ipv6,
        )
    }
}

pub async fn probe() -> SystemProbe {
    let link = crate::platform::active::detect_link().await;
    SystemProbe {
        link_mtu: link.mtu,
        has_ipv6_gateway: link.has_ipv6_gateway,
        total_memory_bytes: read_total_memory(),
        fd_limit: raise_and_read_fd_limit(),
    }
}

fn read_total_memory() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

#[cfg(unix)]
fn raise_and_read_fd_limit() -> Option<u64> {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    let mut limit = getrlimit(Resource::Nofile);
    if let (Some(current), Some(maximum)) = (limit.current, limit.maximum)
        && current < maximum
    {
        let raised = Rlimit {
            current: Some(maximum),
            maximum: Some(maximum),
        };
        if setrlimit(Resource::Nofile, raised).is_ok() {
            limit.current = Some(maximum);
        }
    }
    limit.current
}

#[cfg(not(unix))]
fn raise_and_read_fd_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(mtu: Option<u32>, v6: bool, mem: Option<u64>, fds: Option<u64>) -> SystemProbe {
        SystemProbe {
            link_mtu: mtu,
            has_ipv6_gateway: v6,
            total_memory_bytes: mem,
            fd_limit: fds,
        }
    }

    #[test]
    fn uses_detected_mtu_and_v6_gateway() {
        let t = Tuning::compute(&probe(Some(9000), true, Some(8 << 30), Some(1 << 20)));
        assert_eq!(t.mtu, 9000);
        assert!(t.capture_ipv6);
        assert!(t.relay_buf_size <= RELAY_BUF_MAX);
        assert!(t.relay_buf_size >= RELAY_BUF_MIN);
    }

    #[test]
    fn clamps_extreme_mtu() {
        assert_eq!(
            Tuning::compute(&probe(Some(50), false, None, None)).mtu,
            MIN_MTU
        );
        assert_eq!(
            Tuning::compute(&probe(Some(100000), false, None, None)).mtu,
            MAX_MTU
        );
    }

    #[test]
    fn connection_cap_is_fd_limited_when_fds_are_scarce() {
        let t = Tuning::compute(&probe(Some(1500), false, Some(8 << 30), Some(1024)));
        assert_eq!(t.max_tcp_connections, ((1024 - 64) / 2) as usize);
        assert_eq!(t.max_udp_sessions, t.max_tcp_connections / UDP_PER_TCP);
    }

    #[test]
    fn falls_back_without_system_state() {
        let t = Tuning::compute(&probe(None, false, None, None));
        assert_eq!(t.mtu, FALLBACK_MTU);
        assert!(!t.capture_ipv6);
        assert!(t.max_tcp_connections >= TCP_CONN_MIN);
        assert!(t.max_udp_sessions >= UDP_SESSION_MIN);
        assert_eq!(t.udp_idle_timeout, UDP_IDLE_TIMEOUT);
    }

    #[test]
    fn jumbo_mtu_grows_buffers_versus_small_mtu() {
        let small = Tuning::compute(&probe(Some(1500), false, Some(8 << 30), Some(1 << 20)));
        let jumbo = Tuning::compute(&probe(Some(9000), false, Some(8 << 30), Some(1 << 20)));
        assert!(jumbo.relay_buf_size > small.relay_buf_size);
        assert!(jumbo.relay_copy_buf_size > small.relay_copy_buf_size);
    }
}

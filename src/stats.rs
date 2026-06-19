pub use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

pub static TCP_OPENED: AtomicU64 = AtomicU64::new(0);
pub static TCP_CLOSED: AtomicU64 = AtomicU64::new(0);
pub static TCP_ERRORS: AtomicU64 = AtomicU64::new(0);
pub static TCP_ACTIVE: AtomicU64 = AtomicU64::new(0);
pub static UDP_PACKETS: AtomicU64 = AtomicU64::new(0);
pub static UDP_ERRORS: AtomicU64 = AtomicU64::new(0);
pub static UDP_ACTIVE: AtomicU64 = AtomicU64::new(0);
pub static BYTES_TX: AtomicU64 = AtomicU64::new(0);
pub static BYTES_RX: AtomicU64 = AtomicU64::new(0);
pub static BYTES_V4: AtomicU64 = AtomicU64::new(0);
pub static BYTES_V6: AtomicU64 = AtomicU64::new(0);
pub static DNS_REQUESTS: AtomicU64 = AtomicU64::new(0);
pub static DNS_FAILURES: AtomicU64 = AtomicU64::new(0);
pub static DNS_POOL_HITS: AtomicU64 = AtomicU64::new(0);
pub static DNS_POOL_MISSES: AtomicU64 = AtomicU64::new(0);
pub static ROUTE_DIRECT: AtomicU64 = AtomicU64::new(0);
pub static ROUTE_PROXY: AtomicU64 = AtomicU64::new(0);
pub static CONN_FAILURES: AtomicU64 = AtomicU64::new(0);
pub static SOCKS_HANDSHAKE_FAILURES: AtomicU64 = AtomicU64::new(0);
pub static CONFIG_RELOADS: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn inc(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn add(counter: &AtomicU64, value: u64) {
    counter.fetch_add(value, Ordering::Relaxed);
}

#[inline]
pub fn dec(counter: &AtomicU64) {
    counter.fetch_sub(1, Ordering::Relaxed);
}

#[inline]
pub fn get(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    const STEP: f64 = 1000.0;
    if bytes < STEP as u64 {
        return format!("{bytes} {}", UNITS[0]);
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= STEP && unit < UNITS.len() - 1 {
        value /= STEP;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

#[inline]
pub fn record_traffic(addr: std::net::IpAddr, bytes: u64) {
    match addr {
        std::net::IpAddr::V4(_) => add(&BYTES_V4, bytes),
        std::net::IpAddr::V6(_) => add(&BYTES_V6, bytes),
    }
}

pub struct GaugeGuard {
    gauge: &'static AtomicU64,
}

impl GaugeGuard {
    pub fn new(gauge: &'static AtomicU64) -> Self {
        gauge.fetch_add(1, Ordering::Relaxed);
        Self { gauge }
    }
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.gauge.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gauge_guard_balances() {
        static G: AtomicU64 = AtomicU64::new(0);
        assert_eq!(get(&G), 0);
        {
            let _a = GaugeGuard::new(&G);
            let _b = GaugeGuard::new(&G);
            assert_eq!(get(&G), 2);
        }
        assert_eq!(get(&G), 0);
    }

    #[test]
    fn record_traffic_splits_by_family() {
        let v4_before = get(&BYTES_V4);
        let v6_before = get(&BYTES_V6);
        record_traffic("1.2.3.4".parse().unwrap(), 100);
        record_traffic("::1".parse().unwrap(), 200);
        assert_eq!(get(&BYTES_V4), v4_before + 100);
        assert_eq!(get(&BYTES_V6), v6_before + 200);
    }

    #[test]
    fn format_bytes_scales_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_000), "1.00 KB");
        assert_eq!(format_bytes(1_500), "1.50 KB");
        assert_eq!(format_bytes(2_340_000), "2.34 MB");
        assert_eq!(format_bytes(1_100_000_000), "1.10 GB");
        assert_eq!(format_bytes(3_000_000_000_000), "3.00 TB");
        assert_eq!(format_bytes(5_000_000_000_000_000), "5000.00 TB");
    }

    #[test]
    fn counters_increment() {
        static C: AtomicU64 = AtomicU64::new(0);
        inc(&C);
        add(&C, 5);
        assert_eq!(get(&C), 6);
        dec(&C);
        assert_eq!(get(&C), 5);
    }
}

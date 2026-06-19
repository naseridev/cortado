use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::config::{Config, ProxyConfig};
use crate::net::{RouteTable, diff_cidrs};

pub struct Shared {
    proxy: ArcSwap<ProxyConfig>,
    routes: ArcSwap<RouteTable>,
}

impl Shared {
    pub fn new(proxy: Arc<ProxyConfig>, routes: Arc<RouteTable>) -> Self {
        Self {
            proxy: ArcSwap::from(proxy),
            routes: ArcSwap::from(routes),
        }
    }

    pub fn proxy(&self) -> Arc<ProxyConfig> {
        self.proxy.load_full()
    }

    pub fn routes(&self) -> Arc<RouteTable> {
        self.routes.load_full()
    }

    pub fn store_proxy(&self, proxy: Arc<ProxyConfig>) {
        self.proxy.store(proxy);
    }

    pub fn store_routes(&self, routes: Arc<RouteTable>) {
        self.routes.store(routes);
    }
}

pub const IMMUTABLE_FIELDS: &[&str] = &["tun_name", "tun_ip", "metrics_addr"];

pub fn immutable_changes(old: &Config, new: &Config) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if old.tun_name != new.tun_name {
        changed.push("tun_name");
    }
    if old.tun_ip != new.tun_ip {
        changed.push("tun_ip");
    }
    if old.metrics_addr != new.metrics_addr {
        changed.push("metrics_addr");
    }
    changed
}

pub struct ReloadPlan {
    pub proxy: ProxyConfig,
    pub route_table: RouteTable,
    pub new_bypass: Vec<(IpAddr, u8)>,
    pub bypass_add: Vec<(IpAddr, u8)>,
    pub bypass_remove: Vec<(IpAddr, u8)>,
    pub dns: Option<IpAddr>,
    pub dns_changed: bool,
    pub proxy_route_change: Option<(IpAddr, IpAddr)>,
    pub proxy_changed: bool,
}

impl ReloadPlan {
    pub fn compute(old: &Config, new: &Config) -> Self {
        let old_bypass = old.bypass_routes();
        let new_bypass = new.bypass_routes();
        let (bypass_add, bypass_remove) = diff_cidrs(&old_bypass, &new_bypass);

        let old_proxy = old.proxy_socket_addr();
        let new_proxy = new.proxy_socket_addr();
        let proxy_route_change = if old_proxy.ip() != new_proxy.ip() {
            Some((old_proxy.ip(), new_proxy.ip()))
        } else {
            None
        };

        let proxy_changed =
            old_proxy != new_proxy || old.username != new.username || old.password != new.password;

        Self {
            proxy: ProxyConfig::from_config(new),
            route_table: RouteTable::new(new_bypass.clone()),
            new_bypass,
            bypass_add,
            bypass_remove,
            dns: new.dns_addr(),
            dns_changed: old.dns_addr() != new.dns_addr(),
            proxy_route_change,
            proxy_changed,
        }
    }

    pub fn is_noop(&self) -> bool {
        self.bypass_add.is_empty()
            && self.bypass_remove.is_empty()
            && !self.dns_changed
            && self.proxy_route_change.is_none()
            && !self.proxy_changed
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn shared_swaps_atomically() {
        let p1 = Arc::new(ProxyConfig::from_config(&Config::default()));
        let routes = Arc::new(RouteTable::default());
        let shared = Shared::new(Arc::clone(&p1), routes);
        assert_eq!(shared.proxy().addr, p1.addr);

        let mut cfg2 = Config::default();
        cfg2.proxy_addr = "10.0.0.9:9050".into();
        let p2 = Arc::new(ProxyConfig::from_config(&cfg2));
        shared.store_proxy(Arc::clone(&p2));
        assert_eq!(shared.proxy().addr, p2.addr);
    }

    #[test]
    fn noop_plan_when_unchanged() {
        let cfg = Config::default();
        let plan = ReloadPlan::compute(&cfg, &cfg);
        assert!(plan.is_noop());
    }

    #[test]
    fn detects_proxy_address_change() {
        let old = Config::default();
        let mut new = Config::default();
        new.proxy_addr = "203.0.113.9:1080".into();
        let plan = ReloadPlan::compute(&old, &new);
        assert!(plan.proxy_changed);
        assert_eq!(
            plan.proxy_route_change,
            Some((ip("127.0.0.1"), ip("203.0.113.9")))
        );
        assert!(!plan.is_noop());
    }

    #[test]
    fn detects_bypass_changes() {
        let mut old = Config::default();
        old.bypass_cidrs = vec!["10.0.0.0/8".into()];
        let mut new = Config::default();
        new.bypass_cidrs = vec!["192.168.0.0/16".into()];
        let plan = ReloadPlan::compute(&old, &new);
        assert_eq!(plan.bypass_add, vec![(ip("192.168.0.0"), 16)]);
        assert_eq!(plan.bypass_remove, vec![(ip("10.0.0.0"), 8)]);
    }

    #[test]
    fn detects_dns_change() {
        let old = Config::default();
        let mut new = Config::default();
        new.dns_server = "9.9.9.9".into();
        let plan = ReloadPlan::compute(&old, &new);
        assert!(plan.dns_changed);
        assert_eq!(plan.dns, Some(ip("9.9.9.9")));
    }

    #[test]
    fn dns_unchanged_when_override_off() {
        let mut old = Config::default();
        old.override_dns = false;
        let mut new = Config::default();
        new.override_dns = false;
        new.dns_server = "9.9.9.9".into();
        let plan = ReloadPlan::compute(&old, &new);
        assert!(!plan.dns_changed);
        assert_eq!(plan.dns, None);
    }

    #[test]
    fn flags_immutable_field_changes() {
        let old = Config::default();
        let mut new = Config::default();
        new.tun_ip = "10.9.0.1".into();
        new.tun_name = "tun9".into();
        let changed = immutable_changes(&old, &new);
        assert!(changed.contains(&"tun_ip"));
        assert!(changed.contains(&"tun_name"));
    }

    #[test]
    fn no_immutable_changes_for_proxy_only_edit() {
        let old = Config::default();
        let mut new = Config::default();
        new.proxy_addr = "203.0.113.9:1080".into();
        assert!(immutable_changes(&old, &new).is_empty());
    }
}

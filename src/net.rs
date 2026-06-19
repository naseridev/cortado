use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type CidrList = Vec<(IpAddr, u8)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn new(addr: IpAddr, prefix: u8) -> Self {
        let base = match addr {
            IpAddr::V4(v4) => IpAddr::V4(mask_v4(v4, prefix)),
            IpAddr::V6(v6) => IpAddr::V6(mask_v6(v6, prefix)),
        };
        Self { base, prefix }
    }

    pub fn base(&self) -> IpAddr {
        self.base
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn is_ipv6(&self) -> bool {
        self.base.is_ipv6()
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.base, addr) {
            (IpAddr::V4(b), IpAddr::V4(a)) => mask_v4(a, self.prefix) == b,
            (IpAddr::V6(b), IpAddr::V6(a)) => mask_v6(a, self.prefix) == b,
            _ => false,
        }
    }
}

fn mask_v4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(addr) & prefix_mask_v4(prefix))
}

fn mask_v6(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(addr) & prefix_mask_v6(prefix))
}

pub fn diff_cidrs(old: &[(IpAddr, u8)], new: &[(IpAddr, u8)]) -> (CidrList, CidrList) {
    let to_add = new.iter().filter(|e| !old.contains(e)).copied().collect();
    let to_remove = old.iter().filter(|e| !new.contains(e)).copied().collect();
    (to_add, to_remove)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDecision {
    Direct,
    Proxy,
}

#[derive(Clone, Default)]
pub struct RouteTable {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    len: usize,
}

impl RouteTable {
    pub fn new(direct: impl IntoIterator<Item = (IpAddr, u8)>) -> Self {
        let mut cidrs: Vec<Cidr> = direct
            .into_iter()
            .map(|(addr, prefix)| Cidr::new(addr, prefix))
            .collect();
        cidrs.sort_by_key(|c| std::cmp::Reverse(c.prefix));
        let len = cidrs.len();

        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for c in cidrs {
            match c.base {
                IpAddr::V4(b) => v4.push((u32::from(b), prefix_mask_v4(c.prefix))),
                IpAddr::V6(b) => v6.push((u128::from(b), prefix_mask_v6(c.prefix))),
            }
        }
        Self { v4, v6, len }
    }

    #[inline]
    pub fn decide(&self, addr: IpAddr) -> RouteDecision {
        let matched = match addr {
            IpAddr::V4(a) => {
                let bits = u32::from(a);
                self.v4.iter().any(|&(base, mask)| bits & mask == base)
            }
            IpAddr::V6(a) => {
                let bits = u128::from(a);
                self.v6.iter().any(|&(base, mask)| bits & mask == base)
            }
        };
        if matched {
            RouteDecision::Direct
        } else {
            RouteDecision::Proxy
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

#[inline]
fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[inline]
fn prefix_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else if prefix >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_cidr_contains() {
        let c = Cidr::new(ip("10.0.0.0"), 8);
        assert!(c.contains(ip("10.255.255.255")));
        assert!(c.contains(ip("10.0.0.1")));
        assert!(!c.contains(ip("11.0.0.1")));
    }

    #[test]
    fn v4_host_route() {
        let c = Cidr::new(ip("192.168.1.5"), 32);
        assert!(c.contains(ip("192.168.1.5")));
        assert!(!c.contains(ip("192.168.1.6")));
    }

    #[test]
    fn v4_default_route_matches_everything() {
        let c = Cidr::new(ip("0.0.0.0"), 0);
        assert!(c.contains(ip("8.8.8.8")));
        assert!(c.contains(ip("0.0.0.0")));
    }

    #[test]
    fn v6_cidr_contains() {
        let c = Cidr::new(ip("2001:db8::"), 32);
        assert!(c.contains(ip("2001:db8:dead:beef::1")));
        assert!(!c.contains(ip("2001:db9::1")));
    }

    #[test]
    fn v6_host_route() {
        let c = Cidr::new(ip("fd00::1"), 128);
        assert!(c.contains(ip("fd00::1")));
        assert!(!c.contains(ip("fd00::2")));
    }

    #[test]
    fn v6_default_route_matches_everything() {
        let c = Cidr::new(ip("::"), 0);
        assert!(c.contains(ip("2606:4700:4700::1111")));
    }

    #[test]
    fn cidr_normalizes_base() {
        let c = Cidr::new(ip("10.1.2.3"), 8);
        assert_eq!(c.base(), ip("10.0.0.0"));
    }

    #[test]
    fn family_mismatch_never_matches() {
        let v4 = Cidr::new(ip("0.0.0.0"), 0);
        assert!(!v4.contains(ip("::1")));
        let v6 = Cidr::new(ip("::"), 0);
        assert!(!v6.contains(ip("1.2.3.4")));
    }

    #[test]
    fn route_table_direct_vs_proxy() {
        let table = RouteTable::new([(ip("10.0.0.0"), 8), (ip("fd00::"), 8)]);
        assert_eq!(table.decide(ip("10.5.6.7")), RouteDecision::Direct);
        assert_eq!(table.decide(ip("fd00::abcd")), RouteDecision::Direct);
        assert_eq!(table.decide(ip("8.8.8.8")), RouteDecision::Proxy);
        assert_eq!(table.decide(ip("2606:4700::1")), RouteDecision::Proxy);
    }

    #[test]
    fn route_table_overlapping_prefixes() {
        let table = RouteTable::new([(ip("10.0.0.0"), 8), (ip("10.1.0.0"), 16)]);
        assert_eq!(table.decide(ip("10.1.2.3")), RouteDecision::Direct);
        assert_eq!(table.decide(ip("10.9.2.3")), RouteDecision::Direct);
        assert_eq!(table.decide(ip("11.1.2.3")), RouteDecision::Proxy);
    }

    #[test]
    fn empty_table_is_all_proxy() {
        let table = RouteTable::default();
        assert!(table.is_empty());
        assert_eq!(table.decide(ip("1.2.3.4")), RouteDecision::Proxy);
        assert_eq!(table.decide(ip("::1")), RouteDecision::Proxy);
    }

    #[test]
    fn diff_cidrs_adds_and_removes() {
        let old = vec![(ip("10.0.0.0"), 8), (ip("192.168.0.0"), 16)];
        let new = vec![(ip("10.0.0.0"), 8), (ip("fd00::"), 8)];
        let (add, remove) = diff_cidrs(&old, &new);
        assert_eq!(add, vec![(ip("fd00::"), 8)]);
        assert_eq!(remove, vec![(ip("192.168.0.0"), 16)]);
    }

    #[test]
    fn diff_cidrs_identical_is_empty() {
        let same = vec![(ip("10.0.0.0"), 8)];
        let (add, remove) = diff_cidrs(&same, &same);
        assert!(add.is_empty());
        assert!(remove.is_empty());
    }

    #[test]
    fn mixed_stack_classification() {
        let table = RouteTable::new([(ip("192.168.0.0"), 16)]);
        assert_eq!(table.decide(ip("192.168.50.1")), RouteDecision::Direct);
        assert_eq!(table.decide(ip("2001:db8::1")), RouteDecision::Proxy);
        assert_eq!(table.len(), 1);
    }
}

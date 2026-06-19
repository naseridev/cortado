use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub fn parse_cidr(spec: &str) -> Result<(IpAddr, u8)> {
    let (addr_part, prefix_part) = spec
        .split_once('/')
        .with_context(|| format!("cidr {} is missing a prefix length", spec))?;
    let addr: IpAddr = addr_part
        .parse()
        .with_context(|| format!("cidr {} has an invalid address", spec))?;
    let prefix: u8 = prefix_part
        .parse()
        .with_context(|| format!("cidr {} has an invalid prefix length", spec))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        bail!("cidr {} prefix length exceeds {}", spec, max);
    }
    Ok((addr, prefix))
}

fn default_dns_server() -> String {
    "1.1.1.1".to_string()
}

fn default_override_dns() -> bool {
    true
}

fn default_dns_over_tcp() -> bool {
    true
}

fn default_bypass_cidrs() -> Vec<String> {
    Vec::new()
}

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub proxy_addr: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tun_name: String,
    pub tun_ip: String,
    pub verbose: bool,
    #[serde(default = "default_dns_server")]
    pub dns_server: String,
    #[serde(default = "default_override_dns")]
    pub override_dns: bool,
    #[serde(default = "default_dns_over_tcp")]
    pub dns_over_tcp: bool,
    #[serde(default = "default_bypass_cidrs")]
    pub bypass_cidrs: Vec<String>,
    #[serde(default)]
    pub metrics_addr: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy_addr: "127.0.0.1:1080".into(),
            username: None,
            password: None,
            tun_name: "cortado0".into(),
            tun_ip: "10.0.0.1".into(),
            verbose: false,
            dns_server: default_dns_server(),
            override_dns: default_override_dns(),
            dns_over_tcp: default_dns_over_tcp(),
            bypass_cidrs: default_bypass_cidrs(),
            metrics_addr: None,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        self.proxy_addr
            .parse::<SocketAddr>()
            .context("proxy_addr is not a valid socket address (expected ip:port)")?;
        self.tun_ip
            .parse::<Ipv4Addr>()
            .context("tun_ip is not a valid IPv4 address")?;
        if self.override_dns {
            self.dns_server
                .parse::<IpAddr>()
                .context("dns_server is not a valid IP address")?;
        }
        for cidr in &self.bypass_cidrs {
            parse_cidr(cidr)?;
        }
        if let Some(addr) = &self.metrics_addr {
            addr.parse::<SocketAddr>()
                .context("metrics_addr is not a valid socket address (expected ip:port)")?;
        }
        match (&self.username, &self.password) {
            (Some(_), None) | (None, Some(_)) => {
                bail!("username and password must both be set or both be absent");
            }
            (Some(u), Some(p)) => {
                if u.is_empty() || u.len() > 255 {
                    bail!("username length must be between 1 and 255");
                }
                if p.is_empty() || p.len() > 255 {
                    bail!("password length must be between 1 and 255");
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn proxy_socket_addr(&self) -> SocketAddr {
        self.proxy_addr.parse().expect("already validated")
    }

    pub fn tun_ipv4(&self) -> Ipv4Addr {
        self.tun_ip.parse().expect("already validated")
    }

    pub fn dns_addr(&self) -> Option<IpAddr> {
        if self.override_dns {
            Some(self.dns_server.parse().expect("already validated"))
        } else {
            None
        }
    }

    pub fn bypass_routes(&self) -> Vec<(IpAddr, u8)> {
        self.bypass_cidrs
            .iter()
            .map(|c| parse_cidr(c).expect("already validated"))
            .collect()
    }

    pub fn metrics_socket_addr(&self) -> Option<SocketAddr> {
        self.metrics_addr
            .as_ref()
            .map(|a| a.parse().expect("already validated"))
    }
}

#[derive(Clone)]
pub struct ProxyConfig {
    pub addr: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
    pub connect_timeout: Duration,
    pub tcp_nodelay: bool,
}

impl ProxyConfig {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            addr: cfg.proxy_socket_addr(),
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            tcp_nodelay: true,
        }
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn rejects_bad_proxy_addr() {
        let mut cfg = Config::default();
        cfg.proxy_addr = "not-an-addr".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_half_credentials() {
        let mut cfg = Config::default();
        cfg.username = Some("user".into());
        cfg.password = None;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_ipv6_proxy_and_dns() {
        let mut cfg = Config::default();
        cfg.proxy_addr = "[::1]:1080".into();
        cfg.dns_server = "2606:4700:4700::1111".into();
        assert!(cfg.validate().is_ok());
        assert!(cfg.proxy_socket_addr().is_ipv6());
        assert!(cfg.dns_addr().unwrap().is_ipv6());
    }

    #[test]
    fn legacy_auto_tuned_fields_are_ignored() {
        let toml = r#"
proxy_addr = "127.0.0.1:1080"
tun_name = "cortado0"
tun_ip = "10.0.0.1"
verbose = false
mtu = 8500
relay_buf_size = 262144
stack_buf_size = 512
relay_copy_buf_size = 65536
connect_timeout_secs = 10
udp_idle_timeout_secs = 60
max_tcp_connections = 4096
max_udp_sessions = 1024
tcp_nodelay = true
capture_ipv6 = true
"#;
        let cfg: Config = toml::from_str(toml).expect("legacy config still parses");
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.tun_name, "cortado0");
    }

    #[test]
    fn default_serializes_without_auto_tuned_fields() {
        let toml = toml::to_string_pretty(&Config::default()).unwrap();
        for field in [
            "mtu",
            "relay_buf_size",
            "stack_buf_size",
            "relay_copy_buf_size",
            "connect_timeout_secs",
            "udp_idle_timeout_secs",
            "max_tcp_connections",
            "max_udp_sessions",
            "tcp_nodelay",
            "capture_ipv6",
        ] {
            assert!(!toml.contains(field), "default config leaked {field}");
        }
    }

    #[test]
    fn parses_bypass_cidrs() {
        let mut cfg = Config::default();
        cfg.bypass_cidrs = vec!["10.0.0.0/8".into(), "fd00::/8".into()];
        assert!(cfg.validate().is_ok());
        let routes = cfg.bypass_routes();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].1, 8);
    }

    #[test]
    fn rejects_bad_cidr() {
        let mut cfg = Config::default();
        cfg.bypass_cidrs = vec!["10.0.0.0/40".into()];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn cidr_requires_prefix() {
        assert!(parse_cidr("10.0.0.0").is_err());
        assert!(parse_cidr("10.0.0.0/8").is_ok());
        assert!(parse_cidr("::/0").is_ok());
    }

    #[test]
    fn rejects_bad_metrics_addr() {
        let mut cfg = Config::default();
        cfg.metrics_addr = Some("bogus".into());
        assert!(cfg.validate().is_err());
    }
}

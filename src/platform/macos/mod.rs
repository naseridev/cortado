use std::net::IpAddr;

use anyhow::Result;

use crate::config::Config;

pub mod detect;
pub mod dns;
pub mod route;
pub mod tun;

pub use detect::{LinkInfo, detect_link};
pub use route::MacosRoutes;
pub use tun::{MacosTun, create_tun};

pub async fn new_route_controller(
    cfg: &Config,
    proxy_ip: IpAddr,
    tun_name: &str,
    capture_ipv6: bool,
) -> Result<MacosRoutes> {
    MacosRoutes::new(cfg, proxy_ip, tun_name.to_string(), capture_ipv6)
}

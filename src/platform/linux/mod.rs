use std::net::IpAddr;

use anyhow::{Context, Result};

use crate::config::Config;

pub mod detect;
pub mod dns;
pub mod route;
pub mod tun;

pub use detect::{LinkInfo, detect_link};
pub use route::RouteManager;
pub use tun::{LinuxTun, create_tun};

pub async fn new_route_controller(
    cfg: &Config,
    proxy_ip: IpAddr,
    tun_name: &str,
    capture_ipv6: bool,
) -> Result<RouteManager> {
    let (nl_connection, nl_handle, _) =
        rtnetlink::new_connection().context("failed to open netlink socket")?;
    tokio::spawn(nl_connection);
    RouteManager::new(
        nl_handle,
        proxy_ip,
        tun_name,
        cfg.dns_addr(),
        cfg.bypass_routes(),
        capture_ipv6,
    )
    .await
}

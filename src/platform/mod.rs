use std::net::IpAddr;

use anyhow::Result;

use crate::logging::Logger;
use crate::reload::ReloadPlan;

pub trait TunDevice: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {
    fn name(&self) -> &str;
    fn mtu(&self) -> u32;
}

#[allow(async_fn_in_trait)]
pub trait RouteController {
    async fn apply(&mut self, log: &Logger) -> Result<()>;
    async fn reload(&mut self, plan: &ReloadPlan, log: &Logger) -> Result<()>;
    async fn teardown(&mut self, log: &Logger);
}

pub trait DnsConfigurator {
    fn apply(&mut self, server: Option<IpAddr>, log: &Logger) -> Result<()>;
    fn reload(&mut self, server: Option<IpAddr>, log: &Logger) -> Result<()>;
    fn restore(&mut self, log: &Logger);
}

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as active;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos as active;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows as active;

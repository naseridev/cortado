use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use tokio_tun::Tun;

use crate::config::Config;
use crate::platform::TunDevice;

pub const TUN_PEER_ADDR: &str = "10.0.0.2";
pub const TUN_NETMASK: &str = "255.255.255.0";

pub struct LinuxTun {
    inner: Tun,
    name: String,
    mtu: u32,
}

impl LinuxTun {
    pub fn into_inner(self) -> Tun {
        self.inner
    }
}

pub fn create_tun(cfg: &Config, mtu: u32) -> Result<LinuxTun> {
    let peer: Ipv4Addr = TUN_PEER_ADDR.parse().expect("static literal");
    let netmask: Ipv4Addr = TUN_NETMASK.parse().expect("static literal");
    let inner = tokio_tun::TunBuilder::new()
        .name(&cfg.tun_name)
        .address(cfg.tun_ipv4())
        .destination(peer)
        .netmask(netmask)
        .mtu(mtu as i32)
        .packet_info(false)
        .up()
        .try_build()
        .context("failed to create TUN device, is cortado running as root?")?;
    Ok(LinuxTun {
        inner,
        name: cfg.tun_name.clone(),
        mtu,
    })
}

impl tokio::io::AsyncRead for LinuxTun {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for LinuxTun {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl TunDevice for LinuxTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }
}

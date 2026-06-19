use std::net::IpAddr;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::logging::Logger;
use crate::net::CidrList;
use crate::platform::{DnsConfigurator, RouteController};
use crate::reload::ReloadPlan;

use super::dns::NetshDns;

const V4_SPLIT: [(&str, &str); 2] = [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")];
const V6_SPLIT: [&str; 2] = ["::/1", "8000::/1"];

fn host_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

fn netsh(args: &[&str]) -> Result<()> {
    let status = Command::new("netsh")
        .args(args)
        .status()
        .context("failed to run netsh")?;
    if !status.success() {
        bail!("netsh {:?} exited with {}", args, status);
    }
    Ok(())
}

fn netsh_quiet(args: &[&str]) {
    let _ = Command::new("netsh").args(args).status();
}

fn default_gateway() -> Option<IpAddr> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim().parse::<IpAddr>().ok()
}

pub struct WindowsRoutes {
    proxy_ip: IpAddr,
    interface: String,
    bypass: CidrList,
    capture_ipv6: bool,
    gateway: Option<IpAddr>,
    dns: NetshDns,
    dns_server: Option<IpAddr>,
    applied: bool,
}

impl WindowsRoutes {
    pub fn new(
        cfg: &Config,
        proxy_ip: IpAddr,
        interface: String,
        capture_ipv6: bool,
    ) -> Result<Self> {
        Ok(Self {
            proxy_ip,
            interface: interface.clone(),
            bypass: cfg.bypass_routes(),
            capture_ipv6,
            gateway: None,
            dns: NetshDns::new(interface),
            dns_server: cfg.dns_addr(),
            applied: false,
        })
    }

    fn add_split_v4(&self) -> Result<()> {
        for (net, mask) in V4_SPLIT {
            netsh(&[
                "interface",
                "ipv4",
                "add",
                "route",
                &format!("{net}/{}", mask_to_prefix(mask)),
                &format!("interface={}", self.interface),
                "store=active",
            ])?;
        }
        Ok(())
    }
}

fn mask_to_prefix(mask: &str) -> u8 {
    match mask.parse::<std::net::Ipv4Addr>() {
        Ok(m) => u32::from(m).count_ones() as u8,
        Err(_) => 1,
    }
}

impl RouteController for WindowsRoutes {
    async fn apply(&mut self, log: &Logger) -> Result<()> {
        self.gateway = default_gateway();

        if let Some(gw) = self.gateway {
            netsh(&[
                "interface",
                "ipv4",
                "add",
                "route",
                &format!("{}/{}", self.proxy_ip, host_prefix(self.proxy_ip)),
                &format!("nexthop={gw}"),
                "store=active",
            ])
            .context("failed to pin proxy host route")?;
            log.info(format!(
                "proxy host route {} via {} added",
                self.proxy_ip, gw
            ));
        } else {
            log.warn("no default gateway found, proxy route not pinned");
        }

        for (dst, prefix) in &self.bypass {
            if let Some(gw) = self.gateway {
                let family = if dst.is_ipv4() { "ipv4" } else { "ipv6" };
                netsh_quiet(&[
                    "interface",
                    family,
                    "add",
                    "route",
                    &format!("{dst}/{prefix}"),
                    &format!("nexthop={gw}"),
                    "store=active",
                ]);
                log.info(format!("bypass route {dst}/{prefix} via {gw} added"));
            }
        }

        self.add_split_v4()?;
        log.info("IPv4 split-default routes into tun added");

        if self.capture_ipv6 {
            for net in V6_SPLIT {
                netsh_quiet(&[
                    "interface",
                    "ipv6",
                    "add",
                    "route",
                    net,
                    &format!("interface={}", self.interface),
                    "store=active",
                ]);
            }
            log.info("IPv6 split-default routes into tun added");
        }

        self.dns.apply(self.dns_server, log)?;
        self.applied = true;
        Ok(())
    }

    async fn reload(&mut self, plan: &ReloadPlan, log: &Logger) -> Result<()> {
        if !self.applied {
            return Ok(());
        }

        if let Some((old_ip, new_ip)) = plan.proxy_route_change {
            if let Some(gw) = self.gateway {
                netsh_quiet(&[
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    &format!("{old_ip}/{}", host_prefix(old_ip)),
                    &format!("nexthop={gw}"),
                ]);
                netsh(&[
                    "interface",
                    "ipv4",
                    "add",
                    "route",
                    &format!("{new_ip}/{}", host_prefix(new_ip)),
                    &format!("nexthop={gw}"),
                    "store=active",
                ])?;
            }
            self.proxy_ip = new_ip;
            log.info(format!("proxy host route moved to {new_ip}"));
        }

        for (dst, prefix) in &plan.bypass_remove {
            if let Some(gw) = self.gateway {
                let family = if dst.is_ipv4() { "ipv4" } else { "ipv6" };
                netsh_quiet(&[
                    "interface",
                    family,
                    "delete",
                    "route",
                    &format!("{dst}/{prefix}"),
                    &format!("nexthop={gw}"),
                ]);
            }
        }
        for (dst, prefix) in &plan.bypass_add {
            if let Some(gw) = self.gateway {
                let family = if dst.is_ipv4() { "ipv4" } else { "ipv6" };
                netsh_quiet(&[
                    "interface",
                    family,
                    "add",
                    "route",
                    &format!("{dst}/{prefix}"),
                    &format!("nexthop={gw}"),
                    "store=active",
                ]);
                log.info(format!(
                    "bypass route {dst}/{prefix} via {gw} added (reload)"
                ));
            }
        }
        self.bypass = plan.new_bypass.clone();

        if plan.dns_changed {
            self.dns.reload(plan.dns, log)?;
            self.dns_server = plan.dns;
        }
        Ok(())
    }

    async fn teardown(&mut self, log: &Logger) {
        if !self.applied {
            return;
        }
        self.applied = false;

        if let Some(gw) = self.gateway {
            netsh_quiet(&[
                "interface",
                "ipv4",
                "delete",
                "route",
                &format!("{}/{}", self.proxy_ip, host_prefix(self.proxy_ip)),
                &format!("nexthop={gw}"),
            ]);
            for (dst, prefix) in &self.bypass {
                let family = if dst.is_ipv4() { "ipv4" } else { "ipv6" };
                netsh_quiet(&[
                    "interface",
                    family,
                    "delete",
                    "route",
                    &format!("{dst}/{prefix}"),
                    &format!("nexthop={gw}"),
                ]);
            }
        }

        for (net, mask) in V4_SPLIT {
            netsh_quiet(&[
                "interface",
                "ipv4",
                "delete",
                "route",
                &format!("{net}/{}", mask_to_prefix(mask)),
                &format!("interface={}", self.interface),
            ]);
        }
        if self.capture_ipv6 {
            for net in V6_SPLIT {
                netsh_quiet(&[
                    "interface",
                    "ipv6",
                    "delete",
                    "route",
                    net,
                    &format!("interface={}", self.interface),
                ]);
            }
        }

        log.info("routes removed");
        self.dns.restore(log);
    }
}

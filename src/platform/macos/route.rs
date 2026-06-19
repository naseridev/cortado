use std::net::IpAddr;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::logging::Logger;
use crate::net::CidrList;
use crate::platform::{DnsConfigurator, RouteController};
use crate::reload::ReloadPlan;

use super::dns::NetworkSetupDns;

const V4_SPLIT: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
const V6_SPLIT: [&str; 2] = ["::/1", "8000::/1"];

fn host_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

fn route(args: &[&str]) -> Result<()> {
    let status = Command::new("/sbin/route")
        .args(args)
        .status()
        .context("failed to run route")?;
    if !status.success() {
        bail!("route {:?} exited with {}", args, status);
    }
    Ok(())
}

fn route_quiet(args: &[&str]) {
    let _ = Command::new("/sbin/route").args(args).status();
}

fn default_gateway(family: &str) -> Option<IpAddr> {
    let out = Command::new("/sbin/route")
        .args(["-n", "get", family, "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(gw) = line.strip_prefix("gateway:")
            && let Ok(ip) = gw.trim().parse::<IpAddr>()
        {
            return Some(ip);
        }
    }
    None
}

pub struct MacosRoutes {
    proxy_ip: IpAddr,
    tun_name: String,
    bypass: CidrList,
    capture_ipv6: bool,
    v4_gateway: Option<IpAddr>,
    v6_gateway: Option<IpAddr>,
    dns: NetworkSetupDns,
    dns_server: Option<IpAddr>,
    applied: bool,
}

impl MacosRoutes {
    pub fn new(
        cfg: &Config,
        proxy_ip: IpAddr,
        tun_name: String,
        capture_ipv6: bool,
    ) -> Result<Self> {
        Ok(Self {
            proxy_ip,
            tun_name,
            bypass: cfg.bypass_routes(),
            capture_ipv6,
            v4_gateway: None,
            v6_gateway: None,
            dns: NetworkSetupDns::discover()?,
            dns_server: cfg.dns_addr(),
            applied: false,
        })
    }

    fn gateway_for(&self, addr: IpAddr) -> Option<IpAddr> {
        match addr {
            IpAddr::V4(_) => self.v4_gateway,
            IpAddr::V6(_) => self.v6_gateway,
        }
    }

    fn add_host_via_gateway(&self, dst: IpAddr, prefix: u8, gw: IpAddr) -> Result<()> {
        let inet = if dst.is_ipv4() { "-inet" } else { "-inet6" };
        let net = format!("{dst}/{prefix}");
        route(&["add", inet, "-net", &net, &gw.to_string()])
    }
}

impl RouteController for MacosRoutes {
    async fn apply(&mut self, log: &Logger) -> Result<()> {
        self.v4_gateway = default_gateway("-inet");
        self.v6_gateway = default_gateway("-inet6");

        let gw = self
            .gateway_for(self.proxy_ip)
            .with_context(|| format!("no default gateway for proxy {}", self.proxy_ip))?;
        self.add_host_via_gateway(self.proxy_ip, host_prefix(self.proxy_ip), gw)
            .context("failed to pin proxy host route")?;
        log.info(format!(
            "proxy host route {} via {} added",
            self.proxy_ip, gw
        ));

        for (dst, prefix) in &self.bypass {
            match self.gateway_for(*dst) {
                Some(g) => {
                    self.add_host_via_gateway(*dst, *prefix, g)?;
                    log.info(format!("bypass route {dst}/{prefix} via {g} added"));
                }
                None => log.warn(format!("skipping bypass {dst}/{prefix}: no gateway")),
            }
        }

        for net in V4_SPLIT {
            route(&["add", "-inet", "-net", net, "-interface", &self.tun_name])?;
        }
        log.info("IPv4 split-default routes into tun added");

        if self.capture_ipv6 && (self.v6_gateway.is_some() || self.proxy_ip.is_ipv6()) {
            for net in V6_SPLIT {
                route(&["add", "-inet6", "-net", net, "-interface", &self.tun_name])?;
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
            if let Some(gw) = self.gateway_for(old_ip) {
                let net = format!("{old_ip}/{}", host_prefix(old_ip));
                let inet = if old_ip.is_ipv4() { "-inet" } else { "-inet6" };
                route_quiet(&["delete", inet, "-net", &net, &gw.to_string()]);
            }
            let gw = self
                .gateway_for(new_ip)
                .with_context(|| format!("no gateway for new proxy {new_ip}"))?;
            self.add_host_via_gateway(new_ip, host_prefix(new_ip), gw)?;
            self.proxy_ip = new_ip;
            log.info(format!("proxy host route moved to {new_ip} via {gw}"));
        }

        for (dst, prefix) in &plan.bypass_remove {
            if let Some(gw) = self.gateway_for(*dst) {
                let inet = if dst.is_ipv4() { "-inet" } else { "-inet6" };
                let net = format!("{dst}/{prefix}");
                route_quiet(&["delete", inet, "-net", &net, &gw.to_string()]);
            }
        }
        for (dst, prefix) in &plan.bypass_add {
            if let Some(gw) = self.gateway_for(*dst) {
                self.add_host_via_gateway(*dst, *prefix, gw)?;
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

        if let Some(gw) = self.gateway_for(self.proxy_ip) {
            let inet = if self.proxy_ip.is_ipv4() {
                "-inet"
            } else {
                "-inet6"
            };
            let net = format!("{}/{}", self.proxy_ip, host_prefix(self.proxy_ip));
            route_quiet(&["delete", inet, "-net", &net, &gw.to_string()]);
        }

        for (dst, prefix) in &self.bypass {
            if let Some(gw) = self.gateway_for(*dst) {
                let inet = if dst.is_ipv4() { "-inet" } else { "-inet6" };
                let net = format!("{dst}/{prefix}");
                route_quiet(&["delete", inet, "-net", &net, &gw.to_string()]);
            }
        }

        for net in V4_SPLIT {
            route_quiet(&["delete", "-inet", "-net", net, "-interface", &self.tun_name]);
        }
        if self.capture_ipv6 {
            for net in V6_SPLIT {
                route_quiet(&[
                    "delete",
                    "-inet6",
                    "-net",
                    net,
                    "-interface",
                    &self.tun_name,
                ]);
            }
        }

        log.info("routes removed");
        self.dns.restore(log);
    }
}

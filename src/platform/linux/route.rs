use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail};
use futures::TryStreamExt;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteHeader, RouteMessage};
use rtnetlink::Handle;

use crate::logging::Logger;
use crate::net::CidrList;
use crate::platform::{DnsConfigurator, RouteController};
use crate::reload::ReloadPlan;

use super::dns::ResolvConf;

const V4_SPLIT: [(Ipv4Addr, u8); 2] = [
    (Ipv4Addr::new(0, 0, 0, 0), 1),
    (Ipv4Addr::new(128, 0, 0, 0), 1),
];

const V6_SPLIT: [(Ipv6Addr, u8); 2] = [
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 1),
    (Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1),
];

fn host_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

pub struct RouteManager {
    handle: Handle,
    proxy_ip: IpAddr,
    tun_index: u32,
    dns: ResolvConf,
    dns_server: Option<IpAddr>,
    bypass: CidrList,
    capture_ipv6: bool,
    v4_gateway: Option<(Ipv4Addr, u32)>,
    v6_gateway: Option<(Ipv6Addr, u32)>,
    applied: bool,
}

impl RouteManager {
    pub async fn new(
        handle: Handle,
        proxy_ip: IpAddr,
        tun_name: &str,
        dns_server: Option<IpAddr>,
        bypass: CidrList,
        capture_ipv6: bool,
    ) -> Result<Self> {
        let tun_index = Self::resolve_link_index(&handle, tun_name).await?;
        Ok(Self {
            handle,
            proxy_ip,
            tun_index,
            dns: ResolvConf::system(),
            dns_server,
            bypass,
            capture_ipv6,
            v4_gateway: None,
            v6_gateway: None,
            applied: false,
        })
    }

    async fn resolve_link_index(handle: &Handle, name: &str) -> Result<u32> {
        let mut stream = handle.link().get().match_name(name.to_owned()).execute();
        let msg = stream
            .try_next()
            .await
            .context("netlink error querying link index")?
            .with_context(|| format!("interface {} not found", name))?;
        Ok(msg.header.index)
    }

    async fn read_v4_gateway(&self) -> Result<Option<(Ipv4Addr, u32)>> {
        let mut stream = self.handle.route().get(rtnetlink::IpVersion::V4).execute();
        while let Some(route) = stream
            .try_next()
            .await
            .context("netlink error reading IPv4 routes")?
        {
            if route.header.destination_prefix_length != 0 {
                continue;
            }
            let mut gw = None;
            let mut oif = None;
            for attr in &route.attributes {
                match attr {
                    RouteAttribute::Gateway(RouteAddress::Inet(addr)) => gw = Some(*addr),
                    RouteAttribute::Oif(idx) => oif = Some(*idx),
                    _ => {}
                }
            }
            if let (Some(g), Some(i)) = (gw, oif) {
                return Ok(Some((g, i)));
            }
        }
        Ok(None)
    }

    async fn read_v6_gateway(&self) -> Result<Option<(Ipv6Addr, u32)>> {
        let mut stream = self.handle.route().get(rtnetlink::IpVersion::V6).execute();
        while let Some(route) = stream
            .try_next()
            .await
            .context("netlink error reading IPv6 routes")?
        {
            if route.header.destination_prefix_length != 0 {
                continue;
            }
            let mut gw = None;
            let mut oif = None;
            for attr in &route.attributes {
                match attr {
                    RouteAttribute::Gateway(RouteAddress::Inet6(addr)) => gw = Some(*addr),
                    RouteAttribute::Oif(idx) => oif = Some(*idx),
                    _ => {}
                }
            }
            if let (Some(g), Some(i)) = (gw, oif) {
                return Ok(Some((g, i)));
            }
        }
        Ok(None)
    }

    async fn add_via_gateway(&self, dst: IpAddr, prefix: u8, gw: IpAddr, oif: u32) -> Result<()> {
        match (dst, gw) {
            (IpAddr::V4(d), IpAddr::V4(g)) => self
                .handle
                .route()
                .add()
                .replace()
                .v4()
                .destination_prefix(d, prefix)
                .gateway(g)
                .output_interface(oif)
                .execute()
                .await
                .with_context(|| format!("failed to add route {}/{} via {}", d, prefix, g)),
            (IpAddr::V6(d), IpAddr::V6(g)) => self
                .handle
                .route()
                .add()
                .replace()
                .v6()
                .destination_prefix(d, prefix)
                .gateway(g)
                .output_interface(oif)
                .execute()
                .await
                .with_context(|| format!("failed to add route {}/{} via {}", d, prefix, g)),
            _ => bail!("address family mismatch for route {}/{}", dst, prefix),
        }
    }

    async fn add_via_tun(&self, dst: IpAddr, prefix: u8) -> Result<()> {
        match dst {
            IpAddr::V4(d) => self
                .handle
                .route()
                .add()
                .replace()
                .v4()
                .destination_prefix(d, prefix)
                .output_interface(self.tun_index)
                .execute()
                .await
                .with_context(|| format!("failed to add split route {}/{} via tun", d, prefix)),
            IpAddr::V6(d) => self
                .handle
                .route()
                .add()
                .replace()
                .v6()
                .destination_prefix(d, prefix)
                .output_interface(self.tun_index)
                .execute()
                .await
                .with_context(|| format!("failed to add split route {}/{} via tun", d, prefix)),
        }
    }

    fn build_del_message(dst: IpAddr, prefix: u8, oif: u32, gw: Option<IpAddr>) -> RouteMessage {
        let mut msg = RouteMessage::default();
        let (family, dst_attr) = match dst {
            IpAddr::V4(d) => (AddressFamily::Inet, RouteAddress::Inet(d)),
            IpAddr::V6(d) => (AddressFamily::Inet6, RouteAddress::Inet6(d)),
        };
        msg.header = RouteHeader {
            address_family: family,
            destination_prefix_length: prefix,
            ..RouteHeader::default()
        };
        msg.attributes.push(RouteAttribute::Destination(dst_attr));
        if let Some(gw) = gw {
            let gw_attr = match gw {
                IpAddr::V4(g) => RouteAddress::Inet(g),
                IpAddr::V6(g) => RouteAddress::Inet6(g),
            };
            msg.attributes.push(RouteAttribute::Gateway(gw_attr));
        }
        msg.attributes.push(RouteAttribute::Oif(oif));
        msg
    }

    async fn del_route(&self, dst: IpAddr, prefix: u8, oif: u32, gw: Option<IpAddr>) -> Result<()> {
        let msg = Self::build_del_message(dst, prefix, oif, gw);
        self.handle
            .route()
            .del(msg)
            .execute()
            .await
            .with_context(|| format!("failed to delete route {}/{}", dst, prefix))
    }

    fn gateway_for(&self, family: IpAddr) -> Option<(IpAddr, u32)> {
        match family {
            IpAddr::V4(_) => self.v4_gateway.map(|(g, o)| (IpAddr::V4(g), o)),
            IpAddr::V6(_) => self.v6_gateway.map(|(g, o)| (IpAddr::V6(g), o)),
        }
    }
}

impl RouteController for RouteManager {
    async fn apply(&mut self, log: &Logger) -> Result<()> {
        self.v4_gateway = self.read_v4_gateway().await?;
        self.v6_gateway = self.read_v6_gateway().await?;
        if let Some((g, o)) = self.v4_gateway {
            log.info(format!("IPv4 gateway: {} on ifindex {}", g, o));
        }
        if let Some((g, o)) = self.v6_gateway {
            log.info(format!("IPv6 gateway: {} on ifindex {}", g, o));
        }

        let (proxy_gw, proxy_oif) = self.gateway_for(self.proxy_ip).with_context(|| {
            format!(
                "no default gateway for proxy address family ({})",
                self.proxy_ip
            )
        })?;
        self.add_via_gateway(
            self.proxy_ip,
            host_prefix(self.proxy_ip),
            proxy_gw,
            proxy_oif,
        )
        .await
        .context("failed to protect proxy route")?;
        log.info(format!(
            "host route for proxy {} via {} added",
            self.proxy_ip, proxy_gw
        ));

        for (dst, prefix) in &self.bypass {
            match self.gateway_for(*dst) {
                Some((gw, oif)) => {
                    self.add_via_gateway(*dst, *prefix, gw, oif)
                        .await
                        .with_context(|| {
                            format!("failed to add bypass route {}/{}", dst, prefix)
                        })?;
                    log.info(format!("bypass route {}/{} via {} added", dst, prefix, gw));
                }
                None => log.warn(format!(
                    "skipping bypass route {}/{}: no gateway for its family",
                    dst, prefix
                )),
            }
        }

        for (dst, prefix) in V4_SPLIT {
            self.add_via_tun(IpAddr::V4(dst), prefix).await?;
        }
        log.info("IPv4 split-default routes into tun added");

        if self.capture_ipv6 {
            if self.v6_gateway.is_some() || self.proxy_ip.is_ipv6() {
                for (dst, prefix) in V6_SPLIT {
                    self.add_via_tun(IpAddr::V6(dst), prefix).await?;
                }
                log.info("IPv6 split-default routes into tun added");
            } else {
                log.warn("capture_ipv6 enabled but no IPv6 gateway present, skipping IPv6 capture");
            }
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
            if let Some((gw, oif)) = self.gateway_for(old_ip)
                && let Err(e) = self
                    .del_route(old_ip, host_prefix(old_ip), oif, Some(gw))
                    .await
            {
                log.warn(format!("reload: removing old proxy route: {e}"));
            }
            let (gw, oif) = self.gateway_for(new_ip).with_context(|| {
                format!("no default gateway for new proxy address family ({new_ip})")
            })?;
            self.add_via_gateway(new_ip, host_prefix(new_ip), gw, oif)
                .await
                .context("failed to install new proxy host route")?;
            self.proxy_ip = new_ip;
            log.info(format!("proxy host route moved to {new_ip} via {gw}"));
        }

        for (dst, prefix) in &plan.bypass_remove {
            if let Some((gw, oif)) = self.gateway_for(*dst)
                && let Err(e) = self.del_route(*dst, *prefix, oif, Some(gw)).await
            {
                log.warn(format!("reload: removing bypass {dst}/{prefix}: {e}"));
            }
        }

        for (dst, prefix) in &plan.bypass_add {
            match self.gateway_for(*dst) {
                Some((gw, oif)) => {
                    self.add_via_gateway(*dst, *prefix, gw, oif)
                        .await
                        .with_context(|| format!("failed to add bypass route {dst}/{prefix}"))?;
                    log.info(format!(
                        "bypass route {dst}/{prefix} via {gw} added (reload)"
                    ));
                }
                None => log.warn(format!(
                    "reload: skipping bypass route {dst}/{prefix}: no gateway for its family"
                )),
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

        if let Some((gw, oif)) = self.gateway_for(self.proxy_ip)
            && let Err(e) = self
                .del_route(self.proxy_ip, host_prefix(self.proxy_ip), oif, Some(gw))
                .await
        {
            log.warn(format!("teardown: {e}"));
        }

        for (dst, prefix) in &self.bypass {
            if let Some((gw, oif)) = self.gateway_for(*dst)
                && let Err(e) = self.del_route(*dst, *prefix, oif, Some(gw)).await
            {
                log.warn(format!("teardown: {e}"));
            }
        }

        for (dst, prefix) in V4_SPLIT {
            if let Err(e) = self
                .del_route(IpAddr::V4(dst), prefix, self.tun_index, None)
                .await
            {
                log.warn(format!("teardown: {e}"));
            }
        }

        if self.capture_ipv6 {
            for (dst, prefix) in V6_SPLIT {
                if let Err(e) = self
                    .del_route(IpAddr::V6(dst), prefix, self.tun_index, None)
                    .await
                {
                    log.warn(format!("teardown: {e}"));
                }
            }
        }

        log.info("routes removed");
        self.dns.restore(log);
    }
}

use std::net::IpAddr;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::logging::Logger;
use crate::platform::DnsConfigurator;

pub struct NetshDns {
    interface: String,
    current: Option<IpAddr>,
    configured: bool,
}

fn set_static(interface: &str, dns: IpAddr) -> Result<()> {
    let family = if dns.is_ipv4() { "ipv4" } else { "ipv6" };
    let status = Command::new("netsh")
        .args([
            "interface",
            family,
            "set",
            "dnsservers",
            &format!("name={interface}"),
            "static",
            &dns.to_string(),
            "primary",
        ])
        .status()
        .context("failed to run netsh set dnsservers")?;
    if !status.success() {
        bail!("netsh set dnsservers exited with {}", status);
    }
    Ok(())
}

fn set_dhcp(interface: &str, family: &str) {
    let _ = Command::new("netsh")
        .args([
            "interface",
            family,
            "set",
            "dnsservers",
            &format!("name={interface}"),
            "dhcp",
        ])
        .status();
}

impl NetshDns {
    pub fn new(interface: String) -> Self {
        Self {
            interface,
            current: None,
            configured: false,
        }
    }
}

impl DnsConfigurator for NetshDns {
    fn apply(&mut self, server: Option<IpAddr>, log: &Logger) -> Result<()> {
        let dns = match server {
            Some(dns) => dns,
            None => return Ok(()),
        };
        set_static(&self.interface, dns)?;
        self.current = Some(dns);
        self.configured = true;
        log.info(format!("DNS set to {} on {}", dns, self.interface));
        Ok(())
    }

    fn reload(&mut self, server: Option<IpAddr>, log: &Logger) -> Result<()> {
        if server == self.current {
            return Ok(());
        }
        match server {
            Some(dns) => {
                set_static(&self.interface, dns)?;
                self.configured = true;
                log.info(format!("DNS set to {} on {} (reload)", dns, self.interface));
            }
            None => {
                set_dhcp(&self.interface, "ipv4");
                set_dhcp(&self.interface, "ipv6");
                self.configured = false;
                log.info("DNS reset to DHCP (reload)");
            }
        }
        self.current = server;
        Ok(())
    }

    fn restore(&mut self, log: &Logger) {
        if !self.configured {
            return;
        }
        set_dhcp(&self.interface, "ipv4");
        set_dhcp(&self.interface, "ipv6");
        self.configured = false;
        self.current = None;
        log.info("DNS reset to DHCP");
    }
}

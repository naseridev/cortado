use std::net::IpAddr;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::logging::Logger;
use crate::platform::DnsConfigurator;

pub struct NetworkSetupDns {
    service: String,
    current: Option<IpAddr>,
    original: Option<Vec<String>>,
}

fn primary_service() -> Result<String> {
    let out = Command::new("/usr/sbin/networksetup")
        .arg("-listnetworkserviceorder")
        .output()
        .context("failed to run networksetup")?;
    let text = String::from_utf8_lossy(&out.stdout);
    for block in text.split("\n\n") {
        if block.contains("Device:") {
            for line in block.lines() {
                if let Some(rest) = line.trim().strip_prefix('(')
                    && let Some(name) = rest.split(')').nth(1)
                {
                    let name = name.trim();
                    if !name.is_empty() {
                        return Ok(name.to_string());
                    }
                }
            }
        }
    }
    bail!("could not determine primary network service")
}

fn get_servers(service: &str) -> Vec<String> {
    let out = match Command::new("/usr/sbin/networksetup")
        .args(["-getdnsservers", service])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    if text.contains("There aren't any") {
        return Vec::new();
    }
    text.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

fn set_servers(service: &str, servers: &[String]) -> Result<()> {
    let mut args = vec!["-setdnsservers".to_string(), service.to_string()];
    if servers.is_empty() {
        args.push("Empty".to_string());
    } else {
        args.extend(servers.iter().cloned());
    }
    let status = Command::new("/usr/sbin/networksetup")
        .args(&args)
        .status()
        .context("failed to run networksetup -setdnsservers")?;
    if !status.success() {
        bail!("networksetup -setdnsservers exited with {}", status);
    }
    Ok(())
}

impl NetworkSetupDns {
    pub fn discover() -> Result<Self> {
        Ok(Self {
            service: primary_service()?,
            current: None,
            original: None,
        })
    }

    fn ensure_backup(&mut self) {
        if self.original.is_none() {
            self.original = Some(get_servers(&self.service));
        }
    }

    pub fn current(&self) -> Option<IpAddr> {
        self.current
    }
}

impl DnsConfigurator for NetworkSetupDns {
    fn apply(&mut self, server: Option<IpAddr>, log: &Logger) -> Result<()> {
        let dns = match server {
            Some(dns) => dns,
            None => return Ok(()),
        };
        self.ensure_backup();
        set_servers(&self.service, &[dns.to_string()])?;
        self.current = Some(dns);
        log.info(format!("DNS set to {} on {}", dns, self.service));
        Ok(())
    }

    fn reload(&mut self, server: Option<IpAddr>, log: &Logger) -> Result<()> {
        if server == self.current {
            return Ok(());
        }
        match server {
            Some(dns) => {
                self.ensure_backup();
                set_servers(&self.service, &[dns.to_string()])?;
                log.info(format!("DNS set to {} on {} (reload)", dns, self.service));
            }
            None => {
                if let Some(orig) = &self.original {
                    set_servers(&self.service, orig)?;
                    log.info("DNS override disabled (reload)");
                }
            }
        }
        self.current = server;
        Ok(())
    }

    fn restore(&mut self, log: &Logger) {
        if self.current.is_none() {
            return;
        }
        if let Some(orig) = self.original.take() {
            if let Err(e) = set_servers(&self.service, &orig) {
                log.warn(format!("failed to restore DNS: {e}"));
            } else {
                log.info("DNS restored");
            }
        }
        self.current = None;
    }
}

use std::process::Command;

pub struct LinkInfo {
    pub mtu: Option<u32>,
    pub has_ipv6_gateway: bool,
}

pub async fn detect_link() -> LinkInfo {
    LinkInfo {
        mtu: default_interface().and_then(|iface| interface_mtu(&iface)),
        has_ipv6_gateway: has_default_gateway("-inet6"),
    }
}

fn default_interface() -> Option<String> {
    let out = Command::new("/sbin/route")
        .args(["-n", "get", "-inet", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(iface) = line.trim().strip_prefix("interface:") {
            return Some(iface.trim().to_string());
        }
    }
    None
}

fn interface_mtu(iface: &str) -> Option<u32> {
    let out = Command::new("/sbin/ifconfig").arg(iface).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut tokens = text.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "mtu" {
            return tokens.next()?.parse().ok();
        }
    }
    None
}

fn has_default_gateway(family: &str) -> bool {
    let out = match Command::new("/sbin/route")
        .args(["-n", "get", family, "default"])
        .output()
    {
        Ok(out) => out,
        Err(_) => return false,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().any(|line| line.trim().starts_with("gateway:"))
}

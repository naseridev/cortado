use std::process::Command;

pub struct LinkInfo {
    pub mtu: Option<u32>,
    pub has_ipv6_gateway: bool,
}

pub async fn detect_link() -> LinkInfo {
    LinkInfo {
        mtu: default_interface_mtu(),
        has_ipv6_gateway: has_ipv6_default_route(),
    }
}

fn powershell(command: &str) -> Option<String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", command])
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn default_interface_mtu() -> Option<u32> {
    let text = powershell(
        "$i = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex; (Get-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4).NlMtu",
    )?;
    text.lines().next()?.trim().parse().ok()
}

fn has_ipv6_default_route() -> bool {
    powershell("(Get-NetRoute -DestinationPrefix '::/0' | Measure-Object).Count")
        .and_then(|text| text.lines().next()?.trim().parse::<u32>().ok())
        .map(|count| count > 0)
        .unwrap_or(false)
}

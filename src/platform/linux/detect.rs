use anyhow::{Context, Result};
use futures::TryStreamExt;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use rtnetlink::Handle;

pub struct LinkInfo {
    pub mtu: Option<u32>,
    pub has_ipv6_gateway: bool,
}

pub async fn detect_link() -> LinkInfo {
    match detect_link_inner().await {
        Ok(info) => info,
        Err(_) => LinkInfo {
            mtu: None,
            has_ipv6_gateway: false,
        },
    }
}

async fn detect_link_inner() -> Result<LinkInfo> {
    let (connection, handle, _) =
        rtnetlink::new_connection().context("failed to open netlink socket")?;
    let conn_task = tokio::spawn(connection);

    let result = gather(&handle).await;

    conn_task.abort();
    result
}

async fn gather(handle: &Handle) -> Result<LinkInfo> {
    let oif = default_v4_oif(handle).await?;
    let mtu = match oif {
        Some(index) => link_mtu(handle, index).await?,
        None => None,
    };
    let has_ipv6_gateway = default_v6_present(handle).await?;
    Ok(LinkInfo {
        mtu,
        has_ipv6_gateway,
    })
}

async fn default_v4_oif(handle: &Handle) -> Result<Option<u32>> {
    let mut stream = handle.route().get(rtnetlink::IpVersion::V4).execute();
    while let Some(route) = stream
        .try_next()
        .await
        .context("netlink error reading IPv4 routes")?
    {
        if route.header.destination_prefix_length != 0 {
            continue;
        }
        for attr in &route.attributes {
            if let RouteAttribute::Oif(index) = attr {
                return Ok(Some(*index));
            }
        }
    }
    Ok(None)
}

async fn default_v6_present(handle: &Handle) -> Result<bool> {
    let mut stream = handle.route().get(rtnetlink::IpVersion::V6).execute();
    while let Some(route) = stream
        .try_next()
        .await
        .context("netlink error reading IPv6 routes")?
    {
        if route.header.destination_prefix_length != 0 {
            continue;
        }
        for attr in &route.attributes {
            if let RouteAttribute::Gateway(RouteAddress::Inet6(_)) = attr {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

async fn link_mtu(handle: &Handle, index: u32) -> Result<Option<u32>> {
    let mut stream = handle.link().get().match_index(index).execute();
    if let Some(msg) = stream
        .try_next()
        .await
        .context("netlink error reading link attributes")?
    {
        for attr in &msg.attributes {
            if let LinkAttribute::Mtu(mtu) = attr {
                return Ok(Some(*mtu));
            }
        }
    }
    Ok(None)
}

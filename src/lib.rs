pub mod config;
pub mod dns;
pub mod logging;
pub mod metrics;
pub mod net;
pub mod platform;
pub mod reload;
pub mod socks;
pub mod stats;
pub mod tune;
pub mod udp;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional_with_sizes};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use config::{Config, ProxyConfig};
use logging::Logger;
use platform::{RouteController, TunDevice};

pub const CONFIG_FILE_NAME: &str = "cortado.conf";
const SYSTEM_CONFIG_DIR: &str = "/etc/cortado";
const STATS_INTERVAL_SECS: u64 = 30;

fn system_config_path() -> PathBuf {
    Path::new(SYSTEM_CONFIG_DIR).join(CONFIG_FILE_NAME)
}

fn user_config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("cortado").join(CONFIG_FILE_NAME))
}

pub fn existing_config_path() -> Option<PathBuf> {
    let system = system_config_path();
    if system.is_file() {
        return Some(system);
    }
    user_config_path().filter(|p| p.is_file())
}

pub fn writable_config_path() -> PathBuf {
    if fs::create_dir_all(SYSTEM_CONFIG_DIR).is_ok() {
        return system_config_path();
    }
    user_config_path().unwrap_or_else(system_config_path)
}

pub fn init_config() -> Result<PathBuf> {
    let path = writable_config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory {}", parent.display()))?;
    }
    let content =
        toml::to_string_pretty(&Config::default()).context("failed to serialize default config")?;
    fs::write(&path, &content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn load_config() -> Result<Config> {
    let path = existing_config_path().with_context(|| {
        format!(
            "no configuration found (looked in {} and the per-user config directory); run `cortado init` to create one",
            system_config_path().display()
        )
    })?;
    read_config(&path)
}

pub fn reload_config() -> Result<Config> {
    let path = existing_config_path().context("configuration file disappeared during reload")?;
    read_config(&path)
}

fn read_config(path: &Path) -> Result<Config> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))?;
    cfg.validate()?;
    Ok(cfg)
}

async fn probe_proxy(proxy: &ProxyConfig) -> Result<()> {
    tokio::time::timeout(proxy.connect_timeout, TcpStream::connect(proxy.addr))
        .await
        .context("timed out connecting to SOCKS5 proxy")?
        .context("cannot reach SOCKS5 proxy")?;
    Ok(())
}

async fn bridge_tun_to_stack<D: TunDevice>(tun: D, stack: netstack_smoltcp::Stack, mtu: usize) {
    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut tun_rx, mut tun_tx) = tokio::io::split(tun);

    let downlink = tokio::spawn(async move {
        while let Some(item) = stack_stream.next().await {
            match item {
                Ok(pkt) => {
                    if tun_tx.write_all(&pkt).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; mtu];
        loop {
            match tun_rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stack_sink.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let _ = tokio::join!(downlink, uplink);
}

async fn relay_tcp_connection(
    mut inbound: netstack_smoltcp::TcpStream,
    src: SocketAddr,
    dst: SocketAddr,
    proxy: Arc<ProxyConfig>,
    routes: Arc<net::RouteTable>,
    log: Arc<Logger>,
    buf_size: usize,
) {
    stats::inc(&stats::TCP_OPENED);
    let _active = stats::GaugeGuard::new(&stats::TCP_ACTIVE);
    match routes.decide(dst.ip()) {
        net::RouteDecision::Direct => stats::inc(&stats::ROUTE_DIRECT),
        net::RouteDecision::Proxy => stats::inc(&stats::ROUTE_PROXY),
    }
    log.debug(|| format!("tcp {src} -> {dst}"));

    let outbound = match socks::tcp_connect(&proxy, dst).await {
        Ok(s) => s,
        Err(e) => {
            stats::inc(&stats::TCP_CLOSED);
            stats::inc(&stats::TCP_ERRORS);
            stats::inc(&stats::CONN_FAILURES);
            if is_handshake_failure(&e) {
                stats::inc(&stats::SOCKS_HANDSHAKE_FAILURES);
            }
            log.debug(|| format!("tcp {src} -> {dst} connect failed: {e}"));
            return;
        }
    };

    let mut outbound = outbound;
    let result = copy_bidirectional_with_sizes(&mut inbound, &mut outbound, buf_size, buf_size)
        .await
        .context("relay I/O error");

    stats::inc(&stats::TCP_CLOSED);
    match result {
        Ok((tx, rx)) => {
            stats::add(&stats::BYTES_TX, tx);
            stats::add(&stats::BYTES_RX, rx);
            stats::record_traffic(dst.ip(), tx + rx);
        }
        Err(e) => {
            stats::inc(&stats::TCP_ERRORS);
            log.debug(|| format!("tcp {src} -> {dst} ended: {e}"));
        }
    }
}

fn is_handshake_failure(err: &anyhow::Error) -> bool {
    let text = format!("{err:#}").to_lowercase();
    text.contains("socks") || text.contains("authentication") || text.contains("handshake")
}

async fn run_stats_reporter(log: Arc<Logger>) {
    let mut interval = tokio::time::interval(Duration::from_secs(STATS_INTERVAL_SECS));
    interval.tick().await;
    loop {
        interval.tick().await;
        log.info(format!(
            "stats: tcp_active={} tcp_open={} tcp_err={} udp_active={} udp_pkts={} udp_err={} dns_req={} dns_fail={} tx={} rx={}",
            stats::get(&stats::TCP_ACTIVE),
            stats::get(&stats::TCP_OPENED),
            stats::get(&stats::TCP_ERRORS),
            stats::get(&stats::UDP_ACTIVE),
            stats::get(&stats::UDP_PACKETS),
            stats::get(&stats::UDP_ERRORS),
            stats::get(&stats::DNS_REQUESTS),
            stats::get(&stats::DNS_FAILURES),
            stats::format_bytes(stats::get(&stats::BYTES_TX)),
            stats::format_bytes(stats::get(&stats::BYTES_RX)),
        ));
    }
}

pub async fn run(cfg: Config, log: Arc<Logger>) -> Result<()> {
    let tuning = tune::Tuning::compute(&tune::probe().await);
    log.info(tuning.summary());

    let proxy = Arc::new(ProxyConfig::from_config(&cfg));

    probe_proxy(&proxy).await?;
    log.info(format!("SOCKS5 proxy reachable at {}", proxy.addr));

    let device = platform::active::create_tun(&cfg, tuning.mtu)?;
    let tun_name = device.name().to_string();
    log.info(format!(
        "TUN interface {} up at {} mtu {}",
        tun_name,
        cfg.tun_ip,
        device.mtu()
    ));

    let mut route_manager = platform::active::new_route_controller(
        &cfg,
        proxy.addr.ip(),
        &tun_name,
        tuning.capture_ipv6,
    )
    .await?;
    route_manager.apply(&log).await?;
    log.info("routing configured automatically");

    let relay_copy_buf_size = tuning.relay_copy_buf_size;

    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .stack_buffer_size(tuning.stack_buf_size)
        .tcp_buffer_size(tuning.relay_buf_size)
        .udp_buffer_size(tuning.relay_buf_size)
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(false)
        .mtu(tuning.mtu as usize)
        .build()
        .context("failed to build netstack")?;

    if let Some(r) = runner {
        tokio::spawn(r);
    }

    let mut tcp_listener = tcp_listener.context("TCP listener missing while TCP enabled")?;
    let udp_socket = udp_socket.context("UDP socket missing while UDP enabled")?;

    let bridge_handle = tokio::spawn(bridge_tun_to_stack(device, stack, tuning.mtu as usize));

    let routes = Arc::new(net::RouteTable::new(cfg.bypass_routes()));
    let shared = Arc::new(reload::Shared::new(Arc::clone(&proxy), routes));
    let dns_pool = Arc::new(dns::DnsPool::new(
        Arc::clone(&proxy),
        proxy.connect_timeout,
        tuning.udp_idle_timeout,
    ));

    let tcp_semaphore = Arc::new(Semaphore::new(tuning.max_tcp_connections));
    let shared_for_tcp = Arc::clone(&shared);
    let log_for_tcp = Arc::clone(&log);
    let tcp_handle = tokio::spawn(async move {
        while let Some((stream, src, dst)) = tcp_listener.next().await {
            let permit = match Arc::clone(&tcp_semaphore).acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let proxy = shared_for_tcp.proxy();
            let routes = shared_for_tcp.routes();
            let log = Arc::clone(&log_for_tcp);
            tokio::spawn(async move {
                let _permit = permit;
                relay_tcp_connection(stream, src, dst, proxy, routes, log, relay_copy_buf_size)
                    .await;
            });
        }
        log_for_tcp.warn("TCP listener closed unexpectedly");
    });

    let (udp_read, udp_write) = udp_socket.split();
    let mut udp_task = tokio::spawn(udp::run_udp(
        udp_read,
        udp_write,
        Arc::clone(&shared),
        Arc::clone(&dns_pool),
        Arc::clone(&log),
        udp::UdpOptions {
            idle_timeout: tuning.udp_idle_timeout,
            max_sessions: tuning.max_udp_sessions,
            dns_over_tcp: cfg.dns_over_tcp,
        },
    ));

    let stats_handle = tokio::spawn(run_stats_reporter(Arc::clone(&log)));

    let metrics_handle = cfg
        .metrics_socket_addr()
        .map(|addr| tokio::spawn(metrics::serve(addr, Arc::clone(&log))));

    let mut shutdown_signal = ShutdownSignal::new()?;
    let mut reload_signal = ReloadSignal::new()?;

    let mut current_cfg = cfg;

    loop {
        tokio::select! {
            _ = &mut udp_task => {
                log.warn("UDP task exited unexpectedly");
                break;
            }
            _ = shutdown_signal.recv() => {
                log.info("shutting down");
                break;
            }
            _ = reload_signal.recv() => {
                apply_reload(&mut current_cfg, &mut route_manager, &shared, &dns_pool, &log).await;
            }
        }
    }

    udp_task.abort();
    bridge_handle.abort();
    tcp_handle.abort();
    stats_handle.abort();
    if let Some(h) = metrics_handle {
        h.abort();
    }

    route_manager.teardown(&log).await;
    Ok(())
}

#[cfg(unix)]
struct ShutdownSignal {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}
#[cfg(not(unix))]
struct ShutdownSignal;

impl ShutdownSignal {
    #[cfg(unix)]
    fn new() -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())
                .context("failed to install SIGINT handler")?,
            terminate: signal(SignalKind::terminate())
                .context("failed to install SIGTERM handler")?,
        })
    }

    #[cfg(not(unix))]
    fn new() -> Result<Self> {
        Ok(Self)
    }

    #[cfg(unix)]
    async fn recv(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    async fn recv(&mut self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(unix)]
struct ReloadSignal(tokio::signal::unix::Signal);
#[cfg(not(unix))]
struct ReloadSignal;

impl ReloadSignal {
    #[cfg(unix)]
    fn new() -> Result<Self> {
        let sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .context("failed to install SIGHUP handler")?;
        Ok(Self(sig))
    }

    #[cfg(not(unix))]
    fn new() -> Result<Self> {
        Ok(Self)
    }

    #[cfg(unix)]
    async fn recv(&mut self) {
        self.0.recv().await;
    }

    #[cfg(not(unix))]
    async fn recv(&mut self) {
        std::future::pending::<()>().await;
    }
}

async fn apply_reload<R: RouteController>(
    current_cfg: &mut Config,
    route_manager: &mut R,
    shared: &Arc<reload::Shared>,
    dns_pool: &Arc<dns::DnsPool>,
    log: &Arc<Logger>,
) {
    let new_cfg = match reload_config() {
        Ok(c) => c,
        Err(e) => {
            log.error(format!("reload: invalid config, keeping current: {e:#}"));
            return;
        }
    };

    let immutable = reload::immutable_changes(current_cfg, &new_cfg);
    if !immutable.is_empty() {
        log.warn(format!(
            "reload: these fields require a restart and were not applied: {}",
            immutable.join(", ")
        ));
    }

    let plan = reload::ReloadPlan::compute(current_cfg, &new_cfg);
    if plan.is_noop() {
        log.info("reload: no effective changes");
        *current_cfg = new_cfg;
        return;
    }

    if let Err(e) = route_manager.reload(&plan, log).await {
        log.error(format!("reload: route update failed, partial state: {e:#}"));
        return;
    }

    let new_proxy = Arc::new(plan.proxy.clone());
    shared.store_proxy(Arc::clone(&new_proxy));
    shared.store_routes(Arc::new(plan.route_table.clone()));
    if plan.proxy_changed {
        dns_pool.set_proxy(new_proxy).await;
    }
    stats::inc(&stats::CONFIG_RELOADS);
    *current_cfg = new_cfg;
    log.info("configuration reloaded");
}

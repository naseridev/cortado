use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::udp::{ReadHalf, UdpMsg, WriteHalf};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, mpsc};

use crate::config::ProxyConfig;
use crate::dns::DnsPool;
use crate::logging::Logger;
use crate::reload::Shared;
use crate::socks;
use crate::stats;

const MAX_DATAGRAM: usize = 65535;
const REPLY_CHANNEL_DEPTH: usize = 2048;
const SESSION_CHANNEL_DEPTH: usize = 256;
const DONE_CHANNEL_DEPTH: usize = 256;
const DNS_PORT: u16 = 53;
const DNS_PRUNE_INTERVAL_SECS: u64 = 30;

struct Session {
    outbound: mpsc::Sender<(SocketAddr, Vec<u8>)>,
}

pub struct UdpOptions {
    pub idle_timeout: Duration,
    pub max_sessions: usize,
    pub dns_over_tcp: bool,
}

pub async fn run_udp(
    mut udp_rx: ReadHalf,
    udp_tx: WriteHalf,
    shared: Arc<Shared>,
    dns_pool: Arc<DnsPool>,
    log: Arc<Logger>,
    opts: UdpOptions,
) {
    let UdpOptions {
        idle_timeout,
        max_sessions,
        dns_over_tcp,
    } = opts;
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpMsg>(REPLY_CHANNEL_DEPTH);

    let mut sink = udp_tx;
    let writer = tokio::spawn(async move {
        while let Some(msg) = reply_rx.recv().await {
            let bytes = msg.0.len() as u64;
            let remote = msg.1;
            if sink.send(msg).await.is_err() {
                break;
            }
            stats::add(&stats::BYTES_RX, bytes);
            stats::record_traffic(remote.ip(), bytes);
        }
    });

    let (done_tx, mut done_rx) = mpsc::channel::<SocketAddr>(DONE_CHANNEL_DEPTH);
    let mut sessions: HashMap<SocketAddr, Session> = HashMap::new();
    let dns_limit = Arc::new(Semaphore::new(max_sessions));

    let prune_pool = Arc::clone(&dns_pool);
    let pruner = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(DNS_PRUNE_INTERVAL_SECS));
        interval.tick().await;
        loop {
            interval.tick().await;
            prune_pool.prune().await;
        }
    });

    loop {
        tokio::select! {
            biased;

            Some(dead) = done_rx.recv() => {
                if let Some(existing) = sessions.get(&dead)
                    && existing.outbound.is_closed()
                {
                    sessions.remove(&dead);
                }
            }

            item = udp_rx.next() => {
                let Some((payload, src, dst)) = item else {
                    break;
                };

                stats::inc(&stats::UDP_PACKETS);
                stats::add(&stats::BYTES_TX, payload.len() as u64);
                stats::record_traffic(dst.ip(), payload.len() as u64);

                if dns_over_tcp && dst.port() == DNS_PORT {
                    match Arc::clone(&dns_limit).try_acquire_owned() {
                        Ok(permit) => {
                            tokio::spawn(dns_query_pooled(
                                permit,
                                Arc::clone(&dns_pool),
                                dst,
                                src,
                                payload,
                                reply_tx.clone(),
                                Arc::clone(&log),
                            ));
                        }
                        Err(_) => {
                            stats::inc(&stats::UDP_ERRORS);
                            stats::inc(&stats::DNS_FAILURES);
                            log.debug(|| format!("dns concurrency limit reached, dropping {src}"));
                        }
                    }
                    continue;
                }

                let live = sessions
                    .get(&src)
                    .map(|s| !s.outbound.is_closed())
                    .unwrap_or(false);

                if !live {
                    if sessions.len() >= max_sessions {
                        stats::inc(&stats::UDP_ERRORS);
                        log.debug(|| format!("udp session limit reached, dropping {src}"));
                        continue;
                    }
                    let session = spawn_session(
                        src,
                        shared.proxy(),
                        reply_tx.clone(),
                        done_tx.clone(),
                        Arc::clone(&log),
                        idle_timeout,
                    );
                    sessions.insert(src, session);
                }

                if let Some(session) = sessions.get(&src)
                    && session.outbound.try_send((dst, payload)).is_err()
                {
                    stats::inc(&stats::UDP_ERRORS);
                }
            }
        }
    }

    pruner.abort();
    drop(reply_tx);
    drop(done_tx);
    sessions.clear();
    let _ = writer.await;
}

fn spawn_session(
    src: SocketAddr,
    proxy: Arc<ProxyConfig>,
    reply_tx: mpsc::Sender<UdpMsg>,
    done_tx: mpsc::Sender<SocketAddr>,
    log: Arc<Logger>,
    idle_timeout: Duration,
) -> Session {
    let (otx, orx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(SESSION_CHANNEL_DEPTH);
    tokio::spawn(async move {
        let _active = stats::GaugeGuard::new(&stats::UDP_ACTIVE);
        if let Err(e) = session_task(src, &proxy, orx, &reply_tx, idle_timeout).await {
            stats::inc(&stats::UDP_ERRORS);
            log.debug(|| format!("udp session {src} ended: {e}"));
        }
        let _ = done_tx.send(src).await;
    });
    Session { outbound: otx }
}

async fn session_task(
    src: SocketAddr,
    proxy: &ProxyConfig,
    mut orx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    reply_tx: &mpsc::Sender<UdpMsg>,
    idle_timeout: Duration,
) -> Result<()> {
    let (mut control, relay) = socks::udp_associate(proxy).await?;

    let bind_addr: SocketAddr = if relay.is_ipv4() {
        "0.0.0.0:0".parse().expect("static literal")
    } else {
        "[::]:0".parse().expect("static literal")
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .context("failed to bind local UDP socket")?;
    socket
        .connect(relay)
        .await
        .context("failed to connect local UDP socket to relay")?;

    let mut recv_buf = vec![0u8; MAX_DATAGRAM];
    let mut enc_buf: Vec<u8> = Vec::with_capacity(2048);
    let mut control_buf = [0u8; 256];

    loop {
        tokio::select! {
            outbound = orx.recv() => {
                let Some((dst, payload)) = outbound else {
                    return Ok(());
                };
                socks::encode_udp(dst, &payload, &mut enc_buf);
                socket
                    .send(&enc_buf)
                    .await
                    .context("failed to send datagram to relay")?;
            }

            received = socket.recv(&mut recv_buf) => {
                let n = received.context("failed to receive datagram from relay")?;
                if let Some((remote, data)) = socks::decode_udp(&recv_buf[..n])
                    && reply_tx.send((data.to_vec(), remote, src)).await.is_err()
                {
                    return Ok(());
                }
            }

            control_read = control.read(&mut control_buf) => {
                match control_read {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(e) => return Err(e).context("SOCKS5 control connection error"),
                }
            }

            _ = tokio::time::sleep(idle_timeout) => {
                return Ok(());
            }
        }
    }
}

async fn dns_query_pooled(
    _permit: tokio::sync::OwnedSemaphorePermit,
    pool: Arc<DnsPool>,
    dst: SocketAddr,
    src: SocketAddr,
    query: Vec<u8>,
    reply_tx: mpsc::Sender<UdpMsg>,
    log: Arc<Logger>,
) {
    stats::inc(&stats::DNS_REQUESTS);
    match pool.resolve(dst, &query).await {
        Ok(resp) => {
            let _ = reply_tx.send((resp, dst, src)).await;
        }
        Err(e) => {
            stats::inc(&stats::UDP_ERRORS);
            stats::inc(&stats::DNS_FAILURES);
            log.debug(|| format!("dns {src} -> {dst} failed: {e}"));
        }
    }
}

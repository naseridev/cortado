use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{Mutex, oneshot};
use tokio::time::{Instant, timeout};

use crate::config::ProxyConfig;
use crate::socks;
use crate::stats;

const MAX_INFLIGHT_PER_CONN: usize = 256;
const MAX_CONNS_PER_TARGET: usize = 8;
const MAX_DNS_MESSAGE: usize = 65535;

enum Outcome {
    Ok(Vec<u8>),
    Retry(anyhow::Error),
    Fatal(anyhow::Error),
}

type Inflight = Arc<Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>>;

struct Conn {
    writer: Mutex<OwnedWriteHalf>,
    inflight: Inflight,
    next_id: AtomicU64,
    alive: Arc<AtomicBool>,
    last_used: Mutex<Instant>,
}

impl Conn {
    async fn allocate_id(&self) -> Option<u16> {
        let mut guard = self.inflight.lock().await;
        if guard.len() >= MAX_INFLIGHT_PER_CONN {
            return None;
        }
        for _ in 0..=u16::MAX as u64 {
            let candidate = (self.next_id.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
            if let std::collections::hash_map::Entry::Vacant(slot) = guard.entry(candidate) {
                let (tx, _rx) = oneshot::channel();
                slot.insert(tx);
                return Some(candidate);
            }
        }
        None
    }
}

pub struct DnsPool {
    proxy: ArcSwap<ProxyConfig>,
    query_timeout: Duration,
    idle_timeout: Duration,
    conns: Mutex<HashMap<SocketAddr, Vec<Arc<Conn>>>>,
    open_lock: Mutex<()>,
}

impl DnsPool {
    pub fn new(proxy: Arc<ProxyConfig>, query_timeout: Duration, idle_timeout: Duration) -> Self {
        Self {
            proxy: ArcSwap::from(proxy),
            query_timeout,
            idle_timeout,
            conns: Mutex::new(HashMap::new()),
            open_lock: Mutex::new(()),
        }
    }

    pub async fn set_proxy(&self, proxy: Arc<ProxyConfig>) {
        self.proxy.store(proxy);
        let mut map = self.conns.lock().await;
        for bucket in map.values() {
            for conn in bucket {
                conn.alive.store(false, Ordering::Relaxed);
            }
        }
        map.clear();
    }

    async fn open_conn(&self, server: SocketAddr) -> Result<Arc<Conn>> {
        let proxy = self.proxy.load_full();
        let stream = socks::tcp_connect(&proxy, server)
            .await
            .context("failed to open pooled DNS connection")?;
        let (mut reader, writer) = stream.into_split();
        let inflight: Inflight = Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));

        let reader_inflight = Arc::clone(&inflight);
        let reader_alive = Arc::clone(&alive);
        let idle = self.idle_timeout;
        tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            loop {
                match timeout(idle, reader.read_exact(&mut len_buf)).await {
                    Err(_) => {
                        if reader_inflight.lock().await.is_empty() {
                            break;
                        }
                    }
                    Ok(Err(_)) | Ok(Ok(0)) => break,
                    Ok(Ok(_)) => {
                        let len = u16::from_be_bytes(len_buf) as usize;
                        if len < 2 {
                            break;
                        }
                        let mut body = vec![0u8; len];
                        if reader.read_exact(&mut body).await.is_err() {
                            break;
                        }
                        let id = u16::from_be_bytes([body[0], body[1]]);
                        if let Some(tx) = reader_inflight.lock().await.remove(&id) {
                            let _ = tx.send(body);
                        }
                    }
                }
            }
            reader_alive.store(false, Ordering::Relaxed);
            reader_inflight.lock().await.clear();
        });

        Ok(Arc::new(Conn {
            writer: Mutex::new(writer),
            inflight,
            next_id: AtomicU64::new(0),
            alive,
            last_used: Mutex::new(Instant::now()),
        }))
    }

    async fn try_reuse(&self, server: SocketAddr) -> Option<(Arc<Conn>, u16, bool)> {
        let mut map = self.conns.lock().await;
        let bucket = map.entry(server).or_default();
        bucket.retain(|c| c.alive.load(Ordering::Relaxed));
        for conn in bucket.iter() {
            if let Some(id) = conn.allocate_id().await {
                stats::inc(&stats::DNS_POOL_HITS);
                return Some((Arc::clone(conn), id, true));
            }
        }
        None
    }

    async fn acquire(&self, server: SocketAddr) -> Result<(Arc<Conn>, u16, bool)> {
        if let Some(r) = self.try_reuse(server).await {
            return Ok(r);
        }

        let _open = self.open_lock.lock().await;
        if let Some(r) = self.try_reuse(server).await {
            return Ok(r);
        }

        {
            let mut map = self.conns.lock().await;
            let bucket = map.entry(server).or_default();
            bucket.retain(|c| c.alive.load(Ordering::Relaxed));
            if bucket.len() >= MAX_CONNS_PER_TARGET {
                bail!("DNS connection pool exhausted for {server}");
            }
        }

        let conn = self.open_conn(server).await?;
        let id = conn
            .allocate_id()
            .await
            .context("freshly opened DNS connection rejected allocation")?;
        let mut map = self.conns.lock().await;
        map.entry(server).or_default().push(Arc::clone(&conn));
        stats::inc(&stats::DNS_POOL_MISSES);
        Ok((conn, id, false))
    }

    pub async fn resolve(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
        if query.len() < 12 {
            bail!("DNS query too short");
        }
        if query.len() > MAX_DNS_MESSAGE {
            bail!("DNS query too large");
        }
        let original_id = [query[0], query[1]];

        let mut last_err = None;
        for attempt in 0..2 {
            match self.attempt(server, query, original_id, attempt > 0).await {
                Outcome::Ok(resp) => return Ok(resp),
                Outcome::Retry(e) => last_err = Some(e),
                Outcome::Fatal(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DNS resolution failed")))
    }

    async fn attempt(
        &self,
        server: SocketAddr,
        query: &[u8],
        original_id: [u8; 2],
        force_new: bool,
    ) -> Outcome {
        let acquired = if force_new {
            self.open_and_register(server).await
        } else {
            self.acquire(server).await
        };
        let (conn, id, _reused) = match acquired {
            Ok(v) => v,
            Err(e) => return Outcome::Retry(e),
        };

        let (tx, rx) = oneshot::channel();
        conn.inflight.lock().await.insert(id, tx);

        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
        let id_bytes = id.to_be_bytes();
        framed[2] = id_bytes[0];
        framed[3] = id_bytes[1];

        let write_result = {
            let mut w = conn.writer.lock().await;
            w.write_all(&framed).await
        };
        if let Err(e) = write_result {
            conn.alive.store(false, Ordering::Relaxed);
            conn.inflight.lock().await.remove(&id);
            return Outcome::Retry(anyhow::Error::from(e).context("failed to write DNS query"));
        }
        *conn.last_used.lock().await = Instant::now();

        match timeout(self.query_timeout, rx).await {
            Ok(Ok(mut resp)) => {
                resp[0] = original_id[0];
                resp[1] = original_id[1];
                Outcome::Ok(resp)
            }
            Ok(Err(_)) => {
                conn.inflight.lock().await.remove(&id);
                Outcome::Retry(anyhow::anyhow!("pooled DNS connection closed before reply"))
            }
            Err(_) => {
                conn.inflight.lock().await.remove(&id);
                Outcome::Fatal(anyhow::anyhow!("pooled DNS query timed out"))
            }
        }
    }

    async fn open_and_register(&self, server: SocketAddr) -> Result<(Arc<Conn>, u16, bool)> {
        let _open = self.open_lock.lock().await;
        let conn = self.open_conn(server).await?;
        let id = conn
            .allocate_id()
            .await
            .context("freshly opened DNS connection rejected allocation")?;
        let mut map = self.conns.lock().await;
        map.entry(server).or_default().push(Arc::clone(&conn));
        stats::inc(&stats::DNS_POOL_MISSES);
        Ok((conn, id, false))
    }

    pub async fn prune(&self) {
        let now = Instant::now();
        let idle = self.idle_timeout;
        let mut map = self.conns.lock().await;
        for bucket in map.values_mut() {
            let mut keep = Vec::with_capacity(bucket.len());
            for conn in bucket.drain(..) {
                if !conn.alive.load(Ordering::Relaxed) {
                    continue;
                }
                let last = *conn.last_used.lock().await;
                let empty = conn.inflight.lock().await.is_empty();
                if empty && now.duration_since(last) > idle {
                    conn.alive.store(false, Ordering::Relaxed);
                    continue;
                }
                keep.push(conn);
            }
            *bucket = keep;
        }
        map.retain(|_, v| !v.is_empty());
    }

    pub async fn conn_count(&self) -> usize {
        self.conns.lock().await.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn proxy_for(addr: SocketAddr) -> Arc<ProxyConfig> {
        Arc::new(ProxyConfig {
            addr,
            username: None,
            password: None,
            connect_timeout: Duration::from_secs(5),
            tcp_nodelay: true,
        })
    }

    fn dns_message(id: u16, marker: u8) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[0..2].copy_from_slice(&id.to_be_bytes());
        m.push(marker);
        m
    }

    async fn mock_socks_dns_server(listener: TcpListener) {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                if stream.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; head[1] as usize];
                let _ = stream.read_exact(&mut methods).await;
                let _ = stream.write_all(&[0x05, 0x00]).await;

                let mut req = [0u8; 4];
                if stream.read_exact(&mut req).await.is_err() {
                    return;
                }
                let skip = match req[3] {
                    0x01 => 6,
                    0x04 => 18,
                    _ => return,
                };
                let mut rest = vec![0u8; skip];
                let _ = stream.read_exact(&mut rest).await;
                let _ = stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;

                loop {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut body = vec![0u8; len];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let mut resp = Vec::with_capacity(len + 2);
                    resp.extend_from_slice(&(len as u16).to_be_bytes());
                    resp.extend_from_slice(&body);
                    if stream.write_all(&resp).await.is_err() {
                        return;
                    }
                }
            });
        }
    }

    #[tokio::test]
    async fn resolve_echoes_and_preserves_id() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(mock_socks_dns_server(listener));

        let pool = DnsPool::new(
            proxy_for(proxy_addr),
            Duration::from_secs(5),
            Duration::from_secs(30),
        );
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let query = dns_message(0xABCD, 0x11);
        let resp = pool.resolve(server, &query).await.unwrap();
        assert_eq!(&resp[0..2], &0xABCDu16.to_be_bytes());
        assert_eq!(resp[12], 0x11);
    }

    #[tokio::test]
    async fn reuses_single_connection_for_sequential_queries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(mock_socks_dns_server(listener));

        let pool = DnsPool::new(
            proxy_for(proxy_addr),
            Duration::from_secs(5),
            Duration::from_secs(30),
        );
        let server: SocketAddr = "1.1.1.1:53".parse().unwrap();
        for i in 0..10u16 {
            let q = dns_message(i, i as u8);
            let r = pool.resolve(server, &q).await.unwrap();
            assert_eq!(&r[0..2], &i.to_be_bytes());
        }
        assert_eq!(pool.conn_count().await, 1);
    }

    #[tokio::test]
    async fn concurrent_queries_multiplex() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(mock_socks_dns_server(listener));

        let pool = Arc::new(DnsPool::new(
            proxy_for(proxy_addr),
            Duration::from_secs(5),
            Duration::from_secs(30),
        ));
        let server: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let mut handles = Vec::new();
        for i in 0..50u16 {
            let pool = Arc::clone(&pool);
            handles.push(tokio::spawn(async move {
                let q = dns_message(i, (i % 256) as u8);
                let r = pool.resolve(server, &q).await.unwrap();
                assert_eq!(&r[0..2], &i.to_be_bytes());
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(pool.conn_count().await <= MAX_CONNS_PER_TARGET);
    }

    #[tokio::test]
    async fn rejects_short_query() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(mock_socks_dns_server(listener));
        let pool = DnsPool::new(
            proxy_for(proxy_addr),
            Duration::from_secs(5),
            Duration::from_secs(30),
        );
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        assert!(pool.resolve(server, &[0u8; 4]).await.is_err());
    }

    async fn mock_socks_dns_oneshot(listener: TcpListener) {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                if stream.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; head[1] as usize];
                let _ = stream.read_exact(&mut methods).await;
                let _ = stream.write_all(&[0x05, 0x00]).await;
                let mut req = [0u8; 4];
                if stream.read_exact(&mut req).await.is_err() {
                    return;
                }
                let skip = match req[3] {
                    0x01 => 6,
                    0x04 => 18,
                    _ => return,
                };
                let mut rest = vec![0u8; skip];
                let _ = stream.read_exact(&mut rest).await;
                let _ = stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                if stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                let mut resp = Vec::with_capacity(len + 2);
                resp.extend_from_slice(&(len as u16).to_be_bytes());
                resp.extend_from_slice(&body);
                let _ = stream.write_all(&resp).await;
                let _ = stream.shutdown().await;
            });
        }
    }

    #[tokio::test]
    async fn recovers_after_connection_drop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(mock_socks_dns_oneshot(listener));

        let pool = DnsPool::new(
            proxy_for(proxy_addr),
            Duration::from_secs(5),
            Duration::from_secs(30),
        );
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let r1 = pool.resolve(server, &dns_message(1, 0xAA)).await.unwrap();
        assert_eq!(&r1[0..2], &1u16.to_be_bytes());

        tokio::time::sleep(Duration::from_millis(50)).await;

        let r2 = pool.resolve(server, &dns_message(2, 0xBB)).await.unwrap();
        assert_eq!(&r2[0..2], &2u16.to_be_bytes());
        assert_eq!(r2[12], 0xBB);
    }

    #[tokio::test]
    async fn set_proxy_invalidates_and_reroutes() {
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        tokio::spawn(mock_socks_dns_server(listener_a));
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        tokio::spawn(mock_socks_dns_server(listener_b));

        let pool = DnsPool::new(
            proxy_for(addr_a),
            Duration::from_secs(5),
            Duration::from_secs(30),
        );
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        pool.resolve(server, &dns_message(1, 1)).await.unwrap();
        assert_eq!(pool.conn_count().await, 1);

        pool.set_proxy(proxy_for(addr_b)).await;
        assert_eq!(pool.conn_count().await, 0);

        let r = pool.resolve(server, &dns_message(2, 2)).await.unwrap();
        assert_eq!(&r[0..2], &2u16.to_be_bytes());
        assert_eq!(pool.conn_count().await, 1);
    }

    #[tokio::test]
    async fn prune_drops_idle_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(mock_socks_dns_server(listener));
        let pool = DnsPool::new(
            proxy_for(proxy_addr),
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let q = dns_message(1, 1);
        pool.resolve(server, &q).await.unwrap();
        assert_eq!(pool.conn_count().await, 1);
        tokio::time::sleep(Duration::from_millis(40)).await;
        pool.prune().await;
        assert_eq!(pool.conn_count().await, 0);
    }
}

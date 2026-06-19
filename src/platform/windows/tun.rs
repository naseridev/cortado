use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result, bail};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::config::Config;
use crate::platform::TunDevice;

const RING_CAPACITY: u32 = 0x40_0000;
const CHANNEL_DEPTH: usize = 4096;

pub struct WindowsTun {
    name: String,
    mtu: u32,
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::UnboundedSender<Vec<u8>>,
    pending: Option<(Vec<u8>, usize)>,
    _adapter: Arc<wintun::Adapter>,
    _session: Arc<wintun::Session>,
}

fn configure_interface(name: &str, cfg: &Config, mtu: u32) -> Result<()> {
    let status = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "address",
            &format!("name={name}"),
            "static",
            &cfg.tun_ip,
            "255.255.255.0",
        ])
        .status()
        .context("failed to run netsh to set address")?;
    if !status.success() {
        bail!("netsh set address exited with {}", status);
    }
    let status = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "subinterface",
            name,
            &format!("mtu={mtu}"),
            "store=active",
        ])
        .status()
        .context("failed to run netsh to set mtu")?;
    if !status.success() {
        bail!("netsh set mtu exited with {}", status);
    }
    Ok(())
}

pub fn create_tun(cfg: &Config, mtu: u32) -> Result<WindowsTun> {
    let wintun = unsafe { wintun::load() }.context("failed to load wintun.dll")?;
    let name = cfg.tun_name.clone();
    let adapter = wintun::Adapter::create(&wintun, &name, "cortado", None)
        .context("failed to create wintun adapter")?;
    let session = Arc::new(
        adapter
            .start_session(RING_CAPACITY)
            .context("failed to start wintun session")?,
    );

    configure_interface(&name, cfg, mtu)?;

    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let reader_session = Arc::clone(&session);
    std::thread::spawn(move || {
        while let Ok(packet) = reader_session.receive_blocking() {
            if in_tx.blocking_send(packet.bytes().to_vec()).is_err() {
                break;
            }
        }
    });

    let writer_session = Arc::clone(&session);
    std::thread::spawn(move || {
        while let Some(buf) = out_rx.blocking_recv() {
            let len = buf.len();
            if len == 0 || len > u16::MAX as usize {
                continue;
            }
            if let Ok(mut packet) = writer_session.allocate_send_packet(len as u16) {
                packet.bytes_mut().copy_from_slice(&buf);
                writer_session.send_packet(packet);
            }
        }
    });

    Ok(WindowsTun {
        name,
        mtu,
        incoming: in_rx,
        outgoing: out_tx,
        pending: None,
        _adapter: adapter,
        _session: session,
    })
}

impl AsyncRead for WindowsTun {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some((pkt, offset)) = this.pending.take() {
            let remaining = &pkt[offset..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            if offset + take < pkt.len() {
                this.pending = Some((pkt, offset + take));
            }
            return Poll::Ready(Ok(()));
        }
        match this.incoming.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => {
                let take = pkt.len().min(buf.remaining());
                buf.put_slice(&pkt[..take]);
                if take < pkt.len() {
                    this.pending = Some((pkt, take));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WindowsTun {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.outgoing.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wintun writer closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl TunDevice for WindowsTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }
}

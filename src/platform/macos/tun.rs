use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result, bail};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::Config;
use crate::platform::TunDevice;

const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
const UTUN_PREFIX: usize = 4;
const MAX_PACKET: usize = 65_536;

pub struct MacosTun {
    fd: AsyncFd<OwnedFd>,
    name: String,
    mtu: u32,
    read_scratch: Vec<u8>,
    write_scratch: Vec<u8>,
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn open_utun(unit: u32) -> Result<(OwnedFd, String)> {
    unsafe {
        let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("failed to open PF_SYSTEM socket");
        }
        let owned = OwnedFd::from_raw_fd(fd);

        let mut info: libc::ctl_info = mem::zeroed();
        let name = UTUN_CONTROL_NAME;
        for (i, b) in name.iter().enumerate() {
            info.ctl_name[i] = *b as libc::c_char;
        }
        if libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) < 0 {
            return Err(io::Error::last_os_error()).context("CTLIOCGINFO ioctl failed");
        }

        let mut addr: libc::sockaddr_ctl = mem::zeroed();
        addr.sc_len = mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar;
        addr.sc_family = libc::AF_SYSTEM as libc::c_uchar;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = unit + 1;

        if libc::connect(
            fd,
            &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error()).context("failed to connect utun control");
        }

        let mut ifname = [0u8; 32];
        let mut ifname_len = ifname.len() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            ifname.as_mut_ptr() as *mut libc::c_void,
            &mut ifname_len,
        ) < 0
        {
            return Err(io::Error::last_os_error()).context("failed to read utun interface name");
        }

        let end = ifname
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(ifname_len as usize);
        let name = String::from_utf8_lossy(&ifname[..end]).into_owned();
        Ok((owned, name))
    }
}

fn run_ifconfig(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("/sbin/ifconfig")
        .args(args)
        .status()
        .context("failed to run ifconfig")?;
    if !status.success() {
        bail!("ifconfig {:?} exited with {}", args, status);
    }
    Ok(())
}

pub fn create_tun(cfg: &Config, mtu: u32) -> Result<MacosTun> {
    let (owned, name) = open_utun(0)?;
    set_nonblocking(owned.as_raw_fd()).context("failed to set utun nonblocking")?;

    let local = cfg.tun_ip.clone();
    run_ifconfig(&[&name, &local, &local, "up"])?;
    run_ifconfig(&[&name, "mtu", &mtu.to_string()])?;

    Ok(MacosTun {
        fd: AsyncFd::new(owned).context("failed to register utun with tokio")?,
        name,
        mtu,
        read_scratch: vec![0u8; UTUN_PREFIX + MAX_PACKET],
        write_scratch: vec![0u8; UTUN_PREFIX + MAX_PACKET],
    })
}

impl AsyncRead for MacosTun {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let raw = this.fd.as_raw_fd();
            let scratch = &mut this.read_scratch;
            let result = guard.try_io(|_| {
                let n = unsafe {
                    libc::read(
                        raw,
                        scratch.as_mut_ptr() as *mut libc::c_void,
                        scratch.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match result {
                Ok(Ok(n)) => {
                    if n > UTUN_PREFIX {
                        let payload = &this.read_scratch[UTUN_PREFIX..n];
                        let take = payload.len().min(buf.remaining());
                        buf.put_slice(&payload[..take]);
                    }
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for MacosTun {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let af: u32 = if buf[0] >> 4 == 6 {
            libc::AF_INET6 as u32
        } else {
            libc::AF_INET as u32
        };
        let total = UTUN_PREFIX + buf.len();
        if total > this.write_scratch.len() {
            this.write_scratch.resize(total, 0);
        }
        this.write_scratch[..UTUN_PREFIX].copy_from_slice(&af.to_be_bytes());
        this.write_scratch[UTUN_PREFIX..total].copy_from_slice(buf);

        loop {
            let mut guard = match this.fd.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let raw = this.fd.as_raw_fd();
            let frame = &this.write_scratch[..total];
            let result = guard.try_io(|_| {
                let n =
                    unsafe { libc::write(raw, frame.as_ptr() as *const libc::c_void, frame.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match result {
                Ok(Ok(_)) => return Poll::Ready(Ok(buf.len())),
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl TunDevice for MacosTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }
}

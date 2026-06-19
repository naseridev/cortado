# Cortado

Cortado is a transparent TUN-to-SOCKS5 tunnel for Linux. It creates a TUN
interface, rewrites the system routing table to funnel traffic through it, runs
a userspace network stack to terminate the captured flows, and relays each
connection out through an upstream SOCKS5 proxy. It is a tun2socks-class
forwarding engine intended for always-on, system-wide proxying.

## Features

- Transparent capture of all IPv4 (and optionally IPv6) traffic via a split
  default route, with configurable bypass CIDRs routed directly.
- TCP relaying over SOCKS5 CONNECT and UDP relaying over RFC 1928 UDP ASSOCIATE.
- DNS relayed over TCP framing, so name resolution works even against proxies
  that do not support UDP.
- Userspace TCP/UDP stack with decoupled relay and socket buffers to bound
  per-connection memory under high connection counts.
- Zero performance tuning: MTU, buffer sizes, connection caps, and IPv6 capture
  are auto-detected from the live system at startup (see
  [Automatic tuning](#automatic-tuning)).
- Live configuration reload on `SIGHUP` for proxy and bypass-route changes.
- Optional Prometheus metrics endpoint.
- Graceful shutdown that restores the routing table and `/etc/resolv.conf`.

## Why use this instead of tun2socks?

If you have already run a tun2socks — whether the classic `badvpn-tun2socks` or
the modern Go [`tun2socks`](https://github.com/xjasonlyu/tun2socks) — you know
the shape of the problem is solved: a TUN device, a userspace stack, packets
relayed out a proxy. Cortado does not claim to reinvent that. What it changes is
everything *around* the forwarding loop — the parts that decide whether an
always-on tunnel is actually stable and fast without you babysitting it.

### Where tun2socks tends to fall short

- **You tune it by hand.** MTU, buffer sizes, and queue depths are flags or
  compile-time constants. The "right" values depend on your link's
  bandwidth-delay product and your host's memory, so getting throughput right is
  trial and error — and the wrong guess shows up as mysterious stalls under
  load, not as an error.
- **Nothing adapts.** Those values are fixed for the life of the process
  regardless of the interface MTU, available RAM, or file-descriptor limits.
  A config that's fine on a laptop silently caps throughput or exhausts memory
  on a busy server (or vice versa).
- **It forwards packets; it doesn't manage the system.** Routing and
  `/etc/resolv.conf` are your job to script before and tear down after. A crash
  or a missed cleanup step leaves the box with split routes and broken DNS, and
  there's no built-in "put it back" path.
- **UDP and DNS need extra moving parts.** `badvpn-tun2socks` needs a separate
  `badvpn-udpgw` helper for UDP at all, and DNS against a proxy that doesn't
  speak UDP is a common failure that you work around externally.
- **You can't see what it's doing.** Logging is sparse and there are no metrics,
  so "is the tunnel healthy and how much is flowing through it" is hard to answer
  without external tooling.

### What Cortado does differently

- **No tuning knobs to get wrong.** MTU is read from the egress interface;
  socket windows, stack queue depth, and copy buffers are derived from that MTU
  and total RAM; connection and UDP-session caps are derived from `RLIMIT_NOFILE`
  (raised to its hard limit) and memory; IPv6 capture switches on only when a v6
  gateway exists. The chosen values are logged once at startup. See
  [Automatic tuning](#automatic-tuning).
- **It owns the system state it touches.** It installs the split-default routes
  and DNS override itself and restores both on `Ctrl-C`/`SIGTERM`. `SIGHUP`
  reloads proxy and bypass changes *without dropping the tunnel*, and the
  recovery steps for a hard kill are documented.
- **UDP and DNS work out of the box.** Full RFC 1928 UDP ASSOCIATE, plus DNS
  relayed over TCP framing so name resolution works even against a UDP-less
  proxy — no side helper.
- **It's observable.** A Prometheus metrics endpoint plus periodic throughput /
  connection / error stats, and structured leveled logs.
- **It stays bounded under load.** Per-connection memory is capped by decoupling
  the relay copy buffer from the socket window, and concurrency is gated by caps
  sized to what the host can actually sustain.

### When switching is worth it

- You have chased `--mtu` and buffer flags to fix throughput and still hit
  stalls on a high-latency or high-bandwidth link.
- Your proxy doesn't support UDP and DNS keeps breaking.
- You run the tunnel always-on, and a crash has at some point left you with
  broken routing or DNS to untangle by hand.
- You operate it on real hosts and need to *see* throughput, active connections,
  and failure counts.
- You're deploying on machines with very different memory / fd limits and don't
  want to hand-pick a connection cap for each.

### When it isn't (be honest)

- **Linux only, today.** The macOS (utun) and Windows (Wintun) seams exist but
  are incomplete; tun2socks variants run on more platforms now.
- **SOCKS5 only.** The Go tun2socks also speaks Shadowsocks, HTTP, and others —
  if you need those upstreams, it's the better fit.
- **Younger and smaller.** `tun2socks` is battle-tested across a huge install
  base. If you already have a tun2socks setup you never touch and never lose DNS
  over, switching buys you little.

## Installation

```sh
cargo build --release
sudo install -m 0755 target/release/cortado /usr/local/bin/cortado
```

Once `cortado` is on your `PATH`, it can be run from anywhere.

## Usage

Cortado mutates global system state (routes and DNS) and `run` must be invoked
as root.

```sh
cortado init            # create or reset the default configuration
sudo cortado run        # start the tunnel (runs in the foreground)
```

Run `cortado init`, edit the generated configuration, then `sudo cortado run`.
The tunnel runs in the foreground; `Ctrl-C` (or `SIGTERM`) triggers a graceful
teardown that restores the routing table and `/etc/resolv.conf`. Sending
`SIGHUP` reloads the proxy and bypass-route settings without a restart.

| Command   | Description                                          |
| --------- | ---------------------------------------------------- |
| `init`    | Create or completely reset the default configuration |
| `run`     | Start the tunnel                                     |

## Configuration

Cortado reads `cortado.conf` (TOML) from the first location that exists:

1. `/etc/cortado/cortado.conf` (system-wide)
2. `$XDG_CONFIG_HOME/cortado/cortado.conf`, falling back to
   `~/.config/cortado/cortado.conf` (per-user)

`cortado init` writes the system-wide file when run as root and the per-user
file otherwise. It always writes a complete default, so it doubles as a reset.

The configuration is deliberately small: it holds only what is specific to *you*
— where your proxy is, your credentials, your DNS preference, and which
destinations to send direct. Everything that affects throughput and stability is
measured and computed at startup (see [Automatic tuning](#automatic-tuning)).

| Key                   | Default          | Description                                        |
| --------------------- | ---------------- | -------------------------------------------------- |
| `proxy_addr`          | `127.0.0.1:1080` | Upstream SOCKS5 proxy (`ip:port`).                 |
| `username`/`password` | unset            | SOCKS5 credentials; set both or neither.           |
| `tun_name`            | `cortado0`       | TUN interface name.                                |
| `tun_ip`              | `10.0.0.1`       | TUN interface address.                             |
| `dns_server`          | `1.1.1.1`        | DNS server written to `/etc/resolv.conf`.          |
| `override_dns`        | `true`           | Whether to rewrite `/etc/resolv.conf`.             |
| `dns_over_tcp`        | `true`           | Relay DNS over TCP framing.                        |
| `bypass_cidrs`        | `[]`             | CIDRs routed directly, bypassing the proxy.        |
| `metrics_addr`        | unset            | Address to serve Prometheus metrics on.            |

After editing the configuration, send `SIGHUP` to apply proxy and bypass-route
changes without restarting; fields that require a restart are reported and left
unchanged. Configuration files from older versions that still contain tuning
keys (`mtu`, `relay_buf_size`, `max_tcp_connections`, …) keep working — those
keys are now ignored in favour of automatic tuning.

## Automatic tuning

Cortado has no buffer-size, MTU, timeout, or connection-cap knobs to get wrong.
At startup it probes real system state and derives the values that govern
throughput and stability:

- **MTU** is read from the egress interface of the default route, so the tunnel
  matches the real outbound path instead of a guessed constant.
- **Socket windows, the userspace stack queue depth, and the per-connection copy
  buffer** are derived from the detected MTU and total system memory — large
  enough to keep high-bandwidth flows from stalling, bounded so they cannot
  exhaust RAM under load.
- **Connection and UDP-session caps** are derived from the file-descriptor
  `RLIMIT_NOFILE` (which Cortado raises to its hard limit) and from memory, so
  the tunnel admits as many flows as the host can actually sustain and no more.
- **IPv6 capture** turns on automatically when — and only when — a default IPv6
  gateway is present, so enabling it can never blackhole v6 on a v4-only host.

The computed values are logged once at startup (`auto-tuned: mtu=… relay_buf=…
max_tcp=… capture_ipv6=…`) so you can see exactly what was chosen.

## Recovery

A hard kill (`SIGKILL`) skips teardown and can leave the system with the split
routes and a modified `/etc/resolv.conf`. To recover, restore the DNS backup
and delete the split-default routes:

```sh
sudo cp /etc/resolv.conf.cortado.bak /etc/resolv.conf
sudo ip route del 0.0.0.0/1
sudo ip route del 128.0.0.0/1
```

## Platform support

**Linux** is the fully supported, exercised target: the TUN device
(`tokio-tun`), routing and link/MTU detection (netlink), and DNS handling
(`/etc/resolv.conf`) are all implemented and tested.

The codebase carries platform seams for **macOS** (utun) and **Windows**
(Wintun) behind a common interface, and they now include the same automatic
tuning detection as Linux — MTU and default-IPv6-gateway discovery via the
platform's native tooling (`route`/`ifconfig` on macOS, `Get-NetRoute` /
`Get-NetIPInterface` on Windows). These seams compile and type-check for their
respective targets, but the backends are **not yet complete or runtime-tested**;
treat them as in-progress. When they are finished they inherit Cortado's
zero-knob auto-tuning unchanged.

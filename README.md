# Cortado
A TUN-to-SOCKS5 tunnel for Linux, macOS, and Windows. Routes all system traffic through a userspace network stack and relays it to an upstream SOCKS5 proxy, with no manual tuning required.

## Installation

```sh
cargo build --release
sudo install -m 0755 target/release/cortado /usr/local/bin/cortado
```

## Usage

Cortado mutates global system state (routes and DNS) and `run` must be invoked as root.

### Init

Initialize or reset the default configuration:

```sh
cortado init
```

Writes the configuration file to `/etc/cortado/cortado.conf` when run as root, or `~/.config/cortado/cortado.conf` otherwise. Always writes a complete default, so it doubles as a reset.

### Run

Start the tunnel:

```sh
sudo cortado run
```

The tunnel runs in the foreground. `Ctrl-C` or `SIGTERM` triggers a graceful teardown that restores the routing table and `/etc/resolv.conf`. Sending `SIGHUP` reloads proxy and bypass-route settings without restarting.

## Technical Implementation

### Architecture

Cortado creates a TUN interface and rewrites the system routing table to funnel all IPv4 (and optionally IPv6) traffic through it. A userspace TCP/UDP stack terminates the captured flows and relays each connection through the upstream SOCKS5 proxy:

- TCP relayed via SOCKS5 CONNECT
- UDP relayed via RFC 1928 UDP ASSOCIATE
- DNS relayed over TCP framing, so name resolution works even against proxies that do not support UDP

Per-connection memory is bounded by decoupling the relay copy buffer from the socket window. Concurrency is gated by caps derived from what the host can actually sustain.

### Automatic Tuning

At startup, Cortado probes live system state and derives all values governing throughput and stability:

- MTU is read from the egress interface of the default route
- Socket windows, stack queue depth, and per-connection copy buffer are derived from the detected MTU and total system memory
- Connection and UDP-session caps are derived from `RLIMIT_NOFILE` (raised to its hard limit) and available memory
- IPv6 capture activates only when a default IPv6 gateway is present

The computed values are logged once at startup (`auto-tuned: mtu=… relay_buf=… max_tcp=… capture_ipv6=…`).

### Configuration Reload

Sending `SIGHUP` applies proxy and bypass-route changes without dropping the tunnel. Fields that require a full restart are reported and left unchanged. Configuration files containing legacy tuning keys (`mtu`, `relay_buf_size`, `max_tcp_connections`, …) remain valid: those keys are now ignored in favour of automatic tuning.

### Recovery

A hard kill (`SIGKILL`) skips teardown and can leave the system with split routes and a modified `/etc/resolv.conf`. To recover:

```sh
sudo cp /etc/resolv.conf.cortado.bak /etc/resolv.conf
sudo ip route del 0.0.0.0/1
sudo ip route del 128.0.0.0/1
```

## Configuration

Cortado reads `cortado.conf` (TOML) from the first location that exists:

1. `/etc/cortado/cortado.conf` (system-wide)
2. `$XDG_CONFIG_HOME/cortado/cortado.conf`, falling back to `~/.config/cortado/cortado.conf` (per-user)

| Key                   | Default          | Description                                        |
| --------------------- | ---------------- | -------------------------------------------------- |
| `proxy_addr`          | `127.0.0.1:1080` | Upstream SOCKS5 proxy (`ip:port`)                  |
| `username`/`password` | unset            | SOCKS5 credentials; set both or neither            |
| `tun_name`            | `cortado0`       | TUN interface name                                 |
| `tun_ip`              | `10.0.0.1`       | TUN interface address                              |
| `dns_server`          | `1.1.1.1`        | DNS server written to `/etc/resolv.conf`           |
| `override_dns`        | `true`           | Whether to rewrite `/etc/resolv.conf`              |
| `dns_over_tcp`        | `true`           | Relay DNS over TCP framing                         |
| `bypass_cidrs`        | `[]`             | CIDRs routed directly, bypassing the proxy         |
| `metrics_addr`        | unset            | Address to serve Prometheus metrics on             |

## Limitations

### Platform Support

- Linux: Fully supported and tested: TUN device (`tokio-tun`), routing and MTU detection (netlink), and DNS handling (`/etc/resolv.conf`) are all implemented
- macOS (utun) and Windows (Wintun): Platform seams exist and compile, but backends are not yet complete or runtime-tested; treat as in-progress

### Security Considerations

- SOCKS5 credentials are stored in plaintext in the configuration file
- No traffic encryption beyond what the upstream proxy provides
- LSB steganography is detectable through statistical analysis
- Password-based SOCKS5 authentication is vulnerable to weak passwords

## Comparison with tun2socks

Cortado is a tun2socks-class forwarding engine. The packet forwarding problem is solved by existing tools: `badvpn-tun2socks` and the Go [`tun2socks`](https://github.com/xjasonlyu/tun2socks) among them. What Cortado changes is everything around the forwarding loop.

### Approach

- tun2socks: Forwards packets; routing, DNS, and teardown are the user's responsibility to script
- Cortado: Owns the system state it touches: installs routes and DNS override itself, restores both on exit, reloads on `SIGHUP`

### Medium

- tun2socks: Statically configured via flags or compile-time constants; values are fixed for the life of the process
- Cortado: All throughput parameters auto-derived from live system state at startup; no tuning flags

### Advantages over tun2socks

- No tuning knobs: MTU, buffer sizes, and connection caps are computed automatically: no trial-and-error for different link conditions
- System state management: Routes and DNS are installed and restored automatically; a crash is recoverable with two commands
- UDP and DNS out of the box: Full RFC 1928 UDP ASSOCIATE plus DNS-over-TCP framing; no `badvpn-udpgw` side helper needed
- Observability: Prometheus metrics endpoint and structured leveled logs; throughput, active connections, and error counts are visible
- Memory bounded under load: Per-connection memory is capped; concurrency is gated to what the host can actually sustain

### Trade-offs

- Maturity: tun2socks has a longer track record on production systems
- Platform coverage: macOS and Windows support is in-progress vs tun2socks being cross-platform today
- Simplicity: Cortado's automatic system management is an implicit contract: it touches routes and DNS that users may want to control manually

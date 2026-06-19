use std::net::{IpAddr, SocketAddr};

use cortado::net::RouteTable;
use cortado::socks::{decode_udp, encode_udp};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

fn build_table() -> RouteTable {
    let mut routes: Vec<(IpAddr, u8)> = Vec::new();
    for i in 0..64u8 {
        routes.push((format!("10.{i}.0.0").parse().unwrap(), 16));
        routes.push((format!("fd00:{i:x}::").parse().unwrap(), 32));
    }
    routes.push(("192.168.0.0".parse().unwrap(), 16));
    RouteTable::new(routes)
}

fn bench_route_lookup(c: &mut Criterion) {
    let table = build_table();
    let hit_v4: IpAddr = "10.40.5.6".parse().unwrap();
    let miss_v4: IpAddr = "8.8.8.8".parse().unwrap();
    let hit_v6: IpAddr = "fd00:20::1".parse().unwrap();
    let miss_v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();

    let mut group = c.benchmark_group("route");
    group.bench_function("lookup_v4_hit", |b| {
        b.iter(|| black_box(table.decide(black_box(hit_v4))))
    });
    group.bench_function("lookup_v4_miss", |b| {
        b.iter(|| black_box(table.decide(black_box(miss_v4))))
    });
    group.bench_function("lookup_v6_hit", |b| {
        b.iter(|| black_box(table.decide(black_box(hit_v6))))
    });
    group.bench_function("lookup_v6_miss", |b| {
        b.iter(|| black_box(table.decide(black_box(miss_v6))))
    });
    group.finish();
}

fn bench_udp_codec(c: &mut Criterion) {
    let target_v4: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let target_v6: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
    let payload = vec![0x41u8; 512];
    let mut buf = Vec::with_capacity(600);

    let mut group = c.benchmark_group("udp_codec");
    group.bench_function("encode_v4", |b| {
        b.iter(|| {
            encode_udp(black_box(target_v4), black_box(&payload), &mut buf);
            black_box(buf.len())
        })
    });
    group.bench_function("encode_v6", |b| {
        b.iter(|| {
            encode_udp(black_box(target_v6), black_box(&payload), &mut buf);
            black_box(buf.len())
        })
    });

    encode_udp(target_v4, &payload, &mut buf);
    let encoded = buf.clone();
    group.bench_function("decode_v4", |b| {
        b.iter(|| black_box(decode_udp(black_box(&encoded))))
    });
    group.finish();
}

fn bench_uplink(c: &mut Criterion) {
    let mtus = [1500usize, 1900, 8500];
    let sizes = [64usize, 576, 1400];

    let mut group = c.benchmark_group("uplink");
    for &mtu in &mtus {
        for &size in &sizes {
            if size > mtu {
                continue;
            }
            let packet = vec![0xABu8; size];
            let label = format!("mtu{mtu}/{size}");
            group.throughput(Throughput::Bytes(size as u64));

            group.bench_with_input(
                BenchmarkId::new("read_into_fresh", &label),
                &packet,
                |b, pkt| {
                    b.iter(|| {
                        let mut buf = Vec::with_capacity(mtu);
                        buf.extend_from_slice(black_box(pkt));
                        black_box(buf)
                    })
                },
            );

            group.bench_with_input(
                BenchmarkId::new("reused_plus_to_vec", &label),
                &packet,
                |b, pkt| {
                    let mut reused = vec![0u8; mtu];
                    b.iter(|| {
                        let n = pkt.len();
                        reused[..n].copy_from_slice(black_box(pkt));
                        black_box(reused[..n].to_vec())
                    })
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_route_lookup, bench_udp_codec, bench_uplink);
criterion_main!(benches);

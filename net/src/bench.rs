//! Datapath microbenchmark (P5 "net-bench").
//!
//! The P1–P5 datapath work targets line rate by cutting the *per-packet
//! software cost* — the work the CPU does for every frame that a hardware
//! offload or a batching stage removes. This module measures that cost
//! directly for the hot operations the phases touch: the L4 checksum (what
//! TX checksum offload removes, P2), software GSO segmentation (the TSO
//! fallback, P2), and software GRO coalescing (the RX batching stage, P3).
//!
//! It is not a pass/fail gate — each case always passes and logs a `NETBENCH`
//! line with the measured ns/packet and the packet-rate / throughput ceiling
//! that cost implies, so a human (or a log scrape) can see where the software
//! path stands and whether a change moved it. Complements `MtEchoBench`, which
//! measures the integrated TCP-over-virtio req/s + latency; this isolates the
//! per-packet primitives. Behind `kernel-test`, so production neither links nor
//! pays for it.
//!
//! The derived rates assume the measured op is the *only* per-packet cost, so
//! they are an upper bound on what that primitive alone would allow — useful
//! for comparing before/after and for spotting which primitive is the ceiling,
//! not as an end-to-end throughput claim.

extern crate alloc;

use alloc::vec::Vec;

use narf_console::klog;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_scheduler::narf_time::{cycles_to_ns, now_cycles};

use crate::pkt::{set_ipv4_checksum, ETH_HDR_LEN, IPV4_HDR_LEN, IP_PROTO_TCP};
use crate::pkt_tcp::{ipv4_pseudo_checksum, FLAG_ACK, TCP_HDR_MIN};

const MSS: usize = 1448;

/// Log one benchmark result: the elapsed time, the per-packet cost, and the
/// packet-rate / bitrate ceiling `packets` of `bytes_each` imply.
fn report(name: &str, packets: u64, bytes_each: usize, cycles: u64) {
    let ns = cycles_to_ns(cycles).max(1);
    let ns_per_pkt = ns / packets.max(1);
    // packets / ns → packets/s; /1e6 → Mpps (×1000 first for 3 decimals).
    let mpps_milli = packets.saturating_mul(1_000_000_000) / ns * 1000 / 1_000_000;
    // bytes·8 bits over `ns` nanoseconds is exactly Gbit/s; ×100 for 2 decimals.
    let gbps_centi = packets.saturating_mul(bytes_each as u64).saturating_mul(8) * 100 / ns;
    klog!(
        "NETBENCH {}: {} pkts x {} B, {} ns total, {} ns/pkt, {}.{:03} Mpps, {}.{:02} Gb/s",
        name,
        packets,
        bytes_each,
        ns,
        ns_per_pkt,
        mpps_milli / 1000,
        mpps_milli % 1000,
        gbps_centi / 100,
        gbps_centi % 100
    );
}

/// A well-formed Ethernet/IPv4/TCP frame carrying `payload_len` data bytes, for
/// feeding the segmentation / coalescing / checksum primitives.
fn v4_tcp_frame(seq: u32, flags: u8, payload_len: usize) -> Vec<u8> {
    let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
    let total = tcp_off + TCP_HDR_MIN + payload_len;
    let mut f = alloc::vec![0u8; total];
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    f[ETH_HDR_LEN] = 0x45;
    let ip_total = (IPV4_HDR_LEN + TCP_HDR_MIN + payload_len) as u16;
    f[ETH_HDR_LEN + 2..ETH_HDR_LEN + 4].copy_from_slice(&ip_total.to_be_bytes());
    f[ETH_HDR_LEN + 9] = IP_PROTO_TCP;
    f[ETH_HDR_LEN + 12..ETH_HDR_LEN + 16].copy_from_slice(&[10, 0, 0, 1]);
    f[ETH_HDR_LEN + 16..ETH_HDR_LEN + 20].copy_from_slice(&[10, 0, 0, 2]);
    set_ipv4_checksum(&mut f[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
    f[tcp_off..tcp_off + 2].copy_from_slice(&40000u16.to_be_bytes());
    f[tcp_off + 2..tcp_off + 4].copy_from_slice(&80u16.to_be_bytes());
    f[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
    f[tcp_off + 12] = (TCP_HDR_MIN as u8 / 4) << 4;
    f[tcp_off + 13] = flags;
    f
}

/// TX L4 checksum: the cost per MSS segment that `tx_checksum` offload removes.
fn bench_ipv4_tcp_checksum() -> TestResult {
    const PKTS: u64 = 100_000;
    let seg = alloc::vec![0xa5u8; TCP_HDR_MIN + MSS];
    let src = [10, 0, 0, 1];
    let dst = [10, 0, 0, 2];
    let start = now_cycles();
    let mut acc = 0u16;
    for _ in 0..PKTS {
        acc ^= ipv4_pseudo_checksum(src, dst, &seg);
    }
    let dt = now_cycles().wrapping_sub(start);
    core::hint::black_box(acc);
    report("ipv4_tcp_checksum", PKTS, seg.len(), dt);
    TestResult::Pass
}
kernel_test_in!("net/bench", bench_ipv4_tcp_checksum);

/// Software GSO: segmenting a 64 KB TSO super-frame into MSS wire segments —
/// the per-MSS cost of the TSO software fallback (P2).
fn bench_gso_ipv4() -> TestResult {
    const ROUNDS: u64 = 2_000;
    let super_payload = 64 * 1024;
    let frame = v4_tcp_frame(1, FLAG_ACK, super_payload);
    // Warm once to learn the segment count for the per-packet accounting.
    let segs = crate::gso::segment_ipv4_tcp(&frame, MSS).map_or(0, |s| s.len()) as u64;
    if segs == 0 {
        return TestResult::Fail("gso produced no segments");
    }
    let start = now_cycles();
    for _ in 0..ROUNDS {
        let out = crate::gso::segment_ipv4_tcp(&frame, MSS);
        core::hint::black_box(&out);
    }
    let dt = now_cycles().wrapping_sub(start);
    report("gso_ipv4_segment", ROUNDS * segs, MSS, dt);
    TestResult::Pass
}
kernel_test_in!("net/bench", bench_gso_ipv4);

/// Software GRO: coalescing a run of contiguous in-order MSS segments into one
/// frame — the per-segment cost of the RX batching stage (P3).
fn bench_gro_ipv4() -> TestResult {
    const ROUNDS: u64 = 4_000;
    const BATCH: u32 = 16;
    // Pre-build the segment templates once; `offer` takes an owned Vec, so the
    // clone per offer is part of the realistic (driver-hands-a-frame) cost.
    let templates: Vec<Vec<u8>> = (0..BATCH)
        .map(|i| v4_tcp_frame(1 + i * MSS as u32, FLAG_ACK, MSS))
        .collect();
    let start = now_cycles();
    for _ in 0..ROUNDS {
        let mut gro = crate::gro::Gro::new();
        for t in &templates {
            let out = gro.offer("bench0", t.clone());
            core::hint::black_box(&out);
        }
        let flushed = gro.flush();
        core::hint::black_box(&flushed);
    }
    let dt = now_cycles().wrapping_sub(start);
    report("gro_ipv4_coalesce", ROUNDS * BATCH as u64, MSS, dt);
    TestResult::Pass
}
kernel_test_in!("net/bench", bench_gro_ipv4);

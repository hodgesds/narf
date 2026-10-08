//! Receive-side scaling (RSS) as a first-class, driver-shared primitive.
//!
//! RSS spreads inbound flows across several RX queues — and, with one NAPI
//! poller per queue pinned to the queue's core, across CPUs — so no single
//! core is the bottleneck at 10/40/100G and a connection stays on one core
//! (no cross-core cache bouncing, no reordering). The hash is a standard
//! Toeplitz over the flow 4-tuple, the same function every RSS-capable NIC
//! computes, so the queue a flow lands on is identical whether the hardware
//! steered it or the stack picked the TX queue for it.
//!
//! This module is the shared core: the standard conformance key, the Toeplitz
//! hash, flow-tuple extraction from an Ethernet frame, and the balanced
//! indirection table. Drivers build their hardware RSS programming on top of
//! it and the stack uses the same hash to keep TX on the flow's queue. The
//! algorithm matches the Microsoft RSS conformance vectors (and the i40e
//! driver's existing validated implementation) bit-for-bit.
//!
//! Reference: Microsoft NDIS RSS hashing spec; Linux `netdev` RSS/RFS.

extern crate alloc;

use alloc::vec::Vec;

/// The standard 40-byte Microsoft RSS Toeplitz conformance key. This is a
/// traffic-distribution key, not a secret: every RSS NIC ships it (or a random
/// key) and the exact bytes only decide which queue a flow maps to. Using the
/// published key makes flow→queue placement reproducible and testable.
pub const RSS_KEY: [u8; 40] = [
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
];

/// Toeplitz hash over `tuple` using `key`, MSB-first — the RSS convention.
/// `key` must be at least `tuple.len() + 4` bytes. Matches the Microsoft RSS
/// conformance vectors and the i40e driver's `RssConfig::hash`.
pub fn toeplitz(key: &[u8], tuple: &[u8]) -> u32 {
    debug_assert!(key.len() >= tuple.len() + 4);
    let mut window = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
    let mut hash = 0u32;
    for (byte_index, &byte) in tuple.iter().enumerate() {
        for bit in 0..8 {
            if byte & (0x80 >> bit) != 0 {
                hash ^= window;
            }
            let key_bit = byte_index * 8 + bit + 32;
            window = (window << 1) | ((key[key_bit / 8] >> (7 - key_bit % 8)) & 1) as u32;
        }
    }
    hash
}

/// Extract the RSS flow tuple from an Ethernet frame into `out`, returning its
/// length (0 for a non-IP / malformed frame — those hash to queue 0). The
/// tuple is `src_addr ++ dst_addr ++ src_port ++ dst_port` in wire order:
/// 12 bytes for IPv4/TCP|UDP, 36 for IPv6/TCP|UDP, addresses-only for other
/// L4 or fragments. VLAN tags (one or two) are skipped. Keeping the tuple
/// payload- and IP-ID-independent is what pins a connection to one queue.
pub fn flow_tuple(frame: &[u8], out: &mut [u8; 36]) -> usize {
    if frame.len() < 14 {
        return 0;
    }
    let mut kind = u16::from_be_bytes([frame[12], frame[13]]);
    let mut ip = 14;
    for _ in 0..2 {
        if !matches!(kind, 0x8100 | 0x88a8) {
            break;
        }
        if frame.len() < ip + 4 {
            return 0;
        }
        kind = u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]);
        ip += 4;
    }
    let (mut n, l4, protocol, fragmented) = match kind {
        0x0800 if frame.len() >= ip + 20 && frame[ip] >> 4 == 4 => {
            let ihl = (frame[ip] as usize & 15) * 4;
            if ihl < 20 || frame.len() < ip + ihl {
                return 0;
            }
            out[..8].copy_from_slice(&frame[ip + 12..ip + 20]);
            (
                8,
                ip + ihl,
                frame[ip + 9],
                frame[ip + 6] & 0x3f != 0 || frame[ip + 7] != 0,
            )
        }
        0x86dd if frame.len() >= ip + 40 && frame[ip] >> 4 == 6 => {
            out[..32].copy_from_slice(&frame[ip + 8..ip + 40]);
            (32, ip + 40, frame[ip + 6], false)
        }
        _ => return 0,
    };
    if !fragmented && matches!(protocol, 6 | 17) && frame.len() >= l4 + 4 {
        out[n..n + 4].copy_from_slice(&frame[l4..l4 + 4]);
        n += 4;
    }
    n
}

/// A balanced indirection table: `len` entries round-robin over `queues`, so
/// every queue draws an equal share of the hash space. `len` is the hardware
/// table size (commonly 128 or 512); `queues` the active RX queue count.
pub fn balanced_indirection(queues: usize, len: usize) -> Vec<u8> {
    let queues = queues.max(1);
    (0..len).map(|i| (i % queues) as u8).collect()
}

/// Per-queue CPU/IRQ binding. The NAPI poller for a queue pins to `core`, and
/// (when the device has per-queue MSI-X) parks on `irq`. Default binds to the
/// boot CPU with no dedicated vector — the single-queue case.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueAffinity {
    /// Logical CPU the queue's poller runs on.
    pub core: u32,
    /// Per-queue MSI-X vector, when the device routes one; `None` ⇒ the poller
    /// polls (or shares a vector).
    pub irq: Option<u8>,
}

/// First-class RSS configuration a multi-queue `Interface` exposes: the
/// Toeplitz key and the indirection table mapping hash → RX queue. The same
/// config drives hardware steering and the stack's TX-queue selection, so a
/// flow's TX and RX queues agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RssConfig {
    /// Toeplitz key. 40 bytes is the standard; hardware that wants a wider key
    /// pads it (see the i40e driver).
    pub key: Vec<u8>,
    /// Indirection table: `indirection[hash & (len-1)]` is the RX queue. `len`
    /// is a power of two.
    pub indirection: Vec<u8>,
}

impl RssConfig {
    /// A config with the standard key and a balanced `table_len`-entry table
    /// over `queues`.
    pub fn standard(queues: usize, table_len: usize) -> Self {
        Self {
            key: RSS_KEY.to_vec(),
            indirection: balanced_indirection(queues, table_len),
        }
    }

    /// RX queue for `frame`: Toeplitz over its flow tuple, low bits index the
    /// indirection table — the hardware-accurate path. A non-IP frame or an
    /// empty table lands on queue 0.
    pub fn rx_queue(&self, frame: &[u8]) -> usize {
        if self.indirection.is_empty() {
            return 0;
        }
        let mut tuple = [0u8; 36];
        let n = flow_tuple(frame, &mut tuple);
        if n == 0 {
            return 0;
        }
        let hash = toeplitz(&self.key, &tuple[..n]);
        // Table length is a power of two on real hardware; mask when it is,
        // else fold so a non-power-of-two table still indexes in range.
        let len = self.indirection.len();
        let idx = if len.is_power_of_two() {
            hash as usize & (len - 1)
        } else {
            hash as usize % len
        };
        self.indirection[idx] as usize
    }
}

/// Stable TX-queue selection for `frame` over `queues`, hashing the flow with
/// the standard key — independent of payload and the submitting CPU. Drivers
/// without a programmed indirection table use this so TX lands on the same
/// queue the flow's RX hashes to. Non-IP / malformed frames use queue 0.
pub fn tx_queue_for_frame(frame: &[u8], queues: usize) -> usize {
    if queues <= 1 {
        return 0;
    }
    let mut tuple = [0u8; 36];
    let n = flow_tuple(frame, &mut tuple);
    if n == 0 {
        return 0;
    }
    toeplitz(&RSS_KEY, &tuple[..n]) as usize % queues
}

#[cfg(any(test, feature = "kernel-test"))]
mod rss_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // The published Microsoft RSS conformance vectors: (src, dst, sport, dport)
    // → (2-tuple hash, 4-tuple hash). If these change, the bit/byte ordering
    // regressed and a flow would move queues — breaking RX/TX agreement.
    type Vector = ([u8; 4], [u8; 4], u16, u16, u32, u32);
    const VECTORS: &[Vector] = &[
        (
            [66, 9, 149, 187],
            [161, 142, 100, 80],
            2794,
            1766,
            0x323e8fc2,
            0x51ccc178,
        ),
        (
            [199, 92, 111, 2],
            [65, 69, 140, 83],
            14230,
            4739,
            0xd718262a,
            0xc626b0ea,
        ),
        (
            [24, 19, 198, 95],
            [12, 22, 207, 184],
            12898,
            38024,
            0xd2d0a5de,
            0x5c2b394a,
        ),
        (
            [38, 27, 205, 30],
            [209, 142, 163, 6],
            48228,
            2217,
            0x82989176,
            0xafc7327f,
        ),
        (
            [153, 39, 163, 191],
            [202, 188, 127, 2],
            44251,
            1303,
            0x5d1809c5,
            0x10e828a2,
        ),
    ];

    fn smoke_rss_toeplitz_conformance() -> TestResult {
        for &(src, dst, sport, dport, h2, h4) in VECTORS {
            let mut tuple = [0u8; 36];
            tuple[..4].copy_from_slice(&src);
            tuple[4..8].copy_from_slice(&dst);
            if toeplitz(&RSS_KEY, &tuple[..8]) != h2 {
                return TestResult::Fail("RSS 2-tuple Toeplitz vector regressed");
            }
            tuple[8..10].copy_from_slice(&sport.to_be_bytes());
            tuple[10..12].copy_from_slice(&dport.to_be_bytes());
            if toeplitz(&RSS_KEY, &tuple[..12]) != h4 {
                return TestResult::Fail("RSS 4-tuple Toeplitz vector regressed");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("net/rss", smoke_rss_toeplitz_conformance);

    // Build an Ethernet/IPv4/TCP frame for the first conformance tuple.
    fn v4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut f = alloc::vec![0u8; 54];
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[14] = 0x45;
        f[23] = 6; // TCP
        f[26..30].copy_from_slice(&src);
        f[30..34].copy_from_slice(&dst);
        f[34..36].copy_from_slice(&sport.to_be_bytes());
        f[36..38].copy_from_slice(&dport.to_be_bytes());
        f
    }

    fn smoke_rss_flow_tuple_and_queue() -> TestResult {
        let (src, dst, sport, dport, _, h4) = VECTORS[0];
        let frame = v4_tcp(src, dst, sport, dport);
        // Extracted tuple hashes to the conformance 4-tuple value.
        let mut tuple = [0u8; 36];
        let n = flow_tuple(&frame, &mut tuple);
        if n != 12 || toeplitz(&RSS_KEY, &tuple[..n]) != h4 {
            return TestResult::Fail("flow_tuple did not extract the 4-tuple");
        }
        // Payload and IPv4 ID do not move the flow's queue.
        let q = tx_queue_for_frame(&frame, 8);
        if q != h4 as usize % 8 {
            return TestResult::Fail("tx_queue disagrees with the hash");
        }
        let mut f2 = frame.clone();
        f2[18..20].copy_from_slice(&[0xff, 0xff]); // IPv4 ID
        f2.extend_from_slice(&[0xaa; 16]); // payload
        if tx_queue_for_frame(&f2, 8) != q {
            return TestResult::Fail("payload / IP ID changed the flow queue");
        }
        // A VLAN tag must not shift the flow key.
        let mut vlan = frame[..12].to_vec();
        vlan.extend_from_slice(&[0x81, 0x00, 0x00, 0x01]);
        vlan.extend_from_slice(&frame[12..]);
        if tx_queue_for_frame(&vlan, 8) != q {
            return TestResult::Fail("VLAN shifted the flow key");
        }
        // RssConfig.rx_queue agrees with its own indirection table.
        let cfg = RssConfig::standard(8, 128);
        let idx = h4 as usize & 127;
        if cfg.rx_queue(&frame) != cfg.indirection[idx] as usize {
            return TestResult::Fail("rx_queue did not index the indirection table");
        }
        // Non-IP frames land on queue 0.
        let mut arp = frame.clone();
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        if tx_queue_for_frame(&arp, 8) != 0 || cfg.rx_queue(&arp) != 0 {
            return TestResult::Fail("non-IP frame did not default to queue 0");
        }
        // Every queue is reachable as the source port sweeps.
        let mut used = [false; 8];
        let mut sweep = frame.clone();
        for port in 0..256u16 {
            sweep[34..36].copy_from_slice(&port.to_be_bytes());
            used[tx_queue_for_frame(&sweep, 8)] = true;
        }
        if used.contains(&false) {
            return TestResult::Fail("flow hashing fails to use all queues");
        }
        // A balanced table is exactly even.
        for q in 0..8 {
            if cfg.indirection.iter().filter(|&&e| e as usize == q).count() != 128 / 8 {
                return TestResult::Fail("indirection table is unbalanced");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("net/rss", smoke_rss_flow_tuple_and_queue);
}

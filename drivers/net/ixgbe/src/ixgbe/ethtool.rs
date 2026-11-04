//! ixgbe ethtool surface — driver info + statistics snapshot.
//!
//! NARF's ethtool surface lives in `narf_net::iface`: probe records
//! `(driver, version, bus_info)` via `set_driver_info` (what
//! `ETHTOOL_GDRVINFO` reports) and offloads via `set_offloads`.
//! This module adds the driver-side snapshot the control plane
//! reads back: identity, configured queues/caps, filter state, and
//! the hardware counters. Grounding: 82599 Datasheet §8.2.3.23
//! (GPRC at 0x04074, GPTC at 0x04080) and §8.2.3.23.74/.78
//! (QPRC at 0x01030 + 0x40*n, QPTC at 0x06030 + 0x40*n,
//! n = 0..15). All four counters are RC
//! (read-clear): a snapshot consumes the interval since the last
//! read, so snapshots are interval counters, not monotonic totals
//! — the struct documents that, and callers must not present them
//! as lifetime totals.
//!
//! Honest offload advertisement (what the send path actually
//! honors today): TX checksum offload, yes (`tx()` builds
//! `with_csum` from `TxMeta::csum_l4`); RX checksum, no (the
//! `RxDesc::csum_result` decoder exists but is not plumbed into
//! frame metadata); TSO, yes with a bound (`tx()` accepts TSO
//! frames to `TX_TSO_MAX_TX` bytes, the per-slot copy-buffer
//! size; `tx_frame()` runs to `TX_TSO_MAX_TX_FRAME`, the
//! per-descriptor data length — the advertised bound is the
//! conservative send-path one); VLAN insertion, yes (`TxMeta::
//! vlan_tag` rides the context descriptor + VLE on the data
//! descriptor). VLAN + checksum offload without TSO is rejected
//! (the csum path programs no context — see spec §13j). The
//! snapshot reports exactly this set.

use super::queues::RegBank;

/// Driver name reported to ETHTOOL_GDRVINFO.
pub const ETHTOOL_DRIVER: &str = "ixgbe";
/// Driver version string (crate version line, kept in sync with
/// the module's `version: "0.1.0"` declaration by the fixture).
pub const ETHTOOL_VERSION: &str = "0.1.0";

/// Good-packets counters (datasheet §8.2.3.23, RC).
pub const REG_GPRC: u64 = 0x04074;
pub const REG_GPTC: u64 = 0x04080;

/// Number of per-queue packet counters in hardware (datasheet
/// §8.2.3.23.74/.78; Linux ixgbe_type.h "16 of these"). Queues
/// >= 16 have no per-queue packet counter: their traffic still
/// counts in the GPRC/GPTC totals, but no QPRC/QPTC register
/// exists for them.
pub const NUM_QUEUE_COUNTERS: usize = 16;
/// QPRC base: queue n's received-packet counter, RC
/// (datasheet §8.2.3.23.74; Linux IXGBE_QPRC).
pub const REG_QPRC_BASE: u64 = 0x01030;
/// QPTC base: queue n's transmitted-packet counter, RC
/// (datasheet §8.2.3.23.78; Linux IXGBE_QPTC). The datasheet
/// also maps QPTC at 0x08680 + 0x4*n; this driver reads the
/// 82598-compatible 0x06030 + 0x40*n mapping, which is the one
/// Linux reads.
pub const REG_QPTC_BASE: u64 = 0x06030;
/// Per-queue counter stride (same as the queue-block stride).
pub const QUEUE_COUNTER_STRIDE: u64 = 0x40;

/// QPRC address for queue `q`, or `None` when the hardware has
/// no per-queue receive counter for it (q >= 16).
pub const fn qprc_addr(q: usize) -> Option<u64> {
    if q < NUM_QUEUE_COUNTERS {
        Some(REG_QPRC_BASE + (q as u64) * QUEUE_COUNTER_STRIDE)
    } else {
        None
    }
}

/// QPTC address for queue `q`, or `None` when the hardware has
/// no per-queue transmit counter for it (q >= 16).
pub const fn qptc_addr(q: usize) -> Option<u64> {
    if q < NUM_QUEUE_COUNTERS {
        Some(REG_QPTC_BASE + (q as u64) * QUEUE_COUNTER_STRIDE)
    } else {
        None
    }
}

/// Interval statistics snapshot (RC semantics — see header).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NicStats {
    /// Good packets received since the last read.
    pub rx_good_packets: u32,
    /// Good packets transmitted since the last read.
    pub tx_good_packets: u32,
}

/// Read the interval counters from `bank` (each read clears).
pub fn read_stats(bank: &impl RegBank) -> NicStats {
    NicStats {
        rx_good_packets: bank.read32(REG_GPRC),
        tx_good_packets: bank.read32(REG_GPTC),
    }
}

/// Per-queue interval packet counters (RC semantics — see header).
/// Entries at index >= `rx_valid` / `tx_valid` were not read and
/// are 0; a 64-queue bring-up still reports only the first 16
/// queues here (see `NUM_QUEUE_COUNTERS`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QueueStats {
    /// Interval RX packet counts for queues 0..`rx_valid`.
    pub rx_packets: [u32; NUM_QUEUE_COUNTERS],
    /// Interval TX packet counts for queues 0..`tx_valid`.
    pub tx_packets: [u32; NUM_QUEUE_COUNTERS],
    /// Valid entries in `rx_packets` = min(num_rx_queues, 16).
    pub rx_valid: usize,
    /// Valid entries in `tx_packets` = min(num_tx_queues, 16).
    pub tx_valid: usize,
}

/// Read the per-queue interval counters for the configured queues
/// (each read clears). Reads min(num_rx_queues, 16) QPRC and
/// min(num_tx_queues, 16) QPTC registers; a snapshot that reads
/// both `read_stats` and this consumes every interval counter in
/// one interval.
pub fn read_queue_stats(
    bank: &impl RegBank,
    num_rx_queues: usize,
    num_tx_queues: usize,
) -> QueueStats {
    let mut stats = QueueStats::default();
    stats.rx_valid = num_rx_queues.min(NUM_QUEUE_COUNTERS);
    stats.tx_valid = num_tx_queues.min(NUM_QUEUE_COUNTERS);
    for q in 0..stats.rx_valid {
        if let Some(addr) = qprc_addr(q) {
            stats.rx_packets[q] = bank.read32(addr);
        }
    }
    for q in 0..stats.tx_valid {
        if let Some(addr) = qptc_addr(q) {
            stats.tx_packets[q] = bank.read32(addr);
        }
    }
    stats
}

/// The full ethtool-visible snapshot for one device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthtoolInfo {
    pub driver: &'static str,
    pub version: &'static str,
    pub mac: [u8; 6],
    pub mtu: u32,
    pub link_up: bool,
    pub num_tx_queues: u16,
    pub num_rx_queues: u16,
    /// `NicCaps` bits as a raw word (the caps type lives in the
    /// core crate; the snapshot keeps the word to stay dependency
    /// light for fixtures).
    pub caps: u32,
    pub rss_enabled: bool,
    pub vlan_filter_enabled: bool,
    pub wol_supported: bool,
    pub wol_armed: bool,
    pub stats: NicStats,
    /// Per-queue interval packet counters (first 16 queues; see
    /// `QueueStats`). Read by the same snapshot as `stats`, so
    /// one `ethtool_info` call consumes every interval counter.
    pub queue_stats: QueueStats,
}

impl EthtoolInfo {
    /// Render the snapshot as the one-line summary the control
    /// plane logs (stable field order for tests).
    pub fn summary(&self) -> alloc::string::String {
        alloc::format!(
            "{} {} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} mtu={} link={} txq={} rxq={} caps=0x{:x} rss={} vlan={} wol={}/{} rx_pkts={} tx_pkts={}",
            self.driver,
            self.version,
            self.mac[0],
            self.mac[1],
            self.mac[2],
            self.mac[3],
            self.mac[4],
            self.mac[5],
            self.mtu,
            self.link_up,
            self.num_tx_queues,
            self.num_rx_queues,
            self.caps,
            self.rss_enabled,
            self.vlan_filter_enabled,
            self.wol_supported,
            self.wol_armed,
            self.stats.rx_good_packets,
            self.stats.tx_good_packets,
        )
    }
}

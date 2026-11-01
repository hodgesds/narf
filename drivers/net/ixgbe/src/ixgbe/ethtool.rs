//! ixgbe ethtool surface — driver info + statistics snapshot.
//!
//! NARF's ethtool surface lives in `narf_net::iface`: probe records
//! `(driver, version, bus_info)` via `set_driver_info` (what
//! `ETHTOOL_GDRVINFO` reports) and offloads via `set_offloads`.
//! This module adds the driver-side snapshot the control plane
//! reads back: identity, configured queues/caps, filter state, and
//! the hardware counters. Grounding: 82599 Datasheet §8.2.3.23
//! (GPRC at 0x04074, GPTC at 0x04080). Both counters are RC
//! (read-clear): a snapshot consumes the interval since the last
//! read, so snapshots are interval counters, not monotonic totals
//! — the struct documents that, and callers must not present them
//! as lifetime totals.
//!
//! Honest offload advertisement (what the send path actually
//! honors today): TX checksum offload, yes (`tx()` builds
//! `with_csum` from `TxMeta::csum_l4`); RX checksum, no (the
//! `RxDesc::csum_result` decoder exists but is not plumbed into
//! frame metadata); TSO, no advertised bound (`tx()` caps every
//! frame at 1518 bytes, so a large TSO frame is rejected —
//! advertising a bound would invite frames the driver drops);
//! VLAN insertion, no (RX filtering only; TX insertion is a
//! follow-up). The snapshot reports exactly this set.

use super::queues::RegBank;

/// Driver name reported to ETHTOOL_GDRVINFO.
pub const ETHTOOL_DRIVER: &str = "ixgbe";
/// Driver version string (crate version line, kept in sync with
/// the module's `version: "0.1.0"` declaration by the fixture).
pub const ETHTOOL_VERSION: &str = "0.1.0";

/// Good-packets counters (datasheet §8.2.3.23, RC).
pub const REG_GPRC: u64 = 0x04074;
pub const REG_GPTC: u64 = 0x04080;

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

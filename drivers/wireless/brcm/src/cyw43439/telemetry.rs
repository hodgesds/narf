// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-access-category host data-path telemetry for the FullMAC station.
//!
//! Linux brcmfmac classifies every transmitted frame with
//! `cfg80211_classify8021d` and queues it per FIFO/precedence
//! (`brcmf_netdev_start_xmit`, `fwsignal.c`), and its only per-FIFO
//! counters are the `fws_stats` debugfs; cfg80211 `get_station` carries no
//! per-AC/TID statistics for this driver. NARF exposes the equivalent host
//! queue/traffic accounting: frames/bytes submitted to firmware, frames
//! dropped by host queue policy (credit timeout, disconnect/failure flush)
//! and frames/bytes delivered to the stack, each by IEEE 802.1D→AC
//! (`ieee802_1d_to_ac`: 1,2→BK; 0,3→BE; 4,5→VI; 6,7→VO). Counters are
//! monotonic for the device lifetime and also feed `GET_STATION`
//! `tx_packets`/`rx_packets`/`tx_failed`.
use core::sync::atomic::{AtomicU64, Ordering};

/// `ieee80211_ac_numbers` order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ac {
    Vo = 0,
    Vi = 1,
    Be = 2,
    Bk = 3,
}

/// `ieee802_1d_to_ac` (net/mac80211/wme.c).
pub fn ac_of(priority: u8) -> Ac {
    match priority & 7 {
        1 | 2 => Ac::Bk,
        0 | 3 => Ac::Be,
        4 | 5 => Ac::Vi,
        _ => Ac::Vo,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AcStats {
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub tx_dropped: u64,
    pub rx_frames: u64,
    pub rx_bytes: u64,
}

#[derive(Debug, Default)]
struct Row {
    tx_frames: AtomicU64,
    tx_bytes: AtomicU64,
    tx_dropped: AtomicU64,
    rx_frames: AtomicU64,
    rx_bytes: AtomicU64,
}

/// Lock-free counters shared by the device worker and the TX/RX paths.
#[derive(Debug, Default)]
pub struct Counters {
    rows: [Row; 4],
}
impl Counters {
    pub fn transmitted(&self, priority: u8, bytes: usize) {
        let row = &self.rows[ac_of(priority) as usize];
        row.tx_frames.fetch_add(1, Ordering::Relaxed);
        row.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn dropped(&self, priority: u8) {
        self.rows[ac_of(priority) as usize]
            .tx_dropped
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn received(&self, priority: u8, bytes: usize) {
        let row = &self.rows[ac_of(priority) as usize];
        row.rx_frames.fetch_add(1, Ordering::Relaxed);
        row.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    /// Snapshot in `ieee80211_ac_numbers` order (VO, VI, BE, BK).
    pub fn snapshot(&self) -> [AcStats; 4] {
        core::array::from_fn(|i| {
            let row = &self.rows[i];
            AcStats {
                tx_frames: row.tx_frames.load(Ordering::Relaxed),
                tx_bytes: row.tx_bytes.load(Ordering::Relaxed),
                tx_dropped: row.tx_dropped.load(Ordering::Relaxed),
                rx_frames: row.rx_frames.load(Ordering::Relaxed),
                rx_bytes: row.rx_bytes.load(Ordering::Relaxed),
            }
        })
    }
    /// Totals for `NL80211_STA_INFO_{TX,RX}_PACKETS` / `TX_FAILED` (u32
    /// attributes wrap as the kernel's do).
    pub fn totals(&self) -> (u32, u32, u32) {
        let s = self.snapshot();
        let sum = |f: fn(&AcStats) -> u64| s.iter().map(f).sum::<u64>() as u32;
        (
            sum(|r| r.tx_frames),
            sum(|r| r.rx_frames),
            sum(|r| r.tx_dropped),
        )
    }
}

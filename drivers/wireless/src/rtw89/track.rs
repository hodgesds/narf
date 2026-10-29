// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B `rtw89_track_work` subset: per-peer RSSI statistics
//! (`rtw89_phy_stat_rssi_update`) feeding dynamic EDCCA
//! (`rtw89_phy_edcca_track` / `rtw89_phy_edcca_thre_calc`).

/// `RTW89_TRACK_WORK_PERIOD` (2 s).
pub(super) const PERIOD_MS: u64 = 2000;
/// `EDCCA_MAX`: the unlinked level, also used by Linux while scanning.
pub(super) const EDCCA_MAX: u8 = 249;
const EDCCA_TH_L2H_LB: i32 = 66;
const EDCCA_TH_REF: i32 = 3;
const RSSI_UNIT_CONVER: i32 = 110;
const EDCCA_UNIT_CONVER: i32 = 128;

/// `DECLARE_EWMA(rssi, 10, 16)` over PPDU status `RSSI_AVG` samples.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Rssi(u32);
impl Rssi {
    pub(super) fn add(&mut self, sample: u8) {
        let sample = u32::from(sample) << 10;
        self.0 = if self.0 == 0 {
            sample
        } else {
            ((self.0 << 4) - self.0 + sample) >> 4
        };
    }
    pub(super) fn read(&self) -> u8 {
        (self.0 >> 10) as u8
    }
}

/// `rtw89_phy_edcca_get_thre_by_rssi`: `rssi_min` is the weakest linked
/// peer's average (`ch_info->rssi_min`), `None` with no associated station.
pub(super) fn edcca_threshold(rssi_min: Option<u8>) -> u8 {
    match rssi_min {
        None => EDCCA_MAX,
        Some(rssi) => (i32::from(rssi >> 1) - RSSI_UNIT_CONVER + EDCCA_UNIT_CONVER - EDCCA_TH_REF)
            .max(EDCCA_TH_L2H_LB) as u8,
    }
}

/// Track-work state for the single station link.
#[derive(Debug, Default)]
pub(super) struct Tracker {
    next_ms: u64,
    /// `edcca_bak.th_old`: the level last written to hardware.
    threshold: Option<u8>,
    rssi: Rssi,
    peer: Option<[u8; 6]>,
    /// Owner disabled tracking (`RTW89_DM_DYNAMIC_EDCCA` in `disabled_dm_bitmap`).
    disabled: bool,
}
impl Tracker {
    /// `ewma_rssi_init` at station add: a new (or no) peer restarts the average.
    fn observe(&mut self, peer: Option<[u8; 6]>) {
        if self.peer != peer {
            self.peer = peer;
            self.rssi = Rssi::default();
        }
    }
    /// `rtw89_core_rx_process_phy_ppdu_iter`: samples only count for a linked peer.
    pub(super) fn sample(&mut self, peer: Option<[u8; 6]>, rssi: u8) {
        self.observe(peer);
        if peer.is_some() {
            self.rssi.add(rssi);
        }
    }
    pub(super) fn rssi(&self) -> u8 {
        self.rssi.read()
    }
    /// One track-work period, when due: the level to program, or `None` when
    /// unchanged (`th == th_old`) or not yet due. Linux skips the whole work
    /// item while scanning.
    pub(super) fn due(&mut self, now_ms: u64, peer: Option<[u8; 6]>, scanning: bool) -> Option<u8> {
        if self.disabled || scanning || now_ms < self.next_ms {
            return None;
        }
        self.next_ms = now_ms.saturating_add(PERIOD_MS);
        self.observe(peer);
        let threshold = edcca_threshold(peer.map(|_| self.rssi.read()));
        (self.threshold != Some(threshold)).then_some(threshold)
    }
    pub(super) fn written(&mut self, threshold: u8) {
        self.threshold = Some(threshold);
    }
    pub(super) fn disable(&mut self) {
        self.disabled = true;
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "track/tests.rs"]
mod tests;

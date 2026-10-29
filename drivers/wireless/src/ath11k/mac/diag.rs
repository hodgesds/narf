//! ath11k firmware diagnostics that Linux exposes through debugfs rather
//! than nl80211: per-dialog TWT control and radar-detector diagnostics.
//!
//! | NARF | Linux |
//! |---|---|
//! | [`Mac::twt_add_dialog`] | `debugfs.c::ath11k_write_twt_add_dialog` → `ath11k_wmi_send_twt_add_dialog_cmd` |
//! | [`Mac::twt_del_dialog`] | `ath11k_write_twt_del_dialog` → `ath11k_wmi_send_twt_del_dialog_cmd` |
//! | [`Mac::twt_pause_dialog`] | `ath11k_write_twt_pause_dialog` → `ath11k_wmi_send_twt_pause_dialog_cmd` |
//! | [`Mac::twt_resume_dialog`] | `ath11k_write_twt_resume_dialog` → `ath11k_wmi_send_twt_resume_dialog_cmd` |
//! | [`Mac::take_twt_add_dialog_events`] | `wmi.c::ath11k_wmi_twt_add_dialog_event` (status warning) |
//! | [`Mac::simulate_radar`] | debugfs `dfs_simulate_radar` → `ath11k_wmi_simulate_radar` (`WMI_UNIT_TEST_CMDID`, DFS module) |
//! | [`RadarDiagnostics`] | `ath11k_wmi_pdev_dfs_radar_detected_event`'s detector record + debugfs `dfs_block_radar_events` |
//!
//! These are host controls over firmware state, not mac80211 policy: the
//! TWT agreement negotiation itself (IEEE 802.11ax-2021 26.8 individual
//! TWT) stays inside the firmware scheduler that `WMI_TWT_ENABLE_CMDID`
//! configured.  The radar detector is likewise firmware-owned (DFS phyerr
//! offload); the host retains its report and decides whether to act on it
//! (IEEE 802.11-2020 11.8.8.2 / the regulatory non-occupancy period).

extern crate alloc;

use core::fmt::Write as _;

use super::super::wmi::{
    dfs_simulate_radar_cmd, twt_add_dialog_cmd, twt_add_dialog_status_str, twt_del_dialog_cmd,
    twt_disable_cmd, twt_enable_cmd, twt_pause_dialog_cmd, twt_resume_dialog_cmd, DfsRadarDetected,
    TwtAddDialogEvent, TwtAddDialogParams, TwtEnableParams, WmiCmd, WMI_HOST_WLAN_5G_CAP,
};
use super::{errno, DataPort, Mac, VifKind, WmiPort};

/// Retained `WMI_TWT_ADD_DIALOG_EVENTID` completions per MAC. Linux only
/// logs them; NARF keeps a bounded queue so the issuer can read the
/// firmware's verdict for its own dialog.
pub const TWT_ADD_DIALOG_EVENTS_MAX: usize = 16;

/// Radio-wide radar-detector diagnostics: the fields
/// `ath11k_wmi_pdev_dfs_radar_detected_event` prints for every report, the
/// counts of reports acted on and ignored, and ath11k's
/// `ar->dfs_block_radar_events` debug switch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RadarDiagnostics {
    /// `dfs_block_radar_events`: a report is logged but not handed to
    /// `ieee80211_radar_detected`.
    pub block_radar_events: bool,
    /// Reports for this radio's pdev that reached the DFS state machine.
    pub detected: u32,
    /// Reports for this radio's pdev dropped by `block_radar_events`.
    pub ignored: u32,
    /// Reports naming another pdev ("radar detected in invalid pdev").
    pub invalid_pdev: u32,
    /// The latest detector report for this radio's pdev.
    pub last: Option<DfsRadarDetected>,
}

impl RadarDiagnostics {
    /// Record one report. `pdev_id` is this radio's pdev (`None` before the
    /// capabilities are known: Linux's `ath11k_mac_get_ar_by_pdev_id` then
    /// finds no radio either). Returns whether mac80211's radar handling
    /// should run, i.e. the report is for this pdev and not blocked.
    pub fn record(&mut self, ev: &DfsRadarDetected, pdev_id: Option<u32>) -> bool {
        if pdev_id != Some(ev.pdev_id) {
            self.invalid_pdev = self.invalid_pdev.saturating_add(1);
            return false;
        }
        self.last = Some(*ev);
        if self.block_radar_events {
            // "DFS Radar detected, but ignored as requested".
            self.ignored = self.ignored.saturating_add(1);
            return false;
        }
        self.detected = self.detected.saturating_add(1);
        true
    }
}

impl<P: WmiPort, D: DataPort> Mac<P, D> {
    async fn diag_send(&mut self, c: WmiCmd) -> Result<(), i32> {
        self.wmi.send(c).await
    }

    /// The debugfs files exist per vif; the debugfs handlers refuse with
    /// `-EOPNOTSUPP` while the pdev TWT engine is off.
    fn twt_dialog_vdev(&self) -> Result<(u32, VifKind), i32> {
        let vif = self.vif.as_ref().ok_or(errno::ENODEV)?;
        if !self.twt_enabled {
            return Err(errno::EOPNOTSUPP);
        }
        Ok((vif.vdev_id, vif.kind))
    }

    /// `arvif->vif->type == NL80211_IFTYPE_STATION` (a P2P client is a
    /// station interface in mac80211; P2P_DEVICE is not).
    fn twt_station(kind: VifKind) -> bool {
        matches!(kind, VifKind::Station | VifKind::P2pClient)
    }

    /// The station "manual TWT" re-arm: disable the pdev engine, then
    /// enable it with `params`. Linux ignores both command results.
    async fn twt_rearm(&mut self, params: TwtEnableParams) {
        let pdev_id = self.caps.pdev_id;
        let _ = self.diag_send(twt_disable_cmd(pdev_id)).await;
        let _ = self.diag_send(twt_enable_cmd(pdev_id, &params)).await;
    }

    /// `ath11k_write_twt_add_dialog`. For a station "TWT is entirely
    /// handled by the firmware based on the input parameters in the TWT
    /// enable WMI command": the engine is re-enabled with
    /// `sta_cong_timer_ms = 0` first, and restored to the defaults if the
    /// add command cannot be sent. `vdev_id` is always this vif's.
    pub async fn twt_add_dialog(&mut self, mut params: TwtAddDialogParams) -> Result<(), i32> {
        let (vdev_id, kind) = self.twt_dialog_vdev()?;
        let station = Self::twt_station(kind);
        if station {
            self.twt_rearm(TwtEnableParams {
                sta_cong_timer_ms: 0,
                ..TwtEnableParams::default()
            })
            .await;
        }
        params.vdev_id = vdev_id;
        let r = self.diag_send(twt_add_dialog_cmd(&params)).await;
        if r.is_err() && station {
            self.twt_rearm(TwtEnableParams::default()).await;
        }
        r
    }

    /// `ath11k_write_twt_del_dialog`: delete, then (station) restore the
    /// default congestion-timer engine configuration.
    pub async fn twt_del_dialog(&mut self, peer: [u8; 6], dialog_id: u32) -> Result<(), i32> {
        let (vdev_id, kind) = self.twt_dialog_vdev()?;
        self.diag_send(twt_del_dialog_cmd(vdev_id, &peer, dialog_id))
            .await?;
        if Self::twt_station(kind) {
            self.twt_rearm(TwtEnableParams::default()).await;
        }
        Ok(())
    }

    /// `ath11k_write_twt_pause_dialog`.
    pub async fn twt_pause_dialog(&mut self, peer: [u8; 6], dialog_id: u32) -> Result<(), i32> {
        let (vdev_id, _) = self.twt_dialog_vdev()?;
        self.diag_send(twt_pause_dialog_cmd(vdev_id, &peer, dialog_id))
            .await
    }

    /// `ath11k_write_twt_resume_dialog`: `sp_offset_us` is the next service
    /// period offset and `next_twt_size` the Next TWT subfield size.
    pub async fn twt_resume_dialog(
        &mut self,
        peer: [u8; 6],
        dialog_id: u32,
        sp_offset_us: u32,
        next_twt_size: u32,
    ) -> Result<(), i32> {
        let (vdev_id, _) = self.twt_dialog_vdev()?;
        self.diag_send(twt_resume_dialog_cmd(
            vdev_id,
            &peer,
            dialog_id,
            sp_offset_us,
            next_twt_size,
        ))
        .await
    }

    /// `ath11k_wmi_twt_add_dialog_event` for this vif: a failed status is
    /// logged exactly like Linux's warning and every completion is kept.
    pub(super) fn twt_add_dialog_event(&mut self, ev: TwtAddDialogEvent) {
        if ev.status != 0 {
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: wmi add twt dialog event vdev {} dialog id {} status {}",
                ev.vdev_id,
                ev.dialog_id,
                twt_add_dialog_status_str(ev.status)
            );
        }
        let q = &mut self.pending.twt_add_dialog;
        if q.len() >= TWT_ADD_DIALOG_EVENTS_MAX {
            q.pop_front();
        }
        q.push_back(ev);
    }

    /// Drain the retained TWT add-dialog completions.
    pub fn take_twt_add_dialog_events(&mut self) -> alloc::vec::Vec<TwtAddDialogEvent> {
        self.pending.twt_add_dialog.drain(..).collect()
    }

    /// `ath11k_wmi_simulate_radar`: ask the firmware DFS module to inject a
    /// radar report through the normal detection event. Linux requires a
    /// started AP vdev (`-EINVAL` otherwise) and offers the control only on
    /// a 5 GHz-capable radio.
    pub async fn simulate_radar(&mut self) -> Result<(), i32> {
        if self.caps.pdev.supported_bands & WMI_HOST_WLAN_5G_CAP == 0 {
            return Err(errno::EOPNOTSUPP);
        }
        let vdev_id = self
            .vif
            .as_ref()
            .filter(|vif| vif.is_started && vif.kind.is_ap())
            .map(|vif| vif.vdev_id)
            .ok_or(errno::EINVAL)?;
        let pdev_id = self.caps.pdev_id;
        self.diag_send(dfs_simulate_radar_cmd(vdev_id, pdev_id))
            .await
    }
}

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Native Gen2/API77 WoWLAN owner: Linux `mvm/d3.c::__iwl_mvm_suspend` and
//! `__iwl_mvm_resume` for an associated station on a unified image.
//!
//! Suspend keeps the firmware association, hands it the host's current
//! per-TID replay floors and QoS sequence numbers, programs the triggers and
//! moves the transport into D3. Resume waits for the firmware's
//! notification-based report, restores counters into the host owner and
//! keeps the association only when Linux would
//! (`iwl_mvm_setup_connection_keep`); every other outcome tells the caller
//! to perform the full restart Linux requests with
//! `IWL_MVM_STATUS_HW_RESTART_REQUESTED`.
use super::super::mvm_d3::{self as d3, D3Api, Wake, WakeReport};
use super::{Owner, Phase};
use alloc::vec::Vec;

/// `IWL_MVM_D3_NOTIF_TIMEOUT` (HZ / 3).
const NOTIF_TIMEOUT_MS: u64 = 333;

/// Outcome of a WoWLAN resume conversation.
#[derive(Debug)]
pub(in crate::iwlwifi) struct Resumed {
    /// cfg80211 wakeup report (`ieee80211_report_wowlan_wakeup`).
    pub report: WakeReport,
    /// The association and every restored counter remain valid. False
    /// requires the full firmware restart and a disconnected station.
    pub keep: bool,
}

impl Owner {
    /// The exact admitted D3 surface of the retained executable, if any.
    pub(in crate::iwlwifi) fn wowlan_api(&self) -> Result<D3Api, &'static str> {
        let parsed = super::super::parse_ucode(&self.firmware)
            .map_err(|_| "invalid retained MVM firmware")?;
        D3Api::admit(&parsed.api)
    }

    /// `wiphy->wowlan` registration: the exact D3 surface plus the 22000
    /// D3 transport this driver implements.
    pub(in crate::iwlwifi) fn wowlan_capable(&self) -> bool {
        self.hardware.d3_transport_supported() && self.wowlan_api().is_ok()
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::iwlwifi) fn model_wowlan_sequence(&self) -> u16 {
        self.power
            .prepared
            .as_ref()
            .and_then(|p| p.mlme.data.as_ref())
            .map_or(0, |data| data.sequence)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::iwlwifi) fn model_pairwise_floor(&self, tid: usize) -> u64 {
        self.power
            .prepared
            .as_ref()
            .and_then(|p| p.mlme.data.as_ref())
            .map_or(0, |data| data.replay.pairwise[tid])
    }

    /// `iwl_mvm_get_bss_vif` + `ap_sta_id != IWL_INVALID_STA`: only a
    /// completed association with an open controlled port can stay
    /// connected in D3. Anything else uses the ordinary suspend
    /// (`__iwl_mvm_suspend` returns 1 without net-detect).
    pub(in crate::iwlwifi) fn wowlan_associated(&self) -> bool {
        if self.phase != Phase::DataPrepared || self.station_failed() {
            return false;
        }
        let Some(data) = self
            .power
            .prepared
            .as_ref()
            .and_then(|p| p.mlme.data.as_ref())
        else {
            return false;
        };
        data.port_open && (!data.status.protected || self.security.ready())
    }

    /// `__iwl_mvm_suspend` for the associated case. mac80211 has already
    /// flushed the queues (`__ieee80211_suspend` -> `ieee80211_flush_queues`),
    /// which `drain_transmits` performs here before any D3 command.
    pub(in crate::iwlwifi) async fn wowlan_suspend(
        &mut self,
        wake: &Wake,
    ) -> Result<(), &'static str> {
        if !self.wowlan_associated() {
            return Err("MVM WoWLAN requires an associated station");
        }
        let api = self.wowlan_api()?;
        self.hardware.drain_transmits().await?;
        let ht = self.power.phy.negotiated.as_ref().is_some_and(|p| p.ht);
        let data = self
            .power
            .prepared
            .as_ref()
            .and_then(|p| p.mlme.data.as_ref())
            .ok_or("MVM WoWLAN data owner absent")?;
        // TID0 uses `sequence`; TIDs 1..=7 their own counters.
        let mut next_qos_seq = data.tid_sequences.map(|seq| seq << 4);
        next_qos_seq[0] = data.sequence << 4;
        let station = d3::Station {
            sta_id: super::data::STATION,
            ht,
            mfp: data.status.pmf,
            next_qos_seq,
        };
        let counters = if data.status.protected {
            // iwl_mvm_wowlan_get_rsc_v5_data: firmware and mac80211 check
            // non-QoS PNs on TID 0; the host keeps them in slot 16.
            let fold = |floors: [u64; 17]| {
                let mut tids = [0u64; 8];
                tids.copy_from_slice(&floors[..8]);
                tids[0] = tids[0].max(floors[16]);
                tids
            };
            let mut gtks = Vec::new();
            for id in 0..4 {
                if !data.replay.group_valid[id] {
                    continue;
                }
                let mut floors = data.replay.group[id];
                for rx in &data.extra_rx {
                    for (floor, pn) in floors.iter_mut().zip(rx.replay.group[id]) {
                        *floor = (*floor).max(pn);
                    }
                }
                gtks.push((id as u8, fold(floors)));
            }
            d3::Counters {
                ptk: Some(fold(data.pairwise_floors())),
                gtks,
            }
        } else {
            d3::Counters::default()
        };
        // iwl_mvm_wowlan_config_key_params (unified: no key reprogramming).
        if let Some(rsc) = d3::rsc_tsc_v5(station.sta_id, &counters)? {
            self.hardware
                .command(0, d3::WOWLAN_TSC_RSC_PARAM, &rsc)
                .await?;
        }
        self.hardware
            .command(
                0,
                d3::WOWLAN_CONFIGURATION,
                &d3::configuration_v6(wake, &station),
            )
            .await?;
        if let Some(patterns) = d3::patterns_v3(station.sta_id, &wake.patterns) {
            self.hardware
                .command(0, d3::WOWLAN_PATTERNS, &patterns)
                .await?;
        }
        self.hardware
            .command(
                0,
                d3::PROT_OFFLOAD_CONFIG_CMD,
                &d3::proto_offload_v4(station.sta_id, &api),
            )
            .await?;
        // "must be last -- this switches firmware state"
        self.hardware
            .command(0, d3::D3_CONFIG_CMD, &d3::d3_config())
            .await?;
        self.hardware.d3_suspend()
    }

    /// `__iwl_mvm_resume` (notification-based, unified image, 22000 with
    /// `D0I3_END_FIRST`). An `Err` means the transport did not come back and
    /// no report exists; the caller restarts exactly like `Ok(keep: false)`.
    pub(in crate::iwlwifi) async fn wowlan_resume(&mut self) -> Result<Resumed, &'static str> {
        if !self.hardware.is_in_d3() {
            return Err("MVM WoWLAN resume without D3");
        }
        self.hardware.d3_resume().await?;
        // `iwl_mvm_resume_firmware`: 22000 with D0I3_END_FIRST triggers the
        // resume flow with D0I3_END_CMD before the D3 notifications.
        self.hardware.command(0, d3::D0I3_END_CMD, &[]).await?;
        let deadline = narf_time::Deadline::after_ms(NOTIF_TIMEOUT_MS);
        let remaining =
            || (narf_time::wall::cycles_to_ns(deadline.remaining_cycles()) / 1_000_000).max(1);
        let info = self
            .hardware
            .wait_notification(
                d3::PROT_OFFLOAD_GROUP,
                d3::WOWLAN_INFO_NOTIFICATION,
                remaining(),
            )
            .await?;
        let status = d3::parse_info_v1(&info.payload)?;
        let packet = if status.reasons & d3::reason::HAS_WAKE_PACKET != 0 {
            let packet = self
                .hardware
                .wait_notification(
                    d3::PROT_OFFLOAD_GROUP,
                    d3::WOWLAN_WAKE_PKT_NOTIFICATION,
                    remaining(),
                )
                .await?;
            // A malformed wake packet is logged and ignored by Linux.
            d3::parse_wake_packet(&packet.payload).unwrap_or_default()
        } else {
            Vec::new()
        };
        let end = self
            .hardware
            .wait_notification(d3::PROT_OFFLOAD_GROUP, d3::D3_END_NOTIFICATION, remaining())
            .await?;
        let reset = d3::parse_d3_end(&end.payload)?;
        let report = d3::report(&status, packet);
        let keep = !reset
            && d3::keeps_connection(&status)
            && status.station_id == super::data::STATION
            && self.wowlan_restore(&status).is_ok();
        Ok(Resumed { report, keep })
    }

    /// `iwl_mvm_query_wakeup_reasons` + `iwl_mvm_d3_update_keys`: replay
    /// floors only rise, QoS sequence numbers continue after the last value
    /// firmware used, and the offload TID queue follows the firmware
    /// scheduler (`iwl_trans_set_q_ptrs`).
    fn wowlan_restore(&mut self, status: &d3::WakeStatus) -> Result<(), &'static str> {
        let data = self
            .power
            .prepared
            .as_mut()
            .and_then(|p| p.mlme.data.as_mut())
            .ok_or("MVM WoWLAN data owner absent")?;
        if data.status.protected {
            let raise = |floors: &mut [u64; 17], pns: &[u64; 8]| {
                for (floor, pn) in floors.iter_mut().zip(pns) {
                    *floor = (*floor).max(*pn);
                }
                floors[16] = floors[16].max(pns[0]);
            };
            let mut replays: Vec<&mut super::super::frame_api::Replay> = Vec::new();
            replays.push(&mut data.replay);
            for rx in &mut data.extra_rx {
                replays.push(&mut rx.replay);
            }
            for replay in replays {
                raise(&mut replay.pairwise, &status.ptk_rx);
                for (id, pns) in &status.gtk_rx {
                    let id = usize::from(*id);
                    if replay.group_valid[id] {
                        raise(&mut replay.group[id], pns);
                    }
                }
            }
        }
        // "firmware stores last-used value, we store next value"
        let next = |seq: u16| (seq.wrapping_add(0x10) >> 4) & 0xfff;
        let previous = data.sequence;
        data.sequence = next(status.qos_seq[0]);
        for (sequence, last) in data.tid_sequences.iter_mut().zip(status.qos_seq).skip(1) {
            *sequence = next(last);
        }
        let frames = data.sequence.wrapping_sub(previous) & 0xfff;
        let queue = data.queue.ok_or("MVM WoWLAN offload queue absent")?;
        if frames == 0 {
            return Ok(());
        }
        self.hardware.advance_queue_pointers(queue, frames)
    }
}

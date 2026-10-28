//! C21 actual retained reserved firmware DMA → Q/P/S/L/H → HT station adapter.
use super::*;
use crate::rtw88::firmware_transport::Error;
use crate::rtw88::{ht, ht_tests as cases};
struct Case {
    e: Extended,
    cap: Cap<FirmwareBlob, Read>,
}
fn smoke_rtw8821ce_rts_open_native_dhcp_ip_and_h_r_t() -> TestResult {
    check(|| crate::rtw88::protection_tests::composition::<Case>(false))
}
kernel_test_in!(
    "drivers/wireless/rtw88/rts/rtl8821c",
    smoke_rtw8821ce_rts_open_native_dhcp_ip_and_h_r_t
);
fn smoke_rtw8821ce_rts_wpa2_native_dhcp_ip_and_h_r_t() -> TestResult {
    check(|| crate::rtw88::protection_tests::composition::<Case>(true))
}
kernel_test_in!(
    "drivers/wireless/rtw88/rts/rtl8821c",
    smoke_rtw8821ce_rts_wpa2_native_dhcp_ip_and_h_r_t
);
fn smoke_rtw8821ce_rts_distinct_assets_old_profiles_and_bounds() -> TestResult {
    check(crate::rtw88::protection_tests::assets_and_old_profiles::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rts/rtl8821c",
    smoke_rtw8821ce_rts_distinct_assets_old_profiles_and_bounds
);
fn smoke_rtw8821ce_rts_held_ccx_native_key_and_threshold() -> TestResult {
    check(crate::rtw88::protection_tests::held_ccx_key_and_setting::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rts/rtl8821c",
    smoke_rtw8821ce_rts_held_ccx_native_key_and_threshold
);
fn smoke_rtw8821ce_rts_native_failures_sources_policy_and_dma() -> TestResult {
    check(crate::rtw88::protection_tests::failures_and_current_sources::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rts/rtl8821c",
    smoke_rtw8821ce_rts_native_failures_sources_policy_and_dma
);
fn smoke_rtw8821ce_rts_partial_bd_cancel_and_mac_fifo_setting() -> TestResult {
    check(crate::rtw88::protection_tests::partial_publication_and_fifo_setting::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rts/rtl8821c",
    smoke_rtw8821ce_rts_partial_bd_cancel_and_mac_fifo_setting
);
fn smoke_rtw8821ce_native_early_m3_and_closed_data_before_m2_ccx() -> TestResult {
    check(cases::early_m3_control::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8821c",
    smoke_rtw8821ce_native_early_m3_and_closed_data_before_m2_ccx
);
fn smoke_rtw8821ce_tx_ba_open_dhcp_ip_and_recipient_coexistence() -> TestResult {
    check(|| crate::rtw88::tx_ba_tests::composition::<Case>(false))
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8821c",
    smoke_rtw8821ce_tx_ba_open_dhcp_ip_and_recipient_coexistence
);
fn smoke_rtw8821ce_tx_ba_wpa2_dhcp_ip_and_recipient_coexistence() -> TestResult {
    check(|| crate::rtw88::tx_ba_tests::composition::<Case>(true))
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8821c",
    smoke_rtw8821ce_tx_ba_wpa2_dhcp_ip_and_recipient_coexistence
);
fn smoke_rtw8821ce_tx_ba_distinct_assets_and_h_fallback() -> TestResult {
    check(crate::rtw88::tx_ba_tests::refusal_and_legacy::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8821c",
    smoke_rtw8821ce_tx_ba_distinct_assets_and_h_fallback
);
fn smoke_rtw8821ce_tx_ba_peer_response_and_actual_per_tid_ssn() -> TestResult {
    check(crate::rtw88::tx_ba_tests::peer_response_and_ssn::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8821c",
    smoke_rtw8821ce_tx_ba_peer_response_and_actual_per_tid_ssn
);
fn smoke_rtw8821ce_tx_ba_held_request_ccx_cancel_and_dma() -> TestResult {
    check(crate::rtw88::tx_ba_tests::held_dialog_and_cancel::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8821c",
    smoke_rtw8821ce_tx_ba_held_request_ccx_cancel_and_dma
);
fn smoke_rtw8821ce_tx_ba_mac_fifo_all_sources_and_late_receipts() -> TestResult {
    check(crate::rtw88::tx_ba_tests::fifo_and_authority::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8821c",
    smoke_rtw8821ce_tx_ba_mac_fifo_all_sources_and_late_receipts
);
fn smoke_rtw8821ce_tx_ba_partial_bd_current_authority_and_close() -> TestResult {
    check(crate::rtw88::tx_ba_tests::partial_publication_and_close::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8821c",
    smoke_rtw8821ce_tx_ba_partial_bd_current_authority_and_close
);
fn smoke_rtw8821ce_tx_ba_peer_delba_and_real_key_epoch() -> TestResult {
    check(crate::rtw88::tx_ba_tests::delba_and_key_epoch::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8821c",
    smoke_rtw8821ce_tx_ba_peer_delba_and_real_key_epoch
);
fn smoke_rtw8821ce_dm_open_watchdog_revocation_restore() -> TestResult {
    check(|| crate::rtw88::dm_station_tests::composition::<Case>(false))
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm/rtl8821c",
    smoke_rtw8821ce_dm_open_watchdog_revocation_restore
);
fn smoke_rtw8821ce_dm_wpa2_watchdog_revocation_restore() -> TestResult {
    check(|| crate::rtw88::dm_station_tests::composition::<Case>(true))
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm/rtl8821c",
    smoke_rtw8821ce_dm_wpa2_watchdog_revocation_restore
);
fn smoke_rtw8821ce_dm_refusals_and_unqualified_station() -> TestResult {
    check(crate::rtw88::dm_station_tests::refusals::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm/rtl8821c",
    smoke_rtw8821ce_dm_refusals_and_unqualified_station
);
fn smoke_rtw8821ce_ht_protection_modes_admitted() -> TestResult {
    check(|| {
        for mode in 1..=3 {
            crate::rtw88::dm_station_tests::protection_modes::<Case>(mode)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht_protection/rtl8821c",
    smoke_rtw8821ce_ht_protection_modes_admitted
);
fn smoke_rtw8821ce_coding_ldpc_stbc_and_revocation() -> TestResult {
    check(crate::rtw88::coding_tests::composition::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/coding/rtl8821c",
    smoke_rtw8821ce_coding_ldpc_stbc_and_revocation
);
fn smoke_rtw8821ce_coding_not_granted_or_uncoded_peer() -> TestResult {
    check(crate::rtw88::coding_tests::not_granted::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/coding/rtl8821c",
    smoke_rtw8821ce_coding_not_granted_or_uncoded_peer
);
fn smoke_rtw8821ce_coding_refusals_and_teardown() -> TestResult {
    check(crate::rtw88::coding_tests::refusals::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/coding/rtl8821c",
    smoke_rtw8821ce_coding_refusals_and_teardown
);
fn smoke_rtw8821ce_qos_open_all_ac_tid_routing_and_revocation() -> TestResult {
    check(|| crate::rtw88::qos_tests::composition::<Case>(false))
}
kernel_test_in!(
    "drivers/wireless/rtw88/qos/rtl8821c",
    smoke_rtw8821ce_qos_open_all_ac_tid_routing_and_revocation
);
fn smoke_rtw8821ce_qos_wpa2_all_ac_tid_routing_and_revocation() -> TestResult {
    check(|| crate::rtw88::qos_tests::composition::<Case>(true))
}
kernel_test_in!(
    "drivers/wireless/rtw88/qos/rtl8821c",
    smoke_rtw8821ce_qos_wpa2_all_ac_tid_routing_and_revocation
);
fn smoke_rtw8821ce_qos_not_granted_and_subset() -> TestResult {
    check(crate::rtw88::qos_tests::not_granted::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/qos/rtl8821c",
    smoke_rtw8821ce_qos_not_granted_and_subset
);
fn smoke_rtw8821ce_qos_refusals() -> TestResult {
    check(crate::rtw88::qos_tests::refusals::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/qos/rtl8821c",
    smoke_rtw8821ce_qos_refusals
);
impl cases::Fixture for Case {
    fn kind_request(
        &self,
        kind: &'static crate::rtw88::qualification::Kind,
    ) -> Result<crate::rtw88::ContinuationRequest, Error> {
        self.e.h.port.kind_request(kind)
    }
    fn stage_kind(
        &self,
        kind: &'static crate::rtw88::qualification::Kind,
        bytes: Vec<u8>,
        cap: Cap<FirmwareBlob, Read>,
        signed: bool,
    ) -> Result<(), Error> {
        self.e.h.port.qualify(
            kind,
            crate::rtw88::qualification::Source::Verified {
                bytes,
                cap,
                signer: signed.then_some([19; 32]),
            },
        )
    }
    fn dm_request(&self) -> Result<crate::rtw88::ContinuationRequest, Error> {
        self.e.h.port.dm_request()
    }
    fn stage_dm(
        &self,
        bytes: Vec<u8>,
        cap: Cap<FirmwareBlob, Read>,
        signed: bool,
    ) -> Result<(), Error> {
        self.e
            .h
            .port
            .qualify_dm(crate::rtw88::qualification::Source::Verified {
                bytes,
                cap,
                signer: signed.then_some([18; 32]),
            })
    }
    type Io = Backend<Port, Block>;
    fn rts_request(&self) -> Result<crate::rtw88::RtsRequest, Error> {
        self.e.h.port.rts_request()
    }
    fn stage_rts(
        &self,
        bytes: Vec<u8>,
        cap: Cap<FirmwareBlob, Read>,
        signed: bool,
    ) -> Result<(), Error> {
        self.e
            .h
            .port
            .qualify_protection(crate::rtw88::protection::Source::Verified {
                bytes,
                cap,
                signer: signed.then_some([17; 32]),
            })
    }
    fn tx_request(&self) -> Result<crate::rtw88::TxBaRequest, Error> {
        self.e.h.port.tx_ba_request()
    }
    fn stage_tx(&self, bytes: Vec<u8>, cap: Cap<FirmwareBlob, Read>) -> Result<(), Error> {
        self.e
            .h
            .port
            .qualify_tx_ba(crate::rtw88::tx_ba_power::Source::Verified {
                bytes,
                cap,
                signer: Some([16; 32]),
            })
    }
    fn descriptors(&self) -> Vec<[u8; 48]> {
        self.e.h.port.0.lock().packet_model.descriptors.clone()
    }
    fn ba_request(&self) -> Result<crate::rtw88::RxBaRequest, Error> {
        self.e.h.port.rx_ba_request()
    }
    fn stage_ba(&self, bytes: Vec<u8>, cap: Cap<FirmwareBlob, Read>) -> Result<(), Error> {
        self.e
            .h
            .port
            .qualify_rx_ba(crate::rtw88::rx_ba_power::Source::Verified {
                bytes,
                signer: Some([14; 32]),
                cap,
            })
    }
    fn advance_ms(&self, ms: u64) {
        let mut m = self.e.h.port.0.lock();
        m.clock.fetch_add(ms, core::sync::atomic::Ordering::AcqRel);
        m.packet_model.now += ms * 1000;
    }
    fn make(protected: bool, mcs: u8, sgi: bool, qualified: bool) -> Result<Self, &'static str> {
        let e = setup(protected, true, true, None)?;
        let cap = Cap::bootstrap();
        let ht = cases::elements(true);
        let beacon = {
            let mut peer = e.h.peer.lock();
            peer.ht = Some(ht.clone());
            let mut b = peer.ap.beacon();
            b.extend_from_slice(peer.wmm.as_ref().unwrap());
            b.extend_from_slice(&ht);
            b
        };
        e.h.port
            .0
            .lock()
            .packet_model
            .receive(&beacon, false, false);
        if qualified {
            let r =
                e.h.port
                    .ht_request()
                    .map_err(|_| "C21 HT request/factory facts missing")?;
            e.h.port
                .qualify_ht(ht::Source::Verified {
                    bytes: cases::record(&r, mcs, sgi, true),
                    signer: Some([11; 32]),
                    cap,
                })
                .map_err(|_| "C21 distinct synthetic H record")?;
        }
        Ok(Self { e, cap })
    }
    fn device(&self) -> &Arc<TestDevice> {
        &self.e.h.device
    }
    fn peer(&self) -> &Arc<IrqSafeSpinLock<Peer>> {
        &self.e.h.peer
    }
    fn pump(&self) {
        self.e.h.pump()
    }
    fn received(&self) -> Vec<Vec<u8>> {
        self.e.h.received()
    }
    fn inject(&self, b: &[u8], r: u8, w: u8) {
        self.e.h.port.0.lock().packet_model.receive_rate(b, r, w)
    }
    fn mailboxes(&self) -> Vec<[u8; 8]> {
        self.e.h.port.0.lock().mailboxes.clone()
    }
    fn descriptor(&self) -> Option<[u8; 48]> {
        self.e.h.port.0.lock().packet_model.last_descriptor
    }
    fn register(&self, r: u16) -> u32 {
        word(&self.e.h.port.0.lock().bytes, usize::from(r))
    }
    fn lose(&self, r: u16) {
        self.e.h.port.0.lock().ignore_write = Some(r)
    }
    fn cap(&self) -> Cap<FirmwareBlob, Read> {
        self.cap
    }
    fn request(&self) -> Result<ht::Request, &'static str> {
        self.e.h.port.ht_request().map_err(|_| "C21 H metadata")
    }
    fn stage(&self, b: Vec<u8>, c: Cap<FirmwareBlob, Read>) -> Result<(), Error> {
        self.e.h.port.qualify_ht(ht::Source::Verified {
            bytes: b,
            signer: Some([11; 32]),
            cap: c,
        })
    }
    fn retained(&self) -> (usize, u64) {
        self.e
            .h
            .port
            .0
            .lock()
            .packet_model
            .payload_identity()
            .unwrap()
    }
    fn after_descriptor(&self, f: Arc<dyn Fn() + Send + Sync>) {
        self.e.h.port.0.lock().packet_model.after_descriptor = Some(f)
    }
    fn after_idle(&self, f: Arc<dyn Fn() + Send + Sync>) {
        self.e.h.port.0.lock().packet_model.after_idle = Some(f)
    }
    fn clear_policy(&self) {
        self.e.h.db.clear()
    }
    fn install_policy(&self) {
        self.e.h.db.install(domain());
    }
    fn c21() -> bool {
        true
    }
    fn conversions(&self) -> Option<usize> {
        Some(self.e.h.port.0.lock().thermal_conversions)
    }
    fn inject_status(&self, b: &[u8], p: &[u8], i: u8, flag: bool, s: u8) {
        self.e
            .h
            .port
            .0
            .lock()
            .packet_model
            .receive_status(b, p, i, flag, s)
    }
    fn controls(&self) -> Arc<crate::rtw88::packet_core::tests::Controls> {
        self.e.h.port.0.lock().packet_model.controls.clone()
    }
    fn sources(&self) -> Vec<Cap<FirmwareBlob, Read>> {
        let mut sources = self.e.h.sources.to_vec();
        sources.extend_from_slice(&[self.e.cap, self.cap]);
        sources
    }
}
fn smoke_rtw8821ce_ht_native_open_lgi_sgi_dhcp_ip() -> TestResult {
    check(|| cases::composition::<Case>(false))
}
fn smoke_rtw8821ce_ht_reentrant_original_amsdu_group_epoch_and_tx_credit() -> TestResult {
    check(cases::reentrant_receive_epoch::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8821c",
    smoke_rtw8821ce_ht_reentrant_original_amsdu_group_epoch_and_tx_credit
);
fn smoke_rtw8821ce_ht_native_phy_pages_before_ccmp_and_original_amsdu() -> TestResult {
    check(cases::native_phy_status::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8821c",
    smoke_rtw8821ce_ht_native_phy_pages_before_ccmp_and_original_amsdu
);
fn smoke_rtw8821ce_ht_real_m4_cancel_all_sources_originals_and_close() -> TestResult {
    check(cases::held_m4::<Case>)
}
fn smoke_rtw8821ce_ht_bound_response_and_original_mandatory_selector() -> TestResult {
    check(cases::responses::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8821c",
    smoke_rtw8821ce_ht_real_m4_cancel_all_sources_originals_and_close
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8821c",
    smoke_rtw8821ce_ht_bound_response_and_original_mandatory_selector
);

// Recipient RX BA uses the same retained H fixture, with a distinct R grant.
fn smoke_rtw8821ce_rx_ba_open_reordered_dhcp_ip() -> TestResult {
    check(|| crate::rtw88::rx_ba_tests::composition::<Case>(false))
}
fn smoke_rtw8821ce_rx_ba_pre_m4_closed_capture_cannot_stage_or_activate() -> TestResult {
    check(crate::rtw88::rx_ba_tests::pre_m4_denial::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8821c",
    smoke_rtw8821ce_rx_ba_pre_m4_closed_capture_cannot_stage_or_activate
);
fn smoke_rtw8821ce_rx_ba_delba_before_proposal_or_native_submit() -> TestResult {
    check(crate::rtw88::rx_ba_tests::delba_before_submit::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8821c",
    smoke_rtw8821ce_rx_ba_delba_before_proposal_or_native_submit
);
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8821c",
    smoke_rtw8821ce_rx_ba_open_reordered_dhcp_ip
);
fn smoke_rtw8821ce_rx_ba_wpa2_reordered_dhcp_ip() -> TestResult {
    check(|| crate::rtw88::rx_ba_tests::composition::<Case>(true))
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8821c",
    smoke_rtw8821ce_rx_ba_wpa2_reordered_dhcp_ip
);
fn smoke_rtw8821ce_rx_ba_ssn_wrap_bar_holes_and_tu_inactivity() -> TestResult {
    check(crate::rtw88::rx_ba_tests::windows_bar_timers::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8821c",
    smoke_rtw8821ce_rx_ba_ssn_wrap_bar_holes_and_tu_inactivity
);
fn smoke_rtw8821ce_rx_ba_original3839_amsdu_mic_and_tid_pn() -> TestResult {
    check(crate::rtw88::rx_ba_tests::original_amsdu::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8821c",
    smoke_rtw8821ce_rx_ba_original3839_amsdu_mic_and_tid_pn
);
fn smoke_rtw8821ce_rx_ba_held_success_ccx_capture_and_peer_delba() -> TestResult {
    check(crate::rtw88::rx_ba_tests::receipt_and_delba::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8821c",
    smoke_rtw8821ce_rx_ba_held_success_ccx_capture_and_peer_delba
);
fn smoke_rtw8821ce_rx_ba_distinct_asset_refusal_retry_and_h_decline() -> TestResult {
    check(crate::rtw88::rx_ba_tests::assets_and_fallback::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8821c",
    smoke_rtw8821ce_rx_ba_distinct_asset_refusal_retry_and_h_decline
);
fn smoke_rtw8821ce_rx_ba_current_sources_cancel_and_uncertain_dma() -> TestResult {
    check(crate::rtw88::rx_ba_tests::authority_and_uncertainty::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8821c",
    smoke_rtw8821ce_rx_ba_current_sources_cancel_and_uncertain_dma
);
fn smoke_rtw8821ce_rx_ba_real_group_reply_retires_old_key_window() -> TestResult {
    check(crate::rtw88::rx_ba_tests::key_epoch::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8821c",
    smoke_rtw8821ce_rx_ba_real_group_reply_retires_old_key_window
);
fn smoke_rtw8821ce_ht_native_wpa2_lgi_sgi_dhcp_ip() -> TestResult {
    check(|| cases::composition::<Case>(true))
}
fn smoke_rtw8821ce_ht_original_authenticated_default3839_amsdu() -> TestResult {
    check(cases::amsdu::<Case>)
}
fn smoke_rtw8821ce_ht_distinct_assets_retry_and_legacy_fallback() -> TestResult {
    check(cases::refused_assets::<Case>)
}
fn smoke_rtw8821ce_ht_each_mcs_native_rx_bounds_and_lost_gain() -> TestResult {
    check(cases::rates_and_native_errors::<Case>)
}
fn smoke_rtw8821ce_ht_actual_addba_decline_receipt_and_source_loss() -> TestResult {
    check(cases::decline_and_authority::<Case>)
}
fn smoke_rtw8821ce_ht_descriptor_rx_current_policy_publication_fences() -> TestResult {
    check(cases::publication_fences::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8821c",
    smoke_rtw8821ce_ht_native_open_lgi_sgi_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8821c",
    smoke_rtw8821ce_ht_native_wpa2_lgi_sgi_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8821c",
    smoke_rtw8821ce_ht_original_authenticated_default3839_amsdu
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8821c",
    smoke_rtw8821ce_ht_distinct_assets_retry_and_legacy_fallback
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8821c",
    smoke_rtw8821ce_ht_each_mcs_native_rx_bounds_and_lost_gain
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8821c",
    smoke_rtw8821ce_ht_actual_addba_decline_receipt_and_source_loss
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8821c",
    smoke_rtw8821ce_ht_descriptor_rx_current_policy_publication_fences
);

//! C22 actual retained firmware/radio/packet/DHCP adapter for distinct N22H.
use super::*;
use crate::rtw88::firmware_transport::Error;
use crate::rtw88::{ht, ht_tests as cases};
struct Case {
    e: Extended,
    cap: Cap<FirmwareBlob, Read>,
}
fn smoke_rtw8822ce_native_early_m3_and_closed_data_before_m2_ccx() -> TestResult {
    result(cases::early_m3_control::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8822c",
    smoke_rtw8822ce_native_early_m3_and_closed_data_before_m2_ccx
);
fn smoke_rtw8822ce_tx_ba_open_dhcp_ip_and_recipient_coexistence() -> TestResult {
    result(|| crate::rtw88::tx_ba_tests::composition::<Case>(false))
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8822c",
    smoke_rtw8822ce_tx_ba_open_dhcp_ip_and_recipient_coexistence
);
fn smoke_rtw8822ce_tx_ba_wpa2_dhcp_ip_and_recipient_coexistence() -> TestResult {
    result(|| crate::rtw88::tx_ba_tests::composition::<Case>(true))
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8822c",
    smoke_rtw8822ce_tx_ba_wpa2_dhcp_ip_and_recipient_coexistence
);
fn smoke_rtw8822ce_tx_ba_distinct_assets_and_h_fallback() -> TestResult {
    result(crate::rtw88::tx_ba_tests::refusal_and_legacy::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8822c",
    smoke_rtw8822ce_tx_ba_distinct_assets_and_h_fallback
);
fn smoke_rtw8822ce_tx_ba_peer_response_and_actual_per_tid_ssn() -> TestResult {
    result(crate::rtw88::tx_ba_tests::peer_response_and_ssn::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8822c",
    smoke_rtw8822ce_tx_ba_peer_response_and_actual_per_tid_ssn
);
fn smoke_rtw8822ce_tx_ba_held_request_ccx_cancel_and_dma() -> TestResult {
    result(crate::rtw88::tx_ba_tests::held_dialog_and_cancel::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8822c",
    smoke_rtw8822ce_tx_ba_held_request_ccx_cancel_and_dma
);
fn smoke_rtw8822ce_tx_ba_mac_fifo_all_sources_and_late_receipts() -> TestResult {
    result(crate::rtw88::tx_ba_tests::fifo_and_authority::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8822c",
    smoke_rtw8822ce_tx_ba_mac_fifo_all_sources_and_late_receipts
);
fn smoke_rtw8822ce_tx_ba_partial_bd_current_authority_and_close() -> TestResult {
    result(crate::rtw88::tx_ba_tests::partial_publication_and_close::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8822c",
    smoke_rtw8822ce_tx_ba_partial_bd_current_authority_and_close
);
fn smoke_rtw8822ce_tx_ba_peer_delba_and_real_key_epoch() -> TestResult {
    result(crate::rtw88::tx_ba_tests::delba_and_key_epoch::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba/rtl8822c",
    smoke_rtw8822ce_tx_ba_peer_delba_and_real_key_epoch
);
impl cases::Fixture for Case {
    type Io = RadioIo;
    fn tx_request(&self) -> Result<crate::rtw88::TxBaRequest, Error> {
        self.e.h.model(|io| io.tx_ba_request())
    }
    fn stage_tx(&self, bytes: Vec<u8>, cap: Cap<FirmwareBlob, Read>) -> Result<(), Error> {
        self.e.h.model(|io| {
            io.qualify_tx_ba(crate::rtw88::tx_ba_power::Source::Verified {
                bytes,
                cap,
                signer: Some([16; 32]),
            })
        })
    }
    fn descriptors(&self) -> Vec<[u8; 48]> {
        self.e.h.model(|io| io.packets.descriptors.clone())
    }
    fn ba_request(&self) -> Result<crate::rtw88::RxBaRequest, Error> {
        self.e.h.model(|io| io.rx_ba_request())
    }
    fn stage_ba(&self, bytes: Vec<u8>, cap: Cap<FirmwareBlob, Read>) -> Result<(), Error> {
        self.e.h.model(|io| {
            io.qualify_rx_ba(crate::rtw88::rx_ba_power::Source::Verified {
                bytes,
                signer: Some([13; 32]),
                cap,
            })
        })
    }
    fn advance_ms(&self, ms: u64) {
        self.e.h.model(|io| {
            io.clock.fetch_add(ms, core::sync::atomic::Ordering::AcqRel);
            io.packets.now += ms * 1000;
        });
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
        e.h.model(|io| io.packets.receive(&beacon, false, false));
        if qualified {
            let r =
                e.h.model(|io| io.ht_request())
                    .map_err(|_| "C22 HT request/factory facts missing")?;
            e.h.model(|io| {
                io.qualify_ht(ht::Source::Verified {
                    bytes: cases::record(&r, mcs, sgi, false),
                    signer: Some([12; 32]),
                    cap,
                })
            })
            .map_err(|_| "C22 distinct synthetic H record")?;
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
        self.e.h.model(|io| io.packets.receive_rate(b, r, w))
    }
    fn descriptor(&self) -> Option<[u8; 48]> {
        self.e.h.model(|io| io.packets.last_descriptor)
    }
    fn register(&self, r: u16) -> u32 {
        self.e.h.model(|io| io.register(usize::from(r)))
    }
    fn lose(&self, r: u16) {
        self.e.h.model(|io| io.lose_write(r))
    }
    fn cap(&self) -> Cap<FirmwareBlob, Read> {
        self.cap
    }
    fn request(&self) -> Result<ht::Request, &'static str> {
        self.e
            .h
            .model(|io| io.ht_request())
            .map_err(|_| "C22 H metadata")
    }
    fn stage(
        &self,
        b: Vec<u8>,
        c: Cap<FirmwareBlob, Read>,
    ) -> Result<(), crate::rtw88::firmware_transport::Error> {
        self.e.h.model(|io| {
            io.qualify_ht(ht::Source::Verified {
                bytes: b,
                signer: Some([12; 32]),
                cap: c,
            })
        })
    }
    fn retained(&self) -> (usize, u64) {
        self.e.h.model(|io| io.packets.payload_identity().unwrap())
    }
    fn after_descriptor(&self, f: Arc<dyn Fn() + Send + Sync>) {
        self.e.h.model(|io| io.packets.after_descriptor = Some(f))
    }
    fn after_idle(&self, f: Arc<dyn Fn() + Send + Sync>) {
        self.e.h.model(|io| io.packets.after_idle = Some(f))
    }
    fn clear_policy(&self) {
        self.e.db.clear()
    }
    fn install_policy(&self) {
        self.e.db.install(domain());
    }
    fn c21() -> bool {
        false
    }
    fn conversions(&self) -> Option<usize> {
        None
    }
    fn inject_status(&self, b: &[u8], p: &[u8], i: u8, flag: bool, s: u8) {
        self.e
            .h
            .model(|io| io.packets.receive_status(b, p, i, flag, s))
    }
    fn controls(&self) -> Arc<crate::rtw88::packet_core::tests::Controls> {
        self.e.h.model(|io| io.packets.controls.clone())
    }
    fn sources(&self) -> Vec<Cap<FirmwareBlob, Read>> {
        vec![self.e.h.calibration, self.e.cap, self.cap]
    }
}
fn smoke_rtw8822ce_ht_native_open_lgi_sgi_dhcp_ip() -> TestResult {
    result(|| cases::composition::<Case>(false))
}
fn smoke_rtw8822ce_ht_reentrant_original_amsdu_group_epoch_and_tx_credit() -> TestResult {
    result(cases::reentrant_receive_epoch::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8822c",
    smoke_rtw8822ce_ht_reentrant_original_amsdu_group_epoch_and_tx_credit
);
fn smoke_rtw8822ce_ht_native_phy_pages_before_ccmp_and_original_amsdu() -> TestResult {
    result(cases::native_phy_status::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8822c",
    smoke_rtw8822ce_ht_native_phy_pages_before_ccmp_and_original_amsdu
);
fn smoke_rtw8822ce_ht_real_m4_cancel_all_sources_originals_and_close() -> TestResult {
    result(cases::held_m4::<Case>)
}
fn smoke_rtw8822ce_ht_bound_response_and_original_mandatory_selector() -> TestResult {
    result(cases::responses::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8822c",
    smoke_rtw8822ce_ht_real_m4_cancel_all_sources_originals_and_close
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8822c",
    smoke_rtw8822ce_ht_bound_response_and_original_mandatory_selector
);
fn smoke_rtw8822ce_ht_native_wpa2_lgi_sgi_dhcp_ip() -> TestResult {
    result(|| cases::composition::<Case>(true))
}
fn smoke_rtw8822ce_ht_original_authenticated_default3839_amsdu() -> TestResult {
    result(cases::amsdu::<Case>)
}
fn smoke_rtw8822ce_ht_distinct_assets_retry_and_legacy_fallback() -> TestResult {
    result(cases::refused_assets::<Case>)
}
fn smoke_rtw8822ce_ht_each_mcs_native_rx_bounds_and_lost_gain() -> TestResult {
    result(cases::rates_and_native_errors::<Case>)
}
fn smoke_rtw8822ce_ht_actual_addba_decline_receipt_and_source_loss() -> TestResult {
    result(cases::decline_and_authority::<Case>)
}
fn smoke_rtw8822ce_ht_descriptor_rx_current_policy_publication_fences() -> TestResult {
    result(cases::publication_fences::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8822c",
    smoke_rtw8822ce_ht_native_open_lgi_sgi_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8822c",
    smoke_rtw8822ce_ht_native_wpa2_lgi_sgi_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8822c",
    smoke_rtw8822ce_ht_original_authenticated_default3839_amsdu
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8822c",
    smoke_rtw8822ce_ht_distinct_assets_retry_and_legacy_fallback
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8822c",
    smoke_rtw8822ce_ht_each_mcs_native_rx_bounds_and_lost_gain
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8822c",
    smoke_rtw8822ce_ht_actual_addba_decline_receipt_and_source_loss
);
kernel_test_in!(
    "drivers/wireless/rtw88/ht/rtl8822c",
    smoke_rtw8822ce_ht_descriptor_rx_current_policy_publication_fences
);

// Recipient RX BA uses the same retained H fixture, with a distinct R grant.
fn smoke_rtw8822ce_rx_ba_open_reordered_dhcp_ip() -> TestResult {
    result(|| crate::rtw88::rx_ba_tests::composition::<Case>(false))
}
fn smoke_rtw8822ce_rx_ba_pre_m4_closed_capture_cannot_stage_or_activate() -> TestResult {
    result(crate::rtw88::rx_ba_tests::pre_m4_denial::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8822c",
    smoke_rtw8822ce_rx_ba_pre_m4_closed_capture_cannot_stage_or_activate
);
fn smoke_rtw8822ce_rx_ba_delba_before_proposal_or_native_submit() -> TestResult {
    result(crate::rtw88::rx_ba_tests::delba_before_submit::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8822c",
    smoke_rtw8822ce_rx_ba_delba_before_proposal_or_native_submit
);
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8822c",
    smoke_rtw8822ce_rx_ba_open_reordered_dhcp_ip
);
fn smoke_rtw8822ce_rx_ba_wpa2_reordered_dhcp_ip() -> TestResult {
    result(|| crate::rtw88::rx_ba_tests::composition::<Case>(true))
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8822c",
    smoke_rtw8822ce_rx_ba_wpa2_reordered_dhcp_ip
);
fn smoke_rtw8822ce_rx_ba_ssn_wrap_bar_holes_and_tu_inactivity() -> TestResult {
    result(crate::rtw88::rx_ba_tests::windows_bar_timers::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8822c",
    smoke_rtw8822ce_rx_ba_ssn_wrap_bar_holes_and_tu_inactivity
);
fn smoke_rtw8822ce_rx_ba_original3839_amsdu_mic_and_tid_pn() -> TestResult {
    result(crate::rtw88::rx_ba_tests::original_amsdu::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8822c",
    smoke_rtw8822ce_rx_ba_original3839_amsdu_mic_and_tid_pn
);
fn smoke_rtw8822ce_rx_ba_held_success_ccx_capture_and_peer_delba() -> TestResult {
    result(crate::rtw88::rx_ba_tests::receipt_and_delba::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8822c",
    smoke_rtw8822ce_rx_ba_held_success_ccx_capture_and_peer_delba
);
fn smoke_rtw8822ce_rx_ba_distinct_asset_refusal_retry_and_h_decline() -> TestResult {
    result(crate::rtw88::rx_ba_tests::assets_and_fallback::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8822c",
    smoke_rtw8822ce_rx_ba_distinct_asset_refusal_retry_and_h_decline
);
fn smoke_rtw8822ce_rx_ba_current_sources_cancel_and_uncertain_dma() -> TestResult {
    result(crate::rtw88::rx_ba_tests::authority_and_uncertainty::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8822c",
    smoke_rtw8822ce_rx_ba_current_sources_cancel_and_uncertain_dma
);
fn smoke_rtw8822ce_rx_ba_real_group_reply_retires_old_key_window() -> TestResult {
    result(crate::rtw88::rx_ba_tests::key_epoch::<Case>)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba/rtl8822c",
    smoke_rtw8822ce_rx_ba_real_group_reply_retires_old_key_window
);

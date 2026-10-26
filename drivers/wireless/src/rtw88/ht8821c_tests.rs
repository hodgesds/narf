//! C21 actual retained reserved firmware DMA → Q/P/S/L/H → HT station adapter.
use super::*;
use crate::rtw88::{ht, ht_tests as cases};
struct Case {
    e: Extended,
    cap: Cap<FirmwareBlob, Read>,
}
impl cases::Fixture for Case {
    type Io = Backend<Port, Block>;
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

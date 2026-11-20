// SPDX-License-Identifier: GPL-2.0-or-later
//! Optional PMF over actual SDPCM/BCDC commands, events and BDC data.
use super::super::optional_mfp_common::{self as common, Factory, Fixture};
use super::*;
use crate::cyw43439::mfp_fixture::Conversation;
use narf_wireless::reg::db::Database;

struct Native;
impl Factory for Native {
    type Native = Harness;
    fn create(
        &mut self,
        secure: bool,
        supported: bool,
        plan: Conversation,
        db: Option<Arc<Database>>,
    ) -> Result<Harness, &'static str> {
        let mut h = Harness::new_config(secure, db, Some((supported, false, 0)))?;
        h.association_ies = plan.expected_request(secure);
        h.bus.firmware.lock().mfp_conversation(plan);
        Ok(h)
    }
}
impl Fixture for Harness {
    type Radio = Runtime<Bus>;
    fn device(&self) -> &Arc<ModelDevice> {
        &self.device
    }
    fn configure(&self, plan: Conversation) {
        self.bus.firmware.lock().mfp_conversation(plan);
    }
    fn commands(&self) -> Vec<(u32, Vec<u8>)> {
        self.bus.firmware.lock().mfp_commands()
    }
    fn scan(&self) -> Result<(), &'static str> {
        Harness::scan(self)
    }
    fn key(&self, foreign: bool) {
        self.bus.firmware.lock().key_receipt(foreign);
    }
    // This native SDPCM fixture is PIO and owns no hardware DMA mappings.
    fn clean_dma(&self) -> bool {
        true
    }
}
fn smoke_cyw_optional_pmf_native_policy_ap_matrix() -> TestResult {
    common::matrix(&mut Native).map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/optional_pmf",
    smoke_cyw_optional_pmf_native_policy_ap_matrix
);
fn smoke_cyw_optional_pmf_original_request_response_and_absence_proof() -> TestResult {
    common::proof(&mut Native).map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/optional_pmf",
    smoke_cyw_optional_pmf_original_request_response_and_absence_proof
);
fn smoke_cyw_optional_pmf_cancelled_native_mode_request_response() -> TestResult {
    common::cancellation(&mut Native).map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/optional_pmf",
    smoke_cyw_optional_pmf_cancelled_native_mode_request_response
);
fn smoke_cyw_optional_pmf_foreign_key_receipt_cannot_authorize() -> TestResult {
    common::foreign_keys(&mut Native).map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/optional_pmf",
    smoke_cyw_optional_pmf_foreign_key_receipt_cannot_authorize
);
fn smoke_cyw_optional_pmf_current_policy_fences_held_response() -> TestResult {
    common::current_policy(&mut Native).map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/optional_pmf",
    smoke_cyw_optional_pmf_current_policy_fences_held_response
);
fn smoke_cyw_optional_pmf_real_nl80211_connect() -> TestResult {
    common::nl_connect(&mut Native).map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/optional_pmf",
    smoke_cyw_optional_pmf_real_nl80211_connect
);

fn network() -> Result<(), &'static str> {
    for (secure, mode, ap) in [
        (false, 0, 0),
        (true, 1, 0),
        (true, 1, 128),
        (true, 1, 192),
        (true, 2, 128),
    ] {
        let h = Native.create(secure, true, Conversation::new(mode, ap), None)?;
        composition_native(h, secure, mode != 0 && ap != 0, false)?;
    }
    let mut h = Harness::new_features(true, None, Some((true, false, 0)), Some((1, 0)))?;
    let plan = Conversation::new(1, 128);
    h.association_ies = plan.expected_request(true);
    h.bus.firmware.lock().mfp_conversation(plan);
    composition_native(h, true, true, true)?;
    Ok(())
}
fn smoke_cyw_optional_pmf_open_wpa2_protected_unprotected_real_dhcp_ip() -> TestResult {
    network().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/optional_pmf",
    smoke_cyw_optional_pmf_open_wpa2_protected_unprotected_real_dhcp_ip
);

fn native_faults() -> Result<(), &'static str> {
    for fault in [1, 3, 4] {
        let h = Native.create(true, true, Conversation::new(1, 128), None)?;
        h.bus.firmware.lock().mfp_profile(true, false, fault);
        if h.scan_and_associate(true).is_ok()
            || h.device.link_up()
            || h.device
                .state
                .try_lock()
                .unwrap()
                .station
                .management_protection()
        {
            return Err("native optional mode/BSSID/length fault became PMF proof");
        }
    }
    // Invalid caller OCV cannot be discarded by canonicalization.
    let mut h = Native.create(true, true, Conversation::new(1, 128), None)?;
    h.association_ies[21] = 64;
    if h.scan_and_associate(true).is_ok() || h.bus.firmware.lock().command_count(26) != 0 {
        return Err("optional RSNE silently discarded caller OCV");
    }
    Ok(())
}
fn smoke_cyw_optional_pmf_native_mode_peer_and_caller_denials() -> TestResult {
    native_faults().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/optional_pmf",
    smoke_cyw_optional_pmf_native_mode_peer_and_caller_denials
);

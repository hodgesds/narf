// SPDX-License-Identifier: GPL-2.0-or-later
//! Optional PMF over retained CR4/common-ring native command and packet DMA.
use super::super::optional_mfp_common::{self as common, Factory, Fixture};
use super::*;
use crate::cyw43439::mfp_fixture::Conversation;
use narf_wireless::reg::db::Database;

struct Native(u32);
impl Factory for Native {
    type Native = Harness;
    fn create(
        &mut self,
        secure: bool,
        supported: bool,
        plan: Conversation,
        db: Option<Arc<Database>>,
    ) -> Result<Harness, &'static str> {
        let mut h = Harness::new_profile(
            self.0,
            secure,
            true,
            false,
            6,
            db,
            Some((supported, false, 0)),
        )?;
        h.association_ies = plan.expected_request(secure);
        h.bus.mfp_conversation(plan);
        Ok(h)
    }
}
impl Fixture for Harness {
    type Radio = TestAdapter;
    fn device(&self) -> &Arc<ModelDevice> {
        &self.device
    }
    fn configure(&self, plan: Conversation) {
        self.bus.mfp_conversation(plan);
    }
    fn commands(&self) -> Vec<(u32, Vec<u8>)> {
        self.bus
            .commands()
            .into_iter()
            .map(|(id, b, _)| (id, b))
            .collect()
    }
    fn scan(&self) -> Result<(), &'static str> {
        Harness::scan(self)
    }
    fn key(&self, foreign: bool) {
        self.bus.key_receipt(foreign);
    }
    fn clean_dma(&self) -> bool {
        self.bus.stats().5 == 0
    }
}
fn both(f: impl Fn(&mut Native) -> Result<(), &'static str>) -> TestResult {
    for version in [5, 6] {
        if let Err(error) = f(&mut Native(version)) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
fn smoke_brcmf_optional_pmf_native_policy_ap_matrix() -> TestResult {
    both(common::matrix)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/optional_pmf",
    smoke_brcmf_optional_pmf_native_policy_ap_matrix
);
fn smoke_brcmf_optional_pmf_original_request_response_and_absence_proof() -> TestResult {
    both(common::proof)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/optional_pmf",
    smoke_brcmf_optional_pmf_original_request_response_and_absence_proof
);
fn smoke_brcmf_optional_pmf_cancelled_native_mode_request_response() -> TestResult {
    both(common::cancellation)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/optional_pmf",
    smoke_brcmf_optional_pmf_cancelled_native_mode_request_response
);
fn smoke_brcmf_optional_pmf_foreign_key_receipt_cannot_authorize() -> TestResult {
    both(common::foreign_keys)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/optional_pmf",
    smoke_brcmf_optional_pmf_foreign_key_receipt_cannot_authorize
);
fn smoke_brcmf_optional_pmf_current_policy_fences_held_response() -> TestResult {
    both(common::current_policy)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/optional_pmf",
    smoke_brcmf_optional_pmf_current_policy_fences_held_response
);
fn smoke_brcmf_optional_pmf_real_nl80211_connect() -> TestResult {
    both(common::nl_connect)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/optional_pmf",
    smoke_brcmf_optional_pmf_real_nl80211_connect
);

fn network(native: &mut Native) -> Result<(), &'static str> {
    for (secure, mode, ap) in [
        (false, 0, 0),
        (true, 1, 0),
        (true, 1, 128),
        (true, 1, 192),
        (true, 2, 128),
    ] {
        let h = native.create(secure, true, Conversation::new(mode, ap), None)?;
        composition_native(h, secure, mode != 0 && ap != 0, false)?;
    }
    let vht = crate::cyw43439::phy_fixture::Vht80 {
        caps: [3, 7],
        mode: Some(1),
        txstreams: Some(3),
        txbf: [None, None],
        txbf_request: 0,
        inventory: vec![0xd826, 0xe02a],
        center: 42,
        fault: crate::cyw43439::phy_fixture::VhtFault::None,
    };
    let mut h = Harness::new_vht(native.0, true, 36, None, true, 7, vht)?;
    let plan = Conversation::new(1, 128);
    h.association_ies = plan.expected_request(true);
    h.bus.mfp_conversation(plan);
    composition_native(h, true, true, true)?;
    Ok(())
}
fn smoke_brcmf_optional_pmf_open_wpa2_protected_unprotected_real_dhcp_ip() -> TestResult {
    both(network)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/optional_pmf",
    smoke_brcmf_optional_pmf_open_wpa2_protected_unprotected_real_dhcp_ip
);

fn native_faults(native: &mut Native) -> Result<(), &'static str> {
    for fault in [1, 3, 4] {
        let h = native.create(true, true, Conversation::new(1, 128), None)?;
        h.bus.mfp_profile(true, false, fault);
        if h.associate(true).is_ok()
            || h.device.link_up()
            || h.device
                .state
                .try_lock()
                .unwrap()
                .station
                .management_protection()
            || h.bus.stats().5 != 0
        {
            return Err("native optional mode/BSSID/length fault became PMF proof or freed DMA");
        }
    }
    let mut h = native.create(true, true, Conversation::new(1, 128), None)?;
    h.association_ies[21] = 64;
    if h.associate(true).is_ok() || h.bus.commands().iter().any(|(id, _, _)| *id == 26) {
        return Err("optional RSNE silently discarded caller OCV");
    }
    Ok(())
}
fn smoke_brcmf_optional_pmf_native_mode_peer_and_caller_denials() -> TestResult {
    both(native_faults)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/optional_pmf",
    smoke_brcmf_optional_pmf_native_mode_peer_and_caller_denials
);

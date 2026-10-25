// SPDX-License-Identifier: GPL-2.0-or-later
//! Live host-policy replacement through retained PCIe/msgbuf DMA.
use super::*;
include!("../cyw43439/live_policy_cases.rs");
fn live(database: Arc<Database>) -> Result<Harness, &'static str> {
    Harness::new_channel_policy(6, true, false, false, 6, Some(database))
}
fn connect(harness: &Harness) -> Result<(), &'static str> {
    harness.associate(true)
}
fn scan(harness: &Harness) -> Result<(), &'static str> {
    harness.scan()
}
fn request() -> AssociateRequest {
    Harness::request(true)
}
fn sent(harness: &Harness) -> usize {
    harness.bus.sent()
}
fn powers(harness: &Harness) -> Vec<Vec<u8>> {
    harness
        .bus
        .commands()
        .iter()
        .filter(|(command, body, _)| *command == 263 && body.starts_with(b"qtxpower\0"))
        .map(|(_, body, _)| body[9..].to_vec())
        .collect()
}
fn replace_on_command(harness: &Harness, command: u32, database: Arc<Database>) {
    harness.bus.clear_policy_on(command, database);
}
fn stale_authorization(harness: &Harness) {
    harness.bus.stale_authorization();
}
fn retained(harness: &Harness) -> Result<(), &'static str> {
    if harness.bus.stats().5 != 0 {
        return Err("policy loss released DMA without firmware quiescence");
    }
    Ok(())
}
fn smoke_brcmf_live_tightened_removed_or_cleared_policy_closes_queued_tx() -> TestResult {
    tightening().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/regulatory",
    smoke_brcmf_live_tightened_removed_or_cleared_policy_closes_queued_tx
);
fn smoke_brcmf_live_looser_policy_preserves_acknowledged_power_and_data() -> TestResult {
    relaxation().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/regulatory",
    smoke_brcmf_live_looser_policy_preserves_acknowledged_power_and_data
);
fn smoke_brcmf_live_policy_loss_during_native_join_and_power_receipts_is_terminal() -> TestResult {
    between_receipts().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/regulatory",
    smoke_brcmf_live_policy_loss_during_native_join_and_power_receipts_is_terminal
);

fn smoke_brcmf_live_policy_loss_before_firmware_up_prevents_attachment() -> TestResult {
    for version in [5, 6] {
        let database = database();
        let Ok((adapter, bus)) = firmware::create(version, true) else {
            return TestResult::Fail("native bootstrap owner");
        };
        bus.clear_policy_on(86, database.clone());
        if !matches!(
            ready(Station::initialize_live(adapter, &[], database)),
            Ok(Err(Error::Authority))
        ) || bus.commands().iter().any(|(command, _, _)| *command == 2)
            || bus.stats().5 != 0
        {
            return TestResult::Fail("policy lost during setup enabled firmware or freed DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/regulatory",
    smoke_brcmf_live_policy_loss_before_firmware_up_prevents_attachment
);

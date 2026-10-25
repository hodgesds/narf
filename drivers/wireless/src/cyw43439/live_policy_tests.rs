// SPDX-License-Identifier: GPL-2.0-or-later
//! Live host-policy replacement through native SDPCM/BCDC control/data.
use super::*;
include!("live_policy_cases.rs");
fn live(database: Arc<Database>) -> Result<Harness, &'static str> {
    Harness::new_policy(true, Some(database))
}
fn connect(harness: &Harness) -> Result<(), &'static str> {
    harness.scan_and_associate(true)
}
fn scan(harness: &Harness) -> Result<(), &'static str> {
    ready(harness.device.scan(scan_request()))?
        .map(|_| ())
        .map_err(|_| "live escan")
}
fn scan_request() -> ScanRequest {
    ScanRequest {
        ssids: Vec::new(),
        channels: vec![6],
        frequencies_mhz: vec![2437],
        active: false,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    }
}
fn request() -> AssociateRequest {
    AssociateRequest {
        bssid: AP,
        ssid: b"test".to_vec(),
        frequency_mhz: 2437,
        channel: 6,
        security: narf_wireless::SecurityConfig::Wpa2 { psk: [0x11; 32] },
        ie: Vec::new(),
    }
}
fn sent(harness: &Harness) -> usize {
    harness.bus.firmware.lock().sent_data()
}
fn powers(harness: &Harness) -> Vec<Vec<u8>> {
    harness.bus.firmware.lock().qtxpowers()
}
fn replace_on_command(harness: &Harness, command: u32, database: Arc<Database>) {
    harness
        .bus
        .firmware
        .lock()
        .clear_policy_on(command, database);
}
fn stale_authorization(harness: &Harness) {
    let mut firmware = harness.bus.firmware.lock();
    let maximum = firmware.credit_window(8);
    firmware.event(0, 0, 0, &[], maximum);
    firmware.event(46, 6, 0, &[], maximum);
}
fn retained(_: &Harness) -> Result<(), &'static str> {
    Ok(())
}
fn smoke_cyw_live_tightened_removed_or_cleared_policy_closes_queued_tx() -> TestResult {
    tightening().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/regulatory",
    smoke_cyw_live_tightened_removed_or_cleared_policy_closes_queued_tx
);
fn smoke_cyw_live_looser_policy_preserves_acknowledged_power_and_data() -> TestResult {
    relaxation().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/regulatory",
    smoke_cyw_live_looser_policy_preserves_acknowledged_power_and_data
);
fn smoke_cyw_live_policy_loss_during_native_join_and_power_receipts_is_terminal() -> TestResult {
    between_receipts().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/regulatory",
    smoke_cyw_live_policy_loss_during_native_join_and_power_receipts_is_terminal
);

fn smoke_cyw_live_policy_loss_before_firmware_up_prevents_attachment() -> TestResult {
    let database = database();
    let bus = Bus::new(true);
    bus.firmware.lock().clear_policy_on(86, database.clone());
    if !matches!(
        ready(Station::initialize_live(
            Runtime::new(bus.clone()),
            &[1],
            database
        )),
        Ok(Err(Error::Authority))
    ) || bus.firmware.lock().command_count(2) != 0
    {
        return TestResult::Fail("policy lost during setup still enabled/published firmware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/regulatory",
    smoke_cyw_live_policy_loss_before_firmware_up_prevents_attachment
);

fn resumed_credit_wait() -> Result<(), &'static str> {
    let database = database();
    let harness = live(database.clone())?;
    connect(&harness)?;
    {
        let mut firmware = harness.bus.firmware.lock();
        let maximum = firmware.credit_window(0);
        firmware.event(16, 0, 1, &[], maximum);
    }
    harness.device.drain();
    let before = harness.bus.firmware.lock().power_commands();
    harness
        .device
        .set_power_save(true)
        .map_err(|_| "credit-held PS request")?;
    {
        let mut future = pin!(harness.device.apply_power_save());
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return Err("native control did not wait for real SDPCM credit");
        }
        if harness.bus.firmware.lock().power_commands() != before {
            return Err("native control published before credit grant");
        }
        database.clear();
        {
            let mut firmware = harness.bus.firmware.lock();
            let maximum = firmware.credit_window(8);
            firmware.event(16, 0, 1, &[], maximum);
        }
        if future.as_mut().poll(&mut cx).is_pending() {
            return Err("revoked control kept waiting after resume instead of closing");
        }
    }
    if harness.bus.firmware.lock().power_commands() != before {
        return Err("resumed native control published with revoked host policy");
    }
    terminal(&harness, &database, sent(&harness))
}
fn smoke_cyw_live_policy_fence_prevents_publication_after_native_credit_wait() -> TestResult {
    resumed_credit_wait().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/regulatory",
    smoke_cyw_live_policy_fence_prevents_publication_after_native_credit_wait
);

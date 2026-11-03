//! EMLSR policy vectors authored from Linux mld/mlo.c semantics; they
//! exercise decisions only and claim no firmware or RF behaviour.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn link(spec: u8, band: Band, primary: u32, width: u32, grade: u16) -> Candidate {
    Candidate {
        spec_link: spec,
        band,
        primary_mhz: primary,
        center_mhz: primary,
        width_mhz: width,
        signal_dbm: -50,
        csa_active: false,
        grade,
        chan_load: 128,
        active: true,
        load_not_by_us: 60,
    }
}

fn smoke_iwl_emlsr_pair_state_and_link_selection() -> TestResult {
    let five = link(1, Band::Five, 5180, 20, 100);
    let six = link(2, Band::Six, 6115, 20, 90);
    let two = link(0, Band::Two, 2437, 20, 80);
    if pair_state(&five, &six, false, false) != 0 {
        return TestResult::Fail("5/6GHz pair refused");
    }
    if pair_state(&two, &six, true, false) & exit::BT_COEX == 0 {
        return TestResult::Fail("2.4GHz link with active BT allowed");
    }
    let mut weak = six;
    weak.signal_dbm = -70;
    if pair_state(&five, &weak, false, false) & exit::LOW_RSSI == 0 {
        return TestResult::Fail("low-RSSI secondary allowed");
    }
    // Same 5GHz band: 36 (5180) vs 149 (5745) is separated; 36 vs 52 not.
    let high = link(3, Band::Five, 5745, 20, 90);
    let near = link(4, Band::Five, 5260, 20, 90);
    if pair_state(&five, &high, false, false) & exit::EQUAL_BAND != 0
        || pair_state(&five, &near, false, false) & exit::EQUAL_BAND == 0
    {
        return TestResult::Fail("5GHz equal-band separation rule differs from Linux");
    }
    let mut idle = five;
    idle.load_not_by_us = 5;
    if pair_state(&idle, &six, false, false) & exit::CHAN_LOAD == 0 {
        return TestResult::Fail("unloaded primary entered EMLSR");
    }
    let mut wide = five;
    wide.width_mhz = 80;
    wide.center_mhz = 5210;
    wide.load_not_by_us = 30;
    if channel_load_allows(&wide, &six, false) || !channel_load_allows(&wide, &six, true) {
        return TestResult::Fail("bandwidth-ratio channel load rule differs from Linux");
    }
    if rssi_threshold(80, false) != Some(-61) || rssi_threshold(60, false).is_some() {
        return TestResult::Fail("EMLSR RSSI thresholds differ from constants.h");
    }
    let mut state = Emlsr::default();
    let chosen = state.select(&[five, six], true, false, false);
    if chosen
        != Some(Selection {
            active: 0b110,
            primary: 1,
        })
    {
        return TestResult::Fail("EMLSR pair not preferred over single best link");
    }
    let single = state.select(&[five, six], false, false, false);
    if single.map(|s| s.active) != Some(0b10) {
        return TestResult::Fail("EMLSR pair selected without capability");
    }
    state.blocked = blocked::TPT;
    if state
        .select(&[five, six], true, false, false)
        .map(|s| s.active)
        != Some(0b10)
    {
        return TestResult::Fail("blocked EMLSR selected a pair");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_emlsr_pair_state_and_link_selection
);

fn smoke_iwl_emlsr_block_exit_prevention_and_notifications() -> TestResult {
    let mut state = Emlsr {
        selected: 0b110,
        selected_primary: 2,
        ..Emlsr::default()
    };
    state.links_activated(0b110);
    if !state.emlsr_active() || state.primary_link() != 2 {
        return TestResult::Fail("selected EMLSR primary not retained");
    }
    // Block keeps the requested link and installs no prevention.
    if state.block(blocked::ROC, 1, true, 1_000) != Some(0b10)
        || state.blocked != blocked::ROC
        || state.block(blocked::ROC, 1, true, 1_001).is_some()
    {
        return TestResult::Fail("EMLSR block did not exit once to the kept link");
    }
    if !state.unblock(blocked::ROC, true) || state.unblock(blocked::ROC, true) {
        return TestResult::Fail("EMLSR unblock did not report a single full unblock");
    }
    // FW recommend-leave exits to the primary and prevents for 30s.
    let leave = [0u8; 8];
    if state.mode_notification(&leave, true, 2_000) != Ok(Some(0b100))
        || state.blocked & blocked::PREVENTION == 0
    {
        return TestResult::Fail("FW recommend-leave did not exit with prevention");
    }
    if state.mode_notification(&leave[..4], true, 2_000).is_ok() {
        return TestResult::Fail("ESR mode notification v1 size accepted as v2");
    }
    if state.prevention_tick(true, 31_000) || !state.prevention_tick(true, 32_000) {
        return TestResult::Fail("EMLSR prevention timing differs from 30s");
    }
    // Second FW-request exit inside 400s gets the 300s prevention.
    state.links_activated(0b110);
    let _ = state.mode_notification(&leave, true, 40_000);
    if state.prevention_tick(true, 339_000) || !state.prevention_tick(true, 340_000) {
        return TestResult::Fail("repeated FW-request exit lacks short prevention");
    }
    // Transition failure: unknown fw link or failed deactivation disconnects.
    let mut fail = [0u8; 12];
    fail[4] = 1;
    state.links_activated(0b110);
    let spec = |fw: u32| match fw {
        0 => Some(1),
        1 => Some(2),
        _ => None,
    };
    if state.transition_failure(&fail, spec, 400_000) != Ok(TransitionFailure::Keep(0b10)) {
        return TestResult::Fail("EMLSR entry failure did not keep firmware-named link");
    }
    fail[0] = 3;
    if state.transition_failure(&fail, spec, 400_001) != Ok(TransitionFailure::Disconnect) {
        return TestResult::Fail("EMLSR failure on unowned fw link did not disconnect");
    }
    fail[0] = 0;
    fail[4] = 0;
    if state.transition_failure(&fail, spec, 400_002) != Ok(TransitionFailure::Disconnect) {
        return TestResult::Fail("EMLSR deactivation failure did not disconnect");
    }
    if state.transition_failure(&fail[..8], spec, 400_003).is_ok() {
        return TestResult::Fail("short EMLSR transition failure accepted");
    }
    let ap = Some(EmlCapabilities(1 | (15 << 11)));
    if client_mld_fields(ap, Some(9)) != (10, 9) || client_mld_fields(None, None) != (0, 0) {
        return TestResult::Fail("MAC client EMLSR timeout clamp differs from mld/iface.c");
    }
    if !capable(true, true, true, ap, false) || capable(true, true, true, ap, true) {
        return TestResult::Fail("EMLSR capability ignored CDB dual-radio exclusion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_emlsr_block_exit_prevention_and_notifications
);

fn smoke_iwl_mld_fw_link_station_ids_bounded_by_tlvs() -> TestResult {
    use super::super::sc_mlo::FwIds;
    if FwIds::new(None, Some(16)).is_ok() || FwIds::new(Some(5), Some(16)).is_ok() {
        return TestResult::Fail("FW link ids admitted without valid NUM_LINKS TLV");
    }
    let Ok(mut ids) = FwIds::new(Some(2), Some(2)) else {
        return TestResult::Fail("valid FW link/station counts refused");
    };
    if ids.claim(0, 0).is_err() || ids.claim(0, 1).is_ok() {
        return TestResult::Fail("association FW link0/STA0 claim not exclusive");
    }
    if ids.allocate() != Ok((1, 1)) || ids.allocate().is_ok() {
        return TestResult::Fail("second link FW ids exceeded firmware counts");
    }
    ids.release(1, 1);
    if ids.allocate() != Ok((1, 1)) {
        return TestResult::Fail("released second-link FW ids not reusable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_fw_link_station_ids_bounded_by_tlvs
);

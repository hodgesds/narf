// SPDX-License-Identifier: GPL-2.0-or-later
//! Native source-program tests, using a register/H2C boundary rather than C
//! compilation or source extraction. No hardware acceptance follows.
use super::super::{btc::*, tests::FakeHal};
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
fn board() -> BtCoexist {
    BtCoexist::bind(HwPg {
        bt_exist: true,
        ant_num: 1,
        single_ant_path: 0,
        chip_type: ChipType::Rtl8821,
        package_type: 0,
        rfe_type: 0,
        interface: ChipInterface::Pci,
    })
}
fn run<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    for _ in 0..1024 {
        if let Poll::Ready(value) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return value;
        }
    }
    panic!("bounded8821A source fixture did not complete");
}
fn tdma(hal: &FakeHal) -> Vec<Vec<u8>> {
    hal.h2c
        .iter()
        .filter(|(id, _)| *id == 0x60)
        .map(|(_, v)| v.clone())
        .collect()
}

fn smoke_8821a1ant_source_init_antenna_backup_and_autoreport() -> TestResult {
    let mut btc = board();
    let mut hal = FakeHal::default();
    let mut algorithm = B8821a1Ant::new();
    hal.regs.insert(0x790, 0xc0);
    hal.regs.insert(0x430, 0x55);
    hal.regs.insert(0x42a, 8);
    if run(Ctx::new(&mut btc, &mut hal).init_hw_config(&mut algorithm)).is_err()
        || !btc.initialized
        || !btc.auto_report_1ant
        || algorithm.dm.backup_arfr_cnt1 != 0x55
        || algorithm.dm.backup_retry_limit != 8
        || hal.last(0x790) != Some(0xc5)
        || hal.last(0x4c) != Some(1 << 24)
        || hal.last(0xcb4) != Some(0x66)
        || hal.get(0xcb7, 1) & 0x30 != 0x10
        || hal.last(0x76e) != Some(12)
        || !hal.h2c.contains(&(0x65, vec![1, 1]))
        || !hal.h2c.contains(&(0x61, vec![1]))
        || hal.last(0x6c0) != Some(0x55555555)
        || hal.last(0x6c4) != Some(0x55555555)
    {
        return TestResult::Fail("8821A init reused a different chip antenna/table/report program");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a1ant_source_init_antenna_backup_and_autoreport
);

fn smoke_8821a1ant_literal_tdma_rows_and_ap_rewrite() -> TestResult {
    let mut btc = board();
    let mut hal = FakeHal::default();
    let mut a = B8821a1Ant::new();
    for (kind, expected) in [
        (2, [0x51, 0x2b, 3, 0x10, 0x50]),
        (3, [0x51, 0x1d, 0x1d, 0, 0x10]),
        (5, [0x61, 0x15, 3, 0x11, 0x10]),
        (11, [0x51, 0x15, 3, 0x10, 0x50]),
        (14, [0x51, 0x1e, 3, 0x10, 0x14]),
        (20, [0x61, 0x35, 3, 0x11, 0x10]),
        (33, [0xa3, 0x25, 3, 0x30, 0x90]),
        (41, [0x51, 0x15, 3, 0x11, 0x11]),
        (42, [0x51, 0x20, 3, 0x11, 0x11]),
        (43, [0x51, 0x30, 3, 0x10, 0x11]),
    ] {
        if run(a.ps_tdma(&mut Ctx::new(&mut btc, &mut hal), true, true, kind)).is_err()
            || hal.h2c.last() != Some(&(0x60, expected.to_vec()))
        {
            return TestResult::Fail("8821A literal TDMA row mismatch");
        }
    }
    btc.wifi.ap_mode = true;
    if run(a.ps_tdma(&mut Ctx::new(&mut btc, &mut hal), true, true, 1)).is_err()
        || hal.h2c.last() != Some(&(0x60, vec![0x61, 0x3a, 3, 0x10, 0x30]))
    {
        return TestResult::Fail("source AP TDMA rewrite mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a1ant_literal_tdma_rows_and_ap_rewrite
);

fn smoke_8821a1ant_c2h_acl_a2dp_drives_actual_lps_table_and_tdma() -> TestResult {
    let mut btc = board();
    btc.wifi.station_linked = true;
    btc.wifi.busy = true;
    let mut hal = FakeHal::default();
    let mut a = B8821a1Ant::new();
    if run(a.bt_info_notify(&mut Ctx::new(&mut btc, &mut hal), &[1, 0x49, 0x40, 30, 0])).is_err()
        || a.dm.bt_status != BtStatus::AclBusy
        || a.sta.bt_rssi != 70
        || !btc.bt_link_info.a2dp_only
        || !btc.bt_info.bt_busy
        || !btc.bt_info.bt_ctrl_agg_buf_size
        || btc.bt_info.agg_buf_size != 8
        || !hal.lps.iter().any(|(enter, _)| *enter)
        || tdma(&hal).last() != Some(&vec![0x51, 0x1e, 3, 0x10, 0x14])
        || hal.last(0x6c4) != Some(0x5a5a5a5a)
    {
        return TestResult::Fail("native BT-info did not compose 8821A ACL/A2DP source actions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a1ant_c2h_acl_a2dp_drives_actual_lps_table_and_tdma
);

fn smoke_8821a1ant_fourway_preserves_both_source_special_transitions() -> TestResult {
    let mut btc = board();
    btc.wifi.station_linked = true;
    btc.wifi.in_4way = true;
    let mut hal = FakeHal::default();
    let mut a = B8821a1Ant::new();
    if run(a.bt_info_notify(&mut Ctx::new(&mut btc, &mut hal), &[1, 0x69, 0x40, 30, 0])).is_err()
        || tdma(&hal)
            != vec![
                vec![0x61, 0x35, 3, 0x11, 0x11],
                vec![0x51, 0x1e, 3, 0x10, 0x14],
            ]
    {
        return TestResult::Fail("special packet independent source ifs were collapsed or aliased");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a1ant_fourway_preserves_both_source_special_transitions
);

fn smoke_8821a1ant_5g_and_manual_stop_source_boundaries() -> TestResult {
    let mut btc = board();
    btc.wifi.under_5g = true;
    let mut hal = FakeHal::default();
    let mut a = B8821a1Ant::new();
    if run(a.run(&mut Ctx::new(&mut btc, &mut hal))).is_err()
        || !hal.h2c.contains(&(0x63, vec![1]))
        || !hal.h2c.contains(&(0x60, vec![0, 0, 0, 8, 0]))
        || hal.last(0xcb4) != Some(0x77)
        || hal.get(0xcb7, 1) & 0x30 != 0x20
    {
        return TestResult::Fail("5GHz did not select the 8821A BT-side source path");
    }
    let effects = (hal.writes.len(), hal.h2c.len());
    btc.manual_control = true;
    if run(a.run(&mut Ctx::new(&mut btc, &mut hal))).is_err()
        || effects != (hal.writes.len(), hal.h2c.len())
    {
        return TestResult::Fail("manual stop emitted a mechanism");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a1ant_5g_and_manual_stop_source_boundaries
);

fn smoke_8821a1ant_partial_effects_do_not_commit_previous_program() -> TestResult {
    let mut btc = board();
    let mut hal = FakeHal::default();
    let mut a = B8821a1Ant::new();
    hal.deny_write = Some(0x6c8);
    if a.coex_table_with_type(&mut Ctx::new(&mut btc, &mut hal), true, 3) != Err(Error::State)
        || a.dm.pre_val0x6c0 != 0
        || hal.writes.len() != 2
    {
        return TestResult::Fail("partial table write became a completed cached program");
    }
    hal.deny_h2c = Some(0x60);
    if run(a.ps_tdma(&mut Ctx::new(&mut btc, &mut hal), true, true, 14)) != Err(Error::State)
        || a.dm.pre_ps_tdma_on
        || a.dm.pre_ps_tdma != 0
    {
        return TestResult::Fail("failed TDMA advanced previous state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a1ant_partial_effects_do_not_commit_previous_program
);

fn smoke_8821a1ant_malformed_c2h_and_rssi_hysteresis() -> TestResult {
    let mut btc = board();
    let mut hal = FakeHal::default();
    let mut a = B8821a1Ant::new();
    for body in [&[][..], &[1][..], &[1, 9, 0][..], &[1; 11][..]] {
        if run(a.bt_info_notify(&mut Ctx::new(&mut btc, &mut hal), body)) != Err(Error::Packet) {
            return TestResult::Fail("malformed BT-info accepted");
        }
    }
    if !hal.h2c.is_empty()
        || !hal.writes.is_empty()
        || a.sta.bt_info_c2h_cnt != [0; 3]
        || rssi_state(RssiState::Low, 29, 2, 28, 0) != RssiState::StayLow
        || rssi_state(RssiState::Low, 30, 2, 28, 0) != RssiState::High
        || rssi_state(RssiState::High, 27, 2, 28, 0) != RssiState::Low
    {
        return TestResult::Fail("malformed state mutation or source RSSI thresholds differ");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a1ant_malformed_c2h_and_rssi_hysteresis
);

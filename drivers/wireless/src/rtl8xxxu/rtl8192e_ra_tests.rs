//! RTL8192EU gen2 H2C rate-adaptation regressions. Expected masks/words are
//! derived by hand from Linux `rtl8xxxu/core.c` (`rtl8xxxu_refresh_rate_mask`,
//! `rtl8xxxu_gen2_update_rate_mask`, `rtl8xxxu_gen2_report_connect`,
//! `rtl8xxxu_bss_info_changed`); nothing here is a hardware receipt.

use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::firmware_transport::Owner;
use super::rate_adaptation::Level;
use super::regs::ChipFamily;
use super::rtl8192e_packet::RaReport;
use super::rtl8192e_power as rf;
use super::rtl8192e_ra::{self as ra, rate_id, Peer, Ra};
use super::rtl8192e_tests::{Fake, Op};

const BGN_2SS: Peer = Peer {
    legacy: 0xfff,
    mcs: [0xff, 0xff],
    ht: true,
    sgi: true,
};

fn smoke_rtl8192eu_ra_level_masks() -> TestResult {
    let m = ra::level_mask(BGN_2SS, Level::High, true, false);
    if m.mask != 0x0f8f_0000 || m.rate_id != rate_id::BGN_20M_2SS_BN || !m.sgi {
        return TestResult::Fail("BGN 2SS high");
    }
    let m = ra::level_mask(BGN_2SS, Level::Low, false, true);
    if m.mask != 0x000f_f015 || m.rate_id != rate_id::BGN_40M_1SS || !m.bandwidth40 {
        return TestResult::Fail("BGN 1SS 40 low");
    }
    let gn = Peer {
        legacy: 0xff0,
        ..BGN_2SS
    };
    let m = ra::level_mask(gn, Level::High, true, false);
    if m.mask != 0x0fff_fff0 || m.rate_id != rate_id::GN_N2SS {
        return TestResult::Fail("GN has no level mask");
    }
    let b = Peer {
        legacy: 0xf,
        mcs: [0; 2],
        ht: false,
        sgi: false,
    };
    let m = ra::level_mask(b, Level::Low, true, false);
    if m.mask != 0xd || m.rate_id != rate_id::B {
        return TestResult::Fail("B mask");
    }
    if ra::macid_cfg(0x0fff_ffff, 2, true, true, 0) != [0x40, 0, 0x82, 1, 0xff, 0xff, 0xff, 0x0f]
        || ra::media_status(0, ra::MACID_ROLE_AP, true) != [0x01, 0x21, 0, 0]
        || ra::rssi_setting(0, 70) != [0x42, 0, 0, 70, 0, 0, 0, 0]
    {
        return TestResult::Fail("H2C layouts");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_ra_level_masks
);

fn smoke_rtl8192eu_ra_refuses_unadmitted_and_folds_reports() -> TestResult {
    // A 2SS peer against a 1SS admitted set is refused, never narrowed.
    if Ra::new(BGN_2SS, 0x000f_ffff, 1, false).is_ok() {
        return TestResult::Fail("unadmitted MCS8..15 narrowed");
    }
    let legacy = Peer {
        legacy: 0xff0,
        mcs: [0; 2],
        ht: false,
        sgi: false,
    };
    if Ra::new(legacy, 0xfff, 2, true).is_ok() {
        return TestResult::Fail("40 MHz for a non-HT peer");
    }
    let mut state = match Ra::new(BGN_2SS, 0x0fff_ffff, 2, false) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("admitted peer refused"),
    };
    match state.refresh(-30) {
        Some(m) if m.mask == 0x0f8f_0000 && state.level() == Level::High => {}
        _ => return TestResult::Fail("first refresh high"),
    }
    if state.refresh(-30).is_some() {
        return TestResult::Fail("unchanged level re-sent");
    }
    match state.refresh(-75) {
        Some(m) if m.mask == 0x0f8f_f000 && state.level() == Level::Mid => {}
        _ => return TestResult::Fail("mid refresh"),
    }
    let report = RaReport {
        rate: 0x13,
        sgi: true,
        macid: 0,
        ldpc: false,
        txbf: false,
        noisy: false,
        bandwidth40: Some(false),
    };
    state.report(&report);
    match state.tx_rate() {
        Some(r) if r.desc_rate == 0x13 && r.sgi && !r.bandwidth40 => {}
        _ => return TestResult::Fail("RA report fold"),
    }
    state.report(&RaReport {
        macid: 3,
        rate: 0,
        ..report
    });
    if state.tx_rate().map(|r| r.desc_rate) != Some(0x13) {
        return TestResult::Fail("foreign macid folded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_ra_refuses_unadmitted_and_folds_reports
);

fn smoke_rtl8192eu_ra_connect_sequence() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    let mut state = Ra::new(BGN_2SS, 0x0fff_ffff, 2, false).unwrap();
    if narf_scheduler::block_on(owner.ra_connect_8192e(&mut state, 0)).is_ok() {
        return TestResult::Fail("aid 0 accepted");
    }
    if narf_scheduler::block_on(owner.ra_connect_8192e(&mut state, 5)).is_err() {
        return TestResult::Fail("connect failed");
    }
    let writes: Vec<(u16, Vec<u8>)> =
        io.0.lock()
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::Write(a, v) => Some((*a, v.clone())),
                _ => None,
            })
            .collect();
    let expect: [(u16, &[u8]); 8] = [
        (0x1f0, &[0xff, 0xff, 0xff, 0x0f]),
        (0x1d0, &[0x40, 0, 0x80, 0]),
        (0x55d, &[0xff]),
        (0x422, &[0]),
        (0x541, &[0x64]),
        (0x542, &[0]),
        (0x6a8, &[0x05, 0xc0]),
        (0x1d4, &[0x01, 0x21, 0, 0]),
    ];
    if writes.len() != expect.len()
        || writes
            .iter()
            .zip(expect.iter())
            .any(|((a, v), (ea, ev))| a != ea || v.as_slice() != *ev)
    {
        return TestResult::Fail("joinbss write order");
    }
    match state.tx_rate() {
        Some(r) if r.desc_rate == 27 && r.sgi && !r.bandwidth40 => {}
        _ => return TestResult::Fail("association ra_report"),
    }
    if narf_scheduler::block_on(owner.ra_watchdog_8192e(&mut state, -30)).is_err() {
        return TestResult::Fail("watchdog");
    }
    let rssi = io.writes(0x1d8);
    let refresh = io.writes(0x1dc);
    if rssi != [alloc::vec![0x42, 0, 0, 70]]
        || refresh != [alloc::vec![0x40, 0, 0x82, 0]]
        || io.writes(0x1f8) != [alloc::vec![0, 0, 0, 0]]
        || io.writes(0x1fc) != [alloc::vec![0, 0, 0x8f, 0x0f]]
    {
        return TestResult::Fail("watchdog RSSI + refresh H2C");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_ra_connect_sequence
);

fn smoke_rtl8192eu_enable_disable_rf() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    io.0.lock().regs[0x4c..0x50].copy_from_slice(&(1u32 << 24).to_le_bytes());
    io.0.lock().regs[0x64] = 0x03;
    if narf_scheduler::block_on(rf::enable_rf(&owner)).is_err() {
        return TestResult::Fail("enable_rf");
    }
    if io.writes(0xe70) != [alloc::vec![0, 0, 0xc0, 0]]
        || io.writes(0x40) != [alloc::vec![0x20]]
        || io.writes(0x76e) != [alloc::vec![0x04]]
        || io.writes(0x38) != [alloc::vec![0, 0x08, 0, 0]]
        || io.writes(0x944) != [alloc::vec![3, 0, 0, 0]]
        || io.writes(0x930) != [alloc::vec![0x77]]
        || io.writes(0x4c) != [alloc::vec![0, 0, 0x80, 0]]
        || io.writes(0x64) != [alloc::vec![0x02]]
        || io.writes(0x522) != [alloc::vec![0]]
    {
        return TestResult::Fail("rtl8192e_enable_rf writes");
    }
    if narf_scheduler::block_on(rf::disable_rf(&owner)).is_err()
        || io.writes(0xe70).last() != Some(&alloc::vec![0, 0, 0, 0])
    {
        return TestResult::Fail("gen2_disable_rf");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_enable_disable_rf
);

fn smoke_rtl8192eu_power_off_sequence() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    // RXDMA never idle: terminal before RF/MCU are touched.
    if narf_scheduler::block_on(rf::power_off(&owner)).is_ok() {
        return TestResult::Fail("busy RXDMA accepted");
    }
    if !io.writes(0x1f).is_empty() || !io.writes(0x80).is_empty() {
        return TestResult::Fail("touched RF/MCU after failed flush");
    }
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    {
        let mut g = io.0.lock();
        g.regs[0x286] = 0x02; // RXDMA idle
        g.regs[0x80] = 0x80; // firmware in RAM
        g.regs[0x02..0x04].copy_from_slice(&0x0403u16.to_le_bytes());
        g.regs[0x04ec] = 0x02;
        g.aps_off_completes = true;
    }
    if narf_scheduler::block_on(rf::power_off(&owner)).is_err() {
        return TestResult::Fail("power_off failed");
    }
    if io.writes(0x214) != [alloc::vec![0, 0]]
        || io.writes(0x200) != [alloc::vec![0, 0, 0, 0x80]]
        || io.writes(0x4ec) != [alloc::vec![0]]
        || io.writes(0x1f).first() != Some(&alloc::vec![0])
        || io.writes(0x1cf) != [alloc::vec![0x20]]
        || io.writes(0x80) != [alloc::vec![0]]
        || io.writes(0x553) != [alloc::vec![0x20]]
    {
        return TestResult::Fail("rtl8192eu_power_off writes");
    }
    // BB reset bits cleared, CPU enable forced off, then reset_8051 re-enables.
    let func: Vec<Vec<u8>> = io.writes(0x02);
    if func.first() != Some(&alloc::vec![0x02]) || func.get(1) != Some(&alloc::vec![0x00]) {
        return TestResult::Fail("BBRSTB then BB_GLB_RSTN");
    }
    // emu_to_disabled leaves APS_FSMCO[11] (bit 3 of byte 1) set.
    if io.0.lock().regs[5] & 0x18 != 0x08 {
        return TestResult::Fail("card disabled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_power_off_sequence
);

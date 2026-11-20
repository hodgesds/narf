// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE media-status, RF-saving, false-alarm and power-off
//! tests (software register models only; written, unexecuted).

use super::phy_tests::Fake;
use super::ps::{self, BcnCtrl, RfSaving, RfState};
use super::version::Version;
use crate::rtlwifi::firmware_transport::Io;
use narf_kernel_test::{kernel_test_in, TestResult};

fn ver(raw: u8) -> Version {
    match Version::qualify(raw) {
        Ok(v) => v,
        Err(_) => unreachable!("test version qualifies"),
    }
}

/// `_rtl92ce_set_media_status` (stop TX beacon, enable the beacon
/// sub-function, MSR, `BCNTCFG + 1`) and `HW_VAR_AID`.
fn smoke_rtl8192ce_media_status_and_aid() -> TestResult {
    let io = Fake::new();
    {
        let mut g = io.0.lock();
        g.regs[usize::from(ps::REG_MSR)] = 0xf1;
        g.regs[usize::from(ps::REG_FWHW_TXQ_CTRL + 2)] = 0xff;
        g.regs[usize::from(ps::REG_TBTT_PROHIBIT + 2)] = 0x03;
        g.regs[usize::from(ps::REG_BCN_PSR_RPT + 1)] = 0xc5;
    }
    let mut bcn = BcnCtrl::default();
    if ps::set_media_status(&io, &mut bcn, true).is_err() || ps::set_aid(&io, 0x0123).is_err() {
        return TestResult::Fail("station media status");
    }
    {
        let g = io.0.lock();
        if g.regs[usize::from(ps::REG_MSR)] != 0xf2
            || g.regs[usize::from(ps::REG_FWHW_TXQ_CTRL + 2)] != 0xbf
            || g.regs[usize::from(ps::REG_TBTT_PROHIBIT + 1)] != 0x64
            || g.regs[usize::from(ps::REG_TBTT_PROHIBIT + 2)] != 0x02
            || g.regs[usize::from(ps::REG_BCN_CTRL)] != 0x1d
            || g.regs[usize::from(ps::REG_BCNTCFG + 1)] != 0x66
            || g.regs[usize::from(ps::REG_BCN_PSR_RPT)..usize::from(ps::REG_BCN_PSR_RPT) + 2]
                != [0x23, 0xc1]
        {
            return TestResult::Fail("MSR_INFRA / beacon / AID registers");
        }
    }
    if ps::set_media_status(&io, &mut bcn, false).is_err()
        || io.read8(ps::REG_MSR) != Ok(0xf0)
        || bcn.0 != 0x1d
    {
        return TestResult::Fail("MSR_NOLINK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_media_status_and_aid
);

/// `rtl92c_dm_rf_saving`: forced normal from `RF_MAX` restores the latched
/// registers; the 30/25 hysteresis enters and leaves `RF_SAVE`.
fn smoke_rtl8192ce_rf_saving_hysteresis() -> TestResult {
    let io = Fake::new();
    let _ = io.write32(0x0874, 0x0014_4000);
    let _ = io.write32(0x0c70, 0x8);
    let _ = io.write32(0x085c, 0x5500_0000);
    let _ = io.write32(0x0a74, 0x7000);
    let mut s = RfSaving::new();
    if s.run(&io, true, 0).is_err() || s.pre != RfState::Normal {
        return TestResult::Fail("forced normal");
    }
    if io.read32(0x0874) != Ok(0x0014_4000) || io.read32(0x085c) != Ok(0x5500_0000) {
        return TestResult::Fail("restore keeps latched values");
    }
    if s.run(&io, false, 29).is_err() || s.pre != RfState::Normal {
        return TestResult::Fail("below 30 stays normal");
    }
    if s.run(&io, false, 30).is_err() || s.pre != RfState::Save {
        return TestResult::Fail("30 enters save");
    }
    if io.read32(0x085c) != Ok(0x6300_0000)
        || io.read32(0x0c70) != Ok(0)
        || io.read32(0x0a74) != Ok(0x3000)
        || io.read32(0x0818).map(|v| v & (1 << 28)) != Ok(1 << 28)
    {
        return TestResult::Fail("RF_SAVE register set");
    }
    if s.run(&io, false, 26).is_err() || s.pre != RfState::Save {
        return TestResult::Fail("26 stays save");
    }
    if s.run(&io, false, 25).is_err() || s.pre != RfState::Normal {
        return TestResult::Fail("25 leaves save");
    }
    if io.read32(0x085c) != Ok(0x5500_0000) || io.read32(0x0c70) != Ok(0x8) {
        return TestResult::Fail("restore after save");
    }
    if s.run(&io, false, 0).is_err() || s.pre != RfState::Max {
        return TestResult::Fail("no RSSI is RF_MAX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_rf_saving_hysteresis
);

/// `rtl92c_dm_false_alarm_counter_statistics` sums and counter resets.
fn smoke_rtl8192ce_false_alarm_statistics() -> TestResult {
    let io = Fake::new();
    let _ = io.write32(0x0da0, 0x0003_0000);
    let _ = io.write32(0x0da4, 0x0005_0004);
    let _ = io.write32(0x0da8, 0x0000_0006);
    let _ = io.write32(0x0cf0, 0x0008_0007);
    let _ = io.write32(0x0a5c, 0x0000_0010);
    let _ = io.write32(0x0a58, 0x0200_0000);
    let fa = match ps::false_alarm(&io) {
        Ok(fa) => fa,
        Err(_) => return TestResult::Fail("read"),
    };
    if fa.ofdm != 3 + 4 + 5 + 6 + 7 + 8 || fa.cck != 0x210 || fa.all != 3 + 4 + 5 + 6 + 0x210 {
        return TestResult::Fail("counter sums");
    }
    if io.read32(0x0a2c).map(|v| (v >> 14) & 3) != Ok(2)
        || io.read32(0x0d00).map(|v| v & 0x0800_0000) != Ok(0)
    {
        return TestResult::Fail("counter reset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_false_alarm_statistics
);

/// `_rtl92ce_poweroff_adapter` (non-BT): RF A reg 0 cleared, the
/// digital-core drop and the UMC B-cut `SPS0_CTRL` exception.
fn smoke_rtl8192ce_poweroff_adapter() -> TestResult {
    for (raw, umc_b) in [(0x10u8, false), (0x71, true)] {
        let io = Fake::new();
        io.0.lock().regs[usize::from(ps::REG_GPIO_PIN_CTRL)] = 0;
        io.0.lock().rf[0][0] = 0x3_0000;
        if narf_scheduler::block_on(ps::poweroff_adapter(&io, ver(raw))).is_err() {
            return TestResult::Fail("poweroff");
        }
        let g = io.0.lock();
        if g.rf[0][0] != 0
            || g.regs[usize::from(ps::REG_TXPAUSE)] != 0xff
            || g.regs[0x02] != 0xe0
            || g.regs[0x03] != 0x51
            || g.regs[0x80] != 0
            || g.regs[0x46] != 0xff
            || g.regs[0x42..0x44] != [0x90, 0x07]
            || g.regs[0x4c..0x4e] != [0x80, 0x80]
            || g.regs[0x28] != 0x80
            || g.regs[0x24] != 0x0e
            || g.regs[0x1c] != 0x0e
            || g.regs[0x05] != 0x10
            || g.w8.iter().any(|(r, v)| *r == 0x11 && *v == 0x23) == umc_b
        {
            return TestResult::Fail("poweroff register sequence");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_poweroff_adapter
);

/// `rtl92ce_set_hw_reg` station registers: `HW_VAR_BASIC_RATE` (RRSR +
/// `INIRTS_RATE_SEL`), slot / SIFS (`0x1010` with HT), ACK preamble, the
/// fixed `set_qos` rows and `rtl92ce_set_network_type` RCR/BCN_CTRL.
fn smoke_rtl8192ce_station_registers() -> TestResult {
    use super::mac::REG_RCR;
    use super::station as hw;
    if hw::basic_rate(0x0fff) != (0x015f, 8) || hw::basic_rate(0x000f) != (0x000f, 3) {
        return TestResult::Fail("HW_VAR_BASIC_RATE");
    }
    let io = Fake::new();
    if hw::configure_rates(&io, 0x0fff, 0x0001, 0x0420, None, true, 1).is_err() {
        return TestResult::Fail("configure_rates");
    }
    {
        let g = io.0.lock();
        let r = |a: u16| g.regs[usize::from(a)];
        if r(hw::REG_RRSR) != 0x5f
            || r(hw::REG_RRSR + 1) != 0x01
            || r(hw::REG_INIRTS_RATE_SEL) != 8
            || r(hw::REG_SLOT) != 9
            || r(hw::REG_SIFS_CTX + 1) != 0x10
            || r(hw::REG_RESP_SIFS_OFDM) != 0x10
            || r(hw::REG_RRSR + 2) != 0xa0
            || r(hw::REG_EDCA_VI_PARAM + 2) != 0x5e
        {
            return TestResult::Fail("rate / SIFS / preamble / EDCA registers");
        }
    }
    if hw::configure_rates(&io, 0x0ffe, 0x0001, 0, None, false, 0).is_ok() {
        return TestResult::Fail("basic set without 1M admitted");
    }
    let mut rcr = 0xf000_6a0e;
    let mut bcn = BcnCtrl::default();
    if hw::network_type_station(&io, &mut rcr, &mut bcn, true).is_err()
        || rcr != 0xf000_6ace
        || io.read32(REG_RCR) != Ok(0xf000_6ace)
        || bcn.0 & (1 << 4) != 0
    {
        return TestResult::Fail("linked network type");
    }
    if hw::network_type_station(&io, &mut rcr, &mut bcn, false).is_err()
        || rcr != 0xf000_6a0e
        || bcn.0 & (1 << 4) == 0
        || io.read8(ps::REG_MSR).map(|m| m & 3) != Ok(ps::MSR_NOLINK)
    {
        return TestResult::Fail("unlinked network type");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_station_registers
);

/// `_rtl_init_hw_ht_capab` per RF type (RX MCS0-7 on 1T1R, MCS0-15 on
/// 2T2R; the 20/40 form only when asked), `BSS_CHANGED_HT`
/// (`HW_VAR_SHORTGI_DENSITY`, `regtoset_normal` lowered to the peer factor,
/// `HW_VAR_AMPDU_MIN_SPACE` density 7) and `BSS_CHANGED_ERP_*`.
fn smoke_rtl8192ce_ht_capability_timing_and_erp() -> TestResult {
    use super::ht;
    use super::station as hw;
    use super::version::RfType;
    let one = ht::capability(RfType::T1R1, false, true).capability_body();
    let two = ht::capability(RfType::T2R2, true, true).capability_body();
    let cap = |b: &[u8; 26]| u16::from_le_bytes([b[0], b[1]]);
    if one[3] != 0xff
        || one[4] != 0
        || cap(&one) & 0x0002 != 0
        || cap(&one) & 0x0020 == 0
        || two[3] != 0xff
        || two[4] != 0xff
        || cap(&two) & 0x0042 != 0x0042
        || cap(&two) & 0x1000 == 0
        || one[2] & 0x1f != 0x1f
    {
        return TestResult::Fail("92CE / 88CE HT capability per RF type");
    }
    let io = Fake::new();
    let mut min_space = 0u8;
    if ht::timing(&io, &mut min_space, 0, 0).is_err() || min_space != 7 {
        return TestResult::Fail("BSS_CHANGED_HT timing");
    }
    {
        let g = io.0.lock();
        let r = |a: u16| g.regs[usize::from(a)];
        if [0u16, 1, 2, 3].map(|i| r(ht::REG_AGGLEN_LMT + i)) != [0x41, 0x44, 0x42, 0x44]
            || r(ht::REG_AMPDU_MIN_SPACE) != 7
        {
            return TestResult::Fail("AGGLEN_LMT / AMPDU_MIN_SPACE");
        }
    }
    if ht::timing(&io, &mut min_space, 3, 7).is_err()
        || [0u16, 1, 2, 3].map(|i| io.0.lock().regs[usize::from(ht::REG_AGGLEN_LMT + i)])
            != [0x41, 0xa8, 0x72, 0xb9]
    {
        return TestResult::Fail("64K factor keeps regtoset_normal");
    }
    if hw::erp_changed(&io, (false, false), (true, true), 1).is_err() {
        return TestResult::Fail("erp_changed");
    }
    let g = io.0.lock();
    if g.regs[usize::from(hw::REG_RRSR + 2)] != 0xa0 || g.regs[usize::from(hw::REG_SLOT)] != 9 {
        return TestResult::Fail("ERP preamble / slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_ht_capability_timing_and_erp
);

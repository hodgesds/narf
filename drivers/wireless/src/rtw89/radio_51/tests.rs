// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn calibration(thermal: u8, pa: u8) -> factory_51::Calibration {
    factory_51::Calibration {
        thermal: 0,
        tssi_cck: [0; 6],
        tssi_mcs: [0; 19],
        tssi_trim: [0; 8],
        trim_programmed: false,
        thermal_trim: thermal,
        thermal_programmed: thermal != 255,
        pa_bias: pa,
        pa_programmed: pa != 255,
        gain_offset: [0; 5],
        offset_valid: false,
        gain_comp: [0; 5],
        comp_valid: false,
        adc_td: 0,
    }
}

fn smoke_rtw89_n51_dm_init_txrx_path_and_power_trim_follow_rtw8851b() -> TestResult {
    let gain = Gain::default();
    let cal = calibration(0x0b, 0x5a);
    let inputs = channel_51::Inputs {
        gain: &gain,
        calibration: &cal,
        bases: [0, 0],
    };
    // rtw8851b_bb_ctrl_rx_path(RF_A) prefix.
    let fields = txrx_path_fields(Profile::INITIAL, &inputs);
    let head = [
        (PHY + 0x49c4, 0xf, 1),
        (PHY + 0x49c0, 0x3_c000, 1),
        (PHY + 0x49c0, 0x3c_0000, 1),
        (PHY + 0x0d18, 0x300, 0),
        (PHY + 0x0d18, 0x60_0000, 0),
        (PHY + 0x0d80, 0x3fc0, 4),
        (PHY + 0x0d80, 0x1_c000, 0),
        (PHY + 0x0d80, 0x380_0000, 0),
    ];
    if fields[..8] != head {
        return TestResult::Fail("ctrl_rx_path RF_A prefix differs from rtw8851b");
    }
    // No efuse gain: set_gain_offset writes nothing; then RSTB 1/3, the
    // rx_nss 1 limits and R_MAC_SEL MAC_SEL_MOD 0.
    let tail = [
        (PHY + 0x58dc, 0xc000_0000, 1),
        (PHY + 0x58dc, 0xc000_0000, 3),
        (PHY + 0x0d18, 0x300, 0),
        (PHY + 0x0d18, 0x60_0000, 0),
        (PHY + 0x0d80, 0x1_c000, 0),
        (PHY + 0x0d80, 0x380_0000, 0),
        (PHY + 0x09a4, 0x1c, 0),
    ];
    if fields[8..] != tail {
        return TestResult::Fail("cfg_txrx_path tail differs from rtw8851b");
    }
    // Valid gain comp inserts the R_P0_AGC_RSVD byte between them.
    let mut comp = cal;
    comp.comp_valid = true;
    comp.gain_comp[0] = -3;
    let inputs = channel_51::Inputs {
        gain: &gain,
        calibration: &comp,
        bases: [0, 0],
    };
    let with = txrx_path_fields(Profile::INITIAL, &inputs);
    if with[8] != (PHY + 0x4acc, 0xff, (-12i32) as u32) || with.len() != fields.len() + 1 {
        return TestResult::Fail("2.4GHz set_gain_offset comp not in cfg_txrx_path");
    }
    // rtw8851b_power_trim: __thm_setting(0x0b) = (1 << 3) | 5 = 0xd on
    // path A; PA bias 0x5a -> 2G 0xa, 5G 0x5. Unprogrammed writes nothing.
    let expected = [
        (0, 0x43, 0xf_0000, 0xd),
        (0, 0x60, 0xf000, 0xa),
        (0, 0x60, 0xf_0000, 0x5),
    ];
    if power_trim_writes(&cal) != expected {
        return TestResult::Fail("power trim differs from rtw8851b_power_trim");
    }
    if !power_trim_writes(&calibration(255, 255)).is_empty() {
        return TestResult::Fail("unprogrammed trim wrote RF");
    }
    // set_txpwr_ctrl: B_AX_PWR_REF 0 then path-A OFDM/CCK reference words.
    let mut refs = Vec::new();
    let _ = radio_power_c::reference_51(|a, m, v| {
        refs.push((a, m, v));
        Ok(())
    });
    let word = (172 << 18) | (312 << 9);
    if refs
        != [
            (0xd200, 0x0fff_fc00, 0),
            (PHY + 0x5804, 0x07ff_ffff, word),
            (PHY + 0x5808, 0x07ff_ffff, word),
        ]
    {
        return TestResult::Fail("txpwr reference differs from rtw8851b_set_txpwr_ref");
    }
    // mac.c rtw89_mac_setup_phycap: one-path ant_diversity = rfe % 3 == 2.
    if !antenna_diversity(2) || !antenna_diversity(53) || antenna_diversity(1) {
        return TestResult::Fail("antenna diversity RFE rule differs from mac.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_dm_init_txrx_path_and_power_trim_follow_rtw8851b
);

fn smoke_rtw89_n51_radio_owner_starts_new() -> TestResult {
    let radio = Radio::default();
    if radio.state() != State::New
        || radio.channel().is_some()
        || radio.bases().is_some()
        || radio.epoch() != 0
        || radio.tracker().is_some()
        || radio.antdiv().is_some()
        || radio.init().results().is_some()
        || radio.rfk().state() != ChannelState::New
    {
        return TestResult::Fail("fresh RTL8851B radio owner is not New");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_radio_owner_starts_new
);

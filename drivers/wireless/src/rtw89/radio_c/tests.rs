// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn calibration(thermal: [u8; 2], pa: [u8; 2]) -> factory_c::Calibration {
    factory_c::Calibration {
        thermal: [0; 2],
        tssi_cck: [[0; 6]; 2],
        tssi_mcs: [[0; 19]; 2],
        tssi_6g_mcs: [[0; 32]; 2],
        tssi_trim: [[0; 8]; 2],
        tssi_trim_6g: [[0; 16]; 2],
        trim_programmed: false,
        thermal_trim: thermal,
        thermal_programmed: thermal.iter().any(|&v| v != 255),
        pa_bias: pa,
        pa_programmed: pa.iter().any(|&v| v != 255),
        gain_offset: [[0; factory_c::GAIN_OFFSET_NR]; 2],
        offset_valid: false,
    }
}

fn smoke_rtw89_c_dm_init_txrx_path_and_power_trim_follow_rtw8852c() -> TestResult {
    // rtw8852c_bb_cfg_txrx_path RF_PATH_AB, rx_nss 2, default 2.4GHz chandef.
    let Some(fields) = txrx_path_fields(Band::Ghz2, 2) else {
        return TestResult::Fail("rx_nss 2 refused");
    };
    let head = [
        (PHY + 0x4978, 0xf, 3),
        (PHY + 0x4974, 0x3_c000, 3),
        (PHY + 0x4974, 0x3c_0000, 3),
        (PHY + 0x0d18, 0x300, 1),
        (PHY + 0x0d18, 0x60_0000, 1),
        (PHY + 0x0d80, 0x1_c000, 1),
        (PHY + 0x0d80, 0x380_0000, 1),
    ];
    if fields[..7] != head {
        return TestResult::Fail("cfg_rx_path RF_AB prefix differs from rtw8852c");
    }
    // ctrl_btg_bt_rx(true) starts with 0x4738 BIT(19) = 1.
    if fields[7] != (PHY + 0x4738, 1 << 19, 1) {
        return TestResult::Fail("btg_bt_rx(2G) does not follow the NSS limits");
    }
    let n = fields.len();
    let tail = [
        (PHY + 0x58dc, 0xc000_0000, 1),
        (PHY + 0x58dc, 0xc000_0000, 3),
        (PHY + 0x78dc, 0xc000_0000, 1),
        (PHY + 0x78dc, 0xc000_0000, 3),
        (PHY + 0x0d80, 0x3fc0, 8),
        (PHY + 0x0d18, 0x300, 1),
        (PHY + 0x0d18, 0x60_0000, 1),
        (PHY + 0x0d80, 0x1_c000, 1),
        (PHY + 0x0d80, 0x380_0000, 1),
    ];
    if fields[n - 9..] != tail {
        return TestResult::Fail("RSTB/USER_MAX/rx_nss tail differs from rtw8852c");
    }
    // rx_nss 1 rewrites the four NSS limits to 0 after cfg_rx_path.
    let Some(one) = txrx_path_fields(Band::Ghz5, 1) else {
        return TestResult::Fail("rx_nss 1 refused");
    };
    if one[one.len() - 4..].iter().any(|f| f.2 != 0) {
        return TestResult::Fail("rx_nss 1 did not clear the NSS limits");
    }
    if one.contains(&(PHY + 0x4738, 1 << 19, 1)) {
        return TestResult::Fail("5GHz chandef enabled BTG BT RX");
    }
    if txrx_path_fields(Band::Ghz2, 0).is_some() || txrx_path_fields(Band::Ghz2, 3).is_some() {
        return TestResult::Fail("invalid rx_nss accepted");
    }
    // rtw8852c_power_trim: __thm_setting(0x0b) = (1 << 3) | 5 = 0xd;
    // PA bias 0x5a -> 2G 0xa, 5G 0x5. Unprogrammed (0xff) writes nothing.
    let writes = power_trim_writes(&calibration([0x0b, 0x02], [0x5a, 0x31]));
    let expected = [
        (0, 0x43, 0xf_0000, 0xd),
        (1, 0x43, 0xf_0000, 0x1),
        (0, 0x60, 0xf000, 0xa),
        (0, 0x60, 0xf_0000, 0x5),
        (1, 0x60, 0xf000, 0x1),
        (1, 0x60, 0xf_0000, 0x3),
    ];
    if writes != expected {
        return TestResult::Fail("power trim RF writes differ from rtw8852c_power_trim");
    }
    if !power_trim_writes(&calibration([0xff; 2], [0xff; 2])).is_empty() {
        return TestResult::Fail("unprogrammed trim wrote RF");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_c_dm_init_txrx_path_and_power_trim_follow_rtw8852c
);

fn smoke_rtw89_c_radio_owner_starts_new() -> TestResult {
    let radio = Radio::default();
    if radio.state() != State::New
        || radio.channel().is_some()
        || radio.offset_base().is_some()
        || radio.epoch() != 0
        || radio.rfk().state() != ChannelState::New
    {
        return TestResult::Fail("fresh C radio owner is not New");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_c_radio_owner_starts_new
);

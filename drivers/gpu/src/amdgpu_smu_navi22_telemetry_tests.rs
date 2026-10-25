use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn table(layout: Layout) -> Vec<u8> {
    let mut b = vec![0u8; METRICS_BYTES];
    for (i, mhz) in [2400, 1000, 2000, 1940, 0, 0, 0, 0, 1200]
        .iter()
        .enumerate()
    {
        put32(&mut b, 4 * i, *mhz);
    }
    put16(&mut b, 52, 2450); // AverageGfxclkFrequencyPreDs
    put16(&mut b, 54, 600); // AverageGfxclkFrequencyPostDs
    put16(&mut b, 58, 1900); // AverageFclkFrequencyPostDs
    put16(&mut b, 62, 1000); // AverageUclkFrequencyPostDs
    put16(&mut b, 64, 40); // AverageGfxActivity
    put16(&mut b, 66, 7); // AverageUclkActivity
    put16(&mut b, 72, 186); // AverageSocketPower
    put16(&mut b, 74, 51); // TemperatureEdge
    put16(&mut b, 76, 63); // TemperatureHotspot
    put16(&mut b, 78, 58); // TemperatureMem
    put16(&mut b, 80, 49); // TemperatureVrGfx
    put16(&mut b, 86, 44); // TemperatureVrSoc
    match layout {
        Layout::V1 => {
            put32(&mut b, 96, (1 << 2) | (1 << 13)); // ThrottlerStatus
            b[101] = 31; // CurrFanPwm (unused: Linux reads THM registers)
            put16(&mut b, 102, 1350); // CurrFanSpeed
            b[130] = 3; // PcieRate
            b[131] = 6; // PcieWidth
        }
        Layout::V2 | Layout::V3 => {
            put32(&mut b, 96, 77); // AccCnt
            b[100 + 2] = 12; // ThrottlingPercentage[TEMP_HOTSPOT]
            b[100 + 13] = 1; // ThrottlingPercentage[PPT0]
            put16(&mut b, 122, 1350);
            let pcie = if layout == Layout::V3 { 152 } else { 150 };
            b[pcie] = 3;
            b[pcie + 1] = 6;
        }
    }
    b
}

fn navi22_metrics_decode_both_linux_layouts() -> TestResult {
    if Layout::for_firmware(0x412cff) != Layout::V1
        || Layout::for_firmware(0x412d00) != Layout::V2
        || Layout::for_firmware(0x413f00) != Layout::V2
    {
        return TestResult::Fail("MP1 11.0.11 metrics version threshold");
    }
    for layout in [Layout::V1, Layout::V2, Layout::V3] {
        let m = Metrics::decode(&table(layout), layout);
        let expected = Metrics {
            edge_milli: 51_000,
            hotspot_milli: 63_000,
            mem_milli: 58_000,
            vr_gfx_milli: 49_000,
            vr_soc_milli: 44_000,
            fan_rpm: 1350,
            socket_power_w: 186,
            gfx_mhz: 2450,
            fclk_mhz: 1900,
            mem_mhz: 1000,
            gfx_current_mhz: 2400,
            uclk_mhz: 2000,
            fclk_current_mhz: 1940,
            socclk_mhz: 1000,
            dcefclk_mhz: 1200,
            gfx_activity: 40,
            mem_activity: 7,
            throttlers: (1 << 2) | (1 << 13),
            pcie_rate: 3,
            pcie_width: 6,
        };
        if m != expected {
            return TestResult::Fail("metrics field offsets/units");
        }
    }
    // A V2 table read as V1 must not alias the fan into AccCnt or vice versa.
    let v2 = table(Layout::V2);
    if Metrics::decode(&v2, Layout::V1).fan_rpm == 1350 {
        return TestResult::Fail("V1 decoding reads the V2 fan offset");
    }
    // Idle GFX selects the post-deep-sleep average (BUSY_THRESHOLD = 15).
    let mut idle = table(Layout::V1);
    put16(&mut idle, 64, 15);
    if Metrics::decode(&idle, Layout::V1).gfx_mhz != 600 {
        return TestResult::Fail("busy threshold selection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    navi22_metrics_decode_both_linux_layouts
);

fn pptable(fan: bool) -> Vec<u8> {
    let mut t = vec![0u8; PPTABLE_BYTES];
    let features: u64 = if fan { FEATURE_FAN_CONTROL } else { 0 } | FEATURE_PPT;
    put32(&mut t, 4, features as u32);
    put32(&mut t, 8, (features >> 32) as u32);
    put16(&mut t, 12, 203); // SocketPowerLimitAc[PPT0]
    put16(&mut t, 52, 100); // TemperatureLimit[EDGE]
    put16(&mut t, 54, 110); // [HOTSPOT]
    put16(&mut t, 56, 100); // [MEM]
    put16(&mut t, 1018, 3300); // FanMaximumRpm
    t
}

fn navi22_board_limits_follow_sienna_thermal_range() -> TestResult {
    if PPTABLE_BYTES != crate::amdgpu_power_navi22::SMC_BYTES {
        return TestResult::Fail("PPTable size differs from the uploaded table");
    }
    let l = Limits::from_table(&pptable(true), 118, 0x13, 0x4).unwrap();
    if l != (Limits {
        edge_crit_milli: 100_000,
        edge_emergency_milli: 105_000,
        hotspot_crit_milli: 110_000,
        hotspot_emergency_milli: 115_000,
        mem_crit_milli: 100_000,
        mem_emergency_milli: 105_000,
        software_shutdown_c: 118,
        fan_max_rpm: Some(3300),
        ppt_table_w: 203,
        thermal_controller: 0x13,
        dc_by_gpio: true,
    }) {
        return TestResult::Fail("board limits");
    }
    if l.alert_window() != (0, 118) {
        return TestResult::Fail("THM alert window");
    }
    let fanless = Limits::from_table(&pptable(false), 300, 0, 0).unwrap();
    if fanless.fan_max_rpm.is_some() || fanless.dc_by_gpio || fanless.alert_window() != (0, 255) {
        return TestResult::Fail("fanless board / clamped window");
    }
    let mut zero = pptable(true);
    put16(&mut zero, 54, 0);
    if Limits::from_table(&zero, 118, 1, 0).is_some()
        || Limits::from_table(&pptable(true)[..PPTABLE_BYTES - 1], 118, 1, 0).is_some()
    {
        return TestResult::Fail("missing limit or truncated table accepted");
    }
    // smu_swctf_delayed_work_handler.
    if l.software_shutdown(Some(117_999))
        || !l.software_shutdown(Some(118_000))
        || !l.software_shutdown(None)
    {
        return TestResult::Fail("software CTF decision");
    }
    let unlimited = Limits {
        software_shutdown_c: 0,
        ..l
    };
    if !unlimited.software_shutdown(Some(20_000)) {
        return TestResult::Fail("no software limit must treat L2H as emergency");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    navi22_board_limits_follow_sienna_thermal_range
);

fn navi22_register_sensors_match_smu_v11_0() -> TestResult {
    // VID 0x40 -> (6200 - 1600) / 4 = 1150 mV; the 9th VID bit is dropped.
    if vddgfx_mv(0x0040_0000) != 1150
        || vddgfx_mv(0x0140_0000) != 1150
        || vddgfx_mv(0x0000_00ff) != 1550
    {
        return TestResult::Fail("SVI0 VDDCOR conversion");
    }
    if fan_pwm(0x0000_00ff, 0x80 << 9) != Some(128)
        || fan_pwm(100, 50 << 9) != Some(127)
        || fan_pwm(100, 200 << 9) != Some(255)
        || fan_pwm(0xffff_ff00, 50 << 9).is_some()
    {
        return TestResult::Fail("FDO PWM scaling");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi22",
    navi22_register_sensors_match_smu_v11_0
);

fn rdna2_metrics_select_exact_asic_thresholds() -> TestResult {
    use crate::amdgpu_rdna2::*;
    for (profile, threshold, layout) in [
        (&NAVI21, 0x3a4300, Layout::V2),
        (&NAVI21, 0x3a4900, Layout::V3),
        (&NAVI22, 0x412d00, Layout::V2),
        (&NAVI23, 0x3b2300, Layout::V2),
        (&NAVI24, 0x491100, Layout::V2),
    ] {
        let before = if layout == Layout::V3 {
            Layout::V2
        } else {
            Layout::V1
        };
        if Layout::for_profile(profile, threshold - 1) != before
            || Layout::for_profile(profile, threshold) != layout
        {
            return TestResult::Fail("ASIC-specific metrics threshold");
        }
        let decoded = Metrics::decode(&table(layout), layout);
        if decoded.fan_rpm != 1350
            || decoded.pcie_rate != 3
            || decoded.pcie_width != 6
            || decoded.hotspot_milli != 63000
            || decoded.throttlers != (1 << 2) | (1 << 13)
        {
            return TestResult::Fail("RDNA2 metrics union layout");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_metrics_select_exact_asic_thresholds
);

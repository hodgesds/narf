use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn metrics_table() -> Vec<u8> {
    let mut b = vec![0u8; METRICS_BYTES];
    put32(&mut b, 0, 2400); // CurrClock[GFXCLK]
    put32(&mut b, 4, 1000); // CurrClock[SOCCLK]
    put32(&mut b, 8, 2000); // CurrClock[UCLK]
    put32(&mut b, 12, 1940); // CurrClock[FCLK]
    put32(&mut b, 44, 1200); // CurrClock[DCFCLK]
    put16(&mut b, 54, 2450); // AverageGfxclkFrequencyPreDs
    put16(&mut b, 56, 600); // AverageGfxclkFrequencyPostDs
    put16(&mut b, 58, 1900); // AverageFclkFrequencyPreDs
    put16(&mut b, 60, 1500); // AverageFclkFrequencyPostDs
    put16(&mut b, 62, 2000); // AverageMemclkFrequencyPreDs
    put16(&mut b, 64, 1000); // AverageMemclkFrequencyPostDs
    put16(&mut b, 66, 1200); // AverageVclk0Frequency
    put16(&mut b, 68, 1100); // AverageDclk0Frequency
    put16(&mut b, 70, 900); // AverageVclk1Frequency
    put16(&mut b, 72, 800); // AverageDclk1Frequency
    put32(&mut b, 80, 77); // MetricsCounter
    put16(&mut b, 84, 1050); // AvgVoltage[GFX]
    put16(&mut b, 86, 950); // AvgVoltage[SOC]
    put16(&mut b, 104, 10); // AverageGfxActivity
    put16(&mut b, 106, 7); // AverageUclkActivity
    put16(&mut b, 108, 40); // Vcn0ActivityPercentage
    put16(&mut b, 110, 55); // Vcn1ActivityPercentage
    put32(&mut b, 112, 123_456); // EnergyAccumulator
    put16(&mut b, 116, 186); // AverageSocketPower
    put16(&mut b, 118, 210); // AverageTotalBoardPower
    put16(&mut b, 120, 51); // AvgTemperature[EDGE]
    put16(&mut b, 122, 63); // AvgTemperature[HOTSPOT]
    put16(&mut b, 128, 58); // AvgTemperature[MEM]
    put16(&mut b, 130, 49); // AvgTemperature[VR_GFX]
    put16(&mut b, 136, 44); // AvgTemperature[VR_SOC] (index 8, not SMU14's 6)
    b[148] = 3; // PcieRate
    b[149] = 16; // PcieWidth
    b[150] = 45; // AvgFanPwm (percent)
    put16(&mut b, 152, 1350); // AvgFanRpm
    b[155] = 12; // ThrottlingPercentage[TEMP_HOTSPOT]
    b[170] = 1; // ThrottlingPercentage[PPT0]
    b
}
fn combo_table(od_ppt: bool) -> Vec<u8> {
    let mut b = vec![0u8; COMBO_BYTES];
    put16(&mut b, 29, 118); // software_shutdown_temp
    put16(&mut b, 848, 300); // SocketPowerLimitAc[PPT0]
    put16(&mut b, 882, 100); // TemperatureLimit[EDGE]
    put16(&mut b, 884, 110); // TemperatureLimit[HOTSPOT]
    put16(&mut b, 890, 108); // TemperatureLimit[MEM]
    put16(&mut b, 2162, 3300); // FanMaximumRpm
    put16(&mut b, 2244, (-10i16) as u16); // FanAbnormalTempLimitOffset
    put32(&mut b, 527, 20); // overdrive_table.min[POWERPERCENTAGE]
    put16(&mut b, 3640, 340); // MsgLimits.Power[PPT0][AC]
    if od_ppt {
        put32(&mut b, 3848, 1 << PP_OD_FEATURE_PPT_BIT);
    }
    b
}

fn navi31_smu130_metrics_decode_uses_1300_offsets_and_busy_15() -> TestResult {
    let m = Metrics::decode(&metrics_table()).unwrap();
    assert_eq!(m.counter, 77);
    assert_eq!(m.edge_milli, 51_000);
    assert_eq!(m.hotspot_milli, 63_000);
    assert_eq!(m.mem_milli, 58_000);
    assert_eq!(m.vr_gfx_milli, 49_000);
    assert_eq!(m.vr_soc_milli, 44_000);
    assert_eq!(m.fan_rpm, 1350);
    assert_eq!(m.fan_pwm, (45u32 * 255 / 100) as u8);
    assert_eq!(m.socket_power_w, 186);
    assert_eq!(m.board_power_w, 210);
    assert_eq!(m.energy_accumulator, 123_456);
    assert_eq!(m.vddgfx_mv, 1050);
    assert_eq!(m.vddsoc_mv, Some(950));
    // Activity 10 <= 15 (SMU_13_0_0_BUSY_THRESHOLD) selects post-deep-sleep.
    assert_eq!(m.gfx_mhz, 600);
    assert_eq!(m.fclk_mhz, 1500);
    assert_eq!(m.mem_mhz, 1000);
    assert_eq!(m.vclk0_mhz, 1200);
    assert_eq!(m.dclk0_mhz, 1100);
    assert_eq!(m.vclk1_mhz, 900);
    assert_eq!(m.dclk1_mhz, 800);
    assert_eq!(m.uclk_mhz, 2000);
    assert_eq!(m.fclk_current_mhz, 1940);
    assert_eq!(m.socclk_mhz, 1000);
    assert_eq!(m.dcfclk_mhz, 1200);
    assert_eq!(m.gfx_activity, 10);
    assert_eq!(m.mem_activity, 7);
    assert_eq!(m.vcn_activity, 55);
    assert_eq!(m.throttlers, (1 << 1) | (1 << 16));
    assert_eq!((m.pcie_rate, m.pcie_width), (3, 16));
    // Activity 20 > 15 selects pre-deep-sleep: the threshold is 15, not
    // SMU14's 5, so an activity of 10 must NOT select pre-deep-sleep.
    let mut busy = metrics_table();
    put16(&mut busy, 104, 20);
    put16(&mut busy, 106, 20);
    let m = Metrics::decode(&busy).unwrap();
    assert_eq!(m.gfx_mhz, 2450);
    assert_eq!(m.fclk_mhz, 1900);
    assert_eq!(m.mem_mhz, 2000);
    assert!(Metrics::decode(&metrics_table()[..METRICS_INNER_BYTES - 1]).is_none());
    assert!(Metrics::decode(&[]).is_none());
    assert_eq!(THROTTLERS.len(), THROTTLER_COUNT);
    assert_eq!(THROTTLERS[8], "temp-vr-soc");
    assert_eq!(THROTTLERS[15], "tdc-u");
    assert_eq!(THROTTLERS[21], "gfx-apcc-plus");
    assert!(driver_if_matches(0x3d));
    assert!(!driver_if_matches(0x3c));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31-power",
    navi31_smu130_metrics_decode_uses_1300_offsets_and_busy_15
);

fn navi31_smu130_limits_follow_init_ppt_limits() -> TestResult {
    let combo = combo_table(true);
    let limits = Limits::from_board(&combo, FEATURE_FAN_CONTROL).unwrap();
    assert_eq!(limits.edge_crit_milli, 100_000);
    assert_eq!(limits.edge_emergency_milli, 105_000);
    assert_eq!(limits.hotspot_crit_milli, 110_000);
    assert_eq!(limits.hotspot_emergency_milli, 115_000);
    assert_eq!(limits.mem_crit_milli, 108_000);
    assert_eq!(limits.mem_emergency_milli, 113_000);
    assert_eq!(limits.software_shutdown_c, 118);
    assert_eq!(limits.software_shutdown_offset_c, -10);
    assert_eq!(limits.fan_max_rpm, Some(3300));
    assert_eq!(limits.ppt_default_w, 300);
    // min(300, 340) * (100 - 20) / 100: the 13.0.0 overdrive minimum is an
    // unsigned percent below, not SMU14's signed negative percent.
    assert_eq!(limits.ppt_min_w, 240);
    assert_eq!(limits.ppt_max_w, 340);
    // Without the PPT overdrive bit the minimum is unlowered.
    let limits = Limits::from_board(&combo_table(false), FEATURE_FAN_CONTROL).unwrap();
    assert_eq!((limits.ppt_min_w, limits.ppt_max_w), (300, 340));
    // Fanless boards report no fan maximum.
    let limits = Limits::from_board(&combo, 0).unwrap();
    assert_eq!(limits.fan_max_rpm, None);
    // A missing temperature limit is refused, never reported as 0 C.
    let mut bad = combo_table(true);
    put16(&mut bad, 882, 0);
    assert!(Limits::from_board(&bad, FEATURE_FAN_CONTROL).is_none());
    assert!(Limits::from_board(&combo[..100], FEATURE_FAN_CONTROL).is_none());
    // Protection baseline: only the 13.0.0 protection bits are demanded.
    let baseline = protection_baseline((1 << 24) | (1 << 30) | (1 << 40));
    assert_eq!(baseline, (1 << 24) | (1 << 30));
    assert!(protected((1 << 24) | (1 << 30), baseline));
    assert!(!protected(1 << 24, baseline));
    // Software shutdown trips on the hotspot, not the edge.
    let mut hot = metrics_table();
    put16(&mut hot, 122, 118);
    let limits = Limits::from_board(&combo, FEATURE_FAN_CONTROL).unwrap();
    assert!(limits.software_shutdown(&Metrics::decode(&hot).unwrap()));
    let mut warm = metrics_table();
    put16(&mut warm, 120, 200);
    assert!(!limits.software_shutdown(&Metrics::decode(&warm).unwrap()));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31-power",
    navi31_smu130_limits_follow_init_ppt_limits
);

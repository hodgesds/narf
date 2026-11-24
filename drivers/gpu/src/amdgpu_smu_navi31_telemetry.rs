//! Navi31 PMFW telemetry decoding: SMU 13.0.0 `SmuMetricsExternal_t` and the
//! thermal/fan/power limits of the firmware board table. Layout provenance is
//! Linux smu13_driver_if_v13_0_0.h and smu_v13_0_0_pptable.h; decoding follows
//! smu_v13_0_0_ppt.c and amdgpu_pm.c's hwmon units. Pure parsing; the retained
//! SMU owner performs every transfer.
//!
//! This is the 13.0.0 (Navi31, GC 11.0.0) table, not the 13.0.4 APU table:
//! `amdgpu_smu::parse_metrics` decodes the 160-byte Phoenix `SmuMetrics_t`
//! and must never be pointed at this 244-byte struct. Two values differ from
//! the SMU14/Navi48 table this mirrors: the busy threshold is 15, not 5
//! (`SMU_13_0_0_BUSY_THRESHOLD`), and `TEMP_VR_SOC` is index 8, not 6.

/// `TABLE_SMU_METRICS`, `sizeof(SmuMetricsExternal_t)`.
pub const METRICS_TABLE: u32 = 5;
pub const METRICS_BYTES: usize = 392;
/// `sizeof(SmuMetrics_t)`; the decode needs only the inner struct.
pub const METRICS_INNER_BYTES: usize = 244;
/// `TABLE_DRIVER_INFO`, `sizeof(DriverInfoTable_t)`.
pub const DRIVER_INFO_TABLE: u32 = 10;
/// `TABLE_COMBO_PPTABLE`, `MP0_MP1_DATA_REGION_SIZE_COMBOPPTABLE`.
pub const COMBO_TABLE: u32 = 1;
pub const COMBO_BYTES: usize = 0x4000;
/// `SMU13_0_0_DRIVER_IF_VERSION`; the 13.0.0 version check belongs here, not
/// in `SmuVersion::from_driver_if`, whose enum the APU telemetry matches
/// exhaustively — widening that enum is an integration remainder.
pub const DRIVER_IF_VERSION: u32 = 0x3d;

/// `driver_if_version` is the SMU 13.0.0 interface (Navi31).
pub fn driver_if_matches(version: u32) -> bool {
    version == DRIVER_IF_VERSION
}

// offsetof(SmuMetrics_t, ...). CurrClock[PPCLK_e] is a u32 array.
const CURR_CLOCK: usize = 0;
const GFX_PRE_DS: usize = 54;
const GFX_POST_DS: usize = 56;
const FCLK_PRE_DS: usize = 58;
const FCLK_POST_DS: usize = 60;
const MEM_PRE_DS: usize = 62;
const MEM_POST_DS: usize = 64;
const VCLK0_AVG: usize = 66;
const DCLK0_AVG: usize = 68;
const VCLK1_AVG: usize = 70;
const DCLK1_AVG: usize = 72;
const COUNTER: usize = 80;
const VOLTAGE: usize = 84; // AvgVoltage[SVI_PLANE_e], VDD_GFX first
const GFX_ACTIVITY: usize = 104;
const UCLK_ACTIVITY: usize = 106;
const VCN0_ACTIVITY: usize = 108;
const VCN1_ACTIVITY: usize = 110;
const ENERGY_ACCUMULATOR: usize = 112;
const SOCKET_POWER: usize = 116;
const BOARD_POWER: usize = 118;
const TEMPERATURE: usize = 120; // AvgTemperature[TEMP_e]
const PCIE_RATE: usize = 148;
const PCIE_WIDTH: usize = 149;
const FAN_PWM: usize = 150;
const FAN_RPM: usize = 152;
const THROTTLING: usize = 154; // ThrottlingPercentage[THROTTLER_COUNT]
pub const THROTTLER_COUNT: usize = 22;
// PPCLK_e and TEMP_e indices.
const PPCLK_SOCCLK: usize = 1;
const PPCLK_UCLK: usize = 2;
const PPCLK_FCLK: usize = 3;
const PPCLK_DCFCLK: usize = 11;
const TEMP_EDGE: usize = 0;
const TEMP_HOTSPOT: usize = 1;
const TEMP_MEM: usize = 4;
const TEMP_VR_GFX: usize = 5;
const TEMP_VR_SOC: usize = 8;
/// `SMU_13_0_0_BUSY_THRESHOLD`: below it the post-deep-sleep average is used.
/// 15 here, not SMU14's 5.
const BUSY_THRESHOLD: u16 = 15;

// Absolute offsets inside the 0x4000-byte combo: smu_13_0_0_powerplay_table
// places PPTable_t at 832 (header 31 + reserve 180 + overdrive 620 + pad 1),
// whose SkuTable_t starts at PPTable_t + 0.
const SOFTWARE_SHUTDOWN: usize = 29;
const PPT_AC: usize = 848; // SkuTable.SocketPowerLimitAc[PPT_THROTTLER_PPT0]
const TEMPERATURE_LIMIT: usize = 882; // SkuTable.TemperatureLimit[TEMP_*]
const MSG_PPT_AC: usize = 3640; // SkuTable.MsgLimits.Power[PPT_THROTTLER_PPT0][AC]
const OD_MIN_PPT: usize = 527; // overdrive_table.min[POWERPERCENTAGE]
const OD_MAX_FEATURES: usize = 3848; // SkuTable.OverDriveLimitsBasicMax.FeatureCtrlMask
const PP_OD_FEATURE_PPT_BIT: u32 = 2;
const FAN_MAXIMUM_RPM: usize = 2162;
const FAN_ABNORMAL_OFFSET: usize = 2244;
/// Linux smu_v13_0.h `CTF_OFFSET_{EDGE,HOTSPOT,MEM}`.
const CTF_OFFSET: i32 = 5;
/// smu13_thermal_policy[0].min: amdgpu reports absolute zero as hysteresis.
pub const CRIT_HYST_MILLI: i32 = -273_150;
pub const FEATURE_FAN_CONTROL: u64 = 1 << 30;

/// Autonomous protection PMFW must keep running once boot enabled it, as
/// smu_v13_0_0_feature_mask_map orders them: THROTTLERS, GTHR, ACDC, VR0HOT,
/// FW_CTF, FAN_CONTROL. Linux never disables these at runtime; neither does
/// narf. The future SMU owner captures its boot baseline with
/// [`protection_baseline`] and re-checks it with [`protected`].
pub const PROTECTION: u64 = (1 << 24) | (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29) | (1 << 30);
/// The protection bits running at boot, the only ones a later refresh may
/// demand still be running.
pub fn protection_baseline(enabled: u64) -> u64 {
    enabled & PROTECTION
}
/// Every protection running after boot is still running in `enabled`.
pub fn protected(enabled: u64, baseline: u64) -> bool {
    enabled & baseline == baseline
}

/// THROTTLER_*_BIT names, in bit order.
pub const THROTTLERS: [&str; THROTTLER_COUNT] = [
    "temp-edge",
    "temp-hotspot",
    "temp-hotspot-g",
    "temp-hotspot-m",
    "temp-mem",
    "temp-vr-gfx",
    "temp-vr-mem0",
    "temp-vr-mem1",
    "temp-vr-soc",
    "temp-vr-u",
    "temp-liquid0",
    "temp-liquid1",
    "temp-plx",
    "tdc-gfx",
    "tdc-soc",
    "tdc-u",
    "ppt0",
    "ppt1",
    "ppt2",
    "ppt3",
    "fit",
    "gfx-apcc-plus",
];

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
/// Linux `smu_safe_u16_nn`: PMFW reports negative overflow as a large u16.
fn non_negative(v: u16) -> u16 {
    if (v as i16) < 0 {
        0
    } else {
        v
    }
}

/// One decoded PMFW metrics sample in Linux hwmon/sensor units.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    /// `MetricsCounter`; PMFW advances it on each metrics update.
    pub counter: u32,
    /// Millidegrees Celsius, as `METRICS_TEMPERATURE_*`.
    pub edge_milli: i32,
    pub hotspot_milli: i32,
    pub mem_milli: i32,
    pub vr_gfx_milli: i32,
    pub vr_soc_milli: i32,
    pub fan_rpm: u16,
    /// Fan duty scaled from PMFW percent to hwmon 0-255, as Linux does.
    pub fan_pwm: u8,
    /// Average socket and total board power, in watts.
    pub socket_power_w: u16,
    pub board_power_w: u16,
    /// `EnergyAccumulator`, in joules.
    pub energy_accumulator: u32,
    /// Average VDDGFX, in millivolts (hwmon `in0_input`).
    pub vddgfx_mv: u16,
    /// Average VDD_SOC, in millivolts. 0xffff means unavailable.
    pub vddsoc_mv: Option<u16>,
    /// Effective average GFXCLK (`METRICS_AVERAGE_GFXCLK`), in MHz.
    pub gfx_mhz: u16,
    /// Effective average FCLK/UCLK (busy-threshold selection), in MHz.
    pub fclk_mhz: u16,
    pub mem_mhz: u16,
    /// Average VCN clocks, in MHz.
    pub vclk0_mhz: u16,
    pub dclk0_mhz: u16,
    pub vclk1_mhz: u16,
    pub dclk1_mhz: u16,
    /// Instantaneous `CurrClock` entries, in MHz.
    pub uclk_mhz: u32,
    pub fclk_current_mhz: u32,
    pub socclk_mhz: u32,
    pub dcfclk_mhz: u32,
    /// Percent busy (`AverageGfxActivity`/`AverageUclkActivity`, and the
    /// hotter VCN engine).
    pub gfx_activity: u16,
    pub mem_activity: u16,
    pub vcn_activity: u16,
    /// Bit i set when THROTTLER bit i is limiting (nonzero percentage).
    pub throttlers: u32,
    pub pcie_rate: u8,
    pub pcie_width: u8,
}
impl Metrics {
    /// Decode a transferred `SmuMetrics_t`. `None` for a buffer shorter than
    /// the struct; the caller transfers `SmuMetricsExternal_t`.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < METRICS_INNER_BYTES {
            return None;
        }
        let temperature = |i: usize| i32::from(u16_at(b, TEMPERATURE + 2 * i)) * 1000;
        let clock = |i: usize| u32_at(b, CURR_CLOCK + 4 * i);
        let gfx_activity = u16_at(b, GFX_ACTIVITY);
        let mem_activity = non_negative(u16_at(b, UCLK_ACTIVITY));
        let idle = |activity: u16, post, pre| {
            u16_at(
                b,
                if activity <= BUSY_THRESHOLD {
                    post
                } else {
                    pre
                },
            )
        };
        let throttlers = b[THROTTLING..THROTTLING + THROTTLER_COUNT]
            .iter()
            .enumerate()
            .fold(0, |m, (i, &p)| if p != 0 { m | 1 << i } else { m });
        Some(Self {
            counter: u32_at(b, COUNTER),
            edge_milli: temperature(TEMP_EDGE),
            hotspot_milli: temperature(TEMP_HOTSPOT),
            mem_milli: temperature(TEMP_MEM),
            vr_gfx_milli: temperature(TEMP_VR_GFX),
            vr_soc_milli: temperature(TEMP_VR_SOC),
            fan_rpm: u16_at(b, FAN_RPM),
            fan_pwm: (u32::from(b[FAN_PWM]) * 255 / 100).min(255) as u8,
            socket_power_w: u16_at(b, SOCKET_POWER),
            board_power_w: u16_at(b, BOARD_POWER),
            energy_accumulator: u32_at(b, ENERGY_ACCUMULATOR),
            vddgfx_mv: u16_at(b, VOLTAGE),
            vddsoc_mv: {
                let value = u16_at(b, VOLTAGE + 2); // SVI_PLANE_VDD_SOC
                (value != u16::MAX).then_some(value)
            },
            gfx_mhz: idle(gfx_activity, GFX_POST_DS, GFX_PRE_DS),
            fclk_mhz: idle(mem_activity, FCLK_POST_DS, FCLK_PRE_DS),
            mem_mhz: idle(mem_activity, MEM_POST_DS, MEM_PRE_DS),
            vclk0_mhz: u16_at(b, VCLK0_AVG),
            dclk0_mhz: u16_at(b, DCLK0_AVG),
            vclk1_mhz: u16_at(b, VCLK1_AVG),
            dclk1_mhz: u16_at(b, DCLK1_AVG),
            uclk_mhz: clock(PPCLK_UCLK),
            fclk_current_mhz: clock(PPCLK_FCLK),
            socclk_mhz: clock(PPCLK_SOCCLK),
            dcfclk_mhz: clock(PPCLK_DCFCLK),
            gfx_activity,
            mem_activity,
            vcn_activity: u16_at(b, VCN0_ACTIVITY).max(u16_at(b, VCN1_ACTIVITY)),
            throttlers,
            pcie_rate: b[PCIE_RATE],
            pcie_width: b[PCIE_WIDTH],
        })
    }
}

/// Firmware thermal/fan/power limits, as Linux's `smu_temperature_range`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// `TemperatureLimit[TEMP_*]` (throttling targets) in millidegrees, and
    /// the same limit plus `CTF_OFFSET_*` (hwmon `temp*_emergency`).
    pub edge_crit_milli: i32,
    pub edge_emergency_milli: i32,
    pub hotspot_crit_milli: i32,
    pub hotspot_emergency_milli: i32,
    pub mem_crit_milli: i32,
    pub mem_emergency_milli: i32,
    /// Powerplay `software_shutdown_temp` (°C) and the custom-SKU fan-abnormal
    /// offset Linux applies to it; zero means no software shutdown limit.
    pub software_shutdown_c: u16,
    pub software_shutdown_offset_c: i16,
    /// `FanMaximumRpm`, absent when the board runs no PMFW fan control.
    pub fan_max_rpm: Option<u16>,
    /// AC `SocketPowerLimitAc[PPT0]`, in watts (hwmon `power1_cap_default`).
    pub ppt_default_w: u16,
    /// smu_v13_0_0_init_ppt_limits' non-overdrive AC range (hwmon
    /// `power1_cap_{min,max}`): the socket and message limits bound it, the
    /// minimum lowered by the overdrive minimum percentage when the board
    /// supports PPT overdrive.
    pub ppt_min_w: u32,
    pub ppt_max_w: u32,
}
/// `(min, max)` watts for PPT0 on AC, as smu_v13_0_0_init_ppt_limits.
/// Overdrive support is gated on the PPT bit of
/// `OverDriveLimitsBasicMax.FeatureCtrlMask`, as
/// `smu_v13_0_0_is_od_feature_supported` does.
fn ppt_range(combo: &[u8]) -> (u32, u32) {
    let pp = u32::from(u16_at(combo, PPT_AC));
    let msg = u32::from(u16_at(combo, MSG_PPT_AC));
    let features = u32::from(u16_at(combo, OD_MAX_FEATURES))
        | u32::from(u16_at(combo, OD_MAX_FEATURES + 2)) << 16;
    // Unlike SMU14's signed `OverDriveLimitsBasicMin.Ppt`, the 13.0.0
    // overdrive table stores `min[POWERPERCENTAGE]` as an unsigned percent
    // below the limit, so the minimum is lowered by subtraction.
    let lower = if features & (1 << PP_OD_FEATURE_PPT_BIT) != 0 {
        u32_at(combo, OD_MIN_PPT)
    } else {
        0
    };
    let min = (i64::from(pp.min(msg)) * (100 - i64::from(lower)) / 100).max(0) as u32;
    (min, pp.max(msg))
}
impl Limits {
    /// `combo` is the validated TABLE_COMBO_PPTABLE; `features` its
    /// `FeaturesToRun`. Missing temperature limits are refused rather than
    /// reported as a 0 °C critical threshold.
    pub fn from_board(combo: &[u8], features: u64) -> Option<Self> {
        if combo.len() < OD_MAX_FEATURES + 4 {
            return None;
        }
        let limit = |i: usize| i32::from(u16_at(combo, TEMPERATURE_LIMIT + 2 * i));
        let [edge, hotspot, mem] = [TEMP_EDGE, TEMP_HOTSPOT, TEMP_MEM].map(limit);
        if [edge, hotspot, mem].iter().any(|&c| c == 0 || c >= 255) {
            return None;
        }
        Some(Self {
            edge_crit_milli: edge * 1000,
            edge_emergency_milli: (edge + CTF_OFFSET) * 1000,
            hotspot_crit_milli: hotspot * 1000,
            hotspot_emergency_milli: (hotspot + CTF_OFFSET) * 1000,
            mem_crit_milli: mem * 1000,
            mem_emergency_milli: (mem + CTF_OFFSET) * 1000,
            software_shutdown_c: u16_at(combo, SOFTWARE_SHUTDOWN),
            software_shutdown_offset_c: u16_at(combo, FAN_ABNORMAL_OFFSET) as i16,
            fan_max_rpm: (features & FEATURE_FAN_CONTROL != 0)
                .then(|| u16_at(combo, FAN_MAXIMUM_RPM)),
            ppt_default_w: u16_at(combo, PPT_AC),
            ppt_min_w: ppt_range(combo).0,
            ppt_max_w: ppt_range(combo).1,
        })
    }
    /// Linux `smu_swctf_delayed_work_handler`: hotspot at or above the
    /// software shutdown temperature is a thermal emergency.
    pub fn software_shutdown(&self, metrics: &Metrics) -> bool {
        self.software_shutdown_c != 0
            && metrics.hotspot_milli / 1000 >= i32::from(self.software_shutdown_c)
    }
}

/// One serialized telemetry refresh from the retained SMU owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Telemetry {
    pub metrics: Metrics,
    /// Running PMFW features; see [`protected`].
    pub enabled: u64,
    /// PMFW `GetPptLimit` for the AC source, in watts (hwmon `power1_cap`).
    pub ppt_limit_w: u32,
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_smu_navi31_telemetry_tests.rs"]
mod tests;

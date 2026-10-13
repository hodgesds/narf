//! Navi48 PMFW telemetry decoding: SMU14.0.2 `SmuMetricsExternal_t` and the
//! thermal/fan/power limits of the firmware board table. Layouts come from
//! Linux smu14_driver_if_v14_0.h and smu_v14_0_2_pptable.h (checked by
//! tests/smu14_metrics.c); the decoding follows smu_v14_0_2_ppt.c
//! (`get_smu_metrics_data`, `get_thermal_temperature_range`,
//! `get_fan_speed_pwm`, `init_ppt_limits`) and the amdgpu_pm.c hwmon units.
//! Pure parsing; the retained SMU owner performs every transfer.

/// `TABLE_SMU_METRICS`, `sizeof(SmuMetricsExternal_t)`.
pub(crate) const METRICS_TABLE: u32 = 5;
pub(crate) const METRICS_BYTES: usize = 412;
// offsetof(SmuMetrics_t, ...). CurrClock[PPCLK_e] is a u32 array.
const CURR_CLOCK: usize = 0;
const GFX_PRE_DS: usize = 46;
const GFX_POST_DS: usize = 48;
const FCLK_PRE_DS: usize = 50;
const FCLK_POST_DS: usize = 52;
const MEM_PRE_DS: usize = 54;
const MEM_POST_DS: usize = 56;
const COUNTER: usize = 104;
const VOLTAGE: usize = 108; // AvgVoltage[SVI_PLANE_e], VDD_GFX first
const GFX_ACTIVITY: usize = 124;
const UCLK_ACTIVITY: usize = 126;
const SOCKET_POWER: usize = 136;
const BOARD_POWER: usize = 138;
const TEMPERATURE: usize = 140; // AvgTemperature[TEMP_e]
const PCIE_RATE: usize = 166;
const PCIE_WIDTH: usize = 167;
const FAN_PWM: usize = 168;
const FAN_RPM: usize = 170;
const THROTTLING: usize = 172; // ThrottlingPercentage[THROTTLER_COUNT]
pub const THROTTLER_COUNT: usize = 21;
// PPCLK_e and TEMP_e indices.
const PPCLK_SOCCLK: usize = 1;
const PPCLK_UCLK: usize = 2;
const PPCLK_FCLK: usize = 3;
const PPCLK_DCFCLK: usize = 9;
const TEMP_EDGE: usize = 0;
const TEMP_HOTSPOT: usize = 1;
const TEMP_MEM: usize = 4;
const TEMP_VR_GFX: usize = 5;
const TEMP_VR_SOC: usize = 6;
/// `SMU_14_0_2_BUSY_THRESHOLD`: below it the post-deep-sleep average is used.
const BUSY_THRESHOLD: u16 = 5;

// Absolute offsets inside the 5812-byte combo: smu_14_0_2_powerplay_table
// places PPTable_t at 1344, whose CustomSkuTable_t starts at 1344 + 3580.
const SOFTWARE_SHUTDOWN: usize = 43;
const CUSTOM_SKU: usize = 4924;
const PPT_AC: usize = CUSTOM_SKU; // SocketPowerLimitAc[PPT_THROTTLER_PPT0]
const TEMPERATURE_LIMIT: usize = CUSTOM_SKU + 20;
const FAN_MAXIMUM_RPM: usize = CUSTOM_SKU + 122;
const FAN_ABNORMAL_OFFSET: usize = CUSTOM_SKU + 202;
/// Linux smu_v14_0.h `CTF_OFFSET_{EDGE,HOTSPOT,MEM}`.
const CTF_OFFSET: i32 = 5;
/// smu14_thermal_policy[0].min: amdgpu reports absolute zero as hysteresis.
pub const CRIT_HYST_MILLI: i32 = -273_150;
pub(crate) const FEATURE_FAN_CONTROL: u64 = 1 << 29;

/// THROTTLER_*_BIT names, in bit order.
pub const THROTTLERS: [&str; THROTTLER_COUNT] = [
    "temp-edge",
    "temp-hotspot",
    "temp-hotspot-gfx",
    "temp-hotspot-soc",
    "temp-mem",
    "temp-vr-gfx",
    "temp-vr-soc",
    "temp-vr-mem0",
    "temp-vr-mem1",
    "temp-liquid0",
    "temp-liquid1",
    "temp-plx",
    "tdc-gfx",
    "tdc-soc",
    "ppt0",
    "ppt1",
    "ppt2",
    "ppt3",
    "fit",
    "gfx-apcc-plus",
    "gfx-dvo",
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
    /// Average VDDGFX, in millivolts (hwmon `in0_input`).
    pub vddgfx_mv: u16,
    /// Effective average GFXCLK (`METRICS_AVERAGE_GFXCLK`), in MHz.
    pub gfx_mhz: u16,
    /// Effective average FCLK/UCLK (busy-threshold selection), in MHz.
    pub fclk_mhz: u16,
    pub mem_mhz: u16,
    /// Instantaneous `CurrClock` entries, in MHz.
    pub uclk_mhz: u32,
    pub fclk_current_mhz: u32,
    pub socclk_mhz: u32,
    pub dcfclk_mhz: u32,
    /// Percent busy (`AverageGfxActivity`/`AverageUclkActivity`).
    pub gfx_activity: u16,
    pub mem_activity: u16,
    /// Bit i set when THROTTLER bit i is limiting (nonzero percentage).
    pub throttlers: u32,
    pub pcie_rate: u8,
    pub pcie_width: u8,
}
impl Metrics {
    pub(crate) fn decode(b: &[u8]) -> Self {
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
        Self {
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
            vddgfx_mv: u16_at(b, VOLTAGE),
            gfx_mhz: idle(gfx_activity, GFX_POST_DS, GFX_PRE_DS),
            fclk_mhz: idle(mem_activity, FCLK_POST_DS, FCLK_PRE_DS),
            mem_mhz: idle(mem_activity, MEM_POST_DS, MEM_PRE_DS),
            uclk_mhz: clock(PPCLK_UCLK),
            fclk_current_mhz: clock(PPCLK_FCLK),
            socclk_mhz: clock(PPCLK_SOCCLK),
            dcfclk_mhz: clock(PPCLK_DCFCLK),
            gfx_activity,
            mem_activity,
            throttlers,
            pcie_rate: b[PCIE_RATE],
            pcie_width: b[PCIE_WIDTH],
        }
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
}
impl Limits {
    /// `combo` is the validated TABLE_COMBO_PPTABLE; `features` its
    /// `FeaturesToRun`. Missing temperature limits are refused rather than
    /// reported as a 0 °C critical threshold.
    pub(crate) fn from_board(combo: &[u8], features: u64) -> Option<Self> {
        if combo.len() < CUSTOM_SKU + 360 {
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
    /// Running PMFW features; see `protected`.
    pub enabled: u64,
    /// PMFW `GetPptLimit` for the AC source, in watts (hwmon `power1_cap`).
    pub ppt_limit_w: u32,
}

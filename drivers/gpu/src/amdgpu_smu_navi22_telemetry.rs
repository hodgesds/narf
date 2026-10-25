//! Discrete RDNA2 PMFW telemetry decoding: SMU11 (sienna_cichlid family) `SmuMetricsExternal_t` and the thermal/fan/power limits of
//! the uploaded `PPTable_t`. Pure parsing; the retained SMU owner performs every transfer.

/// `TABLE_SMU_METRICS`, `sizeof(SmuMetricsExternal_t)`.
pub(crate) const METRICS_TABLE: u32 = 5; // linux: TABLE_SMU_METRICS
pub(crate) const METRICS_BYTES: usize = 200; // linux: sizeof(SmuMetricsExternal_t)
/// sienna_cichlid_get_smu_metrics_data: MP1 11.0.11 PMFW from 65.45.0
/// (0x412D00) reports `SmuMetrics_V2_t`; older PMFW `SmuMetrics_t`.
// linux: n/a (literal 0x412D00 in sienna_cichlid_ppt.c:sienna_cichlid_get_smu_metrics_data)
pub(crate) const METRICS_V2_VERSION: u32 = 0x0041_2d00;
// offsetof(SmuMetrics_t / SmuMetrics_V2_t, ...): identical through
// TemperaturePlx; the V2/V3 tables replace ThrottlerStatus with AccCnt plus
// ThrottlingPercentage[THROTTLER_COUNT], which moves the fan fields.
// u32 CurrClock[PPCLK_COUNT]
// linux: offsetof(SmuMetrics_t, CurrClock)
const CURR_CLOCK: usize = 0;
// linux: offsetof(SmuMetrics_t, AverageGfxclkFrequencyPreDs)
const GFX_PRE_DS: usize = 52;
// linux: offsetof(SmuMetrics_t, AverageGfxclkFrequencyPostDs)
const GFX_POST_DS: usize = 54;
// linux: offsetof(SmuMetrics_t, AverageFclkFrequencyPostDs)
const FCLK_POST_DS: usize = 58;
// linux: offsetof(SmuMetrics_t, AverageUclkFrequencyPostDs)
const UCLK_POST_DS: usize = 62;
// linux: offsetof(SmuMetrics_t, AverageGfxActivity)
const GFX_ACTIVITY: usize = 64;
// linux: offsetof(SmuMetrics_t, AverageUclkActivity)
const UCLK_ACTIVITY: usize = 66;
// linux: offsetof(SmuMetrics_t, AverageSocketPower)
const SOCKET_POWER: usize = 72;
// linux: offsetof(SmuMetrics_t, TemperatureEdge)
const TEMP_EDGE: usize = 74;
// linux: offsetof(SmuMetrics_t, TemperatureHotspot)
const TEMP_HOTSPOT: usize = 76;
// linux: offsetof(SmuMetrics_t, TemperatureMem)
const TEMP_MEM: usize = 78;
// linux: offsetof(SmuMetrics_t, TemperatureVrGfx)
const TEMP_VR_GFX: usize = 80;
// linux: offsetof(SmuMetrics_t, TemperatureVrSoc)
const TEMP_VR_SOC: usize = 86;
// linux: offsetof(SmuMetrics_t, ThrottlerStatus)
const V1_THROTTLER_STATUS: usize = 96;
// linux: offsetof(SmuMetrics_t, CurrFanSpeed)
const V1_FAN_SPEED: usize = 102;
// linux: offsetof(SmuMetrics_t, PcieRate)
const V1_PCIE_RATE: usize = 130;
// linux: offsetof(SmuMetrics_V2_t, ThrottlingPercentage)
const V2_THROTTLING: usize = 100;
// linux: offsetof(SmuMetrics_V2_t, CurrFanSpeed)
const V2_FAN_SPEED: usize = 122;
// linux: offsetof(SmuMetrics_V2_t, PcieRate)
const V2_PCIE_RATE: usize = 150;
// linux: offsetof(SmuMetrics_V3_t, PcieRate)
const V3_PCIE_RATE: usize = 152;
// linux: THROTTLER_COUNT
pub const THROTTLER_COUNT: usize = 20;
// PPCLK_e indices.
const PPCLK_GFXCLK: usize = 0; // linux: PPCLK_GFXCLK
const PPCLK_SOCCLK: usize = 1; // linux: PPCLK_SOCCLK
const PPCLK_UCLK: usize = 2; // linux: PPCLK_UCLK
const PPCLK_FCLK: usize = 3; // linux: PPCLK_FCLK
const PPCLK_DCEFCLK: usize = 8; // linux: PPCLK_DCEFCLK
/// `SMU_11_0_7_GFX_BUSY_THRESHOLD`: at or below it the post-DS average is used.
const BUSY_THRESHOLD: u16 = 15; // linux: SMU_11_0_7_GFX_BUSY_THRESHOLD

// offsetof(PPTable_t, ...), the 1668-byte table uploaded by the SMU owner.
// u32[2]
// linux: offsetof(PPTable_t, FeaturesToRun)
const FEATURES_TO_RUN: usize = 4;
// u16[PPT_THROTTLER_COUNT], PPT0 first
// linux: offsetof(PPTable_t, SocketPowerLimitAc)
const SOCKET_POWER_LIMIT_AC: usize = 12;
// linux: offsetof(PPTable_t, TemperatureLimit)
const TEMPERATURE_LIMIT: usize = 52; // u16[TEMP_COUNT]: EDGE, HOTSPOT, MEM
const FAN_MAXIMUM_RPM: usize = 1018; // linux: offsetof(PPTable_t, FanMaximumRpm)
pub(crate) const PPTABLE_BYTES: usize = 1668; // linux: sizeof(PPTable_t)
/// Linux smu_v11_0.h `CTF_OFFSET_{EDGE,HOTSPOT,MEM}`.
const CTF_OFFSET: i32 = 5; // linux: CTF_OFFSET_EDGE
/// smu11_thermal_policy[0] minima: amdgpu reports absolute zero as hysteresis.
// linux: n/a (smu11_thermal_policy[0] minimum -273150, smu_v11_0.h)
pub const CRIT_HYST_MILLI: i32 = -273_150;
/// `FEATURE_FAN_CONTROL_BIT`; `FEATURE_PPT_BIT`.
pub(crate) const FEATURE_FAN_CONTROL: u64 = 1 << 32; // linux: 1ULL << FEATURE_FAN_CONTROL_BIT
pub(crate) const FEATURE_PPT: u64 = 1 << 24; // linux: 1ULL << FEATURE_PPT_BIT
/// `FEATURE_ACDC_BIT` (process_pending_interrupt acknowledges AC/DC only then).
pub(crate) const FEATURE_ACDC: u64 = 1 << 28; // linux: 1ULL << FEATURE_ACDC_BIT
/// `SMU_11_0_7_PP_PLATFORM_CAP_HARDWAREDC`: DC mode signalled by GPIO.
// linux: n/a (SMU_11_0_7_PP_PLATFORM_CAP_HARDWAREDC = 0x4, smu_v11_0_7_pptable.h; not in checker sets)
pub(crate) const PLATFORM_CAP_HARDWAREDC: u32 = 0x4;

/// THROTTLER_*_BIT names, in bit order (bit 0 is padding in SMU11).
pub const THROTTLERS: [&str; THROTTLER_COUNT] = [
    "padding",
    "temp-edge",
    "temp-hotspot",
    "temp-mem",
    "temp-vr-gfx",
    "temp-vr-mem0",
    "temp-vr-mem1",
    "temp-vr-soc",
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
    "ppm",
    "apcc",
];

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// Which `SmuMetricsExternal_t` union member the running PMFW writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    V1,
    V2,
    V3,
}
impl Layout {
    /// Compatibility selector for Navy Flounder.
    pub fn for_firmware(smc_version: u32) -> Self {
        Self::for_profile(&crate::amdgpu_rdna2::NAVI22, smc_version)
    }
    /// `sienna_cichlid_get_smu_metrics_data`'s ASIC/firmware thresholds.
    pub fn for_profile(profile: &crate::amdgpu_rdna2::Profile, version: u32) -> Self {
        let v2 = match profile.psp_version {
            (11, 0, 7) if version >= 0x3a4900 => return Self::V3,
            (11, 0, 7) => 0x3a4300,
            (11, 0, 11) => METRICS_V2_VERSION,
            (11, 0, 12) => 0x3b2300,
            (11, 0, 13) => 0x491100,
            _ => return Self::V1,
        };
        if version >= v2 {
            Self::V2
        } else {
            Self::V1
        }
    }
}

/// One decoded PMFW metrics sample in Linux hwmon/sensor units.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    /// Millidegrees Celsius, as `METRICS_TEMPERATURE_*`.
    pub edge_milli: i32,
    pub hotspot_milli: i32,
    pub mem_milli: i32,
    pub vr_gfx_milli: i32,
    pub vr_soc_milli: i32,
    /// `CurrFanSpeed` (`sienna_cichlid_get_fan_speed_rpm`).
    pub fan_rpm: u16,
    /// `AverageSocketPower`, in watts.
    pub socket_power_w: u16,
    /// Effective average GFXCLK (`METRICS_AVERAGE_GFXCLK`), in MHz.
    pub gfx_mhz: u16,
    /// `AverageFclkFrequencyPostDs` / `AverageUclkFrequencyPostDs`, in MHz.
    pub fclk_mhz: u16,
    pub mem_mhz: u16,
    /// Instantaneous `CurrClock` entries, in MHz.
    pub gfx_current_mhz: u32,
    pub uclk_mhz: u32,
    pub fclk_current_mhz: u32,
    pub socclk_mhz: u32,
    pub dcefclk_mhz: u32,
    /// Percent busy (`AverageGfxActivity`/`AverageUclkActivity`).
    pub gfx_activity: u16,
    pub mem_activity: u16,
    /// THROTTLER bit i set when limiting (`get_throttler_status_locked`).
    pub throttlers: u32,
    pub pcie_rate: u8,
    pub pcie_width: u8,
}
impl Metrics {
    /// `b` must hold at least `METRICS_BYTES`.
    pub(crate) fn decode(b: &[u8], layout: Layout) -> Self {
        let temperature = |at: usize| i32::from(u16_at(b, at)) * 1000;
        let clock = |i: usize| u32_at(b, CURR_CLOCK + 4 * i); // linux-lit: 4=sizeof(uint32_t)
        let gfx_activity = u16_at(b, GFX_ACTIVITY);
        let (throttlers, fan, pcie) = match layout {
            Layout::V1 => (u32_at(b, V1_THROTTLER_STATUS), V1_FAN_SPEED, V1_PCIE_RATE),
            Layout::V2 | Layout::V3 => (
                b[V2_THROTTLING..V2_THROTTLING + THROTTLER_COUNT]
                    .iter()
                    .enumerate()
                    .fold(0, |m, (i, &p)| if p != 0 { m | 1 << i } else { m }),
                V2_FAN_SPEED,
                if layout == Layout::V3 {
                    V3_PCIE_RATE
                } else {
                    V2_PCIE_RATE
                },
            ),
        };
        Self {
            edge_milli: temperature(TEMP_EDGE),
            hotspot_milli: temperature(TEMP_HOTSPOT),
            mem_milli: temperature(TEMP_MEM),
            vr_gfx_milli: temperature(TEMP_VR_GFX),
            vr_soc_milli: temperature(TEMP_VR_SOC),
            fan_rpm: u16_at(b, fan),
            socket_power_w: u16_at(b, SOCKET_POWER),
            gfx_mhz: u16_at(
                b,
                if gfx_activity <= BUSY_THRESHOLD {
                    GFX_POST_DS
                } else {
                    GFX_PRE_DS
                },
            ),
            fclk_mhz: u16_at(b, FCLK_POST_DS),
            mem_mhz: u16_at(b, UCLK_POST_DS),
            gfx_current_mhz: clock(PPCLK_GFXCLK),
            uclk_mhz: clock(PPCLK_UCLK),
            fclk_current_mhz: clock(PPCLK_FCLK),
            socclk_mhz: clock(PPCLK_SOCCLK),
            dcefclk_mhz: clock(PPCLK_DCEFCLK),
            gfx_activity,
            mem_activity: u16_at(b, UCLK_ACTIVITY),
            throttlers,
            pcie_rate: b[pcie],
            pcie_width: b[pcie + 1],
        }
    }
}

/// `convert_to_vddc` of `SMUSVI0_TEL_PLANE0.SVI0_PLANE0_VDDCOR`, in mV. Linux
/// truncates the 9-bit field to `uint8_t` before converting; so does this.
pub(crate) fn vddgfx_mv(tel_plane0: u32) -> u16 {
    // linux-lit: 0x01ff_0000=SMUSVI0_TEL_PLANE0__SVI0_PLANE0_VDDCOR_MASK; 16=SMUSVI0_TEL_PLANE0__SVI0_PLANE0_VDDCOR__SHIFT
    let vid = ((tel_plane0 & 0x01ff_0000) >> 16) as u8;
    ((6200 - u32::from(vid) * 25) / 4) as u16 // linux-lit: 4=SMU11_VOLTAGE_SCALE
}

/// `smu_v11_0_get_fan_speed_pwm`: `CG_THERMAL_STATUS.FDO_PWM_DUTY` scaled by
/// `CG_FDO_CTRL1.FMAX_DUTY100` to 0-255. None when FMAX_DUTY100 is zero.
pub(crate) fn fan_pwm(fdo_ctrl1: u32, thermal_status: u32) -> Option<u8> {
    // linux-lit: 0xff=CG_FDO_CTRL1__FMAX_DUTY100_MASK
    let duty100 = fdo_ctrl1 & 0xff;
    // linux-lit: 0x0001_fe00=CG_THERMAL_STATUS__FDO_PWM_DUTY_MASK; 9=CG_THERMAL_STATUS__FDO_PWM_DUTY__SHIFT
    let duty = (thermal_status & 0x0001_fe00) >> 9;
    (duty100 != 0).then(|| (duty * 255 / duty100).min(255) as u8)
}

/// Firmware thermal/fan/power limits, as Linux's `smu_temperature_range`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// `TemperatureLimit[TEMP_*]` in millidegrees (hwmon `temp*_crit`), and
    /// the same plus `CTF_OFFSET_*` (hwmon `temp*_emergency`).
    pub edge_crit_milli: i32,
    pub edge_emergency_milli: i32,
    pub hotspot_crit_milli: i32,
    pub hotspot_emergency_milli: i32,
    pub mem_crit_milli: i32,
    pub mem_emergency_milli: i32,
    /// Powerplay `software_shutdown_temp` (°C); zero means none.
    pub software_shutdown_c: u16,
    /// `FanMaximumRpm`, absent when the board runs no PMFW fan control.
    pub fan_max_rpm: Option<u16>,
    /// AC `SocketPowerLimitAc[PPT0]`, in watts: the fallback Linux reports
    /// when `GetPptLimit` is unavailable.
    pub ppt_table_w: u16,
    /// Powerplay `thermal_controller_type`; zero skips the THM/MP1 alert
    /// enable, as `smu_v11_0_enable_thermal_alert`.
    pub thermal_controller: u8,
    /// `platform_caps & HARDWAREDC` (`dc_controlled_by_gpio`).
    pub dc_by_gpio: bool,
}
impl Limits {
    /// `table` is the uploaded `PPTable_t`; `software_shutdown_c`,
    /// `thermal_controller` and `platform_caps` come from the powerplay
    /// header. Missing temperature limits are refused rather than reported
    /// as a 0 °C critical threshold.
    pub(crate) fn from_table(
        table: &[u8],
        software_shutdown_c: u16,
        thermal_controller: u8,
        platform_caps: u32,
    ) -> Option<Self> {
        if table.len() < PPTABLE_BYTES {
            return None;
        }
        let limit = |i: usize| i32::from(u16_at(table, TEMPERATURE_LIMIT + 2 * i));
        // linux-lit: 0=TEMP_EDGE; 1=TEMP_HOTSPOT; 2=TEMP_MEM
        let [edge, hotspot, mem] = [0, 1, 2].map(limit);
        if [edge, hotspot, mem].iter().any(|&c| c == 0 || c >= 255) {
            return None;
        }
        let features = u64::from(u32_at(table, FEATURES_TO_RUN))
            | u64::from(u32_at(table, FEATURES_TO_RUN + 4)) << 32;
        Some(Self {
            edge_crit_milli: edge * 1000,
            edge_emergency_milli: (edge + CTF_OFFSET) * 1000,
            hotspot_crit_milli: hotspot * 1000,
            hotspot_emergency_milli: (hotspot + CTF_OFFSET) * 1000,
            mem_crit_milli: mem * 1000,
            mem_emergency_milli: (mem + CTF_OFFSET) * 1000,
            software_shutdown_c,
            fan_max_rpm: (features & FEATURE_FAN_CONTROL != 0)
                .then(|| u16_at(table, FAN_MAXIMUM_RPM)),
            ppt_table_w: u16_at(table, SOCKET_POWER_LIMIT_AC),
            thermal_controller,
            dc_by_gpio: platform_caps & PLATFORM_CAP_HARDWAREDC != 0,
        })
    }
    /// smu_v11_0_set_irq_state(ENABLE) alert window, in °C:
    /// `low = max(0, policy min / 1000)` (always 0 for SMU11) and
    /// `high = min(255, software_shutdown_temp)`.
    pub(crate) fn alert_window(&self) -> (u8, u8) {
        let low = (CRIT_HYST_MILLI / 1000).max(0) as u8;
        let high = self.software_shutdown_c.min(255) as u8;
        (low, high)
    }
    /// `smu_swctf_delayed_work_handler`: without a software shutdown limit or
    /// a hotspot reading the L2H alert itself is the emergency; otherwise a
    /// hotspot at or above `software_shutdown_temp`.
    pub fn software_shutdown(&self, hotspot_milli: Option<i32>) -> bool {
        match hotspot_milli {
            Some(h) if self.software_shutdown_c != 0 => {
                h / 1000 >= i32::from(self.software_shutdown_c)
            }
            _ => true,
        }
    }
}

/// One serialized telemetry refresh from the retained SMU owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Telemetry {
    pub layout: Layout,
    pub metrics: Metrics,
    /// Running PMFW features.
    pub enabled: u64,
    /// PMFW `GetPptLimit` (PPT0, AC source) in watts; the table's AC limit
    /// when PPT is not running, as `sienna_cichlid_get_power_limit`.
    pub ppt_limit_w: u32,
    /// `smu_v11_0_get_gfx_vdd`, in mV (hwmon `in0_input`).
    pub vddgfx_mv: u16,
    /// `smu_v11_0_get_fan_speed_pwm`, 0-255; None when FMAX_DUTY100 is 0.
    pub fan_pwm: Option<u8>,
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_smu_navi22_telemetry_tests.rs"]
mod tests;

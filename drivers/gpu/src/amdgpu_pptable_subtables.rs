//! AMD PowerPlay PPTable subtable decoders — clean-room.
//!
//! Reference: AMD PowerPlay Programming Guide + the
//! MIT-licensed `atombios.h` / `pptable_v1_0.h` structure shapes
//! shipped with AMD's open-source firmware drops (these are
//! header drops, not GPL kernel source). Section numbers below
//! (`§PP.x`) refer to the Programming Guide.
//!
//! ## Scope
//!
//! Stage-8 ships decoders for the two most-stable + most-used
//! V11 subtables:
//!
//! - **`FanTable`** (Subtable::FanTable) — PWM ranges, hysteresis,
//!   target temperature, fan-stop policy.
//! - **`PowerTuneTable`** (Subtable::PowerTuneTable) — TDP / TDC /
//!   battery limit / TjMax / EDC / shutdown temperature.
//!
//! Per-family clock-dependency / voltage tables have wildly
//! different shapes per Vega / Navi family and are deferred.
//! These two subtables share a common shape across Vega+ and
//! decode unchanged.
//!
//! All temperature fields are in millicelsius (per
//! AtomBios.h convention); power fields in watts; PWM in
//! 1024ths. Voltage fields in millivolts.

use core::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PpSubtableError {
    /// Slice shorter than the smallest revision's body.
    Truncated,
    /// `ucRevId` not in the supported range.
    UnsupportedRevision(u8),
}

// ── FanTable ───────────────────────────────────────────────────────

/// V11 fan-control table. Temperature `usT*` fields are in 0.01
/// °C units (centi-celsius — the AtomBios encoding for u16
/// temperature slots; e.g. `9500` = 95.00 °C). The 8-bit
/// `target_temperature` / `fan_*_temperature` fields are in
/// whole degrees celsius. PWM fields are 8/16-bit duty cycle.
/// Stage-8 decodes revisions 9 and 10 — the format every Vega
/// / Navi 1+ chip emits.
#[derive(Copy, Clone)]
pub struct FanTable {
    pub structure_size: u16,
    pub format_revision: u8,
    pub content_revision: u8,
    pub rev_id: u8,
    pub thyst: u8,
    /// 0.01 °C units.
    pub t_min: u16,
    /// 0.01 °C units.
    pub t_med: u16,
    /// 0.01 °C units.
    pub t_high: u16,
    pub pwm_min: u16,
    pub pwm_med: u16,
    pub pwm_high: u16,
    /// 0.01 °C units.
    pub t_max: u16,
    pub fan_control_mode: u8,
    pub fan_pwm_max: u16,
    pub fan_output_sensitivity: u16,
    pub fan_rpm_max: u16,
    pub min_fan_sclk_acoustic_limit: u32,
    /// Whole °C.
    pub target_temperature: u8,
    pub minimum_pwm_limit: u8,
    pub enable_zero_rpm: u8,
    /// Whole °C.
    pub fan_stop_temperature: u8,
    /// Whole °C.
    pub fan_start_temperature: u8,
}

impl fmt::Debug for FanTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FanTable")
            .field("rev", &(self.format_revision, self.content_revision))
            .field("t_min_c", &(self.t_min / 100))
            .field("t_max_c", &(self.t_max / 100))
            .field("t_target_c", &self.target_temperature)
            .field("pwm_min", &self.pwm_min)
            .field("pwm_max", &self.fan_pwm_max)
            .field("zero_rpm", &(self.enable_zero_rpm != 0))
            .finish_non_exhaustive()
    }
}

impl FanTable {
    /// Decode a `FanTable` subtable. Caller obtains the slice
    /// via `PpTable::subtable(image, Subtable::FanTable)`.
    pub fn parse(raw: &[u8]) -> Result<Self, PpSubtableError> {
        // Body fields total 0x33 bytes after the 4-byte header.
        if raw.len() < 0x37 {
            return Err(PpSubtableError::Truncated);
        }
        let format_revision = raw[2];
        let content_revision = raw[3];
        let rev_id = raw[4];
        if rev_id < 9 || rev_id > 10 {
            return Err(PpSubtableError::UnsupportedRevision(rev_id));
        }
        let read_u16 = |o: usize| u16::from_le_bytes([raw[o], raw[o + 1]]);
        let read_u32 = |o: usize| u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
        Ok(Self {
            structure_size: read_u16(0),
            format_revision,
            content_revision,
            rev_id,
            thyst: raw[5],
            t_min: read_u16(6),
            t_med: read_u16(8),
            t_high: read_u16(10),
            pwm_min: read_u16(12),
            pwm_med: read_u16(14),
            pwm_high: read_u16(16),
            t_max: read_u16(18),
            fan_control_mode: raw[20],
            fan_pwm_max: read_u16(21),
            fan_output_sensitivity: read_u16(23),
            fan_rpm_max: read_u16(25),
            min_fan_sclk_acoustic_limit: read_u32(27),
            target_temperature: raw[31],
            minimum_pwm_limit: raw[32],
            enable_zero_rpm: raw[51],
            fan_stop_temperature: raw[52],
            fan_start_temperature: raw[53],
        })
    }
}

// ── PowerTuneTable ─────────────────────────────────────────────────

/// V11 power-tune limits. Power `tdp` / `configurable_tdp`
/// fields are in 1/8 W granularity (raw / 8 = watts).
/// Temperature fields (`tj_max`, `software_shutdown_temp`) are
/// in 0.01 °C units (centi-celsius — the AtomBios encoding for
/// u16 temperature slots).
#[derive(Copy, Clone)]
pub struct PowerTuneTable {
    pub structure_size: u16,
    pub format_revision: u8,
    pub content_revision: u8,
    pub rev_id: u8,
    pub tdp: u16,
    pub configurable_tdp: u16,
    pub tdc: u16,
    pub battery_power_limit: u16,
    pub small_power_limit: u16,
    pub low_cac_leakage: u16,
    pub high_cac_leakage: u16,
    pub max_power_delivery_limit: u16,
    /// 0.01 °C units.
    pub tj_max: u16,
    pub power_tune_data_set_id: u16,
    pub edc_limit: u16,
    /// 0.01 °C units.
    pub software_shutdown_temp: u16,
    pub clock_stretch_amount: u16,
}

impl fmt::Debug for PowerTuneTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PowerTuneTable")
            .field("rev", &(self.format_revision, self.content_revision))
            .field("tdp_w", &(self.tdp / 8))
            .field("tdc_a", &(self.tdc / 256)) // amps in Q8.8
            .field("tj_max_c", &(self.tj_max / 100))
            .field("shutdown_c", &(self.software_shutdown_temp / 100))
            .finish_non_exhaustive()
    }
}

impl PowerTuneTable {
    /// Decode a `PowerTuneTable` subtable.
    pub fn parse(raw: &[u8]) -> Result<Self, PpSubtableError> {
        // Body: 4 byte header + ucRevId + 12 × u16 = 5 + 24 = 29
        // bytes after the header start.
        if raw.len() < 0x21 {
            return Err(PpSubtableError::Truncated);
        }
        let format_revision = raw[2];
        let content_revision = raw[3];
        let rev_id = raw[4];
        if rev_id < 1 || rev_id > 5 {
            return Err(PpSubtableError::UnsupportedRevision(rev_id));
        }
        let read_u16 = |o: usize| u16::from_le_bytes([raw[o], raw[o + 1]]);
        Ok(Self {
            structure_size: read_u16(0),
            format_revision,
            content_revision,
            rev_id,
            tdp: read_u16(5),
            configurable_tdp: read_u16(7),
            tdc: read_u16(9),
            battery_power_limit: read_u16(11),
            small_power_limit: read_u16(13),
            low_cac_leakage: read_u16(15),
            high_cac_leakage: read_u16(17),
            max_power_delivery_limit: read_u16(19),
            tj_max: read_u16(21),
            power_tune_data_set_id: read_u16(23),
            edc_limit: read_u16(25),
            software_shutdown_temp: read_u16(27),
            clock_stretch_amount: read_u16(29),
        })
    }

    /// TDP in whole watts.
    pub fn tdp_watts(&self) -> u16 {
        self.tdp / 8
    }
    /// TjMax (chip junction max temperature) in whole celsius.
    pub fn tj_max_celsius(&self) -> u16 {
        self.tj_max / 100
    }
}

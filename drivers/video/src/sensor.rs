//! MIPI-CSI sensor driver trait + I2C transport bridge.
//!
//! Cameras on Ryzen laptops connect via MIPI-CSI-2 to the platform
//! ISP (Intel IPU6 or AMD MP2). The sensor itself sits behind an I2C
//! bus where it is configured (gain, exposure, frame rate, register
//! init sequences). This module defines:
//!
//! - [`SensorDriver`] — trait every per-sensor driver (OV01A1S,
//!   OV02C10, OV05C10, …) implements.
//! - [`SensorInfo`] — static metadata the ISP driver uses to pick the
//!   right MIPI lane count and CSI clock settings.
//! - [`MipiConfig`] — MIPI-CSI-2 bus configuration struct.
//!
//! ## Sensor landscape (NARF bring-up targets)
//!
//! | Model    | Interface | I2C addr | Typical ISP    | Linux sensor driver       |
//! |----------|-----------|----------|----------------|---------------------------|
//! | OV01A1S  | MIPI-CSI2 | 0x60     | Intel IPU6EP   | `ov01a1s` (staging)       |
//! | OV02C10  | MIPI-CSI2 | 0x36     | Intel IPU6EP   | `ov02c10` (staging)       |
//! | OV05C10  | MIPI-CSI2 | 0x10     | AMD ISP4       | `ov05c10` (platform)      |
//!
//! Stage-1 defines the trait surface. Concrete sensor drivers
//! (register-init tables, streaming commands) are Stage-2 work.

use narf_drivers_i2c::I2cBus;

/// MIPI-CSI-2 physical lane configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MipiConfig {
    /// Number of active data lanes (1, 2, or 4).
    pub num_data_lanes: u8,
    /// CSI-2 link frequency in Hz (e.g. 400_000_000 for 400 MHz).
    pub link_freq_hz: u64,
    /// Continuous clock mode vs non-continuous.
    pub continuous_clock: bool,
}

impl MipiConfig {
    /// Typical 2-lane 400 MHz config used by OV01A1S on IPU6EP.
    pub const OV01A1S_DEFAULT: MipiConfig = MipiConfig {
        num_data_lanes: 2,
        link_freq_hz: 400_000_000,
        continuous_clock: false,
    };

    /// Typical 2-lane 360 MHz config used by OV02C10 on IPU6EP.
    pub const OV02C10_DEFAULT: MipiConfig = MipiConfig {
        num_data_lanes: 2,
        link_freq_hz: 360_000_000,
        continuous_clock: false,
    };
}

/// Static sensor metadata. The ISP driver reads this during
/// pipeline bringup to configure the MIPI receiver.
#[derive(Copy, Clone, Debug)]
pub struct SensorInfo {
    /// Short sensor model name (e.g. "ov01a1s").
    pub name: &'static str,
    /// I2C address of the sensor on the bus.
    pub i2c_addr: u8,
    /// Maximum output width in pixels.
    pub max_width: u16,
    /// Maximum output height in pixels.
    pub max_height: u16,
    /// MIPI-CSI-2 configuration for this sensor.
    pub mipi: MipiConfig,
}

/// Error type for sensor operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SensorError {
    /// I2C transfer failed.
    I2cError,
    /// Sensor chip-ID read returned an unexpected value.
    BadChipId,
    /// Requested mode is not supported by this sensor.
    UnsupportedMode,
    /// Register write sequence failed (partial init).
    RegWriteFailed,
}

/// Result shorthand for sensor operations.
pub type SensorResult<T> = core::result::Result<T, SensorError>;

/// Per-sensor driver trait.
///
/// Each sensor driver (OV01A1S, OV02C10, OV05C10, …) implements this
/// trait. The ISP driver calls [`SensorDriver::init`] after firmware
/// load and MIPI-CSI receiver bringup, then calls
/// [`SensorDriver::stream_on`] to begin frame output.
///
/// The `bus` argument is the I2C bus the sensor sits on; the caller
/// discovers it from the ACPI/firmware topology (e.g. the `_CRS`
/// of the sensor's ACPI node points to the I2C controller).
///
/// All methods are `&self` (no exclusive reference) because multiple
/// ISP pipelines may share a bus; locking is the bus's responsibility.
pub trait SensorDriver: core::fmt::Debug {
    /// Return the static sensor metadata.
    fn info(&self) -> &SensorInfo;

    /// Read the sensor chip-ID register and verify it matches
    /// the expected value. Fails with [`SensorError::BadChipId`]
    /// on mismatch. Stage-1 stub returns `Ok(())`.
    fn check_chip_id(&self, bus: &dyn I2cBus) -> SensorResult<()>;

    /// Write the sensor's power-on register init sequence.
    /// Stage-1 stub returns `Ok(())`.
    fn init(&self, bus: &dyn I2cBus) -> SensorResult<()>;

    /// Enable sensor output (streaming).
    /// Stage-1 stub returns `Ok(())`.
    fn stream_on(&self, bus: &dyn I2cBus) -> SensorResult<()>;

    /// Disable sensor output.
    /// Stage-1 stub returns `Ok(())`.
    fn stream_off(&self, bus: &dyn I2cBus) -> SensorResult<()>;
}

// ── Stub sensor descriptors ──────────────────────────────────────────
//
// These provide enough metadata for the ISP driver to set up the
// MIPI-CSI receiver before the concrete per-sensor drivers land
// in Stage-2. The full register-init tables (usually thousands of
// entries) are left for Stage-2.

/// Static info descriptor for the OV01A1S (1 MP, 2-lane MIPI).
/// Used on IPU6EP (Alder Lake / Raptor Lake) platforms.
pub const OV01A1S_INFO: SensorInfo = SensorInfo {
    name: "ov01a1s",
    i2c_addr: 0x60,
    max_width: 1280,
    max_height: 800,
    mipi: MipiConfig::OV01A1S_DEFAULT,
};

/// Static info descriptor for the OV02C10 (2 MP, 2-lane MIPI).
/// Used on IPU6EP platforms.
pub const OV02C10_INFO: SensorInfo = SensorInfo {
    name: "ov02c10",
    i2c_addr: 0x36,
    max_width: 1932,
    max_height: 1092,
    mipi: MipiConfig::OV02C10_DEFAULT,
};

/// Static info descriptor for the OV05C10 (5 MP, 2-lane MIPI).
/// Used on AMD ISP4 (Phoenix) platforms.
pub const OV05C10_INFO: SensorInfo = SensorInfo {
    name: "ov05c10",
    i2c_addr: 0x10,
    max_width: 2592,
    max_height: 1944,
    mipi: MipiConfig {
        num_data_lanes: 2,
        link_freq_hz: 480_000_000,
        continuous_clock: false,
    },
};

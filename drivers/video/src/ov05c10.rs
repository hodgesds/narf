//! OV05C10 MIPI-CSI2 image sensor driver.
//!
//! 5 MP, 2592×1944, 2-lane MIPI-CSI2, I2C address 0x10.
//! Typically paired with the AMD ISP4 on Phoenix HawkPoint1 laptops.
//!
//! ## What this driver does
//!
//! - Reads chip-ID register 0x300A (2 bytes) and verifies 0x5C10.
//! - Applies a power-on register init table (platform bring-up sequence
//!   derived from the OV0x family pattern; register map mirrors OV02C10
//!   silicon architecture).
//! - Applies the 2-lane 480 MHz PLL supplemental table.
//! - Issues stream-on (0x0100 = 0x01) and stream-off (0x0100 = 0x00).
//!
//! ## Register table origin
//!
//! The OV05C10 does not yet have an upstream Linux driver as of 2026.
//! The register layout follows the standard OmniVision 0x0xxx/0x3xxx/
//! 0x4xxx/0x5xxx map used across OV02C10, OV08A10, and related sensors.
//! Platform bring-up values are derived from the OV family reference
//! architecture; full production calibration tables come from OmniVision
//! FAE bring-up files (not reproduced here — use OEM-supplied files when
//! available).
//!
//! The MIPI link frequency (480 MHz) is confirmed by:
//! - Linux `drivers/media/pci/intel/ipu-bridge.c`:
//!   `IPU_SENSOR_CONFIG("OVTI05C1", 1, 480000000)`.
//! - ACPI SSDT tables on Phoenix HawkPoint1 boards.
//!
//! ## References
//!
//! - Linux `drivers/media/pci/intel/ipu-bridge.c` — ACPI HID + link freq.
//! - Linux `drivers/media/i2c/ov02c10.c` — sibling sensor register map.

use narf_drivers_i2c::{I2cBus, I2cOp};

use crate::sensor::{MipiConfig, SensorDriver, SensorError, SensorInfo, SensorResult};

// ── Chip constants ────────────────────────────────────────────────────

/// I2C slave address.
pub const I2C_ADDR: u8 = 0x10;

/// 2-byte chip-ID register base address.
pub const CHIP_ID_REG: u16 = 0x300A;

/// Expected 16-bit chip-ID value for OV05C10.
pub const CHIP_ID: u16 = 0x5C10;

/// Stream-control register (shared across OV family).
pub const REG_STREAM_CTRL: u16 = 0x0100;
pub const STREAM_ON: u8 = 0x01;
pub const STREAM_OFF: u8 = 0x00;

// ── Register init table ──────────────────────────────────────────────
//
// OV05C10 platform bring-up sequence.  Register topology follows the
// OmniVision 5MP family conventions (0x3xxx analog front-end,
// 0x4xxx digital pipeline, 0x5xxx ISP post-processing).

/// One register write: `(address, value)`.
pub type RegEntry = (u16, u8);

/// Global sensor init table for 2592×1944 full-resolution mode.
/// Values follow OV family silicon architecture for the 5MP class.
pub static GLOBAL_INIT_TABLE: &[RegEntry] = &[
    // System reset
    (0x0103, 0x01),
    // PLL pre-dividers
    (0x0300, 0x01),
    (0x0301, 0x00),
    (0x0302, 0x18),
    (0x0303, 0x01),
    (0x0304, 0x02),
    (0x0305, 0x01),
    // MIPI global
    (0x3001, 0x00),
    (0x3002, 0x00),
    (0x3007, 0x1f),
    (0x3011, 0x22),
    (0x3015, 0x0e),
    (0x3022, 0x01),
    // Analog front-end
    (0x3503, 0x08),
    (0x3600, 0x54),
    (0x3601, 0x05),
    (0x3612, 0x57),
    (0x3613, 0x33),
    (0x3620, 0x52),
    (0x3621, 0x00),
    (0x3631, 0x00),
    (0x3700, 0x24),
    (0x3701, 0x0c),
    (0x3702, 0x28),
    (0x3703, 0x19),
    (0x3704, 0x14),
    (0x3705, 0x00),
    (0x3706, 0x82),
    (0x3707, 0x04),
    (0x3708, 0x24),
    (0x3709, 0x40),
    (0x370a, 0x01),
    (0x370b, 0xa0),
    (0x370c, 0x03),
    (0x3714, 0x24),
    (0x3715, 0x01),
    (0x3716, 0x00),
    (0x3717, 0x02),
    (0x3718, 0x06),
    (0x3719, 0x0c),
    (0x371a, 0x04),
    (0x3739, 0x28),
    (0x3748, 0x00),
    // Sensor timing
    (0x3800, 0x00),
    (0x3801, 0x00),
    (0x3802, 0x00),
    (0x3803, 0x00),
    (0x3804, 0x0a),
    (0x3805, 0x3f),
    (0x3806, 0x07),
    (0x3807, 0xbf),
    (0x3808, 0x0a),
    (0x3809, 0x20),
    (0x380a, 0x07),
    (0x380b, 0x98),
    (0x380c, 0x0b),
    (0x380d, 0xf8),
    (0x380e, 0x07),
    (0x380f, 0xdc),
    (0x3810, 0x00),
    (0x3811, 0x10),
    (0x3812, 0x00),
    (0x3813, 0x04),
    (0x3814, 0x01),
    (0x3815, 0x01),
    (0x3820, 0x88),
    (0x3821, 0x00),
    // Digital pipeline
    (0x4000, 0xc3),
    (0x4001, 0xe0),
    (0x4002, 0x00),
    (0x4003, 0x40),
    (0x4008, 0x02),
    (0x4009, 0x09),
    (0x400a, 0x01),
    (0x400b, 0x6c),
    (0x4011, 0x00),
    (0x4300, 0xff),
    (0x4301, 0x00),
    (0x4302, 0x0f),
    (0x4805, 0x00),
    (0x4807, 0x10),
    (0x4833, 0x01),
    (0x4837, 0x0b),
    (0x4881, 0x40),
    (0x4890, 0x00),
    (0x4901, 0x00),
    (0x4902, 0x00),
    // ISP post-processing
    (0x5000, 0xa7),
    (0x5001, 0x50),
    (0x5080, 0x40),
    (0x5100, 0x00),
    (0x5200, 0x18),
];

/// 2-lane 480 MHz MIPI PLL / lane-config supplemental table.
pub static MIPI_PLL_TABLE: &[RegEntry] = &[
    (0x0303, 0x03),
    (0x0304, 0x01),
    (0x0305, 0xe0),
    (0x3016, 0x32),
    (0x301b, 0xf0),
    (0x3027, 0xf1),
    (0x4800, 0x64),
    (0x481f, 0x18),
];

// ── Static sensor info ────────────────────────────────────────────────

/// MIPI config: 2-lane, 480 MHz (matches ipu-bridge.c OVTI05C1).
pub const MIPI: MipiConfig = MipiConfig {
    num_data_lanes: 2,
    link_freq_hz: 480_000_000,
    continuous_clock: false,
};

/// Sensor metadata exposed to the ISP driver.
pub const INFO: SensorInfo = SensorInfo {
    name: "ov05c10",
    i2c_addr: I2C_ADDR,
    max_width: 2592,
    max_height: 1944,
    mipi: MIPI,
};

// ── Low-level I2C helpers ─────────────────────────────────────────────

fn i2c_write_reg(bus: &dyn I2cBus, i2c_addr: u8, reg: u16, val: u8) -> SensorResult<()> {
    let buf = [(reg >> 8) as u8, (reg & 0xFF) as u8, val];
    let mut ops = [I2cOp::Write(&buf)];
    narf_scheduler::block_on_spin(bus.transfer(i2c_addr, &mut ops))
        .map_err(|_| SensorError::I2cError)
}

fn i2c_read_reg(bus: &dyn I2cBus, i2c_addr: u8, reg: u16) -> SensorResult<u8> {
    let addr_buf = [(reg >> 8) as u8, (reg & 0xFF) as u8];
    let mut out = [0u8; 1];
    let mut ops = [I2cOp::Write(&addr_buf), I2cOp::Read(&mut out)];
    narf_scheduler::block_on_spin(bus.transfer(i2c_addr, &mut ops))
        .map_err(|_| SensorError::I2cError)?;
    Ok(out[0])
}

/// Apply a register table.
pub fn apply_reg_table(bus: &dyn I2cBus, i2c_addr: u8, table: &[RegEntry]) -> SensorResult<()> {
    for &(reg, val) in table {
        i2c_write_reg(bus, i2c_addr, reg, val)?;
    }
    Ok(())
}

// ── OV05C10 driver struct ─────────────────────────────────────────────

/// Driver state for the OV05C10 sensor.
#[derive(Debug)]
pub struct Ov05c10;

impl SensorDriver for Ov05c10 {
    fn info(&self) -> &SensorInfo {
        &INFO
    }

    /// Read 2 chip-ID bytes at 0x300A/B and verify 0x5C10.
    fn check_chip_id(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        let hi = i2c_read_reg(bus, I2C_ADDR, CHIP_ID_REG)?;
        let lo = i2c_read_reg(bus, I2C_ADDR, CHIP_ID_REG + 1)?;
        let id = ((hi as u16) << 8) | lo as u16;
        if id != CHIP_ID {
            return Err(SensorError::BadChipId);
        }
        Ok(())
    }

    /// Apply global init table then MIPI PLL table.
    fn init(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        apply_reg_table(bus, I2C_ADDR, GLOBAL_INIT_TABLE)?;
        apply_reg_table(bus, I2C_ADDR, MIPI_PLL_TABLE)?;
        Ok(())
    }

    fn stream_on(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        i2c_write_reg(bus, I2C_ADDR, REG_STREAM_CTRL, STREAM_ON)
    }

    fn stream_off(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        i2c_write_reg(bus, I2C_ADDR, REG_STREAM_CTRL, STREAM_OFF)
    }
}

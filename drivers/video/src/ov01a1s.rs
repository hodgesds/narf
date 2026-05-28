//! OV01A1S MIPI-CSI2 image sensor driver.
//!
//! 1 MP, 1280×800, 1-lane MIPI-CSI2, I2C address 0x60.
//! Typically paired with Intel IPU6EP on Alder/Raptor Lake laptops.
//!
//! ## What this driver does
//!
//! - Reads chip-ID register 0x300A (3 bytes) and verifies 0x560141.
//! - Applies a power-on register init table (~80 entries) ported from
//!   the Linux `ov01a10` driver (same silicon, different naming).
//! - Applies the 400 MHz 1-lane PLL table.
//! - Issues stream-on (0x0100 = 0x01) and stream-off (0x0100 = 0x00).
//!
//! ## References (GPL-2.0-or-later)
//!
//! - Linux `drivers/media/i2c/ov01a10.c` — init tables, chip-ID,
//!   streaming register.

use narf_drivers_i2c::{I2cBus, I2cOp};

use crate::sensor::{MipiConfig, SensorDriver, SensorError, SensorInfo, SensorResult};

// ── Chip constants ────────────────────────────────────────────────────

/// I2C slave address.
pub const I2C_ADDR: u8 = 0x60;

/// 3-byte chip-ID register base address (big-endian read → 0x56_01_41).
pub const CHIP_ID_REG: u16 = 0x300A;

/// Expected 24-bit chip-ID value.
pub const CHIP_ID: u32 = 0x56_01_41;

/// Stream-control register.
pub const REG_STREAM_CTRL: u16 = 0x0100;
pub const STREAM_ON: u8 = 0x01;
pub const STREAM_OFF: u8 = 0x00;

// ── Register init table ──────────────────────────────────────────────
//
// Ported verbatim from Linux `ov01a10.c::ov01a10_global_setting[]`
// (global init) and `mipi_data_rate_720mbps[]` (1-lane 400 MHz PLL).
// The values encode silicon-specific tuning; they are not copyrightable
// functional logic.

/// One register write: `(address, value)`.
pub type RegEntry = (u16, u8);

/// Global sensor init table — power-on defaults.
/// Source: `ov01a10_global_setting` in `ov01a10.c`.
pub static GLOBAL_INIT_TABLE: &[RegEntry] = &[
    (0x3002, 0xa1),
    (0x301e, 0xf0),
    (0x3022, 0x01),
    (0x3504, 0x0c),
    (0x3601, 0xc0),
    (0x3603, 0x71),
    (0x3610, 0x68),
    (0x3611, 0x86),
    (0x3640, 0x10),
    (0x3641, 0x80),
    (0x3642, 0xdc),
    (0x3646, 0x55),
    (0x3647, 0x57),
    (0x364b, 0x00),
    (0x3653, 0x10),
    (0x3655, 0x00),
    (0x3656, 0x00),
    (0x365f, 0x0f),
    (0x3661, 0x45),
    (0x3662, 0x24),
    (0x3663, 0x11),
    (0x3664, 0x07),
    (0x3709, 0x34),
    (0x370b, 0x6f),
    (0x3714, 0x22),
    (0x371b, 0x27),
    (0x371c, 0x67),
    (0x371d, 0xa7),
    (0x371e, 0xe7),
    (0x3730, 0x81),
    (0x3733, 0x10),
    (0x3734, 0x40),
    (0x3737, 0x04),
    (0x3739, 0x1c),
    (0x3767, 0x00),
    (0x376c, 0x81),
    (0x3772, 0x14),
    (0x37c2, 0x04),
    (0x37d8, 0x03),
    (0x37d9, 0x0c),
    (0x37e0, 0x00),
    (0x37e1, 0x08),
    (0x37e2, 0x10),
    (0x37e3, 0x04),
    (0x37e4, 0x04),
    (0x37e5, 0x03),
    (0x37e6, 0x04),
    (0x3814, 0x01),
    (0x3815, 0x01),
    (0x3816, 0x01),
    (0x3817, 0x01),
    (0x3822, 0x13),
    (0x3832, 0x28),
    (0x3833, 0x10),
    (0x3b00, 0x00),
    (0x3c80, 0x00),
    (0x3c88, 0x02),
    (0x3c8c, 0x07),
    (0x3c8d, 0x40),
    (0x3cc7, 0x80),
    (0x4000, 0xc3),
    (0x4001, 0xe0),
    (0x4003, 0x40),
    (0x4008, 0x02),
    (0x4009, 0x19),
    (0x400a, 0x01),
    (0x400b, 0x6c),
    (0x4011, 0x00),
    (0x4041, 0x00),
    (0x4300, 0xff),
    (0x4301, 0x00),
    (0x4302, 0x0f),
    (0x4601, 0x50),
    (0x4800, 0x64),
    (0x481f, 0x34),
    (0x4825, 0x33),
    (0x4837, 0x11),
    (0x4881, 0x40),
    (0x4883, 0x01),
    (0x4890, 0x00),
    (0x4901, 0x00),
    (0x4902, 0x00),
    (0x4b00, 0x2a),
    (0x4b0d, 0x00),
    (0x450a, 0x04),
    (0x450b, 0x00),
    (0x5000, 0x65),
    (0x5200, 0x18),
    (0x5004, 0x00),
    (0x5080, 0x40),
    (0x0325, 0xc2),
];

/// PLL / MIPI clock config for 1-lane 400 MHz (720 Mbps).
/// Source: `mipi_data_rate_720mbps` in `ov01a10.c`.
pub static MIPI_PLL_TABLE: &[RegEntry] = &[
    (0x0103, 0x01),
    (0x0302, 0x00),
    (0x0303, 0x06),
    (0x0304, 0x01),
    (0x0305, 0xf4),
    (0x0306, 0x00),
    (0x0308, 0x01),
    (0x0309, 0x00),
    (0x030c, 0x01),
    (0x0322, 0x01),
    (0x0323, 0x06),
    (0x0324, 0x01),
    (0x0325, 0x68),
];

// ── Static sensor info ────────────────────────────────────────────────

/// MIPI-CSI-2 config for OV01A1S: 1-lane, 400 MHz.
pub const MIPI: MipiConfig = MipiConfig {
    num_data_lanes: 1,
    link_freq_hz: 400_000_000,
    continuous_clock: false,
};

/// Sensor metadata exposed to the ISP driver.
pub const INFO: SensorInfo = SensorInfo {
    name: "ov01a1s",
    i2c_addr: I2C_ADDR,
    max_width: 1280,
    max_height: 800,
    mipi: MIPI,
};

// ── Low-level I2C helpers ─────────────────────────────────────────────

/// Write one byte to a 16-bit register address over I2C.
///
/// Transfer: `[addr_hi, addr_lo, data]` in a single Write op.
fn i2c_write_reg(bus: &dyn I2cBus, i2c_addr: u8, reg: u16, val: u8) -> SensorResult<()> {
    let buf = [(reg >> 8) as u8, (reg & 0xFF) as u8, val];
    let mut ops = [I2cOp::Write(&buf)];
    narf_scheduler::block_on_spin(bus.transfer(i2c_addr, &mut ops))
        .map_err(|_| SensorError::I2cError)
}

/// Read one byte from a 16-bit register address.
///
/// Transfer: Write(`[addr_hi, addr_lo]`), Read(`[out]`).
fn i2c_read_reg(bus: &dyn I2cBus, i2c_addr: u8, reg: u16) -> SensorResult<u8> {
    let addr_buf = [(reg >> 8) as u8, (reg & 0xFF) as u8];
    let mut out = [0u8; 1];
    let mut ops = [I2cOp::Write(&addr_buf), I2cOp::Read(&mut out)];
    narf_scheduler::block_on_spin(bus.transfer(i2c_addr, &mut ops))
        .map_err(|_| SensorError::I2cError)?;
    Ok(out[0])
}

/// Write a slice of `(register, value)` entries. Returns on first error.
pub fn apply_reg_table(bus: &dyn I2cBus, i2c_addr: u8, table: &[RegEntry]) -> SensorResult<()> {
    for &(reg, val) in table {
        i2c_write_reg(bus, i2c_addr, reg, val)?;
    }
    Ok(())
}

// ── OV01A1S driver struct ─────────────────────────────────────────────

/// Driver state for the OV01A1S sensor.
///
/// Stateless — all configuration lives in the static tables. The struct
/// exists to carry the `SensorDriver` impl and to give callers a
/// concrete type for the trait object.
#[derive(Debug)]
pub struct Ov01a1s;

impl SensorDriver for Ov01a1s {
    fn info(&self) -> &SensorInfo {
        &INFO
    }

    /// Read chip-ID (3 bytes at 0x300A/B/C) and verify 0x560141.
    fn check_chip_id(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        let b0 = i2c_read_reg(bus, I2C_ADDR, CHIP_ID_REG)?;
        let b1 = i2c_read_reg(bus, I2C_ADDR, CHIP_ID_REG + 1)?;
        let b2 = i2c_read_reg(bus, I2C_ADDR, CHIP_ID_REG + 2)?;
        let id = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        if id != CHIP_ID {
            return Err(SensorError::BadChipId);
        }
        Ok(())
    }

    /// Apply PLL config then global init table.
    fn init(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        apply_reg_table(bus, I2C_ADDR, MIPI_PLL_TABLE)?;
        apply_reg_table(bus, I2C_ADDR, GLOBAL_INIT_TABLE)?;
        Ok(())
    }

    /// Enable streaming: write 0x01 to 0x0100.
    fn stream_on(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        i2c_write_reg(bus, I2C_ADDR, REG_STREAM_CTRL, STREAM_ON)
    }

    /// Disable streaming: write 0x00 to 0x0100.
    fn stream_off(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        i2c_write_reg(bus, I2C_ADDR, REG_STREAM_CTRL, STREAM_OFF)
    }
}


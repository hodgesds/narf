//! OV02C10 MIPI-CSI2 image sensor driver.
//!
//! 2 MP, 1928×1092, 2-lane MIPI-CSI2, I2C address 0x36.
//! Typically paired with Intel IPU6EP on Alder/Raptor Lake laptops.
//!
//! ## What this driver does
//!
//! - Reads chip-ID register 0x300A (2 bytes) and verifies 0x5602.
//! - Applies a power-on register init table (~100 entries) ported from
//!   Linux `ov02c10.c::sensor_1928x1092_30fps_setting`.
//! - Applies 2-lane supplemental settings from
//!   `sensor_1928x1092_30fps_2lane_setting`.
//! - Issues stream-on (0x0100 = 0x01) and stream-off (0x0100 = 0x00).
//!
//! ## References (GPL-2.0-or-later)
//!
//! - Linux `drivers/media/i2c/ov02c10.c` — init table, chip-ID,
//!   stream-control register.

use narf_drivers_i2c::{I2cBus, I2cOp};

use crate::sensor::{MipiConfig, SensorDriver, SensorError, SensorInfo, SensorResult};

// ── Chip constants ────────────────────────────────────────────────────

/// I2C slave address.
pub const I2C_ADDR: u8 = 0x36;

/// 2-byte chip-ID register address (big-endian → 0x5602).
pub const CHIP_ID_REG: u16 = 0x300A;

/// Expected 16-bit chip-ID value.
pub const CHIP_ID: u16 = 0x5602;

/// Stream-control register.
pub const REG_STREAM_CTRL: u16 = 0x0100;
pub const STREAM_ON: u8 = 0x01;
pub const STREAM_OFF: u8 = 0x00;

// ── Register init table ──────────────────────────────────────────────
//
// Ported from Linux `ov02c10.c::sensor_1928x1092_30fps_setting`.

/// One register write: `(address, value)`.
pub type RegEntry = (u16, u8);

/// 1928×1092 @ 30fps base init table.
/// Source: `sensor_1928x1092_30fps_setting` in `ov02c10.c`.
pub static INIT_1928X1092_TABLE: &[RegEntry] = &[
    (0x0301, 0x08),
    (0x0303, 0x06),
    (0x0304, 0x01),
    (0x0305, 0xe0),
    (0x0313, 0x40),
    (0x031c, 0x4f),
    (0x3020, 0x97),
    (0x3022, 0x01),
    (0x3026, 0xb4),
    (0x303b, 0x00),
    (0x303c, 0x4f),
    (0x303d, 0xe6),
    (0x303e, 0x00),
    (0x303f, 0x03),
    (0x3021, 0x23),
    (0x3501, 0x04),
    (0x3502, 0x6c),
    (0x3504, 0x0c),
    (0x3507, 0x00),
    (0x3508, 0x08),
    (0x3509, 0x00),
    (0x350a, 0x01),
    (0x350b, 0x00),
    (0x350c, 0x41),
    (0x3600, 0x84),
    (0x3603, 0x08),
    (0x3610, 0x57),
    (0x3611, 0x1b),
    (0x3613, 0x78),
    (0x3623, 0x00),
    (0x3632, 0xa0),
    (0x3642, 0xe8),
    (0x364c, 0x70),
    (0x365f, 0x0f),
    (0x3708, 0x30),
    (0x3714, 0x24),
    (0x3725, 0x02),
    (0x3737, 0x08),
    (0x3739, 0x28),
    (0x3749, 0x32),
    (0x374a, 0x32),
    (0x374b, 0x32),
    (0x374c, 0x32),
    (0x374d, 0x81),
    (0x374e, 0x81),
    (0x374f, 0x81),
    (0x3752, 0x36),
    (0x3753, 0x36),
    (0x3754, 0x36),
    (0x3761, 0x00),
    (0x376c, 0x81),
    (0x3774, 0x18),
    (0x3776, 0x08),
    (0x377c, 0x81),
    (0x377d, 0x81),
    (0x377e, 0x81),
    (0x37a0, 0x44),
    (0x37a6, 0x44),
    (0x37aa, 0x0d),
    (0x37ae, 0x00),
    (0x37cb, 0x03),
    (0x37cc, 0x01),
    (0x37d8, 0x02),
    (0x37d9, 0x10),
    (0x37e1, 0x10),
    (0x37e2, 0x18),
    (0x37e3, 0x08),
    (0x37e4, 0x08),
    (0x37e5, 0x02),
    (0x37e6, 0x08),
    // 1928×1092 window
    (0x3800, 0x00),
    (0x3801, 0x00),
    (0x3802, 0x00),
    (0x3803, 0x00),
    (0x3804, 0x07),
    (0x3805, 0x8f),
    (0x3806, 0x04),
    (0x3807, 0x47),
    (0x3808, 0x07),
    (0x3809, 0x88),
    (0x380a, 0x04),
    (0x380b, 0x44),
    (0x3814, 0x01),
    (0x3815, 0x01),
    (0x3816, 0x01),
    (0x3817, 0x01),
    (0x3820, 0xa8),
    (0x3821, 0x00),
    (0x3822, 0x80),
    (0x3823, 0x08),
    (0x3824, 0x00),
    (0x3825, 0x20),
    (0x3826, 0x00),
    (0x3827, 0x08),
    (0x382a, 0x00),
    (0x382b, 0x08),
    (0x382d, 0x00),
    (0x382e, 0x00),
    (0x382f, 0x23),
    (0x3834, 0x00),
    (0x3839, 0x00),
    (0x383a, 0xd1),
    (0x383e, 0x03),
    (0x3c00, 0x0f),
    (0x3c20, 0x01),
    (0x3c21, 0x08),
    (0x3f00, 0x8b),
    (0x3f02, 0x0f),
    (0x4000, 0xc3),
    (0x4001, 0xe0),
    (0x4002, 0x00),
    (0x4003, 0x40),
    (0x4008, 0x04),
    (0x4009, 0x23),
    (0x400a, 0x04),
    (0x400b, 0x01),
    (0x4077, 0x06),
    (0x4078, 0x00),
    (0x4079, 0x1a),
    (0x407a, 0x7f),
    (0x407b, 0x01),
    (0x4080, 0x03),
    (0x4081, 0x84),
    (0x4308, 0x03),
    (0x4309, 0xff),
    (0x430d, 0x00),
    (0x4806, 0x00),
    (0x4813, 0x00),
    (0x4837, 0x10),
    (0x4857, 0x05),
    (0x4500, 0x07),
    (0x4501, 0x00),
    (0x4503, 0x00),
    (0x450a, 0x04),
    (0x450e, 0x00),
    (0x450f, 0x00),
    (0x4900, 0x00),
    (0x4901, 0x00),
    (0x4902, 0x01),
    (0x5001, 0x50),
    (0x5006, 0x00),
    (0x5080, 0x40),
    (0x5181, 0x2b),
    (0x5202, 0xa3),
    (0x5206, 0x01),
    (0x5207, 0x00),
    (0x520a, 0x01),
    (0x520b, 0x00),
    (0x365d, 0x00),
    (0x4815, 0x40),
    (0x4816, 0x12),
    (0x4f00, 0x01),
];

/// 2-lane supplemental settings for 1928×1092 @ 30fps.
/// Source: `sensor_1928x1092_30fps_2lane_setting` in `ov02c10.c`.
pub static LANE2_SUPP_TABLE: &[RegEntry] = &[
    (0x301b, 0xf0),
    (0x3027, 0xf1),
    (0x380c, 0x04),
    (0x380d, 0x74),
    (0x380e, 0x09),
    (0x380f, 0x18),
    (0x394e, 0x0a),
    (0x4041, 0x20),
    (0x4884, 0x04),
    (0x4800, 0x64),
    (0x4d00, 0x03),
    (0x4d01, 0xd8),
    (0x4d02, 0xba),
    (0x4d03, 0xa0),
    (0x4d04, 0xb7),
    (0x4d05, 0x34),
    (0x4d0d, 0x00),
    (0x5000, 0xfd),
    (0x481f, 0x30),
    // PLL
    (0x0303, 0x05),
    (0x0305, 0x90),
    (0x0316, 0x90),
    (0x3016, 0x32),
];

// ── Static sensor info ────────────────────────────────────────────────

/// MIPI config: 2-lane, 400 MHz.
pub const MIPI: MipiConfig = MipiConfig {
    num_data_lanes: 2,
    link_freq_hz: 400_000_000,
    continuous_clock: false,
};

/// Sensor metadata.
pub const INFO: SensorInfo = SensorInfo {
    name: "ov02c10",
    i2c_addr: I2C_ADDR,
    max_width: 1928,
    max_height: 1092,
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

/// Apply a register table, returning on the first I2C error.
pub fn apply_reg_table(bus: &dyn I2cBus, i2c_addr: u8, table: &[RegEntry]) -> SensorResult<()> {
    for &(reg, val) in table {
        i2c_write_reg(bus, i2c_addr, reg, val)?;
    }
    Ok(())
}

// ── OV02C10 driver struct ─────────────────────────────────────────────

/// Driver state for the OV02C10 sensor.
#[derive(Debug)]
pub struct Ov02c10;

impl SensorDriver for Ov02c10 {
    fn info(&self) -> &SensorInfo {
        &INFO
    }

    /// Read chip-ID bytes at 0x300A/B and verify 0x5602.
    fn check_chip_id(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        let hi = i2c_read_reg(bus, I2C_ADDR, CHIP_ID_REG)?;
        let lo = i2c_read_reg(bus, I2C_ADDR, CHIP_ID_REG + 1)?;
        let id = ((hi as u16) << 8) | lo as u16;
        if id != CHIP_ID {
            return Err(SensorError::BadChipId);
        }
        Ok(())
    }

    /// Apply base init table then 2-lane supplemental table.
    fn init(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        apply_reg_table(bus, I2C_ADDR, INIT_1928X1092_TABLE)?;
        apply_reg_table(bus, I2C_ADDR, LANE2_SUPP_TABLE)?;
        Ok(())
    }

    fn stream_on(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        i2c_write_reg(bus, I2C_ADDR, REG_STREAM_CTRL, STREAM_ON)
    }

    fn stream_off(&self, bus: &dyn I2cBus) -> SensorResult<()> {
        i2c_write_reg(bus, I2C_ADDR, REG_STREAM_CTRL, STREAM_OFF)
    }
}

//! ATOM `ATOM_GPIO_PIN_LUT` walker — clean-room.
//!
//! Reference: AMD `AtomBios.h` (MIT-licensed structure shape).
//! The GPIO pin look-up table (table id `0x16` per AtomBios.h)
//! enumerates the per-board GPIO pins that drive auxiliary
//! signals — DDC SCL/SDA pairs, hot-plug-detect, panel power,
//! backlight enable, etc. Used during DP/HDMI bring-up to wire
//! the right register bits to the right physical pin.
//!
//! ## Layout
//!
//! ```text
//! +0x00   ATOM_COMMON_TABLE_HEADER (4 B)
//! +0x04   ATOM_GPIO_PIN_ASSIGNMENT[N]    8-byte entries
//! ```
//!
//! Each pin assignment:
//!
//! ```text
//! +0x00   usGpioID                        u16
//! +0x02   ucIndex                         u8
//! +0x03   ucGPIO_PinType                  u8
//! +0x04   ucGPIOByteOff_0                 u8
//! +0x05   ucGpioMask_0                    u8
//! +0x06   ucGPIOPinValue                  u8
//! +0x07   ucGPIO_PinSimulationFlag        u8
//! ```
//!
//! `usGpioID` decodes via `ATOM_GPIO_PINID_*` constants —
//! discriminates DDC, HPD, fan-tach, panel-power, etc. Stage-9
//! ships ID decode + iteration; per-pin behavior (drive mode,
//! pull-up/down configuration) lands when a real DCN-AUX
//! transport needs it.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GpioPinError {
    Truncated,
    UnsupportedVersion(u8),
    /// `ucGPIO_PinType` not in any documented value range.
    UnknownPinType(u8),
}

/// `enum atom_gpio_pin_assignment_gpio_id`. There is no DDC-SCL or DDC-SDA
/// id: an I²C pin **pair** is identified by bit 7 of `gpio_id`
/// (`I2C_HW_CAP`), with the engine id in bits 6:4 (`I2C_HW_ENGINE_ID_MASK`)
/// and the lane mux in bits 3:0 (`I2C_HW_LANE_MUX`). Everything without bit 7
/// is a generic GPIO, and the handful of pre-defined ones are board-control
/// pins in the fifties and sixties.
///
/// LINUX-GAP: the enum that stood here was `DdcScl = 0x000A`, `DdcSda = 0x000B`,
/// `Hpd = 0x0001`, `PanelPower = 0x0002`, `BacklightPwm = 0x0003`,
/// `FanTach = 0x000C`, described as "Documented `usGpioID` discriminants per
/// AtomBios.h". None of those values or names appear in any AMD header, and
/// `gpio_id` is one byte, not a `u16`. The DDC lines in particular are not
/// found by id at all — `amdgpu_atombios_i2c_init` walks the LUT for entries
/// with `I2C_HW_CAP` set and reads the register index out of each.
pub const I2C_HW_CAP: u8 = 0x80;
pub const I2C_HW_ENGINE_ID_MASK: u8 = 0x70;
pub const I2C_HW_ENGINE_ID_SHIFT: u8 = 4;
pub const I2C_HW_LANE_MUX: u8 = 0x0f;
pub const PCIE_VDDC_CONTROL_GPIO_PINID: u8 = 56;
pub const PP_AC_DC_SWITCH_GPIO_PINID: u8 = 60;
pub const VDDC_VRHOT_GPIO_PINID: u8 = 61;
pub const VDDC_PCC_GPIO_PINID: u8 = 62;
pub const EFUSE_CUT_ENABLE_GPIO_PINID: u8 = 63;
pub const DRAM_SELF_REFRESH_GPIO_PINID: u8 = 64;
pub const THERMAL_INT_OUTPUT_GPIO_PINID: u8 = 65;

/// `sizeof(struct atom_gpio_pin_assignment)`.
pub const GPIO_PIN_ASSIGNMENT_BYTES: usize = 8;
/// `sizeof(struct atom_common_table_header)` — the LUT's entries follow it.
pub const TABLE_HEADER_BYTES: usize = 4;

/// One pin-assignment entry, `struct atom_gpio_pin_assignment`:
///
/// ```text
/// +0x00  data_a_reg_index    u32
/// +0x04  gpio_bitshift       u8
/// +0x05  gpio_mask_bitshift  u8
/// +0x06  gpio_id             u8
/// +0x07  reserved            u8
/// ```
///
/// LINUX-GAP: the previous decode read a `u16` id at 0x00, an `index` at 0x02,
/// a `pin_type` at 0x03, then named 0x04..0x07 `gpio_byte_offset`,
/// `gpio_mask`, `gpio_pin_value` and `simulation_flag`. Every field was
/// displaced, `pin_type`/`gpio_pin_value`/`simulation_flag` do not exist, and
/// `data_a_reg_index` — the register the pin actually lives in, which is the
/// reason the table exists — was never read at all. The 8-byte stride was the
/// one thing right about it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GpioPin {
    /// Dword index of the GPIO's data-A register.
    pub data_a_reg_index: u32,
    /// Bit position of this pin within that register.
    pub gpio_bitshift: u8,
    /// Bit position of this pin's mask within the paired mask register.
    pub gpio_mask_bitshift: u8,
    pub gpio_id: u8,
}

impl GpioPin {
    /// `true` when `gpio_id` has `I2C_HW_CAP` set, meaning this entry is one
    /// line of an I²C pair rather than a generic GPIO.
    pub fn is_i2c(&self) -> bool {
        self.gpio_id & I2C_HW_CAP != 0
    }
    /// The I²C engine id, bits 6:4. Meaningless unless [`Self::is_i2c`].
    pub fn i2c_engine_id(&self) -> u8 {
        (self.gpio_id & I2C_HW_ENGINE_ID_MASK) >> I2C_HW_ENGINE_ID_SHIFT
    }
    /// The I²C lane mux, bits 3:0. Meaningless unless [`Self::is_i2c`].
    pub fn i2c_lane_mux(&self) -> u8 {
        self.gpio_id & I2C_HW_LANE_MUX
    }
    /// Mask of this pin within its data-A register.
    pub fn bit_mask(&self) -> u32 {
        1u32 << self.gpio_bitshift
    }
}

/// Iterator over the GPIO pin LUT.
#[derive(Debug)]
pub struct GpioPinLut<'a> {
    raw: &'a [u8],
    n_pins: usize,
    cursor: usize,
}

impl<'a> GpioPinLut<'a> {
    /// Parse the LUT directory. Caller obtains the slice via
    /// `Atombios::data_table(0x16)`.
    pub fn parse(raw: &'a [u8]) -> Result<Self, GpioPinError> {
        // Header is 4 bytes; minimum table = header alone.
        if raw.len() < 4 {
            return Err(GpioPinError::Truncated);
        }
        let format_revision = raw[2];
        if format_revision != 1 {
            return Err(GpioPinError::UnsupportedVersion(format_revision));
        }
        // "the real number of this included in the structure is calculated by
        // using the (whole structure size - the header size) / size of
        // atom_gpio_pin_lut" — the comment on `atom_gpio_pin_lut_v2_1`.
        let body_bytes = raw.len().saturating_sub(TABLE_HEADER_BYTES);
        let n_pins = body_bytes / GPIO_PIN_ASSIGNMENT_BYTES;
        Ok(Self {
            raw,
            n_pins,
            cursor: TABLE_HEADER_BYTES,
        })
    }

    /// Number of pin assignments in the table.
    pub fn pin_count(&self) -> usize {
        self.n_pins
    }

    /// Reset iterator cursor to the first pin.
    pub fn rewind(&mut self) {
        self.cursor = TABLE_HEADER_BYTES;
    }

    /// Look up the first entry whose `gpio_id` matches exactly.
    pub fn find_id(&mut self, want: u8) -> Option<GpioPin> {
        self.rewind();
        Iterator::find(self, |p| p.gpio_id == want)
    }

    /// The I²C pin pair for `engine_id`, as `amdgpu_atombios_i2c_init` finds
    /// it: entries with `I2C_HW_CAP` set, matched on the engine id in bits
    /// 6:4. Returns them in table order; a pair is two consecutive entries,
    /// clock then data.
    pub fn find_i2c_engine(&mut self, engine_id: u8) -> Option<(GpioPin, GpioPin)> {
        self.rewind();
        let first = Iterator::find(self, |p| p.is_i2c() && p.i2c_engine_id() == engine_id)?;
        let second = Iterator::find(self, |p| p.is_i2c() && p.i2c_engine_id() == engine_id)?;
        Some((first, second))
    }
}

impl<'a> Iterator for GpioPinLut<'a> {
    type Item = GpioPin;
    fn next(&mut self) -> Option<GpioPin> {
        if self.cursor + GPIO_PIN_ASSIGNMENT_BYTES > self.raw.len() {
            return None;
        }
        let off = self.cursor;
        let pin = GpioPin {
            data_a_reg_index: u32::from_le_bytes([
                self.raw[off],
                self.raw[off + 1],
                self.raw[off + 2],
                self.raw[off + 3],
            ]),
            gpio_bitshift: self.raw[off + 4],
            gpio_mask_bitshift: self.raw[off + 5],
            gpio_id: self.raw[off + 6],
        };
        self.cursor += GPIO_PIN_ASSIGNMENT_BYTES;
        Some(pin)
    }
}

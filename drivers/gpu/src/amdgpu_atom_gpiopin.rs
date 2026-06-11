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

use core::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GpioPinError {
    Truncated,
    UnsupportedVersion(u8),
    /// `ucGPIO_PinType` not in any documented value range.
    UnknownPinType(u8),
}

/// Documented `usGpioID` discriminants per AtomBios.h.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GpioId {
    /// DDC clock line (I²C SCL for EDID DDC reads).
    DdcScl,
    /// DDC data line (I²C SDA).
    DdcSda,
    /// Hot-plug-detect input.
    Hpd,
    /// Panel power enable (eDP).
    PanelPower,
    /// Backlight PWM output.
    BacklightPwm,
    /// Fan tach input.
    FanTach,
    /// Catch-all for un-recognised IDs; preserves the raw u16.
    Other(u16),
}

impl GpioId {
    fn from_raw(raw: u16) -> Self {
        match raw {
            0x000A => GpioId::DdcScl,
            0x000B => GpioId::DdcSda,
            0x0001 => GpioId::Hpd,
            0x0002 => GpioId::PanelPower,
            0x0003 => GpioId::BacklightPwm,
            0x000C => GpioId::FanTach,
            other => GpioId::Other(other),
        }
    }
}

/// One pin-assignment entry from the GPIO pin LUT.
#[derive(Copy, Clone)]
pub struct GpioPin {
    pub id: GpioId,
    /// Per-pin index within the GPIO controller block.
    pub index: u8,
    /// `ucGPIO_PinType` — 0 = input, 1 = output, others
    /// vendor-specific.
    pub pin_type: u8,
    pub gpio_byte_offset: u8,
    pub gpio_mask: u8,
    pub gpio_pin_value: u8,
    pub simulation_flag: u8,
}

impl fmt::Debug for GpioPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GpioPin")
            .field("id", &self.id)
            .field("index", &self.index)
            .field("type", &self.pin_type)
            .field("byte_off", &self.gpio_byte_offset)
            .field("mask", &self.gpio_mask)
            .finish_non_exhaustive()
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
        let body_bytes = raw.len().saturating_sub(4);
        let n_pins = body_bytes / 8;
        if 4 + n_pins * 8 > raw.len() {
            return Err(GpioPinError::Truncated);
        }
        Ok(Self {
            raw,
            n_pins,
            cursor: 4,
        })
    }

    /// Number of pin assignments in the table.
    pub fn pin_count(&self) -> usize {
        self.n_pins
    }

    /// Reset iterator cursor to the first pin.
    pub fn rewind(&mut self) {
        self.cursor = 4;
    }

    /// Look up the first entry whose `id` matches. Useful for
    /// "give me the DDC SCL pin for connector 0".
    pub fn find(&mut self, want: GpioId) -> Option<GpioPin> {
        self.rewind();
        Iterator::find(self, |p| p.id == want)
    }
}

impl<'a> Iterator for GpioPinLut<'a> {
    type Item = GpioPin;
    fn next(&mut self) -> Option<GpioPin> {
        if self.cursor + 8 > self.raw.len() {
            return None;
        }
        let off = self.cursor;
        let raw_id = u16::from_le_bytes([self.raw[off], self.raw[off + 1]]);
        let pin = GpioPin {
            id: GpioId::from_raw(raw_id),
            index: self.raw[off + 2],
            pin_type: self.raw[off + 3],
            gpio_byte_offset: self.raw[off + 4],
            gpio_mask: self.raw[off + 5],
            gpio_pin_value: self.raw[off + 6],
            simulation_flag: self.raw[off + 7],
        };
        self.cursor += 8;
        Some(pin)
    }
}

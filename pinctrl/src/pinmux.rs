//! Generic pin-mux config word encoding.
//!
//! Most ARM SoC pin-controllers expose a per-pin 32-bit config
//! register with a similar shape: function-select bits, drive
//! strength, pull-up / pull-down, output enable, and an optional
//! bias-disable bit. The exact bit positions vary; this module
//! provides a *packed* representation [`PinConfig`] that vendor
//! drivers translate into their MMIO layout.
//!
//! Reference: layouts cross-validated against Qualcomm TLMM (32-bit
//! "GPIO_CFG" register), Rockchip GRF, and MediaTek pinctrl IP.
//! Bit positions in [`pack`] / [`unpack`] are this crate's
//! canonical form, *not* any specific SoC — drivers shift fields
//! as needed.

extern crate alloc;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PinDirection {
    Input = 0,
    Output = 1,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PinPull {
    None = 0,
    Down = 1,
    Up = 2,
    /// Bus keeper / "weak hold" — keeps the last driven value when
    /// the line goes high-Z. SoCs that don't expose this collapse
    /// to `None`.
    Keeper = 3,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PinDriveStrength {
    /// 2 mA (typical low-current input/output).
    Strength2mA = 0,
    Strength4mA = 1,
    Strength6mA = 2,
    Strength8mA = 3,
    Strength10mA = 4,
    Strength12mA = 5,
    Strength14mA = 6,
    Strength16mA = 7,
}

/// Canonical packed pin config word. Layout (LSB-first):
///
/// ```text
///   bits[3:0]   function (0..15) — 0 = GPIO, 1..15 = alt-mux N
///   bits[5:4]   pull (none/down/up/keeper)
///   bits[8:6]   drive strength (2..16 mA in 2-mA steps)
///   bit  9      direction (0 = input, 1 = output)
///   bit  10     output enable (0 = HiZ, 1 = drive)
///   bit  11     open-drain (1 = open-drain output)
///   bit  12     schmitt-trigger input
///   bits[31:13] reserved (must be 0)
/// ```
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PinConfig {
    pub function: u8,
    pub pull: PinPullOpt,
    pub drive: PinDriveOpt,
    pub direction: PinDirection,
    pub output_enabled: bool,
    pub open_drain: bool,
    pub schmitt: bool,
}

/// Newtype wrapper so a fully-default `PinConfig` reads as
/// "function=0, pull=None, drive=Strength2mA, direction=Input".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PinPullOpt(pub PinPull);
impl Default for PinPullOpt {
    fn default() -> Self {
        Self(PinPull::None)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PinDriveOpt(pub PinDriveStrength);
impl Default for PinDriveOpt {
    fn default() -> Self {
        Self(PinDriveStrength::Strength2mA)
    }
}

impl Default for PinDirection {
    fn default() -> Self {
        Self::Input
    }
}

impl PinConfig {
    /// Pack into the 32-bit canonical word.
    pub fn pack(self) -> u32 {
        let mut v: u32 = (self.function as u32) & 0xF;
        v |= ((self.pull.0 as u32) & 0x3) << 4;
        v |= ((self.drive.0 as u32) & 0x7) << 6;
        v |= (self.direction as u32 & 1) << 9;
        if self.output_enabled {
            v |= 1 << 10;
        }
        if self.open_drain {
            v |= 1 << 11;
        }
        if self.schmitt {
            v |= 1 << 12;
        }
        v
    }

    /// Decode from the 32-bit canonical word.
    pub fn unpack(v: u32) -> Self {
        Self {
            function: (v & 0xF) as u8,
            pull: PinPullOpt(match (v >> 4) & 0x3 {
                0 => PinPull::None,
                1 => PinPull::Down,
                2 => PinPull::Up,
                _ => PinPull::Keeper,
            }),
            drive: PinDriveOpt(match (v >> 6) & 0x7 {
                0 => PinDriveStrength::Strength2mA,
                1 => PinDriveStrength::Strength4mA,
                2 => PinDriveStrength::Strength6mA,
                3 => PinDriveStrength::Strength8mA,
                4 => PinDriveStrength::Strength10mA,
                5 => PinDriveStrength::Strength12mA,
                6 => PinDriveStrength::Strength14mA,
                _ => PinDriveStrength::Strength16mA,
            }),
            direction: if v & (1 << 9) != 0 {
                PinDirection::Output
            } else {
                PinDirection::Input
            },
            output_enabled: v & (1 << 10) != 0,
            open_drain: v & (1 << 11) != 0,
            schmitt: v & (1 << 12) != 0,
        }
    }

    /// Builder helpers — common combinations.
    pub const fn input() -> Self {
        Self {
            function: 0,
            pull: PinPullOpt(PinPull::None),
            drive: PinDriveOpt(PinDriveStrength::Strength2mA),
            direction: PinDirection::Input,
            output_enabled: false,
            open_drain: false,
            schmitt: false,
        }
    }
    pub const fn output_pushpull() -> Self {
        Self {
            function: 0,
            pull: PinPullOpt(PinPull::None),
            drive: PinDriveOpt(PinDriveStrength::Strength2mA),
            direction: PinDirection::Output,
            output_enabled: true,
            open_drain: false,
            schmitt: false,
        }
    }
    pub const fn output_open_drain() -> Self {
        Self {
            function: 0,
            pull: PinPullOpt(PinPull::None),
            drive: PinDriveOpt(PinDriveStrength::Strength2mA),
            direction: PinDirection::Output,
            output_enabled: true,
            open_drain: true,
            schmitt: false,
        }
    }
    pub const fn alt(func: u8) -> Self {
        Self {
            function: func & 0xF,
            pull: PinPullOpt(PinPull::None),
            drive: PinDriveOpt(PinDriveStrength::Strength2mA),
            direction: PinDirection::Input,
            output_enabled: false,
            open_drain: false,
            schmitt: false,
        }
    }
}

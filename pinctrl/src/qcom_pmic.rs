//! Qualcomm PMIC peripheral GPIO type — clean-room.
//!
//! ## Reference (public only)
//!
//! - **Qualcomm PMIC peripheral register reference** — peripheral
//!   type IDs and register layouts. The constants here are the
//!   device-side reality (read off PMICs via SPMI), not Linux's
//!   interpretation of them.
//!   <https://docs.kernel.org/devicetree/bindings/pinctrl/qcom,pmic-gpio.yaml>
//!   (the kernel binding doc lists the public register layout the
//!   hardware exposes; we re-derive from the same set of public bits).
//!
//! No GPL / Linux source consulted (only public binding docs that
//! describe the hardware-visible registers).
//!
//! ## What this is
//!
//! Decoders + builders for the per-PMIC-GPIO peripheral register
//! block. Each Qualcomm PMIC peripheral occupies 0x100 bytes of
//! the SPMI register space; multiple peripherals (GPIOs, RTC, MPP,
//! regulators) live alongside each other.
//!
//! Peripheral type IDs (offset 0x4 in each peripheral block):
//! - 0x05 = SMPS regulator
//! - 0x06 = LDO regulator
//! - 0x10 = GPIO
//! - 0x11 = MPP (multi-purpose pad)
//! - 0x6000 = RTC

extern crate alloc;

/// Per-peripheral registers (offsets within a 0x100-byte block).
pub mod regs {
    pub const TYPE: usize = 0x04;
    pub const SUBTYPE: usize = 0x05;
    pub const STATUS1: usize = 0x08;
    pub const MODE_CTL: usize = 0x40;
    pub const DIG_VIN_CTL: usize = 0x41;
    pub const DIG_PULL_CTL: usize = 0x42;
    pub const DIG_IN_CTL: usize = 0x43;
    pub const DIG_OUT_CTL: usize = 0x45;
    pub const EN_CTL: usize = 0x46;
}

pub mod ptype {
    pub const SMPS_REG: u8 = 0x05;
    pub const LDO_REG: u8 = 0x06;
    pub const GPIO: u8 = 0x10;
    pub const MPP: u8 = 0x11;
}

/// MODE_CTL bit layout (Qualcomm PMIC GPIO peripheral).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioMode {
    Input = 0b00,
    Output = 0b01,
    InputOutput = 0b10,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioOutputType {
    /// CMOS push-pull (default).
    Cmos = 0,
    /// Open drain.
    Open = 1,
}

/// Build the `MODE_CTL` byte (bits[7:0] of register 0x40).
///
/// ```text
///   bits[1:0]  reserved
///   bits[3:2]  output type (00 = CMOS, 01 = open-drain NMOS,
///                          10 = open-source PMOS, 11 = reserved)
///   bits[6:4]  mode select (Input=0, Output=1, In/Out=2)
///   bit  7     output value (when mode = Output)
/// ```
pub fn build_mode_ctl(mode: GpioMode, out_type: GpioOutputType, output_value: bool) -> u8 {
    let mut v: u8 = 0;
    let ot_bits = match out_type {
        GpioOutputType::Cmos => 0b00,
        GpioOutputType::Open => 0b01,
    };
    v |= ot_bits << 2;
    v |= (mode as u8) << 4;
    if output_value {
        v |= 1 << 7;
    }
    v
}

/// Pull configuration encoded into `DIG_PULL_CTL` (register 0x42).
/// Bits[2:0] select pull strength + direction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PmicPull {
    /// No pull. Common for output pins.
    NoPull = 0b101,
    /// 30 kΩ pull-up.
    PullUp30k = 0b000,
    /// 1.5 kΩ pull-up.
    PullUp1_5k = 0b001,
    /// 31.5 kΩ pull-up.
    PullUp31_5k = 0b010,
    /// 1.5 kΩ pull-up + 30 kΩ pull-down combined ("BUS HOLD").
    BusHold = 0b011,
    /// 10 kΩ pull-down.
    PullDown10k = 0b100,
}

pub fn build_dig_pull_ctl(p: PmicPull) -> u8 {
    p as u8
}

/// Bring-up: build the four register writes a Qualcomm PMIC GPIO
/// peripheral needs to come up as a push-pull output driving 0.
/// Returns `(offset, value)` pairs the caller submits via SPMI
/// extended-write commands in order.
pub fn make_gpio_pushpull_output_writes(initial_value: bool) -> [(usize, u8); 4] {
    [
        // Pull: no pull (output).
        (regs::DIG_PULL_CTL, build_dig_pull_ctl(PmicPull::NoPull)),
        // Output drive control: low / mid / high — pick "low" (0b01)
        // as the safe default; vendor drivers tune per-board.
        (regs::DIG_OUT_CTL, 0b01),
        // Mode = output, CMOS push-pull, supplied initial value.
        (
            regs::MODE_CTL,
            build_mode_ctl(GpioMode::Output, GpioOutputType::Cmos, initial_value),
        ),
        // Enable.
        (regs::EN_CTL, 1 << 7),
    ]
}

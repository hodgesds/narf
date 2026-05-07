//! Wolfson / Cirrus Logic WM8960 audio codec — clean-room.
//!
//! ## Sources (public only)
//!
//! - **Cirrus Logic, "WM8960 Stereo Codec with 1W Stereo Class D
//!   Speaker Drivers" datasheet**, Rev 4.4, 2010. Public.
//!   <https://statics.cirrus.com/pubs/proDatasheet/WM8960_Rev_4.4.pdf>
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Register-write codec for the WM8960 — a popular reference
//! audio codec used by Raspberry Pi audio HATs, eval boards, and
//! many embedded products. Configured over I2C; the chip exposes
//! a 9-bit register address space (0x00..=0x37) accessed via a
//! 16-bit I2C write where the high 7 bits are the address and
//! the low 9 bits are the data.
//!
//! All routines produce the canonical 16-bit value to be sent to
//! the I2C transport — no live MMIO / I2C calls here.

extern crate alloc;
use alloc::vec::Vec;

/// 7-bit I2C address. WM8960 is hard-wired to `0b0011010` =
/// `0x1A` (datasheet §6).
pub const I2C_ADDRESS: u8 = 0x1A;

/// Register addresses (datasheet §3 "Register Map").
pub mod regs {
    pub const LEFT_INPUT_VOLUME: u8 = 0x00;
    pub const RIGHT_INPUT_VOLUME: u8 = 0x01;
    pub const LOUT1_VOLUME: u8 = 0x02;
    pub const ROUT1_VOLUME: u8 = 0x03;
    pub const CLOCKING_1: u8 = 0x04;
    pub const ADC_DAC_CTRL_1: u8 = 0x05;
    pub const ADC_DAC_CTRL_2: u8 = 0x06;
    pub const AUDIO_INTERFACE: u8 = 0x07;
    pub const CLOCKING_2: u8 = 0x08;
    pub const AUDIO_INTERFACE_2: u8 = 0x09;
    pub const LEFT_DAC_VOLUME: u8 = 0x0A;
    pub const RIGHT_DAC_VOLUME: u8 = 0x0B;
    pub const RESET: u8 = 0x0F;
    pub const POWER_MGMT_1: u8 = 0x19;
    pub const POWER_MGMT_2: u8 = 0x1A;
    pub const ADDITIONAL_CTRL_1: u8 = 0x1B;
    pub const ADDITIONAL_CTRL_2: u8 = 0x1C;
    pub const POWER_MGMT_3: u8 = 0x2F;
    pub const ANTI_POP_1: u8 = 0x1D;
    pub const ANTI_POP_2: u8 = 0x1E;
    pub const LEFT_OUT_MIX: u8 = 0x22;
    pub const RIGHT_OUT_MIX: u8 = 0x25;
    pub const SPEAKER_OUT_LEFT: u8 = 0x28;
    pub const SPEAKER_OUT_RIGHT: u8 = 0x29;
    pub const SPEAKER_OUT_VOLUME: u8 = 0x2D;
    pub const CLASS_D_CTRL_1: u8 = 0x31;
    pub const CLASS_D_CTRL_3: u8 = 0x33;
    pub const PLL_N: u8 = 0x34;
    pub const PLL_K_1: u8 = 0x35;
    pub const PLL_K_2: u8 = 0x36;
    pub const PLL_K_3: u8 = 0x37;
}

/// Audio Interface register (R7) bit fields.
pub mod audio_iface {
    /// Format bits[1:0]: 00 = Right Justified, 01 = Left Justified,
    /// 10 = Standard I2S, 11 = DSP/PCM.
    pub const FORMAT_RIGHT_JUSTIFIED: u16 = 0b00;
    pub const FORMAT_LEFT_JUSTIFIED: u16 = 0b01;
    pub const FORMAT_I2S: u16 = 0b10;
    pub const FORMAT_DSP: u16 = 0b11;

    /// Word Length bits[3:2]: 00 = 16, 01 = 20, 10 = 24, 11 = 32.
    pub const WL_16: u16 = 0b00 << 2;
    pub const WL_20: u16 = 0b01 << 2;
    pub const WL_24: u16 = 0b10 << 2;
    pub const WL_32: u16 = 0b11 << 2;

    pub const LRCLK_INVERT: u16 = 1 << 4;
    pub const BCLK_INVERT: u16 = 1 << 7;
    /// Master/slave (bit 6): 0 = slave (codec receives BCLK/LRC),
    /// 1 = master.
    pub const MASTER: u16 = 1 << 6;
}

/// Pack a register-write into the 16-bit I2C wire form: 7-bit
/// address in [15:9], 9-bit data in [8:0]. The WM8960 receives
/// these as two-byte big-endian I2C transfers.
pub fn pack_register_write(reg: u8, data: u16) -> [u8; 2] {
    let v = (((reg & 0x7F) as u16) << 9) | (data & 0x01FF);
    v.to_be_bytes()
}

/// Decode a 2-byte register write back into `(reg, data)`.
pub fn unpack_register_write(buf: [u8; 2]) -> (u8, u16) {
    let v = u16::from_be_bytes(buf);
    let reg = ((v >> 9) & 0x7F) as u8;
    let data = v & 0x01FF;
    (reg, data)
}

/// Build the canonical "fresh-start" sequence: software reset, then
/// power on the analogue + digital domains, configure I2S as the
/// audio interface, set DAC volume to 0 dB, enable the line/
/// speaker output mixers. Caller submits each `(reg, value)` pair
/// via I2C in order.
pub fn build_init_sequence_i2s_master_16bit() -> Vec<(u8, u16)> {
    use audio_iface::*;
    let mut out = Vec::new();
    // Software reset — write any value to R15.
    out.push((regs::RESET, 0x000));
    // Power Management 1: VMID=50 kΩ (bit 8/7 = 01), VREF on.
    out.push((regs::POWER_MGMT_1, (0b01 << 7) | (1 << 6)));
    // Power Management 2: DACL, DACR, LOUT1, ROUT1 on.
    out.push((regs::POWER_MGMT_2, (1 << 8) | (1 << 7) | (1 << 6) | (1 << 5)));
    // Power Management 3: LOMIX, ROMIX on.
    out.push((regs::POWER_MGMT_3, (1 << 3) | (1 << 2)));
    // Audio Interface (R7): I2S, 16-bit, master.
    out.push((regs::AUDIO_INTERFACE, FORMAT_I2S | WL_16 | MASTER));
    // Left/Right DAC volume = 0 dB. The DAC volume register is
    // 8-bit; bit 8 = simultaneous-update flag.
    out.push((regs::LEFT_DAC_VOLUME, 0xFF | (1 << 8)));
    out.push((regs::RIGHT_DAC_VOLUME, 0xFF | (1 << 8)));
    // Output Mixer enables: LOMIX, ROMIX = LD2LO / RD2RO.
    out.push((regs::LEFT_OUT_MIX, 1 << 8));
    out.push((regs::RIGHT_OUT_MIX, 1 << 8));
    // LOUT1 / ROUT1 volumes = 0 dB with simultaneous update.
    out.push((regs::LOUT1_VOLUME, 0x79 | (1 << 8) | (1 << 7)));
    out.push((regs::ROUT1_VOLUME, 0x79 | (1 << 8) | (1 << 7)));
    out
}

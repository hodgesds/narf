//! Intel 8254 PIT (Programmable Interval Timer) — clean-room.
//!
//! Reference: **Intel "8254 Programmable Interval Timer"** datasheet
//! (free, intel.com / many mirrors). The IBM PC PIT lives at IO
//! ports 0x40..0x43:
//!
//! | port | content                              |
//! |------|--------------------------------------|
//! | 0x40 | Channel 0 data                       |
//! | 0x41 | Channel 1 data (refresh; do not use) |
//! | 0x42 | Channel 2 data (PC speaker)          |
//! | 0x43 | Mode/Command register                |
//!
//! Input clock is 1.193182 MHz (the original IBM PC's
//! `14.31818 MHz / 12` divider). The 16-bit count register
//! decrements once per input tick; rolling over generates the
//! programmed event.
//!
//! ## Modes
//!
//! Stage cut covers two:
//!
//! - **Mode 0** — interrupt on terminal count. Useful as a
//!   one-shot: counter starts when written, OUT goes high after
//!   the count expires, stays high until the next mode write.
//! - **Mode 2** — rate generator. OUT pulses low for one input
//!   tick every `count` ticks (periodic).
//!
//! Channel 2's OUT is connected to the PC speaker through the
//! PPI gate at 0x61; the PIT module here only programs the
//! counter, the gate logic lives in the speaker driver.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::io_port::{inb, outb};

/// Input clock frequency in Hz.
pub const PIT_INPUT_HZ: u32 = 1_193_182;

const PIT_CH0:  u16 = 0x40;
const PIT_CH2:  u16 = 0x42;
const PIT_CTRL: u16 = 0x43;

const PPI_PORT: u16 = 0x61;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Channel { Ch0 = 0, Ch2 = 2 }

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode { OneShot = 0, RateGenerator = 2, SquareWave = 3 }

fn ctrl_byte(ch: Channel, mode: Mode) -> u8 {
    // bits[7:6] = channel, bits[5:4] = access mode (0b11 = lo/hi
    // word), bits[3:1] = operating mode, bit 0 = BCD.
    ((ch as u8) << 6) | (0b11 << 4) | ((mode as u8) << 1)
}

/// Program a channel with `(count, mode)`. The counter is loaded
/// low-byte first, then high-byte.
///
/// # Safety
/// CPL = 0; PIT IO window owned.
pub unsafe fn program(ch: Channel, mode: Mode, count: u16) {
    // SAFETY: caller-asserted.
    unsafe {
        outb(PIT_CTRL, ctrl_byte(ch, mode));
        let port = match ch { Channel::Ch0 => PIT_CH0, Channel::Ch2 => PIT_CH2 };
        outb(port, (count & 0xFF) as u8);
        outb(port, (count >> 8)   as u8);
    }
}

/// Program a one-shot of `nanos` nanoseconds on channel 2 (PC
/// speaker line — works as a free-running timer when the
/// speaker gate is low). Returns the actual programmed count;
/// caller can multiply back through `PIT_INPUT_HZ` to learn
/// the realised duration.
///
/// # Safety
/// CPL = 0.
pub unsafe fn one_shot_ch2(nanos: u64) -> u16 {
    let ticks = (nanos as u128 * PIT_INPUT_HZ as u128 / 1_000_000_000) as u64;
    let count = ticks.min(u16::MAX as u64).max(1) as u16;
    // Disable speaker gate (bit 1), enable timer 2 gate (bit 0).
    // SAFETY: caller-asserted.
    unsafe {
        let v = inb(PPI_PORT);
        outb(PPI_PORT, (v & !0x02) | 0x01);
        program(Channel::Ch2, Mode::OneShot, count);
    }
    count
}

/// Read the current channel-2 counter via the latch command.
///
/// # Safety
/// CPL = 0.
pub unsafe fn read_ch2() -> u16 {
    // SAFETY: caller-asserted.
    unsafe {
        // Latch-counter command: bits[7:6] = ch, bits[5:4] = 0 (latch).
        outb(PIT_CTRL, (Channel::Ch2 as u8) << 6);
        let lo = inb(PIT_CH2);
        let hi = inb(PIT_CH2);
        ((hi as u16) << 8) | lo as u16
    }
}

/// Spin until channel 2's counter reaches zero (OUT goes high),
/// up to a bounded number of polls. Used when calibrating a
/// derived clock off the PIT.
///
/// # Safety
/// CPL = 0; channel 2 is currently programmed in Mode 0 (one-shot).
pub unsafe fn wait_ch2_done() -> bool {
    for _ in 0..100_000_000u32 {
        // SAFETY: caller-asserted.
        let v = unsafe { inb(PPI_PORT) };
        if v & 0x20 != 0 { return true; }   // Bit 5 = TIMER 2 OUT.
        core::hint::spin_loop();
    }
    false
}

//! Nuvoton NCT6775/6776/6779/6791–6798 Super-I/O driver — clean-room.
//!
//! Reference: `linux/drivers/hwmon/nct6775_core.c` (Guenter Roeck —
//! GPL-2.0-or-later).  Register offsets and chip IDs are from the
//! publicly-available Nuvoton NCT6775 datasheet and the Linux source.
//!
//! ## Hardware access
//!
//! The Super-I/O is accessed through ISA I/O ports at either base
//! 0x2E (standard) or 0x4E (alternate, if 0x2E conflicts):
//!
//! - Write `0x87, 0x87` to the **index** port (0x2E/0x4E) to enter
//!   Extended Function Mode (EFM). Linux nct6775_core.c `superio_enter`.
//! - Read chip ID: write 0x20 to index port, read **data** port
//!   (0x2F/0x4F); then write 0x21 and read for the low byte.
//!   Chip ID = `(high << 8) | low`.
//! - Select Logical Device N: write `0x07` to index, write LDN to data.
//! - Write `0xAA, 0xAA` to index port to exit EFM.
//!
//! ## Chip IDs
//!
//! | Chip     | ID (16-bit) | Notes                     |
//! |----------|-------------|---------------------------|
//! | NCT6775F | 0xB470      | Initial Nuvoton SIO chip   |
//! | NCT6776F | 0xC330      | Added 6-pin fan headers    |
//! | NCT6779D | 0xC560      | 5-fan + 7-voltage + 6-temp |
//! | NCT6791D | 0xD280      | PECI support               |
//! | NCT6792D | 0xD420      |                            |
//! | NCT6793D | 0xD121      |                            |
//! | NCT6795D | 0xD352      |                            |
//! | NCT6796D | 0xD423      |                            |
//! | NCT6797D | 0xD451      |                            |
//! | NCT6798D | 0xD42B      |                            |
//!
//! Linux nct6775_core.c `nct6775_chip` enum and `match_chip_id` ~L2800.
//!
//! ## Register map (Hardware Monitor Logical Device, LDN 0x0B)
//!
//! All addresses below are within the HWM LDN's I/O address space
//! (base address read from SIO offset 0x60/0x61):
//!
//! | Offset | Register                              |
//! |--------|---------------------------------------|
//! | 0x00   | Bank select                           |
//! | 0x29   | Tcase / CPU temp input 0 (Bank 1-4)   |
//! | 0x50   | TEMP_IN[0]  (Bank 4, temp sense 1)    |
//! | 0x51   | TEMP_IN[1]  (Bank 4, temp sense 2)    |
//! | 0x20   | FAN1 tach high byte                   |
//! | 0x21   | FAN1 tach low byte                    |
//! | 0x22   | FAN2 tach high byte                   |
//! | 0x23   | FAN2 tach low byte                    |
//! | 0x24   | FAN3 tach high byte                   |
//! | 0x25   | FAN3 tach low byte                    |
//! | 0x26   | FAN4 tach high byte                   |
//! | 0x27   | FAN4 tach low byte                    |
//! | 0x28   | FAN5 tach high byte                   |
//! | 0x29   | FAN5 tach low byte                    |
//! | 0x20   | Voltage IN0 (Bank 4)                  |
//! | 0x21   | Voltage IN1 (Bank 4)                  |
//! | 0x04   | PWM1 output (Bank 4, 0x04)            |
//! | 0x09   | PWM2 output                           |
//! | 0x0E   | PWM3 output                           |
//! | 0x13   | PWM4 output                           |
//! | 0x18   | PWM5 output                           |
//!
//! Actual register layout is chip-specific; the full table lives in
//! `nct6775_chip_data` in the Linux source (~L450–L800).

extern crate alloc;

use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
use crate::registry;

// ── Chip IDs ──────────────────────────────────────────────────────────

/// NCT6775F chip ID. Linux nct6775_core.c ~L2800 `match_chip_id`.
pub const NCT6775F_ID: u16 = 0xB470;
pub const NCT6776F_ID: u16 = 0xC330;
pub const NCT6779D_ID: u16 = 0xC560;
pub const NCT6791D_ID: u16 = 0xD280;
pub const NCT6792D_ID: u16 = 0xD420;
pub const NCT6793D_ID: u16 = 0xD121;
pub const NCT6795D_ID: u16 = 0xD352;
pub const NCT6796D_ID: u16 = 0xD423;
pub const NCT6797D_ID: u16 = 0xD451;
pub const NCT6798D_ID: u16 = 0xD42B;

// ── HWM I/O window / EC register access constants ─────────────────────
//
// Linux ref: nct6775-platform.c.
//
// The HWM logical device (LDN 0x0B) exposes a 2-byte ADDR/DATA window.
// Linux reads the LDN base from SIO offset 0x60/0x61, masks it with
// `IOREGION_ALIGNMENT` (~7), then accesses the EC window at
// `base + IOREGION_OFFSET`.  Within that window the ADDR port is at
// +ADDR_REG_OFFSET and the DATA port at +DATA_REG_OFFSET.
//
//   nct6775-platform.c L57-61:
//     #define IOREGION_ALIGNMENT  (~7)
//     #define IOREGION_OFFSET     5
//     #define ADDR_REG_OFFSET     0
//     #define DATA_REG_OFFSET     1

/// Mask applied to the raw HWM base address (nct6775-platform.c
/// `IOREGION_ALIGNMENT`). The low 3 bits are not part of the address.
pub const IOREGION_ALIGNMENT: u16 = !7u16;
/// Offset from the LDN base to the start of the EC ADDR/DATA window
/// (nct6775-platform.c `IOREGION_OFFSET`).
pub const IOREGION_OFFSET: u16 = 5;
/// ADDR register offset within the EC window (nct6775-platform.c).
pub const ADDR_REG_OFFSET: u16 = 0;
/// DATA register offset within the EC window (nct6775-platform.c).
pub const DATA_REG_OFFSET: u16 = 1;

/// Bank-select pseudo-register written to the ADDR port to switch the
/// active 256-byte register bank (nct6775.h `NCT6775_REG_BANK` = 0x4E).
pub const NCT6775_REG_BANK: u8 = 0x4E;

/// SIO logical-device base-address register (high byte); low byte is at
/// `SIO_REG_ADDR + 1`. nct6775-platform.c `SIO_REG_ADDR` = 0x60.
pub const SIO_REG_ADDR: u8 = 0x60;

// ── HWM register map (NCT6775/6776 common layout) ─────────────────────
//
// Linux ref: nct6775-core.c. These are 16-bit "banked" register
// addresses: the high byte selects the bank, the low byte the offset.

/// Voltage input registers in0..in6 (nct6775-core.c `NCT6775_REG_IN`
/// L94; first seven entries 0x20-0x26 are the directly-readable inputs).
pub const NCT6775_REG_IN: [u16; 7] = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26];

/// Fan tachometer registers (nct6775-core.c `NCT6775_REG_FAN` L150).
/// These are word-sized (16-bit) — one read yields the full count.
pub const NCT6775_REG_FAN: [u16; 5] = [0x630, 0x632, 0x634, 0x636, 0x638];

/// Temperature source registers temp1..temp6 (nct6775-core.c
/// `NCT6775_REG_TEMP` L156). 0x150/0x250 are word-sized (hi:integer °C,
/// lo:fraction); the rest are byte-sized (integer °C only).
pub const NCT6775_REG_TEMP: [u16; 6] = [0x27, 0x150, 0x250, 0x62b, 0x62c, 0x62d];

/// PWM duty-cycle output registers (nct6775-core.c `NCT6775_REG_PWM`
/// L145). Byte-sized, 0..255 duty.
pub const NCT6775_REG_PWM: [u16; 5] = [0x109, 0x209, 0x309, 0x809, 0x909];

// ── SIO access ports ──────────────────────────────────────────────────

/// Standard Super-I/O index/data port pair.
pub const SIO_INDEX_STD: u16 = 0x2E;
pub const SIO_DATA_STD: u16 = 0x2F;
/// Alternate Super-I/O index/data port pair.
pub const SIO_INDEX_ALT: u16 = 0x4E;
pub const SIO_DATA_ALT: u16 = 0x4F;

// ── SIO register offsets ──────────────────────────────────────────────

/// SIO chip ID high byte register.
pub const SIO_CHIP_ID_HIGH: u8 = 0x20;
/// SIO chip ID low byte register.
pub const SIO_CHIP_ID_LOW: u8 = 0x21;
/// SIO logical device number select.
pub const SIO_LDN_SELECT: u8 = 0x07;
/// Hardware monitor logical device number.
pub const LDN_HWM: u8 = 0x0B;

// ── NCT chip variant enum ─────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NctChip {
    Nct6775F,
    Nct6776F,
    Nct6779D,
    Nct6791D,
    Nct6792D,
    Nct6793D,
    Nct6795D,
    Nct6796D,
    Nct6797D,
    Nct6798D,
    Unknown(u16),
}

impl NctChip {
    /// Decode chip-ID word to variant. Masks the low nibble on some
    /// chips that encode a stepping there. Linux `match_chip_id` ~L2800.
    pub fn from_id(id: u16) -> Self {
        match id {
            NCT6775F_ID => NctChip::Nct6775F,
            NCT6776F_ID => NctChip::Nct6776F,
            NCT6779D_ID => NctChip::Nct6779D,
            NCT6791D_ID => NctChip::Nct6791D,
            NCT6792D_ID => NctChip::Nct6792D,
            NCT6793D_ID => NctChip::Nct6793D,
            NCT6795D_ID => NctChip::Nct6795D,
            NCT6796D_ID => NctChip::Nct6796D,
            NCT6797D_ID => NctChip::Nct6797D,
            NCT6798D_ID => NctChip::Nct6798D,
            other => NctChip::Unknown(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            NctChip::Nct6775F => "NCT6775F",
            NctChip::Nct6776F => "NCT6776F",
            NctChip::Nct6779D => "NCT6779D",
            NctChip::Nct6791D => "NCT6791D",
            NctChip::Nct6792D => "NCT6792D",
            NctChip::Nct6793D => "NCT6793D",
            NctChip::Nct6795D => "NCT6795D",
            NctChip::Nct6796D => "NCT6796D",
            NctChip::Nct6797D => "NCT6797D",
            NctChip::Nct6798D => "NCT6798D",
            NctChip::Unknown(_) => "NCT67xxUnknown",
        }
    }

    /// Number of fan tachometer inputs on this chip.
    pub fn num_fans(self) -> u8 {
        match self {
            NctChip::Nct6775F => 3,
            NctChip::Nct6776F => 3,
            NctChip::Nct6779D => 5,
            NctChip::Nct6791D
            | NctChip::Nct6792D
            | NctChip::Nct6793D
            | NctChip::Nct6795D
            | NctChip::Nct6796D
            | NctChip::Nct6797D
            | NctChip::Nct6798D => 5,
            NctChip::Unknown(_) => 0,
        }
    }

    /// Number of temperature sensor inputs.
    pub fn num_temps(self) -> u8 {
        match self {
            NctChip::Nct6775F | NctChip::Nct6776F => 3,
            _ => 6,
        }
    }
}

// ── Fan tach decode ───────────────────────────────────────────────────

/// Decode a 16-bit fan tachometer count to RPM.
///
/// NCT677x formula (Linux nct6775_core.c `nct6775_fan_from_reg`):
///   `RPM = 1350000 / count` when count != 0 and count != 0xFFFF.
/// count = 0 or 0xFFFF means fan stopped / not connected.
#[inline]
pub fn fan_count_to_rpm(count: u16) -> Option<u32> {
    if count == 0 || count == 0xFFFF {
        return None;
    }
    Some(1_350_000 / count as u32)
}

// ── Pure conversion free functions (host-testable) ────────────────────

/// Convert a raw voltage register value to millivolts.
///
/// Linux ref: nct6775-core.c `in_from_reg` (L1002) with the common
/// `scale_in` entry of 800: `result_mV = reg * 800 / 100 = reg * 8`.
/// This is the 8 mV/LSB ADC scaling used for the non-divided inputs
/// (CPUVC, IN0/IN4/IN5/IN6, 3VSB with a board divider handled by the
/// input's `scale_in[nr]` which is not modelled here). Inputs with a
/// 2:1 divider (3VCC, AVSB, VBAT; `scale_in` entry 1600) read at
/// 16 mV/LSB — use [`in_from_reg_scaled`] for those.
#[inline]
pub fn in_from_reg(raw: u8) -> i32 {
    // 8 mV per LSB. nct6775-core.c scale_in[] default entry == 800,
    // i.e. (8 mV * 100), and in_from_reg divides the product by 100.
    raw as i32 * 8
}

/// Convert a raw voltage register value to millivolts using an explicit
/// per-input scale factor (`scale_in` units: 8 mV-per-LSB * 100).
///
/// Linux ref: nct6775-core.c `in_from_reg` (L1002):
///   `DIV_ROUND_CLOSEST(reg * scale, 100)`.
/// Common scales are 800 (8 mV/LSB) and 1600 (16 mV/LSB).
#[inline]
pub fn in_from_reg_scaled(raw: u8, scale: u16) -> i32 {
    // DIV_ROUND_CLOSEST(a, b) == (a + b/2) / b for non-negative a.
    let num = raw as i32 * scale as i32;
    (num + 50) / 100
}

/// Convert a raw temperature register word to millidegrees Celsius.
///
/// Linux ref: lm75.h `LM75_TEMP_FROM_REG`:
///   `((s16)reg / 128) * 500`
/// The register word packs temperature as (0.5 °C/bit, two's complement)
/// shifted left by 7. For byte-sized temp registers (integer °C only),
/// the raw byte is first shifted into the high byte (see
/// nct6775-core.c `nct6775_read_temp` L1220: `*val <<= 8` when the reg
/// is not word-sized); pass that shifted word here.
#[inline]
pub fn temp_from_reg_word(reg: u16) -> i32 {
    // Integer division (not >>) to guarantee arithmetic/sign behaviour,
    // matching the kernel comment in lm75.h.
    ((reg as i16) / 128) as i32 * 500
}

/// Convert a byte-sized temperature register (integer °C) to
/// millidegrees. Equivalent to `temp_from_reg_word((raw as u16) << 8)`.
///
/// Linux ref: nct6775-core.c `nct6775_read_temp` + lm75.h.
/// For a byte value `t` (0..127): `((t<<8) as i16)/128 == t*2`, and
/// `t*2*500 == t*1000` millidegrees. Values 128..255 decode as negative
/// temperatures via two's complement, matching the kernel.
#[inline]
pub fn temp_from_reg(raw: u8) -> i32 {
    temp_from_reg_word((raw as u16) << 8)
}

/// True if a 16-bit HWM register is accessed as a 16-bit word on the
/// NCT6775/6776 family (the only families this driver reads).
///
/// Linux ref: nct6775-core.c `nct6775_reg_is_word_sized` L1151 (the
/// `nct6775`/`nct6776` arms; common subset). We only need the cases the
/// register maps above can produce: the banked temp regs 0x150/0x250
/// (`(reg&0xff00)==0x100||0x200 && (reg&0xff)==0x50`) and the fan
/// tach regs 0x630-0x638 (`(reg&0xfff0)==0x630`).
#[inline]
pub fn reg_is_word_sized(reg: u16) -> bool {
    (((reg & 0xff00) == 0x100 || (reg & 0xff00) == 0x200)
        && ((reg & 0x00ff) == 0x50 || (reg & 0x00ff) == 0x53 || (reg & 0x00ff) == 0x55))
        || (reg & 0xfff0) == 0x630
}

// ── SIO access primitives ─────────────────────────────────────────────

/// Enter Extended Function Mode.
/// Write the unlock sequence 0x87, 0x87 to the index port.
/// Linux nct6775_core.c `superio_enter`.
///
/// # Safety
///
/// The caller must ensure we are in kernel context (CPL-0) and that
/// `index_port` is a valid Super-I/O port (0x2E or 0x4E).
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn sio_enter(index_port: u16) {
    // SAFETY: caller ensures we are in kernel context (CPL-0) and that
    // index_port is 0x2E or 0x4E — standard Super-I/O ports.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        narf_arch::x86_64::io_port::outb(index_port, 0x87);
        narf_arch::x86_64::io_port::outb(index_port, 0x87);
    }
}

/// Exit Extended Function Mode.
/// Write the lock sequence 0xAA to the index port.
/// Linux nct6775_core.c `superio_exit`.
///
/// # Safety
///
/// Same requirements as `sio_enter`.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn sio_exit(index_port: u16) {
    // SAFETY: same as `sio_enter`.
    unsafe {
        narf_arch::x86_64::io_port::outb(index_port, 0xAA);
    }
}

/// Read a byte from a Super-I/O register. Must be called with the
/// device in EFM (after `sio_enter`).
///
/// # Safety
///
/// Must be called with CPL-0 privileges and within an EFM block (after `sio_enter` and before `sio_exit`).
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn sio_read(index_port: u16, data_port: u16, reg: u8) -> u8 {
    // SAFETY: CPL-0 I/O, called within sio_enter / sio_exit block.
    unsafe {
        narf_arch::x86_64::io_port::outb(index_port, reg);
        narf_arch::x86_64::io_port::inb(data_port)
    }
}

/// Write a byte to a Super-I/O register.
///
/// # Safety
///
/// Same requirements as `sio_read`.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn sio_write(index_port: u16, data_port: u16, reg: u8, val: u8) {
    // SAFETY: CPL-0 I/O, called within sio_enter / sio_exit block.
    unsafe {
        narf_arch::x86_64::io_port::outb(index_port, reg);
        narf_arch::x86_64::io_port::outb(data_port, val);
    }
}

// ── HWM EC register access ────────────────────────────────────────────
//
// Linux ref: nct6775-platform.c `nct6775_set_bank` (L316),
// `nct6775_reg_read` (L327), `nct6775_reg_write` (L343).
//
// Access uses a two-register ADDR/DATA window at `ec = hwm_base +
// IOREGION_OFFSET`. To read a 16-bit banked register `reg`:
//   1. Select the bank `reg >> 8`: write NCT6775_REG_BANK (0x4E) to
//      ADDR, then the bank byte to DATA.
//   2. Write the low byte `reg & 0xff` to ADDR, read DATA (high/first
//      byte). For word-sized regs, write `(reg & 0xff) + 1` to ADDR and
//      read DATA again; the 16-bit value is `(first << 8) | second`.
//
// Unlike Linux we do not cache the active bank (no persistent device
// state in the read path), so every access re-selects the bank. This is
// always correct, just slightly more port traffic.

/// Compute the EC ADDR port for a HWM base.
#[cfg(target_arch = "x86_64")]
#[inline]
fn ec_addr_port(hwm_base: u16) -> u16 {
    hwm_base + IOREGION_OFFSET + ADDR_REG_OFFSET
}

/// Compute the EC DATA port for a HWM base.
#[cfg(target_arch = "x86_64")]
#[inline]
fn ec_data_port(hwm_base: u16) -> u16 {
    hwm_base + IOREGION_OFFSET + DATA_REG_OFFSET
}

/// Select the register bank `reg >> 8` on the EC window.
/// Linux nct6775-platform.c `nct6775_set_bank` L316.
///
/// # Safety
///
/// `hwm_base` must be a validated, nonzero HWM I/O base and we must be
/// at CPL-0. Caller must serialise EC access (no concurrent bank state).
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn ec_set_bank(hwm_base: u16, reg: u16) {
    let addr = ec_addr_port(hwm_base);
    let data = ec_data_port(hwm_base);
    // SAFETY: CPL-0 port I/O to the driver-owned EC window; ports are
    // derived from a validated nonzero base.
    unsafe {
        narf_arch::x86_64::io_port::outb(addr, NCT6775_REG_BANK);
        narf_arch::x86_64::io_port::outb(data, (reg >> 8) as u8);
    }
}

/// Read a (possibly word-sized) HWM register.
/// Linux nct6775-platform.c `nct6775_reg_read` L327.
///
/// Returns the raw register value: 8 bits for byte-sized registers,
/// 16 bits (big-endian: first byte is the high byte) for word-sized.
///
/// # Safety
///
/// Same requirements as [`ec_set_bank`].
#[cfg(target_arch = "x86_64")]
unsafe fn ec_read16(hwm_base: u16, reg: u16) -> u16 {
    let addr = ec_addr_port(hwm_base);
    let data = ec_data_port(hwm_base);
    // SAFETY: CPL-0 port I/O to the driver-owned EC window.
    unsafe {
        ec_set_bank(hwm_base, reg);
        narf_arch::x86_64::io_port::outb(addr, (reg & 0xff) as u8);
        let mut val = narf_arch::x86_64::io_port::inb(data) as u16;
        if reg_is_word_sized(reg) {
            narf_arch::x86_64::io_port::outb(addr, ((reg & 0xff) + 1) as u8);
            val = (val << 8) | narf_arch::x86_64::io_port::inb(data) as u16;
        }
        val
    }
}

/// Read a single byte-sized HWM register.
/// Linux nct6775-platform.c `nct6775_reg_read` L327 (byte path).
///
/// # Safety
///
/// Same requirements as [`ec_set_bank`]. `reg` must be a byte-sized
/// register (see [`reg_is_word_sized`]).
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn ec_read(hwm_base: u16, reg: u16) -> u8 {
    // SAFETY: delegated to ec_read16; byte-sized reg yields low 8 bits.
    unsafe { ec_read16(hwm_base, reg) as u8 }
}

/// Write a byte-sized HWM register.
/// Linux nct6775-platform.c `nct6775_reg_write` L343 (byte path).
///
/// # Safety
///
/// Same requirements as [`ec_set_bank`]. Only byte-sized registers are
/// written here (PWM duty).
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn ec_write(hwm_base: u16, reg: u16, val: u8) {
    let addr = ec_addr_port(hwm_base);
    let data = ec_data_port(hwm_base);
    // SAFETY: CPL-0 port I/O to the driver-owned EC window.
    unsafe {
        ec_set_bank(hwm_base, reg);
        narf_arch::x86_64::io_port::outb(addr, (reg & 0xff) as u8);
        narf_arch::x86_64::io_port::outb(data, val);
    }
}

/// Read the HWM logical-device I/O base address from the SIO config
/// space. Returns `None` if the base is zero (disabled / invalid).
/// Linux nct6775-platform.c `nct6775_find` L1051-1060.
///
/// Selects LDN 0x0B, reads SIO 0x60 (high) / 0x61 (low), masks with
/// `IOREGION_ALIGNMENT`. Must be called inside an EFM block.
///
/// # Safety
///
/// CPL-0, called within `sio_enter`/`sio_exit`.
#[cfg(target_arch = "x86_64")]
unsafe fn read_hwm_base(index_port: u16, data_port: u16) -> Option<u16> {
    // SAFETY: CPL-0 SIO access within an EFM block.
    let base = unsafe {
        // Select the Hardware Monitor logical device.
        sio_write(index_port, data_port, SIO_LDN_SELECT, LDN_HWM);
        let hi = sio_read(index_port, data_port, SIO_REG_ADDR) as u16;
        let lo = sio_read(index_port, data_port, SIO_REG_ADDR + 1) as u16;
        (hi << 8) | lo
    };
    let base = base & IOREGION_ALIGNMENT;
    if base == 0 {
        None
    } else {
        Some(base)
    }
}

/// Read the chip ID from the Super-I/O at `index_port`.
/// Returns `None` if the chip ID is not a known NCT value.
///
/// Must NOT be called from a hot path — the SIO is port-mapped I/O
/// and the lock-open/lock sequence is required.
#[cfg(target_arch = "x86_64")]
pub fn detect_chip(index_port: u16, data_port: u16) -> Option<(NctChip, u16)> {
    // SAFETY: EFM entry/exit are paired; the SIO is read-only here
    // (chip detect only — we do not write any configuration).
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let chip_id = unsafe {
        sio_enter(index_port);
        let hi = sio_read(index_port, data_port, SIO_CHIP_ID_HIGH);
        let lo = sio_read(index_port, data_port, SIO_CHIP_ID_LOW);
        sio_exit(index_port);
        (hi as u16) << 8 | lo as u16
    };
    let chip = NctChip::from_id(chip_id);
    match chip {
        NctChip::Unknown(_) => None,
        _ => Some((chip, chip_id)),
    }
}

// ── nct6775 device ────────────────────────────────────────────────────

/// Temperature labels for nct6775 family.
pub const TEMP_LABELS: &[&str] = &["temp1", "temp2", "temp3", "temp4", "temp5", "temp6"];
/// Fan labels.
pub const FAN_LABELS: &[&str] = &["fan1", "fan2", "fan3", "fan4", "fan5"];
/// Voltage labels.
pub const VOLT_LABELS: &[&str] = &["in0", "in1", "in2", "in3", "in4", "in5", "in6"];
/// PWM fan control labels.
pub const PWM_LABELS: &[&str] = &["pwm1", "pwm2", "pwm3", "pwm4", "pwm5"];

/// A bound NCT6775-family device.
#[derive(Debug)]
pub struct Nct6775 {
    pub chip: NctChip,
    pub chip_id: u16,
    pub index_port: u16,
    pub data_port: u16,
    /// HWM LDN base I/O address (read from SIO LDN 0x0B offset 0x60/0x61).
    pub hwm_base: u16,
}

impl Nct6775 {
    /// Construct a device with the HWM I/O base unset (`hwm_base = 0`).
    /// Use [`Nct6775::with_hwm_base`] to attach a discovered base; until
    /// then all HWM register reads return `None`.
    pub fn new(chip: NctChip, chip_id: u16, index_port: u16, data_port: u16) -> Self {
        Self {
            chip,
            chip_id,
            index_port,
            data_port,
            hwm_base: 0,
        }
    }

    /// Builder: attach the (already masked, nonzero) HWM logical-device
    /// I/O base read from SIO 0x60/0x61. See `read_hwm_base`.
    pub fn with_hwm_base(mut self, hwm_base: u16) -> Self {
        self.hwm_base = hwm_base;
        self
    }
}

impl crate::HwmonDevice for Nct6775 {
    fn name(&self) -> &str {
        "nct6775"
    }

    fn read_temp(&self, label: &str) -> Option<i32> {
        let idx = TEMP_LABELS.iter().position(|&l| l == label)?;
        if idx >= self.chip.num_temps() as usize || idx >= NCT6775_REG_TEMP.len() {
            return None;
        }
        #[cfg(target_arch = "x86_64")]
        {
            if self.hwm_base == 0 {
                return None;
            }
            let reg = NCT6775_REG_TEMP[idx];
            // SAFETY: hwm_base is a validated nonzero HWM I/O base; EC
            // access is a sequence of CPL-0 port I/Os on the driver's
            // own window. nct6775-platform.c nct6775_reg_read.
            let word = unsafe {
                if reg_is_word_sized(reg) {
                    // Word-sized temp reg: hi:integer °C, lo:fraction.
                    ec_read16(self.hwm_base, reg)
                } else {
                    // Byte-sized: shift integer °C into the high byte,
                    // matching nct6775_read_temp (`*val <<= 8`).
                    (ec_read(self.hwm_base, reg) as u16) << 8
                }
            };
            Some(temp_from_reg_word(word))
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            None
        }
    }

    fn read_fan(&self, label: &str) -> Option<u32> {
        let idx = FAN_LABELS.iter().position(|&l| l == label)?;
        if idx >= self.chip.num_fans() as usize || idx >= NCT6775_REG_FAN.len() {
            return None;
        }
        #[cfg(target_arch = "x86_64")]
        {
            if self.hwm_base == 0 {
                return None;
            }
            // Fan tach regs are word-sized; one read yields the 16-bit
            // count (nct6775-core.c NCT6775_REG_FAN, word-sized per
            // nct6775_reg_is_word_sized `(reg & 0xfff0) == 0x630`).
            // SAFETY: validated nonzero hwm_base; CPL-0 EC window I/O.
            let count = unsafe { ec_read16(self.hwm_base, NCT6775_REG_FAN[idx]) };
            fan_count_to_rpm(count)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            None
        }
    }

    fn read_voltage(&self, label: &str) -> Option<i32> {
        let idx = VOLT_LABELS.iter().position(|&l| l == label)?;
        if idx >= NCT6775_REG_IN.len() {
            return None;
        }
        #[cfg(target_arch = "x86_64")]
        {
            if self.hwm_base == 0 {
                return None;
            }
            // 8-bit ADC reading; 8 mV/LSB for the undivided inputs.
            // nct6775-core.c in_from_reg / scale_in.
            // SAFETY: validated nonzero hwm_base; CPL-0 EC window I/O.
            let raw = unsafe { ec_read(self.hwm_base, NCT6775_REG_IN[idx]) };
            Some(in_from_reg(raw))
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            None
        }
    }

    fn set_fan(&self, label: &str, level: u8) -> bool {
        let idx = match PWM_LABELS.iter().position(|&l| l == label) {
            Some(i) => i,
            None => return false,
        };
        if idx >= self.chip.num_fans() as usize || idx >= NCT6775_REG_PWM.len() {
            return false;
        }
        #[cfg(target_arch = "x86_64")]
        {
            if self.hwm_base == 0 {
                return false;
            }
            // Write the raw PWM duty (0..255) to the fan's PWM register.
            // nct6775-core.c NCT6775_REG_PWM.
            // SAFETY: validated nonzero hwm_base; CPL-0 EC window I/O.
            unsafe { ec_write(self.hwm_base, NCT6775_REG_PWM[idx], level) };
            true
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = level;
            false
        }
    }

    fn list_labels(&self) -> Vec<&str> {
        let mut v: Vec<&str> = Vec::new();
        for &l in TEMP_LABELS.iter().take(self.chip.num_temps() as usize) {
            v.push(l);
        }
        for &l in FAN_LABELS.iter().take(self.chip.num_fans() as usize) {
            v.push(l);
        }
        for &l in VOLT_LABELS {
            v.push(l);
        }
        v
    }
}

// ── ISA driver registration ───────────────────────────────────────────

/// Probe both standard (0x2E) and alternate (0x4E) SIO base addresses.
/// Registers a [`Nct6775`] device if a known chip is found.
pub fn register_isa_driver() {
    #[cfg(target_arch = "x86_64")]
    use core::fmt::Write as _;
    #[cfg(target_arch = "x86_64")]
    {
        let candidates = [(SIO_INDEX_STD, SIO_DATA_STD), (SIO_INDEX_ALT, SIO_DATA_ALT)];
        for (idx, dat) in candidates {
            if let Some((chip, chip_id)) = detect_chip(idx, dat) {
                // Re-enter EFM to read the HWM logical-device I/O base
                // (SIO 0x60/0x61 after selecting LDN 0x0B). See
                // nct6775-platform.c nct6775_find L1051.
                // SAFETY: EFM enter/exit are paired; read_hwm_base only
                // selects the HWM LDN and reads its base registers.
                let hwm_base = unsafe {
                    sio_enter(idx);
                    let b = read_hwm_base(idx, dat);
                    sio_exit(idx);
                    b
                };
                let _ = writeln!(
                    narf_console::Writer,
                    "  nct6775: {} (id=0x{:04X}) at 0x{:02X}, hwm_base=0x{:04X}",
                    chip.name(),
                    chip_id,
                    idx,
                    hwm_base.unwrap_or(0)
                );
                registry::register(registry::RegisteredSensor {
                    name: "nct6775",
                    description: chip.name(),
                    bus_loc: "isa",
                });
                use alloc::sync::Arc;
                registry::register_device(Arc::new(
                    Nct6775::new(chip, chip_id, idx, dat).with_hwm_base(hwm_base.unwrap_or(0)),
                ));
                return;
            }
        }
        let _ = writeln!(narf_console::Writer, "  nct6775: no chip found");
    }
}

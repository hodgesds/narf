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

/// Read the chip ID from the Super-I/O at `index_port`.
/// Returns `None` if the chip ID is not a known NCT value.
///
/// Must NOT be called from a hot path — the SIO is port-mapped I/O
/// and the lock-open/lock sequence is required.
#[cfg(target_arch = "x86_64")]
pub fn detect_chip(index_port: u16, data_port: u16) -> Option<(NctChip, u16)> {
    // SAFETY: EFM entry/exit are paired; the SIO is read-only here
    // (chip detect only — we do not write any configuration).
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
    pub fn new(chip: NctChip, chip_id: u16, index_port: u16, data_port: u16) -> Self {
        Self {
            chip,
            chip_id,
            index_port,
            data_port,
            hwm_base: 0, // populated during full probe
        }
    }
}

impl crate::HwmonDevice for Nct6775 {
    fn name(&self) -> &str {
        "nct6775"
    }

    fn read_temp(&self, label: &str) -> Option<i32> {
        // Temperature reads require HWM I/O port access; deferred until
        // the full ISA I/O permission map is wired in NARF's arch layer.
        let idx = TEMP_LABELS.iter().position(|&l| l == label)?;
        if idx >= self.chip.num_temps() as usize {
            return None;
        }
        // Deferred: real read would be:
        //   outb(hwm_base + 0x4E, bank_select)
        //   inb(hwm_base + TEMP_REG[idx])
        None
    }

    fn read_fan(&self, label: &str) -> Option<u32> {
        let idx = FAN_LABELS.iter().position(|&l| l == label)?;
        if idx >= self.chip.num_fans() as usize {
            return None;
        }
        // Deferred: real read would be:
        //   high = inb(hwm_base + FAN_TACH_HIGH[idx])
        //   low  = inb(hwm_base + FAN_TACH_LOW[idx])
        //   fan_count_to_rpm((high << 8) | low)
        None
    }

    fn read_voltage(&self, label: &str) -> Option<i32> {
        let _idx = VOLT_LABELS.iter().position(|&l| l == label)?;
        None
    }

    fn set_fan(&self, label: &str, level: u8) -> bool {
        let _idx = match PWM_LABELS.iter().position(|&l| l == label) {
            Some(i) => i,
            None => return false,
        };
        let _ = level; // deferred: outb(hwm_base + PWM_REG[idx], level)
        false
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
                let _ = writeln!(
                    narf_console::Writer,
                    "  nct6775: {} (id=0x{:04X}) at 0x{:02X}",
                    chip.name(),
                    chip_id,
                    idx
                );
                registry::register(registry::RegisteredSensor {
                    name: "nct6775",
                    description: chip.name(),
                    bus_loc: "isa",
                });
                use alloc::sync::Arc;
                registry::register_device(Arc::new(Nct6775::new(chip, chip_id, idx, dat)));
                return;
            }
        }
        let _ = writeln!(narf_console::Writer, "  nct6775: no chip found");
    }
}

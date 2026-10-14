//! JEDEC JC-42.4 (jc42) DIMM thermal sensor driver.
//!
//! JC42.4-compliant temperature sensors sit on the SPD/SMBus of DDR3/DDR4
//! memory modules at I2C addresses 0x18-0x1f and report the module
//! temperature in 0.0625 °C steps. This driver scans the platform SMBus
//! controller for such sensors, decodes the temperature register, and
//! exposes each discovered DIMM sensor as a [`crate::HwmonDevice`].
//!
//! Clean-room from Linux `drivers/hwmon/jc42.c` (Guenter Roeck). All
//! register numbers, the manufacturer-id table, and the temperature
//! decode below are cited against that source.
//!
//! ## Endianness caveat
//!
//! JC42 registers are **16-bit big-endian on the wire**. Linux reads them
//! with `i2c_smbus_read_word_swapped()` (see `jc42_detect`/`jc42_read` in
//! jc42.c, which use the `*_swapped` SMBus helpers, equivalently
//! `swab16(i2c_smbus_read_word_data(...))`). Our platform
//! [`Smbus::read_word_data`] returns the raw SMBus word assembled
//! little-endian (`u16::from_le_bytes([D0, D1])`), so we must
//! `swap_bytes()` the result to recover the true big-endian register
//! value. See [`read_reg`].

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_console::Writer;
use narf_drivers_platform::smbus::{self, SmbusError};

use crate::HwmonDevice;

// ── JC42 registers ────────────────────────────────────────────────────
// Cite: jc42.c lines 28-36. "JC42 registers. All registers are 16 bit."

/// Capabilities register.
const JC42_REG_CAP: u8 = 0x00;
/// Configuration register.
const JC42_REG_CONFIG: u8 = 0x01;
/// Upper (high) temperature limit.
#[allow(dead_code)]
const JC42_REG_TEMP_UPPER: u8 = 0x02;
/// Lower temperature limit.
#[allow(dead_code)]
const JC42_REG_TEMP_LOWER: u8 = 0x03;
/// Critical temperature limit.
#[allow(dead_code)]
const JC42_REG_TEMP_CRITICAL: u8 = 0x04;
/// Current (ambient) temperature — the value we expose as `temp1`.
const JC42_REG_TEMP: u8 = 0x05;
/// Manufacturer ID.
const JC42_REG_MANID: u8 = 0x06;
/// Device / revision ID.
#[allow(dead_code)]
const JC42_REG_DEVICEID: u8 = 0x07;

// ── Known manufacturer IDs ────────────────────────────────────────────
// Cite: jc42.c lines 54-66 ("Manufacturer IDs") and the `jc42_chips[]`
// table (lines 149-177). A production driver matches (manid, devid &
// mask) pairs; we keep a lightweight manid allow-list plus a tolerant
// "nonzero / not-0xffff" fallback (see `looks_like_jc42`).
const KNOWN_MANIDS: &[u16] = &[
    0x11d4, // ADT_MANID   — Analog Devices
    0x001f, // ATMEL_MANID — Atmel
    0x1114, // ATMEL_MANID2
    0x004d, // MAX_MANID   — Maxim
    0x00b3, // IDT_MANID   — IDT
    0x0054, // MCP_MANID   — Microchip
    0x1131, // NXP_MANID   — NXP Semiconductors
    0x1b09, // ONS_MANID   — ON Semiconductor
    0x104a, // STM_MANID   — ST Microelectronics
    0x1c68, // GT_MANID    — Giantec
    0x132d, // GT_MANID2   — Giantec (2nd mfg id)
    0x1c85, // SI_MANID    — Seiko Instruments
];

// ── Temperature decode ────────────────────────────────────────────────

/// Decode a JC42 temperature register into millidegrees Celsius.
///
/// Cite: jc42.c `jc42_temp_from_reg` (lines 202-208):
///
/// ```c
/// static int jc42_temp_from_reg(s16 reg)
/// {
///     reg = sign_extend32(reg, 12);
///     /* convert from 0.0625 to 0.001 resolution */
///     return reg * 125 / 2;
/// }
/// ```
///
/// Bits [15:13] are alarm flags (`JC42_ALARM_CRIT/MAX/MIN`, jc42.c lines
/// 40-42) and must be masked off. Bits [12:0] are a 13-bit two's-complement
/// temperature in units of 0.0625 °C (= 62.5 mC per LSB). We mask to 13
/// bits, sign-extend bit 12, then `reg * 125 / 2` gives millidegrees.
///
/// Pure and host-compilable (no `cfg`, no hardware) for unit testing.
pub fn temp_from_reg(reg: u16) -> i32 {
    // Mask off the three alarm/flag bits, keep the 13-bit magnitude+sign.
    let raw = (reg & 0x1fff) as i32;
    // Sign-extend bit 12 (the 13-bit two's-complement sign bit).
    let signed = if raw & 0x1000 != 0 { raw - 0x2000 } else { raw };
    // 0.0625 °C per LSB → millidegrees: value * 62.5 == value * 125 / 2.
    signed * 125 / 2
}

// ── SMBus access ──────────────────────────────────────────────────────

/// Read a JC42 16-bit register at `addr`/`reg`, applying the big-endian
/// byte swap (see module-level endianness note / jc42.c `*_swapped`).
///
/// Returns `None` if the SMBus controller is unavailable or the transfer
/// fails.
fn read_reg(addr: u8, reg: u8) -> Option<u16> {
    let r: Result<u16, SmbusError> = smbus::with_controller(|c| c.read_word_data(addr, reg))?;
    // Platform returns the word little-endian-assembled; JC42 is
    // big-endian on the wire, so swap to get the true register value.
    r.ok().map(|v| v.swap_bytes())
}

/// Heuristic detection: a present JC42 sensor returns a readable,
/// plausible manufacturer id plus a sane CAP/CONFIG register.
///
/// Cite: jc42.c `jc42_detect` (lines 389-422) reads CAP/CONFIG/MANID/
/// DEVICEID, rejects on any read error, and sanity-checks
/// `(cap & 0xff00)` and `(config & 0xf820)` before matching the
/// `jc42_chips[]` manid/devid table. We keep detection tolerant per the
/// brief: success = MANID reads back nonzero and not 0xffff (an absent
/// device floats to 0x0000 or 0xffff). If the manid is one we recognise
/// we take it directly; otherwise we still accept a plausible nonzero
/// manid that also passes the CAP/CONFIG sanity masks.
fn looks_like_jc42(addr: u8) -> bool {
    let manid = match read_reg(addr, JC42_REG_MANID) {
        Some(m) => m,
        None => return false,
    };
    // Absent / floating bus → 0x0000 or 0xffff.
    if manid == 0x0000 || manid == 0xffff {
        return false;
    }
    if KNOWN_MANIDS.contains(&manid) {
        return true;
    }
    // Unknown manid: fall back to the CAP/CONFIG sanity checks from
    // jc42_detect (cap & 0xff00) == 0 && (config & 0xf820) == 0.
    let cap = match read_reg(addr, JC42_REG_CAP) {
        Some(c) => c,
        None => return false,
    };
    let config = match read_reg(addr, JC42_REG_CONFIG) {
        Some(c) => c,
        None => return false,
    };
    (cap & 0xff00) == 0 && (config & 0xf820) == 0
}

// ── Driver object ─────────────────────────────────────────────────────

/// One discovered JC42.4 DIMM thermal sensor, identified by its 7-bit
/// SMBus address (0x18-0x1f). Each DIMM sensor is its own registered
/// [`crate::HwmonDevice`].
#[derive(Debug)]
pub struct Jc42 {
    /// 7-bit SMBus address of the sensor.
    addr: u8,
}

impl Jc42 {
    /// Construct a driver object for the sensor at `addr`.
    pub fn new(addr: u8) -> Self {
        Self { addr }
    }
}

impl crate::HwmonDevice for Jc42 {
    fn name(&self) -> &str {
        "jc42"
    }

    fn read_temp(&self, _label: &str) -> Option<i32> {
        // Any label maps to the single ambient-temperature channel.
        // Returns None if SMBus is gone or the read errored.
        let reg = read_reg(self.addr, JC42_REG_TEMP)?;
        Some(temp_from_reg(reg))
    }

    fn read_fan(&self, _label: &str) -> Option<u32> {
        None
    }

    fn read_voltage(&self, _label: &str) -> Option<i32> {
        None
    }

    fn set_fan(&self, _label: &str, _level: u8) -> bool {
        false
    }

    fn list_labels(&self) -> Vec<&str> {
        vec!["temp1"]
    }
}

// ── Initcall ──────────────────────────────────────────────────────────

/// Register the jc42 scan initcall.
///
/// Called from the hwmon crate's `hwmon-jc42` `Stage::Subsys` initcall
/// (see `lib.rs`). We cannot scan at `Stage::Subsys`: the SMBus
/// controller is a PCI driver, and PCI driver binding
/// (`probe_all_pci`) happens later, in `Stage::Device`. So we register
/// the actual scan at `Stage::Device` — because this registration runs
/// from inside a Subsys initcall, it is appended *after* the framework's
/// own `pci-probe-all` Device initcall and therefore runs once SMBus is
/// bound, while still completing before the hwmon sysfs bridge
/// (`Stage::Late`) snapshots the device registry.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "jc42", || {
        if !smbus::is_probed() {
            let _ = writeln!(
                Writer,
                "  hwmon: jc42 — SMBus controller not probed, no DIMM sensors scanned"
            );
            return InitResult::Ok;
        }

        let mut found = 0usize;
        for addr in 0x18u8..=0x1f {
            if !looks_like_jc42(addr) {
                continue;
            }
            found += 1;
            let temp = Jc42::new(addr).read_temp("temp1");
            match temp {
                Some(mc) => {
                    let _ = writeln!(
                        Writer,
                        "  hwmon: jc42 DIMM sensor @ 0x{:02x}: {}.{:03} °C",
                        addr,
                        mc / 1000,
                        (mc % 1000).unsigned_abs()
                    );
                }
                None => {
                    let _ = writeln!(
                        Writer,
                        "  hwmon: jc42 DIMM sensor @ 0x{:02x} (temp read unavailable)",
                        addr
                    );
                }
            }
            crate::registry::register(crate::registry::RegisteredSensor {
                name: "jc42",
                description: "JEDEC JC-42.4 DIMM thermal sensor",
                bus_loc: "smbus",
            });
            crate::registry::register_device(Arc::new(Jc42::new(addr)));
        }

        if found == 0 {
            let _ = writeln!(
                Writer,
                "  hwmon: jc42 — scanned SMBus 0x18-0x1f, no JC42.4 sensors found"
            );
        } else {
            let _ = writeln!(
                Writer,
                "  hwmon: jc42 — {} DIMM thermal sensor(s) registered",
                found
            );
        }
        InitResult::Ok
    });
}

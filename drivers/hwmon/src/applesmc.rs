//! Apple SMC (System Management Controller) driver.
//!
//! Provides read access to Apple SMC temperature sensors and fan
//! tachometers via a pair of ISA I/O ports discovered through the
//! ACPI device `APP0001`.
//!
//! Clean-room implementation derived from `linux/drivers/hwmon/applesmc.c`
//! (Nicolas Boichat, Henrik Rydberg — GPL-2.0). Only the register
//! offsets, status-bit layout, and the command/key/length handshake
//! sequence are taken from the reference; all code here is original.
//!
//! ## Hardware access
//!
//! The SMC exposes two 8-bit ISA ports relative to a base discovered
//! from the ACPI `_CRS`:
//!
//! - DATA port    = base + 0  (`APPLESMC_DATA_PORT`, default 0x300)
//! - COMMAND/STATUS port = base + 4  (`APPLESMC_CMD_PORT`, default 0x304)
//!
//! A read transaction (`read_smc`) sends the READ command byte (0x10) to
//! the CMD port, then the 4 key bytes followed by the data-length byte to
//! the DATA port, and finally reads `len` data bytes back from the DATA
//! port — with each step gated by polling the status byte (read from the
//! CMD port) for the expected status bits. See applesmc.c `send_byte`,
//! `send_command`, `smc_sane`, and `read_smc`.
//!
//! ## No-std / no-sleep note
//!
//! applesmc.c `wait_status` uses `usleep_range`/`udelay` with an
//! exponential back-off for a ~262ms budget. NARF's probe path has no
//! sleep primitive here, so `wait_status` below is a bounded busy-spin
//! (`WAIT_SPIN` iterations of `inb`). This is the no_std-friendly
//! equivalent: it polls the same status mask and fails closed (returns
//! `Err`) if the SMC does not reach the expected state in time.
//!
//! ## Encodings
//!
//! - Temperature keys ("TC0P", "TCPU", …) return an `sp78` value: a
//!   signed 8.8 fixed-point number (2 bytes, big-endian). See
//!   [`sp78_to_mc`]. applesmc.c newer models also use a `flt ` (float)
//!   encoding; that path is NOT implemented here — the sp78 path covers
//!   the common Intel-Mac sensors and is sufficient for the first cut.
//! - Fan keys ("F0Ac", …) return an `fpe2` value: a 14.2 fixed-point
//!   number (2 bytes, big-endian). See [`fpe2_to_rpm`].
//!
//! ## Simplifications vs applesmc.c
//!
//! applesmc.c walks the full key table (via `#KEY` count + the
//! `GET_KEY_BY_INDEX`/`GET_KEY_TYPE` commands) to enumerate every
//! sensor and its type dynamically. This driver instead probes a small
//! fixed set of common labels (see [`TEMP_LABELS`] / [`FAN_LABELS`]) and
//! returns `None` for any key whose read fails, which is enough to
//! surface CPU temperature and the main fan on typical Intel Macs.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Write as _;
use narf_console::Writer;

// ── ACPI identity ─────────────────────────────────────────────────────

/// ACPI hardware ID for the Apple SMC (applesmc.c matches "APP0001").
const APPLESMC_ACPI_HID: &str = "APP0001";

// ── Port offsets (from applesmc.c) ────────────────────────────────────

/// DATA port offset relative to the discovered base.
/// applesmc.c `APPLESMC_DATA_PORT` = 0x300 (base + 0).
#[cfg(target_arch = "x86_64")]
const APPLESMC_DATA_OFFSET: u16 = 0x00;
/// COMMAND/STATUS port offset relative to the discovered base.
/// applesmc.c `APPLESMC_CMD_PORT` = 0x304 (base + 4).
#[cfg(target_arch = "x86_64")]
const APPLESMC_CMD_OFFSET: u16 = 0x04;

/// Default I/O base used when ACPI `_CRS` yields no usable IO resource.
/// Matches applesmc.c `APPLESMC_DATA_PORT` (0x300).
const APPLESMC_DEFAULT_BASE: u16 = 0x300;

// ── Status bits (from applesmc.c "Apple SMC status bits") ──────────────

/// SMC has data waiting to be read (applesmc.c `SMC_STATUS_AWAITING_DATA`, BIT(0)).
#[cfg(target_arch = "x86_64")]
const SMC_STATUS_AWAITING_DATA: u8 = 1 << 0;
/// SMC will ignore any input (applesmc.c `SMC_STATUS_IB_CLOSED`, BIT(1)).
#[cfg(target_arch = "x86_64")]
const SMC_STATUS_IB_CLOSED: u8 = 1 << 1;
/// Command in progress (applesmc.c `SMC_STATUS_BUSY`, BIT(2)).
#[cfg(target_arch = "x86_64")]
const SMC_STATUS_BUSY: u8 = 1 << 2;

// ── Commands (from applesmc.c) ─────────────────────────────────────────

/// Read-key command byte (applesmc.c `APPLESMC_READ_CMD`).
#[cfg(target_arch = "x86_64")]
const APPLESMC_READ_CMD: u8 = 0x10;

/// Bounded busy-poll budget for `wait_status`. applesmc.c uses a timed
/// back-off (~262ms); this is the no_std equivalent (see module docs).
#[cfg(target_arch = "x86_64")]
const WAIT_SPIN: u32 = 0x10000;

// ── Pure decode helpers (host-compilable; unit-tested) ─────────────────

/// Decode an Apple SMC `sp78` temperature value into millidegrees Celsius.
///
/// `sp78` is a signed 8.8 fixed-point number: `hi` is the signed integer
/// part, `lo` is the fractional part in units of 1/256 °C. The value in
/// degrees is `(i8)hi + lo/256`, so in millidegrees:
/// `hi*1000 + lo*1000/256`.
///
/// This matches applesmc.c `applesmc_show_temperature`, which computes
/// `250 * (value >> 6)` where `value = (s16)hi<<8 | lo`; both expressions
/// equal `value * 1000 / 256`.
///
/// Not `cfg`-gated: pure arithmetic, usable on the host for tests.
#[inline]
pub fn sp78_to_mc(hi: u8, lo: u8) -> i32 {
    (hi as i8 as i32) * 1000 + (lo as i32) * 1000 / 256
}

/// Decode an Apple SMC `fpe2` fan value into RPM.
///
/// `fpe2` is a 14.2 unsigned fixed-point number (2 bytes, big-endian):
/// `rpm = (hi<<8 | lo) >> 2`. Matches applesmc.c `applesmc_show_fan_speed`.
///
/// Not `cfg`-gated: pure arithmetic, usable on the host for tests.
#[inline]
pub fn fpe2_to_rpm(hi: u8, lo: u8) -> u32 {
    (((hi as u32) << 8) | (lo as u32)) >> 2
}

// ── Fixed label set (simplification vs applesmc.c key-table walk) ──────

/// Temperature labels probed. These are their own 4-char SMC keys.
const TEMP_LABELS: &[&str] = &["TC0P", "TCPU", "TG0P"];

/// Fan labels and the SMC key each maps to. applesmc.c's key is "F%dAc"
/// (actual speed); "fan1" is the hwmon-style label exposed to consumers.
const FAN_LABELS: &[(&str, &[u8; 4])] = &[("fan1", b"F0Ac")];

/// Map a temperature label to its 4-char SMC key.
fn temp_key_for(label: &str) -> Option<[u8; 4]> {
    for &l in TEMP_LABELS {
        if l == label && l.len() == 4 {
            let b = l.as_bytes();
            return Some([b[0], b[1], b[2], b[3]]);
        }
    }
    None
}

/// Map a fan label to its 4-char SMC key.
fn fan_key_for(label: &str) -> Option<[u8; 4]> {
    FAN_LABELS
        .iter()
        .find(|(l, _)| *l == label)
        .map(|(_, k)| **k)
}

// ── SMC handshake (x86_64 I/O ports only) ──────────────────────────────

/// Poll the status port until `(status & mask) == val`, or fail after a
/// bounded number of iterations. Mirrors applesmc.c `wait_status`, but
/// uses a busy-spin instead of `usleep_range` (see module docs).
#[cfg(target_arch = "x86_64")]
unsafe fn wait_status(cmd_port: u16, val: u8, mask: u8) -> Result<(), ()> {
    for _ in 0..WAIT_SPIN {
        // SAFETY: `cmd_port` is the SMC COMMAND/STATUS port derived from
        // the ACPI-reported (or default) base; reading it is a side-effect-
        // free status probe, as in applesmc.c `wait_status`.
        let status = unsafe { narf_arch::x86_64::io_port::inb(cmd_port) };
        if status & mask == val {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(())
}

/// Write one byte to the DATA port, gated by the SMC input handshake.
///
/// applesmc.c `send_byte`: wait for `IB_CLOSED` to fall (input buffer
/// open), then wait for `BUSY` to assert, then write. The two waits are
/// deliberately separate reads (see the comment in applesmc.c).
#[cfg(target_arch = "x86_64")]
unsafe fn send_byte(cmd_port: u16, data_port: u16, value: u8) -> Result<(), ()> {
    // Wait for the input buffer to be open (IB_CLOSED clear).
    // SAFETY: cmd_port is the SMC status port; wait_status only reads it.
    unsafe { wait_status(cmd_port, 0, SMC_STATUS_IB_CLOSED)? };
    // Then wait for BUSY to assert before writing (separate read, per
    // applesmc.c — consolidating with the wait above can miss the edge).
    // SAFETY: as above.
    unsafe { wait_status(cmd_port, SMC_STATUS_BUSY, SMC_STATUS_BUSY)? };
    // SAFETY: data_port is the SMC DATA port derived from the discovered
    // base; writing the handshaked byte is the documented protocol step.
    unsafe { narf_arch::x86_64::io_port::outb(data_port, value) };
    Ok(())
}

/// Write a command byte to the COMMAND port, gated by the input handshake.
/// applesmc.c `send_command`.
#[cfg(target_arch = "x86_64")]
unsafe fn send_command(cmd_port: u16, cmd: u8) -> Result<(), ()> {
    // SAFETY: cmd_port is the SMC status port; wait_status only reads it.
    unsafe { wait_status(cmd_port, 0, SMC_STATUS_IB_CLOSED)? };
    // SAFETY: cmd_port is the SMC COMMAND port; writing the command byte
    // once the input buffer is open is the documented protocol step.
    unsafe { narf_arch::x86_64::io_port::outb(cmd_port, cmd) };
    Ok(())
}

/// Reset/settle the SMC state machine before a transaction.
/// applesmc.c `smc_sane`: if BUSY is stuck, issue a READ command to kick
/// the state machine, then wait for BUSY to clear.
#[cfg(target_arch = "x86_64")]
unsafe fn smc_sane(cmd_port: u16) -> Result<(), ()> {
    // SAFETY: cmd_port is the SMC status port; wait_status only reads it.
    if unsafe { wait_status(cmd_port, 0, SMC_STATUS_BUSY) }.is_ok() {
        return Ok(());
    }
    // SAFETY: issuing a READ command to unstick a jammed state machine,
    // per applesmc.c smc_sane.
    unsafe { send_command(cmd_port, APPLESMC_READ_CMD)? };
    // SAFETY: as above.
    unsafe { wait_status(cmd_port, 0, SMC_STATUS_BUSY) }
}

/// Read an SMC key into `buf`. `buf.len()` is the requested data length
/// (bounded to 0..=32 by the caller). Mirrors applesmc.c `read_smc`.
#[cfg(target_arch = "x86_64")]
unsafe fn read_smc(base: u16, key: &[u8; 4], buf: &mut [u8]) -> Result<(), ()> {
    let cmd_port = base + APPLESMC_CMD_OFFSET;
    let data_port = base + APPLESMC_DATA_OFFSET;
    let len = buf.len();
    if len == 0 || len > 32 {
        return Err(());
    }

    // Settle the state machine, then send READ + key + length.
    // SAFETY: cmd_port/data_port are the SMC ports derived from `base`.
    unsafe {
        smc_sane(cmd_port)?;
        send_command(cmd_port, APPLESMC_READ_CMD)?;
        for &k in key.iter() {
            send_byte(cmd_port, data_port, k)?;
        }
        // Length byte (no effect on 2012+ SMCs, but required by older ones).
        send_byte(cmd_port, data_port, len as u8)?;
    }

    // Read `len` data bytes, each gated on AWAITING_DATA|BUSY both set.
    for byte in buf.iter_mut().take(len) {
        // SAFETY: cmd_port is the status port; wait_status only reads it.
        unsafe {
            wait_status(
                cmd_port,
                SMC_STATUS_AWAITING_DATA | SMC_STATUS_BUSY,
                SMC_STATUS_AWAITING_DATA | SMC_STATUS_BUSY,
            )?
        };
        // SAFETY: data_port is the SMC DATA port; reading it once the
        // SMC reports AWAITING_DATA returns the next data byte.
        *byte = unsafe { narf_arch::x86_64::io_port::inb(data_port) };
    }

    // Wait for BUSY to clear, marking the transaction complete.
    // SAFETY: cmd_port is the status port; wait_status only reads it.
    unsafe { wait_status(cmd_port, 0, SMC_STATUS_BUSY) }
}

/// Read a 2-byte key and return the (hi, lo) bytes, or `None` on failure.
#[cfg(target_arch = "x86_64")]
fn read_key_u16(base: u16, key: &[u8; 4]) -> Option<(u8, u8)> {
    let mut buf = [0u8; 2];
    // SAFETY: `base` is a validated SMC I/O base; read_smc performs the
    // documented handshake and only touches the two SMC ports.
    unsafe { read_smc(base, key, &mut buf) }.ok()?;
    Some((buf[0], buf[1]))
}

// ── Port-base discovery via ACPI _CRS ──────────────────────────────────

/// Extract an I/O base from a `_CRS` resource list: the first `Io` or
/// `FixedIo` descriptor's base address. Returns `None` if none present.
fn io_base_from_crs(items: &[narf_aml::resource::ResourceItem]) -> Option<u16> {
    use narf_aml::resource::ResourceItem;
    for item in items {
        match item {
            ResourceItem::Io { min, .. } => return Some(*min),
            ResourceItem::FixedIo { base, .. } => return Some(*base),
            _ => {}
        }
    }
    None
}

/// Discover the SMC I/O base for an ACPI device path. Evaluates `_CRS`
/// and takes the first IO/FixedIo base; falls back to the Linux default
/// (0x300) if `_CRS` evaluation yields nothing usable.
fn discover_base(device_path: &str) -> u16 {
    match narf_aml::prt_crs::evaluate_crs_for(device_path) {
        Ok(items) => io_base_from_crs(&items).unwrap_or(APPLESMC_DEFAULT_BASE),
        Err(_) => APPLESMC_DEFAULT_BASE,
    }
}

// ── Device object ──────────────────────────────────────────────────────

/// Apple SMC hwmon device. Holds the discovered I/O port base.
#[derive(Debug)]
pub struct AppleSmc {
    /// DATA port base (DATA = base+0, CMD/STATUS = base+4).
    base: u16,
}

impl AppleSmc {
    /// Construct a driver instance bound to a discovered I/O base.
    pub fn new(base: u16) -> Self {
        Self { base }
    }

    /// The discovered I/O port base.
    pub fn base(&self) -> u16 {
        self.base
    }
}

impl crate::HwmonDevice for AppleSmc {
    fn name(&self) -> &str {
        "applesmc"
    }

    fn read_temp(&self, label: &str) -> Option<i32> {
        let key = temp_key_for(label)?;
        #[cfg(target_arch = "x86_64")]
        {
            let (hi, lo) = read_key_u16(self.base, &key)?;
            Some(sp78_to_mc(hi, lo))
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = key;
            None
        }
    }

    fn read_fan(&self, label: &str) -> Option<u32> {
        let key = fan_key_for(label)?;
        #[cfg(target_arch = "x86_64")]
        {
            let (hi, lo) = read_key_u16(self.base, &key)?;
            Some(fpe2_to_rpm(hi, lo))
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = key;
            None
        }
    }

    fn read_voltage(&self, _label: &str) -> Option<i32> {
        None // Not exposed by this first-cut driver.
    }

    fn set_fan(&self, _label: &str, _level: u8) -> bool {
        false // Fan control (write_smc / FS!) not implemented.
    }

    fn list_labels(&self) -> Vec<&str> {
        let mut v: Vec<&str> = Vec::with_capacity(TEMP_LABELS.len() + FAN_LABELS.len());
        v.extend_from_slice(TEMP_LABELS);
        for (l, _) in FAN_LABELS {
            v.push(l);
        }
        v
    }
}

// ── Driver registration ────────────────────────────────────────────────

/// Probe for the Apple SMC via ACPI and register it with the hwmon
/// registry. Public entry called from the hwmon Stage::Subsys initcalls.
pub fn register_smc_driver() {
    let devs = narf_aml::find_all_devices_by_hid(APPLESMC_ACPI_HID);
    let Some(node) = devs.into_iter().next() else {
        return;
    };

    let base = discover_base(&node.path);

    let _ = writeln!(
        Writer,
        "  applesmc: Found Apple SMC (APP0001) at {} — I/O base 0x{:03x}",
        node.path, base
    );

    crate::registry::register(crate::registry::RegisteredSensor {
        name: "applesmc",
        description: "Apple System Management Controller",
        bus_loc: "acpi:APP0001",
    });
    crate::registry::register_device(alloc::sync::Arc::new(AppleSmc::new(base)));
}

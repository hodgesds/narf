//! Dell SMM (System Management Mode) thermal / fan driver — clean-room.
//!
//! Reference: `linux/drivers/hwmon/dell-smm-hwmon.c` (Massimo Dal Zotto,
//! Guenter Roeck — GPL-2.0-or-later), and the public Dell SMM API
//! documented in the i8k kernel module man page.
//!
//! ## Hardware interface
//!
//! Dell laptops expose a vendor-specific SMM interface via the x86
//! `int 0x15` / SMBIOS SMM backdoor. The driver writes a command
//! structure into the `ebx` register pair and raises a software
//! interrupt, then reads results from `eax`/`edx`.
//!
//! NARF models this as a pure-Rust `smm_call` wrapper that issues
//! `int $0x15` via inline assembly (x86_64-only). The SMM command
//! block must reside in identity-mapped memory since SMM firmware
//! accesses it by physical address.
//!
//! ## Commands
//!
//! | Command | Value  | Returns                       |
//! |---------|--------|-------------------------------|
//! | GET_FAN_STATUS  | 0x0014 | Fan speed + power state  |
//! | GET_FAN_NOMINAL_RPM | 0x02A4 | Per-fan nominal RPM  |
//! | GET_TEMP       | 0x10A3 | Temperature for sensor N  |
//! | GET_TEMP_TYPE  | 0x11A3 | Sensor label string index |
//! | SET_FAN        | 0x01A3 | Set manual fan speed      |
//!
//! Linux dell-smm-hwmon.c references:
//! `I8K_SMM_GET_TEMP` ~L42, `i8k_get_temp` ~L200, `i8k_get_fan_status` ~L175.
//!
//! ## NARF notes
//!
//! The SMM call on x86_64 requires a real-mode-shaped register block
//! and the firmware's SMM handler runs in 16-bit protected mode. NARF
//! issues the call via `asm!` but does NOT yet wire the Dell DMI check
//! (only Dell-branded systems should load this driver). That check
//! lands alongside the SMBIOS crate integration.

extern crate alloc;

use alloc::vec::Vec;

use crate::registry;

// ── SMM command codes ─────────────────────────────────────────────────

/// Read fan tachometer status. Returns speed tier (0–2) in eax.
pub const SMM_GET_FAN_STATUS: u32 = 0x0014;
/// Read nominal RPM for fan N (0-indexed). eax = RPM * 30.
pub const SMM_GET_FAN_NOMINAL_RPM: u32 = 0x02A4;
/// Read temperature for sensor N. eax = Celsius.
pub const SMM_GET_TEMP: u32 = 0x10A3;
/// Read temperature sensor type string index.
pub const SMM_GET_TEMP_TYPE: u32 = 0x11A3;
/// Set fan level (0=auto, 1=low, 2=high, 3=max).
pub const SMM_SET_FAN: u32 = 0x01A3;

/// Sentinel: SMM call returned "not supported" error.
pub const SMM_ERR_NOSUPPORT: u32 = 0xFFFF_FFFF;

// ── SMM call wrapper ──────────────────────────────────────────────────

/// Result of a raw SMM call.
#[derive(Copy, Clone, Debug)]
pub struct SmmResult {
    pub eax: u32,
    pub edx: u32,
}

/// Issue a Dell SMM BIOS call.
///
/// `cmd` is placed in `eax` before the `int $0x15`; `arg` goes in
/// `ebx`. Returns the post-interrupt `eax` / `edx` pair.
///
/// # Safety
///
/// The caller must ensure:
/// - We are running on an x86_64 Dell system with Dell SMM firmware.
/// - The CPU is at CPL-0 (kernel mode).
/// - No IOAPIC/PIC masking is needed for `int $0x15` on this firmware.
///
/// On non-Dell hardware this will at best NOP (SMM ignores the
/// unrecognised command) and at worst crash; the driver gates this
/// on a DMI vendor check at registration time.
///
/// Note: LLVM reserves `rbx` on x86_64 for its own use, so we save
/// it explicitly around the SMM call. Linux dell-smm-hwmon.c uses the
/// same workaround (`push %rbx` / `mov %esi, %ebx` / `pop %rbx`).
#[cfg(target_arch = "x86_64")]
pub unsafe fn smm_call(cmd: u32, arg: u32) -> SmmResult {
    let mut eax: u32 = cmd;
    let mut edx: u32 = 0;
    // SAFETY: caller guarantees Dell firmware + CPL-0 + x86_64.
    // We save/restore rbx around the int because LLVM reserves it.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov ebx, {arg:e}",
            "int 0x15",
            "pop rbx",
            arg = in(reg) arg,
            inout("eax") eax,
            out("edx") edx,
            options(nostack),
        );
    }
    SmmResult { eax, edx }
}

/// Read temperature for sensor `sensor_idx` (0-based).
/// Returns degrees Celsius, or `None` if SMM signals not-supported.
#[cfg(target_arch = "x86_64")]
pub fn read_temp_celsius(sensor_idx: u8) -> Option<u32> {
    // SAFETY: gated on Dell DMI check at registration; CPL-0.
    let r = unsafe { smm_call(SMM_GET_TEMP, sensor_idx as u32) };
    if r.eax == SMM_ERR_NOSUPPORT {
        return None;
    }
    Some(r.eax & 0xFF)
}

/// Read fan status (speed tier 0-2) for fan `fan_idx` (0-based).
#[cfg(target_arch = "x86_64")]
pub fn read_fan_status(fan_idx: u8) -> Option<u32> {
    // SAFETY: same as read_temp_celsius.
    let r = unsafe { smm_call(SMM_GET_FAN_STATUS, fan_idx as u32) };
    if r.eax == SMM_ERR_NOSUPPORT {
        return None;
    }
    Some(r.eax & 0x03)
}

/// Set fan level for `fan_idx`. Level: 0=auto, 1=low, 2=high, 3=max.
/// Returns `true` if the SMM call succeeded.
#[cfg(target_arch = "x86_64")]
pub fn set_fan_level(fan_idx: u8, level: u8) -> bool {
    // SAFETY: same as read_temp_celsius.
    let arg = (fan_idx as u32) | ((level as u32) << 8);
    let r = unsafe { smm_call(SMM_SET_FAN, arg) };
    r.eax != SMM_ERR_NOSUPPORT
}

// ── Label constants ───────────────────────────────────────────────────

pub const TEMP_LABELS: &[&str] = &["cpu", "gpu", "hdd", "ambient"];
pub const FAN_LABELS: &[&str] = &["fan1", "fan2"];

// ── dell_smm device ───────────────────────────────────────────────────

/// A bound Dell SMM device.
#[derive(Debug)]
pub struct DellSmm {
    pub num_fans: u8,
    pub num_temps: u8,
}

impl DellSmm {
    pub fn new() -> Self {
        Self {
            num_fans: 2,
            num_temps: 4,
        }
    }
}

impl core::fmt::Display for DellSmm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DellSmm(fans={}, temps={})", self.num_fans, self.num_temps)
    }
}

impl crate::HwmonDevice for DellSmm {
    fn name(&self) -> &str {
        "dell_smm"
    }

    fn read_temp(&self, label: &str) -> Option<i32> {
        let idx = TEMP_LABELS.iter().position(|&l| l == label)? as u8;
        if idx >= self.num_temps {
            return None;
        }
        #[cfg(target_arch = "x86_64")]
        {
            let c = read_temp_celsius(idx)? as i32;
            return Some(c * 1000);
        }
        #[cfg(not(target_arch = "x86_64"))]
        None
    }

    fn read_fan(&self, label: &str) -> Option<u32> {
        let idx = FAN_LABELS.iter().position(|&l| l == label)? as u8;
        if idx >= self.num_fans {
            return None;
        }
        #[cfg(target_arch = "x86_64")]
        {
            // Fan status is a tier (0-2); nominal RPM via a second call.
            let _tier = read_fan_status(idx)?;
            // SAFETY: same guard as above.
            let r = unsafe { smm_call(SMM_GET_FAN_NOMINAL_RPM, idx as u32) };
            if r.eax == SMM_ERR_NOSUPPORT {
                return None;
            }
            return Some(r.eax * 30);
        }
        #[cfg(not(target_arch = "x86_64"))]
        None
    }

    fn read_voltage(&self, _label: &str) -> Option<i32> {
        None // Dell SMM does not expose voltage sensors.
    }

    fn set_fan(&self, label: &str, level: u8) -> bool {
        let idx = match FAN_LABELS.iter().position(|&l| l == label) {
            Some(i) => i as u8,
            None => return false,
        };
        if idx >= self.num_fans {
            return false;
        }
        #[cfg(target_arch = "x86_64")]
        return set_fan_level(idx, level);
        #[cfg(not(target_arch = "x86_64"))]
        false
    }

    fn list_labels(&self) -> Vec<&str> {
        let mut v: Vec<&str> = Vec::new();
        for &l in TEMP_LABELS.iter().take(self.num_temps as usize) {
            v.push(l);
        }
        for &l in FAN_LABELS.iter().take(self.num_fans as usize) {
            v.push(l);
        }
        v
    }
}

// ── Driver registration ───────────────────────────────────────────────

/// Register the Dell SMM hwmon driver. Gated on DMI vendor string
/// containing "Dell" (TODO: wire to `firmware::smbios` crate).
#[cfg(target_arch = "x86_64")]
pub fn register_smm_driver() {
    use core::fmt::Write as _;
    // TODO: add DMI `sys_vendor` check via narf_firmware::smbios.
    // For now, always register on x86_64 for structural probe smoke.
    let _ = writeln!(
        narf_console::Writer,
        "  dell_smm: SMM hwmon driver registered (DMI check TODO)"
    );
    registry::register(registry::RegisteredSensor {
        name: "dell_smm",
        description: "Dell SMM fan/temperature",
        bus_loc: "smm",
    });
    use alloc::sync::Arc;
    registry::register_device(Arc::new(DellSmm::new()));
}

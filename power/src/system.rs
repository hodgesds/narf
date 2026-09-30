//! System power transitions: reboot + power-off.
//!
//! Single user-facing surface that picks the right mechanism per
//! arch + platform:
//!
//! - **x86_64 reboot**: ACPI FADT.RESET_REG when present, falling
//!   back to legacy port 0xCF9 (the ICH/PCH "reset control"
//!   register that every PC-class chipset since the early 2000s
//!   has carried). The CF9 fallback covers platforms whose FADT
//!   omits RESET_REG (rare but legal pre-ACPI 2.0).
//! - **x86_64 power-off**: ACPI S5 sleep state via PM1a/b CNT.
//!   The platform's SLP_TYPa/b values come from `\_S5_` in the AML
//!   namespace. They are platform encodings, not an ordered state id:
//!   zero is valid (and is QEMU q35's S5 encoding).
//! - **aarch64 reboot / power-off**: PSCI SYSTEM_RESET /
//!   SYSTEM_OFF through the architecture-selected HVC/SMC conduit.
//!
//! Each entry point is `-> !` — they don't return on success, and
//! on failure they `halt_forever` rather than letting the caller
//! limp on with a half-broken transition in flight.

/// Legacy fallback `\_S5` SLP_TYP values used only when firmware does not
/// expose an evaluable `\_S5_` package. Real hardware varies; firmware values
/// always take precedence, including `(0, 0)`.
pub const QEMU_S5_SLP_TYPA: u8 = 5;
pub const QEMU_S5_SLP_TYPB: u8 = 0;

pub(crate) fn select_s5_sleep_types(firmware: Option<(u8, u8)>) -> (u8, u8) {
    firmware.unwrap_or((QEMU_S5_SLP_TYPA, QEMU_S5_SLP_TYPB))
}

/// ICH/PCH "reset control" register — write 0x06 to issue a
/// hard reset on every PC-class x86 platform since ~2000.
/// Fallback when the FADT doesn't carry RESET_REG.
#[cfg(target_arch = "x86_64")]
const PORT_CF9: u16 = 0xCF9;
#[cfg(target_arch = "x86_64")]
const CF9_HARD_RESET: u8 = 0x06;

/// Reboot the system. Tries ACPI FADT.RESET_REG first, then
/// falls back to legacy port 0xCF9 on x86_64. Never returns on
/// success; halts forever on failure (the platform is in a
/// state we can't recover from).
#[cfg(target_arch = "x86_64")]
pub fn reboot() -> ! {
    // SAFETY: both reboot mechanisms hard-reset the platform —
    // they can't safely return.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        if narf_acpi::reboot_via_fadt() {
            // Some platforms take a moment to act on the write;
            // give the bus a few hundred cycles to settle before
            // we fall through to CF9.
            for _ in 0..1_000_000 {
                core::hint::spin_loop();
            }
        }
        narf_arch::x86_64::io_port::outb(PORT_CF9, CF9_HARD_RESET);
        // Both mechanisms tried — wait for the platform to act.
    }
    // On the off chance both writes silently failed, halt rather
    // than spinning in a loop pretending we rebooted.
    narf_arch::halt_forever();
}

/// Power off the system via ACPI S5. Reads `\_S5` from the AML
/// namespace for the SLP_TYPa / SLP_TYPb pair and uses that pair verbatim:
/// SLP_TYP is a platform-specific encoding, and zero is valid for S5 on QEMU
/// q35. Falls back to the legacy values only when `_S5` is unavailable.
/// Never returns on success.
#[cfg(target_arch = "x86_64")]
pub fn power_off() -> ! {
    let (slp_typ_a, slp_typ_b) = select_s5_sleep_types(narf_aml::evaluate_s5());
    // SAFETY: enters S5 — the platform powers off; this call
    // is documented to never return.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_acpi::shutdown_via_pm1(slp_typ_a, slp_typ_b);
    }
    // Some firmware needs PMx_CNT writes mirrored after a brief
    // pause; spin briefly then halt if power didn't drop.
    for _ in 0..10_000_000 {
        core::hint::spin_loop();
    }
    narf_arch::halt_forever();
}

/// aarch64 reboot via PSCI SYSTEM_RESET. Returns `!`.
#[cfg(target_arch = "aarch64")]
pub fn reboot() -> ! {
    // QEMU/KVM use HVC while bare-metal firmware commonly uses SMC. The
    // architecture PSCI layer owns that selection and the SMCCC clobber set.
    let _ = narf_arch::aarch64::psci::system_reset();
    narf_arch::halt_forever();
}

/// aarch64 power-off via PSCI SYSTEM_OFF.
#[cfg(target_arch = "aarch64")]
pub fn power_off() -> ! {
    let _ = narf_arch::aarch64::psci::system_off();
    narf_arch::halt_forever();
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn reboot() -> ! {
    narf_arch::halt_forever();
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn power_off() -> ! {
    narf_arch::halt_forever();
}

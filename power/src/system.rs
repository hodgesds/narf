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
//!   Caller passes the platform's SLP_TYPa/b values (from `\_S5_`
//!   in the AML namespace); QEMU defaults to `(5, 0)`. Until the
//!   AML namespace walk surfaces a typed accessor, the wrapper
//!   pre-loads the QEMU values and accepts caller overrides.
//! - **aarch64 reboot / power-off**: PSCI SYSTEM_RESET /
//!   SYSTEM_OFF via SMC. Function IDs from `crate::psci::fn_id`.
//!
//! Each entry point is `-> !` — they don't return on success, and
//! on failure they `halt_forever` rather than letting the caller
//! limp on with a half-broken transition in flight.

/// Default `\_S5` SLP_TYP values for QEMU + most x86 firmware.
/// Real hardware varies — when the AML interpreter lands a
/// `\_S5_` evaluator, callers should prefer those values.
pub const QEMU_S5_SLP_TYPA: u8 = 5;
pub const QEMU_S5_SLP_TYPB: u8 = 0;

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
/// namespace for the SLP_TYPa / SLP_TYPb pair; falls back to the
/// QEMU defaults when the namespace is missing the package or
/// reports a degenerate `(0, 0)` (QEMU q35 ships this — a
/// SLP_TYP of 0 means "enter S0" which would be a no-op write
/// to PM1a_CNT). Never returns on success.
#[cfg(target_arch = "x86_64")]
pub fn power_off() -> ! {
    let (slp_typ_a, slp_typ_b) = match narf_aml::evaluate_s5() {
        Some((0, 0)) | None => (QEMU_S5_SLP_TYPA, QEMU_S5_SLP_TYPB),
        Some(p) => p,
    };
    // SAFETY: enters S5 — the platform powers off; this call
    // is documented to never return.
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

/// aarch64 reboot via PSCI SYSTEM_RESET (SMC). Returns `!`.
#[cfg(target_arch = "aarch64")]
pub fn reboot() -> ! {
    // SMC #0 with x0 = SYSTEM_RESET function id.
    // SAFETY: SMC at EL1 traps to EL3 firmware; PSCI SYSTEM_RESET
    // doesn't return on success.
    unsafe {
        let _ = psci_smc(crate::psci::fn_id::SYSTEM_RESET, 0, 0, 0);
    }
    narf_arch::halt_forever();
}

/// aarch64 power-off via PSCI SYSTEM_OFF.
#[cfg(target_arch = "aarch64")]
pub fn power_off() -> ! {
    // SAFETY: SMC at EL1; PSCI SYSTEM_OFF doesn't return.
    unsafe {
        let _ = psci_smc(crate::psci::fn_id::SYSTEM_OFF, 0, 0, 0);
    }
    narf_arch::halt_forever();
}

#[cfg(target_arch = "aarch64")]
unsafe fn psci_smc(fn_id: u32, x1: u64, x2: u64, x3: u64) -> i64 {
    let ret: i64;
    // SAFETY: SMC #0 traps to EL3 (or HVC #0 to EL2 on
    // hyp-managed systems). PSCI uses the SMC32 / SMC64 calling
    // convention — fn_id in w0, args in x1..x3, result in x0.
    // Power-off / reset don't return; for callers that do
    // (PSCI_VERSION etc.) the result is i64.
    unsafe {
        core::arch::asm!(
            "smc #0",
            in("w0") fn_id,
            in("x1") x1,
            in("x2") x2,
            in("x3") x3,
            lateout("x0") ret,
            out("x4") _,
            out("x5") _,
            out("x6") _,
            out("x7") _,
            out("x8") _,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            out("x13") _,
            out("x14") _,
            out("x15") _,
            out("x16") _,
            out("x17") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn reboot() -> ! {
    narf_arch::halt_forever();
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn power_off() -> ! {
    narf_arch::halt_forever();
}

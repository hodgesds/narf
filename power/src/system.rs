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

use core::sync::atomic::{AtomicBool, Ordering};

// ── Device shutdown hooks ──────────────────────────────────────────

/// A driver's final quiesce before the platform resets or powers off
/// (Linux `device_shutdown` → `pci_device_shutdown` → e.g. `nvme_shutdown`).
/// Runs with the system otherwise idle; it must be bounded and must not
/// sleep on the scheduler.
pub type ShutdownHook = fn();

type HookList = alloc::vec::Vec<(&'static str, ShutdownHook)>;
static SHUTDOWN_HOOKS: narf_lib::sync::IrqSafeSpinLock<HookList> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Register `hook` under `name` (idempotent on `name`). Hooks run on every
/// [`reboot`] and [`power_off`], after the persistent-log flush, in reverse
/// registration order (Linux shuts devices down in reverse probe order).
pub fn register_shutdown_hook(name: &'static str, hook: ShutdownHook) {
    let mut g = SHUTDOWN_HOOKS.lock();
    if let Some(e) = g.iter_mut().find(|(n, _)| *n == name) {
        e.1 = hook;
    } else {
        g.push((name, hook));
    }
}

/// Run every registered shutdown hook once (reverse registration order).
/// Called by [`reboot`] / [`power_off`]; exposed for tests. The list is
/// copied out first, so no lock is held while a driver runs.
pub fn run_shutdown_hooks() {
    let hooks = SHUTDOWN_HOOKS.lock().clone();
    for (_, hook) in hooks.iter().rev() {
        hook();
    }
}

/// Replace the whole shutdown-hook list, returning the old one. Test-only:
/// lets a model test observe the transition order without running the real
/// NVMe shutdown against the controllers later tests still use.
#[doc(hidden)]
pub fn __swap_shutdown_hooks_for_test(
    hooks: alloc::vec::Vec<(&'static str, ShutdownHook)>,
) -> alloc::vec::Vec<(&'static str, ShutdownHook)> {
    core::mem::replace(&mut *SHUTDOWN_HOOKS.lock(), hooks)
}

// ── Transition prologue ────────────────────────────────────────────

/// Everything that runs before the platform reset / S5 write — Linux
/// `kernel_shutdown_prepare` / `kernel_restart_prepare` (`kernel/reboot.c`),
/// whose `device_shutdown()` NARF runs as the shutdown hooks:
///
/// 1. the persistent-log flush (Linux `kmsg_dump(KMSG_DUMP_SHUTDOWN)`, run
///    there after `device_shutdown`; here first, while the log's backing
///    device is still up);
/// 2. the device shutdown hooks (NVMe Flush + CC.SHN, ...).
///
/// No filesystem sync: Linux's `reboot(2)` "doesn't sync: do that yourself
/// before calling this" — userspace (systemd-shutdown, the `reboot` binary)
/// syncs and remounts read-only first, and the kernel's own forced paths
/// ([`crate::orderly`]) run their emergency sync before they call in here.
pub fn before_transition() {
    narf_console::run_persist_hook(None);
    run_shutdown_hooks();
}

/// Set by the first reboot / power-off to start; the transition runs once.
static TRANSITION_STARTED: AtomicBool = AtomicBool::new(false);

/// Whether a reboot / power-off has begun (the emergency watchdog of
/// [`crate::orderly::hw_protection_shutdown`] checks it).
pub fn transition_started() -> bool {
    TRANSITION_STARTED.load(Ordering::Acquire)
}

/// Gate every `-> !` transition entry point:
///
/// - **Never from interrupt context.** The device shutdown hooks wait on I/O
///   and on locks the interrupted code may hold (the NVMe request gate held
///   by the very I/O the IRQ interrupted). An IRQ-context caller is turned
///   into a request the task-context orderly worker serves with a kernel
///   power-off, and this CPU parks.
/// - **Once.** A second, concurrent caller parks instead of running the
///   hooks a second time against devices the first is shutting down.
fn begin_transition(what: &str) {
    use core::fmt::Write as _;
    if narf_lib::context::in_irq() {
        let _ = writeln!(
            narf_console::Writer,
            "{what}: refused from interrupt context; handing over to the orderly power-off worker"
        );
        crate::orderly::orderly_poweroff(crate::orderly::OrderlyReason::IrqContextRequest, true);
        narf_arch::halt_forever();
    }
    if TRANSITION_STARTED.swap(true, Ordering::AcqRel) {
        let _ = writeln!(
            narf_console::Writer,
            "{what}: a reboot/power-off is already in progress on another CPU; parking"
        );
        narf_arch::halt_forever();
    }
}

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

/// Reboot the system — Linux `kernel_restart`; no filesystem sync (see
/// [`before_transition`]). Tries ACPI FADT.RESET_REG first, then
/// falls back to legacy port 0xCF9 on x86_64. Never returns on
/// success; halts forever on failure (the platform is in a
/// state we can't recover from).
#[cfg(target_arch = "x86_64")]
pub fn reboot() -> ! {
    begin_transition("reboot");
    // Final persistent-log flush, then device shutdown (NVMe Flush + CC.SHN,
    // ...). No sync: see [`before_transition`].
    before_transition();
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

/// Power off the system via ACPI S5 — Linux `kernel_power_off`: device
/// shutdown, then the platform call; no filesystem sync (see
/// [`before_transition`]). Reads `\_S5` from the AML
/// namespace for the SLP_TYPa / SLP_TYPb pair and uses that pair verbatim:
/// SLP_TYP is a platform-specific encoding, and zero is valid for S5 on QEMU
/// q35. Falls back to the legacy values only when `_S5` is unavailable.
/// Never returns on success.
#[cfg(target_arch = "x86_64")]
pub fn power_off() -> ! {
    begin_transition("power-off");
    before_transition();
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
    begin_transition("reboot");
    before_transition();
    // QEMU/KVM use HVC while bare-metal firmware commonly uses SMC. The
    // architecture PSCI layer owns that selection and the SMCCC clobber set.
    let _ = narf_arch::aarch64::psci::system_reset();
    narf_arch::halt_forever();
}

/// aarch64 power-off via PSCI SYSTEM_OFF.
#[cfg(target_arch = "aarch64")]
pub fn power_off() -> ! {
    begin_transition("power-off");
    before_transition();
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

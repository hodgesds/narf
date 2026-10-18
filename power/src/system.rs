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

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
/// [`reboot`] and [`power_off`], after the pre-shutdown filesystem sync and
/// the persistent-log flush, in reverse registration order (Linux shuts
/// devices down in reverse probe order).
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

// ── Pre-shutdown filesystem sync ───────────────────────────────────

/// The step that makes every mounted filesystem durable before any device
/// is shut down. The filesystem walk needs the syscall layer's way of
/// waiting on a future from synchronous code (a stackful task parks on the
/// filesystem's waker), which lives above this crate, so the layer that owns
/// it installs it ([`install_pre_shutdown_sync`]; `narf_userspace` does at
/// init). It must be bounded.
pub type PreShutdownSync = fn();

/// `PreShutdownSync as usize`; 0 = none installed.
static PRE_SHUTDOWN_SYNC: AtomicUsize = AtomicUsize::new(0);

/// Install the pre-shutdown sync step (idempotent; the last one wins).
pub fn install_pre_shutdown_sync(hook: PreShutdownSync) {
    PRE_SHUTDOWN_SYNC.store(hook as usize, Ordering::Release);
}

/// Swap the installed sync step, returning the previous one. Test-only.
#[doc(hidden)]
pub fn __swap_pre_shutdown_sync_for_test(hook: Option<PreShutdownSync>) -> Option<PreShutdownSync> {
    let old = PRE_SHUTDOWN_SYNC.swap(hook.map_or(0, |h| h as usize), Ordering::AcqRel);
    // SAFETY: a non-zero value was stored from a `PreShutdownSync`.
    (old != 0).then(|| unsafe { core::mem::transmute::<usize, PreShutdownSync>(old) })
}

/// Run the installed pre-shutdown sync step. Returns whether one was
/// installed.
pub fn run_pre_shutdown_sync() -> bool {
    let h = PRE_SHUTDOWN_SYNC.load(Ordering::Acquire);
    if h == 0 {
        return false;
    }
    // SAFETY: stored as `PreShutdownSync as usize` by
    // `install_pre_shutdown_sync`.
    let f: PreShutdownSync = unsafe { core::mem::transmute::<usize, PreShutdownSync>(h) };
    f();
    true
}

/// Whether filesystems still need syncing on the way down. The orderly
/// path ([`crate::orderly`]) syncs asynchronously, with its own bound, before
/// it calls [`power_off_synced`]; every other caller syncs here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SyncStep {
    /// Run the pre-shutdown sync first (every ordinary transition).
    Sync,
    /// The caller already synced (or gave up on it with a logged reason).
    AlreadyDone,
}

/// Everything that runs before the platform reset / S5 write, in this
/// order, which is the point:
///
/// 1. the pre-shutdown filesystem sync (every mounted filesystem's `syncfs`,
///    then a flush of every disk this boot wrote) — Linux userspace's final
///    `sync()` plus the kernel's `emergency_sync` for the forced paths;
/// 2. the persistent-log flush;
/// 3. the device shutdown hooks (NVMe Flush + CC.SHN, ...).
///
/// The sync must precede (3): a filesystem commit issued after the NVMe
/// controller has been sent CC.SHN never reaches the media.
pub fn before_transition(sync: SyncStep) {
    if sync == SyncStep::Sync {
        run_pre_shutdown_sync();
    }
    narf_console::run_persist_hook(None);
    run_shutdown_hooks();
}

/// Set by the first reboot / power-off to start; the transition runs once.
static TRANSITION_STARTED: AtomicBool = AtomicBool::new(false);

/// Whether a reboot / power-off has begun (the forced-fallback timer of
/// [`crate::orderly::hw_protection_shutdown`] checks it).
pub fn transition_started() -> bool {
    TRANSITION_STARTED.load(Ordering::Acquire)
}

/// Gate every `-> !` transition entry point:
///
/// - **Never from interrupt context.** The sync and the device shutdown
///   hooks wait on I/O and on locks the interrupted code may hold (the NVMe
///   request gate held by the very I/O the IRQ interrupted). An IRQ-context
///   caller is turned into an orderly power-off request served by the
///   task-context worker, and this CPU parks.
/// - **Once.** A second, concurrent caller parks instead of running the
///   hooks a second time against devices the first is shutting down.
fn begin_transition(what: &str) {
    use core::fmt::Write as _;
    if narf_lib::context::in_irq() {
        let _ = writeln!(
            narf_console::Writer,
            "{what}: refused from interrupt context; handing over to the orderly power-off worker"
        );
        crate::orderly::orderly_poweroff(crate::orderly::OrderlyReason::IrqContextRequest, None);
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

/// Reboot the system. Tries ACPI FADT.RESET_REG first, then
/// falls back to legacy port 0xCF9 on x86_64. Never returns on
/// success; halts forever on failure (the platform is in a
/// state we can't recover from).
#[cfg(target_arch = "x86_64")]
pub fn reboot() -> ! {
    begin_transition("reboot");
    // Filesystem sync, final persistent-log flush, then device shutdown
    // (NVMe Flush + CC.SHN, ...).
    before_transition(SyncStep::Sync);
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
    power_off_after(SyncStep::Sync)
}

/// [`power_off`] for a caller that already synced every filesystem itself
/// (the orderly path, which bounds its sync with a deadline).
#[cfg(target_arch = "x86_64")]
pub fn power_off_synced() -> ! {
    power_off_after(SyncStep::AlreadyDone)
}

#[cfg(target_arch = "x86_64")]
fn power_off_after(sync: SyncStep) -> ! {
    begin_transition("power-off");
    before_transition(sync);
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
    before_transition(SyncStep::Sync);
    // QEMU/KVM use HVC while bare-metal firmware commonly uses SMC. The
    // architecture PSCI layer owns that selection and the SMCCC clobber set.
    let _ = narf_arch::aarch64::psci::system_reset();
    narf_arch::halt_forever();
}

/// aarch64 power-off via PSCI SYSTEM_OFF.
#[cfg(target_arch = "aarch64")]
pub fn power_off() -> ! {
    power_off_after(SyncStep::Sync)
}

/// See the x86_64 [`power_off_synced`].
#[cfg(target_arch = "aarch64")]
pub fn power_off_synced() -> ! {
    power_off_after(SyncStep::AlreadyDone)
}

#[cfg(target_arch = "aarch64")]
fn power_off_after(sync: SyncStep) -> ! {
    begin_transition("power-off");
    before_transition(sync);
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

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn power_off_synced() -> ! {
    narf_arch::halt_forever();
}

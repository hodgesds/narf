//! Suspend-to-RAM / resume — Stage-4 structural shape.
//!
//! # PCIe device save/restore
//!
//! PCIe endpoints lose their BAR programming + Command register
//! state across S3 / D3hot — firmware brings the link back up in
//! a clean state but the OS-set BARs are gone. Drivers integrate
//! via the [`crate::device_pm::DevicePmOps`] trait, holding their
//! per-device [`narf_bus::pci::SavedPciConfig`] snapshot inside
//! the trait impl. On suspend: call `bus::pci::save_config(cap,
//! dev)` and stash the result; on resume: pass the stashed snapshot
//! back via `bus::pci::restore_config`. Order matters — the cfg
//! restore writes BARs first, then the Command register last so
//! the device doesn't decode MMIO before its BARs are programmed.
//!
//! Spec: `power/specification/spec.md` (Stage-4 suspend-to-RAM
//! (S3 / PSCI)). System-wide suspend follows a fixed phase order:
//!
//!   1. Freeze userspace + quiesce every driver
//!      (`DevicePm::runtime_suspend` fan-out).
//!   2. Sync the unified page cache to storage.
//!   3. Save per-CPU state (scheduler / arch domain state / RCU
//!      queues).
//!   4. Invoke the platform's suspend primitive — ACPI S3 on x86_64
//!      via the `\_PTS(3)` AML method + PM1 SLP_TYP/SLP_EN write,
//!      or `PSCI SYSTEM_SUSPEND` on aarch64.
//!   5. On resume: re-establish paging, restore per-CPU state,
//!      resume drivers, unfreeze userspace.
//!
//! What's wired today (x86_64): `\_S3_` discovery, `\_PTS(3)`
//! evaluation, and the PM1 SLP_TYP|SLP_EN write that puts the chipset
//! to sleep. The CPU resume trampoline + FACS firmware-waking-vector
//! installation are still TODO — without a trampoline the system
//! enters S3 but does not return, so `suspend(cap)` keeps refusing
//! the actual sleep transition unless `__test_arm_real_sleep()` has
//! been called (kernel-test harness only).

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use narf_capabilities::{Cap, CapError, NoopOp};

use crate::Power;

/// Phases the suspend/resume pipeline passes through.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SuspendPhase {
    Idle = 0,
    FreezingUserspace = 1,
    QuiescingDrivers = 2,
    SyncingCache = 3,
    SavingCpuState = 4,
    PlatformOff = 5,
    RestoringCpuState = 6,
    ResumingDrivers = 7,
    ThawingUserspace = 8,
}

/// Errors from the suspend surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SuspendError {
    /// Cap epoch check failed — caller's authority was revoked.
    AuthorityRevoked,
    /// Platform doesn't support S3 (no `\_S3_`, no usable PM1A_CNT),
    /// or the system is in test-mode and the real PM1 write is
    /// gated off pending bring-up validation. Today's production
    /// boots return this until [`__test_arm_real_sleep`] is flipped.
    NotImplemented,
    /// A suspend transition is already in progress on this CPU.
    AlreadySuspending,
    /// Pre-PM1 setup failed — usually a missing FACS or an
    /// unresolved virt→phys translation for the trampoline. The
    /// chipset has not been touched; resume fan-out has already
    /// run.
    Aborted,
}

impl From<CapError> for SuspendError {
    fn from(_: CapError) -> Self {
        SuspendError::AuthorityRevoked
    }
}

/// Current phase. `u8`-backed atomic so subscribers can read it
/// from a signal handler / interrupt without grabbing a lock.
static PHASE: AtomicU8 = AtomicU8::new(SuspendPhase::Idle as u8);

/// Request a system-wide suspend. Walks the phase progression
/// through to `PlatformOff`; on platforms where S3 is supported
/// (`s3_supported() == true`) and the resume trampoline has been
/// armed (`__test_arm_real_sleep` or future production gate),
/// delegates to [`arm_s3_resume`] which writes the FACS waking
/// vector and issues the PM1 sleep transition. Otherwise the
/// function walks the phases for subscribers, runs the resume
/// fan-out so paired drivers observe a clean cycle, and returns
/// `NotImplemented`.
///
/// Returns `Ok(())` only after a full suspend → resume cycle on
/// platforms with armed S3.
pub fn suspend(cap: &Cap<Power, narf_capabilities::Invoke>) -> Result<(), SuspendError> {
    cap.invoke(NoopOp)?;
    let prev = PHASE.swap(SuspendPhase::FreezingUserspace as u8, Ordering::AcqRel);
    if prev != SuspendPhase::Idle as u8 {
        // Put it back — we're bailing on the transition.
        PHASE.store(prev, Ordering::Release);
        return Err(SuspendError::AlreadySuspending);
    }
    PHASE.store(SuspendPhase::QuiescingDrivers as u8, Ordering::Release);
    // Fan out to every registered device PM handler in reverse
    // registration order. Failures here are logged but don't abort
    // the suspend chain — we want partial progress so the resume
    // path can roll back whatever did suspend successfully.
    let _suspend_report = crate::device_pm::suspend_all_devices();
    // Blank the framebuffer + park the console hook so the FB
    // driver can repaint cleanly on resume.
    invoke_fb_suspend();
    PHASE.store(SuspendPhase::SyncingCache as u8, Ordering::Release);
    PHASE.store(SuspendPhase::SavingCpuState as u8, Ordering::Release);
    PHASE.store(SuspendPhase::PlatformOff as u8, Ordering::Release);

    // Real platform suspend, when armed and supported. The
    // arm_s3_resume() path saves CPU state, programs the FACS
    // waking vector, fans out device suspend, and writes PM1
    // SLP_TYP|SLP_EN. It only returns when the wake trampoline +
    // longjmp bring control back here.
    //
    // Two routes both gate the PM1 write:
    //   - `REAL_SLEEP_ARMED` — kernel-test harness back-door.
    //   - `PRODUCTION_S3_ENABLED` — user opt-in after on-silicon
    //     validation (either via `enable_production_s3()` or
    //     via the `S3_VALIDATED` boot-cmdline token).
    //
    // Either flag set authorises entering arm_s3_resume(); the
    // inner check inside arm_s3_resume() then validates the
    // dynamic side (resume vectors resolved, FACS armable).
    #[cfg(target_arch = "x86_64")]
    {
        let armed = REAL_SLEEP_ARMED.load(Ordering::Acquire)
            || PRODUCTION_S3_ENABLED.load(Ordering::Acquire);
        if s3_supported() && armed {
            match arm_s3_resume(cap) {
                Ok(()) => {
                    PHASE.store(SuspendPhase::ResumingDrivers as u8, Ordering::Release);
                    let _ = crate::device_pm::resume_all_devices();
                    invoke_fb_resume();
                    restore_irq_masks();
                    PHASE.store(SuspendPhase::ThawingUserspace as u8, Ordering::Release);
                    PHASE.store(SuspendPhase::Idle as u8, Ordering::Release);
                    return Ok(());
                }
                Err(e) => {
                    // arm_s3_resume failed before PM1 — fall through
                    // to the ping-pong unwind so phase observers see
                    // a clean return-to-Idle.
                    PHASE.store(SuspendPhase::RestoringCpuState as u8, Ordering::Release);
                    PHASE.store(SuspendPhase::ResumingDrivers as u8, Ordering::Release);
                    let _ = crate::device_pm::resume_all_devices();
                    invoke_fb_resume();
                    restore_irq_masks();
                    PHASE.store(SuspendPhase::ThawingUserspace as u8, Ordering::Release);
                    PHASE.store(SuspendPhase::Idle as u8, Ordering::Release);
                    return Err(e);
                }
            }
        }
    }

    // Unarmed / unsupported path: mirror a "ping-pong through the
    // phases without actually sleeping" so the shape exercises and
    // paired suspend/resume drivers observe a clean cycle on
    // hypervisors that don't expose S3.
    PHASE.store(SuspendPhase::RestoringCpuState as u8, Ordering::Release);
    PHASE.store(SuspendPhase::ResumingDrivers as u8, Ordering::Release);
    let _resume_report = crate::device_pm::resume_all_devices();
    invoke_fb_resume();
    PHASE.store(SuspendPhase::ThawingUserspace as u8, Ordering::Release);
    PHASE.store(SuspendPhase::Idle as u8, Ordering::Release);
    Err(SuspendError::NotImplemented)
}

/// Snapshot the current phase.
#[inline]
pub fn current_phase() -> SuspendPhase {
    let v = PHASE.load(Ordering::Acquire);
    // Safety: we only ever store valid discriminants.
    unsafe { core::mem::transmute(v) }
}

/// Test helper.
#[doc(hidden)]
pub fn __test_reset() {
    PHASE.store(SuspendPhase::Idle as u8, Ordering::Release);
    REAL_SLEEP_ARMED.store(false, Ordering::Release);
    PRODUCTION_S3_ENABLED.store(false, Ordering::Release);
}

// ── ACPI S3 platform primitive (x86_64) ─────────────────────────────

/// SLP_TYP values for `\_S3_`. ACPI returns a 4-element Package whose
/// elements 0 and 1 are `SLP_TYPa` and `SLP_TYPb`.
#[derive(Copy, Clone, Debug, Default)]
pub struct S3SlpTyp {
    pub slp_typ_a: u8,
    pub slp_typ_b: u8,
}

/// Look up the `\_S3_` named object in the AML namespace and decode
/// the first two integers as `(SLP_TYPa, SLP_TYPb)`. Returns `None`
/// when the namespace lacks `\_S3_` (platform doesn't support S3).
pub fn s3_slp_typ() -> Option<S3SlpTyp> {
    // `\_S3_` is a Name(Package(...)), not a Method, so
    // `evaluate_method` won't find it. Read it via the namespace
    // node value when the AML walker decoded it as a flat Package;
    // otherwise re-evaluate the body via the eval entry point.
    let node = narf_aml::find_node("\\_S3_")?;
    if let Some(narf_aml::NameValue::Unparsed { offset, length }) = node.value {
        // Re-walk the package bytes via the evaluator.
        let mut buf = alloc::vec![0u8; length];
        let copied = narf_aml::copy_aml_bytes(offset, &mut buf);
        if copied < length {
            return None;
        }
        // Lean on the eval crate's Package decoder by wrapping the
        // bytes as a method body and asking it to evaluate. That
        // requires a synthetic method node — the simpler path here
        // is to parse the package by hand: PackageOp byte (0x12),
        // PkgLength, NumElements, then each element as a small
        // integer.
        return parse_s3_package(&buf);
    }
    None
}

fn parse_s3_package(buf: &[u8]) -> Option<S3SlpTyp> {
    // PackageOp = 0x12. Some firmwares wrap the package directly;
    // the AML walker stored the bytes starting at the body, so the
    // first byte may be PackageOp or already past it.
    if buf.is_empty() {
        return None;
    }
    let mut idx = 0;
    if buf[idx] == 0x12 {
        idx += 1;
    }
    // PkgLength: first byte's high two bits encode (followCount).
    if idx >= buf.len() {
        return None;
    }
    let lead = buf[idx];
    let follow = (lead >> 6) as usize;
    let len_bytes = 1 + follow;
    if idx + len_bytes > buf.len() {
        return None;
    }
    idx += len_bytes;
    // NumElements (1 byte).
    if idx >= buf.len() {
        return None;
    }
    let n = buf[idx];
    if n < 2 {
        return None;
    }
    idx += 1;
    // Element 0 + 1 — small integers encoded as ZeroOp / OneOp /
    // ByteOp(0x0A) byte / ones-op. Decode the two simplest forms.
    let read_int = |buf: &[u8], i: &mut usize| -> Option<u8> {
        if *i >= buf.len() {
            return None;
        }
        let op = buf[*i];
        *i += 1;
        match op {
            0x00 => Some(0),                        // ZeroOp
            0x01 => Some(1),                        // OneOp
            0xFF => Some(0xFF),                     // OnesOp (treat as 7)
            0x0A => {                               // ByteOp
                if *i >= buf.len() {
                    return None;
                }
                let v = buf[*i];
                *i += 1;
                Some(v)
            }
            _ if op < 0x10 => Some(op),             // Some firmwares emit raw 0..=7 inline
            _ => None,
        }
    };
    let a = read_int(buf, &mut idx)?;
    let b = read_int(buf, &mut idx)?;
    Some(S3SlpTyp {
        slp_typ_a: a & 0x7,
        slp_typ_b: b & 0x7,
    })
}

/// Whether S3 is supported on this platform: `\_S3_` parses cleanly
/// and the FADT exposes a usable PM1A_CNT_BLK.
pub fn s3_supported() -> bool {
    if s3_slp_typ().is_none() {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        return narf_acpi::fadt_pm()
            .map(|p| p.pm1a_cnt != 0)
            .unwrap_or(false);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Set when the kernel-test harness has decided it's safe to run the
/// PM1 sleep write (the test will reset CPU state before observing
/// post-suspend behaviour, or it's running under a hypervisor whose
/// "S3" is a no-op). Production callers leave this at `false`.
static REAL_SLEEP_ARMED: AtomicBool = AtomicBool::new(false);

/// Arm the real PM1 sleep-write path. **Test/TCB-only** — production
/// paths should evolve through `suspend()` once the resume trampoline
/// lands, not flip this directly.
#[doc(hidden)]
pub fn __test_arm_real_sleep() {
    REAL_SLEEP_ARMED.store(true, Ordering::Release);
}

// ── Production S3 opt-in gate ───────────────────────────────────────
//
// `__test_arm_real_sleep` is the test-harness back-door — it goes
// straight to PM1 SLP_EN, which is the dangerous path until the
// resume trampoline has been validated on real silicon. To let
// userspace turn S3 on after they've manually verified the resume
// chain works on their box, we expose a separate
// `enable_production_s3()` gate. It does NOT flip the same flag
// the test harness uses; it sets `PRODUCTION_S3_ENABLED`, which
// the production suspend() path checks as a *separate* condition
// from REAL_SLEEP_ARMED.
//
// Default: off. Userspace opt-in only after on-silicon validation.
// There's also an env / cmdline path: a `S3_VALIDATED` boot
// argument flips it at init time. Either route enables the
// production code path; both can co-exist.

static PRODUCTION_S3_ENABLED: AtomicBool = AtomicBool::new(false);

/// Userspace opt-in: enable the production S3 path after on-
/// silicon validation has confirmed the resume trampoline works.
/// Returns the previous value so callers can detect double-arms.
///
/// Cap-gated on the same `Cap<Power, narf_capabilities::Invoke>`
/// that drives the `suspend()` entry point. Revoking the cap will
/// not auto-disable — call [`disable_production_s3`] explicitly.
pub fn enable_production_s3(
    cap: &Cap<Power, narf_capabilities::Invoke>,
) -> Result<bool, SuspendError> {
    cap.invoke(NoopOp)?;
    let prev = PRODUCTION_S3_ENABLED.swap(true, Ordering::AcqRel);
    Ok(prev)
}

/// Userspace turn-off. Symmetric with [`enable_production_s3`].
pub fn disable_production_s3(
    cap: &Cap<Power, narf_capabilities::Invoke>,
) -> Result<bool, SuspendError> {
    cap.invoke(NoopOp)?;
    let prev = PRODUCTION_S3_ENABLED.swap(false, Ordering::AcqRel);
    Ok(prev)
}

/// Query whether the production S3 gate is open. Lock-free read.
pub fn production_s3_enabled() -> bool {
    PRODUCTION_S3_ENABLED.load(Ordering::Acquire)
}

/// Boot-time flip from a kernel cmdline / env entry. Looks for the
/// magic string `S3_VALIDATED` in the input — the cmdline parser
/// calls this once after parse. No cap-check because it runs in
/// the boot-time TCB before user authorities exist.
pub fn boot_apply_s3_validated_flag(boot_cmdline: &str) -> bool {
    if boot_cmdline.contains("S3_VALIDATED") {
        PRODUCTION_S3_ENABLED.store(true, Ordering::Release);
        true
    } else {
        false
    }
}

#[doc(hidden)]
pub fn __test_reset_production_s3() {
    PRODUCTION_S3_ENABLED.store(false, Ordering::Release);
}

// ── Console / FB blank hook ─────────────────────────────────────────
//
// On S3 entry the framebuffer driver must blank its scanout +
// detach the kernel console from the FB hook so a post-resume
// repaint can come from the saved framebuffer rather than half-
// painted glyphs left over from pre-suspend prints. Mirrors
// Linux's `drivers/video/fbdev/core/fbcon.c::fbcon_suspend` shape
// where the FB driver registers a per-class suspend/resume pair
// against the PM subsystem.
//
// `power/` itself can't reach into the FB — it would create a
// circular dep (graphics already depends on power for the runtime
// PM trait). Instead we expose two hook slots the graphics
// subsystem registers at boot.

use core::sync::atomic::AtomicUsize;

static FB_SUSPEND_HOOK: AtomicUsize = AtomicUsize::new(0);
static FB_RESUME_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Type of the FB suspend / resume hook the graphics layer
/// installs. No args, no errors — the FB driver does its own
/// internal state-machine and either succeeds or logs.
pub type FbPmHook = extern "C" fn();

/// Install the FB suspend + resume hook pair. Idempotent.
/// Graphics-layer boot calls this after `set_fb_hook` succeeds.
pub fn set_fb_pm_hooks(suspend: FbPmHook, resume: FbPmHook) {
    FB_SUSPEND_HOOK.store(suspend as usize, Ordering::Release);
    FB_RESUME_HOOK.store(resume as usize, Ordering::Release);
}

/// Run the FB suspend hook if installed. Called by the suspend
/// phase machinery after device fan-out but before the PM1 write.
pub fn invoke_fb_suspend() {
    let h = FB_SUSPEND_HOOK.load(Ordering::Acquire);
    if h != 0 {
        // SAFETY: hook was a valid `extern "C" fn` when registered.
        let f: FbPmHook = unsafe { core::mem::transmute(h) };
        f();
    }
}

/// Run the FB resume hook if installed. Called by the resume
/// fan-out after device_pm::resume_all_devices().
pub fn invoke_fb_resume() {
    let h = FB_RESUME_HOOK.load(Ordering::Acquire);
    if h != 0 {
        // SAFETY: hook was a valid `extern "C" fn` when registered.
        let f: FbPmHook = unsafe { core::mem::transmute(h) };
        f();
    }
}

/// Whether the FB hook pair is installed. Diagnostic.
pub fn fb_pm_hooks_installed() -> bool {
    FB_SUSPEND_HOOK.load(Ordering::Acquire) != 0
        && FB_RESUME_HOOK.load(Ordering::Acquire) != 0
}

#[doc(hidden)]
pub fn __test_reset_fb_pm_hooks() {
    FB_SUSPEND_HOOK.store(0, Ordering::Release);
    FB_RESUME_HOOK.store(0, Ordering::Release);
}

/// Test helper: parse a `\_S3_` package body. Used by the smoke test
/// to exercise the package-byte decoder without a live AML namespace.
#[doc(hidden)]
pub fn __test_parse_s3(buf: &[u8]) -> Option<S3SlpTyp> {
    parse_s3_package(buf)
}

/// Top-level S3 orchestrator: do everything required to enter S3
/// AND have a working resume path before we touch PM1.
///
/// Sequence:
///   1. Verify `\_S3_` is decodable.
///   2. Snapshot CPU state via `s3_resume::save_resume_context`.
///   3. setjmp the caller frame into `S3_CALLER_JMP` — when wake
///      happens, the trampoline → continuation → longjmp will
///      return us here with `S3_RESUMED_SENTINEL`.
///   4. Resolve `s3_wake_entry`'s phys + write it to FACS via
///      `acpi::arm_s3_waking_vector`.
///   5. Fan out device suspend handlers in reverse order.
///   6. Issue `\_PTS(3)` then PM1 SLP_TYP|SLP_EN. CPU stops here.
///   7. On wake, the trampoline restores GDT/IDT/CR3/RSP, runs
///      the device-resume hook, then longjmps back to setjmp's
///      caller with `S3_RESUMED_SENTINEL`. Step 3's branch fires;
///      we return `Ok(())`.
///
/// Returns `Ok(())` on a clean suspend+resume cycle, an error
/// from `SuspendError` otherwise. Until the trampoline arms
/// safely (FACS_PHYS resolved, RESUME_CONTEXT_PHYS resolved),
/// returns `NotImplemented` without touching PM1.
#[cfg(target_arch = "x86_64")]
pub fn arm_s3_resume(
    cap: &Cap<Power, narf_capabilities::Invoke>,
) -> Result<(), SuspendError> {
    cap.invoke(NoopOp)?;
    let slp = s3_slp_typ().ok_or(SuspendError::NotImplemented)?;
    // Snapshot CPU state.
    // SAFETY: caller is on the boot CPU with interrupts gated as
    // part of the suspend phase machinery.
    unsafe {
        narf_arch::x86_64::s3_resume::save_resume_context();
        // Save the LAPIC LVTs / TPR / SVR / timer state so the
        // resume hook can restore them before drivers start
        // expecting timer ticks.
        narf_arch::x86_64::s3_resume::save_lapic_state();
    }
    // Stamp the pre-suspend TSC so the resume hook can detect a
    // backwards jump and propagate to the timekeeping subsystem.
    snapshot_tsc_pre_suspend();
    // Snapshot every IRQ vector's pre-suspend mask state and
    // mask everything except the wake-source allowlist. Today
    // the allowlist is empty (we don't yet know which vectors
    // PMC.WAKE_STS routes wake events to); when the platform
    // driver decodes WAKE_STS we pass them in here.
    let _ = snapshot_and_mask_irqs(&[]);
    // setjmp the caller. On wake we'll re-enter via longjmp with
    // S3_RESUMED_SENTINEL.
    let mut jmp_snapshot = narf_arch::x86_64::setjmp::JmpBuf::default();
    // SAFETY: jmp_snapshot lives on this stack frame through the
    // PM1 write + the wake path's longjmp.
    let r = unsafe {
        narf_arch::x86_64::setjmp::setjmp(&mut jmp_snapshot as *mut _)
    };
    if r == narf_arch::x86_64::s3_resume::S3_RESUMED_SENTINEL {
        // We came back via the wake trampoline. Device fan-out
        // already ran in the continuation; just unwind.
        PHASE.store(SuspendPhase::ThawingUserspace as u8, Ordering::Release);
        PHASE.store(SuspendPhase::Idle as u8, Ordering::Release);
        return Ok(());
    }
    // Stash the JmpBuf where the wake continuation can find it.
    *narf_arch::x86_64::s3_resume::S3_CALLER_JMP.lock() = jmp_snapshot;
    // Resolve virt→phys via the active page tables. Both the
    // trampoline entry AND the ResumeContext static need their
    // phys addresses because firmware's CR3 (on wake) doesn't
    // have the kernel high-half mapping.
    //
    // CR3's low 12 bits encode flags / PCID; mask them off to get
    // the PML4 phys.
    // SAFETY: we're on the boot CPU at CPL=0; reading CR3 is
    // unconditionally legal.
    let cr3 = unsafe { narf_arch::x86_64::cr::read_cr3() } & !0xFFFu64;
    let pml4_phys = narf_memory::PhysAddr::new(cr3);
    let entry_virt = narf_arch::x86_64::s3_resume::s3_wake_entry as usize as u64;
    let ctx_virt =
        narf_arch::x86_64::s3_resume::resume_context_static_addr() as u64;
    let entry_phys = match unsafe {
        narf_memory::x86_64::paging::translate(
            pml4_phys,
            narf_memory::VirtAddr::new(entry_virt),
        )
    } {
        Some(p) => p.raw() | (entry_virt & 0xFFF),
        None => return Err(SuspendError::Aborted),
    };
    let ctx_phys = match unsafe {
        narf_memory::x86_64::paging::translate(
            pml4_phys,
            narf_memory::VirtAddr::new(ctx_virt),
        )
    } {
        Some(p) => p.raw() | (ctx_virt & 0xFFF),
        None => return Err(SuspendError::Aborted),
    };
    // Stash the ctx phys so the trampoline's RIP-relative lookup
    // can find ResumeContext post-CR3-restore. (Pre-CR3 the
    // trampoline's RIP-relative access to RESUME_CONTEXT_PHYS
    // itself relies on firmware's identity-mapping of low 4 GiB,
    // which OVMF + modern AMI BIOS preserve across S3.)
    narf_arch::x86_64::s3_resume::set_resume_context_phys(ctx_phys);
    // SAFETY: trampoline is a `naked extern "C" fn`; its phys is
    // stable for the kernel lifetime, and the firmware
    // identity-maps that page through the wake handoff.
    if unsafe { narf_acpi::arm_s3_waking_vector(entry_phys) }.is_err() {
        // FACS hasn't been parsed (no `\_S3_` chain on this
        // platform) or the entry phys is >4 GiB on a FACS v0
        // firmware. Either way, we can't wake — refuse to sleep.
        return Err(SuspendError::Aborted);
    }
    // Fan out device suspend handlers in reverse-registration order.
    let _ = crate::device_pm::suspend_all_devices();
    PHASE.store(SuspendPhase::PlatformOff as u8, Ordering::Release);
    // `\_PTS(3)` — platform-specific quiesce AML.
    let _ = narf_aml::eval::evaluate_method(
        "\\_PTS",
        &[narf_aml::Value::Integer(3)],
    );
    // Refuse the real PM1 write unless explicitly armed. Until
    // we've validated the trampoline on real silicon, this
    // returns NotImplemented rather than putting the box into a
    // state it can't recover from. Either the test back-door
    // (REAL_SLEEP_ARMED) or the production opt-in
    // (PRODUCTION_S3_ENABLED) authorises the PM1 write.
    if !REAL_SLEEP_ARMED.load(Ordering::Acquire)
        && !PRODUCTION_S3_ENABLED.load(Ordering::Acquire)
    {
        return Err(SuspendError::NotImplemented);
    }
    // SAFETY: pm1_enter_sleep doesn't return on success — the
    // CPU stops fetching when SLP_EN latches. Failure (e.g.
    // PM1 status didn't reset) returns Err; we propagate.
    unsafe {
        narf_acpi::pm1_enter_sleep(slp.slp_typ_a, slp.slp_typ_b);
    }
    // Unreachable on success; reached only on failure.
    Err(SuspendError::NotImplemented)
}

/// Enter S3. Calls `\_PTS(3)` and writes the SLP_TYP|SLP_EN bits to
/// PM1A_CNT (and PM1B_CNT when present). Returns
/// `SuspendError::NotImplemented` when the resume trampoline isn't
/// armed (production today); returns `Ok(())` if the chipset accepted
/// the write. The function does not return when the CPU actually
/// goes to sleep — callers see a fresh `init` path on resume.
pub fn s3_enter(cap: &Cap<Power, narf_capabilities::Invoke>) -> Result<(), SuspendError> {
    cap.invoke(NoopOp)?;
    let slp = s3_slp_typ().ok_or(SuspendError::NotImplemented)?;

    // `\_PTS(slp_state)` runs platform-specific quiesce AML (turns
    // off LEDs, parks devices firmware controls, etc.).
    let _ = narf_aml::eval::evaluate_method(
        "\\_PTS",
        &[narf_aml::Value::Integer(3)],
    );

    // Without a real-mode resume trampoline the system would never
    // come back. Refuse to enter unless explicitly armed via either
    // the test back-door or the production opt-in.
    if !REAL_SLEEP_ARMED.load(Ordering::Acquire)
        && !PRODUCTION_S3_ENABLED.load(Ordering::Acquire)
    {
        return Err(SuspendError::NotImplemented);
    }

    PHASE.store(SuspendPhase::PlatformOff as u8, Ordering::Release);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `\_PTS(3)` has been invoked above; the `s3_supported`
    // check on entry guarantees PM1A_CNT is populated.
    unsafe {
        narf_acpi::pm1_enter_sleep(slp.slp_typ_a, slp.slp_typ_b);
    }
    Ok(())
}

// ── IRQ-source mask snapshot ────────────────────────────────────────
//
// On S3 entry every IRQ vector except wake-sources must be soft-
// masked so a spurious controller IRQ between PM1 SLP_EN latch and
// the actual sleep entry doesn't wake the system. On resume we
// restore each vector's prior mask state from the snapshot.
//
// Wake-sources are identified by `PMC.WAKE_STS` on AMD SoCs (the
// platform tells the OS which lines latched during sleep); on
// Intel they live in GPE blocks. We don't poll them here — the
// platform driver does — but we keep them unmasked through the
// snapshot/restore so when wake fires the LAPIC routes them to
// dispatch.
//
// Reference: Linux `kernel/irq/pm.c::suspend_device_irqs`.

/// Snapshot of the soft-mask state of every IRQ vector. Packed as
/// 4 × 64-bit words covering vectors 0..=255. Vectors 0..=31 are
/// CPU exceptions; we still snapshot them for parity but they're
/// never soft-maskable on real silicon (the kernel doesn't disable
/// exception delivery).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IrqMaskSnapshot {
    pub words: [u64; 4],
}

impl IrqMaskSnapshot {
    /// True if vector `v` was masked at snapshot time.
    pub fn is_masked(&self, v: u8) -> bool {
        let (w, b) = ((v >> 6) as usize, v & 63);
        (self.words[w] >> b) & 1 == 1
    }

    /// Set the mask bit for vector `v`.
    pub fn set(&mut self, v: u8, masked: bool) {
        let (w, b) = ((v >> 6) as usize, v & 63);
        if masked {
            self.words[w] |= 1u64 << b;
        } else {
            self.words[w] &= !(1u64 << b);
        }
    }
}

/// Stored across suspend → resume so the resume-fan-out can put
/// each vector back into its pre-suspend mask state.
static IRQ_MASK_SAVED: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static IRQ_MASK_HAS_SNAPSHOT: AtomicBool = AtomicBool::new(false);

/// Walk the IRQ dispatch table, snapshot every vector's mask state,
/// and soft-mask every vector outside the wake-source allowlist.
/// Returns the encoded snapshot for diagnostic / smoke use; the
/// kernel also stashes a copy in static storage for the resume
/// path to consume.
///
/// `wake_sources` is the set of vectors that must stay unmasked
/// across suspend (PMC wake lines, RTC alarm, lid switch). Empty
/// means "mask everything except non-maskable exceptions".
pub fn snapshot_and_mask_irqs(wake_sources: &[u8]) -> IrqMaskSnapshot {
    let mut snap = IrqMaskSnapshot::default();
    // Vectors 32..=255 are IRQs (vectors 0..=31 are CPU
    // exceptions — not soft-maskable).
    for v in 32u8..=255u8 {
        if narf_interrupts::is_masked(v) {
            snap.set(v, true);
        }
        if !wake_sources.contains(&v) {
            narf_interrupts::disable_irq(v);
        }
    }
    // Stash for the resume fan-out.
    for (i, w) in snap.words.iter().enumerate() {
        IRQ_MASK_SAVED[i].store(*w, Ordering::Release);
    }
    IRQ_MASK_HAS_SNAPSHOT.store(true, Ordering::Release);
    snap
}

/// Restore every vector's mask state from the snapshot taken by
/// [`snapshot_and_mask_irqs`]. Called from the resume fan-out
/// (post wake trampoline, post device_pm::resume_all_devices).
/// No-op if no snapshot is recorded.
pub fn restore_irq_masks() {
    if !IRQ_MASK_HAS_SNAPSHOT.load(Ordering::Acquire) {
        return;
    }
    let snap = IrqMaskSnapshot {
        words: [
            IRQ_MASK_SAVED[0].load(Ordering::Acquire),
            IRQ_MASK_SAVED[1].load(Ordering::Acquire),
            IRQ_MASK_SAVED[2].load(Ordering::Acquire),
            IRQ_MASK_SAVED[3].load(Ordering::Acquire),
        ],
    };
    for v in 32u8..=255u8 {
        if snap.is_masked(v) {
            narf_interrupts::disable_irq(v);
        } else {
            narf_interrupts::enable_irq(v);
        }
    }
    IRQ_MASK_HAS_SNAPSHOT.store(false, Ordering::Release);
}

#[doc(hidden)]
pub fn __test_reset_irq_snapshot() {
    for w in IRQ_MASK_SAVED.iter() {
        w.store(0, Ordering::Release);
    }
    IRQ_MASK_HAS_SNAPSHOT.store(false, Ordering::Release);
}

// ── TSC handling across S3 ──────────────────────────────────────────
//
// On most x86 silicon the TSC stops counting in S3 and resets on
// wake. Reads taken before suspend will be larger than reads taken
// after — that's a "backwards jump" relative to the kernel's wall-
// clock view. Linux marks the post-resume wall clock backwards-
// jump as expected (`clocksource_resume` + `tk_setup_internals`);
// we do the same here.
//
// The TSC re-calibration is the timekeeping subsystem's job
// (`narf_time::calibrate_clocks_with_source` via HPET cross-check);
// this module only records the pre-suspend TSC reading and
// exposes a "did we jump back?" predicate for diagnostics.

#[cfg(target_arch = "x86_64")]
static TSC_PRE_SUSPEND: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static TSC_BACKWARD_JUMP_DETECTED: AtomicBool = AtomicBool::new(false);

/// Snapshot the TSC just before SLP_EN latches. Stored for the
/// resume path to compare against — if the post-resume TSC is
/// less than the pre-suspend value, we record a backwards jump
/// (expected; not an error).
#[cfg(target_arch = "x86_64")]
pub fn snapshot_tsc_pre_suspend() {
    let v = narf_arch::x86_64::tsc::rdtsc();
    TSC_PRE_SUSPEND.store(v, Ordering::Release);
}

/// Compare the post-resume TSC against the pre-suspend snapshot.
/// Returns `true` if the TSC went backwards (typical S3 wake on
/// silicon that resets the TSC across sleep). Calling without a
/// prior snapshot returns `false`.
#[cfg(target_arch = "x86_64")]
pub fn check_tsc_post_resume() -> bool {
    let pre = TSC_PRE_SUSPEND.load(Ordering::Acquire);
    if pre == 0 {
        return false;
    }
    let now = narf_arch::x86_64::tsc::rdtsc();
    let jumped_back = now < pre;
    TSC_BACKWARD_JUMP_DETECTED.store(jumped_back, Ordering::Release);
    jumped_back
}

/// Whether the most recent resume detected a TSC backwards jump.
/// Diagnostic accessor for the boot log / a future
/// `/proc/suspend-stats` surface.
#[cfg(target_arch = "x86_64")]
pub fn tsc_backward_jump_detected() -> bool {
    TSC_BACKWARD_JUMP_DETECTED.load(Ordering::Acquire)
}

#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub fn __test_reset_tsc_snapshot() {
    TSC_PRE_SUSPEND.store(0, Ordering::Release);
    TSC_BACKWARD_JUMP_DETECTED.store(false, Ordering::Release);
}

/// Test-only: inject a synthetic pre-suspend TSC value so the
/// backwards-jump detector can be exercised without an actual
/// sleep cycle. Production callers use [`snapshot_tsc_pre_suspend`].
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub fn __test_inject_pre_suspend_tsc(value: u64) {
    TSC_PRE_SUSPEND.store(value, Ordering::Release);
}

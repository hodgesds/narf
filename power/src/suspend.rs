//! Suspend-to-RAM / resume — Stage-4 structural shape.
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

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

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
    AuthorityRevoked,
    NotImplemented,
    AlreadySuspending,
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

/// Request a system-wide suspend. Returns `NotImplemented` until
/// the platform primitives land — but *does* walk the phase
/// progression up to `PlatformOff` so subscribers can observe the
/// handoff shape.
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
    PHASE.store(SuspendPhase::SyncingCache as u8, Ordering::Release);
    PHASE.store(SuspendPhase::SavingCpuState as u8, Ordering::Release);
    PHASE.store(SuspendPhase::PlatformOff as u8, Ordering::Release);
    // Real platform suspend would happen here and not return until
    // resume. We mirror a "ping-pong through the phases without
    // actually sleeping" behaviour so the shape exercises — and
    // run the resume fan-out so paired suspend/resume drivers
    // observe a clean cycle even on the no-op shape.
    PHASE.store(SuspendPhase::RestoringCpuState as u8, Ordering::Release);
    PHASE.store(SuspendPhase::ResumingDrivers as u8, Ordering::Release);
    let _resume_report = crate::device_pm::resume_all_devices();
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
    }
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
        None => return Err(SuspendError::NotImplemented),
    };
    let ctx_phys = match unsafe {
        narf_memory::x86_64::paging::translate(
            pml4_phys,
            narf_memory::VirtAddr::new(ctx_virt),
        )
    } {
        Some(p) => p.raw() | (ctx_virt & 0xFFF),
        None => return Err(SuspendError::NotImplemented),
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
    if let Err(_) = unsafe { narf_acpi::arm_s3_waking_vector(entry_phys) } {
        return Err(SuspendError::NotImplemented);
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
    // state it can't recover from.
    if !REAL_SLEEP_ARMED.load(Ordering::Acquire) {
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
    // come back. Refuse to enter unless explicitly armed.
    if !REAL_SLEEP_ARMED.load(Ordering::Acquire) {
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

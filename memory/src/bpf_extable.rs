//! `bpf_extable` — PC-keyed exception table for JIT-compiled BPF text.
//!
//! Spec: `bpf/specification/spec.md` §4.3, §5.
//!
//! A verified BPF program may still load through a pointer that turns out not
//! to be mapped: that is the entire point of the probe-load form, and it is
//! what makes `task->mm->owner` safe to write without a null check on every
//! hop. Linux's answer is `ex_handler_bpf` (`bpf_jit_comp.c:1479`): on a fault
//! at a registered PC, **zero the destination register and skip the
//! instruction**. NARF does the same, with two deliberate differences:
//!
//! * The fixup is expressed as an *absolute* resume PC rather than a relative
//!   displacement, because we own both sides and the JIT already knows the
//!   final address of every instruction (the text is allocated before codegen
//!   computes displacements).
//! * Zeroing happens by mutating the trap frame's GPR slot, so the JIT needs
//!   **one fixup label per program** — the resume PC — instead of a
//!   per-fault-site stub. Linux needs the stub because its extable entry
//!   encodes the register in the entry and the handler patches `pt_regs`; we
//!   simply do the same thing without the stub.
//!
//! ## Why the lookup is a sorted binary search over per-image tables
//!
//! Faults are rare, but the *lookup* runs on every unrecovered kernel fault,
//! including the ones that are about to panic. It must therefore be
//! allocation-free, lock-light, and O(log n). Entries are registered per JIT
//! image (all of a program's sites at once, already sorted by the JIT), the
//! images are kept sorted by base PC, and the two-level search is
//! image-then-entry.
//!
//! ## Invariant §4.3
//!
//! Registration **precedes** `bpf_text::seal`. A fault at an address with no
//! entry is fatal, by design — a missing entry is a JIT bug, and silently
//! resuming would turn it into a corrupted register.

extern crate alloc as alloc_crate;

use alloc_crate::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

/// One recoverable fault site.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExEntry {
    /// Address of the faulting instruction — the trapping RIP / ELR.
    pub fault_pc: u64,
    /// Where to resume. Normally the instruction after the faulting one.
    pub fixup_pc: u64,
    /// Architectural register to zero before resuming, as a [`GpReg`] index.
    /// `GpReg::NONE` means "resume without touching any register".
    pub dst: GpReg,
}

/// Index of the destination general-purpose register to zero on recovery.
///
/// x86_64: 0..=15 in the canonical `rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
/// r8..r15` encoding — i.e. exactly the ModRM/REX register number the JIT
/// already emitted, so no translation table is needed.
///
/// aarch64: 0..=30 for `x0..x30`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GpReg(pub u8);

impl GpReg {
    /// Sentinel: recover without zeroing anything.
    pub const NONE: Self = Self(0xFF);

    #[inline]
    pub const fn is_none(self) -> bool {
        self.0 == 0xFF
    }
}

/// An image's worth of entries, kept sorted by `fault_pc`.
#[derive(Debug)]
struct Image {
    /// Inclusive low bound of the image's text.
    base: u64,
    /// Exclusive high bound.
    end: u64,
    /// Opaque owner token, so the owner can drop its own entries without
    /// knowing the text bounds it registered under.
    token: u64,
    entries: Vec<ExEntry>,
}

/// Images, sorted by `base`, non-overlapping.
static IMAGES: IrqSafeSpinLock<Vec<Image>> = IrqSafeSpinLock::new(Vec::new());

/// Number of registered images, readable without taking [`IMAGES`].
///
/// [`lookup`] runs on **every** unrecovered kernel fault, including the ones
/// that are about to panic, so on a kernel with no BPF loaded it must not
/// touch a lock at all: a CPU that died holding `IMAGES` would otherwise turn
/// a diagnosable panic into a hang on the next CPU to fault.
static IMAGE_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Registration failures.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExError {
    /// `base >= end`, or an entry falls outside `[base, end)`.
    BadRange,
    /// The range overlaps an already-registered image.
    Overlap,
}

/// Register every recoverable fault site of one JIT image.
///
/// **Must run before `bpf_text::seal` publishes the text as executable**
/// (invariant §4.3). `entries` is sorted in place by `fault_pc`; duplicates
/// are not rejected but the first match wins.
///
/// `token` is returned to the caller's own bookkeeping and is what
/// [`unregister_image`] matches on.
pub fn register_image(
    token: u64,
    base: u64,
    end: u64,
    mut entries: Vec<ExEntry>,
) -> Result<(), ExError> {
    if base >= end {
        return Err(ExError::BadRange);
    }
    if entries
        .iter()
        .any(|e| e.fault_pc < base || e.fault_pc >= end)
    {
        return Err(ExError::BadRange);
    }
    entries.sort_unstable_by_key(|e| e.fault_pc);

    let mut images = IMAGES.lock();
    // Images are non-overlapping and sorted, so the insertion point is the
    // first image whose base is past ours, and only its predecessor and
    // itself can overlap.
    let at = images.partition_point(|i| i.base < base);
    if at > 0 && images[at - 1].end > base {
        return Err(ExError::Overlap);
    }
    if at < images.len() && images[at].base < end {
        return Err(ExError::Overlap);
    }
    images.insert(
        at,
        Image {
            base,
            end,
            token,
            entries,
        },
    );
    IMAGE_COUNT.store(images.len(), core::sync::atomic::Ordering::Release);
    Ok(())
}

/// Drop every entry registered under `token`.
///
/// Call **after** the text has been retired past its RCU grace period, not
/// before: an in-flight fault on a still-running program must still find its
/// entry.
pub fn unregister_image(token: u64) {
    let mut images = IMAGES.lock();
    images.retain(|i| i.token != token);
    IMAGE_COUNT.store(images.len(), core::sync::atomic::Ordering::Release);
}

/// Look up a faulting PC.
///
/// Allocation-free and O(log images + log entries). Called from the trap
/// handler with the fault frame live, so it must not panic and must not take
/// any lock the faulting code might already hold — `IMAGES` is only ever taken
/// by this module, and never across a call that can fault.
#[inline]
pub fn lookup(fault_pc: u64) -> Option<ExEntry> {
    // Fast bail *without* touching the lock: an empty table is the common case
    // on a kernel with no BPF loaded, and every unrecovered kernel fault runs
    // through here — including ones on the way to a panic. See `IMAGE_COUNT`.
    if IMAGE_COUNT.load(core::sync::atomic::Ordering::Acquire) == 0 {
        return None;
    }
    let images = IMAGES.lock();
    let at = images.partition_point(|i| i.base <= fault_pc);
    if at == 0 {
        return None;
    }
    let img = &images[at - 1];
    if fault_pc >= img.end {
        return None;
    }
    let idx = img
        .entries
        .binary_search_by_key(&fault_pc, |e| e.fault_pc)
        .ok()?;
    Some(img.entries[idx])
}

/// Diagnostics: (registered images, total entries).
pub fn stats() -> (usize, usize) {
    let images = IMAGES.lock();
    (images.len(), images.iter().map(|i| i.entries.len()).sum())
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    IMAGES.lock().clear();
    IMAGE_COUNT.store(0, core::sync::atomic::Ordering::Release);
}

// ── The trap-handler side ──────────────────────────────────────────────
//
// `frame/src/{x86_64,aarch64}/trap.rs` calls `try_recover`, which is
// deliberately arch-neutral: it takes and returns the two things a fixup
// changes — the resume PC and the register to zero — and leaves the actual
// frame mutation to the arch code, which owns the `TrapFrame` layout.

/// What the trap handler should do about a fault at `fault_pc`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// New PC to resume at.
    pub resume_pc: u64,
    /// Register to zero first, or [`GpReg::NONE`].
    pub zero_reg: GpReg,
}

/// Decide whether a **kernel-mode** fault at `fault_pc` is a registered BPF
/// probe fault.
///
/// The caller must have established kernel mode already — a user-mode fault
/// can never be in BPF text (the window is kernel-only at every level of the
/// walk), but checking there costs nothing and keeps the invariant local to
/// the trap handler.
#[inline]
pub fn try_recover(fault_pc: u64) -> Option<Recovery> {
    let e = lookup(fault_pc)?;
    Some(Recovery {
        resume_pc: e.fixup_pc,
        zero_reg: e.dst,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(f: u64, x: u64, r: u8) -> ExEntry {
        ExEntry {
            fault_pc: f,
            fixup_pc: x,
            dst: GpReg(r),
        }
    }

    #[test]
    fn finds_a_registered_site() {
        __reset_for_test();
        register_image(1, 0x1000, 0x2000, alloc_crate::vec![e(0x1100, 0x1108, 3)]).unwrap();
        let r = try_recover(0x1100).unwrap();
        assert_eq!(r.resume_pc, 0x1108);
        assert_eq!(r.zero_reg, GpReg(3));
    }

    #[test]
    fn unregistered_pc_is_fatal() {
        __reset_for_test();
        register_image(1, 0x1000, 0x2000, alloc_crate::vec![e(0x1100, 0x1108, 3)]).unwrap();
        // Inside the image but not a registered site — still no recovery.
        assert!(try_recover(0x1104).is_none());
        // Outside every image.
        assert!(try_recover(0x9000).is_none());
    }

    #[test]
    fn entries_outside_the_image_are_rejected() {
        __reset_for_test();
        assert_eq!(
            register_image(1, 0x1000, 0x2000, alloc_crate::vec![e(0x3000, 0x3008, 0)]),
            Err(ExError::BadRange)
        );
    }

    #[test]
    fn overlapping_images_are_rejected() {
        __reset_for_test();
        register_image(1, 0x1000, 0x2000, Vec::new()).unwrap();
        assert_eq!(
            register_image(2, 0x1800, 0x2800, Vec::new()),
            Err(ExError::Overlap)
        );
        assert_eq!(
            register_image(3, 0x0800, 0x1800, Vec::new()),
            Err(ExError::Overlap)
        );
        // Abutting is fine.
        assert!(register_image(4, 0x2000, 0x3000, Vec::new()).is_ok());
    }

    #[test]
    fn unregister_drops_only_its_own_token() {
        __reset_for_test();
        register_image(1, 0x1000, 0x2000, alloc_crate::vec![e(0x1100, 0x1108, 1)]).unwrap();
        register_image(2, 0x2000, 0x3000, alloc_crate::vec![e(0x2100, 0x2108, 2)]).unwrap();
        unregister_image(1);
        assert!(try_recover(0x1100).is_none());
        assert!(try_recover(0x2100).is_some());
    }

    #[test]
    fn many_images_stay_sorted_and_searchable() {
        __reset_for_test();
        for i in 0..64u64 {
            let base = 0x10_0000 + i * 0x1000;
            register_image(
                i,
                base,
                base + 0x1000,
                alloc_crate::vec![e(base + 0x40, base + 0x48, (i % 16) as u8)],
            )
            .unwrap();
        }
        for i in 0..64u64 {
            let base = 0x10_0000 + i * 0x1000;
            let r = try_recover(base + 0x40).unwrap();
            assert_eq!(r.resume_pc, base + 0x48);
        }
        assert_eq!(stats(), (64, 64));
    }
}

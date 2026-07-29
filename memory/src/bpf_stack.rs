//! `bpf_stack` — the dedicated per-CPU BPF stack region.
//!
//! Spec: `bpf/specification/spec.md` §4.8; design rationale in the plan §1.5.
//!
//! Linux puts the BPF stack on the *kernel* stack, and everything painful
//! follows from that: `MAX_BPF_STACK` at 512 bytes,
//! `check_max_stack_depth_subprog()` (159 LOC), `stack_extra`,
//! `fastcall_stack_off`, and then — retrofitted for recursion-prone tracing
//! programs — `priv_stack_ptr` with guard pages
//! (`bpf_jit_comp.c:1580,3762`), which is this module arrived at the long way
//! round.
//!
//! NARF reserves the region up front. Consequences:
//!
//! * the 512-byte limit disappears; the budget is a per-region size,
//! * `check_max_stack_depth` reduces to "does the static call graph fit",
//! * **re-entrancy becomes a depth counter, not a global recursion guard** —
//!   nesting to [`MAX_NEST`] is supported, and the next level *declines the
//!   program* rather than corrupting anything.
//!
//! ## This is not the only stack path
//!
//! Per §4.8 a *sleepable* program cannot hold a per-CPU slot across a yield —
//! another task may run on that CPU — so sleepable programs get a heap stack
//! owned by the future. That path is the BPF runtime's business, not this
//! module's; what matters here is that nothing below assumes it is the only
//! allocator. [`STACK_BYTES`] is public precisely so the heap path can size
//! itself identically and the verifier can use one bound.
//!
//! ## Guard pages are real
//!
//! Each CPU's slot is `guard | stack | guard`, and the guards are genuinely
//! unmapped VA — not merely poisoned bytes. That works because the region
//! lives inside the BPF kernel-VA slot whose top-level table
//! `bpf_text::reserve_kernel_slots` installs at boot (§4.1), so we control the
//! leaf mappings and can simply not create the guard ones. Overflowing the
//! region is a page fault at a known address, which the trap handler's
//! diagnostic names, rather than a silent scribble over the next CPU's frames.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use narf_lib::percpu::{current_cpu, MAX_CPUS};

use crate::bpf_text::{BPF_TEXT_BASE, BPF_TEXT_USABLE};
use crate::{PhysAddr, VirtAddr};

/// Usable stack bytes per CPU.
///
/// 64 KiB, i.e. 128× Linux's `MAX_BPF_STACK`. The number is not load-bearing —
/// it is a budget, and the verifier's job is to prove the static call graph
/// fits inside it.
pub const STACK_BYTES: u64 = 64 * 1024;

/// Guard bytes on each side of every CPU's stack. One page is enough: the
/// guard exists to turn an overflow into a fault, and a BPF frame can never
/// skip a whole page (the verifier bounds every frame).
pub const GUARD_BYTES: u64 = 4096;

/// VA footprint of one CPU's slot, guards included.
pub const SLOT_BYTES: u64 = STACK_BYTES + 2 * GUARD_BYTES;

/// Maximum nesting depth. Level `MAX_NEST + 1` declines the program.
///
/// Four is chosen the way Linux chose its `bpf_prog_active` semantics after
/// the fact: a tracing program can legitimately fire from inside a kfunc that
/// a tracing program is already running (an fentry on an allocator, say), and
/// two or three deep is realistic. Unbounded is not, because each level costs
/// a real [`STACK_BYTES`] of reserved VA.
pub const MAX_NEST: u32 = 4;

/// Base of the per-CPU stack region.
///
/// Placed in the second gibibyte-aligned half of the BPF kernel window, well
/// clear of the text packs (which are capped at
/// [`BPF_TEXT_USABLE`](crate::bpf_text::BPF_TEXT_USABLE) from the window base)
/// and inside the slot whose top-level table is reserved at boot. Keeping it
/// in the *same* PML4 slot as the text is deliberate: it inherits §4.1's
/// boot-order guarantee for free instead of needing a third reserved slot.
pub const STACK_REGION_BASE: u64 = BPF_TEXT_BASE + 2 * (1u64 << 30);

const _: () = assert!(
    STACK_REGION_BASE >= BPF_TEXT_BASE + BPF_TEXT_USABLE,
    "per-CPU BPF stacks overlap the text packs"
);
const _: () = assert!(
    STACK_REGION_BASE + (MAX_CPUS as u64) * SLOT_BYTES < BPF_TEXT_BASE + (1u64 << 39),
    "per-CPU BPF stacks overflow the BPF kernel window"
);

/// Failure modes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StackError {
    /// `bpf_text::reserve_kernel_slots` has not run.
    SlotsUnreserved,
    /// Frame allocator exhausted while backing the region.
    NoFrame,
    /// A page-table walk failed.
    MapFailed,
}

static READY: AtomicBool = AtomicBool::new(false);
/// Number of CPUs whose stack is actually backed. Populating lazily as APs
/// come up would be nicer, but the region is 64 CPUs × 64 KiB = 4 MiB at
/// worst and populating it once at boot keeps the fast path free of any
/// "is this CPU's stack mapped?" branch.
static BACKED_CPUS: AtomicUsize = AtomicUsize::new(0);

/// Base VA of `cpu`'s usable stack (lowest address; the stack grows down from
/// [`top_of`]).
#[inline]
pub const fn base_of(cpu: usize) -> u64 {
    STACK_REGION_BASE + (cpu as u64) * SLOT_BYTES + GUARD_BYTES
}

/// One past the highest usable byte of `cpu`'s stack — the value R10 is
/// initialised from for a depth-0 program.
#[inline]
pub const fn top_of(cpu: usize) -> u64 {
    base_of(cpu) + STACK_BYTES
}

/// `true` once [`init`] has backed the region.
#[inline]
pub fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Back the per-CPU stack region.
///
/// Call after `bpf_text::reserve_kernel_slots` and after the buddy is live.
/// Idempotent.
pub fn init(cpus: usize) -> Result<(), StackError> {
    if ready() {
        return Ok(());
    }
    if !crate::bpf_text::slots_reserved() {
        return Err(StackError::SlotsUnreserved);
    }
    let cpus = cpus.clamp(1, MAX_CPUS);
    for cpu in 0..cpus {
        let base = base_of(cpu);
        for i in 0..(STACK_BYTES / 4096) {
            let frame = crate::frame::alloc_frame().map_err(|_| StackError::NoFrame)?;
            // SAFETY: `base + i*4096` is fresh VA inside the reserved BPF
            // window (the const asserts above bound the region), and `frame`
            // was handed to us exclusively.
            unsafe { map_stack_page(base + i * 4096, frame.start_address())? };
        }
        // The pages on either side are simply never mapped. That *is* the
        // guard — see the module docs.
    }
    BACKED_CPUS.store(cpus, Ordering::Release);
    READY.store(true, Ordering::Release);
    Ok(())
}

// ── Depth counter ──────────────────────────────────────────────────────

/// Per-CPU nesting depth, cache-line isolated so two CPUs' counters never
/// share a line.
#[repr(align(64))]
struct DepthCell {
    inner: UnsafeCell<u32>,
}

// SAFETY: every access goes through `without_interrupts` on the owning CPU
// only — see `try_enter`. Exactly the argument `slab.rs`'s magazine array
// makes for the same shape.
unsafe impl Sync for DepthCell {}

static DEPTH: [DepthCell; MAX_CPUS] = [const {
    DepthCell {
        inner: UnsafeCell::new(0),
    }
}; MAX_CPUS];

/// A claimed nesting level. Releases on drop.
///
/// **`!Send` on purpose**, and it must be dropped inside the same
/// non-preemptible region that created it: the decrement is a per-CPU
/// non-atomic RMW, so a preempt-and-migrate between enter and exit would
/// decrement a *different* CPU's cell and permanently leak a level on this
/// one. `PhantomData<*const ()>` is what makes that a compile error rather
/// than a comment.
#[derive(Debug)]
pub struct StackLease {
    cpu: usize,
    /// Stack top for this nesting level. R10 starts here and grows down.
    top: u64,
    /// Usable bytes below `top` before the next level's frame begins.
    len: u64,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl StackLease {
    /// Highest address of this level's stack; R10's initial value.
    #[inline]
    pub fn top(&self) -> u64 {
        self.top
    }
    /// Bytes available below [`top`](Self::top).
    #[inline]
    pub fn len(&self) -> u64 {
        self.len
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// CPU this lease belongs to.
    #[inline]
    pub fn cpu(&self) -> usize {
        self.cpu
    }
}

impl Drop for StackLease {
    fn drop(&mut self) {
        // Mirror of `try_enter`: mask IRQs so the read-modify-write cannot be
        // interleaved by a nested program on this CPU, and so `current_cpu()`
        // is pinned across it.
        narf_lib::sync::without_interrupts(|| {
            let cpu = current_cpu();
            debug_assert_eq!(
                cpu, self.cpu,
                "StackLease dropped on a different CPU than it was taken on — \
                 the lease must not cross a preemption point"
            );
            // SAFETY: per-CPU access invariant — only the running CPU touches
            // its own cell, and IRQs are masked so no same-CPU re-entry can
            // alias this borrow.
            let d = unsafe { &mut *DEPTH[cpu].inner.get() };
            *d = d.saturating_sub(1);
        });
    }
}

/// Claim the next nesting level of this CPU's BPF stack.
///
/// Returns `None` when the region is not backed yet or when the depth limit is
/// reached — in which case the caller **declines the program**. Declining is
/// the whole point: Linux's global `bpf_prog_active` recursion guard turns the
/// same situation into "silently skip", and the retrofitted `priv_stack_ptr`
/// exists because skipping was not actually safe.
///
/// The read-modify-write is per-CPU and non-atomic, bracketed by
/// `without_interrupts` exactly as `slab.rs`'s magazine pop is. Masking does
/// two jobs, and both are load-bearing:
///
/// 1. a nested IRQ that runs a BPF program between our read and our write
///    would otherwise hand two levels the same stack range, and
/// 2. it pins `current_cpu()` for the duration, so a caller that arrived with
///    IRQs enabled cannot be preempted and migrated mid-update and end up
///    mutating CPU A's cell from CPU B.
///
/// When the caller already has IRQs masked (an IRQ handler, or an
/// `IrqSafeSpinLock` held — which is the normal case for an atomic BPF hook)
/// the save/restore nests to a no-op.
pub fn try_enter() -> Option<StackLease> {
    if !ready() {
        return None;
    }
    narf_lib::sync::without_interrupts(|| {
        let cpu = current_cpu();
        if cpu >= BACKED_CPUS.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: per-CPU access invariant, IRQs masked — see the doc comment.
        let d = unsafe { &mut *DEPTH[cpu].inner.get() };
        if *d >= MAX_NEST {
            return None;
        }
        let level = *d;
        *d = level + 1;

        // Each level gets an equal slice, carved from the top down. Equal
        // slices rather than a bump pointer because the *verifier* needs a
        // static bound per level, and "STACK_BYTES / MAX_NEST" is one it can
        // state without knowing the runtime nesting.
        let per_level = STACK_BYTES / (MAX_NEST as u64);
        let top = top_of(cpu) - (level as u64) * per_level;
        Some(StackLease {
            cpu,
            top,
            len: per_level,
            _not_send: core::marker::PhantomData,
        })
    })
}

/// Current nesting depth on this CPU. Diagnostic only.
pub fn depth() -> u32 {
    narf_lib::sync::without_interrupts(|| {
        let cpu = current_cpu();
        // SAFETY: per-CPU access invariant, IRQs masked.
        unsafe { *DEPTH[cpu].inner.get() }
    })
}

/// Bytes a single nesting level may use. The verifier's stack bound.
#[inline]
pub const fn bytes_per_level() -> u64 {
    STACK_BYTES / (MAX_NEST as u64)
}

// ── Mapping ────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn map_stack_page(va: u64, phys: PhysAddr) -> Result<(), StackError> {
    use crate::x86_64::paging::{map_4kb, PtFlags};
    let root = crate::bpf_text::kernel_root_for_mapping().ok_or(StackError::SlotsUnreserved)?;
    // RW, never executable, GLOBAL: the stack is identical under every CR3
    // (the top-level entry is snapshot-copied into every address space), so
    // there is nothing for a CR3 switch to invalidate.
    let flags = PtFlags::WRITABLE | PtFlags::NO_EXEC | PtFlags::GLOBAL;
    // SAFETY: `root` is the recorded kernel root whose BPF top-level entry
    // exists; `va` is fresh, page-aligned VA in that window.
    unsafe { map_4kb(root, VirtAddr::new(va), phys, flags).map_err(|_| StackError::MapFailed) }
}

#[cfg(target_arch = "aarch64")]
unsafe fn map_stack_page(va: u64, phys: PhysAddr) -> Result<(), StackError> {
    use crate::aarch64::paging::{map_4kb, PtFlags};
    let root = crate::bpf_text::kernel_root_for_mapping().ok_or(StackError::SlotsUnreserved)?;
    let flags = PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN;
    // SAFETY: same as the x86_64 arm.
    unsafe { map_4kb(root, VirtAddr::new(va), phys, flags).map_err(|_| StackError::MapFailed) }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn map_stack_page(_va: u64, _phys: PhysAddr) -> Result<(), StackError> {
    Err(StackError::MapFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_do_not_overlap_and_have_guards() {
        for cpu in 0..MAX_CPUS - 1 {
            // The gap between one stack's top and the next stack's base is
            // two guard pages.
            assert_eq!(base_of(cpu + 1) - top_of(cpu), 2 * GUARD_BYTES);
        }
    }

    #[test]
    fn per_level_slices_partition_the_region() {
        assert_eq!(bytes_per_level() * (MAX_NEST as u64), STACK_BYTES);
    }
}

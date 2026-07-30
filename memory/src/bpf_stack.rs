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

extern crate alloc as alloc_crate;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

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
///
/// **Atomic, not `UnsafeCell<u32>`.** It was the latter, guarded by
/// `without_interrupts` plus a claim that `StackLease` being `!Send` kept every
/// access on the owning CPU. `!Send` does not do that: it stops the *value*
/// being handed to another thread, and says nothing about the *task* being
/// timer-preempted and work-stolen onto another CPU between acquire and
/// release. The premise that used to close the gap — handlers running IRQ-masked
/// end to end — was removed when `tracing::dispatch::fire` started cloning the
/// `Arc` and dropping its lock before invoking.
///
/// With a plain RMW, a migrated release decremented whichever CPU was current:
/// the origin CPU leaked a level permanently (declining every later program once
/// it reached [`MAX_NEST`]) and the destination's count went below its true
/// value, so two live activations could be handed the *same* slice. `saturating_sub`
/// hid the underflow. An atomic makes a cross-CPU release merely unusual instead
/// of unsound, and costs one uncontended RMW per program — nothing against the
/// cost of running one.
#[repr(align(64))]
struct DepthCell {
    inner: AtomicU32,
}

static DEPTH: [DepthCell; MAX_CPUS] = [const {
    DepthCell {
        inner: AtomicU32::new(0),
    }
}; MAX_CPUS];

/// A claimed nesting level. Releases on drop.
///
/// `!Send` is kept — handing a lease to another executor is still not a thing
/// any caller should do — but correctness no longer *rests* on it. See
/// [`DepthCell`] for why it never could: the release always targets
/// [`Self::cpu`], the CPU the level was actually taken on, rather than whichever
/// CPU happens to be current at drop.
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
        // Release on the CPU the level was *taken* on — `self.cpu` — never on
        // whichever CPU is current now. Re-reading `current_cpu()` here was the
        // bug: it is the exact mistake `bpf/src/mem.rs` had already fixed on its
        // own release path (`release: Some((release_cpu, cpu))`), left in place
        // one file over and downgraded to a `debug_assert` that release builds —
        // which this tree now defaults to — compile out entirely.
        //
        // No `without_interrupts` needed: the counter is atomic, so a nested
        // program on this CPU cannot interleave the RMW, and there is nothing
        // left for masking to pin.
        //
        // `fetch_update` rather than `fetch_sub` so an underflow *cannot* be
        // papered over. A saturating decrement of a counter that is already zero
        // means two releases claimed the same level, which is a bookkeeping bug
        // worth leaving detectable rather than silently absorbing.
        let _ = DEPTH[self.cpu]
            .inner
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |d| d.checked_sub(1));
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
/// The claim is a single atomic `fetch_update`, so the level a caller receives
/// is unique by construction rather than by a masking argument. `IRQs` are still
/// masked around it, but now for one reason only: to pin `current_cpu()` long
/// enough that the level is charged to the CPU whose stack we hand out. Getting
/// *that* wrong is a mis-attribution, not a double-issue.
///
/// It used to be a non-atomic RMW resting on two claims — that masking excluded
/// a nested IRQ, and that `StackLease` being `!Send` excluded migration. The
/// second was false (see [`DepthCell`]), which is why this is atomic now.
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
        // Claim a level atomically. `fetch_update` returns the *previous* value
        // on success, which is exactly the level index we want, and declines
        // (rather than clamping) at the limit — declining is the whole point of
        // this design over Linux's global `bpf_prog_active`.
        let level = DEPTH[cpu]
            .inner
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |d| {
                if d >= MAX_NEST {
                    None
                } else {
                    Some(d + 1)
                }
            })
            .ok()?;

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
    narf_lib::sync::without_interrupts(|| DEPTH[current_cpu()].inner.load(Ordering::Acquire))
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

// ── In-kernel smokes ───────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// The region is backed and writable at both ends of a CPU's slice, and the
/// depth counter starts at zero.
fn smoke_bpf_stack_region_is_backed() -> TestResult {
    if init(MAX_CPUS).is_err() {
        return TestResult::Fail("bpf_stack::init failed");
    }
    if depth() != 0 {
        return TestResult::Fail("depth counter did not start at zero");
    }
    let cpu = narf_lib::percpu::current_cpu();
    let base = base_of(cpu);
    let top = top_of(cpu);
    // Touch the first and last usable words. Anything wrong with the mapping
    // (wrong root, wrong slot, off-by-a-page against the guards) faults here.
    // SAFETY: `[base, top)` was mapped RW by `init`; both accesses are inside
    // it and naturally aligned.
    unsafe {
        let lo = base as *mut u64;
        let hi = (top - 8) as *mut u64;
        lo.write_volatile(0xA5A5_A5A5_A5A5_A5A5);
        hi.write_volatile(0x5A5A_5A5A_5A5A_5A5A);
        if lo.read_volatile() != 0xA5A5_A5A5_A5A5_A5A5
            || hi.read_volatile() != 0x5A5A_5A5A_5A5A_5A5A
        {
            return TestResult::Fail("per-CPU BPF stack did not read back what was written");
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_bpf_stack_region_is_backed);

/// Nesting to [`MAX_NEST`] is supported; level `MAX_NEST + 1` **declines the
/// program** rather than handing out a slice that overlaps someone else's.
///
/// This is the whole difference from Linux's global `bpf_prog_active`
/// recursion guard, which turns the same situation into a silent skip.
fn smoke_bpf_stack_depth_declines_beyond_max() -> TestResult {
    if init(MAX_CPUS).is_err() {
        return TestResult::Fail("bpf_stack::init failed");
    }
    // Hold the whole nest inside one IRQ-masked region: a `StackLease` is
    // per-CPU state and must not cross a preemption point.
    narf_lib::sync::without_interrupts(|| {
        let mut held = alloc_crate::vec::Vec::new();
        for level in 0..MAX_NEST {
            match try_enter() {
                Some(l) => {
                    if depth() != level + 1 {
                        return TestResult::Fail("depth counter out of step with the lease count");
                    }
                    held.push(l);
                }
                None => return TestResult::Fail("declined a level within MAX_NEST"),
            }
        }
        // Levels must not overlap.
        for i in 1..held.len() {
            if held[i].top() + held[i].len() != held[i - 1].top() {
                return TestResult::Fail("nesting levels overlap or leave a gap");
            }
        }
        if try_enter().is_some() {
            return TestResult::Fail("MAX_NEST + 1 was granted");
        }
        drop(held);
        if depth() != 0 {
            return TestResult::Fail("dropping every lease did not return depth to zero");
        }
        TestResult::Pass
    })
}
kernel_test_in!("memory", smoke_bpf_stack_depth_declines_beyond_max);

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

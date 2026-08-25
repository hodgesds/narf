//! Cross-CPU TLB-shootdown IPI on x86_64.
//!
//! Mirrors the aarch64 SGI design: each sender publishes one request
//! in its source-owned lane, marks itself in every target CPU's pending
//! bitmap, sends x2APIC IPIs to newly non-empty targets, and waits for
//! every selected CPU to set its completion bit.
//!
//! Shootdowns synchronously wait for completion because callers may reclaim or
//! reuse a physical frame as soon as this function returns. The target bitmap
//! coalesces IPIs, but never coalesces distinct source requests or their ACKs.
//!
//! Vector: `VECTOR_TLB_SHOOTDOWN` (0xF0).

use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use narf_lib::percpu::MAX_CPUS;
use narf_lib::sync::IrqSafeSpinLock;

use crate::x86_64::apic;

/// One cache-line-sized request lane per source CPU. Every target of a
/// shootdown receives the same tuple, so storing a copy for every
/// `(target, source)` pair would waste roughly 100 KiB of static memory.
#[repr(C, align(64))]
struct RequestLane {
    va: AtomicU64,
    pages: AtomicU64,
    tag: AtomicU16,
    _pad: [u8; 46],
}

impl RequestLane {
    const fn new() -> Self {
        Self {
            va: AtomicU64::new(0),
            pages: AtomicU64::new(0),
            tag: AtomicU16::new(0),
            _pad: [0; 46],
        }
    }
}

const _: () = assert!(core::mem::size_of::<RequestLane>() == 64);
const _: () = assert!(MAX_CPUS <= u64::BITS as usize);

static REQUESTS: [RequestLane; MAX_CPUS] = [const { RequestLane::new() }; MAX_CPUS];

/// Bit `source` means that source CPU has a published request in this target's
/// slot. `fetch_or` coalesces concurrent publishers into one IPI; `swap(0)` in
/// the handler atomically claims the complete batch.
static PENDING_SENDERS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Per-source completion bitmap. Target CPU `n` sets bit `n` only after it has
/// applied that source's request. The source does not reuse its lane until all
/// requested target bits are visible.
static COMPLETED_TARGETS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Serialize only nested/concurrent publishers from the same CPU. Different
/// source CPUs retain fully parallel request lanes; the IRQ-safe guard also
/// prevents a local interrupt from reusing this CPU's lane mid-publication.
static OUTGOING: [IrqSafeSpinLock<()>; MAX_CPUS] = [const { IrqSafeSpinLock::new(()) }; MAX_CPUS];

/// Counter bumped when the handler takes the `INVPCID(tag, ...)`
/// branch (tag != 0 and `invpcid_supported()` reports true). Tests
/// sample this to confirm the tag-aware code path actually fires
/// rather than silently degrading to plain INVLPG.
static INVPCID_PATH_TAKEN: AtomicU64 = AtomicU64::new(0);

/// Read-back of the INVPCID-branch counter for tests + diagnostics.
pub fn invpcid_path_taken() -> u64 {
    INVPCID_PATH_TAKEN.load(Ordering::Relaxed)
}

/// Test helper: read the tag belonging to the first source pending for a CPU.
/// Observation is racy in a real SMP run; the tag-flow smoke publishes to a
/// peer without sending an IPI so it stays pending for sampling.
pub fn pending_tag(cpu: u32) -> u16 {
    let target = (cpu as usize).min(MAX_CPUS - 1);
    let sources = PENDING_SENDERS[target].load(Ordering::Acquire);
    if sources == 0 {
        return 0;
    }
    let source = sources.trailing_zeros() as usize;
    REQUESTS[source].tag.load(Ordering::Relaxed)
}

/// Test-only helper: publish (tag, va, pages) directly into this source CPU's
/// lane and mark it pending for a peer *without* sending the IPI. Lets the
/// "tag flows from sender to receiver" smoke observe the request
/// before any handler can clear it.
#[doc(hidden)]
pub fn __publish_for_test(cpu: u32, va: u64, pages: u64, tag: u16) {
    let target = (cpu as usize).min(MAX_CPUS - 1);
    let source = narf_lib::percpu::current_cpu().min(MAX_CPUS - 1);
    REQUESTS[source].tag.store(tag, Ordering::Relaxed);
    REQUESTS[source].pages.store(pages, Ordering::Relaxed);
    REQUESTS[source].va.store(va, Ordering::Relaxed);
    PENDING_SENDERS[target].fetch_or(1u64 << source, Ordering::Release);
}

/// Test-only helper: clear a peer CPU's pending bit and source lane. Used to
/// undo `__publish_for_test` so subsequent IPIs don't see stale
/// state.
#[doc(hidden)]
pub fn __clear_for_test(cpu: u32) {
    let target = (cpu as usize).min(MAX_CPUS - 1);
    let source = narf_lib::percpu::current_cpu().min(MAX_CPUS - 1);
    PENDING_SENDERS[target].fetch_and(!(1u64 << source), Ordering::AcqRel);
    REQUESTS[source].tag.store(0, Ordering::Relaxed);
    REQUESTS[source].pages.store(0, Ordering::Relaxed);
    REQUESTS[source].va.store(0, Ordering::Relaxed);
}

/// Per-CPU diagnostic counter. Incremented after each applied request; request
/// completion itself is tracked by `COMPLETED_TARGETS` so concurrent senders
/// cannot mistake another request's acknowledgement for their own.
static ACK_COUNT: [AtomicU64; MAX_CPUS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; MAX_CPUS]
};

/// Per-CPU "saw at least one shootdown" flag. Useful for tests that
/// need to confirm the IPI delivered without instrumenting the
/// counter at the broadcast site.
static EVER_RECEIVED: [AtomicU64; MAX_CPUS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; MAX_CPUS]
};

/// Read this CPU's accumulated shootdown count.
pub fn ack_count(cpu: u32) -> u64 {
    let i = (cpu as usize).min(MAX_CPUS - 1);
    ACK_COUNT[i].load(Ordering::Relaxed)
}

/// Read this CPU's ever-received counter (test helper).
pub fn ever_received(cpu: u32) -> u64 {
    let i = (cpu as usize).min(MAX_CPUS - 1);
    EVER_RECEIVED[i].load(Ordering::Relaxed)
}

/// Apply one request already claimed from this CPU's pending-source batch.
///
/// # Safety
/// CPL=0; the request fields were published before its source bit with release
/// ordering, and the handler claimed that bit with acquire ordering.
#[inline]
unsafe fn apply_request(va: u64, pages: u64, tag: u16) {
    // Three shapes:
    //   - tag != 0, va == 0  → "flush every TLB entry for this tag"
    //     (INVPCID type 1). Used by `shoot_tag_only`.
    //   - tag != 0, va != 0  → "flush (tag, va[..pages])"
    //     (INVPCID type 0 per page). The tag-aware fast path.
    //   - tag == 0, va != 0  → backwards-compat plain INVLPG over
    //     the range. Matches pre-tag behaviour for callers that
    //     don't know which PCID owns the mapping (the kernel-wide
    //     `invlpg_global` / `invlpg_global_range` hooks).
    //
    // Spec: `memory/specification/asid-pcid-isolation.md` §4.1.
    // INVPCID encoding per Intel SDM Vol 2 INVPCID instruction
    // reference; type semantics per SDM Vol 3 §4.10.4.
    if va == SHOOTDOWN_FULL_SENTINEL {
        // Full non-global flush (see `shoot_full`). INVPCID type-3 drops
        // every non-global entry across all PCIDs; without usable
        // INVPCID/PCIDE a CR3 reload covers the same ground (PCIDE=0 ⇒
        // everything lives in context 0).
        if narf_arch::x86_64::pcid::invpcid_supported() && narf_arch::x86_64::pcid::pcide_enabled()
        {
            // SAFETY: INVPCID gated on support + PCIDE.
            unsafe { narf_arch::x86_64::pcid::invpcid_all_without_globals() };
        } else {
            // SAFETY: CR3 reload at CPL=0 is always legal.
            unsafe {
                let c = narf_arch::x86_64::cr::read_cr3();
                narf_arch::x86_64::cr::write_cr3(c);
            }
        }
    } else if tag != 0 {
        // INVPCID with a NON-ZERO PCID descriptor requires BOTH the INVPCID
        // instruction AND CR4.PCIDE=1 — otherwise it #GP(0). A hypervisor can
        // expose INVPCID-the-instruction on a vCPU while NOT advertising PCID
        // (CPUID(1).ECX[17]): observed under QEMU `-cpu max`+KVM, where the BSP
        // gets PCIDE but the APs do not, so `enable_pcide()` no-op'd on the APs
        // and their CR4.PCIDE stayed 0. A tag-carrying shootdown broadcast then
        // #GP'd on every such AP (16 of them concurrently → a fatal-handler
        // soup that masqueraded as an unrelated SMP "heisenbug"). Gate on the
        // EXECUTING CPU's CR4.PCIDE, not just the instruction, and fall back to
        // a PCID-agnostic flush — a PCIDE-off CPU has no PCID-tagged entries, so
        // INVLPG (per-VA) or a CR3 reload (tag-only) covers the same ground.
        let invpcid_ok = narf_arch::x86_64::pcid::invpcid_supported()
            && narf_arch::x86_64::pcid::pcide_enabled();
        if invpcid_ok {
            INVPCID_PATH_TAKEN.fetch_add(1, Ordering::Relaxed);
            if va == 0 {
                // SAFETY: CPL=0; INVPCID gated above.
                unsafe {
                    narf_arch::x86_64::pcid::invpcid_single(tag);
                }
            } else {
                let n = if pages == 0 { 1 } else { pages };
                for k in 0..n {
                    let addr = va + k * 4096;
                    // SAFETY: same.
                    unsafe {
                        narf_arch::x86_64::pcid::invpcid_addr(tag, addr);
                    }
                }
            }
        } else if va != 0 {
            // CPU lacks INVPCID (very old silicon or hypervisor
            // masking the feature). Best effort: plain INVLPG over
            // the VA range. This drops the tag-scoping property
            // but keeps the broadcast useful — the local INVLPG
            // covers any tag's stale entry for that VA.
            let n = if pages == 0 { 1 } else { pages };
            for k in 0..n {
                let addr = va + k * 4096;
                // SAFETY: INVLPG at CPL=0 is always legal; the memory helper
                // supplies the mandatory compiler-fence pair.
                unsafe {
                    narf_memory::x86_64::paging::invlpg(narf_memory::VirtAddr::new(addr));
                }
            }
        } else {
            // Tag-only flush (va == 0) with no usable INVPCID/PCIDE on this CPU:
            // we can't selectively drop a single PCID, and this CPU has no
            // PCID-tagged entries anyway (CR4.PCIDE=0 ⟹ everything is PCID 0).
            // Reload CR3 to drop all non-global entries — the domain's mappings
            // (non-global) are covered. Mapping changes are boot-rare.
            // SAFETY: writing back the current CR3 at CPL=0 is always legal and
            // flushes non-global TLB entries.
            unsafe {
                let c = narf_arch::x86_64::cr::read_cr3();
                narf_arch::x86_64::cr::write_cr3(c);
            }
        }
    } else if va != 0 {
        let n = if pages == 0 { 1 } else { pages };
        for k in 0..n {
            let addr = va + k * 4096;
            // SAFETY: INVLPG at CPL=0 is always legal; the memory helper
            // supplies the mandatory compiler-fence pair.
            unsafe {
                narf_memory::x86_64::paging::invlpg(narf_memory::VirtAddr::new(addr));
            }
        }
    }
}

/// Drain every source request queued for this target CPU. Concurrent senders
/// own disjoint lanes, and the pending-source bitmap lets one IPI claim the
/// whole batch without losing a later publication.
///
/// # Safety
/// IRQ context or CPL=0 polling context only. Each claimed slot is published
/// before its source bit and is not reused until this handler acknowledges it.
#[inline]
pub unsafe fn on_shootdown_irq() {
    let target = narf_lib::percpu::current_cpu().min(MAX_CPUS - 1);
    let mut sources = PENDING_SENDERS[target].swap(0, Ordering::AcqRel);
    while sources != 0 {
        let source = sources.trailing_zeros() as usize;
        sources &= sources - 1;
        let request = &REQUESTS[source];
        let va = request.va.load(Ordering::Relaxed);
        let pages = request.pages.load(Ordering::Relaxed);
        let tag = request.tag.load(Ordering::Relaxed);

        // SAFETY: this source bit was acquired from PENDING_SENDERS, whose
        // release publication follows the complete request tuple.
        unsafe { apply_request(va, pages, tag) };

        EVER_RECEIVED[target].fetch_add(1, Ordering::Relaxed);
        ACK_COUNT[target].fetch_add(1, Ordering::Relaxed);
        COMPLETED_TARGETS[source].fetch_or(1u64 << target, Ordering::Release);
    }
}

/// Service a TLB shootdown a peer published to THIS cpu, if one is
/// pending, WITHOUT going through the IRQ handler. Returns immediately
/// when nothing is pending (so it never spuriously bumps the ack
/// counter).
///
/// Called from `shoot_range`'s ack-wait spin: a CPU sending a shootdown
/// spins for peer acknowledgements with IRQs masked (it is invoked while a
/// page-table lock is held). If two CPUs shoot down concurrently, each
/// would wait forever for the other's acknowledgement — the other can't take the
/// IPI with IRQs masked. Polling here lets each spinning sender service
/// the other's request directly, breaking the deadlock. A stray IPI that
/// later delivers finds the pending bitmap empty and is a no-op flush.
///
/// # Safety
/// CPL=0; consumes only this CPU's pending-source bitmap and source lanes.
#[inline]
pub unsafe fn poll_pending_shootdown() {
    let target = narf_lib::percpu::current_cpu().min(MAX_CPUS - 1);
    if PENDING_SENDERS[target].load(Ordering::Acquire) == 0 {
        return;
    }
    // SAFETY: same contract as the IRQ-path handler; this CPU owns the target
    // bitmap and every request was release-published before its source bit.
    unsafe {
        on_shootdown_irq();
    }
}

/// Broadcast a TLB-shootdown IPI to every CPU except the sender,
/// requesting an `INVLPG` for `va`. Spins until every online AP has
/// acknowledged this exact source-owned request. Different source CPUs can
/// publish concurrently; requests originating on one CPU are serialized.
///
/// # Safety
/// - x2APIC must be online on this CPU.
/// - VECTOR_TLB_SHOOTDOWN must be installed in the IDT (BSP does
///   this before calling `start_aps`).
/// - Caller must already have invalidated `va` on this CPU (locally
///   `INVLPG`'d) — this routine handles only the *other* CPUs.
pub unsafe fn shoot_va(va: u64, tag: u16) {
    // Single-page broadcast: pages = 0 sentinel = "1 page" in handler.
    // SAFETY: see shoot_range.
    unsafe {
        shoot_range(va, 1, tag);
    }
}

/// Published-VA sentinel requesting a FULL non-global TLB flush on the
/// receiver (INVPCID type-3 when available, CR3 reload otherwise).
/// `u64::MAX` is non-canonical, so it can never collide with a real
/// per-VA request.
pub const SHOOTDOWN_FULL_SENTINEL: u64 = u64::MAX;

/// Broadcast a FULL non-global TLB flush to every peer CPU — ONE IPI +
/// ack-wait for an arbitrarily large invalidation, the batch tail of a
/// whole-address-space PTE walk (fork COW WRITE-strip, exit teardown).
/// The caller is responsible for its own LOCAL flush.
///
/// # Safety
/// Same preconditions as `shoot_va`.
pub unsafe fn shoot_full() {
    // SAFETY: caller contract; the sentinel is routed by the handler and
    // the mask is narrowed to online peers by `shoot_range_mask`.
    unsafe {
        shoot_full_mask(u64::MAX);
    }
}

/// Targeted form of [`shoot_full`]. Only online peer CPUs selected by
/// `target_mask` receive the request and participate in the ACK wait.
///
/// # Safety
/// Same preconditions as [`shoot_full`].
pub unsafe fn shoot_full_mask(target_mask: u64) {
    // SAFETY: caller contract; the non-canonical sentinel cannot collide
    // with an ordinary VA request.
    unsafe {
        shoot_range_mask(SHOOTDOWN_FULL_SENTINEL, 1, 0, target_mask);
    }
}

/// Same shape as `shoot_va` but for a contiguous run of `pages`
/// 4 KiB pages starting at `va`. Receivers loop INVLPG over the
/// range — one IPI for N pages instead of N IPIs.
///
/// # Safety
/// Same preconditions as `shoot_va`.
pub unsafe fn shoot_range(va: u64, pages: u64, tag: u16) {
    // SAFETY: caller contract; `shoot_range_mask` removes self/offline bits.
    unsafe {
        shoot_range_mask(va, pages, tag, u64::MAX);
    }
}

/// Publish one source-owned request to selected online peers and wait until
/// every target has applied that exact request.
///
/// One source lane is sufficient because every selected target receives the
/// same tuple. The per-source lock prevents local nesting/reuse while allowing
/// different CPUs to publish concurrently. A target's pending-source bitmap
/// acts as a lossless queue and permits one IPI to drain several senders.
///
/// # Safety
/// Same preconditions as [`shoot_range`]. The request shape must be one
/// understood by [`apply_request`].
unsafe fn shoot_request_mask(va: u64, pages: u64, tag: u16, target_mask: u64) {
    let source = narf_lib::percpu::current_cpu().min(MAX_CPUS - 1);
    let source_bit = 1u64 << source;
    let targets = target_mask & narf_lib::smp::online_bitmap() & !source_bit;
    if targets == 0 {
        return;
    }

    // IRQs remain masked while this source lane is live. Besides preventing a
    // nested local publisher from reusing the tuple, that makes current_cpu()
    // stable until every selected target has acknowledged it.
    let _outgoing = OUTGOING[source].lock();

    COMPLETED_TARGETS[source].store(0, Ordering::Relaxed);
    let request = &REQUESTS[source];
    request.tag.store(tag, Ordering::Relaxed);
    request.pages.store(pages, Ordering::Relaxed);
    request.va.store(va, Ordering::Relaxed);

    // A release publication of the source bit makes the complete tuple visible
    // to the target's acquire swap. Only a transition from an empty target
    // bitmap needs a new IPI: an already-pending IPI/poller will drain the bit.
    let mut pending = targets;
    let mut kick = 0u64;
    while pending != 0 {
        let target = pending.trailing_zeros() as usize;
        pending &= pending - 1;
        if PENDING_SENDERS[target].fetch_or(source_bit, Ordering::Release) == 0 {
            kick |= 1u64 << target;
        }
    }
    if kick != 0 {
        apic::send_fixed_ipi(kick, crate::VECTOR_TLB_SHOOTDOWN);
    }

    // This wait must not time out and return: the caller may immediately reuse
    // a frame whose stale translation is still cached on a target CPU. Polling
    // incoming requests is necessary because the IRQ-safe guard masks local
    // interrupts and two simultaneous senders may otherwise wait on each other.
    while COMPLETED_TARGETS[source].load(Ordering::Acquire) & targets != targets {
        // SAFETY: CPL=0; consumes only this CPU's pending-source bitmap.
        unsafe { poll_pending_shootdown() };
        core::hint::spin_loop();
    }
}

/// Targeted range shootdown. Publishes the request and sends an x2APIC
/// fixed IPI only to online peer CPUs selected by `target_mask`; the ACK
/// wait covers exactly the same set. This is the sink for
/// `memory::tlb_shootdown`'s active-address-space filter.
///
/// # Safety
/// Same preconditions as [`shoot_range`]. Bits that do not identify an
/// online peer CPU are ignored.
pub unsafe fn shoot_range_mask(va: u64, pages: u64, tag: u16, target_mask: u64) {
    if va == 0 || pages == 0 {
        return;
    }
    // SAFETY: caller contract; validation above selects the range shape.
    unsafe { shoot_request_mask(va, pages, tag, target_mask) };
}

/// Broadcast a "flush every TLB entry tagged with `tag`" request to
/// every peer CPU. `va == 0` in the published cell signals the
/// handler to call `INVPCID(1, tag)` (Intel SDM Vol 2 INVPCID
/// type-1, "single-context invalidation"). Used when a domain's
/// PCID has been rolled over and every peer's view of that tag
/// must be flushed.
///
/// # Safety
/// Same preconditions as `shoot_range` (x2APIC online, vector
/// installed). `tag` must be a non-zero PCID (0 is the no-PCID
/// sentinel and would just be a no-op in the handler).
pub unsafe fn shoot_tag_only(tag: u16) {
    // SAFETY: caller contract; the targeted helper narrows the mask.
    unsafe {
        shoot_tag_only_mask(tag, u64::MAX);
    }
}

/// Targeted form of [`shoot_tag_only`]. Only selected online peers are
/// published to, interrupted, and awaited.
///
/// # Safety
/// Same preconditions as [`shoot_tag_only`].
pub unsafe fn shoot_tag_only_mask(tag: u16, target_mask: u64) {
    if tag == 0 {
        return;
    }
    // SAFETY: caller contract; (va=0, tag!=0) selects single-context flush.
    unsafe { shoot_request_mask(0, 0, tag, target_mask) };
}

/// Convenience wrapper for installing the shootdown handler on the
/// IDT. Done by the BSP after IDT init; APs share the IDT.
pub fn install() {
    crate::dispatch::install(crate::VECTOR_TLB_SHOOTDOWN, || {
        // SAFETY: handler is invoked from the IRQ-dispatch path where
        // the trap stub already saved registers and ack'd the LAPIC
        // is the caller's responsibility — we EOI at the end.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            on_shootdown_irq();
        }
    });
}

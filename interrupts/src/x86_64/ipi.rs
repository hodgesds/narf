//! Cross-CPU TLB-shootdown IPI on x86_64.
//!
//! Mirrors the aarch64 SGI design: the sender publishes a target VA
//! to a per-CPU "pending shootdown" cell, sends an x2APIC IPI with
//! the all-but-self destination shorthand, and waits for every
//! online AP to bump its ack counter past the pre-broadcast snapshot.
//!
//! Today's NARF mappings only mutate during boot and during driver
//! bring-up — calls are infrequent enough that a busy-wait on the
//! ack counter is fine. A future "lazy shootdown" optimisation can
//! batch invalidations.
//!
//! Vector: `VECTOR_TLB_SHOOTDOWN` (0xF0).

use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use narf_lib::percpu::MAX_CPUS;

use crate::x86_64::apic;

/// Per-CPU pending VA. The sender writes this *before* sending the
/// IPI; the handler reads, INVLPGs, then bumps the ack counter.
/// `0` = nothing pending (unmapped VA 0 is also #PF on access — not
/// a useful shootdown target).
static PENDING_VA: [AtomicU64; MAX_CPUS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; MAX_CPUS]
};

/// Per-CPU pending page count for `shoot_range`. When non-zero the
/// handler INVLPGs a contiguous range starting at PENDING_VA;
/// otherwise it INVLPGs a single page. `0` doubles as the "no
/// range pending" sentinel for the single-page path.
static PENDING_PAGES: [AtomicU64; MAX_CPUS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; MAX_CPUS]
};

/// Per-CPU pending PCID tag. `0` = "no tag — fall back to plain
/// INVLPG" (PCID 0 is the reserved no-PCID sentinel per
/// `arch/x86_64/pcid.rs`, so it never identifies a real domain).
/// A non-zero value drives the handler down the `INVPCID(tag, va)`
/// path (Intel SDM Vol 2 INVPCID instruction reference; SDM Vol 3
/// §4.10 cache + TLB behaviour). Stored as a separate `AtomicU16`
/// rather than packed into PENDING_PAGES so the publish ordering
/// stays a plain pair of release stores — the IRQ handler reads
/// the three slots under acquire and either both match or it picks
/// up the partial write and harmlessly INVLPGs the previous VA.
/// At 2 bytes per CPU the storage cost is trivial.
static PENDING_TAG: [AtomicU16; MAX_CPUS] = {
    const Z: AtomicU16 = AtomicU16::new(0);
    [Z; MAX_CPUS]
};

/// Counter bumped when the handler takes the `INVPCID(tag, ...)`
/// branch (tag != 0 and `invpcid_supported()` reports true). Tests
/// sample this to confirm the tag-aware code path actually fires
/// rather than silently degrading to plain INVLPG.
static INVPCID_PATH_TAKEN: AtomicU64 = AtomicU64::new(0);

/// Read-back of the INVPCID-branch counter for tests + diagnostics.
pub fn invpcid_path_taken() -> u64 {
    INVPCID_PATH_TAKEN.load(Ordering::Relaxed)
}

/// Test helper: read this CPU's pending tag slot. The handler clears
/// it after processing, so observation by tests is racy in a real SMP
/// run; the `smoke_ipi_shootdown_carries_tag_through` test publishes
/// to a *peer* slot without sending an IPI so the cell stays valid
/// for sampling.
pub fn pending_tag(cpu: u32) -> u16 {
    let i = (cpu as usize).min(MAX_CPUS - 1);
    PENDING_TAG[i].load(Ordering::Acquire)
}

/// Test-only helper: publish (tag, va, pages) directly into a peer
/// CPU's pending slot *without* sending the IPI. Lets the
/// "tag flows from sender to receiver slot" smoke observe the slot
/// before any handler can clear it.
#[doc(hidden)]
pub fn __publish_for_test(cpu: u32, va: u64, pages: u64, tag: u16) {
    let i = (cpu as usize).min(MAX_CPUS - 1);
    PENDING_TAG[i].store(tag, Ordering::Release);
    PENDING_PAGES[i].store(pages, Ordering::Release);
    PENDING_VA[i].store(va, Ordering::Release);
}

/// Test-only helper: clear a peer CPU's pending slot. Used to
/// undo `__publish_for_test` so subsequent IPIs don't see stale
/// state.
#[doc(hidden)]
pub fn __clear_for_test(cpu: u32) {
    let i = (cpu as usize).min(MAX_CPUS - 1);
    PENDING_TAG[i].store(0, Ordering::Release);
    PENDING_PAGES[i].store(0, Ordering::Release);
    PENDING_VA[i].store(0, Ordering::Release);
}

/// Per-CPU ack counter. Incremented by the handler after INVLPG.
/// Senders snapshot this before sending and spin until it advances
/// past the snapshot for every online AP.
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

/// Handler invoked from the trap path when VECTOR_TLB_SHOOTDOWN
/// fires on the current CPU. Reads the pending VA for this CPU,
/// runs INVLPG, then bumps the ack counter.
///
/// # Safety
/// IRQ context only; per-CPU PENDING_VA is written by the sender
/// before the IPI lands, so the read here observes the up-to-date
/// value (x2APIC IPI delivery serialises against the sending WRMSR).
#[inline]
pub unsafe fn on_shootdown_irq() {
    let cpu = narf_lib::percpu::current_cpu();
    let i = cpu.min(MAX_CPUS - 1);
    let va = PENDING_VA[i].load(Ordering::Acquire);
    let pages = PENDING_PAGES[i].load(Ordering::Acquire);
    let tag = PENDING_TAG[i].load(Ordering::Acquire);

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
    if tag != 0 {
        let invpcid_ok = narf_arch::x86_64::pcid::invpcid_supported();
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
                // SAFETY: INVLPG at CPL=0 is always legal.
                unsafe {
                    core::arch::asm!(
                        "invlpg [{a}]",
                        a = in(reg) addr,
                        options(nostack, preserves_flags),
                    );
                }
            }
        }
    } else if va != 0 {
        let n = if pages == 0 { 1 } else { pages };
        for k in 0..n {
            let addr = va + k * 4096;
            // SAFETY: INVLPG at CPL=0 is always legal.
            unsafe {
                core::arch::asm!(
                    "invlpg [{a}]",
                    a = in(reg) addr,
                    options(nostack, preserves_flags),
                );
            }
        }
    }
    // Clear the slots so subsequent stray fires don't re-flush.
    PENDING_VA[i].store(0, Ordering::Release);
    PENDING_PAGES[i].store(0, Ordering::Release);
    PENDING_TAG[i].store(0, Ordering::Release);
    EVER_RECEIVED[i].fetch_add(1, Ordering::Relaxed);
    ACK_COUNT[i].fetch_add(1, Ordering::Release);
}

/// Service a TLB shootdown a peer published to THIS cpu, if one is
/// pending, WITHOUT going through the IRQ handler. Returns immediately
/// when nothing is pending (so it never spuriously bumps the ack
/// counter).
///
/// Called from `shoot_range`'s ack-wait spin: a CPU sending a shootdown
/// spins for peer acks with IRQs masked (it is invoked while a
/// page-table lock is held). If two CPUs shoot down concurrently, each
/// would wait forever for the other's ack — the other can't take the
/// IPI with IRQs masked. Polling here lets each spinning sender service
/// the other's request directly, breaking the deadlock. A stray IPI that
/// later delivers finds the slot already cleared and is a no-op flush.
///
/// # Safety
/// CPL=0; consumes only this CPU's per-CPU `PENDING_*` cells.
#[inline]
pub unsafe fn poll_pending_shootdown() {
    let cpu = narf_lib::percpu::current_cpu();
    let i = cpu.min(MAX_CPUS - 1);
    // A real request is signalled by a non-zero VA or tag (publish order
    // is TAG → PAGES → VA, so observing either under acquire is enough).
    if PENDING_VA[i].load(Ordering::Acquire) == 0 && PENDING_TAG[i].load(Ordering::Acquire) == 0 {
        return;
    }
    // SAFETY: same contract as the IRQ-path handler; the per-CPU cells
    // are ours to consume and INVLPG/INVPCID at CPL=0 is always legal.
    unsafe {
        on_shootdown_irq();
    }
}

/// x2APIC ICR with delivery mode = Fixed, destination shorthand =
/// "all excluding self" (bits 19..=18 = 0b11), trigger = edge,
/// vector = `VECTOR_TLB_SHOOTDOWN`. Bit 14 (level=assert) is set
/// for compatibility with older docs even though x2APIC ignores it.
const ICR_BROADCAST_SHOOTDOWN: u64 = 0xC0 << 12               // dest shorthand = 0b11 (all-excluding-self) at bits[19:18]
    | (1 << 14)              // level = assert
    | (crate::VECTOR_TLB_SHOOTDOWN as u64); // vector

/// Broadcast a TLB-shootdown IPI to every CPU except the sender,
/// requesting an `INVLPG` for `va`. Spins until every online AP has
/// ack'd. Idempotent across multiple senders — each CPU's PENDING_VA
/// is per-target, so concurrent shootdowns on the same target VA are
/// safe; concurrent shootdowns on *different* VAs serialise on the
/// sender side.
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

/// Same shape as `shoot_va` but for a contiguous run of `pages`
/// 4 KiB pages starting at `va`. Receivers loop INVLPG over the
/// range — one IPI for N pages instead of N IPIs.
///
/// # Safety
/// Same preconditions as `shoot_va`.
pub unsafe fn shoot_range(va: u64, pages: u64, tag: u16) {
    if va == 0 || pages == 0 {
        return;
    }
    let total = narf_lib::smp::cpu_count();
    if total <= 1 {
        return;
    }

    let self_cpu = narf_lib::percpu::current_cpu() as u32;

    // Snapshot every other CPU's ack counter and publish the target
    // VA + range + tag. Publish order: TAG → PAGES → VA. The handler
    // reads in the same order under acquire, so when it sees a
    // non-zero VA the matching tag is already visible.
    let mut snap = [0u64; MAX_CPUS];
    for cpu in 0..total {
        if cpu == self_cpu {
            continue;
        }
        let i = (cpu as usize).min(MAX_CPUS - 1);
        snap[i] = ACK_COUNT[i].load(Ordering::Acquire);
        PENDING_TAG[i].store(tag, Ordering::Release);
        PENDING_PAGES[i].store(pages, Ordering::Release);
        PENDING_VA[i].store(va, Ordering::Release);
    }

    // Send the IPI. WRMSR is a serialising instruction so prior
    // PENDING_VA stores are visible to the receivers.
    // SAFETY: caller-asserted x2APIC online.
    unsafe {
        apic::wrmsr_icr(ICR_BROADCAST_SHOOTDOWN);
    }

    // Wait for every other online CPU to advance its ack counter.
    let mut spins: u32 = 0;
    for cpu in 0..total {
        if cpu == self_cpu {
            continue;
        }
        let i = (cpu as usize).min(MAX_CPUS - 1);
        while ACK_COUNT[i].load(Ordering::Acquire) == snap[i] {
            // Service any shootdown a peer published to US while we spin —
            // we hold IRQs masked here (a page-table lock is held by the
            // caller), so the IPI can't land, and a peer that is likewise
            // spinning for OUR ack would otherwise deadlock against us.
            // SAFETY: CPL=0; consumes only this CPU's pending cells.
            unsafe {
                poll_pending_shootdown();
            }
            // PAUSE hint to release the resource for the other
            // hyperthread / power down the spin.
            core::hint::spin_loop();
            spins = spins.wrapping_add(1);
            if spins > 10_000_000 {
                // Bail rather than hang forever — caller logs the
                // miss; in tests this surfaces as a timeout. In
                // production a missed shootdown leaves stale TLB
                // entries on the target CPU, which the next CR3
                // reload (or context switch) will paper over.
                break;
            }
        }
    }
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
    if tag == 0 {
        return;
    }
    let total = narf_lib::smp::cpu_count();
    if total <= 1 {
        return;
    }
    let self_cpu = narf_lib::percpu::current_cpu() as u32;
    let mut snap = [0u64; MAX_CPUS];
    for cpu in 0..total {
        if cpu == self_cpu {
            continue;
        }
        let i = (cpu as usize).min(MAX_CPUS - 1);
        snap[i] = ACK_COUNT[i].load(Ordering::Acquire);
        PENDING_VA[i].store(0, Ordering::Release);
        PENDING_PAGES[i].store(0, Ordering::Release);
        PENDING_TAG[i].store(tag, Ordering::Release);
    }
    // SAFETY: caller-asserted x2APIC online.
    unsafe {
        apic::wrmsr_icr(ICR_BROADCAST_SHOOTDOWN);
    }
    let mut spins: u32 = 0;
    for cpu in 0..total {
        if cpu == self_cpu {
            continue;
        }
        let i = (cpu as usize).min(MAX_CPUS - 1);
        while ACK_COUNT[i].load(Ordering::Acquire) == snap[i] {
            core::hint::spin_loop();
            spins = spins.wrapping_add(1);
            if spins > 10_000_000 {
                break;
            }
        }
    }
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

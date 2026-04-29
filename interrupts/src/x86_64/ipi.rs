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

use core::sync::atomic::{AtomicU64, Ordering};

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
    if va != 0 {
        // SAFETY: INVLPG at CPL=0 is always legal.
        unsafe {
            core::arch::asm!(
                "invlpg [{addr}]",
                addr = in(reg) va,
                options(nostack, preserves_flags),
            );
        }
        // Clear the slot so subsequent stray fires don't double-flush.
        PENDING_VA[i].store(0, Ordering::Release);
    }
    EVER_RECEIVED[i].fetch_add(1, Ordering::Relaxed);
    ACK_COUNT[i].fetch_add(1, Ordering::Release);
}

/// x2APIC ICR with delivery mode = Fixed, destination shorthand =
/// "all excluding self" (bits 19..=18 = 0b11), trigger = edge,
/// vector = `VECTOR_TLB_SHOOTDOWN`. Bit 14 (level=assert) is set
/// for compatibility with older docs even though x2APIC ignores it.
const ICR_BROADCAST_SHOOTDOWN: u64 =
    0xC0 << 12               // dest shorthand = 0b11 (all-excluding-self) at bits[19:18]
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
pub unsafe fn shoot_va(va: u64) {
    if va == 0 { return; }
    let total = narf_lib::smp::cpu_count() as u32;
    if total <= 1 { return; }

    let self_cpu = narf_lib::percpu::current_cpu() as u32;

    // Snapshot every other CPU's ack counter and publish the target VA.
    let mut snap = [0u64; MAX_CPUS];
    for cpu in 0..total {
        if cpu == self_cpu { continue; }
        let i = (cpu as usize).min(MAX_CPUS - 1);
        snap[i] = ACK_COUNT[i].load(Ordering::Acquire);
        PENDING_VA[i].store(va, Ordering::Release);
    }

    // Send the IPI. WRMSR is a serialising instruction so prior
    // PENDING_VA stores are visible to the receivers.
    // SAFETY: caller-asserted x2APIC online.
    unsafe { apic::wrmsr_icr(ICR_BROADCAST_SHOOTDOWN); }

    // Wait for every other online CPU to advance its ack counter.
    let mut spins: u32 = 0;
    for cpu in 0..total {
        if cpu == self_cpu { continue; }
        let i = (cpu as usize).min(MAX_CPUS - 1);
        while ACK_COUNT[i].load(Ordering::Acquire) == snap[i] {
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

/// Convenience wrapper for installing the shootdown handler on the
/// IDT. Done by the BSP after IDT init; APs share the IDT.
pub fn install() {
    crate::dispatch::install(crate::VECTOR_TLB_SHOOTDOWN, || {
        // SAFETY: handler is invoked from the IRQ-dispatch path where
        // the trap stub already saved registers and ack'd the LAPIC
        // is the caller's responsibility — we EOI at the end.
        unsafe { on_shootdown_irq(); }
    });
}

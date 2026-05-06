//! aarch64 CPU-identity primitive.
//!
//! Read `MPIDR_EL1` and project it through a small lookup that the
//! kernel populates during AP bring-up.
//!
//! ARM's `MPIDR_EL1` returns affinity bits (Aff0..Aff3) — not a
//! dense [0, N) index. The kernel's PerCpu storage wants a dense
//! index, so we keep a translation table populated at boot:
//! `MPIDR_AFF -> logical id`. Until AP bring-up lands the table
//! has one entry (BSP → 0) and `current_cpu()` always returns 0.

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

/// See `cpu::MAX_CPUS` in the cross-arch surface.
pub const MAX_CPUS: usize = 64;

/// Affinity-id → logical-id table. Initialised to all-1s (sentinel
/// "unmapped"). The BSP is registered at boot via
/// `set_current_cpu(mpidr_aff(), 0)`. Subsequent APs register
/// themselves on first entry.
static MPIDR_TABLE: [AtomicU32; MAX_CPUS] = {
    let mut t: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(u32::MAX) }; MAX_CPUS];
    // SAFETY: const-init places sentinel u32::MAX everywhere; the
    // populator writes real affinity values during AP bring-up.
    t[0] = AtomicU32::new(0); // BSP slot — mapped post-init
    t
};

/// Logical CPU id corresponding to the executing core.
///
/// Single-CPU today: returns 0 unconditionally. The MPIDR-walk path
/// stays compiled in (no `cfg`) so AP bring-up can flip the
/// behaviour by populating the table.
#[inline]
pub fn current_cpu() -> u32 {
    let aff = mpidr_aff();
    // Linear scan — N is small (<= MAX_CPUS = 64) and the table
    // is read-mostly.
    for (i, slot) in MPIDR_TABLE.iter().enumerate() {
        if slot.load(Ordering::Acquire) == aff {
            return i as u32;
        }
    }
    // BSP fallback — if the table hasn't been populated yet, all
    // executing CPUs are the BSP.
    0
}

/// Read MPIDR_EL1 and pack the affinity bits into a single u32:
///   bits[7:0]   = Aff0  (thread within core)
///   bits[15:8]  = Aff1  (core within cluster)
///   bits[23:16] = Aff2  (cluster within group)
///   bits[31:24] = Aff3  (group, MPIDR bits[39:32])
#[inline]
pub fn mpidr_aff() -> u32 {
    let mpidr: u64;
    // SAFETY: MRS MPIDR_EL1 is always legal at EL1.
    unsafe {
        asm!(
            "mrs {v}, mpidr_el1",
            v = out(reg) mpidr,
            options(nomem, nostack, preserves_flags),
        );
    }
    let aff0 = ((mpidr >> 0) & 0xFF) as u32;
    let aff1 = ((mpidr >> 8) & 0xFF) as u32;
    let aff2 = ((mpidr >> 16) & 0xFF) as u32;
    let aff3 = ((mpidr >> 32) & 0xFF) as u32;
    (aff3 << 24) | (aff2 << 16) | (aff1 << 8) | aff0
}

/// Register `(mpidr_aff, logical_id)` in the translation table.
///
/// # Safety
/// Must run on the CPU whose mapping is being set, exactly once
/// per AP during bring-up.
#[inline]
pub unsafe fn set_current_cpu(mpidr_aff: u32, logical: u32) {
    let slot = (logical as usize).min(MAX_CPUS - 1);
    MPIDR_TABLE[slot].store(mpidr_aff, Ordering::Release);
}

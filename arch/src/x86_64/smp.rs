//! SMP CPU bring-up — INIT/SIPI sequence + LAPIC ICR helpers.
//!
//! Spec: `arch/specification/smp-topology.md` §2. Wakes
//! application processors via the LAPIC ICR. The trampoline
//! image itself + the long-mode entry stub are caller-provided —
//! this module owns the LAPIC ICR write surface + the timing.
//!
//! Stage cut: ICR write helpers (xAPIC + x2APIC), ACPI MADT →
//! AP-id list extraction, single-AP `start_ap` blocking call.
//! The trampoline image (a 16-bit asm stub) is a `frame/` concern
//! and lands when the per-CPU GDT/IDT/TSS scaffolding does.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::x86_64::acpi;
use crate::x86_64::msr::wrmsr;

/// xAPIC ICR low offset (relative to LAPIC MMIO base).
pub const ICR_LO: u64 = 0x300;
/// xAPIC ICR high offset.
pub const ICR_HI: u64 = 0x310;

/// x2APIC ICR is a single 64-bit MSR.
pub const MSR_X2APIC_ICR: u32 = 0x830;

// ICR delivery / mode bits.
const DELIVERY_INIT: u32 = 0b101 << 8;
const DELIVERY_SIPI: u32 = 0b110 << 8;
const LEVEL_ASSERT:  u32 = 1 << 14;
const LEVEL_DEASSERT:u32 = 0;
const TRIGGER_LEVEL: u32 = 1 << 15;
const PHYS_DEST:     u32 = 0;

/// Issue an INIT-IPI (assert) to `apic_id` via xAPIC MMIO.
///
/// # Safety
/// Caller-owns the LAPIC MMIO window and is on the BSP.
pub unsafe fn xapic_init_assert(lapic_mmio: u64, apic_id: u32) {
    // SAFETY: caller-asserted.
    unsafe {
        core::ptr::write_volatile(
            (lapic_mmio + ICR_HI) as *mut u32,
            (apic_id & 0xFF) << 24,
        );
        core::ptr::write_volatile(
            (lapic_mmio + ICR_LO) as *mut u32,
            DELIVERY_INIT | LEVEL_ASSERT | TRIGGER_LEVEL | PHYS_DEST,
        );
    }
}

/// INIT-IPI deassert.
///
/// # Safety
/// Same as `xapic_init_assert`.
pub unsafe fn xapic_init_deassert(lapic_mmio: u64, apic_id: u32) {
    // SAFETY: caller-asserted.
    unsafe {
        core::ptr::write_volatile(
            (lapic_mmio + ICR_HI) as *mut u32,
            (apic_id & 0xFF) << 24,
        );
        core::ptr::write_volatile(
            (lapic_mmio + ICR_LO) as *mut u32,
            DELIVERY_INIT | LEVEL_DEASSERT | TRIGGER_LEVEL | PHYS_DEST,
        );
    }
}

/// SIPI to `apic_id` with `vector = trampoline_phys >> 12`. The
/// trampoline must live below 1 MiB (8-bit vector × 4 KiB).
///
/// # Safety
/// Same as `xapic_init_assert`.
pub unsafe fn xapic_sipi(lapic_mmio: u64, apic_id: u32, vector: u8) {
    // SAFETY: caller-asserted.
    unsafe {
        core::ptr::write_volatile(
            (lapic_mmio + ICR_HI) as *mut u32,
            (apic_id & 0xFF) << 24,
        );
        core::ptr::write_volatile(
            (lapic_mmio + ICR_LO) as *mut u32,
            DELIVERY_SIPI | LEVEL_ASSERT | PHYS_DEST | (vector as u32),
        );
    }
}

/// x2APIC INIT (assert). MSR-based; takes the full 32-bit APIC id.
///
/// # Safety
/// CPL = 0; x2APIC enabled.
pub unsafe fn x2apic_init_assert(apic_id: u32) {
    let v = ((apic_id as u64) << 32)
          | (DELIVERY_INIT | LEVEL_ASSERT | TRIGGER_LEVEL | PHYS_DEST) as u64;
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_X2APIC_ICR, v); }
}

/// x2APIC INIT deassert.
///
/// # Safety
/// CPL = 0; x2APIC enabled.
pub unsafe fn x2apic_init_deassert(apic_id: u32) {
    let v = ((apic_id as u64) << 32)
          | (DELIVERY_INIT | LEVEL_DEASSERT | TRIGGER_LEVEL | PHYS_DEST) as u64;
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_X2APIC_ICR, v); }
}

/// x2APIC SIPI.
///
/// # Safety
/// CPL = 0; x2APIC enabled.
pub unsafe fn x2apic_sipi(apic_id: u32, vector: u8) {
    let v = ((apic_id as u64) << 32)
          | (DELIVERY_SIPI | LEVEL_ASSERT | PHYS_DEST) as u64
          | (vector as u64);
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_X2APIC_ICR, v); }
}

/// Extract the list of AP APIC ids from an ACPI MADT snapshot.
/// The BSP's APIC id is excluded.
pub fn aps_from_madt(t: &acpi::Tables, bsp_apic_id: u32) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    for e in t.local_apics.iter().chain(t.io_apics.iter()) {
        match *e {
            acpi::MadtEntry::LocalApic { apic_id, flags, .. } => {
                if flags & 1 != 0 && apic_id as u32 != bsp_apic_id {
                    out.push(apic_id as u32);
                }
            }
            acpi::MadtEntry::LocalX2Apic { x2apic_id, flags, .. } => {
                if flags & 1 != 0 && x2apic_id != bsp_apic_id {
                    out.push(x2apic_id);
                }
            }
            _ => {}
        }
    }
    out
}

#[derive(Copy, Clone, Debug)]
pub struct ApBringUpResult {
    pub apic_id: u32,
    pub started: bool,
}

static ALIVE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Per-CPU "alive" hook — the AP's long-mode entrypoint calls
/// this to notify the BSP it has reached the kernel idle task.
pub fn mark_alive() {
    ALIVE_COUNT.fetch_add(1, Ordering::Release);
}

pub fn alive_count() -> u32 { ALIVE_COUNT.load(Ordering::Acquire) }

/// Issue the INIT/SIPI/SIPI sequence to `apic_id`. Returns
/// `started = false` if the AP didn't bump the alive counter
/// within the bounded poll. xAPIC variant.
///
/// # Safety
/// Caller is the BSP, owns the LAPIC MMIO window, and the
/// trampoline at `trampoline_phys` is callable.
pub unsafe fn start_ap_xapic(
    lapic_mmio: u64,
    apic_id:    u32,
    trampoline_phys: u64,
) -> ApBringUpResult {
    let baseline = alive_count();
    let vector = (trampoline_phys >> 12) as u8;
    // SAFETY: caller-asserted.
    unsafe {
        xapic_init_assert(lapic_mmio, apic_id);
    }
    busy_us(10_000);  // 10 ms
    // SAFETY: same.
    unsafe {
        xapic_init_deassert(lapic_mmio, apic_id);
    }
    busy_us(10_000);
    // SAFETY: same.
    unsafe { xapic_sipi(lapic_mmio, apic_id, vector); }
    busy_us(200);
    // SAFETY: same.
    unsafe { xapic_sipi(lapic_mmio, apic_id, vector); }
    // Wait up to ~100 ms for the AP to mark itself alive.
    let mut started = false;
    for _ in 0..100 {
        if alive_count() > baseline { started = true; break; }
        busy_us(1_000);
    }
    ApBringUpResult { apic_id, started }
}

fn busy_us(us: u64) {
    // Coarse busy-wait — a real implementation rides on the
    // calibrated TSC. Stage cut: count cycles assuming a 1 GHz
    // floor (TSC freq is at least 1 GHz on every CPU we care
    // about), so this `us` is at least real time.
    let cycles = us.saturating_mul(1_000);
    for _ in 0..cycles { core::hint::spin_loop(); }
}

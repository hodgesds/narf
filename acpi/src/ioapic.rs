//! IOAPIC (I/O Advanced Programmable Interrupt Controller)
//! programming primitives — clean-room.
//!
//! ## Sources (public only)
//!
//! - **ACPI Specification**, version 6.5, October 2022.
//!   <https://uefi.org/specs/ACPI/6.5/>
//!   - §5.2.12 (MADT) for IOAPIC discovery + ISA-override semantics
//!   - §5.2.9 (FADT.SCI_INT) for SCI routing requirements
//!     (level-triggered, active-low)
//! - **Intel 82093AA I/O Advanced Programmable Interrupt
//!   Controller (IOAPIC) Datasheet**, May 1996, document
//!   number 290566-001.
//!   <https://web.archive.org/web/20171128104420/https://pdos.csail.mit.edu/6.828/2016/readings/ia32/ioapic.pdf>
//!   - §3.0 (Memory Address Format / IOREGSEL + IOWIN)
//!   - §3.2 (Register list — IOAPICID / IOAPICVER / IOREDTBL[])
//!   - §3.2.4 (I/O Redirection Table layout)
//!
//! ## Register access
//!
//! Each IOAPIC sits at a 4 KiB MMIO window. Two registers live in
//! the window — IOREGSEL at offset 0x00 (write the index of the
//! register you want), IOWIN at offset 0x10 (then read or write
//! that register). IOREDTBL[N] is two 32-bit registers at indices
//! `0x10 + 2*N` (low) and `0x10 + 2*N + 1` (high).
//!
//! Locked across the [select, access] pair because the (REGSEL,
//! WIN) pair is shared state — concurrent CPUs would clobber the
//! select register. Single-CPU at boot today; the lock keeps the
//! shape correct for SMP.

#![cfg(target_arch = "x86_64")]

use narf_lib::sync::IrqSafeSpinLock;

/// IOREGSEL offset — write the register index you want to touch.
const REG_IOREGSEL: u64 = 0x00;
/// IOWIN offset — read/write the register selected by IOREGSEL.
const REG_IOWIN: u64 = 0x10;

/// IOAPIC register indices we care about (Intel 82093AA §3.2).
const IDX_IOAPICID: u32 = 0x00;
const IDX_IOAPICVER: u32 = 0x01;
const IDX_IOREDTBL_BASE: u32 = 0x10;

/// Polarity bit position in IOREDTBL low dword. 0 = active-high,
/// 1 = active-low. ACPI requires active-low for SCI; ISA overrides
/// in MADT carry the polarity per pin in their flags field.
pub const POLARITY_HIGH: u32 = 0;
pub const POLARITY_LOW: u32 = 1 << 13;

/// Trigger-mode bit. 0 = edge-triggered, 1 = level-triggered.
/// SCI must be level-triggered.
pub const TRIGGER_EDGE: u32 = 0;
pub const TRIGGER_LEVEL: u32 = 1 << 15;

/// Mask bit. 1 = masked (no delivery).
pub const MASKED: u32 = 1 << 16;

/// Delivery mode FIXED (vector chosen by software, normal IDT
/// dispatch).
const DELIVERY_FIXED: u32 = 0 << 8;

/// Destination mode PHYSICAL (low byte of high dword == APIC ID).
const DEST_MODE_PHYS: u32 = 0 << 11;

/// Per-IOAPIC handle. Holds the MMIO base + the GSI range it
/// owns; the lock serialises (REGSEL, WIN) access pairs. Cloning
/// the handle is fine — the inner state is `Copy` and the lock
/// is keyed off the static.
#[derive(Copy, Clone, Debug)]
pub struct IoApicHandle {
    /// MMIO base — physical address. Identity-mapped on x86_64
    /// in the legacy MMIO hole below 4 GiB.
    pub base_phys: u64,
    /// First Global System Interrupt this IOAPIC owns.
    pub gsi_base: u32,
    /// Last GSI inclusive (`gsi_base + max_redir_entry`).
    pub gsi_end: u32,
}

/// Coarse lock around the (REGSEL, WIN) pair. One lock covers
/// every IOAPIC in the system because the few-microseconds
/// boot-time programming we do here doesn't justify per-IOAPIC
/// locks.
static IOAPIC_LOCK: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// Probe the IOAPIC at `base_phys`. Reads IOAPICVER to determine
/// `max_redir_entry` (which `gsi_end` is computed from).
///
/// # Safety
/// `base_phys` must point at a real IOAPIC MMIO window the CPU
/// can reach. Identity-mapped + uncached on x86_64.
pub unsafe fn probe(base_phys: u64, gsi_base: u32) -> IoApicHandle {
    let _g = IOAPIC_LOCK.lock();
    // SAFETY: caller asserts MMIO window. Sequence is REGSEL
    // write → IOWIN read of IOAPICVER. High byte of returned
    // dword holds Maximum Redirection Entry (a 0-based index;
    // total entry count is +1).
    let ver = unsafe { read_reg_locked(base_phys, IDX_IOAPICVER) };
    let max_entry = (ver >> 16) & 0xFF;
    IoApicHandle {
        base_phys,
        gsi_base,
        gsi_end: gsi_base + max_entry,
    }
}

/// Program redirection-table entry for `gsi` to deliver `vector`
/// to APIC id `dest_apic` with the given polarity + trigger mode
/// + mask state. Returns `false` if the GSI doesn't fall within
///   this IOAPIC's range.
///
/// `flags` is `POLARITY_* | TRIGGER_* | MASKED?` (bits 13/15/16).
/// Other bits in the low dword (vector, delivery mode, dest mode)
/// are filled in here.
///
/// # Safety
/// Caller asserts the IOAPIC is live + the vector is one
/// `narf_interrupts` is willing to dispatch.
pub unsafe fn program_entry(
    h: &IoApicHandle,
    gsi: u32,
    vector: u8,
    dest_apic: u8,
    flags: u32,
) -> bool {
    if gsi < h.gsi_base || gsi > h.gsi_end {
        return false;
    }
    let entry_index = gsi - h.gsi_base;
    let low_idx = IDX_IOREDTBL_BASE + 2 * entry_index;
    let high_idx = low_idx + 1;
    let low = (vector as u32) | DELIVERY_FIXED | DEST_MODE_PHYS | (flags & 0x0001_F000);
    // Mask bit also lives in the low dword (bit 16).
    let low = low | (flags & MASKED);
    let high = (dest_apic as u32) << 24;

    let _g = IOAPIC_LOCK.lock();
    // Spec §3.2.4 recommends programming HIGH first then LOW so
    // the destination is in place before delivery is unmasked
    // (LOW bit 16 = mask). For our boot-time write the order is
    // not racy (single CPU, no IRQ in flight) but matching the
    // recommendation costs nothing.
    // SAFETY: caller-asserted live IOAPIC; locked.
    unsafe {
        write_reg_locked(h.base_phys, high_idx, high);
        write_reg_locked(h.base_phys, low_idx, low);
    }
    true
}

/// Mask a redirection-table entry without changing its other
/// fields. Useful for graceful disable on shutdown.
///
/// # Safety
/// Same as `program_entry`.
pub unsafe fn mask(h: &IoApicHandle, gsi: u32) {
    if gsi < h.gsi_base || gsi > h.gsi_end {
        return;
    }
    let entry_index = gsi - h.gsi_base;
    let low_idx = IDX_IOREDTBL_BASE + 2 * entry_index;
    let _g = IOAPIC_LOCK.lock();
    // SAFETY: caller-asserted live IOAPIC; locked.
    unsafe {
        let cur = read_reg_locked(h.base_phys, low_idx);
        write_reg_locked(h.base_phys, low_idx, cur | MASKED);
    }
}

// ── Locked register access ─────────────────────────────────────────
//
// Internal helpers — caller must hold `IOAPIC_LOCK`.

#[inline]
unsafe fn read_reg_locked(base_phys: u64, index: u32) -> u32 {
    // SAFETY: caller-asserted live IOAPIC + locked. REGSEL +
    // IOWIN are both naturally aligned 32-bit MMIO registers.
    unsafe {
        core::ptr::write_volatile((base_phys + REG_IOREGSEL) as *mut u32, index);
        core::ptr::read_volatile((base_phys + REG_IOWIN) as *const u32)
    }
}

#[inline]
unsafe fn write_reg_locked(base_phys: u64, index: u32, value: u32) {
    // SAFETY: caller-asserted live IOAPIC + locked.
    unsafe {
        core::ptr::write_volatile((base_phys + REG_IOREGSEL) as *mut u32, index);
        core::ptr::write_volatile((base_phys + REG_IOWIN) as *mut u32, value);
    }
}

/// Read IOAPICID — the high 4 bits of register 0 hold the chip's
/// APIC ID (Intel 82093AA §3.2.1). Mostly diagnostic.
///
/// # Safety
/// Caller-asserted live IOAPIC.
pub unsafe fn read_id(h: &IoApicHandle) -> u8 {
    let _g = IOAPIC_LOCK.lock();
    // SAFETY: locked.
    let v = unsafe { read_reg_locked(h.base_phys, IDX_IOAPICID) };
    ((v >> 24) & 0x0F) as u8
}

/// One-stop GSI → vector router: walks the MADT-discovered IOAPICs,
/// finds the one whose range covers `gsi`, probes it, and programs
/// its redirection-table entry to deliver `vector` to `dest_apic`
/// with the given polarity / trigger / mask flags. Returns `true`
/// on success.
///
/// Replaces the per-driver pattern of (probe IOAPIC, find covering,
/// call program_entry) — used by `narf-drivers-platform::ec`'s SCI
/// install and by the xHCI INTx fallback. Constants for `flags` live
/// in this module: `POLARITY_*`, `TRIGGER_*`, `MASKED`.
///
/// # Safety
/// Caller asserts `vector` is one `narf_interrupts` is willing to
/// dispatch (typically freshly allocated via `vector::alloc`), and
/// that the corresponding handler is installed before this routes
/// the line — otherwise the next IRQ delivery hits an unconfigured
/// dispatch slot.
pub unsafe fn route_gsi_to_vector(gsi: u32, vector: u8, dest_apic: u8, flags: u32) -> bool {
    let mut ioapics = [crate::IoApic::default(); crate::MAX_IOAPICS];
    let n = crate::copy_ioapics(&mut ioapics);
    for io in &ioapics[..n] {
        // SAFETY: IOAPIC base from a checksummed MADT.
        let h = unsafe { probe(io.address as u64, io.gsi_base) };
        if gsi >= h.gsi_base && gsi <= h.gsi_end {
            // SAFETY: handle freshly probed; caller asserts vector
            // + handler readiness.
            return unsafe { program_entry(&h, gsi, vector, dest_apic, flags) };
        }
    }
    false
}

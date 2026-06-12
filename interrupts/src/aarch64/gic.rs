//! GICv3 initialisation for the BSP on QEMU virt.
//!
//! Hybrid access: the *distributor* uses MMIO at `0x0800_0000`; the
//! *redistributor* uses MMIO at `0x080A_0000` for CPU 0 on QEMU virt;
//! the *CPU interface* uses system registers (`ICC_*_EL1`).
//!
//! Stage-2 scope: bring the BSP into a state where the generic-timer
//! PPI (INTID 30) can deliver IRQs. SMP AP bring-up + SPI (shared
//! peripheral interrupt) routing are later waves.

use narf_arch::aarch64::mmio::{read_u32, write_u32};
use narf_arch::aarch64::sysreg;

/// QEMU virt GICv3 distributor MMIO base.
const GICD_BASE: usize = 0x0800_0000;
/// QEMU virt GICv3 CPU-0 redistributor MMIO base.
const GICR_BASE: usize = 0x080A_0000;
/// Per-CPU redistributor stride. GICv3 lays each CPU's RD frame
/// 128 KiB apart on QEMU virt.
const GICR_STRIDE: usize = 0x2_0000;

/// Compute the GICR base for a given logical CPU index.
#[inline]
pub fn gicr_base(cpu_index: u32) -> usize {
    GICR_BASE + (cpu_index as usize) * GICR_STRIDE
}

// Distributor register offsets (SDM of GICv3: IHI0069H).
const GICD_CTLR: usize = 0x0000;

// Redistributor register offsets.
const GICR_WAKER: usize = 0x0014;
// SGI_base is at GICR_BASE + 0x1_0000.
const GICR_SGI_OFF: usize = 0x1_0000;
const GICR_IGROUPR0_OFF: usize = GICR_SGI_OFF + 0x0080;
const GICR_ISENABLER0_OFF: usize = GICR_SGI_OFF + 0x0100;
const GICR_IPRIORITYR0_OFF: usize = GICR_SGI_OFF + 0x0400;

/// Initialise the BSP CPU's GICv3 view + enable Group 1 IRQs.
///
/// # Safety
/// - Must run on the BSP, exactly once, at EL1.
/// - GICv3 system-register interface must be available
///   (CPUID: `Features::probe().gicv3_sysreg`).
/// - Interrupts must be disabled in DAIF at call time.
pub unsafe fn init_bsp() {
    // SAFETY: BSP-only init does both the CPU-shared distributor
    // and CPU 0's redistributor + cpu interface.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        init_distributor();
        init_per_cpu(0);
    }
}

/// Per-CPU GICv3 init for an AP. Wakes its redistributor + sets up
/// the EL1 CPU interface + enables the timer PPI.
///
/// # Safety
/// - Must run on the CPU whose `cpu_index` is passed (this is the
///   only place where IRQ delivery for that CPU gets enabled).
/// - GICv3 system-register interface must be available.
/// - Interrupts must be disabled in DAIF at call time.
pub unsafe fn init_ap(cpu_index: u32) {
    // SAFETY: caller-asserted per-CPU invariant.
    unsafe {
        init_per_cpu(cpu_index);
    }
}

/// Distributor-side init (CPU-shared). Only the BSP runs this.
unsafe fn init_distributor() {
    // GICD_CTLR: enable Group 1 NS (bit 1). ARE_NS (bit 4) for
    // affinity routing.
    // SAFETY: identity-mapped MMIO.
    unsafe {
        write_u32((GICD_BASE + GICD_CTLR) as *mut u32, (1 << 4) | (1 << 1));
    }
}

/// CPU-private init: cpu interface (system registers) + the named
/// CPU's redistributor + timer PPI.
unsafe fn init_per_cpu(cpu_index: u32) {
    // ─── CPU interface (system registers) ───────────────────────
    // SAFETY: GICv3 presence verified by caller.
    unsafe {
        sysreg::write_icc_sre_el1(1);
    }
    // SAFETY: SRE set above.
    unsafe {
        sysreg::write_icc_pmr_el1(0xFF);
    }
    // SAFETY: SRE set above.
    unsafe {
        sysreg::write_icc_igrpen1_el1(1);
    }

    // ─── Redistributor ────────────────────────────────────────
    let gicr = gicr_base(cpu_index);
    // Clear ProcessorSleep (bit 1 of GICR_WAKER). Then poll
    // ChildrenAsleep (bit 2) until 0.
    // SAFETY: identity-mapped MMIO; gicr is per-CPU stride.
    unsafe {
        let waker = (gicr + GICR_WAKER) as *mut u32;
        let cur = read_u32(waker);
        write_u32(waker, cur & !(1 << 1));
        while read_u32(waker) & (1 << 2) != 0 {
            core::hint::spin_loop();
        }
    }

    // Put SGIs + PPIs in Group 1 NS.
    // SAFETY: same MMIO window.
    unsafe {
        write_u32((gicr + GICR_IGROUPR0_OFF) as *mut u32, 0xFFFF_FFFF);
    }

    // Set priority for the timer PPI (INTID 30) — byte-addressable.
    // SAFETY: same.
    unsafe {
        let prio = (gicr + GICR_IPRIORITYR0_OFF + 30) as *mut u8;
        core::ptr::write_volatile(prio, 0xA0);
    }

    // Enable the timer PPI + every SGI (INTID 0..15). SGIs are
    // already in Group 1 via IGROUPR0 above; ISENABLER0 must be
    // set per bit to actually deliver. Each SGI also needs a
    // priority below the PMR mask (0xFF) — we set 0xA0 like the
    // timer.
    // SAFETY: identity-mapped MMIO.
    unsafe {
        // Priority for SGIs 0..15.
        for sgi in 0..16u64 {
            let prio = (gicr + GICR_IPRIORITYR0_OFF + sgi as usize) as *mut u8;
            core::ptr::write_volatile(prio, 0xA0);
        }
        // Enable timer PPI + all SGIs.
        let mask = (1u32 << super::TIMER_PPI) | 0x0000_FFFF;
        write_u32((gicr + GICR_ISENABLER0_OFF) as *mut u32, mask);
    }
}

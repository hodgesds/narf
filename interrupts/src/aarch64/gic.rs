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

// Distributor register offsets (SDM of GICv3: IHI0069H).
const GICD_CTLR:     usize = 0x0000;

// Redistributor register offsets.
const GICR_WAKER:        usize = 0x0014;
// SGI_base is at GICR_BASE + 0x1_0000.
const GICR_SGI_OFF:          usize = 0x1_0000;
const GICR_IGROUPR0_OFF:     usize = GICR_SGI_OFF + 0x0080;
const GICR_ISENABLER0_OFF:   usize = GICR_SGI_OFF + 0x0100;
const GICR_IPRIORITYR0_OFF:  usize = GICR_SGI_OFF + 0x0400;

/// Initialise the BSP CPU's GICv3 view + enable Group 1 IRQs.
///
/// # Safety
/// - Must run on the BSP, exactly once, at EL1.
/// - GICv3 system-register interface must be available
///   (CPUID: `Features::probe().gicv3_sysreg`).
/// - Interrupts must be disabled in DAIF at call time.
pub unsafe fn init_bsp() {
    // ─── CPU interface (system registers) ───────────────────────
    // Enable system-register access (ICC_SRE_EL1.SRE = 1, DIB = DFB = 0
    // for now — we don't use FIQ-binary bypass).
    // SAFETY: GICv3 presence verified by caller.
    unsafe { sysreg::write_icc_sre_el1(1); }

    // Allow all priorities to pass.
    // SAFETY: SRE set above.
    unsafe { sysreg::write_icc_pmr_el1(0xFF); }

    // Enable Group 1 (non-secure) IRQs.
    // SAFETY: SRE set above.
    unsafe { sysreg::write_icc_igrpen1_el1(1); }

    // ─── Distributor ────────────────────────────────────────────
    // GICD_CTLR: enable Group 1 NS (bit 1). ARE_NS (bit 4) should be
    // set on GICv3 for affinity routing. Bits 5+ reserved.
    // SAFETY: MMIO to GIC distributor, identity-mapped in our PML4.
    unsafe {
        write_u32((GICD_BASE + GICD_CTLR) as *mut u32, (1 << 4) | (1 << 1));
    }

    // ─── Redistributor (CPU 0) ─────────────────────────────────
    // Clear ProcessorSleep (bit 1 of GICR_WAKER). Then poll
    // ChildrenAsleep (bit 2) until 0.
    // SAFETY: MMIO to GIC redistributor.
    unsafe {
        let waker = (GICR_BASE + GICR_WAKER) as *mut u32;
        let cur = read_u32(waker);
        write_u32(waker, cur & !(1 << 1));
        while read_u32(waker) & (1 << 2) != 0 {
            core::hint::spin_loop();
        }
    }

    // Put SGIs + PPIs in Group 1 NS (all bits set).
    // SAFETY: MMIO; single 32-bit register covers INTID 0..=31.
    unsafe {
        write_u32(
            (GICR_BASE + GICR_IGROUPR0_OFF) as *mut u32,
            0xFFFF_FFFF,
        );
    }

    // Set priority for the timer PPI (INTID 30) — byte-addressable.
    // Priority 0xA0 (below the 0xFF mask). Kernel convention: timer is
    // lower priority than "urgent" kernel work.
    // SAFETY: MMIO; byte store at INTID-indexed offset.
    unsafe {
        let prio = (GICR_BASE + GICR_IPRIORITYR0_OFF + 30) as *mut u8;
        core::ptr::write_volatile(prio, 0xA0);
    }

    // Enable the timer PPI.
    // SAFETY: MMIO; bit 30 of GICR_ISENABLER0.
    unsafe {
        write_u32(
            (GICR_BASE + GICR_ISENABLER0_OFF) as *mut u32,
            1 << super::TIMER_PPI,
        );
    }
}

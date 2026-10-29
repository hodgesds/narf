//! aarch64 interrupt-controller backend (GICv2 / GICv3 + generic timer).

pub mod gic;
pub mod its;
pub mod sgi;
pub mod timer;

pub use gic::init_bsp;
pub use timer::{on_timer_tick, start_timer, stop_timer, timer_ticks};

/// aarch64 generic-timer PPI (private-peripheral IRQ). INTID 30 is the
/// standard EL1 physical-timer entry across GICv2/GICv3 and QEMU virt.
pub const TIMER_PPI: u32 = 30;

/// INTID the CPU interface returns when nothing is pending (both
/// versions). The trap path must not EOI it.
pub const SPURIOUS_INTID: u32 = 1023;

/// Acknowledge the highest-priority pending IRQ and return the raw
/// acknowledge value, to be handed back unchanged to [`eoi_for`].
///
/// GICv3: `ICC_IAR1_EL1`. GICv2: MMIO `GICC_IAR` (whose SGI values carry
/// the source CPU in bits [12:10], which the EOI must echo). The backend
/// is the one `gic::probe` selected at boot; the only per-trap cost over
/// the old GICv3-only path is one load + branch on that static. Both
/// arms use `narf_arch` accessors fenced with `compiler_fence(SeqCst)`
/// before and after (AGENTS.md invariant #4).
///
/// # Safety
/// Must be called from the IRQ vector, on a CPU whose GIC CPU interface
/// was initialised (`gic::init_bsp` / `gic::init_ap`).
#[inline(always)]
pub unsafe fn ack_irq() -> u64 {
    if gic::is_v2() {
        // SAFETY: caller contract.
        u64::from(unsafe { gic::v2_ack() })
    } else {
        // SAFETY: caller contract; GICv3 sysreg interface verified by probe.
        unsafe { narf_arch::aarch64::sysreg::read_icc_iar1_el1() }
    }
}

/// INTID field of an [`ack_irq`] value: bits [9:0] on GICv2, [23:0] on
/// GICv3 (LPIs).
#[inline(always)]
pub fn iar_intid(iar: u64) -> u32 {
    if gic::is_v2() {
        (iar & 0x3FF) as u32
    } else {
        (iar & 0x00FF_FFFF) as u32
    }
}

/// End-of-interrupt for the caller's acknowledged IRQ: `ICC_EOIR1_EL1`
/// (GICv3) or `GICC_EOIR` (GICv2).
///
/// # Safety
/// `iar` must be the value a prior [`ack_irq`] returned on this CPU, from
/// inside the same IRQ handler.
#[inline(always)]
pub unsafe fn eoi_for(iar: u64) {
    if gic::is_v2() {
        // SAFETY: caller contract.
        unsafe { gic::v2_eoi(iar as u32) }
    } else {
        // SAFETY: caller contract.
        unsafe { narf_arch::aarch64::sysreg::write_icc_eoir1_el1(iar) }
    }
}

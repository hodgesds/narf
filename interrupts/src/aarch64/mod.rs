//! aarch64 interrupt-controller backend (GICv3 + generic timer).

pub mod gic;
pub mod its;
pub mod timer;

pub use gic::init_bsp;
pub use timer::{start_timer, stop_timer, on_timer_tick, timer_ticks};

/// aarch64 generic-timer PPI (private-peripheral IRQ). INTID 30 is the
/// standard EL1 physical-timer entry across GICv2/GICv3 and QEMU virt.
pub const TIMER_PPI: u32 = 30;

/// End-of-interrupt for the caller's acknowledged IRQ. Wrap of
/// `ICC_EOIR1_EL1` write.
///
/// # Safety
/// Must match a prior `ICC_IAR1_EL1` read from inside an IRQ handler.
#[inline]
pub unsafe fn eoi_for(iar: u64) {
    // SAFETY: trait delegated to arch.
    unsafe { narf_arch::aarch64::sysreg::write_icc_eoir1_el1(iar); }
}

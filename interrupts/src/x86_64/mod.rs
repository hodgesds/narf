//! x86_64 interrupt-controller backend.

pub mod apic;

pub use apic::{init_bsp, start_timer, stop_timer, eoi, timer_ticks, self_ipi};
pub use narf_arch::x86_64::msr;

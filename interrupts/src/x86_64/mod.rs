//! x86_64 interrupt-controller backend.

pub mod apic;
pub mod ipi;

pub use apic::{init_bsp, start_timer, stop_timer, eoi, timer_ticks, self_ipi};
pub use ipi::{shoot_va, shoot_range, ack_count, ever_received};
pub use narf_arch::x86_64::msr;

//! x86_64 interrupt-controller backend.

pub mod apic;
pub mod hpet_clockevent;
pub mod hpet_oneshot;
pub mod ipi;
pub mod timer_pump;

pub use apic::{eoi, init_bsp, self_ipi, start_timer, stop_timer, timer_ticks};
pub use hpet_oneshot::{arm_oneshot as arm_hpet_oneshot, HpetOneshotError};
pub use ipi::{
    ack_count, ever_received, invpcid_path_taken, pending_tag, shoot_range, shoot_tag_only,
    shoot_va,
};
pub use narf_arch::x86_64::msr;

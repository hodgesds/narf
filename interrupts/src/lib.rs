//! narf-interrupts — IRQ routing.
//!
//! Spec: `interrupts/specification/spec.md`. Stage-2 subset: x2APIC
//! enable + LAPIC-timer periodic IRQ + EOI. Fallbacks to xAPIC on
//! pre-x2APIC parts land when we care about non-Sapphire-Rapids
//! hardware (post-Stage-2).
//!
//! All IRQ vectors are in 32..=255 by convention; 0..=31 are reserved
//! for CPU exceptions. See `frame/x86_64/idt.rs` for the IDT install
//! and `frame/x86_64/trap.rs` for the Rust-side dispatch: vector < 32
//! → exception, vector >= 32 → IRQ (EOI after handler).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod dispatch;
pub mod vector;
pub mod wait;

pub use dispatch::{fire_count, on_irq, NUM_VECTORS};
pub use wait::{wait_for_irq, WaitForIrq};

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as current;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64 as current;

/// Typical IRQ-vector assignments.
pub const VECTOR_TIMER:         u8 = 32;
/// Cross-CPU TLB-shootdown IPI. Sender writes a target VA to a
/// per-CPU shootdown slot then signals via x2APIC ICR all-but-self;
/// the handler runs INVLPG and bumps an ack counter.
pub const VECTOR_TLB_SHOOTDOWN: u8 = 0xF0;
pub const VECTOR_SPURIOUS:      u8 = 0xFF;

/// Send end-of-interrupt to the LAPIC.
///
/// # Safety
/// Must be called from an IRQ handler, with the APIC initialised.
#[cfg(target_arch = "x86_64")]
pub unsafe fn eoi() {
    // SAFETY: platform contract; x86_64 backend writes to the LAPIC EOI
    // register. Must be invoked exactly once per IRQ handler dispatch,
    // else the LAPIC will stall further interrupts on the same level.
    unsafe { current::eoi(); }
}

/// Stub: aarch64 GIC EOI lands with the GICv3 skeleton.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn eoi() {}

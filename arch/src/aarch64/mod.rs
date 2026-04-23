//! aarch64 arch backend.

pub mod asm;
pub mod mmio;

pub use asm::{halt_forever, disable_interrupts, enable_interrupts};

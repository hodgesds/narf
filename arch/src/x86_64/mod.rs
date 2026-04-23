//! x86_64 arch backend.

pub mod asm;
pub mod io_port;

pub use asm::{halt_forever, disable_interrupts, enable_interrupts};

//! x86_64 arch backend.

pub mod asm;
pub mod io_port;

pub use asm::{halt_forever, disable_interrupts, enable_interrupts};

/// Exit QEMU cleanly via the `isa-debug-exit` device (I/O port 0xF4).
/// QEMU computes its exit status as `(code << 1) | 1`, so `exit_qemu(0)`
/// gives exit status 1 and `exit_qemu(16)` gives status 33 — xtask /
/// verification harnesses interpret the mapping.
///
/// If `isa-debug-exit` isn't wired up (real hardware, non-QEMU VMMs),
/// this falls back to `halt_forever`.
///
/// # Safety
/// Arbitrary I/O-port writes are always unsafe; port 0xF4 is specifically
/// QEMU's debug-exit device and has no side effect elsewhere.
pub unsafe fn exit_qemu(code: u32) -> ! {
    // SAFETY: OUT to 0xF4 is benign if the device isn't attached, and
    // exits cleanly if it is. Either way we fall into halt_forever.
    unsafe { io_port::outb(0xF4, code as u8); }
    halt_forever()
}

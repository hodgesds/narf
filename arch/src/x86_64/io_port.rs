//! Legacy I/O-port access. Needed for the 16550A UART at 0x3F8 before any
//! MMIO mapping exists.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// Read a byte from I/O port `port`.
#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: `in al, dx` reads from the chipset's I/O fabric; side effect
    // is visible to devices. Caller is responsible for the port semantics.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port,
             options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    value
}

/// Write a byte to I/O port `port`.
#[inline(always)]
pub unsafe fn outb(port: u16, value: u8) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: `out dx, al` writes to the chipset's I/O fabric. Callers own
    // port-sequence correctness (e.g. UART DLAB toggles).
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value,
             options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

//! 16550A UART backend via legacy I/O ports.
//!
//! Register layout (offsets from `base`, on ports):
//!   0: DLAB=0 → data    ; DLAB=1 → divisor low
//!   1: DLAB=0 → IER     ; DLAB=1 → divisor high
//!   2: FCR / IIR
//!   3: LCR   (bit 7 = DLAB)
//!   4: MCR
//!   5: LSR   (bit 5 = THR empty, bit 6 = TX idle)
//!   6: MSR
//!   7: scratch

use super::UartKind;
use narf_arch::x86_64::io_port::{inb, outb};

/// LSR bit 5 — Transmitter Holding Register empty.
const LSR_THR_EMPTY: u8 = 1 << 5;
/// LSR bit 0 — Data Ready (RX FIFO has at least one byte).
const LSR_DATA_READY: u8 = 1 << 0;

/// Program the UART to 115200 8N1, FIFO on, interrupts off. `base` is an
/// x86 I/O port number (truncated to `u16`).
///
/// # Safety
/// `base` must identify a real 16550A-compatible UART at a port the CPU
/// can reach. No concurrent caller modifies the same port.
pub unsafe fn init(base: usize, kind: UartKind) {
    debug_assert_eq!(
        kind,
        UartKind::Uart16550,
        "console::x86_64::init expects Uart16550"
    );
    let port = base as u16;
    // SAFETY: sequence follows the documented 16550A DLAB-toggle ritual.
    unsafe {
        outb(port + 1, 0x00); // disable all interrupts
        outb(port + 3, 0x80); // LCR: enable DLAB
        outb(port + 0, 0x01); // divisor low  = 1 (115200 baud)
        outb(port + 1, 0x00); // divisor high = 0
        outb(port + 3, 0x03); // LCR: 8 bits, no parity, 1 stop, DLAB off
        outb(port + 2, 0xC7); // FCR: enable FIFO, clear, 14-byte trigger
        outb(port + 4, 0x0B); // MCR: DTR | RTS | OUT2 (for future IRQ use)
    }
}

/// Non-blocking single-byte RX from the 16550A at port `base`.
/// Returns `Some(b)` if the RX FIFO had a byte ready, `None` otherwise.
/// Drives the kernel's serial-input pump — drained from a sleep_pump
/// (and in future, from a UART IRQ) and the bytes pushed onto
/// `narf_input::GLOBAL_RING` as `InputEvent::AsciiByte`.
///
/// # Safety
/// Hardware assumptions per `init`.
pub unsafe fn try_read_byte(base: usize, kind: UartKind) -> Option<u8> {
    debug_assert_eq!(kind, UartKind::Uart16550);
    let port = base as u16;
    // SAFETY: read LSR + RBR, no side effects on TX state.
    unsafe {
        if inb(port + 5) & LSR_DATA_READY == 0 {
            return None;
        }
        Some(inb(port + 0))
    }
}

/// Blocking TX of a byte slice to the 16550A at port `base`.
///
/// # Safety
/// Hardware assumptions per `init`.
pub unsafe fn write_bytes(base: usize, kind: UartKind, bytes: &[u8]) {
    debug_assert_eq!(kind, UartKind::Uart16550);
    let port = base as u16;
    for &b in bytes {
        // SAFETY: hardware programming of the 16550A; spin on LSR THR-empty.
        unsafe {
            while inb(port + 5) & LSR_THR_EMPTY == 0 {
                core::hint::spin_loop();
            }
            // LF ⇒ CR+LF so bare `println` renders on serial terminals.
            if b == b'\n' {
                while inb(port + 5) & LSR_THR_EMPTY == 0 {
                    core::hint::spin_loop();
                }
                outb(port + 0, b'\r');
                while inb(port + 5) & LSR_THR_EMPTY == 0 {
                    core::hint::spin_loop();
                }
                outb(port + 0, b'\n');
            } else {
                outb(port + 0, b);
            }
        }
    }
}

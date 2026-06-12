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

/// IER bit 0 — Received Data Available interrupt enable.
const IER_RDA: u8 = 1 << 0;

/// Enable RX-data-available IRQ on the 16550A at port `base`.
/// Pairs with the IOAPIC routing of ISA IRQ 4 in
/// `frame/bare_main`'s serial-IRQ install path.
///
/// # Safety
/// Hardware assumptions per `init`. Caller must have routed
/// IRQ 4 through the IOAPIC + installed a handler before
/// calling — otherwise the level-triggered IRQ would fire
/// against an unhandled vector.
pub unsafe fn enable_rx_irq(base: usize, kind: UartKind) {
    debug_assert_eq!(kind, UartKind::Uart16550);
    let port = base as u16;
    // SAFETY: caller-asserted live UART; IER is at offset 1
    // when DLAB=0 (set during init).
    // SAFETY: Valid memory or trusted environment
    unsafe {
        outb(port + 1, IER_RDA);
    }
}

/// Tracks whether the UART at port 0x3F8 has been observed alive.
/// Modern laptops typically have no Super I/O / LPC bridge and so
/// no COM1 — `inb` of LSR returns 0x00 (or 0xFF on some boards),
/// neither of which signals "THR ready" reliably. Without this
/// gate, `write_bytes` infinite-loops on the first writeln after
/// `init`.
///
/// Set to true once the scratch register loopback at init time
/// proves a UART is responding. When false, `write_bytes` drops
/// bytes silently rather than spinning.
static UART_PRESENT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Program the UART to 115200 8N1, FIFO on, interrupts off. `base` is an
/// x86 I/O port number (truncated to `u16`).
///
/// Probes the scratch register first (port + 7): writes a known
/// value, reads it back. If the value matches we mark the UART
/// present and proceed with the full programming sequence. If
/// not, we mark it absent so future `write_bytes` calls drop
/// silently. This protects real-HW boots on laptops that lack
/// any Super I/O / LPC UART at port 0x3F8 (most modern Ryzen
/// mobile platforms).
///
/// # Safety
/// `base` must be reachable at the I/O-port boundary; the
/// scratch-register probe is side-effect-free for the rest of
/// the system. No concurrent caller modifies the same port.
pub unsafe fn init(base: usize, kind: UartKind) {
    debug_assert_eq!(
        kind,
        UartKind::Uart16550,
        "console::x86_64::init expects Uart16550"
    );
    let port = base as u16;
    // SAFETY: scratch register at offset 7 has no functional
    // effect; loopback probe.
    // SAFETY: Valid memory or trusted environment
    let present = unsafe {
        outb(port + 7, 0xA5);
        let r1 = inb(port + 7);
        outb(port + 7, 0x5A);
        let r2 = inb(port + 7);
        r1 == 0xA5 && r2 == 0x5A
    };
    UART_PRESENT.store(present, core::sync::atomic::Ordering::Release);
    if !present {
        // No UART here — skip the full programming. `write_bytes`
        // will short-circuit on UART_PRESENT.
        return;
    }
    // SAFETY: sequence follows the documented 16550A DLAB-toggle ritual.
    unsafe {
        outb(port + 1, 0x00); // disable all interrupts
        outb(port + 3, 0x80); // LCR: enable DLAB
        outb(port, 0x01); // divisor low  = 1 (115200 baud)
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
        Some(inb(port))
    }
}

/// Maximum spin iterations waiting for THR-empty before giving
/// up on a single byte. ~10 ms at 4 GHz. If the UART went away
/// or is severely backed up, drop the byte rather than hanging
/// the kernel forever.
const TX_SPIN_MAX: u32 = 10_000_000;

/// Spin until the THR is empty, but bound the wait. Returns
/// false if we gave up — caller drops the byte.
#[inline]
unsafe fn wait_thr_empty(port: u16) -> bool {
    for _ in 0..TX_SPIN_MAX {
        // SAFETY: read LSR; no side effects.
        if unsafe { inb(port + 5) } & LSR_THR_EMPTY != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Blocking TX of a byte slice to the 16550A at port `base`.
/// Bounded — drops bytes if the THR-empty status never comes
/// (UART vanished mid-write, hardware fault, etc.) instead of
/// hanging the kernel. Short-circuits entirely if the init-time
/// probe found no UART at this port.
///
/// # Safety
/// Hardware assumptions per `init`.
pub unsafe fn write_bytes(base: usize, kind: UartKind, bytes: &[u8]) {
    debug_assert_eq!(kind, UartKind::Uart16550);
    if !UART_PRESENT.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    let port = base as u16;
    for &b in bytes {
        // SAFETY: hardware programming of the 16550A; spin on LSR THR-empty.
        unsafe {
            if !wait_thr_empty(port) {
                continue;
            }
            // LF ⇒ CR+LF so bare `println` renders on serial terminals.
            if b == b'\n' {
                outb(port, b'\r');
                if !wait_thr_empty(port) {
                    continue;
                }
                outb(port, b'\n');
            } else {
                outb(port, b);
            }
        }
    }
}

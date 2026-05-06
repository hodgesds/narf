//! PL011 UART backend for aarch64 (QEMU `virt` at 0x0900_0000 by default).
//!
//! Register layout (offsets from MMIO base):
//!   0x000: DR      — data
//!   0x018: FR      — flag (bit 5 TXFF, bit 7 TXFE)
//!   0x024: IBRD    — integer baud divisor
//!   0x028: FBRD    — fractional baud divisor
//!   0x02C: LCR_H   — line control
//!   0x030: CR      — control (bit 0 UARTEN, bit 8 TXE, bit 9 RXE)

use super::UartKind;
use narf_arch::aarch64::mmio::{read_u32, write_u32};

const DR: usize = 0x000;
const FR: usize = 0x018;
const IBRD: usize = 0x024;
const FBRD: usize = 0x028;
const LCR_H: usize = 0x02C;
const CR: usize = 0x030;

const FR_TXFF: u32 = 1 << 5;

/// Initialise PL011 to 8N1, 115200 baud assuming a 24 MHz UARTCLK (QEMU virt).
///
/// # Safety
/// `base` points at a PL011 MMIO register block the CPU can reach.
pub unsafe fn init(base: usize, kind: UartKind) {
    debug_assert_eq!(kind, UartKind::Pl011);
    // SAFETY: PL011 programming sequence — disable, program divisors, enable.
    unsafe {
        write_u32((base + CR) as *mut u32, 0); // disable UART
                                               // 24 MHz / (16 * 115200) = 13.02; ibrd=13, fbrd = round(0.02*64) = 1.
        write_u32((base + IBRD) as *mut u32, 13);
        write_u32((base + FBRD) as *mut u32, 1);
        write_u32((base + LCR_H) as *mut u32, (1 << 4) | (0b11 << 5)); // FIFO, 8 bits
        write_u32((base + CR) as *mut u32, (1 << 9) | (1 << 8) | 1); // RXE|TXE|UARTEN
    }
}

/// Blocking TX of a byte slice to a PL011 at MMIO `base`.
///
/// # Safety
/// See `init`.
pub unsafe fn write_bytes(base: usize, kind: UartKind, bytes: &[u8]) {
    debug_assert_eq!(kind, UartKind::Pl011);
    for &b in bytes {
        // SAFETY: MMIO read/write, volatile via arch/mmio.
        unsafe {
            while read_u32((base + FR) as *const u32) & FR_TXFF != 0 {
                core::hint::spin_loop();
            }
            if b == b'\n' {
                write_u32((base + DR) as *mut u32, b'\r' as u32);
                while read_u32((base + FR) as *const u32) & FR_TXFF != 0 {
                    core::hint::spin_loop();
                }
                write_u32((base + DR) as *mut u32, b'\n' as u32);
            } else {
                write_u32((base + DR) as *mut u32, b as u32);
            }
        }
    }
}

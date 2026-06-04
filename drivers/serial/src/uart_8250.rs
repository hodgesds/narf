//! 8250/16550 UART driver — clean-room implementation.
//!
//! Reference: `linux/drivers/tty/serial/8250/8250_port.c`
//! (Alan Cox, Russell King, et al. — GPL-2.0-or-later).
//!
//! ## Register Map (relative to `port_base`)
//!
//! | Offset | Name | Direction | Description                       |
//! |--------|------|-----------|-----------------------------------|
//! | +0     | THR  | W         | Transmit Holding Register         |
//! | +0     | RBR  | R         | Receive Buffer Register           |
//! | +0/+1  | DLL/DLM | W (DLAB=1) | Divisor Latch Low/High        |
//! | +1     | IER  | R/W       | Interrupt Enable Register         |
//! | +2     | IIR  | R         | Interrupt Identification Register |
//! | +2     | FCR  | W         | FIFO Control Register             |
//! | +3     | LCR  | R/W       | Line Control Register             |
//! | +4     | MCR  | R/W       | Modem Control Register            |
//! | +5     | LSR  | R         | Line Status Register              |
//! | +6     | MSR  | R         | Modem Status Register             |
//! | +7     | SCR  | R/W       | Scratch Register (chip detect)    |
//!
//! ## Baud Rate
//!
//! Clock source is 1.8432 MHz for legacy ISA COM ports.
//! Divisor = clock / (baud × 16).
//!
//! Examples:
//! - 9600 baud  → divisor = 1843200 / (9600 * 16)  = 12
//! - 115200 baud → divisor = 1843200 / (115200 * 16) = 1
//!
//! Linux 8250_port.c `serial8250_do_set_divisor` ~L2100.
//!
//! ## Chip Detection
//!
//! Write a sentinel byte to SCR (+7), read back; if mismatches, not
//! an 8250. Then test FIFO: write 0xC7 to FCR; if IIR bits 7:6 = 11,
//! the chip has a 16550A FIFO.
//! Linux 8250_port.c `autoconfig_16550a` ~L823.

extern crate alloc;

use crate::registry;
use narf_memory::PhysAddr;

// ── UartBase ──────────────────────────────────────────────────────────

/// UART register base address — either an I/O port (legacy x86) or
/// a physical MMIO address.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UartBase {
    Io(u16),
    Mmio(PhysAddr),
}

// ── Legacy COM port addresses ─────────────────────────────────────────

/// COM1 base I/O port.
pub const COM1_BASE: u16 = 0x3F8;
/// COM2 base I/O port.
pub const COM2_BASE: u16 = 0x2F8;
/// COM3 base I/O port.
pub const COM3_BASE: u16 = 0x3E8;
/// COM4 base I/O port.
pub const COM4_BASE: u16 = 0x2E8;

/// COM1 ISA IRQ.
pub const COM1_IRQ: u8 = 4;
/// COM2 ISA IRQ.
pub const COM2_IRQ: u8 = 3;
/// COM3 ISA IRQ (shared with COM1 on many BIOSes).
pub const COM3_IRQ: u8 = 4;
/// COM4 ISA IRQ (shared with COM2 on many BIOSes).
pub const COM4_IRQ: u8 = 3;

// ── Register offsets ──────────────────────────────────────────────────

/// Transmit Holding Register (write) / Receive Buffer (read) — offset +0.
pub const REG_THR_RBR: u16 = 0;
/// Divisor Latch Low — offset +0 when LCR.DLAB=1.
pub const REG_DLL: u16 = 0;
/// Interrupt Enable Register — offset +1.
pub const REG_IER: u16 = 1;
/// Divisor Latch High — offset +1 when LCR.DLAB=1.
pub const REG_DLM: u16 = 1;
/// Interrupt Identification Register (read) — offset +2.
pub const REG_IIR: u16 = 2;
/// FIFO Control Register (write) — offset +2.
pub const REG_FCR: u16 = 2;
/// Line Control Register — offset +3.
pub const REG_LCR: u16 = 3;
/// Modem Control Register — offset +4.
pub const REG_MCR: u16 = 4;
/// Line Status Register — offset +5.
pub const REG_LSR: u16 = 5;
/// Modem Status Register — offset +6.
pub const REG_MSR: u16 = 6;
/// Scratch Register — offset +7 (used for chip detect).
pub const REG_SCR: u16 = 7;

// ── Register bit fields ───────────────────────────────────────────────

/// LCR: Divisor Latch Access Bit. Set to 1 to program DLL/DLM.
pub const LCR_DLAB: u8 = 0x80;
/// LCR: 8 data bits, no parity, 1 stop bit (the typical 8N1 config).
pub const LCR_8N1: u8 = 0x03;

/// FCR: FIFO enable + clear both FIFOs + 14-byte threshold.
pub const FCR_FIFO_ENABLE: u8 = 0x01;
pub const FCR_CLEAR_RX: u8 = 0x02;
pub const FCR_CLEAR_TX: u8 = 0x04;
pub const FCR_TRIGGER_14: u8 = 0xC0;

/// IER: Receive Data Available interrupt enable.
pub const IER_RDA: u8 = 0x01;
/// IER: Transmit Holding Register Empty interrupt enable.
pub const IER_THRE: u8 = 0x02;

/// IIR: FIFO enabled bits 7:6 = 11 for 16550A.
pub const IIR_FIFO_ENABLED: u8 = 0xC0;

/// LSR: Data Ready — a received byte is in RBR.
pub const LSR_DR: u8 = 0x01;
/// LSR: Transmit Holding Register Empty — safe to write THR.
pub const LSR_THRE: u8 = 0x20;
/// LSR: Transmit Empty — both THR and TSR are empty.
pub const LSR_TEMT: u8 = 0x40;

/// MCR: Data Terminal Ready.
pub const MCR_DTR: u8 = 0x01;
/// MCR: Request To Send.
pub const MCR_RTS: u8 = 0x02;
/// MCR: Auxiliary Output 2 — gates IRQ line on most UARTs.
pub const MCR_OUT2: u8 = 0x08;

// ── Clock constant ────────────────────────────────────────────────────

/// Standard ISA UART clock frequency: 1.8432 MHz.
/// Divisor = UART_CLOCK / (baud × 16).
pub const UART_CLOCK_HZ: u32 = 1_843_200;

// ── Baud divisor helpers ──────────────────────────────────────────────

/// Compute the divisor for a given baud rate.
/// Returns `None` for baud = 0 or rates too high for the clock.
#[inline]
pub fn baud_divisor(baud: u32, clock_hz: u32) -> Option<u16> {
    if baud == 0 {
        return None;
    }
    let div = clock_hz / (baud * 16);
    if div == 0 || div > 0xFFFF {
        return None;
    }
    Some(div as u16)
}

// ── Register accessors ────────────────────────────────────────────────

/// Write a byte to a UART register.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn uart_write(base: UartBase, shift: u8, reg: u16, val: u8) {
    match base {
        UartBase::Io(p) => unsafe { narf_arch::x86_64::io_port::outb(p + (reg << shift), val) },
        UartBase::Mmio(a) => unsafe {
            narf_arch::mmio::write8(a.raw() + ((reg as u64) << shift), val)
        },
    }
}

/// Read a byte from a UART register.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn uart_read(base: UartBase, shift: u8, reg: u16) -> u8 {
    match base {
        UartBase::Io(p) => unsafe { narf_arch::x86_64::io_port::inb(p + (reg << shift)) },
        UartBase::Mmio(a) => unsafe { narf_arch::mmio::read8(a.raw() + ((reg as u64) << shift)) },
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn uart_write(_base: UartBase, _shift: u8, _reg: u16, _val: u8) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn uart_read(_base: UartBase, _shift: u8, _reg: u16) -> u8 {
    0
}

// ── UART device ───────────────────────────────────────────────────────

/// UART type detected at probe time.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UartType {
    /// Original 8250 (no FIFO).
    Uart8250,
    /// 16450 (no FIFO, scratch register present).
    Uart16450,
    /// 16550 (broken FIFO, treated as 16450).
    Uart16550,
    /// 16550A (working 16-byte FIFO).
    Uart16550A,
    /// Chip not detected (I/O not present).
    NotDetected,
}

/// A 8250/16550 UART port.
#[derive(Debug)]
pub struct Uart8250 {
    /// Register base address.
    pub base: UartBase,
    /// Register stride (log2). 0 = 1 byte, 2 = 4 bytes.
    pub reg_shift: u8,
    /// Input clock frequency in Hz.
    pub clock_hz: u32,
    /// ISA IRQ number or GSI, if assigned.
    pub irq: Option<u8>,
    /// Detected UART variant.
    pub uart_type: UartType,
    /// Currently programmed baud rate (0 = not initialized).
    pub baud: u32,
}

impl Uart8250 {
    /// Construct a new UART handle for an I/O port.
    pub fn new(base: u16, irq: Option<u8>) -> Self {
        Self {
            base: UartBase::Io(base),
            reg_shift: 0,
            clock_hz: UART_CLOCK_HZ,
            irq,
            uart_type: UartType::NotDetected,
            baud: 0,
        }
    }

    /// Construct a new handle for an MMIO-mapped 8250 port.
    pub fn new_mmio(base_addr: PhysAddr, irq: Option<u8>, reg_shift: u8, clock_hz: u32) -> Self {
        Self {
            base: UartBase::Mmio(base_addr),
            reg_shift,
            clock_hz,
            irq,
            uart_type: UartType::NotDetected,
            baud: 0,
        }
    }

    /// Detect the UART type using the SCR scratch-register loopback
    /// test and the FIFO-presence test.
    ///
    /// Linux 8250_port.c `autoconfig` ~L780 and `autoconfig_16550a` ~L823.
    #[cfg(target_arch = "x86_64")]
    pub fn detect(&mut self) -> UartType {
        // SAFETY: all I/O to base registers, kernel context.
        let has_scratch = unsafe {
            uart_write(self.base, self.reg_shift, REG_SCR, 0xAB);
            let rb = uart_read(self.base, self.reg_shift, REG_SCR);
            rb == 0xAB
        };
        if !has_scratch {
            self.uart_type = UartType::Uart8250;
            return UartType::Uart8250;
        }
        // Try FIFO.
        let has_fifo = unsafe {
            uart_write(
                self.base,
                self.reg_shift,
                REG_FCR,
                FCR_FIFO_ENABLE | FCR_CLEAR_RX | FCR_CLEAR_TX,
            );
            let iir = uart_read(self.base, self.reg_shift, REG_IIR);
            (iir & IIR_FIFO_ENABLED) == IIR_FIFO_ENABLED
        };
        self.uart_type = if has_fifo {
            UartType::Uart16550A
        } else {
            UartType::Uart16450
        };
        self.uart_type
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn detect(&mut self) -> UartType {
        self.uart_type = UartType::NotDetected;
        UartType::NotDetected
    }

    /// Program the UART to the given baud rate.
    #[cfg(target_arch = "x86_64")]
    pub fn set_baud(&mut self, baud: u32) -> bool {
        let div = match baud_divisor(baud, self.clock_hz) {
            Some(d) => d,
            None => return false,
        };
        // SAFETY: LCR.DLAB sequence.
        unsafe {
            uart_write(self.base, self.reg_shift, REG_LCR, LCR_DLAB);
            uart_write(self.base, self.reg_shift, REG_DLL, (div & 0xFF) as u8);
            uart_write(
                self.base,
                self.reg_shift,
                REG_DLM,
                ((div >> 8) & 0xFF) as u8,
            );
            uart_write(self.base, self.reg_shift, REG_LCR, LCR_8N1);
        }
        self.baud = baud;
        true
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn set_baud(&mut self, _baud: u32) -> bool {
        false
    }

    /// Initialize the UART: detect chip, program 8N1 at `baud`.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&mut self, baud: u32) -> bool {
        self.detect();
        if self.uart_type == UartType::NotDetected {
            return false;
        }
        unsafe { uart_write(self.base, self.reg_shift, REG_IER, 0x00) };
        if !self.set_baud(baud) {
            return false;
        }
        if self.uart_type == UartType::Uart16550A {
            unsafe {
                uart_write(
                    self.base,
                    self.reg_shift,
                    REG_FCR,
                    FCR_FIFO_ENABLE | FCR_CLEAR_RX | FCR_CLEAR_TX | FCR_TRIGGER_14,
                );
            }
        }
        unsafe {
            uart_write(
                self.base,
                self.reg_shift,
                REG_MCR,
                MCR_DTR | MCR_RTS | MCR_OUT2,
            )
        };
        true
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn init(&mut self, _baud: u32) -> bool {
        false
    }

    /// Enable receive-data-available interrupt.
    #[cfg(target_arch = "x86_64")]
    pub fn enable_rx_irq(&self) {
        unsafe { uart_write(self.base, self.reg_shift, REG_IER, IER_RDA) };
    }

    /// Write a single byte, blocking until THRE = 1.
    #[cfg(target_arch = "x86_64")]
    pub fn write_byte(&self, byte: u8) {
        unsafe {
            loop {
                let lsr = uart_read(self.base, self.reg_shift, REG_LSR);
                if lsr & LSR_THRE != 0 {
                    break;
                }
            }
            uart_write(self.base, self.reg_shift, REG_THR_RBR, byte);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn write_byte(&self, _byte: u8) {}

    /// Read a received byte if one is available.
    #[cfg(target_arch = "x86_64")]
    pub fn read_byte(&self) -> Option<u8> {
        unsafe {
            let lsr = uart_read(self.base, self.reg_shift, REG_LSR);
            if lsr & LSR_DR != 0 {
                Some(uart_read(self.base, self.reg_shift, REG_THR_RBR))
            } else {
                None
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn read_byte(&self) -> Option<u8> {
        None
    }

    #[cfg(target_arch = "x86_64")]
    pub fn read_lsr(&self) -> u8 {
        unsafe { uart_read(self.base, self.reg_shift, REG_LSR) }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn read_lsr(&self) -> u8 {
        0
    }
}

// ── Legacy COM port registration ──────────────────────────────────────

static COM_PORTS: &[(&str, u16, u8)] = &[
    ("COM1", COM1_BASE, COM1_IRQ),
    ("COM2", COM2_BASE, COM2_IRQ),
    ("COM3", COM3_BASE, COM3_IRQ),
    ("COM4", COM4_BASE, COM4_IRQ),
];

pub fn register_legacy_uarts() {
    use core::fmt::Write as _;
    for &(name, base, irq) in COM_PORTS {
        let mut uart = Uart8250::new(base, Some(irq));
        let utype = uart.detect();
        if utype == UartType::NotDetected {
            continue;
        }
        uart.init(115_200);
        let _ = writeln!(
            narf_console::Writer,
            "  serial: {} at 0x{:03X} irq={} {:?}",
            name,
            base,
            irq,
            utype
        );
        registry::register(registry::UartInfo {
            io_base: base,
            irq: Some(irq),
            name,
            baud: 115_200,
        });
    }
}

//! ARM PrimeCell UART (PL011) Driver.
//!
//! Provides serial console and TTY support for the standard UART
//! block found on most ARM SoCs, including the Raspberry Pi.
//!
//! References: `linux/drivers/tty/serial/amba-pl011.c`
//!
//! ## Register layout
//!
//! Offsets from the MMIO base (ARM PrimeCell UART (PL011) Technical
//! Reference Manual, register summary; the same offsets the early
//! console backend uses in `console::aarch64`):
//!   0x000: UARTDR   — data (bits 7:0 RX/TX byte)
//!   0x018: UARTFR   — flag (bit 4 RXFE, bit 5 TXFF)
//!   0x024: UARTIBRD — integer baud divisor
//!   0x028: UARTFBRD — fractional baud divisor
//!   0x02C: UARTLCR_H — line control (bit 4 FEN, bits 6:5 WLEN = 8 bits)
//!   0x030: UARTCR   — control (bit 0 UARTEN, bit 8 TXE, bit 9 RXE)
//!
//! The handle below only touches DR and FR: the probe / early console
//! already programmed baud, FIFO and line control, so a byte port is
//! a polled pipe over an already-programmed UART — the same shape as
//! `Uart8250BytePort` over the 8250.

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;
#[cfg(any(target_arch = "aarch64", feature = "kernel-test", test))]
use narf_memory::PhysAddr;

#[cfg(any(target_arch = "aarch64", feature = "kernel-test", test))]
use crate::uart_8250::UartBase;

// ── Register offsets ────────────────────────────────────────────────

/// Data register — offset +0x000. Bits 7:0 carry the RX/TX byte.
pub const REG_DR: usize = 0x000;
/// Flag register — offset +0x018.
pub const REG_FR: usize = 0x018;

// ── Register bit fields ─────────────────────────────────────────────

/// FR: RX FIFO empty — no byte to read.
pub const FR_RXFE: u32 = 1 << 4;
/// FR: TX FIFO full — must wait before writing DR.
pub const FR_TXFF: u32 = 1 << 5;

/// Bytes mapped for a PL011 register window. The registers live in
/// the first 0x34 bytes; one page covers the block and is the
/// ioremap granularity. Only used where a PL011 is registered
/// (aarch64).
#[cfg(target_arch = "aarch64")]
const PL011_MAP_LEN: u64 = 0x1000;

// ── UART device ─────────────────────────────────────────────────────

/// A PL011 UART port.
///
/// The handle is stateless apart from its register-block VA and IRQ:
/// the probe / early console already programmed baud, FIFO and line
/// control, so the handle may be dropped and rebuilt from the
/// registry entry, as the PCI and LPSS 8250 probes already do for
/// their ports.
///
/// The VA is the registry entry's `virt` (an `ioremap` Device
/// mapping installed by the probe): the kernel does not
/// identity-map MMIO, so the physical base is never dereferenced
/// directly (see `virtio`'s probe for the same rule).
#[derive(Debug)]
pub struct Pl011 {
    /// Kernel VA of the register block (ioremap Device mapping).
    base: u64,
    /// IRQ line, if assigned.
    pub irq: Option<u8>,
}

impl Pl011 {
    /// Wrap a mapped register window.
    ///
    /// # Safety
    /// `va` must be a live mapping covering the PL011 register block
    /// (Device memory for real hardware — the registry entry's
    /// `virt`, installed by the probe; RAM for a test's fake
    /// register block) for the lifetime of the handle.
    pub const unsafe fn from_va(va: u64, irq: Option<u8>) -> Self {
        Self { base: va, irq }
    }

    /// Write a single byte, blocking until the TX FIFO accepts it
    /// (spins on FR.TXFF, like the console PL011 backend).
    pub fn write_byte(&self, byte: u8) {
        // SAFETY: `base` is a live PL011 mapping (see `from_va`).
        unsafe {
            while narf_arch::mmio::read32(self.base + REG_FR as u64) & FR_TXFF != 0 {
                core::hint::spin_loop();
            }
            narf_arch::mmio::write32(self.base + REG_DR as u64, byte as u32);
        }
    }

    /// Read a received byte if one is available.
    pub fn read_byte(&self) -> Option<u8> {
        // SAFETY: `base` is a live PL011 mapping (see `from_va`).
        unsafe {
            let fr = narf_arch::mmio::read32(self.base + REG_FR as u64);
            if fr & FR_RXFE != 0 {
                return None;
            }
            Some(narf_arch::mmio::read32(self.base + REG_DR as u64) as u8)
        }
    }
}

/// QEMU `virt` PL011 UART0 MMIO base — the machine's only PL011.
/// Same address the early console uses (`boot::aarch64::
/// PL011_QEMU_VIRT`; `frame::bare_main` early-inits the console
/// there). Real ARM boards enumerate their PL011s from the device
/// tree (#1054); this covers the QEMU target until that lands.
#[cfg(target_arch = "aarch64")]
pub const QEMU_VIRT_PL011_BASE: u64 = 0x0900_0000;

/// Registry name for the QEMU virt PL011.
pub const PL011_NAME: &str = "PL011-0";

/// Register the PL011 platform driver.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "pl011", || {
        #[cfg(target_arch = "aarch64")]
        register_qemu_virt_pl011();
        let _ = writeln!(
            Writer,
            "  serial: ARM PrimeCell PL011 UART driver registered"
        );
        // Placeholder: parse DeviceTree for `arm,pl011` compatible strings.
        InitResult::Ok
    });
}

/// Publish the QEMU virt PL011 in the serial registry so H5
/// (`bt-h5=PL011-0`) and other registry consumers can find it.
///
/// The console already programmed this UART (8N1, 115200 baud
/// against the 24 MHz UARTCLK) at early init; registration does not
/// steal it — only an explicit `bt-h5=` opt-in binds it. A second
/// entry for the same base (e.g. from a future DT enumeration) is
/// skipped so one physical port never gets two registry entries.
///
/// The register window is mapped here (the probe owns the mapping)
/// and the VA published in the entry: consumers rebuild their
/// handles from `virt`, never from the physical base.
#[cfg(target_arch = "aarch64")]
fn register_qemu_virt_pl011() {
    use crate::registry::UartFamily;
    let base = PhysAddr::new(QEMU_VIRT_PL011_BASE);
    if crate::registry::uarts()
        .iter()
        .any(|u| u.base == UartBase::Mmio(base))
    {
        return;
    }
    // SAFETY: the QEMU virt PL011 is a real device MMIO window; len
    // covers the register block. Ioremap mappings persist until
    // explicit iounmap, so the published VA stays valid.
    let mapping = match unsafe {
        narf_memory::ioremap::ioremap(
            base.raw(),
            PL011_MAP_LEN,
            narf_memory::ioremap::MmioAttrs::Device,
        )
    } {
        Ok(m) => m,
        Err(_) => {
            let _ = writeln!(
                Writer,
                "  serial-pl011: ioremap of QEMU virt PL011 failed; not registered"
            );
            return;
        }
    };
    crate::registry::register(crate::registry::UartInfo {
        base: UartBase::Mmio(base),
        // PL011 offsets are absolute byte offsets; the stride is an
        // 8250 concept and unused by the PL011 handle.
        reg_shift: 0,
        // QEMU virt UARTCLK; the console programs 13/1 divisors
        // against it for 115200 baud (`console::aarch64`).
        clock_hz: 24_000_000,
        // The virt PL011 IRQ is a GIC SPI, not an ISA-style line;
        // the byte port is polled and never uses it.
        irq: None,
        name: PL011_NAME,
        baud: 115_200,
        kind: UartFamily::Pl011,
        virt: Some(mapping.va()),
    });
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Register offsets match the PL011 layout the console backend
    /// uses (`console::aarch64`): DR 0x000, FR 0x018, RXFE bit 4,
    /// TXFF bit 5.
    fn smoke_pl011_register_offsets() -> TestResult {
        if REG_DR != 0x000 || REG_FR != 0x018 {
            return TestResult::Fail("PL011 DR/FR offsets wrong");
        }
        if FR_RXFE != (1 << 4) || FR_TXFF != (1 << 5) {
            return TestResult::Fail("PL011 FR bits wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/serial/pl011", smoke_pl011_register_offsets);

    /// Fake PL011 register block: 16 u32 cells (64 bytes) covering
    /// DR (cell 0) and FR (cell 6, offset 0x18). Leaked-box shape,
    /// as `drivers/gpio`'s `make_synthetic_mmio`: the block stays
    /// live for the whole test and the handle's volatile accesses
    /// are observable without hardware.
    fn make_fake_regs() -> &'static mut [u32; 16] {
        let buf: alloc::boxed::Box<[u32; 16]> = alloc::boxed::Box::new([0u32; 16]);
        alloc::boxed::Box::leak(buf)
    }

    fn smoke_pl011_byte_read_write_against_fake_uart() -> TestResult {
        let regs = make_fake_regs();
        let base = regs.as_mut_ptr();
        // SAFETY: `regs` is a live RAM-backed register block for the
        // duration of this test; every index below is in-bounds
        // (< 16). Manipulation uses volatile ops, as
        // `drivers/gpio`'s synthetic-MMIO fixtures do, so the
        // handle's volatile accesses observe them in order.
        unsafe {
            // RX FIFO empty: no byte to read.
            core::ptr::write_volatile(base.add(REG_FR / 4), FR_RXFE);
            let uart = Pl011::from_va(base as u64, None);
            if uart.read_byte().is_some() {
                return TestResult::Fail("read_byte must be None when FR.RXFE is set");
            }
            // A byte arrives: DR holds it, RXFE clears.
            core::ptr::write_volatile(base.add(REG_DR / 4), 0x42);
            core::ptr::write_volatile(base.add(REG_FR / 4), 0);
            match uart.read_byte() {
                Some(0x42) => {}
                _ => {
                    return TestResult::Fail(
                        "read_byte must return the DR byte when RXFE is clear",
                    );
                }
            }
            // TX: FIFO not full, so a write lands in DR as a full u32
            // (PL011 DR is a 32-bit register; the byte is its low 8
            // bits). Pre-filling with a sentinel proves the write is
            // 32-bit, not an 8-bit store.
            core::ptr::write_volatile(base.add(REG_DR / 4), 0xDEAD_BEEF);
            core::ptr::write_volatile(base.add(REG_FR / 4), 0);
            uart.write_byte(0x41);
            if core::ptr::read_volatile(base.add(REG_DR / 4)) != 0x41 {
                return TestResult::Fail("write_byte must store the byte in DR (32-bit write)");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/serial/pl011",
        smoke_pl011_byte_read_write_against_fake_uart
    );

    /// A PL011 registry entry round-trips its kind, base and VA:
    /// the fields `H5Transport::from_uart_info` dispatches on.
    fn smoke_pl011_registry_entry_round_trips_kind() -> TestResult {
        use crate::registry::{self, UartFamily};
        let phys = PhysAddr::new(0x0900_0000);
        let regs = make_fake_regs();
        registry::register(registry::UartInfo {
            base: UartBase::Mmio(phys),
            reg_shift: 0,
            clock_hz: 24_000_000,
            irq: None,
            name: "test-PL011-0",
            baud: 115_200,
            kind: UartFamily::Pl011,
            virt: Some(regs.as_ptr() as u64),
        });
        let Some(u) = registry::uarts()
            .into_iter()
            .find(|u| u.name == "test-PL011-0")
        else {
            return TestResult::Fail("PL011 registry entry not found in snapshot");
        };
        if u.kind != UartFamily::Pl011 {
            return TestResult::Fail("PL011 kind did not round-trip");
        }
        if u.base != UartBase::Mmio(phys) {
            return TestResult::Fail("PL011 base did not round-trip");
        }
        if u.virt != Some(regs.as_ptr() as u64) {
            return TestResult::Fail("PL011 virt did not round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/serial/pl011",
        smoke_pl011_registry_entry_round_trips_kind
    );
}

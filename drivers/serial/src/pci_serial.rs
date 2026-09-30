//! PCI serial ports — class-matched 8250/16550-compatible UARTs.
//!
//! ## Reference
//!
//! Linux v7.3-rc4 `drivers/tty/serial/8250/8250_pci.c` (GPL-2.0;
//! NARF is GPL-2.0-or-later so adaptation is permitted). Linux
//! carries a long table of board-specific quirks, and then a generic
//! catch-all entry:
//!
//! ```text
//! { PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID,
//!   PCI_CLASS_COMMUNICATION_SERIAL << 8, 0xffff00, pbn_default }
//! ```
//!
//! That is the path this module implements: a class match on
//! `0x07 / 0x00 / <prog-if>` (Communication controller / serial /
//! UART flavour), BAR0 as the register window, and the standard
//! 16550 bring-up.
//!
//! [`probe::enumerate_acpi_uarts`](crate::probe) covers the legacy
//! `PNP0501` ports; this covers the ones that appear as PCI
//! functions. Together they are the two discovery paths a modern
//! board actually uses.
//!
//! ## Hardware this targets
//!
//! The Minisforum **MS-03** exposes one: the CSME "Keyboard and Text
//! (KT) Redirection" port at PCI `00:16.3` (`8086:e373`, prog-if
//! `0x02`), with an 8-byte I/O BAR0. It is the Serial-over-LAN
//! endpoint the management engine drives. Linux binds it through the
//! same generic class entry — `8086:e373` is not in any of its
//! board-specific tables.
//!
//! ## The Intel KT quirk, and why it does not bite here
//!
//! Linux installs `kt_serial_in` for Intel KT ports: when the
//! management engine resets, the UART registers can momentarily read
//! back as 0, so a read-modify-write of `IER` can silently disable
//! interrupts. Linux works around it by substituting its cached
//! `up->ier` whenever a read of `IER` returns 0.
//!
//! [`crate::uart_8250::Uart8250`] never read-modify-writes `IER` — it
//! writes the whole register from a value it computed — so the window
//! Linux is guarding does not exist on this path. The quirk becomes
//! relevant the moment something saves and restores `IER` around an
//! operation (a polled-console write, for instance). [`is_intel_kt`]
//! flags the affected ports so that code can be written correctly
//! when it lands, and the port's [`PciUart::quirks`] records it.

extern crate alloc;

use alloc::vec::Vec;

use narf_bus::{read_bar, Bar, BarKind, BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::registry::{self, UartInfo};
use crate::uart_8250::{Uart8250, UartBase, UartType};

// ── Class codes ─────────────────────────────────────────────────────

/// PCI base class 0x07 — Communication controller.
pub const PCI_CLASS_COMMUNICATION: u8 = 0x07;
/// Sub-class 0x00 — serial controller.
pub const PCI_SUBCLASS_SERIAL: u8 = 0x00;

/// Prog-IF values under `07:00` that name a UART this driver can
/// drive. PCI Code and ID Assignment spec §1.5, class 07h.
///
/// `0x00` (generic XT-compatible) is deliberately excluded: those
/// parts have no FIFO and no scratch register, so the 16550
/// autodetect below cannot tell them apart from an absent device.
pub const SUPPORTED_PROG_IFS: &[u8] = &[
    0x01, // 16450-compatible
    0x02, // 16550-compatible — the MS-03's KT port
    0x03, // 16650-compatible
    0x04, // 16750-compatible
    0x05, // 16850-compatible
    0x06, // 16950-compatible
];

/// Human-readable name for a prog-IF.
pub const fn prog_if_name(prog_if: u8) -> &'static str {
    match prog_if {
        0x00 => "8250",
        0x01 => "16450",
        0x02 => "16550",
        0x03 => "16650",
        0x04 => "16750",
        0x05 => "16850",
        0x06 => "16950",
        _ => "uart",
    }
}

// ── Quirks ──────────────────────────────────────────────────────────

/// Intel.
pub const INTEL_VENDOR: u16 = 0x8086;

/// Quirk bits recorded for a probed port.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UartQuirks(pub u32);

impl UartQuirks {
    pub const NONE: UartQuirks = UartQuirks(0);
    /// Intel CSME KT port: `IER` can read back 0 across a management
    /// engine reset. See the module docs.
    pub const KT_IER_READS_ZERO: UartQuirks = UartQuirks(1 << 0);
    /// Intel CSME KT port: THRE is unreliable, so a transmitter
    /// should not wait on it indefinitely (`UPF_BUG_THRE` in Linux).
    pub const KT_BUG_THRE: UartQuirks = UartQuirks(1 << 1);

    #[inline]
    pub const fn contains(self, o: UartQuirks) -> bool {
        self.0 & o.0 == o.0
    }
}

impl core::ops::BitOr for UartQuirks {
    type Output = UartQuirks;
    fn bitor(self, rhs: UartQuirks) -> Self {
        UartQuirks(self.0 | rhs.0)
    }
}

/// `true` for an Intel CSME Keyboard-and-Text redirection port.
///
/// Every generation puts the KT function at `00:16.3` with a
/// `07:00:02` class triple; the device id changes per PCH, so the
/// test is on vendor + class + function rather than an id table
/// that would need a new entry every generation.
pub fn is_intel_kt(device: &BusDevice) -> bool {
    if device.id.vendor != INTEL_VENDOR {
        return false;
    }
    match device.kind {
        narf_bus::BusKind::Pcie { addr, .. } => {
            addr.bus == 0 && addr.device == 0x16 && addr.function == 3
        }
        _ => false,
    }
}

/// Quirks for a device, if any.
pub fn quirks_for(device: &BusDevice) -> UartQuirks {
    if is_intel_kt(device) {
        UartQuirks::KT_IER_READS_ZERO | UartQuirks::KT_BUG_THRE
    } else {
        UartQuirks::NONE
    }
}

// ── Probe ───────────────────────────────────────────────────────────

/// Baud the port is programmed to at probe. Matches the rate the
/// in-tree console uses.
pub const DEFAULT_BAUD: u32 = 115_200;

/// A 16550's register file is eight bytes. A BAR smaller than that
/// is not a UART window.
pub const UART_REGISTER_BYTES: u64 = 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PciSerialError {
    /// BAR0 is unimplemented, unprogrammed, or too small.
    BadBar,
    /// The BAR is memory-mapped on an architecture where this driver
    /// only supports I/O-port access.
    UnsupportedBarKind,
    /// The 16550 autodetect found nothing behind the window.
    NotDetected,
}

/// One probed PCI UART.
#[derive(Debug)]
pub struct PciUart {
    /// PCI vendor / device ids.
    pub vendor: u16,
    pub device: u16,
    /// Prog-IF, which names the UART flavour the device claims.
    pub prog_if: u8,
    /// Where the register file lives.
    pub base: UartBase,
    /// What the autodetect actually found, which can be older than
    /// the prog-IF claims.
    pub uart_type: UartType,
    /// Quirks that apply to this port.
    pub quirks: UartQuirks,
}

/// Decode the prog-IF byte out of a device's packed class triple.
pub const fn prog_if_of(class: u32) -> u8 {
    (class & 0xFF) as u8
}

/// Decode the sub-class byte.
pub const fn subclass_of(class: u32) -> u8 {
    ((class >> 8) & 0xFF) as u8
}

/// Decode the base-class byte.
pub const fn base_class_of(class: u32) -> u8 {
    ((class >> 16) & 0xFF) as u8
}

/// Bring up one port: locate its register window and run the 16550
/// autodetect + init.
fn bring_up(device: &BusDevice) -> Result<PciUart, PciSerialError> {
    // SAFETY: the probe owns the device's cfg window for the duration
    // of this call, which is what `read_bar`'s size-detection
    // write-read-restore cycle requires.
    let bar: Bar = unsafe { read_bar(device, 0) }.map_err(|_| PciSerialError::BadBar)?;
    if bar.phys.raw() == 0 || bar.size < UART_REGISTER_BYTES {
        return Err(PciSerialError::BadBar);
    }

    let base = match bar.kind {
        BarKind::Io => {
            // An I/O BAR's base must fit the 16-bit port space.
            let port = bar.phys.raw();
            if port > u16::MAX as u64 {
                return Err(PciSerialError::BadBar);
            }
            UartBase::Io(port as u16)
        }
        BarKind::Mmio32 { .. } | BarKind::Mmio64 { .. } => UartBase::Mmio(bar.phys),
    };

    let mut uart = match base {
        UartBase::Io(port) => Uart8250::new(port, None),
        // A memory-mapped PCI UART uses a byte stride unless the
        // board says otherwise; Linux's `pbn_default` does the same.
        UartBase::Mmio(addr) => Uart8250::new_mmio(addr, None, 0, crate::uart_8250::UART_CLOCK_HZ),
    };

    if !uart.init(DEFAULT_BAUD) {
        return Err(PciSerialError::NotDetected);
    }

    Ok(PciUart {
        vendor: device.id.vendor,
        device: device.id.device,
        prog_if: prog_if_of(device.id.class),
        base,
        uart_type: uart.uart_type,
        quirks: quirks_for(device),
    })
}

// ── Driver-match registration ───────────────────────────────────────

static PORTS: IrqSafeSpinLock<Vec<PciUart>> = IrqSafeSpinLock::new(Vec::new());

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // The class match already filtered on the triple, but a future
    // edit could add a vendor backstop; re-check rather than trust it.
    if base_class_of(device.id.class) != PCI_CLASS_COMMUNICATION
        || subclass_of(device.id.class) != PCI_SUBCLASS_SERIAL
    {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }

    // Both space-enable bits: the register file may be behind either
    // an I/O BAR (the KT port) or an MMIO one.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::IO_SPACE
            | narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    let port = match bring_up(&device) {
        Ok(p) => p,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  pci-serial: {:04x}:{:04x} {} at {:?} detected {:?}{}",
            port.vendor,
            port.device,
            prog_if_name(port.prog_if),
            port.base,
            port.uart_type,
            if port.quirks.contains(UartQuirks::KT_IER_READS_ZERO) {
                " (Intel KT)"
            } else {
                ""
            },
        );
    }

    // The shared registry describes ports by I/O base. A
    // memory-mapped port has no meaningful `io_base`, so only
    // I/O-space ports are published there; MMIO ones stay visible
    // through `ports()`.
    if let UartBase::Io(io_base) = port.base {
        registry::register(UartInfo {
            io_base,
            irq: None,
            name: "pci-serial",
            baud: DEFAULT_BAUD,
        });
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("pci-serial"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });

    PORTS.lock().push(port);
    Ok(())
}

/// Register a class match per supported prog-IF.
///
/// `MatchKind::ClassFull` rather than `MatchKind::Class`: the latter
/// would claim every `0x07` Communication controller, which includes
/// modems, parallel ports, and the two CSME HECI functions on this
/// board — all of which have their own drivers.
pub fn register_pci_driver() {
    for prog_if in SUPPORTED_PROG_IFS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: prog_if_name(prog_if),
            kind: narf_bus::MatchKind::ClassFull {
                class: PCI_CLASS_COMMUNICATION,
                subclass: PCI_SUBCLASS_SERIAL,
                prog_if,
            },
            probe,
        });
    }
}

/// Number of PCI UARTs brought up so far.
pub fn port_count() -> usize {
    PORTS.lock().len()
}

/// Run `f` against port `index`, if it exists.
pub fn with_port<R>(index: usize, f: impl FnOnce(&PciUart) -> R) -> Option<R> {
    PORTS.lock().get(index).map(f)
}

#[doc(hidden)]
/// Test-only: drop every probed port so a smoke can assert end-state.
pub fn __reset_for_test() {
    PORTS.lock().clear();
}

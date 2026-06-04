//! UHCI (USB 1.1 Universal Host Controller Interface) — clean-room.
//!
//! ## Sources (public, non-GPL only)
//!
//! - **"Universal Host Controller Interface (UHCI) Design Guide"**,
//!   Revision 1.1, March 1996 (Intel). Public document, no longer
//!   hosted on intel.com (legacy spec); searchable via the document
//!   title. Section references throughout this file (e.g. `§3.x`)
//!   point at that spec.
//! - **USB 2.0 Specification §11** — root-hub class semantics
//!   shared with UHCI's PORTSC bits (UHCI predates USB 2.0 but
//!   uses the same root-hub semantics).
//!     <https://www.usb.org/document-library/usb-20-specification>
//!
//! No GPL/BSD source code (Linux, FreeBSD, NetBSD, U-Boot)
//! consulted at any point during the writing of this driver.
//!
//! ## What this module is
//!
//! UHCI puts its registers in **I/O port space**, not MMIO — a
//! quirk that's hardware-relevant but doesn't change the codec
//! shapes. We define the register offsets, the Frame List layout,
//! and the QH + TD wire formats. Per-port reset + start-of-frame
//! handling lands when wiring live x86 I/O port access.
//!
//! Memory model (§3):
//!
//! - **I/O Registers** at the BAR base (USBCMD .. PORTSC[1]).
//! - **Frame List** — 1024 × 4-byte pointers, page-aligned (4 KiB),
//!   pointed at by `FRBASEADD`. Each entry's bit 0 is Terminate;
//!   bit 1 is QH (1)/TD(0). Hardware indexes by `FRNUM[10:0]`.
//! - **Transfer Descriptor** — 32 bytes (4 DWords + reserved /
//!   padding); software-only fields can be tucked into the unused
//!   bytes.
//! - **Queue Head** — 8 bytes. UHCI QHs are *much* simpler than
//!   EHCI QHs: just two pointers (link + element).

extern crate alloc;
use alloc::vec::Vec;

// ── I/O Register offsets (§2.1) ──────────────────────────────────

pub mod regs {
    /// USBCMD — 16-bit (§2.1.1).
    pub const USBCMD: usize = 0x00;
    /// USBSTS — 16-bit (§2.1.2). W1C.
    pub const USBSTS: usize = 0x02;
    /// USBINTR — 16-bit (§2.1.3).
    pub const USBINTR: usize = 0x04;
    /// FRNUM — 16-bit (§2.1.4). Bits [10:0] = current frame.
    pub const FRNUM: usize = 0x06;
    /// FRBASEADD — 32-bit (§2.1.5). Frame List base, 4 KiB aligned.
    pub const FRBASEADD: usize = 0x08;
    /// SOFMOD — 8-bit (§2.1.6). 1-ms SOF timing tweak.
    pub const SOFMOD: usize = 0x0C;
    /// PORTSC[N] — 16-bit each (§2.1.7). UHCI HCs always have 2
    /// downstream ports.
    pub const PORTSC1: usize = 0x10;
    pub const PORTSC2: usize = 0x12;
}

/// PCI cfg-space offset for the legacy-support register (§5.2).
/// Writing a 1 to bit 4 (release legacy SMI) is the canonical
/// "claim from the BIOS" sequence.
pub mod pci_legacy {
    pub const USBLEGSUP_OFFSET: u8 = 0xC0;
    pub const RELEASE_SMI: u16 = 0x8F00;
}

/// `USBCMD` (§2.1.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UsbCmd(pub u16);

impl UsbCmd {
    pub const RUN_STOP: u16 = 1 << 0;
    pub const HOST_CONTROLLER_RESET: u16 = 1 << 1;
    pub const GLOBAL_RESET: u16 = 1 << 2;
    pub const ENTER_GLOBAL_SUSPEND: u16 = 1 << 3;
    pub const FORCE_GLOBAL_RESUME: u16 = 1 << 4;
    pub const SOFTWARE_DEBUG: u16 = 1 << 5;
    pub const CONFIGURE_FLAG: u16 = 1 << 6;
    pub const MAX_PACKET: u16 = 1 << 7;
}

/// `USBSTS` (§2.1.2). All bits W1C.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UsbSts(pub u16);

impl UsbSts {
    pub const USB_INTERRUPT: u16 = 1 << 0;
    pub const ERROR_INTERRUPT: u16 = 1 << 1;
    pub const RESUME_DETECT: u16 = 1 << 2;
    pub const HOST_SYSTEM_ERROR: u16 = 1 << 3;
    pub const HOST_CONTROLLER_PROCESS_ERROR: u16 = 1 << 4;
    pub const HC_HALTED: u16 = 1 << 5;
}

/// `PORTSC[N]` (§2.1.7).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortSc(pub u16);

impl PortSc {
    pub const CURRENT_CONNECT_STATUS: u16 = 1 << 0;
    pub const CONNECT_STATUS_CHANGE: u16 = 1 << 1; // W1C
    pub const PORT_ENABLE: u16 = 1 << 2;
    pub const PORT_ENABLE_CHANGE: u16 = 1 << 3; // W1C
    /// Line Status, bits [5:4]. 00 = SE0, 01 = K-state (low-speed
    /// when reset), 10 = J-state, 11 = reserved.
    pub const LINE_STATUS_MASK: u16 = 0b11 << 4;
    pub const RESUME_DETECT: u16 = 1 << 6;
    pub const LOW_SPEED_DEVICE: u16 = 1 << 8;
    pub const PORT_RESET: u16 = 1 << 9;
    pub const SUSPEND: u16 = 1 << 12;

    pub fn connected(self) -> bool {
        self.0 & Self::CURRENT_CONNECT_STATUS != 0
    }
    pub fn low_speed(self) -> bool {
        self.0 & Self::LOW_SPEED_DEVICE != 0
    }
}

// ── Frame List Pointer (§3.1) ────────────────────────────────────

/// One entry in the 1024-entry Frame List. Bits [3:0] of the
/// physical pointer are reused: bit 0 = Terminate, bit 1 = QH/TD
/// flag (1 = QH, 0 = TD). The remaining 28 bits give the 16-byte
/// aligned address of the next descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FrameListPtr(pub u32);

impl FrameListPtr {
    pub fn terminate(self) -> bool {
        self.0 & 1 != 0
    }
    pub fn is_qh(self) -> bool {
        self.0 & (1 << 1) != 0
    }
    pub fn ptr(self) -> u32 {
        self.0 & 0xFFFF_FFF0
    }
    pub fn make(ptr: u32, is_qh: bool) -> Self {
        let mut v = ptr & 0xFFFF_FFF0;
        if is_qh {
            v |= 1 << 1;
        }
        Self(v)
    }
    pub fn make_terminate() -> Self {
        Self(1)
    }
}

// ── Transfer Descriptor (§3.2.1) ─────────────────────────────────

/// Direction PID written into the TD Token DWord (§3.2.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TdPid {
    In = 0x69,
    Out = 0xE1,
    Setup = 0x2D,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Td {
    /// Link Pointer DWord. Same layout as a Frame List entry.
    pub link: FrameListPtr,
    /// Status / Control DWord (§3.2.1 dword 1).
    pub actual_length: u16, // bits [10:0]
    pub status: u8, // bits [23:16]
    pub interrupt_on_completion: bool,
    pub iso: bool,
    pub low_speed: bool,
    pub error_count: u8, // bits [28:27]
    pub short_packet_detect: bool,
    /// Token DWord (§3.2.1 dword 2).
    pub pid: TdPid,
    pub device_addr: u8,   // bits [14:8]
    pub endpoint: u8,      // bits [18:15]
    pub data_toggle: bool, // bit 19
    pub max_len: u16,      // bits [31:21]
    /// Buffer pointer DWord — flat 32-bit address.
    pub buffer: u32,
}

impl Td {
    pub fn pack(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&self.link.0.to_le_bytes());

        let mut d1 = (self.actual_length as u32) & 0x7FF;
        d1 |= ((self.status as u32) & 0xFF) << 16;
        if self.interrupt_on_completion {
            d1 |= 1 << 24;
        }
        if self.iso {
            d1 |= 1 << 25;
        }
        if self.low_speed {
            d1 |= 1 << 26;
        }
        d1 |= ((self.error_count as u32) & 0x3) << 27;
        if self.short_packet_detect {
            d1 |= 1 << 29;
        }
        b[4..8].copy_from_slice(&d1.to_le_bytes());

        let mut d2 = (self.pid as u32) & 0xFF;
        d2 |= ((self.device_addr as u32) & 0x7F) << 8;
        d2 |= ((self.endpoint as u32) & 0xF) << 15;
        if self.data_toggle {
            d2 |= 1 << 19;
        }
        d2 |= ((self.max_len as u32) & 0x7FF) << 21;
        b[8..12].copy_from_slice(&d2.to_le_bytes());

        b[12..16].copy_from_slice(&self.buffer.to_le_bytes());
        b
    }
    pub fn unpack(b: &[u8; 16]) -> Self {
        let link = FrameListPtr(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        let d1 = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let d2 = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        let buffer = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
        Self {
            link,
            actual_length: (d1 & 0x7FF) as u16,
            status: ((d1 >> 16) & 0xFF) as u8,
            interrupt_on_completion: d1 & (1 << 24) != 0,
            iso: d1 & (1 << 25) != 0,
            low_speed: d1 & (1 << 26) != 0,
            error_count: ((d1 >> 27) & 0x3) as u8,
            short_packet_detect: d1 & (1 << 29) != 0,
            pid: match (d2 & 0xFF) as u8 {
                0x69 => TdPid::In,
                0xE1 => TdPid::Out,
                0x2D => TdPid::Setup,
                _ => TdPid::In, // reserved value treated as IN
            },
            device_addr: ((d2 >> 8) & 0x7F) as u8,
            endpoint: ((d2 >> 15) & 0xF) as u8,
            data_toggle: d2 & (1 << 19) != 0,
            max_len: ((d2 >> 21) & 0x7FF) as u16,
            buffer,
        }
    }
}

/// TD Status bits (§3.2.1 dword 1, bits [23:16]).
pub mod td_status {
    pub const ACTIVE: u8 = 1 << 7;
    pub const STALLED: u8 = 1 << 6;
    pub const DATA_BUFFER_ERROR: u8 = 1 << 5;
    pub const BABBLE_DETECTED: u8 = 1 << 4;
    pub const NAK_RECEIVED: u8 = 1 << 3;
    pub const CRC_TIMEOUT_ERROR: u8 = 1 << 2;
    pub const BITSTUFF_ERROR: u8 = 1 << 1;
}

// ── Queue Head (§3.2.2) ──────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Qh {
    pub link: FrameListPtr,
    pub element: FrameListPtr,
}

impl Qh {
    pub fn pack(self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&self.link.0.to_le_bytes());
        b[4..8].copy_from_slice(&self.element.0.to_le_bytes());
        b
    }
    pub fn unpack(b: &[u8; 8]) -> Self {
        Self {
            link: FrameListPtr(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            element: FrameListPtr(u32::from_le_bytes([b[4], b[5], b[6], b[7]])),
        }
    }
}

/// Build a 1024-entry Frame List with every entry pointing to the
/// same QH + Terminate-on-next set. This is the canonical "all
/// frames serve the same async/control schedule" pattern from the
/// UHCI design guide §3.4 (Periodic Schedule Construction).
pub fn make_frame_list_pointing_to(qh_addr: u32) -> Vec<u32> {
    let v = FrameListPtr::make(qh_addr, true).0;
    alloc::vec![v; 1024]
}

// ── PCI bind glue ───────────────────────────────────────────────
//
// UHCI controllers identify on PCI as base class 0x0C (Serial
// Bus), subclass 0x03 (USB), prog-if 0x00 (USB 1.1, Universal HCI).
// UHCI is Intel's legacy USB-1.1 controller — it predates EHCI by
// several years and uses **I/O port** registers rather than MMIO,
// which means BAR4 (UHCI Design Guide §2 — "PCI configuration
// space, Base Address Register #4") rather than BAR0.
//
// Renoir and Phoenix laptops carry no UHCI silicon (AMD never
// shipped UHCI; their chipsets used OHCI for USB-1.1). The probe
// scaffolding lives here so a board with a discrete UHCI block
// (an Intel ICH-family chipset, a PCIe USB-1.1 expansion card)
// still gets a log line. Live bring-up — outb/inb against the
// USBCMD/PORTSC ports, frame-list management — is intentionally
// deferred. The probe just reads the I/O BAR base and logs.

/// PCI base class for "Serial Bus Controllers".
const PCI_CLASS_SERIAL_BUS: u8 = 0x0C;
/// PCI subclass under Serial Bus for "USB".
const PCI_SUBCLASS_USB: u8 = 0x03;
/// PCI prog-if for UHCI under USB.
const PCI_PROGIF_UHCI: u8 = 0x00;

/// UHCI registers live in I/O port space; the BAR slot per the
/// UHCI Design Guide §2 is BAR4 (offset 0x20 in cfg space).
const UHCI_BAR_INDEX: u8 = 4;

pub fn probe(
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<(), narf_bus::ProbeError> {
    let class = ((device.id.class >> 16) & 0xFF) as u8;
    let subclass = ((device.id.class >> 8) & 0xFF) as u8;
    let prog_if = (device.id.class & 0xFF) as u8;
    if class != PCI_CLASS_SERIAL_BUS || subclass != PCI_SUBCLASS_USB || prog_if != PCI_PROGIF_UHCI {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    // UHCI needs IO_SPACE + BUS_MASTER + INTX_DISABLE — the legacy
    // controller signals interrupts via INTx by default, so we
    // mask them at the PCI Command register and the (eventual)
    // live driver will manage them itself.
    let _ = narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::IO_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    );
    // UHCI BAR4 is an I/O-port BAR — `map_bar` rejects those, so
    // go through `read_bar` directly.
    // SAFETY: caller-authority + exclusive cfg-window claim
    // (probe path; bus walker holds the lock).
    let bar = match unsafe { narf_bus::read_bar(&device, UHCI_BAR_INDEX) } {
        Ok(b) => b,
        Err(_) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  uhci: BAR{} read failed for {:04x}:{:04x}",
                UHCI_BAR_INDEX,
                device.id.vendor,
                device.id.device
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };
    if !matches!(bar.kind, narf_bus::BarKind::Io) {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  uhci: BAR{} not an I/O port BAR (kind={:?})",
            UHCI_BAR_INDEX,
            bar.kind
        );
        return Err(narf_bus::ProbeError::BadDevice);
    }
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  uhci: probed {:04x}:{:04x} I/O base=0x{:x} (not implemented)",
        device.id.vendor,
        device.id.device,
        bar.phys.raw(),
    );
    Err(narf_bus::ProbeError::Other("uhci: not implemented"))
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "uhci-class",
        kind: narf_bus::MatchKind::ClassFull {
            class: PCI_CLASS_SERIAL_BUS,
            subclass: PCI_SUBCLASS_USB,
            prog_if: PCI_PROGIF_UHCI,
        },
        probe,
    });
}

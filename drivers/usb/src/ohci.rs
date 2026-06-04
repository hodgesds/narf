//! OHCI (USB 1.1 Open Host Controller Interface) — clean-room.
//!
//! ## Sources (public only)
//!
//! - **"OpenHCI — Open Host Controller Interface Specification for
//!   USB"**, Release 1.0a, September 14, 1999. Compaq / Microsoft /
//!   National Semiconductor. Public.
//!   <https://composter.com.ua/documents/ohci_specification.pdf>
//! - **USB 2.0 Specification §11** — root-hub class semantics
//!   shared with OHCI's HcRhPortStatus bits.
//!   <https://www.usb.org/document-library/usb-20-specification>
//!
//! No GPL / Linux source consulted.
//!
//! ## What this module is
//!
//! Register-block decoders + DMA descriptor (ED / TD) builders.
//! Like the EHCI counterpart, the schedule traversal hot path is
//! deferred to live-MMIO bring-up; this pass nails down the wire
//! formats so the bring-up can go straight to plumbing.
//!
//! Memory model (§4):
//!
//! - **Operational Registers** at the start of the MMIO BAR.
//! - **HCCA** (Host Controller Communication Area) — 256-byte
//!   DMA-coherent block the HC writes to. Pointed at by `HcHCCA`.
//! - **EDs** (Endpoint Descriptors) — 16 bytes each, 16-byte
//!   aligned. Per-endpoint queue head; HC traverses linked lists
//!   of EDs each frame.
//! - **TDs** (Transfer Descriptors) — 16 bytes (general) or 32
//!   bytes (isochronous). Each ED owns a list of TDs, each TD a
//!   single transfer.

extern crate alloc;
use alloc::vec::Vec;

// ── Operational Registers (§7) ───────────────────────────────────

pub mod regs {
    pub const HC_REVISION: usize = 0x00;
    pub const HC_CONTROL: usize = 0x04;
    pub const HC_COMMAND_STATUS: usize = 0x08;
    pub const HC_INTERRUPT_STATUS: usize = 0x0C;
    pub const HC_INTERRUPT_ENABLE: usize = 0x10;
    pub const HC_INTERRUPT_DISABLE: usize = 0x14;
    pub const HC_HCCA: usize = 0x18;
    pub const HC_PERIOD_CURRENT_ED: usize = 0x1C;
    pub const HC_CONTROL_HEAD_ED: usize = 0x20;
    pub const HC_CONTROL_CURRENT_ED: usize = 0x24;
    pub const HC_BULK_HEAD_ED: usize = 0x28;
    pub const HC_BULK_CURRENT_ED: usize = 0x2C;
    pub const HC_DONE_HEAD: usize = 0x30;
    pub const HC_FM_INTERVAL: usize = 0x34;
    pub const HC_FM_REMAINING: usize = 0x38;
    pub const HC_FM_NUMBER: usize = 0x3C;
    pub const HC_PERIODIC_START: usize = 0x40;
    pub const HC_LS_THRESHOLD: usize = 0x44;
    pub const HC_RH_DESCRIPTOR_A: usize = 0x48;
    pub const HC_RH_DESCRIPTOR_B: usize = 0x4C;
    pub const HC_RH_STATUS: usize = 0x50;
    /// HcRhPortStatus[N]: starts at 0x54, one per downstream port.
    pub const HC_RH_PORT_STATUS_BASE: usize = 0x54;
}

/// `HcControl` (§7.1.2). Functional state + list-enable flags.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HcControl(pub u32);

impl HcControl {
    /// Control Bulk Service Ratio — bits [1:0]. The HC traverses
    /// this many control EDs for each bulk ED.
    pub const CBSR_MASK: u32 = 0b11;
    pub const PERIODIC_LIST_ENABLE: u32 = 1 << 2;
    pub const ISOCH_ENABLE: u32 = 1 << 3;
    pub const CONTROL_LIST_ENABLE: u32 = 1 << 4;
    pub const BULK_LIST_ENABLE: u32 = 1 << 5;
    /// HostControllerFunctionalState, bits [7:6].
    /// 00 = USBRESET, 01 = USBRESUME, 10 = USBOPERATIONAL,
    /// 11 = USBSUSPEND.
    pub const HCFS_MASK: u32 = 0b11 << 6;
    pub const INTERRUPT_ROUTING: u32 = 1 << 8;
    pub const REMOTE_WAKEUP_CONNECTED: u32 = 1 << 9;
    pub const REMOTE_WAKEUP_ENABLE: u32 = 1 << 10;

    pub fn hcfs(self) -> Hcfs {
        match (self.0 & Self::HCFS_MASK) >> 6 {
            0 => Hcfs::Reset,
            1 => Hcfs::Resume,
            2 => Hcfs::Operational,
            _ => Hcfs::Suspend,
        }
    }
    pub fn with_hcfs(self, s: Hcfs) -> Self {
        Self((self.0 & !Self::HCFS_MASK) | ((s as u32) << 6))
    }
}

/// HostControllerFunctionalState (§7.1.2 bits [7:6]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Hcfs {
    Reset = 0,
    Resume = 1,
    Operational = 2,
    Suspend = 3,
}

/// `HcInterruptStatus` / `HcInterruptEnable` / `HcInterruptDisable`
/// (§7.1.4). Status is W1C; enable/disable use OR semantics.
pub mod intr {
    pub const SCHEDULING_OVERRUN: u32 = 1 << 0;
    pub const WRITEBACK_DONE_HEAD: u32 = 1 << 1;
    pub const START_OF_FRAME: u32 = 1 << 2;
    pub const RESUME_DETECTED: u32 = 1 << 3;
    pub const UNRECOVERABLE_ERROR: u32 = 1 << 4;
    pub const FRAME_NUMBER_OVERFLOW: u32 = 1 << 5;
    pub const ROOT_HUB_STATUS_CHANGE: u32 = 1 << 6;
    pub const OWNERSHIP_CHANGE: u32 = 1 << 30;
    pub const MASTER_INTERRUPT_ENABLE: u32 = 1 << 31;
}

/// `HcRhDescriptorA` (§7.4.1). Mostly read-only; describes the
/// number of downstream ports + power-switching mode.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HcRhDescriptorA(pub u32);

impl HcRhDescriptorA {
    pub fn ndp(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
    pub fn power_switching_mode(self) -> bool {
        // 0 = global, 1 = per-port.
        self.0 & (1 << 8) != 0
    }
    pub fn no_power_switching(self) -> bool {
        self.0 & (1 << 9) != 0
    }
    pub fn potpgt_2ms(self) -> u8 {
        // Bits [31:24], in 2-ms units.
        ((self.0 >> 24) & 0xFF) as u8
    }
}

/// `HcRhPortStatus[N]` (§7.4.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HcRhPortStatus(pub u32);

impl HcRhPortStatus {
    pub const CURRENT_CONNECT_STATUS: u32 = 1 << 0;
    pub const PORT_ENABLE_STATUS: u32 = 1 << 1;
    pub const PORT_SUSPEND_STATUS: u32 = 1 << 2;
    pub const OVERCURRENT_STATUS: u32 = 1 << 3;
    pub const PORT_RESET_STATUS: u32 = 1 << 4;
    pub const PORT_POWER_STATUS: u32 = 1 << 8;
    pub const LOW_SPEED_DEVICE: u32 = 1 << 9;
    pub const CONNECT_STATUS_CHANGE: u32 = 1 << 16;
    pub const PORT_ENABLE_STATUS_CHANGE: u32 = 1 << 17;
    pub const PORT_SUSPEND_STATUS_CHANGE: u32 = 1 << 18;
    pub const OVERCURRENT_CHANGE: u32 = 1 << 19;
    pub const PORT_RESET_STATUS_CHANGE: u32 = 1 << 20;

    pub fn connected(self) -> bool {
        self.0 & Self::CURRENT_CONNECT_STATUS != 0
    }
    pub fn low_speed(self) -> bool {
        self.0 & Self::LOW_SPEED_DEVICE != 0
    }
}

// ── Endpoint Descriptor (§4.2) ───────────────────────────────────

/// Direction (§4.2 ED dword 0, bits [12:11]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EdDir {
    /// Direction taken from the TD PID byte.
    FromTd = 0,
    Out = 1,
    In = 2,
    /// Reserved — encoded as `FromTd` per the spec note.
    Reserved = 3,
}

/// Endpoint speed (§4.2 ED dword 0, bit 13).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EdSpeed {
    Full = 0,
    Low = 1,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ed {
    pub fa: u8,            // bits [6:0] Function Address
    pub en: u8,            // bits [10:7] Endpoint Number
    pub dir: EdDir,        // bits [12:11]
    pub speed: EdSpeed,    // bit 13
    pub skip: bool,        // bit 14
    pub format_iso: bool,  // bit 15: 0 = General TD, 1 = Iso TD
    pub max_packet: u16,   // bits [26:16]
    pub tail_pointer: u32, // dword 1
    /// Head pointer (low 28 bits; bit 0 = Halted, bit 1 = Toggle
    /// Carry).
    pub head_pointer: u32,
    pub head_halted: bool,
    pub head_toggle_carry: bool,
    pub next_ed: u32, // dword 3
}

impl Ed {
    pub fn pack(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        let mut d0 = (self.fa as u32) & 0x7F;
        d0 |= ((self.en as u32) & 0xF) << 7;
        d0 |= (self.dir as u32 & 0x3) << 11;
        d0 |= (self.speed as u32 & 0x1) << 13;
        if self.skip {
            d0 |= 1 << 14;
        }
        if self.format_iso {
            d0 |= 1 << 15;
        }
        d0 |= ((self.max_packet as u32) & 0x7FF) << 16;
        b[0..4].copy_from_slice(&d0.to_le_bytes());
        b[4..8].copy_from_slice(&(self.tail_pointer & 0xFFFF_FFF0).to_le_bytes());
        let mut head = self.head_pointer & 0xFFFF_FFF0;
        if self.head_halted {
            head |= 1;
        }
        if self.head_toggle_carry {
            head |= 1 << 1;
        }
        b[8..12].copy_from_slice(&head.to_le_bytes());
        b[12..16].copy_from_slice(&(self.next_ed & 0xFFFF_FFF0).to_le_bytes());
        b
    }
    pub fn unpack(b: &[u8; 16]) -> Self {
        let d0 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let tp = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let hp = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        let ne = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
        let dir = match (d0 >> 11) & 0x3 {
            0 => EdDir::FromTd,
            1 => EdDir::Out,
            2 => EdDir::In,
            _ => EdDir::Reserved,
        };
        Self {
            fa: (d0 & 0x7F) as u8,
            en: ((d0 >> 7) & 0xF) as u8,
            dir,
            speed: if d0 & (1 << 13) != 0 {
                EdSpeed::Low
            } else {
                EdSpeed::Full
            },
            skip: d0 & (1 << 14) != 0,
            format_iso: d0 & (1 << 15) != 0,
            max_packet: ((d0 >> 16) & 0x7FF) as u16,
            tail_pointer: tp & 0xFFFF_FFF0,
            head_pointer: hp & 0xFFFF_FFF0,
            head_halted: hp & 1 != 0,
            head_toggle_carry: hp & (1 << 1) != 0,
            next_ed: ne & 0xFFFF_FFF0,
        }
    }
}

// ── General Transfer Descriptor (§4.3.1) ─────────────────────────

/// TD direction PID (§4.3.1 dword 0, bits [20:19]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TdPid {
    Setup = 0,
    Out = 1,
    In = 2,
    Reserved = 3,
}

/// Completion Code (§4.3.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CompletionCode {
    NoError = 0,
    Crc = 1,
    BitStuffing = 2,
    DataToggleMismatch = 3,
    Stall = 4,
    DeviceNotResponding = 5,
    PidCheckFailure = 6,
    UnexpectedPid = 7,
    DataOverrun = 8,
    DataUnderrun = 9,
    /// Codes 10-11 are reserved.
    BufferOverrun = 12,
    BufferUnderrun = 13,
    NotAccessed = 15,
    Unknown = 0xFE,
}

impl CompletionCode {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::NoError,
            1 => Self::Crc,
            2 => Self::BitStuffing,
            3 => Self::DataToggleMismatch,
            4 => Self::Stall,
            5 => Self::DeviceNotResponding,
            6 => Self::PidCheckFailure,
            7 => Self::UnexpectedPid,
            8 => Self::DataOverrun,
            9 => Self::DataUnderrun,
            12 => Self::BufferOverrun,
            13 => Self::BufferUnderrun,
            15 => Self::NotAccessed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GeneralTd {
    pub buffer_rounding: bool, // bit 18
    pub pid: TdPid,            // bits [20:19]
    /// Delay Interrupt, bits [23:21]. 7 = no interrupt, 0 = next
    /// frame.
    pub delay_interrupt: u8,
    pub data_toggle: u8,                // bits [25:24]
    pub error_count: u8,                // bits [27:26]
    pub condition_code: CompletionCode, // bits [31:28]
    pub current_buffer_pointer: u32,
    pub next_td: u32,
    pub buffer_end: u32,
}

impl GeneralTd {
    pub fn pack(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        let mut d0: u32 = 0;
        if self.buffer_rounding {
            d0 |= 1 << 18;
        }
        d0 |= (self.pid as u32 & 0x3) << 19;
        d0 |= ((self.delay_interrupt as u32) & 0x7) << 21;
        d0 |= ((self.data_toggle as u32) & 0x3) << 24;
        d0 |= ((self.error_count as u32) & 0x3) << 26;
        d0 |= ((self.condition_code as u32) & 0xF) << 28;
        b[0..4].copy_from_slice(&d0.to_le_bytes());
        b[4..8].copy_from_slice(&self.current_buffer_pointer.to_le_bytes());
        b[8..12].copy_from_slice(&(self.next_td & 0xFFFF_FFF0).to_le_bytes());
        b[12..16].copy_from_slice(&self.buffer_end.to_le_bytes());
        b
    }
    pub fn unpack(b: &[u8; 16]) -> Self {
        let d0 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        Self {
            buffer_rounding: d0 & (1 << 18) != 0,
            pid: match (d0 >> 19) & 0x3 {
                0 => TdPid::Setup,
                1 => TdPid::Out,
                2 => TdPid::In,
                _ => TdPid::Reserved,
            },
            delay_interrupt: ((d0 >> 21) & 0x7) as u8,
            data_toggle: ((d0 >> 24) & 0x3) as u8,
            error_count: ((d0 >> 26) & 0x3) as u8,
            condition_code: CompletionCode::from_byte(((d0 >> 28) & 0xF) as u8),
            current_buffer_pointer: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            next_td: u32::from_le_bytes([b[8], b[9], b[10], b[11]]) & 0xFFFF_FFF0,
            buffer_end: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        }
    }
}

// ── HCCA layout (§4.4) ────────────────────────────────────────────

/// Host Controller Communication Area — 256 bytes, aligned to 256
/// bytes. The HC writes `HccaDoneHead` after each frame; the host
/// reads it to find completed TDs.
pub const HCCA_SIZE: usize = 256;
pub const HCCA_INTERRUPT_TABLE_ENTRIES: usize = 32;

/// Indices into the 256-byte HCCA layout.
pub mod hcca {
    pub const INTERRUPT_TABLE_OFFSET: usize = 0;
    pub const FRAME_NUMBER_OFFSET: usize = 0x80;
    /// Two reserved bytes at 0x82..0x84.
    pub const DONE_HEAD_OFFSET: usize = 0x84;
}

/// Walk a packed HCCA blob and extract the current `frame_number`
/// + `done_head`. Useful for tests + a future ISR shim that needs
/// to peek state without taking a lock around the live HCCA.
pub fn read_hcca_status(blob: &[u8]) -> Option<(u16, u32)> {
    if blob.len() < HCCA_SIZE {
        return None;
    }
    let fn_lo = blob[hcca::FRAME_NUMBER_OFFSET];
    let fn_hi = blob[hcca::FRAME_NUMBER_OFFSET + 1];
    let frame = u16::from_le_bytes([fn_lo, fn_hi]);
    let done = u32::from_le_bytes([
        blob[hcca::DONE_HEAD_OFFSET],
        blob[hcca::DONE_HEAD_OFFSET + 1],
        blob[hcca::DONE_HEAD_OFFSET + 2],
        blob[hcca::DONE_HEAD_OFFSET + 3],
    ]);
    Some((frame, done & 0xFFFF_FFF0))
}

/// Iterate a HCCA's interrupt-schedule table and return the 32
/// ED pointers in declaration order.
pub fn hcca_interrupt_eds(blob: &[u8]) -> Option<Vec<u32>> {
    if blob.len() < HCCA_SIZE {
        return None;
    }
    let mut out = Vec::with_capacity(HCCA_INTERRUPT_TABLE_ENTRIES);
    for i in 0..HCCA_INTERRUPT_TABLE_ENTRIES {
        let off = hcca::INTERRUPT_TABLE_OFFSET + i * 4;
        out.push(
            u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]])
                & 0xFFFF_FFF0,
        );
    }
    Some(out)
}

// ── PCI bind glue ───────────────────────────────────────────────
//
// OHCI controllers identify on PCI as base class 0x0C (Serial Bus),
// subclass 0x03 (USB), prog-if 0x10 (USB 1.1, OpenHCI). Renoir /
// Phoenix laptops don't carry OHCI silicon (Intel chipsets used
// UHCI for full-speed; AMD chipsets bridged to OHCI but their
// Stage-3+ designs collapsed everything into xHCI). The probe
// scaffolding lives here so a board with a discrete OHCI block (a
// PCIe USB-1.1 expansion card, an ARM SoC integrating an OHCI
// alongside an xHCI for the legacy companion role) still gets a
// log line.
//
// Full bring-up — endpoint descriptor / transfer descriptor list
// walking, HCCA programming, root-hub port reset — is intentionally
// deferred. The probe maps the BAR, decodes HcRevision, logs, and
// returns `ProbeError::Other("ohci: not implemented")`.

/// PCI base class for "Serial Bus Controllers".
const PCI_CLASS_SERIAL_BUS: u8 = 0x0C;
/// PCI subclass under Serial Bus for "USB".
const PCI_SUBCLASS_USB: u8 = 0x03;
/// PCI prog-if for OHCI under USB.
const PCI_PROGIF_OHCI: u8 = 0x10;

/// OHCI MMIO lives in BAR0 (Memory BAR per §7.1 — "the host
/// controller's operational registers are mapped into PCI
/// memory space").
const OHCI_BAR_INDEX: u8 = 0;

pub fn probe(
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<(), narf_bus::ProbeError> {
    let class = ((device.id.class >> 16) & 0xFF) as u8;
    let subclass = ((device.id.class >> 8) & 0xFF) as u8;
    let prog_if = (device.id.class & 0xFF) as u8;
    if class != PCI_CLASS_SERIAL_BUS || subclass != PCI_SUBCLASS_USB || prog_if != PCI_PROGIF_OHCI {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    let _ = narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    );
    // SAFETY: caller-authority. BAR0 is the OHCI operational-
    // register window.
    let mmio = match unsafe { narf_bus::map_bar(&device, OHCI_BAR_INDEX) } {
        Ok(m) => m,
        Err(_) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  ohci: BAR{} map failed for {:04x}:{:04x}",
                OHCI_BAR_INDEX,
                device.id.vendor,
                device.id.device
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };
    // HcRevision lives at register offset 0x00 — low 8 bits carry
    // the BCD spec revision (§7.1.1, "Revision number of the HCI
    // specification implemented by the HC"). 0x10 = OHCI 1.0a.
    let revision = if mmio.len >= 4 {
        // SAFETY: BAR-backed MMIO, 4 bytes in range.
        unsafe { mmio.read32(0) }
    } else {
        0
    };
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  ohci: probed {:04x}:{:04x} HcRevision=0x{:02x} (not implemented)",
        device.id.vendor,
        device.id.device,
        revision & 0xFF,
    );
    Err(narf_bus::ProbeError::Other("ohci: not implemented"))
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "ohci-class",
        kind: narf_bus::MatchKind::ClassFull {
            class: PCI_CLASS_SERIAL_BUS,
            subclass: PCI_SUBCLASS_USB,
            prog_if: PCI_PROGIF_OHCI,
        },
        probe,
    });
}

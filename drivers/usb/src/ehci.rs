//! EHCI (USB 2.0 high-speed host controller) — clean-room.
//!
//! ## Sources (public only)
//!
//! - **"Enhanced Host Controller Interface Specification for
//!   Universal Serial Bus"**, Revision 1.0, March 12, 2002 (Intel).
//!   Public document. Section numbers below (`§n.n`) refer to that
//!   spec.
//!   <https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/ehci-specification-for-usb.pdf>
//! - **USB 2.0 Specification §11** — root-hub class semantics shared
//!   with EHCI's PORTSC bits.
//!   <https://www.usb.org/document-library/usb-20-specification>
//!
//! No GPL / Linux source consulted.
//!
//! ## What this module is
//!
//! Register-block decoders + DMA descriptor (QH / qTD) builders /
//! parsers. The hot path through MMIO + interrupt routing lands
//! when we wire EHCI into the live `xhci`-shaped controller-pump
//! framework; this pass covers the structure-and-bit-layout half
//! so tests can validate every field without DMA.
//!
//! Memory layout per §3 (Operational Model). Two register windows:
//!
//! - **Capability Registers** — 8 bytes, read-only (mostly).
//!   `CAPLENGTH` is at offset 0 and gives the offset of the
//!   Operational Registers.
//! - **Operational Registers** — variable size (depends on
//!   `HCSPARAMS.N_PORTS`).
//!
//! Schedule data structures live in DMA-coherent memory the host
//! programs into `PERIODICLISTBASE` / `ASYNCLISTADDR`.
//!
//! ## Out of scope (this pass)
//!
//! - Live async/periodic schedule walking (Stage-3 follow-on, paired
//!   with the IOMMU + DMA work).
//! - High-speed companion-controller hand-off (UHCI/OHCI fall-back).
//! - Isochronous TD (`iTD`/`siTD`) — boot devices we care about
//!   don't use isoch.

extern crate alloc;
use alloc::vec::Vec;

// ── Capability Register Block (§2.2) ─────────────────────────────

/// Decoded Capability Register block.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRegs {
    /// Operational-register offset from the start of the MMIO
    /// window. `CAPLENGTH` (§2.2.1).
    pub cap_length: u8,
    /// `HCIVERSION` (§2.2.2). BCD, e.g. `0x0100` for EHCI 1.0.
    pub hci_version: u16,
    pub hcs_params: HcsParams,
    pub hcc_params: HccParams,
}

impl CapabilityRegs {
    /// Decode from the first 16 bytes of the EHCI MMIO window.
    pub fn decode(mmio: &[u8]) -> Option<Self> {
        if mmio.len() < 16 {
            return None;
        }
        Some(Self {
            cap_length: mmio[0],
            hci_version: u16::from_le_bytes([mmio[2], mmio[3]]),
            hcs_params: HcsParams(u32::from_le_bytes([
                mmio[4], mmio[5], mmio[6], mmio[7],
            ])),
            hcc_params: HccParams(u32::from_le_bytes([
                mmio[8], mmio[9], mmio[10], mmio[11],
            ])),
        })
    }
}

/// `HCSPARAMS` — Structural Parameters (§2.2.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HcsParams(pub u32);

impl HcsParams {
    /// Number of physical downstream ports the HC implements. Bits
    /// [3:0]; legal range 1..=15.
    pub fn n_ports(self) -> u8 {
        (self.0 & 0x0F) as u8
    }
    /// Port Power Control (bit 4). When set, the controller can
    /// switch port power on/off via `PORTSC.PortPower`.
    pub fn ppc(self) -> bool {
        self.0 & (1 << 4) != 0
    }
    /// Port Routing Rules (bit 7). 0 = first N_PCC ports go to
    /// the first companion controller; 1 = explicit routing
    /// table follows in `HCSP-PORTROUTE`.
    pub fn port_routing_rules(self) -> bool {
        self.0 & (1 << 7) != 0
    }
    /// Number of ports per companion controller. Bits [11:8].
    pub fn n_pcc(self) -> u8 {
        ((self.0 >> 8) & 0x0F) as u8
    }
    /// Number of companion controllers. Bits [15:12].
    pub fn n_cc(self) -> u8 {
        ((self.0 >> 12) & 0x0F) as u8
    }
    /// Port Indicators (bit 16) — HC supports per-port LED
    /// indicators per USB 2.0 §11.5.3.
    pub fn p_indicator(self) -> bool {
        self.0 & (1 << 16) != 0
    }
    /// Debug Port Number (bits [23:20]).
    pub fn debug_port(self) -> u8 {
        ((self.0 >> 20) & 0x0F) as u8
    }
}

/// `HCCPARAMS` — Capability Parameters (§2.2.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HccParams(pub u32);

impl HccParams {
    /// 64-bit Addressing Capability (bit 0). When set, the HC
    /// supports the upper-32-bit segment register
    /// (`CTRLDSSEGMENT`).
    pub fn addr64(self) -> bool {
        self.0 & 1 != 0
    }
    /// Programmable Frame List Flag (bit 1). When set, the host
    /// can choose 256 / 512 / 1024 entry frame lists via
    /// `USBCMD.FrameListSize`.
    pub fn programmable_framelist(self) -> bool {
        self.0 & (1 << 1) != 0
    }
    /// Async Schedule Park Capability (bit 2).
    pub fn async_park(self) -> bool {
        self.0 & (1 << 2) != 0
    }
    /// Isochronous Scheduling Threshold (bits [7:4]).
    pub fn ist(self) -> u8 {
        ((self.0 >> 4) & 0x0F) as u8
    }
    /// Extended Capabilities Pointer (bits [15:8]). PCI cfg-space
    /// offset of the first EHCI extended capability (e.g. legacy-
    /// support, ownership hand-off). 0 = no extended caps.
    pub fn eecp(self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }
}

// ── Operational Register Block (§2.3) ────────────────────────────

/// MMIO offsets within the Operational Register block. Each is a
/// 32-bit register unless noted.
pub mod op_regs {
    pub const USBCMD: usize = 0x00;
    pub const USBSTS: usize = 0x04;
    pub const USBINTR: usize = 0x08;
    pub const FRINDEX: usize = 0x0C;
    pub const CTRLDSSEGMENT: usize = 0x10;
    pub const PERIODICLISTBASE: usize = 0x14;
    pub const ASYNCLISTADDR: usize = 0x18;
    pub const CONFIGFLAG: usize = 0x40;
    /// PORTSC[N]: starts at 0x44, one 32-bit register per port.
    pub const PORTSC_BASE: usize = 0x44;
}

/// `USBCMD` (§2.3.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UsbCmd(pub u32);

impl UsbCmd {
    pub const RUN_STOP: u32 = 1 << 0;
    pub const HCRESET: u32 = 1 << 1;
    /// Frame List Size: 0 = 1024, 1 = 512, 2 = 256, 3 = reserved.
    /// Bits [3:2].
    pub const FRAMELIST_SIZE_MASK: u32 = 0b11 << 2;
    pub const PERIODIC_SCHEDULE_ENABLE: u32 = 1 << 4;
    pub const ASYNC_SCHEDULE_ENABLE: u32 = 1 << 5;
    pub const INTERRUPT_ON_ASYNC_ADVANCE_DOORBELL: u32 = 1 << 6;
    pub const LIGHT_HC_RESET: u32 = 1 << 7;
    /// Async-park-mode Count, bits [9:8].
    pub const ASYNC_PARK_COUNT_MASK: u32 = 0b11 << 8;
    pub const ASYNC_PARK_ENABLE: u32 = 1 << 11;
    /// Interrupt Threshold Control, bits [23:16].
    pub const INTR_THRESHOLD_MASK: u32 = 0xFF << 16;

    pub fn run_stop(self) -> bool {
        self.0 & Self::RUN_STOP != 0
    }
    pub fn frame_list_entries(self) -> u32 {
        match (self.0 & Self::FRAMELIST_SIZE_MASK) >> 2 {
            0 => 1024,
            1 => 512,
            2 => 256,
            _ => 0,
        }
    }
}

/// `USBSTS` (§2.3.2). Status bits; W1C — write a 1 to clear.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UsbSts(pub u32);

impl UsbSts {
    pub const USB_INTERRUPT: u32 = 1 << 0;
    pub const ERROR_INTERRUPT: u32 = 1 << 1;
    pub const PORT_CHANGE_DETECT: u32 = 1 << 2;
    pub const FRAME_LIST_ROLLOVER: u32 = 1 << 3;
    pub const HOST_SYSTEM_ERROR: u32 = 1 << 4;
    pub const INTERRUPT_ON_ASYNC_ADVANCE: u32 = 1 << 5;
    /// Status: 1 = HC is halted, 0 = running. Bit 12.
    pub const HC_HALTED: u32 = 1 << 12;
    pub const RECLAMATION: u32 = 1 << 13;
    pub const PERIODIC_SCHEDULE_STATUS: u32 = 1 << 14;
    pub const ASYNC_SCHEDULE_STATUS: u32 = 1 << 15;

    pub fn halted(self) -> bool {
        self.0 & Self::HC_HALTED != 0
    }
}

/// `PORTSC[N]` (§2.3.8). Per-port status + control. Several bits
/// are W1C — caller must mask carefully on write-back.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortSc(pub u32);

impl PortSc {
    pub const CURRENT_CONNECT_STATUS: u32 = 1 << 0;
    pub const CONNECT_STATUS_CHANGE: u32 = 1 << 1; // W1C
    pub const PORT_ENABLED: u32 = 1 << 2;
    pub const PORT_ENABLE_CHANGE: u32 = 1 << 3; // W1C
    pub const OVERCURRENT_ACTIVE: u32 = 1 << 4;
    pub const OVERCURRENT_CHANGE: u32 = 1 << 5; // W1C
    pub const FORCE_PORT_RESUME: u32 = 1 << 6;
    pub const SUSPEND: u32 = 1 << 7;
    pub const PORT_RESET: u32 = 1 << 8;
    /// Line Status, bits [11:10]: 00 = SE0, 01 = K-state (low-speed),
    /// 10 = J-state (full-speed), 11 = reserved.
    pub const LINE_STATUS_MASK: u32 = 0b11 << 10;
    pub const PORT_POWER: u32 = 1 << 12;
    /// Port Owner: 0 = EHCI, 1 = companion (OHCI/UHCI).
    pub const PORT_OWNER: u32 = 1 << 13;
    /// Bits cleared by W1C masks.
    pub const RWC_MASK: u32 = Self::CONNECT_STATUS_CHANGE
        | Self::PORT_ENABLE_CHANGE
        | Self::OVERCURRENT_CHANGE;

    pub fn connected(self) -> bool {
        self.0 & Self::CURRENT_CONNECT_STATUS != 0
    }
    pub fn enabled(self) -> bool {
        self.0 & Self::PORT_ENABLED != 0
    }
    pub fn line_status(self) -> u8 {
        ((self.0 & Self::LINE_STATUS_MASK) >> 10) as u8
    }
    /// Returns `true` if the port should be released to a companion
    /// controller. Per §4.2: a low-speed device shows up with
    /// LineStatus = `01` (K-state) at port-reset time, and the EHCI
    /// driver hands the port to the companion by writing 1 to
    /// `PORT_OWNER`.
    pub fn is_low_speed_at_reset(self) -> bool {
        self.line_status() == 0b01
    }
    /// Combine a current-state read with a write that clears the
    /// W1C change bits and additionally writes `set` bits. Use this
    /// when programming PortReset / PortPower etc., to avoid
    /// inadvertently clearing changes the driver hasn't observed.
    pub fn with_writable(current: u32, set: u32) -> u32 {
        // Mask off all W1C change bits, then OR in the requested
        // set. Caller can pass `current & !RWC_MASK` if it wants
        // to preserve unrelated change bits — but the standard
        // pattern is to clear them via a dedicated W1C write.
        (current & !Self::RWC_MASK) | set
    }
}

// ── Schedule Data Structures (§3) ─────────────────────────────────

/// Direction / PID of a `qTD` (§3.5 Token DWord 2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QtdPid {
    Out = 0,
    In = 1,
    Setup = 2,
}

/// Queue element Transfer Descriptor — §3.5. 32 bytes, 32-bit
/// aligned in DMA memory. Fields here are decoded into native
/// types; [`Qtd::pack`] yields the 32-byte little-endian wire
/// form.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Qtd {
    /// Next qTD pointer. Bit 0 of the wire form is the Terminate
    /// bit; we expose it separately.
    pub next: u32,
    pub next_terminate: bool,
    /// Alternate-next qTD pointer (used on Short Packet during IN).
    pub alt_next: u32,
    pub alt_next_terminate: bool,
    /// Token DWord (§3.5 dword 2).
    pub status: u8, // bits [7:0]
    pub pid: QtdPid,
    /// Error counter (CErr), bits [11:10]. Decremented on bus
    /// error; transfer halts when it hits 0.
    pub err_count: u8,
    /// Current page index, bits [14:12].
    pub page_index: u8,
    /// Interrupt-on-complete, bit 15.
    pub ioc: bool,
    /// Total bytes to transfer, bits [30:16]. Hardware decrements
    /// on each successful packet.
    pub total_bytes: u16,
    /// Data Toggle, bit 31.
    pub data_toggle: bool,
    /// Buffer Page pointers (5 × 32 bits). Each must be 4 KiB
    /// aligned.
    pub buffer_pages: [u32; 5],
}

impl Qtd {
    /// Pack into the 32-byte wire form (LE, 32-bit aligned). Caller
    /// owns the memory and must arrange 32-byte alignment for the
    /// HC's DMA.
    pub fn pack(self) -> [u8; 32] {
        let mut b = [0u8; 32];
        let next = (self.next & 0xFFFF_FFE0) | if self.next_terminate { 1 } else { 0 };
        b[0..4].copy_from_slice(&next.to_le_bytes());
        let alt = (self.alt_next & 0xFFFF_FFE0) | if self.alt_next_terminate { 1 } else { 0 };
        b[4..8].copy_from_slice(&alt.to_le_bytes());

        let mut tok = self.status as u32;
        tok |= (self.pid as u32 & 0x3) << 8;
        tok |= ((self.err_count as u32) & 0x3) << 10;
        tok |= ((self.page_index as u32) & 0x7) << 12;
        if self.ioc {
            tok |= 1 << 15;
        }
        tok |= ((self.total_bytes as u32) & 0x7FFF) << 16;
        if self.data_toggle {
            tok |= 1 << 31;
        }
        b[8..12].copy_from_slice(&tok.to_le_bytes());
        for (i, p) in self.buffer_pages.iter().enumerate() {
            let off = 12 + i * 4;
            b[off..off + 4].copy_from_slice(&p.to_le_bytes());
        }
        b
    }

    /// Decode from a 32-byte wire form.
    pub fn unpack(buf: &[u8; 32]) -> Self {
        let next = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let alt = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let tok = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let pid = match (tok >> 8) & 0x3 {
            0 => QtdPid::Out,
            1 => QtdPid::In,
            2 => QtdPid::Setup,
            _ => QtdPid::Out, // reserved value; dump as Out.
        };
        let mut pages = [0u32; 5];
        for i in 0..5 {
            let off = 12 + i * 4;
            pages[i] = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        }
        Self {
            next: next & 0xFFFF_FFE0,
            next_terminate: next & 1 != 0,
            alt_next: alt & 0xFFFF_FFE0,
            alt_next_terminate: alt & 1 != 0,
            status: tok as u8,
            pid,
            err_count: ((tok >> 10) & 0x3) as u8,
            page_index: ((tok >> 12) & 0x7) as u8,
            ioc: tok & (1 << 15) != 0,
            total_bytes: ((tok >> 16) & 0x7FFF) as u16,
            data_toggle: tok & (1 << 31) != 0,
            buffer_pages: pages,
        }
    }
}

/// `qTD` Status bits (§3.5.1).
pub mod qtd_status {
    pub const ACTIVE: u8 = 1 << 7;
    pub const HALTED: u8 = 1 << 6;
    pub const DATA_BUFFER_ERROR: u8 = 1 << 5;
    pub const BABBLE: u8 = 1 << 4;
    pub const TRANSACTION_ERROR: u8 = 1 << 3;
    pub const MISSED_MICROFRAME: u8 = 1 << 2;
    pub const SPLIT_TRANSACTION_STATE: u8 = 1 << 1;
    pub const PING_STATE: u8 = 1 << 0;
}

/// Async-list halt diagnostics — convenience for surfacing why a
/// transfer stopped, given a freshly-read Status byte.
pub fn qtd_halt_reason(status: u8) -> Option<&'static str> {
    if status & qtd_status::ACTIVE != 0 {
        return None;
    }
    if status & qtd_status::HALTED == 0 {
        return None;
    }
    if status & qtd_status::DATA_BUFFER_ERROR != 0 {
        return Some("data buffer error");
    }
    if status & qtd_status::BABBLE != 0 {
        return Some("babble detected");
    }
    if status & qtd_status::TRANSACTION_ERROR != 0 {
        return Some("transaction error");
    }
    if status & qtd_status::MISSED_MICROFRAME != 0 {
        return Some("missed microframe");
    }
    Some("halted")
}

// ── Queue Head (§3.6) ────────────────────────────────────────────

/// Endpoint speed (§3.6.2 dword 1, bits [13:12]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Speed {
    /// 1.5 Mbit/s (USB 1.1).
    Low = 1,
    /// 12 Mbit/s (USB 1.1).
    Full = 0,
    /// 480 Mbit/s (USB 2.0). EHCI's native speed.
    High = 2,
}

/// Decoded Queue Head — 48 bytes on the wire. We model the static
/// portion (5 DWords) plus the overlay area is handled by the HC at
/// runtime. [`Qh::pack_static`] covers the part the host programs
/// before adding a new QH to a schedule.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QhEndpointInfo {
    pub device_addr: u8, // bits [6:0]
    /// Inactivate-on-Next-Transaction (bit 7) — periodic schedule
    /// only.
    pub inactivate: bool,
    pub endpoint: u8,        // bits [11:8]
    pub speed: Speed,        // bits [13:12]
    pub data_toggle_ctrl: bool, // bit 14: 0=ignore in setup, 1=use DT from QTD
    pub head_of_list: bool,  // bit 15: H=1 marks the reclaim head
    pub max_packet: u16,     // bits [26:16]
    /// Control endpoint flag (bit 27). For low/full-speed control
    /// endpoints the HC issues per-token PINGs.
    pub control_ep: bool,
    /// Nak Count Reload, bits [31:28].
    pub nak_count_reload: u8,
}

impl QhEndpointInfo {
    pub fn pack(self) -> u32 {
        let mut v = (self.device_addr as u32) & 0x7F;
        if self.inactivate {
            v |= 1 << 7;
        }
        v |= ((self.endpoint as u32) & 0x0F) << 8;
        v |= ((self.speed as u32) & 0x3) << 12;
        if self.data_toggle_ctrl {
            v |= 1 << 14;
        }
        if self.head_of_list {
            v |= 1 << 15;
        }
        v |= ((self.max_packet as u32) & 0x7FF) << 16;
        if self.control_ep {
            v |= 1 << 27;
        }
        v |= ((self.nak_count_reload as u32) & 0xF) << 28;
        v
    }
    pub fn unpack(v: u32) -> Self {
        Self {
            device_addr: (v & 0x7F) as u8,
            inactivate: v & (1 << 7) != 0,
            endpoint: ((v >> 8) & 0xF) as u8,
            speed: match (v >> 12) & 0x3 {
                0 => Speed::Full,
                1 => Speed::Low,
                2 => Speed::High,
                _ => Speed::High,
            },
            data_toggle_ctrl: v & (1 << 14) != 0,
            head_of_list: v & (1 << 15) != 0,
            max_packet: ((v >> 16) & 0x7FF) as u16,
            control_ep: v & (1 << 27) != 0,
            nak_count_reload: ((v >> 28) & 0xF) as u8,
        }
    }
}

/// Static (host-programmed) portion of a Queue Head.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QhStatic {
    /// Horizontal Link Pointer (DWord 0).
    pub horiz_link: u32,
    pub horiz_terminate: bool,
    /// Type bits [2:1]: 0 = iTD, 1 = QH, 2 = siTD, 3 = FSTN.
    pub link_type: u8,
    pub ep_info: QhEndpointInfo,
    /// Endpoint Capabilities — DWord 2.
    pub ep_caps: u32,
    pub current_qtd: u32,
}

impl QhStatic {
    pub fn pack(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        let link = (self.horiz_link & 0xFFFF_FFE0)
            | (((self.link_type as u32) & 0x3) << 1)
            | if self.horiz_terminate { 1 } else { 0 };
        b[0..4].copy_from_slice(&link.to_le_bytes());
        b[4..8].copy_from_slice(&self.ep_info.pack().to_le_bytes());
        b[8..12].copy_from_slice(&self.ep_caps.to_le_bytes());
        b[12..16].copy_from_slice(&self.current_qtd.to_le_bytes());
        b
    }
}

// ── Extended Capabilities — Legacy Support (§5.1) ─────────────────

/// USB Legacy Support Extended Capability — when present, the HC
/// can be owned either by SMI/BIOS or by the OS; the OS must claim
/// it before issuing reset.
pub mod legacy {
    /// Capability ID for the EHCI Legacy Support extended capability.
    pub const CAP_ID: u8 = 0x01;
    /// Offset into the extended-cap register (added to EECP) of the
    /// USBLEGSUP DWord.
    pub const USBLEGSUP_OFFSET: u8 = 0x00;
    /// Offset of the USBLEGCTLSTS DWord.
    pub const USBLEGCTLSTS_OFFSET: u8 = 0x04;

    pub const HC_BIOS_OWNED: u32 = 1 << 16;
    pub const HC_OS_OWNED: u32 = 1 << 24;

    /// Build a USBLEGSUP value that asks the BIOS to release
    /// ownership: set HC_OS_OWNED, leave HC_BIOS_OWNED for the BIOS
    /// to clear.
    pub fn os_claim_value() -> u32 {
        HC_OS_OWNED
    }
}

// ── Tests-only helpers ────────────────────────────────────────────

/// Build a synthetic 16-byte capability-region blob for a given
/// (cap_length, hciversion, hcsparams, hccparams). Tests use this
/// in place of live MMIO reads.
pub fn synth_cap_block(
    cap_length: u8,
    hci_version: u16,
    hcs: HcsParams,
    hcc: HccParams,
) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = cap_length;
    b[2..4].copy_from_slice(&hci_version.to_le_bytes());
    b[4..8].copy_from_slice(&hcs.0.to_le_bytes());
    b[8..12].copy_from_slice(&hcc.0.to_le_bytes());
    b
}

/// Walk a packed EHCI Async list buffer of N consecutive QHs +
/// qTDs and return references to each qTD whose status indicates
/// completion. Demonstrates the reclamation iteration shape; doesn't
/// actually consume MMIO.
pub fn dump_completed_qtds(
    qtd_blob: &[u8],
) -> Vec<Qtd> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 32 <= qtd_blob.len() {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&qtd_blob[off..off + 32]);
        let q = Qtd::unpack(&buf);
        if q.status & qtd_status::ACTIVE == 0 {
            out.push(q);
        }
        off += 32;
    }
    out
}

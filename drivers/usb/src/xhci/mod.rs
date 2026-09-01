//! xHCI 1.2 USB 3.x host controller driver — clean-room.
//!
//! ## References (public, non-GPL only)
//!
//! - Intel "eXtensible Host Controller Interface for Universal Serial
//!   Bus (xHCI)" Revision 1.2, May 2019. Section references throughout
//!   this file (e.g. `§5.4.5`) point at that spec.
//!   <https://www.intel.com/content/www/us/en/products/docs/io/universal-serial-bus/extensible-host-controler-interface-usb-xhci.html>
//! - "Universal Serial Bus 3.2 Specification" Revision 1.1, June 2022
//!   (USB-IF). Standard device requests + descriptor layouts cited as
//!   `USB 3.2 §9.x`.
//!   <https://www.usb.org/document-library/usb-32-revision-11-june-2022>
//! - "Universal Serial Bus Specification" Revision 2.0 (USB-IF, April
//!   2000). Boot-class device + control-transfer request semantics
//!   shared with xHCI; cited as `USB 2.0 §9.x` where applicable.
//!   <https://www.usb.org/document-library/usb-20-specification>
//! - PCIe Base Specification (PCI-SIG). MSI-X Capability layout
//!   (§6.1) + INTx-emulation contract referenced from the
//!   `try_enable_msix` / `try_install_intx` fallback path.
//!   <https://pcisig.com/specifications/pciexpress/>
//!
//! No GPL/BSD source code (Linux, FreeBSD, NetBSD, U-Boot) consulted
//! at any point during the writing of this driver.
//!
//! ## Targets
//!
//! - QEMU `qemu-xhci` (`1B36:000D`) — used by the smoke harness.
//! - AMD Phoenix family-19h xHCI controllers (`1022:15B9 / 15BA /
//!   15C0 / 15C1`) — the four xHCI host controllers exposed by the
//!   user's Ryzen 7 PRO 8840HS laptop.
//! - PCI class match (`Serial Bus Controller / USB / xHCI` —
//!   `0x0C/0x03/0x30`) as a backstop for any other AMD/Intel xHCI
//!   variant we don't have an explicit VID/DID entry for.
//!
//! ## BAR0 layout (§5.1)
//!
//! ```text
//!   +0x000               Capability Registers (CAPLENGTH bytes)
//!   +CAPLENGTH           Operational Registers + Port Register Set
//!   +RTSOFF              Runtime Registers (interrupters live here)
//!   +DBOFF               Doorbell Registers
//! ```
//!
//! ## Stage-5 cut
//!
//! - Reset + run/stop bring-up (was Stage-4)
//! - Event Ring Segment + ERST + interrupter 0 wired up (`§4.9.4`)
//! - Walk PORTSC and report connected ports (`§5.4.8`)
//! - Drive a USB2 port through reset (`PORTSC.PR`) so an attached
//!   device transitions to Default state (`§4.19.5`)
//! - Issue an `Enable Slot` command on the Command Ring and wait for
//!   the Command Completion Event on the Event Ring (`§4.6.3`).
//!
//! Address Device + descriptor fetch + transfer rings are still
//! follow-ups; the bones land here so the next pass can layer on
//! `Address Device` against a known-good slot-id.

use core::sync::atomic::{compiler_fence, Ordering};

use alloc::sync::Arc;
use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

// Spec-aligned submodules. These factor out the register-field decode,
// TRB encode/decode helpers, and PCI-class matching constants so each
// layer of the xHCI specification has a discoverable home. The big
// monolithic implementation in this `mod.rs` still owns the live
// controller state machine — these are pure spec-encode shapes.
pub mod cap;
pub mod cmd_ring;
pub mod dcbaa;
pub mod enumerate;
pub mod event_ring;
pub mod op;
pub mod probe;
pub mod scratchpad;
pub mod slot;
pub mod transfer_ring;

/// QEMU `qemu-xhci`.
pub const QEMU_XHCI_VENDOR: u16 = 0x1B36;
pub const QEMU_XHCI_DEVICE: u16 = 0x000D;

/// AMD Family-19h Phoenix xHCI host controllers. Ryzen 7 PRO
/// 8840HS exposes four of these (15B9 / 15BA / 15C0 / 15C1) on
/// `lspci` — two on the SoC's USB controller block, two on the
/// chipset side. Programming model is stock xHCI 1.1.
pub const AMD_VENDOR: u16 = 0x1022;
pub const AMD_PHX_15B9: u16 = 0x15B9;
pub const AMD_PHX_15BA: u16 = 0x15BA;
pub const AMD_PHX_15C0: u16 = 0x15C0;
pub const AMD_PHX_15C1: u16 = 0x15C1;

/// PCI class triple for an xHCI controller. Class 0x0C (Serial
/// Bus), Subclass 0x03 (USB), Prog-IF 0x30 (xHCI). The bus's
/// `MatchKind::Class` only matches the high byte (0x0C), so this
/// catches every USB controller — that's a wider net than we
/// strictly want, but the probe path checks subclass + prog-if
/// before binding.
const PCI_CLASS_SERIAL_BUS: u8 = 0x0C;
const PCI_SUBCLASS_USB: u8 = 0x03;
const PCI_PROGIF_XHCI: u8 = 0x30;

// Capability-register offsets (relative to BAR0 + 0).
const CAP_CAPLENGTH: u64 = 0x00; // u8
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CAP_HCIVERSION: u64 = 0x02; // u16
const CAP_HCSPARAMS1: u64 = 0x04; // u32: bits[7:0]=MaxSlots, [18:8]=MaxIntrs, [31:24]=MaxPorts
const CAP_HCCPARAMS1: u64 = 0x10; // u32
const CAP_DBOFF: u64 = 0x14; // u32
const CAP_RTSOFF: u64 = 0x18; // u32

// Operational-register offsets (relative to BAR0 + CAPLENGTH).
const OP_USBCMD: u64 = 0x00; // u32
const OP_USBSTS: u64 = 0x04; // u32
const OP_PAGESIZE: u64 = 0x08; // u32
const OP_CRCR: u64 = 0x18; // u64
const OP_DCBAAP: u64 = 0x30; // u64
const OP_CONFIG: u64 = 0x38; // u32

/// Port Register Set base (relative to operational base, §5.4.8).
/// Each port is a 16-byte block: PORTSC / PORTPMSC / PORTLI / PORTHLPMC.
const OP_PORTSC_BASE: u64 = 0x400;
const PORT_REGS_STRIDE: u64 = 0x10;

// USBCMD bits.
const USBCMD_RS: u32 = 1 << 0; // Run/Stop
const USBCMD_HCRST: u32 = 1 << 1; // Host Controller Reset
const USBCMD_INTE: u32 = 1 << 2; // Interrupter Enable

// USBSTS bits.
const USBSTS_HCH: u32 = 1 << 0; // Host Controller Halted
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const USBSTS_HSE: u32 = 1 << 2; // Host System Error (RW1C — fatal: PCIe / mem fault)
const USBSTS_EINT: u32 = 1 << 3; // Event Interrupt (w1c)
const USBSTS_HCE: u32 = 1 << 12; // Host Controller Error (internal HC fault)
const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

// PORTSC bits (§5.4.8).
const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status (RO)
const PORTSC_PED: u32 = 1 << 1; // Port Enabled / Disabled (RW1C)
const PORTSC_PR: u32 = 1 << 4; // Port Reset (RWS)
/// PORTSC.PLS — Port Link State, bits 5..8.
const PORTSC_PLS_MASK: u32 = 0xF << 5;
/// PORTSC.PP — Port Power, bit 9.
const PORTSC_PP: u32 = 1 << 9;
/// PORTSC change bits at [17..23] are RW1C — preserve the RO/RW
/// fields below them when writing back.
const PORTSC_CHG_MASK: u32 = 0x00FE_0000;
const PORTSC_CSC: u32 = 1 << 17; // Connect Status Change (RW1C)
const PORTSC_PEC: u32 = 1 << 18; // Port Enable Change (RW1C)
const PORTSC_PRC: u32 = 1 << 21; // Port Reset Change (RW1C)

// Interrupter Register Set (§5.5.2). One IR per interrupter,
// 32 bytes apart, starting at RTSOFF + 0x20 (IR0).
const IR_BASE_OFF: u64 = 0x20;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const IR_STRIDE: u64 = 0x20;
const IR_IMAN: u64 = 0x00; // u32
const IR_IMOD: u64 = 0x04; // u32
const IR_ERSTSZ: u64 = 0x08; // u32
const IR_ERSTBA_LO: u64 = 0x10; // u32
const IR_ERSTBA_HI: u64 = 0x14; // u32
const IR_ERDP_LO: u64 = 0x18; // u32
const IR_ERDP_HI: u64 = 0x1C; // u32

// IMAN bits.
const IMAN_IP: u32 = 1 << 0; // Interrupt Pending (w1c)
const IMAN_IE: u32 = 1 << 1; // Interrupt Enable

// ERDP.EHB — Event Handler Busy, bit 3, w1c (§5.5.2.3.3).
const ERDP_EHB: u64 = 1 << 3;

/// Event-Ring segment size in TRBs (§4.9.4 — implementation
/// chooses, host minimum 16). One segment is plenty for
/// bring-up; sizing up follows scaling work.
const ER_SEG_TRBS: usize = 64;
/// Command-Ring segment size in TRBs (§4.9.3).
const CMD_RING_TRBS: usize = 256;

/// TRB Type field is bits[15:10] of TRB.dword3 (§4.11.1).
const TRB_TYPE_SHIFT: u32 = 10;
const TRB_TYPE_MASK: u32 = 0x3F << TRB_TYPE_SHIFT;
/// Cycle bit — TRB.dword3 bit 0 (§4.11.1).
const TRB_CYCLE_BIT: u32 = 1 << 0;

// TRB types we care about (§6.4 — Command Descriptors / TRBs).
const TRB_TYPE_NORMAL: u32 = 1;
const TRB_TYPE_ISOCH: u32 = 5;
const TRB_TYPE_SETUP_STAGE: u32 = 2;
const TRB_TYPE_DATA_STAGE: u32 = 3;
const TRB_TYPE_STATUS_STAGE: u32 = 4;
const TRB_TYPE_LINK: u32 = 6;
const TRB_TYPE_ENABLE_SLOT_CMD: u32 = 9;
const TRB_TYPE_DISABLE_SLOT_CMD: u32 = 10;
const TRB_TYPE_ADDRESS_DEVICE_CMD: u32 = 11;
const TRB_TYPE_CONFIGURE_ENDPOINT_CMD: u32 = 12;
const TRB_TYPE_EVAL_CONTEXT_CMD: u32 = 13;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const TRB_TYPE_NO_OP_CMD: u32 = 23;
const TRB_TYPE_TRANSFER_EVENT: u32 = 32;
const TRB_TYPE_CMD_COMPLETION: u32 = 33;
const TRB_TYPE_PORT_STATUS_CHANGE: u32 = 34;

/// USB Endpoint Type values for the EP Context (§6.2.3 Table 6-9).
/// Bits[5:3] of EP Context dword1.
const EP_TYPE_ISOCH_OUT: u32 = 1;
const EP_TYPE_BULK_OUT: u32 = 2;
const EP_TYPE_INT_OUT: u32 = 3;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const EP_TYPE_CONTROL: u32 = 4;
const EP_TYPE_ISOCH_IN: u32 = 5;
const EP_TYPE_BULK_IN: u32 = 6;
const EP_TYPE_INT_IN: u32 = 7;

// Setup Stage TRT (Transfer Type) field, bits[17:16] of dword3
// (§6.4.1.2.1). TRT_OUT_DATA used for control writes, TRT_IN_DATA
// for control reads with data stage; TRT_NO_DATA when no data
// stage. Stage Direction (DIR) bit on Data Stage / Status Stage:
// 1 = IN, 0 = OUT.
const TRT_NO_DATA: u32 = 0;
#[allow(dead_code)]
const TRT_OUT_DATA: u32 = 2;
const TRT_IN_DATA: u32 = 3;
const TRB_DIR_IN: u32 = 1 << 16;
/// IDT — Immediate Data, bit 6 of dword3. Used on Setup Stage to
/// pack the 8-byte SETUP packet into dword0/dword1.
const TRB_IDT: u32 = 1 << 6;
/// IOC — Interrupt On Completion, bit 5 of dword3.
const TRB_IOC: u32 = 1 << 5;
const TRB_TC: u32 = 1 << 1; // Toggle Cycle (Link TRB only, §6.4.4.1)
/// Iso TRB control bit (§6.4.1.3, table 6-49): Start Isochronous
/// As Soon As Possible. The controller picks the next available
/// frame instead of waiting for a host-specified Frame ID. Required
/// for our use case — we don't track the device's frame counter.
const TRB_SIA: u32 = 1 << 31;
/// CH — Chain bit, bit 4 of dword3.
#[allow(dead_code)]
const TRB_CH: u32 = 1 << 4;

/// Doorbell array entry size = 4 bytes; entry 0 is the host
/// controller's command-ring doorbell, entries 1..MAX_SLOTS map
/// to per-device slot doorbells.
const DB_HC_COMMAND: u32 = 0;
/// Default Control Endpoint = DCI 1 (§4.8.1).
const DCI_CONTROL_EP: u32 = 1;
/// Transfer ring size for the default control endpoint.
const CTRL_TR_TRBS: usize = 64;

// Standard USB request constants (§9.4 USB 2.0).
pub const USB_REQ_GET_DESCRIPTOR: u8 = 6;
const USB_DESC_TYPE_DEVICE: u8 = 1;

/// Per xHCI 1.2 §4.5.2 / §6.2.2: bus topology hint passed to
/// `address_device_with` so the controller can route through one or
/// more USB hubs to reach a downstream device. Construct via
/// [`Topology::ROOT`] for a device on the root hub, or via
/// [`Topology::for_downstream`] when descending into a hub.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Topology {
    /// xHCI 1.2 §4.5.2 "Route String": packed 4-bit hop sequence
    /// from the root downwards. Tier 1 hub port goes in bits[3:0],
    /// tier 2 in bits[7:4], etc., up to 5 tiers (20 bits). 0 for a
    /// device on the root hub.
    pub route_string: u32,
    /// Slot ID of the parent high-speed hub when this is a low- or
    /// full-speed device behind it (§6.2.2 dword2[7:0]). 0 for HS+
    /// devices or devices on the root hub.
    pub parent_hub_slot_id: u8,
    /// Port number on the parent hub for an LS/FS device behind it
    /// (§6.2.2 dword2[15:8]). 0 if not applicable.
    pub parent_hub_port: u8,
    /// TT Think Time (§6.2.2 dword2[17:16]) — 0/1/2/3 = 8/16/24/32
    /// FS bit-times. Only meaningful for an LS/FS device behind a
    /// multi-TT high-speed hub.
    pub tt_think_time: u8,
}

impl Topology {
    /// Topology for a device directly on a root-hub port.
    pub const ROOT: Self = Self {
        route_string: 0,
        parent_hub_slot_id: 0,
        parent_hub_port: 0,
        tt_think_time: 0,
    };

    /// Compute the topology for a device reached via `parent_hub`
    /// at downstream port `hub_port`. `tier` is the number of hubs
    /// traversed before the parent (0 if `parent_hub` sits on the
    /// root hub). For HS+ devices, `parent_hub_slot_id` /
    /// `parent_hub_port` stay zero per §6.2.2 (the TT fields only
    /// matter when stepping LS/FS through an HS hub). Callers that
    /// know they're addressing an LS/FS device should override
    /// those fields manually.
    pub const fn for_downstream(parent_route: u32, parent_tier: u32, hub_port: u8) -> Self {
        // Append `hub_port` to the next 4-bit nibble. xHCI clamps
        // the route string at 20 bits (5 hubs); ports >15 must be
        // encoded as 15 per §4.5.2.
        let port4 = if hub_port > 15 {
            15u32
        } else {
            hub_port as u32
        };
        let shift = parent_tier * 4;
        let route = parent_route | ((port4 & 0xF) << shift);
        Self {
            route_string: route & 0x000F_FFFF,
            parent_hub_slot_id: 0,
            parent_hub_port: 0,
            tt_think_time: 0,
        }
    }
}

/// Speed values reported in PORTSC[10..13] / Slot Context (§4.19.7).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortSpeed {
    /// USB 1.1 Full Speed (12 Mbps).
    Full = 1,
    /// USB 1.1 Low Speed (1.5 Mbps).
    Low = 2,
    /// USB 2.0 High Speed (480 Mbps).
    High = 3,
    /// USB 3.x Super Speed (5 Gbps and up).
    Super = 4,
    SuperPlus = 5,
}

impl PortSpeed {
    fn from_portsc_speed(v: u32) -> Option<Self> {
        Some(match v {
            1 => PortSpeed::Full,
            2 => PortSpeed::Low,
            3 => PortSpeed::High,
            4 => PortSpeed::Super,
            5 => PortSpeed::SuperPlus,
            _ => return None,
        })
    }
    /// xHCI 1.2 Table 13: initial Max Packet Size for the
    /// Default Control Endpoint when populating the Input
    /// Endpoint 0 Context for Address Device. Full-speed
    /// devices may use 8/16/32/64; the host doesn't know
    /// which until it reads the first 8 bytes of the Device
    /// Descriptor, so the spec mandates programming 8 for FS
    /// (the smallest legal MPS, guaranteed safe). After
    /// GET_DESCRIPTOR returns the real bMaxPacketSize0, we
    /// issue Evaluate Context to refresh the EP0 context if
    /// it differs (audit F-22 + F-23).
    fn default_max_packet(self) -> u16 {
        match self {
            PortSpeed::Low => 8,
            PortSpeed::Full => 8,
            PortSpeed::High => 64,
            PortSpeed::Super | PortSpeed::SuperPlus => 512,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XhciError {
    BarMapFailed,
    NoMemory,
    /// HCRST never cleared.
    ResetTimeout,
    /// CNR never cleared after reset.
    NotReady,
    /// USBSTS.HCH never cleared after Run/Stop=1.
    StartFailed,
    /// Command Ring is full.
    CmdRingFull,
    /// Command Completion Event never arrived.
    CmdTimeout,
    /// Command completed with non-success completion code.
    CmdFailed(u8),
    /// Port number out of range.
    BadPort,
    /// PORTSC.PR (port reset) never cleared.
    PortResetTimeout,
}

#[derive(Copy, Clone, Debug)]
pub struct XhciCaps {
    pub caplength: u8,
    pub hciversion: u16,
    pub max_slots: u8,
    pub max_intrs: u16,
    pub max_ports: u8,
    pub dboff: u32,
    pub rtsoff: u32,
}

pub struct Xhci {
    pub mmio: MmioRegion,
    pub caps: XhciCaps,
    /// Offset to the operational registers.
    op_off: u64,
    /// Offset to the runtime registers (interrupters live here).
    rts_off: u64,
    /// Offset to the doorbell array.
    db_off: u64,
    /// HCCPARAMS1.CSZ — `false` means 32-byte contexts, `true` means
    /// 64-byte. Stage-5 driver implements the 32-byte variant only;
    /// 64-byte support is a follow-up. Caps the slot allocator if
    /// the controller reports CSZ=1.
    csz_64byte: bool,
    /// Per-port USB protocol major version, indexed 1..=max_ports.
    /// Populated by walking the xHCI Extended Capabilities list
    /// (cap id 2 = Supported Protocol Capability) at init. 0 means
    /// "unknown / no protocol cap matched"; typical values are 2
    /// (USB 2.0) and 3 (USB 3.x). connected_ports uses this to
    /// surface USB2 ports first — boot HID devices on
    /// laptops live behind the rate-matching hub on USB2 logical
    /// ports, but AMD xHCI lays USB3 protocol ports first in the
    /// PORTSC array, so a naive 1..=max_ports walk would try the
    /// USB3 sibling and then fail Address Device.
    port_protocols: [u8; 256],
    /// USB2 ↔ USB3 sibling-port pairing. `port_siblings[N]` returns
    /// the OTHER logical port number that corresponds to the same
    /// physical receptacle. 0 = no sibling (xHCI lacks a second
    /// Supported Protocol Capability matching this port).
    ///
    /// Computed at init by zip-pairing the per-cap (port_off,
    /// port_count) ranges of the USB2 and USB3 caps: cap2 port N
    /// pairs with cap3 port N at the same offset within their
    /// respective ranges. xHCI 1.2 §7.2.2 / §7.2.2.1.4: the
    /// Compatible Port Offset / Compatible Port Count fields name
    /// a contiguous range of PORTSC entries; equivalent-physical-
    /// port pairing across protocols is by index within the range.
    ///
    /// Used by connected_ports() to suppress spurious USB3 CCS
    /// reports when a USB2 device is plugged in: AMD Renoir's xHCI
    /// flags the USB3 logical port "connected" with PLS=Polling
    /// because the SuperSpeed PHY sees voltage on D+/D-, but link
    /// training never completes (device is USB2-only). The actual
    /// device-bearing port is the USB2 sibling; reporting both
    /// causes the supervisor to chase a port that will never
    /// Address-Device.
    port_siblings: [u8; 256],
    /// DCBAA backing — kept alive for the controller's lifetime.
    dcbaa: DmaBuffer,
    cmd_ring: DmaBuffer,
    /// Event Ring segment (one segment of `ER_SEG_TRBS` entries).
    event_ring: DmaBuffer,
    /// Event Ring Segment Table — one entry pointing at `event_ring`.
    _erst: DmaBuffer,
    _scratch: Option<DmaBuffer>,
    /// Per-scratchpad-slot data pages. Audit F-01: pre-fix these
    /// were dropped immediately after their phys was written into
    /// the scratchpad buffer array, leaving the controller holding
    /// dangling pointers and corrupting the FIRST device
    /// transaction (manifested as Address Device → CmdFailed(4)
    /// USB Transaction Error on real Renoir hardware). Now kept
    /// alive for the controller's lifetime.
    _scratch_pages: alloc::vec::Vec<DmaBuffer>,
    /// Producer-cycle state for the command ring (toggles on wrap).
    cmd_pcs: IrqSafeSpinLock<u32>,
    /// Next free TRB index in the command ring.
    cmd_enqueue: IrqSafeSpinLock<usize>,
    /// Consumer-cycle state for the event ring (toggles on wrap).
    er_ccs: IrqSafeSpinLock<u32>,
    /// Next TRB index to dequeue on the event ring.
    er_dequeue: IrqSafeSpinLock<usize>,
    /// Per-slot device state. Indexed by slot id (1-based); slot 0
    /// is unused. Sized lazily on first `address_device` so we
    /// don't burn `MaxSlots+1` empty slots up-front.
    devices: IrqSafeSpinLock<alloc::vec::Vec<Option<Device>>>,
    /// Demuxed event queues populated by `xhci_isr` (and by
    /// callers when they happen to dequeue a TE not destined for
    /// them). Resolves audit findings #2 + #11: the ISR no longer
    /// drops events on the floor + `await_event` reads from
    /// the per-class queue instead of racing the ISR for the next
    /// event off the ring. Bounded depths — events overflow into
    /// `events_overflowed` which is a diagnostic counter.
    cmd_events: IrqSafeSpinLock<alloc::collections::VecDeque<[u32; 4]>>,
    transfer_events: IrqSafeSpinLock<alloc::collections::VecDeque<[u32; 4]>>,
    events_overflowed: core::sync::atomic::AtomicU32,
    pub running: bool,
    /// MSI-X table handle owned by this controller. `Some` when
    /// `bring_up` successfully programmed interrupter 0's vector;
    /// the supervisor pump can then `wait_for_irq(irq_vector).await`
    /// on event-ring updates instead of busy-polling. `None` falls
    /// back to the polling pump cadence.
    ///
    /// Held purely for ownership — never read after construction.
    /// Drop releases the MSI-X cap (clears the global enable bit
    /// and restores the device's INTx routing). `#[allow(dead_code)]`
    /// because the field is load-bearing for Drop semantics; the
    /// compiler can't see that.
    #[allow(dead_code)]
    msix: Option<MsixTable>,
    /// IDT vector allocated for this controller's interrupter 0,
    /// or `None` if MSI-X wasn't enabled.
    pub irq_vector: Option<u8>,
}

/// Per-slot device state held by the controller after a successful
/// Address Device. Holds the DMA pages backing the device context
/// + control transfer ring so they live as long as the slot does.
#[derive(Debug)]
pub struct Device {
    pub slot_id: u8,
    pub port: u8,
    pub speed: PortSpeed,
    pub max_packet_ep0: u16,
    /// Device Context — 32-byte slot ctx + 31 × 32-byte EP ctx.
    /// Lives at DCBAA[slot_id]; engine-owned post-Address Device.
    _device_ctx: DmaBuffer,
    /// Control endpoint (DCI 1) transfer ring.
    ctrl_tr: DmaBuffer,
    /// Producer-cycle state for the control TR.
    ctrl_pcs: u32,
    /// Next-free TRB index on the control TR.
    ctrl_enq: usize,
    /// Persistent 4 KiB DMA scratch for control-IN data stages
    /// (audit F-45). Avoids alloc_coherent / drop churn on every
    /// GET_DESCRIPTOR / SET_CONFIGURATION call. 4 KiB is enough
    /// for any standard descriptor we fetch (max wTotalLength is
    /// 4096 here).
    ctrl_data: DmaBuffer,
    /// Per-endpoint state for non-control endpoints (DCI 2..31).
    /// Indexed by `dci - 2`. Bound when `configure_endpoints` runs.
    eps: alloc::vec::Vec<Option<EndpointState>>,
}

/// One bulk / interrupt / isoch endpoint's runtime state. Lives
/// for as long as the slot is configured.
#[derive(Debug)]
pub struct EndpointState {
    pub dci: u8,
    pub max_packet: u16,
    pub kind: EndpointKind,
    /// Transfer ring backing the endpoint. Slots 0..CTRL_TR_TRBS-1
    /// are usable Normal/Setup/Data/Status TRBs; the last slot
    /// (CTRL_TR_TRBS-1) is reserved for a Link TRB pointing back
    /// to slot 0 with TC=1 (toggle cycle). Without the Link TRB
    /// the producer's `enq` would saturate at CTRL_TR_TRBS-1 and
    /// every subsequent enqueue would return CmdRingFull —
    /// silently killing the keyboard pump after ~64 reports.
    tr: DmaBuffer,
    /// Persistent DMA scratch for bulk_in/bulk_out reuse. One 4
    /// KiB page per endpoint, allocated at configure time and
    /// kept alive for the endpoint's lifetime. Pre-fix, every
    /// bulk_in / bulk_out call did `alloc_coherent(4096)` and
    /// then dropped it at end-of-function — risky under AMD-Vi
    /// (a freed page can be reused by the next allocation while
    /// a delayed device write is still in flight) and slow
    /// under any allocator pressure.
    dma_buf: DmaBuffer,
    /// Producer-cycle state.
    pcs: u32,
    /// Next-free TRB index.
    enq: usize,
}

/// Direction + transfer type for a non-control endpoint. Maps to
/// EP Context Endpoint Type (§6.2.3 Table 6-9).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EndpointKind {
    BulkIn,
    BulkOut,
    InterruptIn,
    InterruptOut,
    IsochIn,
    IsochOut,
}

impl EndpointKind {
    fn ep_type(self) -> u32 {
        match self {
            EndpointKind::IsochOut => EP_TYPE_ISOCH_OUT,
            EndpointKind::BulkOut => EP_TYPE_BULK_OUT,
            EndpointKind::InterruptOut => EP_TYPE_INT_OUT,
            EndpointKind::IsochIn => EP_TYPE_ISOCH_IN,
            EndpointKind::BulkIn => EP_TYPE_BULK_IN,
            EndpointKind::InterruptIn => EP_TYPE_INT_IN,
        }
    }
    fn is_in(self) -> bool {
        matches!(
            self,
            EndpointKind::BulkIn | EndpointKind::InterruptIn | EndpointKind::IsochIn
        )
    }
}

/// Caller-supplied endpoint description for `configure_endpoints`.
/// `ep_addr` matches the `bEndpointAddress` byte from the USB
/// endpoint descriptor (low 4 bits = endpoint number, bit 7 = IN
/// direction). `max_packet` matches `wMaxPacketSize`.
#[derive(Copy, Clone, Debug)]
pub struct EndpointConfig {
    pub ep_addr: u8,
    pub max_packet: u16,
    pub kind: EndpointKind,
}

impl EndpointConfig {
    /// DCI = (endpoint number * 2) + (1 if IN else 0). §4.8.1.
    fn dci(self) -> u8 {
        let num = self.ep_addr & 0x0F;
        let in_bit = if self.kind.is_in() { 1 } else { 0 };
        (num * 2) + in_bit
    }
}

impl core::fmt::Debug for Xhci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Xhci")
            .field("caps", &self.caps)
            .field("running", &self.running)
            .finish_non_exhaustive()
    }
}

impl Xhci {
    /// Read USBSTS. Public for tests / supervisors that want to check
    /// controller health without unsafe MMIO.
    pub fn usbsts(&self) -> u32 {
        // SAFETY: identity-mapped MMIO; OP_USBSTS in-range.
        unsafe { self.mmio.read32(self.op_off + OP_USBSTS) }
    }

    /// In-place recovery from `USBSTS.HCE` (xHCI 1.2 §5.4.2): the
    /// controller signalled an internal protocol error. HCE is RO —
    /// only HCRST clears it (§5.4.1.1). Re-runs the bring-up
    /// register dance (halt → HCRST → CNR clear → re-program
    /// CONFIG/DCBAAP/CRCR/IR0 → RS|INTE) against the *same* DMA
    /// pages we already allocated. Resets the command/event ring
    /// producer/consumer cursors and clears the command-ring TRBs
    /// so the next `submit_command` sees a fresh ring matching
    /// `cmd_pcs = 1`. Defensive: every known cause of HCE in this
    /// Halt the controller for system suspend — clear USBCMD.R/S
    /// and wait for USBSTS.HCH. Endpoint state is preserved in DRAM;
    /// `run_for_resume` re-asserts R/S so the controller picks
    /// up where it left off.
    ///
    /// Returns true if the controller halted cleanly within the
    /// poll budget. Real D3 handling additionally saves the
    /// Operational + Doorbell register windows; this minimal
    /// shape works for systems that stay in S2 / S0i3 (RAM
    /// retains MMIO writes).
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively + no Transfer Rings are being
    /// modified concurrently.
    pub unsafe fn halt_for_suspend(&self) -> bool {
        let mmio = &self.mmio;
        let op_off = self.op_off;
        // SAFETY: caller-asserted ownership.
        let cmd = unsafe { mmio.read32(op_off + OP_USBCMD) };
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_USBCMD, cmd & !USBCMD_RS);
        }
        narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(op_off + OP_USBSTS) } & USBSTS_HCH != 0,
            narf_time::Deadline::after_ms(100),
        )
    }

    /// Resume the controller after system wake — set USBCMD.R/S
    /// so the controller resumes fetching from Transfer Rings.
    /// The supervisor's per-port retry loop re-attaches devices
    /// the platform's wake firmware may have re-enumerated.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively.
    pub unsafe fn run_for_resume(&self) -> bool {
        let mmio = &self.mmio;
        let op_off = self.op_off;
        // SAFETY: caller-asserted ownership.
        let cmd = unsafe { mmio.read32(op_off + OP_USBCMD) };
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_USBCMD, cmd | USBCMD_RS);
        }
        narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(op_off + OP_USBSTS) } & USBSTS_HCH == 0,
            narf_time::Deadline::after_ms(100),
        )
    }

    /// driver was fixed (CRCR/ERSTBA write order, IMAN re-write
    /// after MSI-X enable), but a transient hardware fault on real
    /// silicon could still trip HCE — recover instead of giving up.
    fn soft_recover(&self) -> Result<(), XhciError> {
        let mmio = &self.mmio;
        let op_off = self.op_off;

        // Halt — clear RS, wait HCH=1.
        // SAFETY: identity-mapped MMIO.
        let cmd = unsafe { mmio.read32(op_off + OP_USBCMD) };
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_USBCMD, cmd & !USBCMD_RS);
        }
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(op_off + OP_USBSTS) } & USBSTS_HCH != 0,
            narf_time::Deadline::after_ms(100),
        );

        // HCRST — only way to clear HCE (xHCI §5.4.1.1).
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_USBCMD, USBCMD_HCRST);
        }
        let reset_ok = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(op_off + OP_USBCMD) } & USBCMD_HCRST == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !reset_ok {
            return Err(XhciError::ResetTimeout);
        }
        let cnr_clear = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(op_off + OP_USBSTS) } & USBSTS_CNR == 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !cnr_clear {
            return Err(XhciError::NotReady);
        }

        // Re-program CONFIG.
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_CONFIG, self.caps.max_slots as u32);
        }

        // Re-program DCBAAP + CRCR. LOW-then-HIGH order — see the
        // comment in `bring_up`: the implementation commits the
        // full 64-bit address on the HIGH write, reading LOW at
        // that moment.
        let dcbaa_phys = self.dcbaa.phys_addr().raw();
        let cmd_phys = self.cmd_ring.phys_addr().raw();
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_DCBAAP, dcbaa_phys as u32);
            mmio.write32(op_off + OP_DCBAAP + 4, (dcbaa_phys >> 32) as u32);
            mmio.write32(op_off + OP_CRCR, (cmd_phys as u32) | 1);
            mmio.write32(op_off + OP_CRCR + 4, (cmd_phys >> 32) as u32);
        }

        // Re-program IR0.
        let er_phys = self.event_ring.phys_addr().raw();
        let erst_phys = self._erst.phys_addr().raw();
        let ir0 = self.rts_off + IR_BASE_OFF;
        // SAFETY: same. LOW-then-HIGH order on ERDP/ERSTBA — see
        // the matching comment in `bring_up`.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            mmio.write32(ir0 + IR_ERSTSZ, 1);
            mmio.write32(ir0 + IR_ERDP_LO, er_phys as u32);
            mmio.write32(ir0 + IR_ERDP_HI, (er_phys >> 32) as u32);
            mmio.write32(ir0 + IR_ERSTBA_LO, erst_phys as u32);
            mmio.write32(ir0 + IR_ERSTBA_HI, (erst_phys >> 32) as u32);
            mmio.write32(ir0 + IR_IMOD, 0);
            mmio.write32(ir0 + IR_IMAN, IMAN_IP | IMAN_IE);
        }

        // Reset producer/consumer cursors. Post-HCRST the controller's
        // internal dequeue + cycle state for both rings is reset to the
        // values we just programmed (CRCR.RCS=1, ERDP=ring_base with
        // CCS=1), so we mirror that here.
        *self.cmd_pcs.lock() = 1;
        *self.cmd_enqueue.lock() = 0;
        *self.er_ccs.lock() = 1;
        *self.er_dequeue.lock() = 0;

        // Zero the command-ring data TRBs (preserve the Link TRB at
        // slot N-1). All-zero data TRBs have cycle=0; with PCS=1 the
        // controller stops at the first unwritten slot until we
        // submit a real command with the correct cycle.
        let n_data = CMD_RING_TRBS - 1;
        for i in 0..n_data {
            let trb_addr = cmd_phys + (i * 16) as u64;
            // SAFETY: identity-mapped DMA, in-page.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(trb_addr).kernel_mut_ptr::<u32>(),
                    0,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(trb_addr + 4).kernel_mut_ptr::<u32>(),
                    0,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(trb_addr + 8).kernel_mut_ptr::<u32>(),
                    0,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(trb_addr + 12).kernel_mut_ptr::<u32>(),
                    0,
                );
            }
        }
        // Re-plant the Link TRB (cycle=0; submit_command toggles
        // its cycle on first wrap to match PCS).
        let cmd_link_off = ((CMD_RING_TRBS - 1) * 16) as u64;
        let cmd_link_addr = cmd_phys + cmd_link_off;
        let cmd_link_d3 = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC;
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(cmd_link_addr).kernel_mut_ptr::<u32>(),
                cmd_phys as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(cmd_link_addr + 4).kernel_mut_ptr::<u32>(),
                (cmd_phys >> 32) as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(cmd_link_addr + 8).kernel_mut_ptr::<u32>(),
                0,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(cmd_link_addr + 12).kernel_mut_ptr::<u32>(),
                cmd_link_d3,
            );
        }

        // Drain any queued events — they're stale (controller-reset
        // wiped its internal state).
        self.cmd_events.lock().clear();
        self.transfer_events.lock().clear();

        // Restart.
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_USBCMD, USBCMD_RS | USBCMD_INTE);
        }
        let running = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(op_off + OP_USBSTS) } & USBSTS_HCH == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !running {
            return Err(XhciError::StartFailed);
        }
        if self.usbsts() & USBSTS_HCE != 0 {
            // Recovery didn't stick — the trigger condition is still
            // present. Surface as StartFailed so the caller can decide.
            return Err(XhciError::StartFailed);
        }
        Ok(())
    }

    /// Bring up the controller far enough that USBCMD.RS = 1.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, XhciError> {
        // SAFETY: caller-authority.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| XhciError::BarMapFailed)?;

        // Read caps.
        // SAFETY: identity-mapped MMIO.
        let caplength = unsafe { mmio.read32(CAP_CAPLENGTH) } as u8;
        // SAFETY: same.
        let hci = unsafe { mmio.read32(0) };
        let hciversion = (hci >> 16) as u16;
        // SAFETY: same.
        let p1 = unsafe { mmio.read32(CAP_HCSPARAMS1) };
        let max_slots = (p1 & 0xFF) as u8;
        let max_intrs = ((p1 >> 8) & 0x7FF) as u16;
        let max_ports = ((p1 >> 24) & 0xFF) as u8;
        // SAFETY: same.
        let dboff = unsafe { mmio.read32(CAP_DBOFF) } & !0x3;
        // SAFETY: same.
        let rtsoff = unsafe { mmio.read32(CAP_RTSOFF) } & !0x1F;
        // HCCPARAMS1 (§5.3.6). Bit 2 = CSZ (Context Size): 0 = 32-byte
        // contexts, 1 = 64-byte contexts. Stage-5 driver implements
        // 32-byte only — 64-byte controllers (rare on PC silicon)
        // bring_up succeeds but Address Device returns a fixed
        // CmdFailed code so the test surface flags it.
        // SAFETY: same.
        let hcc1 = unsafe { mmio.read32(CAP_HCCPARAMS1) };
        let csz_64byte = (hcc1 & (1 << 2)) != 0;
        // HCCPARAMS1.AC64 (bit 0): 1 = 64-bit DMA addresses supported,
        // 0 = controller can only consume <4 GiB phys addrs. The
        // driver hands the controller `alloc_coherent` buffers
        // straight from `DomainId::DRIVER_0`, which does NOT cap to
        // 32-bit on a 64-bit kernel; if AC64=0 the controller would
        // truncate the high 32 bits of any DCBAA/Command-Ring/ERST
        // pointer and corrupt arbitrary DRAM. Renoir + Phoenix are
        // AC64=1 (verified on the bring-up laptops); refuse bring-up
        // on AC64=0 hardware so the failure is loud rather than
        // silent corruption. xHCI 1.2 §5.3.6 + Linux
        // `drivers/usb/host/xhci.c:xhci_gen_setup` rejects AC64=0
        // when DMA mask can't be 32-bit-only.
        use core::fmt::Write as _;
        let ac64 = (hcc1 & 0x1) != 0;
        let _ = writeln!(
            narf_console::Writer,
            "  xhci: HCCPARAMS1={:#010x} AC64={} CSZ={}",
            hcc1,
            ac64 as u32,
            csz_64byte as u32,
        );
        if !ac64 {
            // Hard fail. The alternative (filtering alloc_coherent to
            // <4 GiB) needs a DMA-pool plumbing pass that doesn't
            // exist yet; keeping the failure mode predictable here.
            let _ = writeln!(
                narf_console::Writer,
                "  xhci: AC64=0 — controller can't address 64-bit DMA, refusing bring-up",
            );
            return Err(XhciError::NotReady);
        }

        // ── Extended Capabilities walk ─────────────────────────────
        // HCCPARAMS1[31:16] holds xECP, the offset to the first
        // Extended Capability in DWORD units from the *MMIO base*
        // (xHCI §7). Each cap header: byte0 = id, byte1 = next
        // (DWORDs from this cap, 0 terminates the list). We scan
        // for cap id 2 (Supported Protocol) which describes a
        // contiguous range of port numbers + their USB version.
        let mut port_protocols = [0u8; 256];
        let mut port_siblings = [0u8; 256];
        // Up to four Supported Protocol caps in practice (USB2 +
        // USB3 each per host-controller half on some xHCIs). Track
        // (major, port_off, port_count) so we can zip-pair them
        // after the scan.
        let mut proto_caps: [(u8, usize, usize); 4] = [(0, 0, 0); 4];
        let mut proto_caps_n: usize = 0;
        let xecp_dwords = (hcc1 >> 16) & 0xFFFF;
        if xecp_dwords != 0 {
            let mut cap_off = (xecp_dwords as u64) * 4;
            // Hard cap iterations; spec says lists terminate but
            // a malformed table shouldn't hang us forever.
            for _ in 0..32 {
                // SAFETY: identity-mapped MMIO region.
                let hdr = unsafe { mmio.read32(cap_off) };
                let cap_id = (hdr & 0xFF) as u8;
                let next_dwords = ((hdr >> 8) & 0xFF) as u64;
                match cap_id {
                    1 => {
                        // Audit F-08: USB Legacy Support
                        // Capability (xHCI 1.2 §7.1). BIOS owns
                        // the controller via SMM until we set
                        // HC OS Owned (bit 24) and wait for
                        // HC BIOS Owned (bit 16) to clear. SMI
                        // arbitration during halt/reset can
                        // corrupt MMIO writes — a known cause
                        // of CmdFailed(4) on real laptops where
                        // BIOS pre-arms USB legacy emulation.
                        // SAFETY: same.
                        let cur = unsafe { mmio.read32(cap_off) };
                        // Set OS Owned (bit 24) without
                        // disturbing other bits.
                        // SAFETY: same.
                        unsafe {
                            mmio.write32(cap_off, cur | (1 << 24));
                        }
                        // Wait up to 5s for BIOS to release.
                        // responsive_spin_until keeps cursor/FB/serial
                        // alive while the BIOS hand-off SMI runs;
                        // wall-clock budget is now explicit instead
                        // of a CPU-clock-dependent iter count.
                        let released = narf_scheduler::responsive_spin_until(
                            // SAFETY: same.
                            || unsafe { mmio.read32(cap_off) } & (1 << 16) == 0,
                            narf_time::Deadline::after_ms(5_000),
                        );
                        // If BIOS never released, force-clear by
                        // writing 0 to the BIOS-Owned bit (we
                        // own it now regardless). Spec: stale
                        // BIOS may not clear it.
                        if !released {
                            // SAFETY: same.
                            let cur = unsafe { mmio.read32(cap_off) };
                            // SAFETY: same.
                            unsafe {
                                mmio.write32(cap_off, cur & !(1u32 << 16));
                            }
                        }
                        // Mask all SMI sources in USBLEGCTLSTS
                        // (cap_off + 4): bits 0-12 are SMI
                        // enables; bits 16-31 are SMI status
                        // (RW1C). Clear status, disable SMIs.
                        // SAFETY: same.
                        let ctlsts = unsafe { mmio.read32(cap_off + 4) };
                        // Preserve reserved bits; clear enables
                        // (low half) + W1C status (high half).
                        // SAFETY: same.
                        unsafe {
                            mmio.write32(cap_off + 4, ctlsts & 0xFFFF_0000);
                        }
                    }
                    2 => {
                        // Supported Protocol Capability layout:
                        //   +0x00  cap_hdr (id=2, next, MinorRev, MajorRev)
                        //   +0x04  Name string ("USB ", LE)
                        //   +0x08  Compatible Port Offset (byte0) +
                        //          Compatible Port Count (byte1) +
                        //          Protocol Defined (bytes 2..4)
                        //   +0x0C  Protocol Slot Type
                        let major = ((hdr >> 24) & 0xFF) as u8;
                        // SAFETY: same.
                        let pinfo = unsafe { mmio.read32(cap_off + 0x08) };
                        let port_off = (pinfo & 0xFF) as usize;
                        let port_count = ((pinfo >> 8) & 0xFF) as usize;
                        for i in 0..port_count {
                            let p = port_off + i;
                            if p > 0 && p < 256 {
                                port_protocols[p] = major;
                            }
                        }
                        if proto_caps_n < proto_caps.len() {
                            proto_caps[proto_caps_n] = (major, port_off, port_count);
                            proto_caps_n += 1;
                        }
                    }
                    _ => {}
                }
                if next_dwords == 0 {
                    break;
                }
                cap_off += next_dwords * 4;
            }
        }

        // Zip-pair USB2 ↔ USB3 Supported Protocol caps. Two caps with
        // matching port_count (one major=2, one major=3) describe the
        // same physical ports at different logical PORTSC indices.
        // Pair them by intra-range index — xHCI 1.2 §7.2.2 names no
        // explicit pairing field, but in practice every implementation
        // (Intel, AMD, ASMedia, VIA) lays the USB2 and USB3 sub-ranges
        // such that range-relative index identifies the same physical
        // receptacle. If port_counts differ we pair the overlap and
        // leave the unmatched tail with no sibling.
        let mut idx_usb2: Option<usize> = None;
        let mut idx_usb3: Option<usize> = None;
        for (i, (major, _, _)) in proto_caps[..proto_caps_n].iter().enumerate() {
            match major {
                2 if idx_usb2.is_none() => idx_usb2 = Some(i),
                3 if idx_usb3.is_none() => idx_usb3 = Some(i),
                _ => {}
            }
        }
        if let (Some(i2), Some(i3)) = (idx_usb2, idx_usb3) {
            let (_, off2, n2) = proto_caps[i2];
            let (_, off3, n3) = proto_caps[i3];
            let n = n2.min(n3);
            for i in 0..n {
                let p2 = off2 + i;
                let p3 = off3 + i;
                if p2 > 0 && p2 < 256 && p3 > 0 && p3 < 256 {
                    port_siblings[p2] = p3 as u8;
                    port_siblings[p3] = p2 as u8;
                }
            }
        }

        let caps = XhciCaps {
            caplength,
            hciversion,
            max_slots,
            max_intrs,
            max_ports,
            dboff,
            rtsoff,
        };
        let op_off = caplength as u64;

        // Halt the controller (R/S = 0) before reset.
        // SAFETY: identity-mapped MMIO.
        let cmd = unsafe { mmio.read32(op_off + OP_USBCMD) };
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_USBCMD, cmd & !USBCMD_RS);
        }
        // Wait for HCH = 1. responsive_spin_until keeps cursor/FB
        // alive while the controller halts. xHCI 1.2 §5.4.1.1 says
        // the controller must halt within 16 ms of clearing R/S; use
        // a 100 ms budget so a slow controller still has headroom.
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(op_off + OP_USBSTS) } & USBSTS_HCH != 0,
            narf_time::Deadline::after_ms(100),
        );

        // Reset.
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_USBCMD, USBCMD_HCRST);
        }
        // responsive_spin_until ticks sleep_pumps across HCRST
        // self-clear. xHCI §4.2: HCRST should self-clear within
        // 100 ms on a healthy controller.
        let reset_ok = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(op_off + OP_USBCMD) } & USBCMD_HCRST == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !reset_ok {
            return Err(XhciError::ResetTimeout);
        }
        // Wait for CNR = 0. xHCI §4.2: post-reset the controller may
        // hold CNR for up to ~1 s while it loads device-context
        // structures and runs internal POST.
        let cnr_clear = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(op_off + OP_USBSTS) } & USBSTS_CNR == 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !cnr_clear {
            return Err(XhciError::NotReady);
        }

        // Set CONFIG.MAX_SLOTS_EN to the controller-supported max.
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_CONFIG, max_slots as u32);
        }

        // Allocate the Device Context Base Address Array. Spec
        // requires a 64-byte-aligned (max_slots+1) * 8-byte array.
        // One 4 KiB page covers up to 511 slots — plenty.
        let dcbaa = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let dcbaa_phys = dcbaa.phys_addr().raw();

        // Allocate the Command Ring. 4 KiB = 256 TRBs (each 16 bytes).
        // Place a Link TRB at slot N-1 with TC=1 pointing back at the
        // start so submit_command can wrap (audit F-39). Initialise
        // the link's cycle bit to 0 — submit_command flips it (and
        // toggles the producer cycle state) the first time it wraps,
        // matching the controller's PCS=1 dequeue state.
        let cmd_ring = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let cmd_phys = cmd_ring.phys_addr().raw();
        let cmd_link_off = ((CMD_RING_TRBS - 1) * 16) as u64;
        let cmd_link_addr = cmd_phys + cmd_link_off;
        let cmd_link_d3 = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC;
        // SAFETY: identity-mapped DMA, in-page.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(cmd_link_addr).kernel_mut_ptr::<u32>(),
                cmd_phys as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(cmd_link_addr + 4).kernel_mut_ptr::<u32>(),
                (cmd_phys >> 32) as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(cmd_link_addr + 8).kernel_mut_ptr::<u32>(),
                0,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(cmd_link_addr + 12).kernel_mut_ptr::<u32>(),
                cmd_link_d3,
            );
        }

        // Optional: allocate scratchpad buffers if MAX_SCRATCHPAD_BUFS
        // is non-zero.
        // SAFETY: same.
        let p2 = unsafe { mmio.read32(0x08) }; // HCSPARAMS2
        let max_scratch_hi = ((p2 >> 21) & 0x1F) as u32;
        let max_scratch_lo = ((p2 >> 27) & 0x1F) as u32;
        let max_scratch = (max_scratch_hi << 5) | max_scratch_lo;
        let mut scratch_pages: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::new();
        let scratch = if max_scratch > 0 {
            // One page holds 512 8-byte pointers — plenty for any
            // realistic scratchpad count (max 1023 per spec).
            let sb = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
            let sb_phys = sb.phys_addr().raw();
            // PAGESIZE register tells us the natural scratchpad
            // page size; xHCI 1.2 §5.4.3 says it's a bitmap where
            // bit n means "supports 4 KiB << n". Use the lowest
            // set bit. Almost every controller advertises bit 0
            // (4 KiB); this is correct fallback.
            // SAFETY: identity-mapped MMIO.
            let pagesize_bits = unsafe { mmio.read32(op_off + OP_PAGESIZE) };
            let page_shift = pagesize_bits.trailing_zeros();
            let page_size = 4096usize << page_shift;
            // Allocate ALL scratchpads (audit F-02 — pre-fix
            // capped at 8, under-provisioning controllers reporting
            // more) and KEEP them alive in scratch_pages
            // (audit F-01 — pre-fix dropped them, dangling
            // controller pointers).
            scratch_pages.reserve(max_scratch as usize);
            for i in 0..max_scratch as usize {
                let p = alloc_coherent(page_size, DomainId::DRIVER_0)
                    .map_err(|_| XhciError::NoMemory)?;
                // SAFETY: identity-mapped DMA.
                unsafe {
                    core::ptr::write_volatile(
                        narf_memory::PhysAddr::new(sb_phys + (i * 8) as u64)
                            .kernel_mut_ptr::<u64>(),
                        p.phys_addr().raw(),
                    );
                }
                scratch_pages.push(p);
            }
            // Plant the scratchpad-buffer-array pointer at DCBAA[0].
            // SAFETY: identity-mapped DCBAA page.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(dcbaa_phys).kernel_mut_ptr::<u64>(),
                    sb_phys,
                );
            }
            Some(sb)
        } else {
            None
        };

        // Program DCBAAP + CRCR. Order: LOW-dword first, then HIGH.
        // CRCR specifically: xHCI 1.2 §5.4.5 / §4.9.3 describe the
        // Command Ring Pointer as a 64-bit register where the HIGH
        // dword write commits the ring-fetch state. An implementation
        // that latches CRP on the HIGH write reads the LOW dword at
        // that moment; HIGH-first would therefore initialise the
        // command-ring base at `(LOW=0 | HIGH=<our value>)` because
        // LOW wasn't yet stored, leaving the controller fetching
        // garbage TRBs from physical address 0. The first doorbell
        // then trips internal HC error. LOW-then-HIGH stages LOW
        // before the latch, so HIGH commits the correct full 64-bit
        // address. DCBAAP is plain RW (no commit-on-write side
        // effect) but follows the same pattern for symmetry.
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_DCBAAP, dcbaa_phys as u32);
            mmio.write32(op_off + OP_DCBAAP + 4, (dcbaa_phys >> 32) as u32);
            // CRCR: bit 0 = Ring Cycle State (we use 1).
            mmio.write32(op_off + OP_CRCR, (cmd_phys as u32) | 1);
            mmio.write32(op_off + OP_CRCR + 4, (cmd_phys >> 32) as u32);
        }

        // ── Event ring setup (§4.9.4) ─────────────────────────────
        //
        // One segment of `ER_SEG_TRBS` entries. The Event Ring
        // Segment Table (ERST) gets one entry pointing at the
        // segment with the segment size in dword2[15:0]. ERSTSZ is
        // programmed before ERSTBA per spec §5.5.2.3.2 so the
        // controller knows how big the table is when it walks it.
        let event_ring =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let er_phys = event_ring.phys_addr().raw();
        let erst = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let erst_phys = erst.phys_addr().raw();
        // ERST entry layout (16 bytes, §6.5):
        //   +0  Ring Segment Base (64-bit, 64-byte aligned)
        //   +8  Ring Segment Size (low 16 bits = TRB count)
        //   +12 reserved
        // SAFETY: identity-mapped DMA page — fresh from
        // alloc_coherent, exclusive to this driver.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(erst_phys).kernel_mut_ptr::<u64>(),
                er_phys,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(erst_phys + 8).kernel_mut_ptr::<u32>(),
                ER_SEG_TRBS as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(erst_phys + 12).kernel_mut_ptr::<u32>(),
                0,
            );
        }

        // Program interrupter 0: ERSTSZ = 1 (one segment), ERSTBA =
        // erst_phys, ERDP = er_phys (initial dequeue == segment
        // base). IMAN: clear IP, set IE. IMOD = 0 (no moderation
        // for bring-up).
        let ir0 = rtsoff as u64 + IR_BASE_OFF;
        // SAFETY: identity-mapped MMIO.
        // Order matters: ERSTSZ first (sizes the table — xHCI 1.2
        // §5.5.2.3.2 says ERSTSZ shall be programmed before ERSTBA).
        // ERDP before ERSTBA (the dequeue must be valid by the time
        // the controller starts walking events). For the 64-bit
        // pairs we write LOW-then-HIGH because the spec describes
        // ERSTBA as latched on the HIGH write (§5.5.2.3.2): the
        // controller reads the LOW dword at that moment to compute
        // the segment-table base. HIGH-first would cause the
        // controller to read LOW=0 and disable the event ring
        // (erstba=0 ⇒ er_size=0), so transfer events never reach
        // the driver and every command times out. Same hazard as
        // CRCR earlier.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            mmio.write32(ir0 + IR_ERSTSZ, 1);
            mmio.write32(ir0 + IR_ERDP_LO, er_phys as u32);
            mmio.write32(ir0 + IR_ERDP_HI, (er_phys >> 32) as u32);
            mmio.write32(ir0 + IR_ERSTBA_LO, erst_phys as u32);
            mmio.write32(ir0 + IR_ERSTBA_HI, (erst_phys >> 32) as u32);
            mmio.write32(ir0 + IR_IMOD, 0);
            mmio.write32(ir0 + IR_IMAN, IMAN_IP | IMAN_IE);
        }

        // Run! Set INTE so the controller honors the interrupter
        // enable bits (per §5.4.1.1, USBCMD.INTE is the master
        // interrupt enable; without it, interrupters never fire).
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_USBCMD, USBCMD_RS | USBCMD_INTE);
        }
        // Wait for HCH = 0. responsive_spin_until keeps cursor/FB
        // alive across the start. xHCI 1.2 §5.4.1.1 says the
        // controller starts running within ~16 ms of setting R/S;
        // 100 ms gives slow QEMU/firmware variants headroom.
        let running = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(op_off + OP_USBSTS) } & USBSTS_HCH == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !running {
            return Err(XhciError::StartFailed);
        }
        // Power every root-hub port. HCCPARAMS1.PPC (bit 3) = 1
        // means port power is software-controlled — ports come up
        // unpowered and SW must write PORTSC.PP=1 before any device
        // will report a connection (xHCI 1.2 §4.19.4). On AMD FCH
        // xHCI (1022:1639 on Renoir / similar on Phoenix) PPC=1,
        // which is why this Renoir laptop's xHCI saw zero connected
        // devices despite the BAR mapping correctly.
        //
        // Write PP=1 unconditionally — when PPC=0 it's a no-op
        // (the bit is RO-as-set). Mask off the change-status
        // (RW1C) bits so we don't accidentally clear them.
        for port in 1..=max_ports {
            let port_off = op_off + OP_PORTSC_BASE + ((port as u64 - 1) * PORT_REGS_STRIDE);
            // SAFETY: identity-mapped MMIO; port range bounded by
            // HCSPARAMS1.MaxPorts.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let cur = unsafe { mmio.read32(port_off) };
            // Mask change bits AND PED so the PP-set write doesn't
            // double as an accidental "port enabled" write. PED
            // (bit 1) is RW1C; writing 1 disables the port — the
            // pre-fix expression left PED unmasked, so any port the
            // controller already enabled would be torn down by the
            // very write that was supposed to power it. Matches the
            // PORTSC write hygiene in `port_reset_once`.
            let to_write = ((cur & !PORTSC_CHG_MASK) & !PORTSC_PED) | PORTSC_PP;
            // SAFETY: same.
            unsafe {
                mmio.write32(port_off, to_write);
            }
        }
        // xHCI §4.19.4: after asserting PP, give the chipset time
        // to bring VBUS up + detect any attached device. AMD FCH
        // rate-matching hubs (Renoir / Phoenix) take 50-100 ms
        // before CCS asserts on a populated port; the 20 ms budget
        // we used pre-fix caught nothing on real silicon. Poll
        // PORTSC.CCS across every port up to a 150 ms wall-clock
        // bound; exit as soon as any port reports CCS=1, or hit
        // the full window when nothing is attached.
        //
        // Reference: Linux `drivers/usb/host/xhci-hub.c`'s
        // `xhci_hub_control` PORT_RESET path which debounces port
        // status reads against a similar window before reporting
        // GetPortStatus.
        let _ = narf_scheduler::responsive_spin_until(
            || {
                for port in 1..=max_ports {
                    let port_off = op_off + OP_PORTSC_BASE + ((port as u64 - 1) * PORT_REGS_STRIDE);
                    // SAFETY: identity-mapped MMIO; port range
                    // bounded by HCSPARAMS1.MaxPorts.
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    let v = unsafe { mmio.read32(port_off) };
                    if v & PORTSC_CCS != 0 {
                        return true;
                    }
                }
                false
            },
            narf_time::Deadline::after_ms(150),
        );
        // Log per-port post-PP state so dmesg shows which root-hub
        // ports actually saw VBUS + a device. Distinguishes
        // "PP never asserted" from "PP asserted but nothing
        // attached" — the latter is the Renoir+internal-touchpad
        // hypothesis (TP wired to an internal port that should
        // come up CCS=1 once powered).
        let mut connected = 0u32;
        for port in 1..=max_ports {
            let port_off = op_off + OP_PORTSC_BASE + ((port as u64 - 1) * PORT_REGS_STRIDE);
            // SAFETY: same — bounded by MaxPorts.
            let v = unsafe { mmio.read32(port_off) };
            let pp = (v & PORTSC_PP) != 0;
            let ccs = (v & PORTSC_CCS) != 0;
            let pls = (v & PORTSC_PLS_MASK) >> 5;
            if ccs {
                connected += 1;
            }
            let _ = writeln!(
                narf_console::Writer,
                "  xhci: port {} pp={} ccs={} pls={} portsc={:#010x}",
                port,
                pp as u32,
                ccs as u32,
                pls,
                v,
            );
        }
        let _ = writeln!(
            narf_console::Writer,
            "  xhci: {} of {} root-hub port(s) connected after PP=1",
            connected,
            max_ports,
        );
        // Drain any boot-time PORT_STATUS_CHANGE events the
        // controller posts on the RS-edge (one per port that came
        // up with CCS=1). Brief settle, then a cycle-bit walk over
        // the event ring; advance ERDP past the drained slots and
        // ack USBSTS.EINT + IMAN.IP so the first user-issued
        // command sees a clean interrupt state.
        //
        // Wait for EINT only — pre-fix the predicate also tripped
        // on USBSTS.HCE (Host Controller Error), so an HCE storm
        // during bring-up exited the settle window in microseconds
        // and pretended the controller was happy. HCE is RO; the
        // explicit check below treats HCE as a hard bring-up
        // failure.
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(op_off + OP_USBSTS) } & USBSTS_EINT != 0,
            narf_time::Deadline::after_ms(50),
        );
        // SAFETY: identity-mapped MMIO.
        let usbsts_after_settle = unsafe { mmio.read32(op_off + OP_USBSTS) };
        if usbsts_after_settle & USBSTS_HCE != 0 {
            let _ = writeln!(
                narf_console::Writer,
                "  xhci: HCE asserted during PP-settle (USBSTS={:#010x}); aborting bring-up",
                usbsts_after_settle,
            );
            return Err(XhciError::NotReady);
        }
        let mut drained_evs = 0usize;
        loop {
            let trb_off = (drained_evs * 16) as u64;
            let er_addr = event_ring.phys_addr().raw() + trb_off;
            // SAFETY: identity-mapped DMA.
            let d3 = unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(er_addr + 12).kernel_ptr::<u32>(),
                )
            };
            if d3 & TRB_CYCLE_BIT == 0 {
                break;
            }
            drained_evs += 1;
            if drained_evs >= ER_SEG_TRBS {
                break;
            }
        }
        // ERDP must point inside the segment. If the drain consumed
        // the whole segment, wrap to slot 0 — same path `poll_event`
        // takes when the SW dequeue cursor crosses the segment.
        let erdp_slot = if drained_evs >= ER_SEG_TRBS {
            0
        } else {
            drained_evs
        };
        let new_deq_phys = event_ring.phys_addr().raw() + (erdp_slot as u64) * 16;
        let ir0 = rtsoff as u64 + IR_BASE_OFF;
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(ir0 + IR_ERDP_HI, (new_deq_phys >> 32) as u32);
            mmio.write32(ir0 + IR_ERDP_LO, (new_deq_phys as u32) | (ERDP_EHB as u32));
            let cur = mmio.read32(ir0 + IR_IMAN);
            mmio.write32(ir0 + IR_IMAN, cur | IMAN_IP);
            mmio.write32(op_off + OP_USBSTS, USBSTS_EINT);
        }

        // Try MSI-X first, fall back to legacy INTx via PCI _PRT +
        // IOAPIC programming, fall back to polling if neither works.
        // Cap-walking failures, firmware MSI-X disable bits, and
        // platforms whose firmware never enabled MSI-X all land in
        // the INTx path. PCIe Base Spec §6.1 (MSI-X Capability) +
        // §6.1.4 (INTx Emulation) describe the fallback contract.
        //   <https://pcisig.com/specifications/pciexpress/>
        let (msix, irq_vector) = match Self::try_enable_msix(cap, device) {
            Ok((tbl, v)) => (Some(tbl), Some(v)),
            Err(_) => match Self::try_install_intx(cap, device) {
                Some(v) => (None, Some(v)),
                None => (None, None),
            },
        };
        // After MSI-X enable, re-write IMAN so an implementation that
        // registers interrupter→MSI-X-vector binding on the IMAN.IE
        // transition observes IE=1 *while* MSI-X is already enabled
        // in PCI cfg. xHCI 1.2 §5.5.2.1 specifies IE as the gate that
        // permits the interrupter to assert interrupts; the spec is
        // silent on the exact moment the host bus translates the
        // interrupter to a delivered MSI/MSI-X message, but in
        // practice the registration is wired to the IMAN.IE write
        // path. We wrote IMAN earlier (during IR0 setup) when MSI-X
        // wasn't yet enabled in PCI cfg — re-issuing the same write
        // here re-arms the registration so subsequent Transfer
        // Events deliver. INTx-fallback path doesn't need this; the
        // legacy path delivers via IOAPIC redirection set up by
        // `try_install_intx`.
        if msix.is_some() {
            // SAFETY: identity-mapped MMIO; same offset as the
            // earlier write.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe {
                let cur = mmio.read32(ir0 + IR_IMAN);
                mmio.write32(ir0 + IR_IMAN, cur | IMAN_IE);
            }
        }

        Ok(Self {
            mmio,
            caps,
            op_off,
            rts_off: rtsoff as u64,
            db_off: dboff as u64,
            csz_64byte,
            port_protocols,
            port_siblings,
            dcbaa,
            cmd_ring,
            event_ring,
            _erst: erst,
            _scratch: scratch,
            _scratch_pages: scratch_pages,
            cmd_pcs: IrqSafeSpinLock::new(1),
            cmd_enqueue: IrqSafeSpinLock::new(0),
            // After the boot-time drain, SW state has to match the
            // HW ERDP we just wrote. Pre-fix the drain advanced HW
            // ERDP past `drained_evs` slots but left `er_dequeue=0`
            // / `er_ccs=1`, so the first `poll_event` re-read slot 0
            // (still cycle=1 from the boot PSCE) and reported it as a
            // valid event — turning every drained TRB into a stale
            // duplicate. Initialise SW state from the drain count.
            // If the drain filled the segment (rare on boot, but the
            // loop's outer break is `drained_evs >= ER_SEG_TRBS`),
            // wrap dequeue to 0 and flip CCS to match `poll_event`'s
            // wrap-toggle path; otherwise CCS stays 1 because the
            // drain only stops on the first cycle=0 slot.
            er_ccs: IrqSafeSpinLock::new(if drained_evs >= ER_SEG_TRBS { 0 } else { 1 }),
            er_dequeue: IrqSafeSpinLock::new(if drained_evs >= ER_SEG_TRBS {
                0
            } else {
                drained_evs
            }),
            devices: IrqSafeSpinLock::new(alloc::vec::Vec::new()),
            // Pre-allocate to MAX_DEPTH (64) so the ISR's
            // `push_back` from `demux_one_event` never grows the
            // VecDeque — VecDeque::push_back triggers the
            // Sleepable allocator on growth, which panics from
            // IRQ context. Matches the cap enforced in
            // demux_one_event (line 1814: `if g.len() >= MAX_DEPTH
            // { pop_front; }`). Future events recycle slots
            // without ever realloc'ing.
            cmd_events: IrqSafeSpinLock::new(alloc::collections::VecDeque::with_capacity(64)),
            transfer_events: IrqSafeSpinLock::new(alloc::collections::VecDeque::with_capacity(64)),
            events_overflowed: core::sync::atomic::AtomicU32::new(0),
            running: true,
            msix,
            irq_vector,
        })
    }

    /// Walk the controller's MSI-X capability, allocate an IDT
    /// vector + table slot, program slot 0 to deliver to BSP, and
    /// flip the global MSI-X enable. Returns `(table, vector)` on
    /// success. Failure propagates to the bring-up path which
    /// falls back to INTx (try_install_intx) then to polling.
    fn try_enable_msix(
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<(MsixTable, u8), XhciError> {
        let mut msix = enable_msix(cap, device).map_err(|_| XhciError::NoMemory)?;
        let v = narf_interrupts::vector::alloc().map_err(|_| XhciError::NoMemory)?;
        let _ = msix.alloc_vector().ok_or(XhciError::NoMemory)?;
        // Deliver to APIC id 0 (BSP). On aarch64 this routes through
        // the GIC ITS doorbell with EventID=v.
        // SAFETY: caller holds the BusDeviceCap; we own the MSI-X
        // table (no other writer); we issue this write before the
        // global enable so the device can't fire stale data.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let _ = unsafe { msix.program_vector(0, 0, v) }.map_err(|_| XhciError::NoMemory)?;
        // SAFETY: cfg-space write to a known cap-list offset.
        unsafe { msix.enable() }.map_err(|_| XhciError::NoMemory)?;
        // Real ISR — drains the event ring + acknowledges
        // interrupter IP. Replaces the previous fire-count-only
        // pattern; the supervisor pump's wait_for_irq still
        // observes the fire-count bump but the level-triggered
        // IRQ now de-asserts cleanly.
        narf_interrupts::install_handler(v, xhci_isr);
        Ok((msix, v))
    }

    /// Legacy INTx fallback: read PCI INTERRUPT_PIN, look up the
    /// (bridge, slot, pin) triple in the AML `_PRT` routing
    /// table, allocate an IDT vector, install a fire-counter
    /// handler, and program the IOAPIC redirection-table entry
    /// for the resolved GSI.
    ///
    /// PCI INTx is level-triggered, active-low (PCI Local Bus
    /// Spec §2.2.6). We don't support `_PRT.source` (interrupt
    /// link devices) yet — entries with a named link source
    /// return None and the caller falls through to polling.
    /// Real Ryzen / EDK2 firmware tends to expose direct GSI
    /// _PRT entries (source = NULL), so this covers the common
    /// case.
    ///
    /// The handler is a no-op fire counter — same pattern the
    /// MSI-X path uses, where the actual event-ring drain is
    /// done by the supervisor pump task awaiting `wait_for_irq`.
    /// Returns the allocated vector, or None on any failure.
    #[cfg(target_arch = "x86_64")]
    fn try_install_intx(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Option<u8> {
        let pin = narf_bus::pci::read_intx_pin(cap, device).ok()?;
        if pin == 0 || pin > 4 {
            return None; // device doesn't drive an INTx line
        }
        let slot = match device.kind {
            narf_bus::BusKind::Pcie { addr, .. } => addr.device,
            _ => return None,
        };
        // PCI _PRT pin is 0-based (0=INTA..3=INTD); cfg-space
        // pin is 1-based. Map between them.
        let prt_pin = pin - 1;
        // Today every QEMU q35 bridge AML lives at "\\_SB.PCI0";
        // real consumer BIOSes match this convention. Multi-root
        // systems (rare) need bridge resolution from the device's
        // segment/bus, filed as a follow-up if it ever fires.
        let route = narf_aml::irq_routing::route_for("\\_SB.PCI0", slot, prt_pin)?;
        if route.entry.source.is_some() {
            // Named-link _PRT entry — needs link-device _CRS
            // evaluation to learn the current GSI. Not yet
            // supported.
            return None;
        }
        let gsi = route.entry.source_index;
        let v = narf_interrupts::vector::alloc().ok()?;
        // Real ISR — drains the event ring + acknowledges IP.
        // PCI INTx is level-triggered: without the IMAN.IP write
        // the line stays asserted and the IRQ re-fires forever.
        narf_interrupts::install_handler(v, xhci_isr);
        // Program IOAPIC: PCI INTx is level / active-low.
        // SAFETY: vector + handler set above before the route.
        let ok = unsafe {
            narf_acpi::ioapic::route_gsi_to_vector(
                gsi,
                v,
                0, // dest = BSP
                narf_acpi::ioapic::POLARITY_LOW | narf_acpi::ioapic::TRIGGER_LEVEL,
            )
        };
        if !ok {
            return None;
        }
        Some(v)
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn try_install_intx(_cap: &Cap<BusDeviceCap, Write>, _device: &BusDevice) -> Option<u8> {
        None
    }

    pub fn version(&self) -> u16 {
        self.caps.hciversion
    }
    pub fn max_slots(&self) -> u8 {
        self.caps.max_slots
    }
    pub fn max_ports(&self) -> u8 {
        self.caps.max_ports
    }
    /// `true` when the controller advertises `HCCPARAMS1.CSZ = 1`
    /// (64-byte device + input contexts). Both 32-byte and 64-byte
    /// strides are supported; this accessor is kept for tests +
    /// diagnostics.
    pub fn uses_64byte_contexts(&self) -> bool {
        self.csz_64byte
    }

    /// Stride between adjacent contexts inside an Input or Device
    /// Context page. 32 bytes when `HCCPARAMS1.CSZ=0`, 64 bytes
    /// when `HCCPARAMS1.CSZ=1`. The xHCI 1.2 spec lays out only
    /// the lower 32 bytes of fields in either case — the 64-byte
    /// form pads the upper half with reserved zeros.
    #[inline]
    fn context_stride(&self) -> u64 {
        if self.csz_64byte {
            0x40
        } else {
            0x20
        }
    }
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Read the PORTSC register for `port` (1-indexed per spec).
    /// Returns `None` for an out-of-range port number.
    /// Major USB version for `port` (2 or 3 typically), or 0 when
    /// the controller didn't expose a Supported Protocol cap that
    /// covers this port. Populated at init by walking xECP.
    pub fn port_protocol(&self, port: u8) -> u8 {
        if (port as usize) < self.port_protocols.len() {
            self.port_protocols[port as usize]
        } else {
            0
        }
    }

    pub fn portsc(&self, port: u8) -> Option<u32> {
        if port == 0 || port > self.caps.max_ports {
            return None;
        }
        let off = self.op_off + OP_PORTSC_BASE + ((port as u64 - 1) * PORT_REGS_STRIDE);
        // SAFETY: identity-mapped MMIO; port-range checked above.
        Some(unsafe { self.mmio.read32(off) })
    }

    /// `true` if the port currently has a connected device (PORTSC.CCS).
    pub fn port_connected(&self, port: u8) -> bool {
        self.portsc(port).is_some_and(|v| v & PORTSC_CCS != 0)
    }

    /// Enumerate connected ports as a tuple of `(port_id, portsc)`.
    /// USB2 ports first, then USB3, then unknown — matches the
    /// boot-HID-device case (laptop keyboards live behind the
    /// rate-matching hub on USB2 logical ports; trying their USB3
    /// protocol siblings first wastes an enumeration round and can
    /// kick the device into a re-attach loop on some firmwares).
    /// Allocates — fine outside hot paths.
    ///
    /// AMD Renoir-class quirk: when a USB2 device plugs into a
    /// physical receptacle, both the USB2 logical port AND its
    /// USB3 sibling can report CCS=1 — the SuperSpeed PHY sees
    /// voltage on D+/D- and flags "connected" even though link
    /// training never completes (device is FS/HS, not SS).
    /// The USB3 entry then sits at PLS=Polling with PED=0 forever
    /// and Address Device fails on it. Filter that case out: a
    /// USB3 port whose USB2 sibling is ALSO connected is treated
    /// as the spurious entry; the supervisor reaches the real
    /// device through the USB2 sibling instead.
    pub fn connected_ports(&self) -> alloc::vec::Vec<(u8, u32)> {
        let mut usb2 = alloc::vec::Vec::new();
        let mut usb3 = alloc::vec::Vec::new();
        let mut other = alloc::vec::Vec::new();
        // Pre-pass: which USB2 ports report CCS? Used to mute
        // sibling-CCS spurious USB3 entries below.
        let mut usb2_ccs = [false; 256];
        for p in 1..=self.caps.max_ports {
            if self.port_protocol(p) == 2 {
                if let Some(v) = self.portsc(p) {
                    if v & PORTSC_CCS != 0 {
                        usb2_ccs[p as usize] = true;
                    }
                }
            }
        }
        for p in 1..=self.caps.max_ports {
            if let Some(v) = self.portsc(p) {
                if v & PORTSC_CCS != 0 {
                    match self.port_protocol(p) {
                        2 => usb2.push((p, v)),
                        3 => {
                            let sib = self.sibling_port(p);
                            if sib != 0 && usb2_ccs[sib as usize] {
                                // Spurious USB3 connect — the real
                                // device is on the USB2 sibling.
                                continue;
                            }
                            usb3.push((p, v));
                        }
                        _ => other.push((p, v)),
                    }
                }
            }
        }
        usb2.extend(usb3);
        usb2.extend(other);
        usb2
    }

    /// Sibling logical port (paired USB2 ↔ USB3 entry from the
    /// Supported Protocol Capability) for `port`. Returns 0 when
    /// there's no sibling (single-protocol controller, or `port`
    /// outside any cap's range).
    pub fn sibling_port(&self, port: u8) -> u8 {
        let i = port as usize;
        if i < self.port_siblings.len() {
            self.port_siblings[i]
        } else {
            0
        }
    }

    /// Drive `port` through reset. Per xHCI 1.2 §4.19.5 this
    /// transitions an attached device into Default state. The
    /// PORTSC change bits at [17..23] are RW1C — preserve the
    /// RO/RW fields below them when writing back. Returns the
    /// post-reset PORTSC value.
    pub async fn port_reset(&self, port: u8) -> Result<u32, XhciError> {
        if port == 0 || port > self.caps.max_ports {
            return Err(XhciError::BadPort);
        }
        let off = self.op_off + OP_PORTSC_BASE + ((port as u64 - 1) * PORT_REGS_STRIDE);
        // SAFETY: identity-mapped MMIO; port-range checked above.
        let cur = unsafe { self.mmio.read32(off) };
        if cur & PORTSC_CCS == 0 {
            return Err(XhciError::BadPort);
        }
        // CCS-stable debounce. Bound by raw TSC wall-clock instead
        // of the timer wheel — yield_now() between samples uses the
        // executor's self-wake path (sets slot.awake directly via
        // cx.waker()) and bypasses timer_wheel::register entirely.
        // The wheel path was suspected of failing to deliver wakes
        // back to the USB supervisor on real HW; yield_now is the
        // minimum-dependency wait primitive available.
        let debounce_deadline = narf_time::Deadline::after_ms(100);
        loop {
            // SAFETY: same MMIO region.
            let v = unsafe { self.mmio.read32(off) };
            if v & PORTSC_CCS == 0 {
                return Err(XhciError::BadPort);
            }
            if debounce_deadline.expired() {
                break;
            }
            narf_scheduler::yield_now().await;
        }
        self.port_reset_once(port, off).await
    }

    /// One reset attempt. Spec-compliant single-shot per xHCI 1.2
    /// §4.19.5: assert PR, wait for PR to self-clear + PRC to set,
    /// ack PRC, verify PED is set (USB2) or PED + PLS=U0 (USB3),
    /// then wait TRSTRCY (USB 2.0 §7.1.7.3 / §9.2.6.2) before the
    /// caller drives the next bus transaction.
    async fn port_reset_once(&self, port: u8, off: u64) -> Result<u32, XhciError> {
        // SAFETY: identity-mapped MMIO; off bounded by caller.
        let cur = unsafe { self.mmio.read32(off) };
        // Assert PR + keep PP. Mask RW1C change bits to 0 so this
        // write doesn't accidentally clear them, and skip PED
        // (RW1C, leave 0).
        let to_write = (cur & !PORTSC_CHG_MASK) & !PORTSC_PED | PORTSC_PR | PORTSC_PP;
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off, to_write);
        }
        // Wait for PR to clear AND PRC to set (§4.19.5). 250 ms
        // outer bound; yield between samples via the executor's
        // self-wake path (bypasses timer wheel).
        let pr_deadline = narf_time::Deadline::after_ms(250);
        loop {
            if pr_deadline.expired() {
                break;
            }
            // SAFETY: same.
            let v = unsafe { self.mmio.read32(off) };
            if v & PORTSC_PR == 0 && v & PORTSC_PRC != 0 {
                // Ack PRC + CSC together. CSC (RW1C, bit 17) latches
                // on the connect that triggered this reset; leaving
                // it asserted livelocks a level-triggered INTx
                // routing forever because every IMAN.IP write
                // immediately re-asserts (xHCI 1.2 §5.4.8 + Linux
                // `drivers/usb/host/xhci-hub.c:xhci_clear_port_change_bit`,
                // which W1Cs every change bit it observes set). PEC
                // gets the same treatment in case the port toggled
                // PED across the reset.
                let ack = (v & !PORTSC_CHG_MASK) | PORTSC_PRC | PORTSC_CSC | PORTSC_PEC;
                // SAFETY: same.
                unsafe {
                    self.mmio.write32(off, ack);
                }
                // PED / PLS settle. 50 ms outer bound.
                let proto = self.port_protocols[port as usize];
                let ped_deadline = narf_time::Deadline::after_ms(50);
                loop {
                    if ped_deadline.expired() {
                        return Err(XhciError::PortResetTimeout);
                    }
                    // SAFETY: same.
                    let post = unsafe { self.mmio.read32(off) };
                    let ped = post & PORTSC_PED != 0;
                    let pls = (post & PORTSC_PLS_MASK) >> 5;
                    let ok = match proto {
                        3 => ped && pls == 0,
                        _ => ped,
                    };
                    if ok {
                        // TRSTRCY (USB 2.0 §7.1.7.3 / §9.2.6.2):
                        // ≥10 ms quiet between PR clear and the
                        // first SETUP. Spin-yield for ~25 ms via
                        // TSC deadline (not the wheel).
                        let recovery = narf_time::Deadline::after_ms(25);
                        while !recovery.expired() {
                            narf_scheduler::yield_now().await;
                        }
                        return Ok(post);
                    }
                    narf_scheduler::yield_now().await;
                }
            }
            narf_scheduler::yield_now().await;
        }
        Err(XhciError::PortResetTimeout)
    }

    /// Ring the host-controller's Command Ring doorbell. Stream-id /
    /// DB Target both 0 per §5.6 for command-ring kicks.
    fn ring_command_doorbell(&self) {
        // SAFETY: identity-mapped MMIO; doorbell array sized to
        // (MAX_SLOTS + 1) * 4 bytes — entry 0 always exists.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.mmio.write32(self.db_off, DB_HC_COMMAND);
        }
    }

    /// Enqueue a 4-dword TRB at the command ring's enqueue pointer
    /// with the current cycle bit, then ring the command doorbell.
    /// `dword3_no_cycle` must already include the TRB Type field
    /// (bits[15:10]) but should NOT carry the cycle bit — the
    /// helper adds it.
    fn submit_command(
        &self,
        dword0: u32,
        dword1: u32,
        dword2: u32,
        dword3_no_cycle: u32,
    ) -> Result<(), XhciError> {
        let mut enq_g = self.cmd_enqueue.lock();
        let mut pcs_g = self.cmd_pcs.lock();
        // Audit F-39: when we hit the Link TRB at slot N-1, publish
        // it with the *current* PCS so the controller follows it,
        // then wrap enq=0 and toggle PCS so the next normal TRB we
        // write also matches the post-link consumer cycle.
        if *enq_g >= CMD_RING_TRBS - 1 {
            let link_addr = self.cmd_ring.phys_addr().raw() + ((CMD_RING_TRBS - 1) * 16) as u64;
            let link_d3 = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC | (*pcs_g & TRB_CYCLE_BIT);
            // SAFETY: identity-mapped DMA, in-page; only the cycle
            // bit + TC bit need rewriting — the address dwords were
            // planted at init time and don't change.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(link_addr + 12).kernel_mut_ptr::<u32>(),
                    link_d3,
                );
            }
            compiler_fence(Ordering::SeqCst);
            *enq_g = 0;
            *pcs_g ^= TRB_CYCLE_BIT;
        }

        let trb_off = (*enq_g * 16) as u64;
        let trb_addr = self.cmd_ring.phys_addr().raw() + trb_off;
        let dword3 = dword3_no_cycle | (*pcs_g & TRB_CYCLE_BIT);
        // Write the data dwords first, then publish dword3 (which
        // carries the cycle bit) so the controller can't observe a
        // half-written TRB.
        // SAFETY: identity-mapped DMA page; trb_off in-range.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr).kernel_mut_ptr::<u32>(),
                dword0,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 4).kernel_mut_ptr::<u32>(),
                dword1,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 8).kernel_mut_ptr::<u32>(),
                dword2,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 12).kernel_mut_ptr::<u32>(),
                dword3,
            );
        }
        compiler_fence(Ordering::SeqCst);
        *enq_g += 1;
        drop(enq_g);
        drop(pcs_g);
        self.ring_command_doorbell();
        Ok(())
    }

    /// Poll the Event Ring for the next event whose cycle matches
    /// the consumer cycle state. Returns the four TRB dwords and
    /// advances the dequeue pointer + ERDP. Spec § 4.9.4.
    fn poll_event(&self) -> Option<[u32; 4]> {
        let mut deq_g = self.er_dequeue.lock();
        let mut ccs_g = self.er_ccs.lock();
        let trb_off = (*deq_g * 16) as u64;
        let trb_addr = self.event_ring.phys_addr().raw() + trb_off;
        // SAFETY: identity-mapped DMA page; deq in-range.
        let d3 = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(trb_addr + 12).kernel_ptr::<u32>())
        };
        if (d3 & TRB_CYCLE_BIT) != *ccs_g {
            return None;
        }
        // SAFETY: same.
        let d0 = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(trb_addr).kernel_ptr::<u32>())
        };
        // SAFETY: same.
        let d1 = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(trb_addr + 4).kernel_ptr::<u32>())
        };
        // SAFETY: same.
        let d2 = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(trb_addr + 8).kernel_ptr::<u32>())
        };
        *deq_g += 1;
        if *deq_g >= ER_SEG_TRBS {
            *deq_g = 0;
            *ccs_g ^= TRB_CYCLE_BIT;
        }
        // Update ERDP — write the new dequeue phys address (4-byte
        // aligned) with EHB set to clear the busy flag.
        let new_deq_phys = self.event_ring.phys_addr().raw() + (*deq_g as u64) * 16;
        let ir0 = self.rts_off + IR_BASE_OFF;
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio
                .write32(ir0 + IR_ERDP_HI, (new_deq_phys >> 32) as u32);
            self.mmio
                .write32(ir0 + IR_ERDP_LO, (new_deq_phys as u32) | (ERDP_EHB as u32));
        }
        Some([d0, d1, d2, d3])
    }

    /// Snapshot USBSTS and clear any RW1C error bits, returning a
    /// human-readable suffix when something concerning is set.
    /// Called from the cmd-completion error path so a CmdFailed
    /// surfaces *why* in the log rather than just the bare
    /// completion code. Defensive: HSE / HCE are fatal-class
    /// signals from the controller (PCIe fault, internal HC error)
    /// — surface them via the log so a future debugger can spot
    /// "controller fell over" vs "device misbehaved".
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    fn snapshot_usbsts_diagnostics(&self) -> Option<&'static str> {
        // SAFETY: identity-mapped MMIO; OP_USBSTS within bounds.
        let s = unsafe { self.mmio.read32(self.op_off + OP_USBSTS) };
        let mut clear = 0u32;
        let label = if s & USBSTS_HSE != 0 {
            clear |= USBSTS_HSE;
            Some("USBSTS.HSE (host system error)")
        } else if s & USBSTS_HCE != 0 {
            // HCE is RO; clearing requires HCRST. We can only log.
            Some("USBSTS.HCE (internal controller error)")
        } else if s & USBSTS_HCH != 0 {
            Some("USBSTS.HCH (controller halted)")
        } else if s & USBSTS_CNR != 0 {
            Some("USBSTS.CNR (controller not ready)")
        } else {
            None
        };
        if clear != 0 {
            // SAFETY: same; HSE is RW1C, write-back to clear.
            unsafe {
                self.mmio.write32(self.op_off + OP_USBSTS, clear);
            }
        }
        label
    }

    /// Demux one Event Ring entry into the per-class queues. Used
    /// by both the ISR drain and the `await_event` path so a
    /// command/transfer event the wait isn't interested in still
    /// gets stashed for whichever waiter does want it. Returns the
    /// event so direct callers can also inspect.
    fn demux_one_event(&self) -> Option<[u32; 4]> {
        let ev = self.poll_event()?;
        let ty = (ev[3] & TRB_TYPE_MASK) >> TRB_TYPE_SHIFT;
        // Route Port Status Change Events (xHCI 1.2 §6.4.2.3, TRB
        // type 34) to the USB supervisor. Pre-fix the `_ =>` arm
        // below silently dropped these so a hot-plug attach landing
        // while the supervisor was parked never produced a wake;
        // the user had to wait for the next 100 ms pump pause to
        // expire before re-scanning PORTSC. Bump the counter
        // first (so a polling consumer can detect missed events
        // by snapshot-and-compare) then poke the registered
        // supervisor waker.
        if ty == TRB_TYPE_PORT_STATUS_CHANGE {
            USB_PSCE_EVENTS.fetch_add(1, core::sync::atomic::Ordering::Release);
            wake_usb_supervisor();
            return Some(ev);
        }
        const MAX_DEPTH: usize = 64;
        let queue: &IrqSafeSpinLock<alloc::collections::VecDeque<[u32; 4]>> = match ty {
            t if t == TRB_TYPE_CMD_COMPLETION => &self.cmd_events,
            t if t == TRB_TYPE_TRANSFER_EVENT => &self.transfer_events,
            _ => return Some(ev),
        };
        let mut g = queue.lock();
        if g.len() >= MAX_DEPTH {
            // Drop oldest to keep memory bounded; bump the counter
            // so a future debugger can spot the loss.
            g.pop_front();
            self.events_overflowed
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        g.push_back(ev);
        Some(ev)
    }

    /// Drain queued events of either class into a closure until the
    /// predicate matches. Resolves audit #11: the ISR can populate
    /// the queue between submit and await without the sync waiter
    /// timing out, because the await reads the queue (not the
    /// raw event ring directly).
    async fn await_event(
        &self,
        mut predicate: impl FnMut(&[u32; 4]) -> bool,
    ) -> Result<[u32; 4], XhciError> {
        // Helper: try to pop any queued event matching predicate
        // from either class queue. Returns None if no match in
        // either queue. Drains non-matching entries back into a
        // local buffer so they survive for the next await.
        let try_match = |me: &Self, mut p: &mut dyn FnMut(&[u32; 4]) -> bool| -> Option<[u32; 4]> {
            for q in [&me.cmd_events, &me.transfer_events] {
                let mut g = q.lock();
                if let Some(pos) = g.iter().position(&mut p) {
                    return g.remove(pos);
                }
            }
            None
        };

        // First pass: maybe the event we want already arrived
        // (ISR populated it, or a prior await left it in queue).
        if let Some(ev) = try_match(self, &mut predicate) {
            return Ok(ev);
        }

        let deadline = narf_time::Deadline::after_ms(250);
        loop {
            // Drain any new ring entries the ISR may have missed.
            while self.demux_one_event().is_some() {}
            if let Some(ev) = try_match(self, &mut predicate) {
                return Ok(ev);
            }
            if deadline.expired() {
                return Err(XhciError::CmdTimeout);
            }
            // Wheel-bypass: yield_now self-wakes via cx.waker(),
            // bypassing timer_wheel::register entirely. The
            // previous `wait_for_irq_until(v, after_ms(10))` was
            // wheel-based and observed not to fire wakers for the
            // USB supervisor task on real HW even though the same
            // wheel works for the panel paint task — same workaround
            // pattern as port_reset / supervisor's outer YieldTimeout.
            // Trade-off: CPU is busier (re-polls every executor
            // round vs. parked-then-irq), but the outer 250 ms
            // deadline still bounds the busy phase. Other tasks
            // make progress via 10 ms preemption.
            narf_scheduler::yield_now().await;
            let _ = self.irq_vector; // unused while wheel is suspect
        }
    }

    /// Issue an Enable Slot command (§4.6.3) and wait for the
    /// completion event. Returns the assigned slot id (1..=MaxSlots)
    /// on success.
    pub async fn enable_slot(&self) -> Result<u8, XhciError> {
        // If the controller wedged itself (HCE), attempt a soft
        // re-init before submitting the command. HCE is RO and only
        // clears on HCRST — without recovery the doorbell write
        // below has no effect and we'd time out 250 ms later.
        if self.usbsts() & USBSTS_HCE != 0 {
            self.soft_recover()?;
        }
        // Enable Slot TRB (§6.4.3.2): all dwords 0 except TRB Type.
        let trb_type = TRB_TYPE_ENABLE_SLOT_CMD << TRB_TYPE_SHIFT;
        self.submit_command(0, 0, 0, trb_type)?;
        // Wait for a Command Completion Event (§6.4.2.2).
        let cce_type = TRB_TYPE_CMD_COMPLETION << TRB_TYPE_SHIFT;
        let ev = self
            .await_event(|t| (t[3] & TRB_TYPE_MASK) == cce_type)
            .await?;
        // CCE layout (§6.4.2.2):
        //   dword0..1 = command-TRB phys addr
        //   dword2[31:24] = completion code
        //   dword3[31:24] = slot id
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 {
            return Err(XhciError::CmdFailed(ccode));
        }
        let slot_id = ((ev[3] >> 24) & 0xFF) as u8;
        Ok(slot_id)
    }

    /// Disable Slot command (xHCI §4.6.4) — releases the slot's
    /// device context back to the controller's free pool. Called
    /// from the HID enumeration cleanup path when any post-
    /// enable_slot step (Address Device, GET_DESCRIPTOR,
    /// SET_CONFIGURATION, …) fails. Best-effort: an internal
    /// failure here is logged via the returned error but the
    /// caller should ignore it because the original failure is
    /// what matters.
    pub async fn disable_slot(&self, slot_id: u8) -> Result<(), XhciError> {
        if slot_id == 0 || slot_id > self.caps.max_slots {
            return Err(XhciError::CmdFailed(0xFD));
        }
        let trb_type = TRB_TYPE_DISABLE_SLOT_CMD << TRB_TYPE_SHIFT;
        // Slot ID rides in dword3[31:24], same encoding as the
        // Command Completion Event from enable_slot returns it.
        let d3 = trb_type | ((slot_id as u32) << 24);
        self.submit_command(0, 0, 0, d3)?;
        let cce_type = TRB_TYPE_CMD_COMPLETION << TRB_TYPE_SHIFT;
        let ev = self
            .await_event(|t| (t[3] & TRB_TYPE_MASK) == cce_type)
            .await?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 {
            return Err(XhciError::CmdFailed(ccode));
        }
        Ok(())
    }

    /// Drain the Event Ring without dispatching anything. Useful in
    /// tests that just want to count events.
    pub fn drain_events(&self) -> usize {
        let mut n = 0;
        while self.poll_event().is_some() {
            n += 1;
        }
        n
    }

    /// Decode PORTSC.Speed for `port`. Returns `None` if the field
    /// holds a reserved value (or the port is out of range).
    pub fn port_speed(&self, port: u8) -> Option<PortSpeed> {
        let v = self.portsc(port)?;
        // PORTSC bits[10:13] (§5.4.8 Table 5-27).
        let speed_field = (v >> 10) & 0xF;
        PortSpeed::from_portsc_speed(speed_field)
    }

    /// Issue the Address Device command (§4.6.5) for `slot_id`
    /// against the *root-hub* `port` (xHCI 1.2 §4.5.2: a downstream
    /// device's Root Hub Port Number is always the chipset port the
    /// path *originates* from, regardless of how many hubs it
    /// transits). Equivalent to `address_device_with(slot_id, port,
    /// speed, Topology::ROOT)` — for devices reached through one or
    /// more USB hubs use `address_device_with` directly.
    pub async fn address_device(
        &self,
        slot_id: u8,
        port: u8,
        speed: PortSpeed,
    ) -> Result<u8, XhciError> {
        self.address_device_with(slot_id, port, speed, Topology::ROOT)
            .await
    }

    /// Issue the Address Device command (§4.6.5) for `slot_id`,
    /// programming the Slot Context with the supplied `topology`.
    /// Use `Topology::ROOT` for a device on the root hub (port-only
    /// addressing); supply the full hub-walk + parent-TT info for
    /// devices behind one or more USB hubs. Allocates a Device
    /// Context + Input Context + Control Transfer Ring, programs
    /// the Slot + EP0 contexts per §4.3.3, and waits for the Command
    /// Completion Event. Returns the slot id on success and stashes
    /// the per-slot state in `self.devices`.
    ///
    /// Handles both 32-byte (CSZ=0) and 64-byte (CSZ=1) contexts —
    /// the per-context stride is `0x20` or `0x40` respectively, but
    /// the field layout *within* each context is identical (the
    /// 64-byte form just pads the upper half).
    pub async fn address_device_with(
        &self,
        slot_id: u8,
        port: u8,
        speed: PortSpeed,
        topology: Topology,
    ) -> Result<u8, XhciError> {
        if slot_id == 0 || slot_id > self.caps.max_slots {
            return Err(XhciError::CmdFailed(0xFD));
        }
        if port == 0 || port > self.caps.max_ports {
            return Err(XhciError::BadPort);
        }

        // §6.2.5 Input Context layout. Per-context stride is 32 or
        // 64 bytes depending on HCCPARAMS1.CSZ. Worst case (CSZ=1):
        // 64 (Input Control) + 64 (Slot) + 64 × 31 (EP) = 2112 bytes
        // — still fits in one 4 KiB page.
        let input = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let dev_ctx = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let ctrl_tr = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let ctrl_data =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;

        let input_phys = input.phys_addr().raw();
        let dev_ctx_phys = dev_ctx.phys_addr().raw();
        let ctrl_tr_phys = ctrl_tr.phys_addr().raw();
        // Plant a Link TRB at the last slot of the control transfer
        // ring so ctrl_enqueue can wrap (audit #1 — same fix as the
        // per-EP ring above). Cycle bit starts at 0; ctrl_pcs starts
        // at 1 and toggles each wrap.
        let ctrl_link_off = ((CTRL_TR_TRBS - 1) * 16) as u64;
        let ctrl_link_addr = ctrl_tr_phys + ctrl_link_off;
        let ctrl_link_d3 = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC;
        // SAFETY: identity-mapped DMA; offset in-page.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(ctrl_link_addr).kernel_mut_ptr::<u32>(),
                ctrl_tr_phys as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(ctrl_link_addr + 4).kernel_mut_ptr::<u32>(),
                (ctrl_tr_phys >> 32) as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(ctrl_link_addr + 8).kernel_mut_ptr::<u32>(),
                0,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(ctrl_link_addr + 12).kernel_mut_ptr::<u32>(),
                ctrl_link_d3,
            );
        }

        // Input Control Context (§6.2.5.1):
        //   dword0 = D-mask (drop), dword1 = A-mask (add).
        //   We add Slot (A0=1) + EP0 (A1=1).
        //
        // Slot Context (§6.2.2):
        //   dword0 bits[19:0] = Route String (0 — root port)
        //         bits[20:23] = Speed
        //         bit  [27]   = MTT (0 — high-speed-only multi-TT)
        //         bit  [28]   = Hub (0 — not a hub)
        //         bits[31:27] = Context Entries (1, only EP0 set)
        //   dword1 bits[15:0]  = Max Exit Latency (0)
        //         bits[23:16] = Root Hub Port Number (port)
        //         bits[31:24] = Number of Ports (0)
        //   dword2/3 = TT info / interrupter target / device address
        //              (engine fills device address after AddrDev).
        //
        // EP0 Context (§6.2.3):
        //   dword0 bits[16:18] = Interval (0)
        //   dword1 bits[1:0]   = Error Count (3 — typical default)
        //         bits[5:3]   = Endpoint Type (4 = Control)
        //         bits[15:8]  = Max Burst Size (0)
        //         bits[31:16] = Max Packet Size
        //   dword2/3 = TR Dequeue Pointer (low/high) | DCS
        //   dword4 bits[15:0]  = Average TRB Length (8 for Control)
        //         bits[31:16] = Max ESIT Payload Lo (0)

        // Zero the input context first — fresh frames are zeroed,
        // but be explicit so a future allocator change can't bite.
        // SAFETY: identity-mapped DMA; 4 KiB contiguous.
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(input_phys).kernel_mut_ptr::<u8>(),
                0,
                4096,
            );
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(dev_ctx_phys).kernel_mut_ptr::<u8>(),
                0,
                4096,
            );
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(ctrl_tr_phys).kernel_mut_ptr::<u8>(),
                0,
                4096,
            );
        }

        let cs = self.context_stride();
        let input_ctrl = input_phys; // always at offset 0
        let slot_ctx = input_phys + cs; // immediately after Input Control
        let ep0_ctx = input_phys + cs * 2; // EP0 = DCI 1, indexed from Slot
                                           // Equivalent computation is `input_phys
                                           // + cs + cs * dci` with dci=1.

        // Input Control Context — A0 (Slot) + A1 (EP0).
        // SAFETY: identity-mapped DMA; offsets in-page.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(input_ctrl + 4).kernel_mut_ptr::<u32>(),
                (1 << 0) | (1 << 1),
            );
        }

        // Slot Context dword0 + dword1 + dword2 (xHCI 1.2 §6.2.2).
        //   dword0[19:0]  Route String — 4-bit per hop down a hub
        //                 chain (§4.5.2). 0 for a root-hub device.
        //   dword0[23:20] Speed (Table 6-7: 1=FS, 2=LS, 3=HS,
        //                 4=SS, 5=SSP).
        //   dword0[25]    MTT (multi-TT) — 0 unless this device
        //                 itself is a multi-TT hub.
        //   dword0[26]    Hub — 1 if this device is a USB hub. Set
        //                 separately via Evaluate Context after the
        //                 hub descriptor is read.
        //   dword0[31:27] Context Entries — DCI of the highest
        //                 valid endpoint (1 here = EP0 only).
        //   dword1[15:0]  Max Exit Latency (0).
        //   dword1[23:16] Root Hub Port Number — the chipset port
        //                 the path originates from, even for a
        //                 device behind a multi-level hub chain.
        //   dword1[31:24] Number of Ports (0 for non-hubs).
        //   dword2[7:0]   TT Hub Slot ID — slot of the parent
        //                 high-speed hub for an LS/FS device behind
        //                 it; 0 otherwise.
        //   dword2[15:8]  TT Port Number on the parent hub.
        //   dword2[17:16] TT Think Time (0..3 = 8/16/24/32 FS bit
        //                 times) — only meaningful if the parent is
        //                 a multi-TT hub.
        let slot_d0 = (1u32 << 27)              // Context Entries = 1
                    | ((speed as u32) << 20)    // Speed
                    | (topology.route_string & 0x000F_FFFF); // Route String
        let slot_d1 = (port as u32) << 16; // Root Hub Port Number
        let slot_d2 = (topology.parent_hub_slot_id as u32)
            | ((topology.parent_hub_port as u32) << 8)
            | ((topology.tt_think_time as u32 & 0x3) << 16);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(slot_ctx).kernel_mut_ptr::<u32>(),
                slot_d0,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(slot_ctx + 4).kernel_mut_ptr::<u32>(),
                slot_d1,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(slot_ctx + 8).kernel_mut_ptr::<u32>(),
                slot_d2,
            );
        }

        // EP0 Context — Control endpoint, default MaxPacketSize.
        let mps = speed.default_max_packet();
        let ep0_d1 = (3 << 1)                    // Error Count = 3
                   | (4 << 3)                    // EP Type = Control
                   | ((mps as u32) << 16); // Max Packet Size
                                           // TR Dequeue Pointer = ctrl_tr_phys, DCS = 1.
        let trdp_lo = (ctrl_tr_phys as u32) | 1;
        let trdp_hi = (ctrl_tr_phys >> 32) as u32;
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(ep0_ctx + 4).kernel_mut_ptr::<u32>(),
                ep0_d1,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(ep0_ctx + 8).kernel_mut_ptr::<u32>(),
                trdp_lo,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(ep0_ctx + 12).kernel_mut_ptr::<u32>(),
                trdp_hi,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(ep0_ctx + 16).kernel_mut_ptr::<u32>(),
                8u32,
            ); // Avg TRB Len
        }

        // Plant Device Context phys at DCBAA[slot_id] BEFORE issuing
        // the command (§4.3.4 step 6). The engine reads DCBAA when
        // it processes Address Device.
        let dcbaa_phys = self.dcbaa.phys_addr().raw();
        // SAFETY: `dcbaa_phys` is the identity-mapped base of the
        // DCBAA page this controller allocated; `slot_id < MaxSlots`
        // (validated at slot-enable) so `slot_id*8` stays inside the
        // page, giving an aligned, in-range 8-byte slot we exclusively
        // own.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(dcbaa_phys + (slot_id as u64) * 8)
                    .kernel_mut_ptr::<u64>(),
                dev_ctx_phys,
            );
        }
        compiler_fence(Ordering::SeqCst);

        // Address Device — single BSR=0 call (xHCI 1.2 §4.6.5).
        // Earlier code did a two-phase BSR=1-then-BSR=0 dance as a
        // speculative quirk. That turned out to be the cause of the
        // USB Transaction Error (CmdFailed 4) on real Renoir
        // hardware: per §4.6.5 the Input Context is consumed during
        // Address Device processing, so feeding the same Input
        // Context to a second Address Device (BSR=0) after BSR=1
        // leaves the controller using stale state and SET_ADDRESS
        // lands mid-bus. The spec only requires the BSR=1 dance
        // when the device firmware can't tolerate a SET_ADDRESS at
        // attach time (rare); plain BSR=0 is the documented default.
        //
        // TRB layout (§6.4.3.4):
        //   dword0/1 = Input Context phys (low/high)
        //   dword2 = reserved
        //   dword3 = TRB Type | Slot ID << 24
        let trb_type = TRB_TYPE_ADDRESS_DEVICE_CMD << TRB_TYPE_SHIFT;
        let cce = TRB_TYPE_CMD_COMPLETION << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let dword3 = trb_type | ((slot_id as u32) << 24);
        self.submit_command(input_phys as u32, (input_phys >> 32) as u32, 0, dword3)?;
        let ev = self
            .await_event(|t| (t[3] & TRB_TYPE_MASK) == cce && (t[3] & 0xFF00_0000) == want_slot)
            .await?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 {
            return Err(XhciError::CmdFailed(ccode));
        }

        // Slot is now Addressed. Stash the per-slot state.
        let dev = Device {
            slot_id,
            port,
            speed,
            max_packet_ep0: mps,
            _device_ctx: dev_ctx,
            ctrl_tr,
            ctrl_pcs: 1,
            ctrl_enq: 0,
            ctrl_data,
            eps: alloc::vec::Vec::new(),
        };
        let mut g = self.devices.lock();
        let need = (slot_id as usize) + 1;
        while g.len() < need {
            g.push(None);
        }
        g[slot_id as usize] = Some(dev);
        // input drops here — the Address Device command consumed
        // its contents during processing.
        let _ = input;
        Ok(slot_id)
    }

    /// Evaluate Context Command (§4.6.7 / §6.4.3.6) — refresh the
    /// EP0 Max Packet Size after GET_DESCRIPTOR returns the device's
    /// real `bMaxPacketSize0`. Audit F-22 + F-23: we initially seed
    /// EP0 with the smallest legal MPS for the speed (8 for FS), then
    /// fix it up here once the device tells us the true value.
    ///
    /// Input Context layout (§6.2.3.3, Evaluate Context variant):
    ///   - Input Control: A0=0 (Slot not modified), A1=1 (EP0 add).
    ///   - Slot Context: ignored (A0=0) but xHC reads dword0..1 anyway
    ///     for some implementations — populate from current Device
    ///     Context to be safe.
    ///   - EP0 Context dword1: bits[31:16] = new Max Packet Size.
    ///
    /// Idempotent: if `new_mps` matches the cached value, returns Ok
    /// without bothering the controller.
    /// Re-issue Evaluate Context (xHCI 1.2 §4.6.7) to flip the
    /// device's Slot Context into "is a USB hub" state once we've
    /// read the Hub Class Descriptor. Per §6.2.2 the controller
    /// uses the Hub bit + Number of Ports to size internal hub
    /// state for Transaction-Translator routing on LS/FS devices
    /// behind it; without this flip the controller may refuse to
    /// address downstream devices.
    ///
    /// Input Context layout:
    ///   - A0=1 (Slot context valid), all other A bits = 0.
    ///   - Slot dword0: re-stamped with current Speed + Context
    ///     Entries, plus the Hub bit (`1<<26`) and optional MTT
    ///     bit (`1<<25`).
    ///   - Slot dword1: re-stamped with Root Hub Port Number plus
    ///     Number of Ports in bits[31:24].
    pub async fn mark_as_hub(
        &self,
        slot_id: u8,
        num_ports: u8,
        multi_tt: bool,
    ) -> Result<(), XhciError> {
        if slot_id == 0 || slot_id > self.caps.max_slots {
            return Err(XhciError::CmdFailed(0xFD));
        }
        let (speed, port) = {
            let g = self.devices.lock();
            let d = g
                .get(slot_id as usize)
                .and_then(|x| x.as_ref())
                .ok_or(XhciError::CmdFailed(0xFD))?;
            (d.speed, d.port)
        };

        let input = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let input_phys = input.phys_addr().raw();
        // SAFETY: identity-mapped DMA, 4 KiB contiguous, just allocated.
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(input_phys).kernel_mut_ptr::<u8>(),
                0,
                4096,
            );
        }
        let cs = self.context_stride();
        let input_ctrl = input_phys;
        let slot_ctx = input_phys + cs;

        // Add Slot only (A0=1). Drop mask = 0.
        // SAFETY: identity-mapped, in-page.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(input_ctrl + 4).kernel_mut_ptr::<u32>(),
                1 << 0,
            );
        }

        let mut slot_d0 = (1u32 << 27) | ((speed as u32) << 20) | (1u32 << 26); // Hub
        if multi_tt {
            slot_d0 |= 1u32 << 25; // MTT
        }
        let slot_d1 = ((port as u32) << 16) | ((num_ports as u32) << 24);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(slot_ctx).kernel_mut_ptr::<u32>(),
                slot_d0,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(slot_ctx + 4).kernel_mut_ptr::<u32>(),
                slot_d1,
            );
        }
        compiler_fence(Ordering::SeqCst);

        let trb_type = TRB_TYPE_EVAL_CONTEXT_CMD << TRB_TYPE_SHIFT;
        let dword3 = trb_type | ((slot_id as u32) << 24);
        self.submit_command(input_phys as u32, (input_phys >> 32) as u32, 0, dword3)?;
        let cce = TRB_TYPE_CMD_COMPLETION << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let ev = self
            .await_event(|t| (t[3] & TRB_TYPE_MASK) == cce && (t[3] & 0xFF00_0000) == want_slot)
            .await?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 {
            return Err(XhciError::CmdFailed(ccode));
        }
        let _ = input;
        Ok(())
    }

    pub async fn evaluate_context_ep0_mps(
        &self,
        slot_id: u8,
        new_mps: u16,
    ) -> Result<(), XhciError> {
        if slot_id == 0 || slot_id > self.caps.max_slots {
            return Err(XhciError::CmdFailed(0xFD));
        }
        // Snapshot current cached MPS + speed under the devices lock.
        let (cur_mps, speed, port) = {
            let g = self.devices.lock();
            let d = g
                .get(slot_id as usize)
                .and_then(|x| x.as_ref())
                .ok_or(XhciError::CmdFailed(0xFD))?;
            (d.max_packet_ep0, d.speed, d.port)
        };
        if cur_mps == new_mps {
            return Ok(());
        }

        let input = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let input_phys = input.phys_addr().raw();
        // SAFETY: identity-mapped DMA, 4 KiB contiguous, just allocated.
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(input_phys).kernel_mut_ptr::<u8>(),
                0,
                4096,
            );
        }
        let cs = self.context_stride();
        let input_ctrl = input_phys;
        let slot_ctx = input_phys + cs;
        let ep0_ctx = input_phys + cs * 2;

        // Add EP0 only (A1=1, A0=0). Drop mask = 0.
        // SAFETY: identity-mapped, in-page.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(input_ctrl + 4).kernel_mut_ptr::<u32>(),
                1 << 1,
            );
        }
        // Re-populate Slot Context dword0/1 (Context Entries=1 + Speed
        // + Root Hub Port) so an xHC that snapshots them sees a sane
        // shape even though A0=0.
        let slot_d0 = (1u32 << 27) | ((speed as u32) << 20);
        let slot_d1 = (port as u32) << 16;
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(slot_ctx).kernel_mut_ptr::<u32>(),
                slot_d0,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(slot_ctx + 4).kernel_mut_ptr::<u32>(),
                slot_d1,
            );
        }
        // EP0 dword1 with the new MPS. Other EP0 fields (TR Dequeue
        // Pointer, Avg TRB Length) are ignored by Evaluate Context per
        // spec — the controller only consumes the MPS field for this
        // command. Keep the EP-Type/Error-Count bits set so an xHC
        // that requires a fully-formed EP context is still happy.
        let ep0_d1 = (3 << 1) | (4 << 3) | ((new_mps as u32) << 16);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(ep0_ctx + 4).kernel_mut_ptr::<u32>(),
                ep0_d1,
            );
        }
        compiler_fence(Ordering::SeqCst);

        let trb_type = TRB_TYPE_EVAL_CONTEXT_CMD << TRB_TYPE_SHIFT;
        let dword3 = trb_type | ((slot_id as u32) << 24);
        self.submit_command(input_phys as u32, (input_phys >> 32) as u32, 0, dword3)?;
        let cce = TRB_TYPE_CMD_COMPLETION << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let ev = self
            .await_event(|t| (t[3] & TRB_TYPE_MASK) == cce && (t[3] & 0xFF00_0000) == want_slot)
            .await?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 {
            return Err(XhciError::CmdFailed(ccode));
        }

        // Update cache.
        {
            let mut g = self.devices.lock();
            if let Some(Some(d)) = g.get_mut(slot_id as usize) {
                d.max_packet_ep0 = new_mps;
            }
        }
        let _ = input;
        Ok(())
    }

    /// Ring the slot's doorbell. Dword layout (§5.6):
    /// bits[7:0] = DB Target (DCI), bits[31:16] = Stream ID.
    fn ring_slot_doorbell(&self, slot_id: u8, dci: u32) {
        let off = self.db_off + (slot_id as u64) * 4;
        // SAFETY: identity-mapped MMIO; slot_id < MaxSlots so the
        // doorbell array entry exists.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.mmio.write32(off, dci);
        }
    }

    /// Enqueue a TRB on the control transfer ring of `slot_id` and
    /// publish the cycle bit. Returns the in-page byte offset of the
    /// TRB (caller uses this to match a Transfer Event back to a
    /// specific TRB).
    fn ctrl_enqueue(
        &self,
        slot_id: u8,
        d0: u32,
        d1: u32,
        d2: u32,
        d3_no_cycle: u32,
    ) -> Result<u64, XhciError> {
        let mut g = self.devices.lock();
        let dev = g
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::CmdFailed(0xFC))?;
        if dev.ctrl_enq == CTRL_TR_TRBS - 1 {
            // Wrap: re-stamp the Link TRB with current cycle, reset
            // enq, toggle pcs. Same shape as ep_enqueue_normal's
            // wrap branch.
            let link_off = ((CTRL_TR_TRBS - 1) * 16) as u64;
            let link_addr = dev.ctrl_tr.phys_addr().raw() + link_off;
            let link_d3 =
                (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC | (dev.ctrl_pcs & TRB_CYCLE_BIT);
            // SAFETY: identity-mapped DMA, offset in-page.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(link_addr + 12).kernel_mut_ptr::<u32>(),
                    link_d3,
                );
            }
            compiler_fence(Ordering::SeqCst);
            dev.ctrl_enq = 0;
            dev.ctrl_pcs ^= 1;
        }
        let trb_off = (dev.ctrl_enq * 16) as u64;
        let trb_addr = dev.ctrl_tr.phys_addr().raw() + trb_off;
        let d3 = d3_no_cycle | (dev.ctrl_pcs & TRB_CYCLE_BIT);
        // SAFETY: identity-mapped DMA; offset in-page.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr).kernel_mut_ptr::<u32>(),
                d0,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 4).kernel_mut_ptr::<u32>(),
                d1,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 8).kernel_mut_ptr::<u32>(),
                d2,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 12).kernel_mut_ptr::<u32>(),
                d3,
            );
        }
        compiler_fence(Ordering::SeqCst);
        dev.ctrl_enq += 1;
        Ok(trb_off)
    }

    /// Issue a control IN transfer with no OUT data stage and read
    /// the device-supplied bytes into `out`. Builds a Setup Stage
    /// (IDT, TRT=IN) + Data Stage (IN) + Status Stage (OUT) on the
    /// control transfer ring (§4.11.2.2), rings the slot's
    /// doorbell at DCI 1, and waits for a Transfer Event with IOC.
    ///
    /// `bm_request_type` / `b_request` / `w_value` / `w_index` /
    /// `w_length` carry the standard 8-byte SETUP packet (§9.3).
    /// `out` length must equal `w_length`.
    pub async fn control_in(
        &self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        out: &mut [u8],
    ) -> Result<usize, XhciError> {
        if out.len() != w_value.into() && out.is_empty() {
            // Allow the caller to ask for any byte-count that fits
            // a u16; w_length is just the SETUP-packet field.
        }
        let w_length = out.len() as u16;
        // Audit F-45: reuse the per-slot persistent control-data
        // buffer instead of alloc_coherent every call. The buffer
        // lives in the Device struct and is freed when the slot is
        // disabled. 4 KiB is enough for any descriptor we fetch
        // (max wTotalLength capped at 4096 by the kbd path).
        let data_phys = {
            let g = self.devices.lock();
            let d = g
                .get(slot_id as usize)
                .and_then(|x| x.as_ref())
                .ok_or(XhciError::CmdFailed(0xFD))?;
            d.ctrl_data.phys_addr().raw()
        };
        // Zero so a stale buffer can't be confused with the device
        // response on a short read.
        // SAFETY: identity-mapped DMA page; persistent and 4 KiB.
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(data_phys).kernel_mut_ptr::<u8>(),
                0,
                4096,
            );
        }

        // ── Setup Stage TRB (§6.4.1.2.1) ──────────────────────────
        // dword0 = bmRequestType | bRequest << 8 | wValue << 16
        // dword1 = wIndex | wLength << 16
        // dword2 = transfer length (always 8 for SETUP)
        // dword3 = TRB Type=2 | TRT | IDT | IOC=0
        let setup_d0 =
            (bm_request_type as u32) | ((b_request as u32) << 8) | ((w_value as u32) << 16);
        let setup_d1 = (w_index as u32) | ((w_length as u32) << 16);
        let setup_d2 = 8u32;
        let trt = if w_length > 0 {
            TRT_IN_DATA
        } else {
            TRT_NO_DATA
        };
        let setup_d3 = (TRB_TYPE_SETUP_STAGE << TRB_TYPE_SHIFT) | TRB_IDT | (trt << 16);
        self.ctrl_enqueue(slot_id, setup_d0, setup_d1, setup_d2, setup_d3)?;

        // ── Data Stage TRB (§6.4.1.2.2) ───────────────────────────
        // dword0/1 = data buffer phys
        // dword2 = TRB Transfer Length (low 17 bits)
        // dword3 = TRB Type=3 | DIR=IN | IOC=1
        if w_length > 0 {
            let data_d3 = (TRB_TYPE_DATA_STAGE << TRB_TYPE_SHIFT) | TRB_DIR_IN | TRB_IOC;
            self.ctrl_enqueue(
                slot_id,
                data_phys as u32,
                (data_phys >> 32) as u32,
                w_length as u32,
                data_d3,
            )?;
        }

        // ── Status Stage TRB (§6.4.1.2.3) ─────────────────────────
        // dword3 = TRB Type=4 | DIR opposite of data stage | IOC=1
        // For an IN data stage the status stage is OUT (DIR=0).
        // For NO_DATA the status stage is IN (DIR=1).
        let status_dir = if w_length > 0 { 0 } else { TRB_DIR_IN };
        let status_d3 = (TRB_TYPE_STATUS_STAGE << TRB_TYPE_SHIFT) | status_dir | TRB_IOC;
        self.ctrl_enqueue(slot_id, 0, 0, 0, status_d3)?;

        // Ring the slot's control-EP doorbell.
        self.ring_slot_doorbell(slot_id, DCI_CONTROL_EP);

        // Wait for a Transfer Event from this slot's Control EP
        // (DCI=1). Audit F-41: filter on Endpoint ID (dword3
        // bits[20:16]) as well as Slot ID — the prior loose
        // slot-only filter would consume an interrupt-IN event
        // landing at the same time as a control transfer, leaving
        // the actual Status-Stage event in the queue and the
        // interrupt-IN poll missing data. We don't gate on a
        // specific TRB pointer because some controllers emit a
        // Transfer Event for Data Stage too — accept the first
        // Transfer Event for this (slot, EP=1) pair.
        let xfer = TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let want_ep = (DCI_CONTROL_EP) << 16;
        let ev = self
            .await_event(|t| {
                (t[3] & TRB_TYPE_MASK) == xfer
                    && (t[3] & 0xFF00_0000) == want_slot
                    && (t[3] & 0x001F_0000) == want_ep
            })
            .await?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        // Completion code 1 = Success, 13 = Short Packet (also OK
        // for Get Descriptor when the device-reported length is
        // shorter than wLength).
        if ccode != 1 && ccode != 13 {
            return Err(XhciError::CmdFailed(ccode));
        }
        // Transfer Length residue lives in dword2[23:0]. Bytes
        // actually transferred = w_length - residue.
        let residue = ev[2] & 0x00FF_FFFF;
        let xferred = (w_length as u32).saturating_sub(residue) as usize;

        // Copy data buffer → out.
        let copy = xferred.min(out.len());
        for (i, slot) in out[..copy].iter_mut().enumerate() {
            // SAFETY: `data_phys` is this slot's identity-mapped DMA
            // page; `i < copy ≤ xferred ≤ w_length ≤ 4096` keeps the
            // byte read inside that page, aligned for a `u8`.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *slot = unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(data_phys + i as u64).kernel_ptr::<u8>(),
                )
            };
        }
        Ok(xferred)
    }

    /// Issue a host-to-device control transfer with an OUT data
    /// stage (USB 2.0 §9.3 / xHCI 1.2 §6.4.1.2). Mirror of
    /// [`Self::control_in`]: SETUP TRB, optional Data Stage TRB
    /// (DIR=OUT), Status Stage TRB (DIR=IN), then await Transfer
    /// Event. `data` may be empty for class requests that pack
    /// everything into the SETUP packet's wValue/wIndex fields.
    /// Returns the bytes the controller acknowledged delivering.
    pub async fn control_out(
        &self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &[u8],
    ) -> Result<usize, XhciError> {
        if data.len() > 4096 {
            return Err(XhciError::CmdFailed(0xF9));
        }
        let w_length = data.len() as u16;
        let data_phys = {
            let g = self.devices.lock();
            let d = g
                .get(slot_id as usize)
                .and_then(|x| x.as_ref())
                .ok_or(XhciError::CmdFailed(0xFD))?;
            d.ctrl_data.phys_addr().raw()
        };
        // Stage caller's bytes into the persistent control-data
        // buffer (audit F-45). Zero the prefix first so a stale
        // tail can't leak into a subsequent transfer.
        // SAFETY: identity-mapped DMA page; ≤ 4 KiB.
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(data_phys).kernel_mut_ptr::<u8>(),
                0,
                4096,
            );
            for (i, b) in data.iter().enumerate() {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(data_phys + i as u64).kernel_mut_ptr::<u8>(),
                    *b,
                );
            }
        }

        // ── Setup Stage TRB ───────────────────────────────────────
        let setup_d0 =
            (bm_request_type as u32) | ((b_request as u32) << 8) | ((w_value as u32) << 16);
        let setup_d1 = (w_index as u32) | ((w_length as u32) << 16);
        let setup_d2 = 8u32;
        let trt = if w_length > 0 {
            TRT_OUT_DATA
        } else {
            TRT_NO_DATA
        };
        let setup_d3 = (TRB_TYPE_SETUP_STAGE << TRB_TYPE_SHIFT) | TRB_IDT | (trt << 16);
        self.ctrl_enqueue(slot_id, setup_d0, setup_d1, setup_d2, setup_d3)?;

        // ── Data Stage TRB (DIR=OUT) ──────────────────────────────
        if w_length > 0 {
            let data_d3 = (TRB_TYPE_DATA_STAGE << TRB_TYPE_SHIFT) | TRB_IOC; // DIR bit clear = OUT
            self.ctrl_enqueue(
                slot_id,
                data_phys as u32,
                (data_phys >> 32) as u32,
                w_length as u32,
                data_d3,
            )?;
        }

        // ── Status Stage TRB ──────────────────────────────────────
        // For an OUT data stage, status stage is IN (DIR=1). For
        // NO_DATA the status stage is also IN.
        let status_d3 = (TRB_TYPE_STATUS_STAGE << TRB_TYPE_SHIFT) | TRB_DIR_IN | TRB_IOC;
        self.ctrl_enqueue(slot_id, 0, 0, 0, status_d3)?;

        self.ring_slot_doorbell(slot_id, DCI_CONTROL_EP);

        let xfer = TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let want_ep = (DCI_CONTROL_EP) << 16;
        let ev = self
            .await_event(|t| {
                (t[3] & TRB_TYPE_MASK) == xfer
                    && (t[3] & 0xFF00_0000) == want_slot
                    && (t[3] & 0x001F_0000) == want_ep
            })
            .await?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 && ccode != 13 {
            return Err(XhciError::CmdFailed(ccode));
        }
        let residue = ev[2] & 0x00FF_FFFF;
        Ok((w_length as u32).saturating_sub(residue) as usize)
    }

    /// Fetch the 18-byte USB Device Descriptor (§9.6.1) for an
    /// Addressed slot. Returns the byte-aligned descriptor — caller
    /// pulls VID/DID etc. out of fixed offsets.
    pub async fn get_device_descriptor(&self, slot_id: u8) -> Result<[u8; 18], XhciError> {
        let mut buf = [0u8; 18];
        let n = self
            .control_in(
                slot_id,
                0x80,                               // bmRequestType: IN, Standard, Device
                USB_REQ_GET_DESCRIPTOR,             // bRequest
                (USB_DESC_TYPE_DEVICE as u16) << 8, // wValue: descriptor type | index
                0,                                  // wIndex
                &mut buf,
            )
            .await?;
        if n < 8 {
            return Err(XhciError::CmdFailed(0xFB));
        }
        Ok(buf)
    }

    /// Look up a previously-addressed device by slot id.
    pub fn device_info(&self, slot_id: u8) -> Option<(u8, PortSpeed, u16)> {
        let g = self.devices.lock();
        let d = g.get(slot_id as usize)?.as_ref()?;
        Some((d.port, d.speed, d.max_packet_ep0))
    }

    /// First addressed slot id bound to `port`, or `None` if no slot
    /// is currently bound. Used by test cleanup to recycle stale port
    /// bindings left over by prior tests.
    pub fn slot_for_port(&self, port: u8) -> Option<u8> {
        let g = self.devices.lock();
        for (idx, slot) in g.iter().enumerate() {
            if let Some(d) = slot {
                if d.port == port {
                    return Some(idx as u8);
                }
            }
        }
        None
    }

    /// Fetch the 9-byte Configuration Descriptor header (§9.6.3) for
    /// `cfg_index` (typically 0). To read the full configuration tree
    /// (interface + endpoint descriptors), call again with a buffer
    /// sized to `wTotalLength` from the header.
    pub async fn get_config_descriptor(
        &self,
        slot_id: u8,
        cfg_idx: u8,
        out: &mut [u8],
    ) -> Result<usize, XhciError> {
        // wValue = (descriptor_type << 8) | descriptor_index. Type
        // 2 = CONFIGURATION (§9.4 Table 9-5).
        let w_value = (2u16 << 8) | (cfg_idx as u16);
        self.control_in(
            slot_id,
            0x80, // bmRequestType: IN, Standard, Device
            USB_REQ_GET_DESCRIPTOR,
            w_value,
            0,
            out,
        )
        .await
    }

    /// Issue Configure Endpoint (§4.6.6) for `slot_id`, programming
    /// the supplied `endpoints` into the slot's Input Context. The
    /// engine reads the input context and copies updates into the
    /// device context.
    ///
    /// Spec note: Configure Endpoint with the Deconfigure (DC) bit
    /// clear is the typical flow — caller-supplied add-mask covers
    /// every endpoint listed in `endpoints`. Stage-5 cut: caller
    /// must include EP0 (Slot Context A0) is left untouched; we
    /// only flip A bits for the endpoints they pass.
    pub async fn configure_endpoints(
        &self,
        slot_id: u8,
        endpoints: &[EndpointConfig],
    ) -> Result<(), XhciError> {
        if endpoints.is_empty() {
            return Ok(());
        }

        // Allocate Input Context (4 KiB, zeroed). Layout matches
        // address_device — Input Control at 0, Slot Ctx at one
        // stride, per-EP Ctx at `stride * (1 + dci - 1)` =
        // `stride * dci`. The stride is 32 or 64 depending on CSZ.
        let input = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let input_phys = input.phys_addr().raw();
        // SAFETY: identity-mapped DMA; fresh 4 KiB page.
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(input_phys).kernel_mut_ptr::<u8>(),
                0,
                4096,
            );
        }

        // Build per-endpoint state + the Input Control + per-EP
        // contexts. The transfer rings live in `EndpointState`
        // values that we move into `dev.eps` after the command
        // succeeds.
        let mut new_eps: alloc::vec::Vec<EndpointState> =
            alloc::vec::Vec::with_capacity(endpoints.len());
        let mut add_mask: u32 = 0;

        // Add Slot Context (A0) so the engine refreshes Context
        // Entries — required when adding endpoints past EP0.
        // §4.6.6 step 1.
        add_mask |= 1 << 0;

        // Need to compute the new "Context Entries" value: highest
        // DCI in use + 1, capped at 31. Default-control = DCI 1.
        let mut max_dci = 1u32;

        for ep in endpoints.iter().copied() {
            let dci = ep.dci();
            if !(2..=31).contains(&dci) {
                return Err(XhciError::CmdFailed(0xFB));
            }
            max_dci = max_dci.max(dci as u32);
            add_mask |= 1 << dci;

            let tr = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
            let tr_phys = tr.phys_addr().raw();
            // SAFETY: same.
            unsafe {
                core::ptr::write_bytes(
                    narf_memory::PhysAddr::new(tr_phys).kernel_mut_ptr::<u8>(),
                    0,
                    4096,
                );
            }
            // Plant a Link TRB at slot CTRL_TR_TRBS-1 pointing back
            // to slot 0 with TC=1. Cycle bit starts at 0 (the
            // producer's pcs starts at 1; first time we cross the
            // Link, hardware sees Cycle=0 matching its initial CCS
            // expectation, follows the link, and toggles. We toggle
            // pcs in lockstep on the producer side).
            let link_trb_off = ((CTRL_TR_TRBS - 1) * 16) as u64;
            let link_addr = tr_phys + link_trb_off;
            let link_d3 = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC; // TC=1, cycle=0
                                                                      // SAFETY: identity-mapped DMA, offset checked.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(link_addr).kernel_mut_ptr::<u32>(),
                    tr_phys as u32,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(link_addr + 4).kernel_mut_ptr::<u32>(),
                    (tr_phys >> 32) as u32,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(link_addr + 8).kernel_mut_ptr::<u32>(),
                    0,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(link_addr + 12).kernel_mut_ptr::<u32>(),
                    link_d3,
                );
            }
            // Persistent per-EP DMA scratch. One page; bulk_in /
            // bulk_out reuse this instead of allocating on every
            // call (audit #14: drop-then-reuse races with delayed
            // DMA writes when the IOMMU is on).
            let dma_buf =
                alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;

            // EP context at `cs + cs * dci` = `cs * (1 + dci)`. cs
            // = 32 (CSZ=0) or 64 (CSZ=1).
            let cs = self.context_stride();
            let ep_ctx = input_phys + cs * (1 + dci as u64);
            let ep_d1 = (3 << 1)                                    // Error Count = 3
                      | (ep.kind.ep_type() << 3)                    // EP Type
                      | ((ep.max_packet as u32) << 16); // MaxPacketSize
            let trdp_lo = (tr_phys as u32) | 1; // DCS=1
            let trdp_hi = (tr_phys >> 32) as u32;
            // Average TRB length — spec recommends `max_packet / 2`
            // for bulk; 8 for control. We use 8 as a safe default
            // for everything except isoch.
            let avg_trb = match ep.kind {
                EndpointKind::IsochIn | EndpointKind::IsochOut => ep.max_packet as u32,
                _ => 8u32,
            };
            // SAFETY: identity-mapped DMA; offset in-page.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(ep_ctx + 4).kernel_mut_ptr::<u32>(),
                    ep_d1,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(ep_ctx + 8).kernel_mut_ptr::<u32>(),
                    trdp_lo,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(ep_ctx + 12).kernel_mut_ptr::<u32>(),
                    trdp_hi,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(ep_ctx + 16).kernel_mut_ptr::<u32>(),
                    avg_trb,
                );
            }
            new_eps.push(EndpointState {
                dci,
                max_packet: ep.max_packet,
                kind: ep.kind,
                tr,
                dma_buf,
                pcs: 1,
                enq: 0,
            });
        }

        // Slot Context: per xHCI §4.6.6 step 1, copy ALL Slot
        // Context dwords from the running Device Context into the
        // Input Slot Context, then update Context Entries
        // (dword0 bits[31:27]) to reflect the new max DCI. Pre-fix
        // (audit F-31) only copied dword0/1 — leaving dword2/3
        // (TT info, interrupter target, USB device address) zeroed,
        // which the engine writes back to the Device Context after
        // command processing. On real hardware that wipes the
        // assigned device address and leaves the slot in Default
        // state, breaking later control transfers.
        // SAFETY: identity-mapped DCBAA[slot_id] points at the
        // slot's device context.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let dev_ctx_phys = unsafe {
            let dcbaa_phys = self.dcbaa.phys_addr().raw();
            core::ptr::read_volatile(
                narf_memory::PhysAddr::new(dcbaa_phys + (slot_id as u64) * 8).kernel_ptr::<u64>(),
            )
        };
        let slot_ctx_off = input_phys + self.context_stride();
        // Copy the full Slot Context (4 dwords; bytes 0..16). The
        // remainder of the per-context stride is reserved/RsvdZ
        // and was zeroed by the page-zero above.
        // SAFETY: identity-mapped DMA on both ends; both regions
        // owned and 4 KiB.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            for off in 0..4u64 {
                let v = core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(dev_ctx_phys + off * 4).kernel_ptr::<u32>(),
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(slot_ctx_off + off * 4).kernel_mut_ptr::<u32>(),
                    v,
                );
            }
            // Refresh Context Entries with the new max DCI.
            let d0 = core::ptr::read_volatile(
                narf_memory::PhysAddr::new(slot_ctx_off).kernel_ptr::<u32>(),
            );
            let new_d0 = (d0 & !(0x1Fu32 << 27)) | (max_dci << 27);
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(slot_ctx_off).kernel_mut_ptr::<u32>(),
                new_d0,
            );
        }

        // Input Control Context: dword1 = add mask.
        // SAFETY: identity-mapped DMA.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(input_phys + 4).kernel_mut_ptr::<u32>(),
                add_mask,
            );
        }

        // Issue Configure Endpoint (§6.4.3.5): same TRB shape as
        // Address Device, different Type.
        let trb_type = TRB_TYPE_CONFIGURE_ENDPOINT_CMD << TRB_TYPE_SHIFT;
        let dword3 = trb_type | ((slot_id as u32) << 24);
        self.submit_command(input_phys as u32, (input_phys >> 32) as u32, 0, dword3)?;
        let cce = TRB_TYPE_CMD_COMPLETION << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let ev = self
            .await_event(|t| (t[3] & TRB_TYPE_MASK) == cce && (t[3] & 0xFF00_0000) == want_slot)
            .await?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 {
            return Err(XhciError::CmdFailed(ccode));
        }

        // Stash the endpoint states on the slot. Sized so a vec
        // index of `dci - 2` works.
        let mut g = self.devices.lock();
        let dev = g
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::CmdFailed(0xFC))?;
        for ep in new_eps {
            let dci = ep.dci as usize;
            let need = dci.saturating_sub(2) + 1;
            while dev.eps.len() < need {
                dev.eps.push(None);
            }
            dev.eps[dci - 2] = Some(ep);
        }
        let _ = input;
        Ok(())
    }

    /// Enqueue a single Normal TRB on the bulk endpoint at `dci`
    /// pointing at `phys`+`len`, with IOC set so the engine fires
    /// a Transfer Event on completion.
    fn ep_enqueue_normal(
        &self,
        slot_id: u8,
        dci: u8,
        phys: u64,
        len: u32,
    ) -> Result<(), XhciError> {
        let mut g = self.devices.lock();
        let dev = g
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::CmdFailed(0xFC))?;
        let idx = (dci as usize).saturating_sub(2);
        let ep = dev
            .eps
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::CmdFailed(0xFA))?;
        // Slot CTRL_TR_TRBS-1 is the Link TRB planted at ring
        // construction. When enq reaches it, follow the link:
        // re-update the Link TRB's cycle bit so hardware can
        // see it as "valid + toggle" on its next dequeue, reset
        // enq to 0, toggle pcs, then write the new Normal TRB
        // at slot 0 with the toggled cycle.
        if ep.enq == CTRL_TR_TRBS - 1 {
            // Re-stamp the Link TRB with the *current* cycle so
            // the engine consumes it. Without this, a Link TRB
            // written at construction with cycle=0 stays valid
            // forever (engine reads it once, follows it, but
            // subsequent wraps need fresh cycle bits).
            let link_off = ((CTRL_TR_TRBS - 1) * 16) as u64;
            let link_addr = ep.tr.phys_addr().raw() + link_off;
            let link_d3 = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC | (ep.pcs & TRB_CYCLE_BIT);
            // SAFETY: identity-mapped DMA, offset in-page.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(link_addr + 12).kernel_mut_ptr::<u32>(),
                    link_d3,
                );
            }
            compiler_fence(Ordering::SeqCst);
            ep.enq = 0;
            ep.pcs ^= 1;
        }
        let trb_off = (ep.enq * 16) as u64;
        let trb_addr = ep.tr.phys_addr().raw() + trb_off;
        let d3 = (TRB_TYPE_NORMAL << TRB_TYPE_SHIFT) | TRB_IOC | (ep.pcs & TRB_CYCLE_BIT);
        // SAFETY: identity-mapped DMA; offset in-page.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr).kernel_mut_ptr::<u32>(),
                phys as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 4).kernel_mut_ptr::<u32>(),
                (phys >> 32) as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 8).kernel_mut_ptr::<u32>(),
                len,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 12).kernel_mut_ptr::<u32>(),
                d3,
            );
        }
        compiler_fence(Ordering::SeqCst);
        ep.enq += 1;
        Ok(())
    }

    /// Enqueue an Isoch TRB on the slot/dci endpoint. Same ring +
    /// link-wrap logic as `ep_enqueue_normal`; differs only in the
    /// TRB type (5 = Isoch) and the SIA bit set so the controller
    /// schedules in the next available frame instead of waiting
    /// for a host-specified Frame ID. TBC/TLBPC stay 0 (single
    /// burst, single packet per burst) — enough for the bring-up
    /// targets that use 1-packet-per-bInterval (USB 2.0 full-speed).
    fn ep_enqueue_isoch(&self, slot_id: u8, dci: u8, phys: u64, len: u32) -> Result<(), XhciError> {
        let mut g = self.devices.lock();
        let dev = g
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::CmdFailed(0xFC))?;
        let idx = (dci as usize).saturating_sub(2);
        let ep = dev
            .eps
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::CmdFailed(0xFA))?;
        // Link-wrap (mirrors the Normal path).
        if ep.enq == CTRL_TR_TRBS - 1 {
            let link_off = ((CTRL_TR_TRBS - 1) * 16) as u64;
            let link_addr = ep.tr.phys_addr().raw() + link_off;
            let link_d3 = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC | (ep.pcs & TRB_CYCLE_BIT);
            // SAFETY: identity-mapped DMA, offset in-page.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(link_addr + 12).kernel_mut_ptr::<u32>(),
                    link_d3,
                );
            }
            compiler_fence(Ordering::SeqCst);
            ep.enq = 0;
            ep.pcs ^= 1;
        }
        let trb_off = (ep.enq * 16) as u64;
        let trb_addr = ep.tr.phys_addr().raw() + trb_off;
        // Iso TRB d3:
        //   bit 0 = cycle (matches ep.pcs)
        //   bit 5 = IOC (interrupt on completion)
        //   bits 10-15 = TRB Type (5 = Isoch)
        //   bit 31 = SIA (Start Isochronous ASAP)
        // TBC (bits 7-8), TLBPC (bits 16-19), Frame ID (bits 20-30)
        // all stay 0.
        let d3 = (TRB_TYPE_ISOCH << TRB_TYPE_SHIFT) | TRB_IOC | TRB_SIA | (ep.pcs & TRB_CYCLE_BIT);
        // SAFETY: identity-mapped DMA; offset in-page.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr).kernel_mut_ptr::<u32>(),
                phys as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 4).kernel_mut_ptr::<u32>(),
                (phys >> 32) as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 8).kernel_mut_ptr::<u32>(),
                len,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(trb_addr + 12).kernel_mut_ptr::<u32>(),
                d3,
            );
        }
        compiler_fence(Ordering::SeqCst);
        ep.enq += 1;
        Ok(())
    }

    /// Submit a single iso-OUT transfer (host→device, e.g. UAC PCM
    /// playback packet). Caller's `data` is staged into the
    /// per-endpoint persistent DMA buffer; controller picks the
    /// next available frame and ships it. Waits for the Transfer
    /// Event so the caller knows the packet was sent.
    ///
    /// For *continuous* streaming the eventual ring layer pre-stages
    /// many iso TRBs and doesn't wait per-packet; this one-shot
    /// variant is the building block + the path the test smokes
    /// exercise.
    pub async fn isoch_out(&self, slot_id: u8, dci: u8, data: &[u8]) -> Result<usize, XhciError> {
        if data.is_empty() || data.len() > 4096 {
            return Err(XhciError::CmdFailed(0xF9));
        }
        let phys = self.ep_dma_phys(slot_id, dci)?;
        // SAFETY: identity-mapped DMA page; size bounded above.
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>(),
                data.len(),
            );
        }
        compiler_fence(Ordering::SeqCst);
        self.ep_enqueue_isoch(slot_id, dci, phys, data.len() as u32)?;
        self.ring_slot_doorbell(slot_id, dci as u32);
        // Wait for the Transfer Event (slot + ep filter, same shape
        // as bulk_out).
        let xfer = TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let want_ep = (dci as u32) << 16;
        let ev = self
            .await_event(|t| {
                (t[3] & TRB_TYPE_MASK) == xfer
                    && (t[3] & 0xFF00_0000) == want_slot
                    && (t[3] & 0x001F_0000) == want_ep
            })
            .await?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        // CC 1 = Success; CC 13 = Short Packet (acceptable on iso
        // OUT — controller transmitted fewer bytes than requested
        // because the device's iso budget for this frame was
        // smaller, common on under-clocked endpoints).
        if ccode != 1 && ccode != 13 {
            return Err(XhciError::CmdFailed(ccode));
        }
        let residue = ev[2] & 0x00FF_FFFF;
        Ok((data.len() as u32).saturating_sub(residue) as usize)
    }

    /// Submit a single iso-IN transfer (device→host, e.g. UVC
    /// frame packet, UAC mic capture packet). Posts a receive
    /// buffer + waits for the Transfer Event; returns bytes
    /// received into `out`.
    pub async fn isoch_in(&self, slot_id: u8, dci: u8, out: &mut [u8]) -> Result<usize, XhciError> {
        if out.is_empty() || out.len() > 4096 {
            return Err(XhciError::CmdFailed(0xF9));
        }
        let phys = self.ep_dma_phys(slot_id, dci)?;
        // Zero only the prefix we'll read — stale data in the
        // persistent buffer mustn't masquerade as device payload.
        // SAFETY: identity-mapped DMA page; bounds-checked above.
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>(),
                0,
                out.len(),
            );
        }
        self.ep_enqueue_isoch(slot_id, dci, phys, out.len() as u32)?;
        self.ring_slot_doorbell(slot_id, dci as u32);
        let xfer = TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let want_ep = (dci as u32) << 16;
        let ev = self
            .await_event(|t| {
                (t[3] & TRB_TYPE_MASK) == xfer
                    && (t[3] & 0xFF00_0000) == want_slot
                    && (t[3] & 0x001F_0000) == want_ep
            })
            .await?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 && ccode != 13 {
            return Err(XhciError::CmdFailed(ccode));
        }
        let residue = ev[2] & 0x00FF_FFFF;
        let xferred = (out.len() as u32).saturating_sub(residue) as usize;
        let copy = xferred.min(out.len());
        for (i, slot) in out[..copy].iter_mut().enumerate() {
            // SAFETY: `phys` is this endpoint's identity-mapped DMA
            // page; `i < copy ≤ xferred ≤ out.len() ≤ 4096` keeps the
            // read inside that page, aligned for a `u8`.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *slot = unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(phys + i as u64).kernel_ptr::<u8>(),
                )
            };
        }
        Ok(xferred)
    }

    /// Issue a bulk-IN read against `slot_id` / `dci`. Allocates a
    /// single DMA scratch page (max read = 4 KiB), enqueues a
    /// Normal TRB, rings the slot doorbell, and waits for a
    /// Transfer Event. Returns bytes received.
    pub async fn bulk_in(&self, slot_id: u8, dci: u8, out: &mut [u8]) -> Result<usize, XhciError> {
        if out.is_empty() || out.len() > 4096 {
            return Err(XhciError::CmdFailed(0xF9));
        }
        // Reuse the per-EP persistent DMA buffer (audit #14).
        let phys = self.ep_dma_phys(slot_id, dci)?;
        // Zero only the prefix we'll read back so a stale page can't
        // be confused with a 0-length response from the device.
        // SAFETY: identity-mapped DMA page; bounds-checked by the
        // upstream `out.len() > 4096` guard.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>(),
                0,
                out.len(),
            );
        }
        self.ep_enqueue_normal(slot_id, dci, phys, out.len() as u32)?;
        self.ring_slot_doorbell(slot_id, dci as u32);

        // Audit F-41: filter Transfer Events by both Slot ID and
        // Endpoint ID so a parallel control transfer (DCI=1) on the
        // same slot doesn't steal our event.
        let xfer = TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let want_ep = (dci as u32) << 16;
        let ev = self
            .await_event(|t| {
                (t[3] & TRB_TYPE_MASK) == xfer
                    && (t[3] & 0xFF00_0000) == want_slot
                    && (t[3] & 0x001F_0000) == want_ep
            })
            .await?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 && ccode != 13 {
            return Err(XhciError::CmdFailed(ccode));
        }
        let residue = ev[2] & 0x00FF_FFFF;
        let xferred = (out.len() as u32).saturating_sub(residue) as usize;
        let copy = xferred.min(out.len());
        for (i, slot) in out[..copy].iter_mut().enumerate() {
            // SAFETY: `phys` is this endpoint's identity-mapped DMA
            // page; `i < copy ≤ xferred ≤ out.len() ≤ 4096` keeps the
            // read inside that page, aligned for a `u8`.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *slot = unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(phys + i as u64).kernel_ptr::<u8>(),
                )
            };
        }
        Ok(xferred)
    }

    /// Stage one Normal TRB on an interrupt-IN endpoint and ring the
    /// doorbell, without waiting for completion. Used to pre-arm
    /// interrupt-IN polling: the controller starts polling the
    /// device on the EP's bInterval cadence, and a Transfer Event
    /// gets posted whenever the device returns data. The supervisor
    /// task drives this by alternating `arm_interrupt_in` →
    /// `wait_for_irq` → `poll_interrupt_in` per cycle. Returns the
    /// staged DMA buffer phys for inspection (caller need not use).
    pub fn arm_interrupt_in(&self, slot_id: u8, dci: u8, len: u32) -> Result<u64, XhciError> {
        if len == 0 || len > 4096 {
            return Err(XhciError::CmdFailed(0xF9));
        }
        let phys = self.ep_dma_phys(slot_id, dci)?;
        // Zero the prefix so a stale page doesn't masquerade as
        // device data.
        // SAFETY: identity-mapped DMA page; bounds-checked above.
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>(),
                0,
                len as usize,
            );
        }
        self.ep_enqueue_normal(slot_id, dci, phys, len)?;
        self.ring_slot_doorbell(slot_id, dci as u32);
        Ok(phys)
    }

    /// Non-blocking interrupt-IN poll: drains *one* matching Transfer
    /// Event from the demux queue (without re-enqueueing or waiting),
    /// reads the bytes the controller wrote into the EP DMA buffer,
    /// and stages a fresh Normal TRB so the next report arrives. The
    /// caller must have armed the endpoint with `arm_interrupt_in`
    /// at least once before the first call.
    ///
    /// Returns:
    /// - `Ok(Some(n))` — `n` bytes received; a fresh TRB is now armed
    /// - `Ok(None)`    — no event pending; nothing to do
    /// - `Err(e)`      — controller-side error
    ///
    /// This is the right shape for an interrupt-IN endpoint: the
    /// controller may take an indefinite amount of time to deliver
    /// the next report (a HID kbd with SET_IDLE only sends on state
    /// change), so the synchronous `bulk_in` 250 ms timeout
    /// model would either fire CmdTimeout on every idle cycle or
    /// block the supervisor for far too long.
    pub fn poll_interrupt_in(
        &self,
        slot_id: u8,
        dci: u8,
        out: &mut [u8],
    ) -> Result<Option<usize>, XhciError> {
        if out.is_empty() || out.len() > 4096 {
            return Err(XhciError::CmdFailed(0xF9));
        }
        let xfer = TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let want_ep = (dci as u32) << 16;
        // Drain the ring into queues so any event already posted
        // since the last poll lands in transfer_events.
        while self.demux_one_event().is_some() {}
        // Try to pop one matching event (no waiting).
        let ev = {
            let mut g = self.transfer_events.lock();
            let pos = g.iter().position(|t| {
                (t[3] & TRB_TYPE_MASK) == xfer
                    && (t[3] & 0xFF00_0000) == want_slot
                    && (t[3] & 0x001F_0000) == want_ep
            });
            match pos {
                Some(p) => match g.remove(p) {
                    Some(e) => e,
                    None => return Ok(None),
                },
                None => return Ok(None),
            }
        };
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 && ccode != 13 {
            // Re-arm before bailing so a transient device error
            // doesn't permanently silence the endpoint.
            let _ = self.arm_interrupt_in(slot_id, dci, out.len() as u32);
            return Err(XhciError::CmdFailed(ccode));
        }
        let residue = ev[2] & 0x00FF_FFFF;
        let xferred = (out.len() as u32).saturating_sub(residue) as usize;
        let phys = self.ep_dma_phys(slot_id, dci)?;
        let copy = xferred.min(out.len());
        for (i, slot) in out[..copy].iter_mut().enumerate() {
            // SAFETY: `phys` is this endpoint's identity-mapped DMA
            // page; `i < copy ≤ xferred ≤ out.len() ≤ 4096` keeps the
            // read inside that page, aligned for a `u8`.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *slot = unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(phys + i as u64).kernel_ptr::<u8>(),
                )
            };
        }
        // Re-arm for the next report.
        self.arm_interrupt_in(slot_id, dci, out.len() as u32)?;
        Ok(Some(xferred))
    }

    /// Resolve the persistent DMA buffer phys for an endpoint.
    fn ep_dma_phys(&self, slot_id: u8, dci: u8) -> Result<u64, XhciError> {
        let g = self.devices.lock();
        let dev = g
            .get(slot_id as usize)
            .and_then(|s| s.as_ref())
            .ok_or(XhciError::CmdFailed(0xFC))?;
        let idx = (dci as usize).saturating_sub(2);
        let ep = dev
            .eps
            .get(idx)
            .and_then(|s| s.as_ref())
            .ok_or(XhciError::CmdFailed(0xFA))?;
        Ok(ep.dma_buf.phys_addr().raw())
    }

    /// Issue a bulk-OUT write. Mirror of `bulk_in`: stages caller's
    /// bytes into a DMA scratch page, enqueues a Normal TRB,
    /// rings the slot doorbell, awaits the Transfer Event.
    /// Returns bytes acknowledged by the engine.
    pub async fn bulk_out(&self, slot_id: u8, dci: u8, data: &[u8]) -> Result<usize, XhciError> {
        if data.is_empty() || data.len() > 4096 {
            return Err(XhciError::CmdFailed(0xF9));
        }
        // Reuse per-EP DMA buffer (audit #14).
        let phys = self.ep_dma_phys(slot_id, dci)?;
        // SAFETY: identity-mapped DMA page; bounds-checked by guard.
        unsafe {
            for (i, &b) in data.iter().enumerate() {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(phys + i as u64).kernel_mut_ptr::<u8>(),
                    b,
                );
            }
        }
        self.ep_enqueue_normal(slot_id, dci, phys, data.len() as u32)?;
        self.ring_slot_doorbell(slot_id, dci as u32);

        let xfer = TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let want_ep = (dci as u32) << 16;
        let ev = self
            .await_event(|t| {
                (t[3] & TRB_TYPE_MASK) == xfer
                    && (t[3] & 0xFF00_0000) == want_slot
                    && (t[3] & 0x001F_0000) == want_ep
            })
            .await?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 {
            return Err(XhciError::CmdFailed(ccode));
        }
        let residue = ev[2] & 0x00FF_FFFF;
        let acked = (data.len() as u32).saturating_sub(residue) as usize;
        Ok(acked)
    }
}

/// xHCI controller handle. Wrapped in `Arc` so callers can hold a
/// reference to the controller WITHOUT holding the outer registry
/// lock across MMIO, command waits, or port enumeration. The
/// previous design (`IrqSafeSpinLock<Option<Xhci>>` + `with_controller`
/// invoked the closure inside the lock) serialized every operation
/// through one mutex AND disabled interrupts on the holder — port
/// reset (~5-10 ms debounce) + enable_slot (250 ms timeout) +
/// address_device (250 ms timeout) all ran with the lock held, so
/// a busy supervisor cycle could pin the lock for multiple seconds
/// and any concurrent caller (status panel, ISR, sibling pump) was
/// blocked. Switching to Arc lets the lock cover only the brief
/// "clone the handle" window; sub-resource serialization happens
/// at the per-resource inner locks the `Xhci` struct already owns
/// (`cmd_enqueue`, `cmd_pcs`, `cmd_events`, `transfer_events`,
/// `er_dequeue`, `er_ccs`).
static CONTROLLER: IrqSafeSpinLock<Option<Arc<Xhci>>> = IrqSafeSpinLock::new(None);

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // The class-match backstop matches *every* device with PCI
    // base class 0x0C (Serial Bus) — that includes SMBus
    // (subclass 0x05, e.g. AMD FCH 1022:790b), CAN, GPIB, IPMI,
    // etc., not just USB host controllers. Reject anything that
    // isn't specifically USB-xHCI here so we don't try to drive
    // a non-USB device's BAR as xHCI MMIO.
    //
    // Exception: the explicit (vendor, device) match arms above
    // bind by ID without consulting class, so QEMU's xhci-pci
    // model (which sometimes reports class=0) still binds.
    // PCI class triple is (class << 16) | (subclass << 8) | prog_if.
    let class = ((device.id.class >> 16) & 0xFF) as u8;
    let subclass = ((device.id.class >> 8) & 0xFF) as u8;
    let prog_if = (device.id.class & 0xFF) as u8;
    let is_xhci_class =
        class == PCI_CLASS_SERIAL_BUS && subclass == PCI_SUBCLASS_USB && prog_if == PCI_PROGIF_XHCI;
    let is_explicit_match = matches!(
        (device.id.vendor, device.id.device),
        (QEMU_XHCI_VENDOR, QEMU_XHCI_DEVICE)
            | (AMD_VENDOR, AMD_PHX_15B9)
            | (AMD_VENDOR, AMD_PHX_15BA)
            | (AMD_VENDOR, AMD_PHX_15C0)
            | (AMD_VENDOR, AMD_PHX_15C1),
    );
    if !is_xhci_class && !is_explicit_match {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority.
    let dev = match unsafe { Xhci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(Arc::new(dev));
    IS_PROBED.store(true, core::sync::atomic::Ordering::Release);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("xhci0"),
        kind: narf_drivers::BoundKind::UsbHost,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::UsbHost.default_domain(),
    });
    // Register against the device PM registry. xHCI suspend stops
    // the controller; resume re-enables it and re-arms interrupts.
    // Real D3 handling for xHCI also needs to save/restore the
    // Operational + Doorbell register windows, which the
    // current shape doesn't do — registered as best-effort.
    narf_power::device_pm::register_device_pm("xhci0", xhci_suspend_handler, xhci_resume_handler);
    Ok(())
}

/// xHCI suspend handler — halts the controller (R/S bit cleared
/// in USBCMD) so it stops fetching from Transfer Rings. The
/// per-endpoint state is left in DRAM; resume re-asserts R/S.
/// On real silicon a fuller path would also disable interrupts
/// and snapshot Operational registers.
fn xhci_suspend_handler() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    // The controller may not be probed (e.g. no xHCI on the box).
    if !is_probed() {
        return Ok(());
    }
    // Halt: clear USBCMD.R/S. Use with_controller to reach the regs.
    let halted = with_controller(|c| {
        // SAFETY: BAR5 mapped, exclusive owner.
        unsafe { c.halt_for_suspend() }
    })
    .unwrap_or(false);
    if halted {
        Ok(())
    } else {
        Err(narf_power::device_pm::DeviceSuspendError::DriverError)
    }
}

/// xHCI resume handler — re-asserts USBCMD.R/S so the controller
/// resumes fetching from Transfer Rings. The supervisor's
/// per-port retry loop catches any devices that may have been
/// re-enumerated by the platform's wake firmware.
fn xhci_resume_handler() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    if !is_probed() {
        return Ok(());
    }
    let resumed = with_controller(|c| {
        // SAFETY: same.
        unsafe { c.run_for_resume() }
    })
    .unwrap_or(false);
    if resumed {
        Ok(())
    } else {
        Err(narf_power::device_pm::DeviceSuspendError::DriverError)
    }
}

pub fn register_pci_driver() {
    // Explicit (vendor, device) matches — highest specificity. The
    // bus picks these over the class-match backstop when both fire.
    let exact: &[(&'static str, u16, u16)] = &[
        ("xhci-qemu", QEMU_XHCI_VENDOR, QEMU_XHCI_DEVICE),
        ("xhci-amd-15b9", AMD_VENDOR, AMD_PHX_15B9),
        ("xhci-amd-15ba", AMD_VENDOR, AMD_PHX_15BA),
        ("xhci-amd-15c0", AMD_VENDOR, AMD_PHX_15C0),
        ("xhci-amd-15c1", AMD_VENDOR, AMD_PHX_15C1),
    ];
    for (name, v, d) in exact.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: v,
                device: d,
            },
            probe,
        });
    }
    // Class-match backstop: class 0x0C (Serial Bus) catches every
    // USB host controller. The probe function checks the prog-if
    // byte against PCI_PROGIF_XHCI before binding so we don't try
    // to drive an EHCI / UHCI / OHCI controller as xHCI. The
    // bus's `MatchKind::Class` only inspects the high byte of the
    // class triple, so finer-grained filtering happens at probe
    // time.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "xhci-class",
        kind: narf_bus::MatchKind::Class {
            class: PCI_CLASS_SERIAL_BUS,
            mask: 0xFF,
        },
        probe,
    });
}

/// Lock-free probe-status flag. Mirrors `CONTROLLER.is_some()` —
/// set once when probe succeeds, never cleared in production
/// (xhci doesn't unbind today). Diagnostics MUST read this rather
/// than locking CONTROLLER, because the USB HID supervisor holds
/// CONTROLLER for tens of ms during port attach on real silicon
/// and IrqSafeSpinLock disables IF on the waiter — a status-panel
/// paint that locks CONTROLLER freezes the entire CPU until the
/// supervisor releases.
pub static IS_PROBED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn is_probed() -> bool {
    IS_PROBED.load(core::sync::atomic::Ordering::Acquire)
}

/// Monotonic counter of Port Status Change Events (TRB Type 34 —
/// xHCI 1.2 §6.4.2.3) the demux has observed. The USB supervisor
/// uses the high watermark to notice "something changed on a root
/// hub port" without polling PORTSC on every iteration. Bumped
/// from `demux_one_event`; consumers compare against a snapshot.
///
/// Pre-fix the demux dropped PSCE on the floor (`_ =>` arm), so a
/// hot-plug attach landing while the supervisor was parked never
/// woke anything — the user had to wait for the next 100 ms pump
/// pause to expire. With the counter in place the supervisor can
/// also `wake_by_ref` the cached waker (see `USB_SUPERVISOR_WAKER`)
/// for an immediate re-poll.
pub static USB_PSCE_EVENTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Optional supervisor waker. The USB supervisor registers its
/// `core::task::Waker` via [`register_supervisor_waker`]; the xHCI
/// ISR / demux calls `wake_by_ref` on it whenever a Port Status
/// Change Event lands. Stored behind an `IrqSafeSpinLock` so the
/// ISR (which preempts the supervisor) can install/observe it
/// without racing.
///
/// Semantics: the slot holds at most one waker. A new
/// `register_supervisor_waker` replaces the previous occupant —
/// matches `core::task::Waker::will_wake` dedup behaviour but
/// without the lookup, since we only ever have one supervisor.
static USB_SUPERVISOR_WAKER: IrqSafeSpinLock<Option<core::task::Waker>> =
    IrqSafeSpinLock::new(None);

/// Install the USB supervisor's waker so the xHCI demux can poke
/// it on a Port Status Change Event. Replaces any previously
/// installed waker. Pass `cx.waker().clone()` from the supervisor's
/// poll path; the slot caches it across yields.
pub fn register_supervisor_waker(w: core::task::Waker) {
    let mut g = USB_SUPERVISOR_WAKER.lock();
    *g = Some(w);
}

/// Internal: wake the supervisor if a waker is registered.
/// Called from the ISR / demux path on PSCE. Drops the lock
/// before invoking `wake_by_ref` to keep IRQ-context work bounded
/// — the waker only flips the per-task awake flag, but doing it
/// outside the lock keeps the lock-hold-time predictable.
fn wake_usb_supervisor() {
    let w = {
        let g = USB_SUPERVISOR_WAKER.lock();
        g.clone()
    };
    if let Some(w) = w {
        w.wake_by_ref();
    }
}

/// Get a cloned `Arc<Xhci>` handle to the bound controller, or
/// `None` if no controller is bound. The registry lock is held
/// ONLY for the Arc clone — never across the caller's work. Use
/// this in preference to [`with_controller`] when the work spans
/// multiple MMIO ops, command-completion waits, or any path that
/// would benefit from releasing the lock between sub-steps.
pub fn controller() -> Option<Arc<Xhci>> {
    CONTROLLER.lock().clone()
}

/// Convenience wrapper: clone the Arc, drop the registry lock,
/// then invoke `f`. Semantically identical to the previous
/// closure-inside-the-lock shape from the caller's perspective,
/// but the outer lock is no longer held during `f` — `f` can
/// take seconds (port reset, command completion) without blocking
/// every other caller / the ISR.
pub fn with_controller<R>(f: impl FnOnce(&Xhci) -> R) -> Option<R> {
    let c = controller()?;
    Some(f(&c))
}

/// xHCI ISR — runs in IRQ context.
///
/// Two responsibilities per xHCI base spec §5.5.2.3.3 +
/// §4.17.5:
/// 1. Acknowledge the level-triggered IRQ at the interrupter
///    by writing 1 to IMAN.IP (the bit is RW1C). Without this,
///    INTx-routed controllers re-assert the line forever and
///    every other CPU also gets the same vector.
/// 2. Drain pending event-ring TRBs so subsequent IRQs see a
///    fresh ring rather than re-firing on stale events. The
///    supervisor pump still inspects device state via
///    `pump_all`, which is what produces user-visible HID
///    events; this ISR just keeps the ring + IRQ-ack hygiene
///    correct.
///
/// Bounded: drains at most 64 events per IRQ to keep handler
/// latency predictable. A storm of events spreads across
/// successive ISR invocations; the IMAN.IP write keeps the
/// IRQ live until the ring is empty (next-tick if we hit the
/// per-IRQ cap).
fn xhci_isr() {
    // Brief Arc clone, then drop the registry lock — the ISR no
    // longer races the supervisor for the outer mutex. Each
    // demux/poll/ack step takes its own per-resource inner lock
    // as needed; that's the right granularity for a shared
    // controller handle.
    let xhci = match controller() {
        Some(x) => x,
        None => return,
    };
    let xhci = &*xhci;
    // Demux up to N events into the per-class queues so any
    // waiter (await_event) sees its event regardless of
    // whether the ISR or the waiter dequeued it from the ring.
    // Pre-fix the ISR called poll_event and dropped the result,
    // racing with await_event for the very Transfer Event the
    // waiter expected — surfaced as CmdTimeout under MSI-X
    // load (audit #11).
    const MAX_DRAIN_PER_IRQ: usize = 64;
    for _ in 0..MAX_DRAIN_PER_IRQ {
        if xhci.demux_one_event().is_none() {
            break;
        }
    }
    // Acknowledge IMAN.IP for interrupter 0. Read-modify-write:
    // preserve IE, write 1 to IP (W1C).
    let ir0 = xhci.rts_off + IR_BASE_OFF;
    // SAFETY: identity-mapped MMIO; xhci stays alive for the
    // duration of the lock guard.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        let cur = xhci.mmio.read32(ir0 + IR_IMAN);
        // Mask to (IE | IP) to W1C the IP bit while keeping IE set.
        xhci.mmio.write32(ir0 + IR_IMAN, cur | IMAN_IP);
    }
}

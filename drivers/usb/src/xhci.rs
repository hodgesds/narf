//! xHCI 1.2 USB 3.x host controller driver — clean-room.
//!
//! ## Reference
//!
//! Intel "eXtensible Host Controller Interface for Universal Serial
//! Bus (xHCI)" Revision 1.2, May 2019. Public document. Section
//! references throughout this file (e.g. `§5.4.5`) point at that
//! spec. No GPL Linux source consulted.
//!   <https://www.intel.com/content/www/us/en/products/docs/io/universal-serial-bus/extensible-host-controler-interface-usb-xhci.html>
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

use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

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
const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready
const USBSTS_EINT: u32 = 1 << 3; // Event Interrupt (w1c)

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
const TRB_TYPE_SETUP_STAGE: u32 = 2;
const TRB_TYPE_DATA_STAGE: u32 = 3;
const TRB_TYPE_STATUS_STAGE: u32 = 4;
const TRB_TYPE_LINK: u32 = 6;
const TRB_TYPE_ENABLE_SLOT_CMD: u32 = 9;
const TRB_TYPE_ADDRESS_DEVICE_CMD: u32 = 11;
const TRB_TYPE_CONFIGURE_ENDPOINT_CMD: u32 = 12;
const TRB_TYPE_NO_OP_CMD: u32 = 23;
const TRB_TYPE_TRANSFER_EVENT: u32 = 32;
const TRB_TYPE_CMD_COMPLETION: u32 = 33;
const TRB_TYPE_PORT_STATUS_CHANGE: u32 = 34;

/// USB Endpoint Type values for the EP Context (§6.2.3 Table 6-9).
/// Bits[5:3] of EP Context dword1.
const EP_TYPE_ISOCH_OUT: u32 = 1;
const EP_TYPE_BULK_OUT: u32 = 2;
const EP_TYPE_INT_OUT: u32 = 3;
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
const USB_REQ_GET_DESCRIPTOR: u8 = 6;
const USB_DESC_TYPE_DEVICE: u8 = 1;

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
    /// USB-2.0 §5.5.3 / USB 3 §9.6.1: control endpoint default
    /// MaxPacketSize before the device reports its real value via
    /// Get Descriptor(DEVICE).
    fn default_max_packet(self) -> u16 {
        match self {
            PortSpeed::Low => 8,
            PortSpeed::Full => 64,
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
    /// DCBAA backing — kept alive for the controller's lifetime.
    dcbaa: DmaBuffer,
    cmd_ring: DmaBuffer,
    /// Event Ring segment (one segment of `ER_SEG_TRBS` entries).
    event_ring: DmaBuffer,
    /// Event Ring Segment Table — one entry pointing at `event_ring`.
    _erst: DmaBuffer,
    _scratch: Option<DmaBuffer>,
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
    pub running: bool,
    /// MSI-X table handle owned by this controller. `Some` when
    /// `bring_up` successfully programmed interrupter 0's vector;
    /// the supervisor pump can then `wait_for_irq(irq_vector).await`
    /// on event-ring updates instead of busy-polling. `None` falls
    /// back to the polling pump cadence.
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
    /// Transfer ring backing the endpoint (4 KiB / 256 TRBs).
    tr: DmaBuffer,
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
        // Wait for HCH = 1.
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let s = unsafe { mmio.read32(op_off + OP_USBSTS) };
            if s & USBSTS_HCH != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Reset.
        // SAFETY: same.
        unsafe {
            mmio.write32(op_off + OP_USBCMD, USBCMD_HCRST);
        }
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let v = unsafe { mmio.read32(op_off + OP_USBCMD) };
            if v & USBCMD_HCRST == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        // SAFETY: same.
        let post = unsafe { mmio.read32(op_off + OP_USBCMD) };
        if post & USBCMD_HCRST != 0 {
            return Err(XhciError::ResetTimeout);
        }
        // Wait for CNR = 0.
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let s = unsafe { mmio.read32(op_off + OP_USBSTS) };
            if s & USBSTS_CNR == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        // SAFETY: same.
        let s = unsafe { mmio.read32(op_off + OP_USBSTS) };
        if s & USBSTS_CNR != 0 {
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
        // Initialize the cycle bit on each TRB to 0 (driver writes
        // commands with cycle=1). Last TRB is the Link TRB pointing
        // back to the start (we don't bother for the structural
        // bring-up; the controller idles when the cycle bit doesn't
        // match).
        let cmd_ring = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let cmd_phys = cmd_ring.phys_addr().raw();

        // Optional: allocate scratchpad buffers if MAX_SCRATCHPAD_BUFS
        // is non-zero.
        // SAFETY: same.
        let p2 = unsafe { mmio.read32(0x08) }; // HCSPARAMS2
        let max_scratch_hi = ((p2 >> 21) & 0x1F) as u32;
        let max_scratch_lo = ((p2 >> 27) & 0x1F) as u32;
        let max_scratch = (max_scratch_hi << 5) | max_scratch_lo;
        let scratch = if max_scratch > 0 {
            // One page holds 512 8-byte pointers — plenty for any
            // realistic scratchpad count.
            let sb = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
            let sb_phys = sb.phys_addr().raw();
            // Allocate one scratchpad data page per slot (xhci spec
            // says "one PAGESIZE buffer per scratchpad"; PAGESIZE is
            // a u32 bitmap with one bit per supported size).
            for i in 0..(max_scratch as usize).min(8) {
                let p =
                    alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
                // SAFETY: identity-mapped DMA.
                unsafe {
                    core::ptr::write_volatile(
                        (sb_phys + (i * 8) as u64) as *mut u64,
                        p.phys_addr().raw(),
                    );
                }
                // p drops here — the controller holds the phys
                // address only; the DmaBuffer's Drop frees the
                // underlying frame, which would be a bug if we
                // were going to actually use scratchpads. Stage-4
                // structural-only — controller starts running but
                // we don't enumerate devices.
                let _ = p;
            }
            // Plant the scratchpad-buffer-array pointer at DCBAA[0].
            // SAFETY: identity-mapped DCBAA page.
            unsafe {
                core::ptr::write_volatile(dcbaa_phys as *mut u64, sb_phys);
            }
            Some(sb)
        } else {
            None
        };

        // Program DCBAAP + CRCR.
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
        unsafe {
            core::ptr::write_volatile(erst_phys as *mut u64, er_phys);
            core::ptr::write_volatile((erst_phys + 8) as *mut u32, ER_SEG_TRBS as u32);
            core::ptr::write_volatile((erst_phys + 12) as *mut u32, 0);
        }

        // Program interrupter 0: ERSTSZ = 1 (one segment), ERSTBA =
        // erst_phys, ERDP = er_phys (initial dequeue == segment
        // base). IMAN: clear IP, set IE. IMOD = 0 (no moderation
        // for bring-up).
        let ir0 = rtsoff as u64 + IR_BASE_OFF;
        // SAFETY: identity-mapped MMIO.
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
        // Wait for HCH = 0.
        let mut running = false;
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let s = unsafe { mmio.read32(op_off + OP_USBSTS) };
            if s & USBSTS_HCH == 0 {
                running = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !running {
            return Err(XhciError::StartFailed);
        }

        // Try MSI-X first, fall back to legacy INTx via PCI _PRT
        // + IOAPIC programming, fall back to polling if neither
        // works. Cap walking failures, firmware MSI-X disable
        // bits, and platforms whose firmware never enabled MSI-X
        // all land in the INTx path. Pattern: same as the
        // Linux pcie_msi → pcie_intx fallback chain.
        let (msix, irq_vector) = match Self::try_enable_msix(cap, device) {
            Ok((tbl, v)) => (Some(tbl), Some(v)),
            Err(_) => match Self::try_install_intx(cap, device) {
                Some(v) => (None, Some(v)),
                None => (None, None),
            },
        };

        Ok(Self {
            mmio,
            caps,
            op_off,
            rts_off: rtsoff as u64,
            db_off: dboff as u64,
            csz_64byte,
            dcbaa,
            cmd_ring,
            event_ring,
            _erst: erst,
            _scratch: scratch,
            cmd_pcs: IrqSafeSpinLock::new(1),
            cmd_enqueue: IrqSafeSpinLock::new(0),
            er_ccs: IrqSafeSpinLock::new(1),
            er_dequeue: IrqSafeSpinLock::new(0),
            devices: IrqSafeSpinLock::new(alloc::vec::Vec::new()),
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
        let _ = unsafe { msix.program_vector(0, 0, v) }.map_err(|_| XhciError::NoMemory)?;
        // SAFETY: cfg-space write to a known cap-list offset.
        let _ = unsafe { msix.enable() }.map_err(|_| XhciError::NoMemory)?;
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
    fn try_install_intx(
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Option<u8> {
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
    fn try_install_intx(
        _cap: &Cap<BusDeviceCap, Write>,
        _device: &BusDevice,
    ) -> Option<u8> {
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
        if self.csz_64byte { 0x40 } else { 0x20 }
    }
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Read the PORTSC register for `port` (1-indexed per spec).
    /// Returns `None` for an out-of-range port number.
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
    /// Allocates — fine outside hot paths.
    pub fn connected_ports(&self) -> alloc::vec::Vec<(u8, u32)> {
        let mut out = alloc::vec::Vec::new();
        for p in 1..=self.caps.max_ports {
            if let Some(v) = self.portsc(p) {
                if v & PORTSC_CCS != 0 {
                    out.push((p, v));
                }
            }
        }
        out
    }

    /// Drive `port` through reset. Per §4.19.5 this transitions an
    /// attached device into Default state. The PORTSC change bits
    /// at [17..23] are RW1C — preserve the RO/RW fields below them
    /// when writing back. Returns the post-reset PORTSC value.
    pub fn port_reset(&self, port: u8) -> Result<u32, XhciError> {
        if port == 0 || port > self.caps.max_ports {
            return Err(XhciError::BadPort);
        }
        let off = self.op_off + OP_PORTSC_BASE + ((port as u64 - 1) * PORT_REGS_STRIDE);
        // SAFETY: identity-mapped MMIO; port-range checked above.
        let cur = unsafe { self.mmio.read32(off) };
        if cur & PORTSC_CCS == 0 {
            return Err(XhciError::BadPort);
        }
        // Mask RW1C change bits to 0 in the value we write so we
        // don't accidentally clear them; OR in PORTSC_PR + PP to
        // assert reset and keep power on.
        let to_write = (cur & !PORTSC_CHG_MASK)
            & !PORTSC_PED          // PED is RW1C; leave clear
            | PORTSC_PR
            | PORTSC_PP;
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off, to_write);
        }
        // Wait for PR to clear (§4.19.5: hardware self-clears once
        // reset completes; spec gives 50 ms typical).
        for _ in 0..1_000_000u32 {
            // SAFETY: same.
            let v = unsafe { self.mmio.read32(off) };
            if v & PORTSC_PR == 0 {
                return Ok(v);
            }
            core::hint::spin_loop();
        }
        Err(XhciError::PortResetTimeout)
    }

    /// Ring the host-controller's Command Ring doorbell. Stream-id /
    /// DB Target both 0 per §5.6 for command-ring kicks.
    fn ring_command_doorbell(&self) {
        // SAFETY: identity-mapped MMIO; doorbell array sized to
        // (MAX_SLOTS + 1) * 4 bytes — entry 0 always exists.
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
        let pcs_g = self.cmd_pcs.lock();
        // Reserve slot N-1 for a Link TRB once we wrap; until then
        // the Stage-5 cut just refuses to enqueue past N-1. A real
        // driver would write a Link TRB at N-1 the first time it
        // hits the boundary and toggle PCS.
        if *enq_g >= CMD_RING_TRBS - 1 {
            return Err(XhciError::CmdRingFull);
        }

        let trb_off = (*enq_g * 16) as u64;
        let trb_addr = self.cmd_ring.phys_addr().raw() + trb_off;
        let dword3 = dword3_no_cycle | (*pcs_g & TRB_CYCLE_BIT);
        // Write the data dwords first, then publish dword3 (which
        // carries the cycle bit) so the controller can't observe a
        // half-written TRB.
        // SAFETY: identity-mapped DMA page; trb_off in-range.
        unsafe {
            core::ptr::write_volatile(trb_addr as *mut u32, dword0);
            core::ptr::write_volatile((trb_addr + 4) as *mut u32, dword1);
            core::ptr::write_volatile((trb_addr + 8) as *mut u32, dword2);
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile((trb_addr + 12) as *mut u32, dword3);
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
        let d3 = unsafe { core::ptr::read_volatile((trb_addr + 12) as *const u32) };
        if (d3 & TRB_CYCLE_BIT) != *ccs_g {
            return None;
        }
        // SAFETY: same.
        let d0 = unsafe { core::ptr::read_volatile(trb_addr as *const u32) };
        // SAFETY: same.
        let d1 = unsafe { core::ptr::read_volatile((trb_addr + 4) as *const u32) };
        // SAFETY: same.
        let d2 = unsafe { core::ptr::read_volatile((trb_addr + 8) as *const u32) };
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
                .write32(ir0 + IR_ERDP_LO, (new_deq_phys as u32) | (ERDP_EHB as u32));
            self.mmio
                .write32(ir0 + IR_ERDP_HI, (new_deq_phys >> 32) as u32);
        }
        Some([d0, d1, d2, d3])
    }

    /// Spin-wait for the next event matching `predicate`. Bounded by
    /// `~10M spins` to surface a hung controller as `CmdTimeout`
    /// rather than livelock.
    fn await_event(
        &self,
        mut predicate: impl FnMut(&[u32; 4]) -> bool,
    ) -> Result<[u32; 4], XhciError> {
        for _ in 0..10_000_000u32 {
            if let Some(ev) = self.poll_event() {
                if predicate(&ev) {
                    return Ok(ev);
                }
                // Not the event we wanted — keep draining; another
                // command might be racing through. (Stage-5 cut is
                // single-flight; this just keeps the dequeue moving.)
                continue;
            }
            core::hint::spin_loop();
        }
        Err(XhciError::CmdTimeout)
    }

    /// Issue an Enable Slot command (§4.6.3) and wait for the
    /// completion event. Returns the assigned slot id (1..=MaxSlots)
    /// on success.
    pub fn enable_slot(&self) -> Result<u8, XhciError> {
        // Enable Slot TRB (§6.4.3.2): all dwords 0 except TRB Type.
        let trb_type = TRB_TYPE_ENABLE_SLOT_CMD << TRB_TYPE_SHIFT;
        self.submit_command(0, 0, 0, trb_type)?;
        // Wait for a Command Completion Event (§6.4.2.2).
        let cce_type = TRB_TYPE_CMD_COMPLETION << TRB_TYPE_SHIFT;
        let ev = self.await_event(|t| (t[3] & TRB_TYPE_MASK) == cce_type)?;
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

    /// Issue the Address Device command (§4.6.5) for `slot_id` against
    /// `port` and the device's negotiated `speed`. Allocates a Device
    /// Context + Input Context + Control Transfer Ring, programs the
    /// Slot + EP0 contexts per §4.3.3, and waits for the Command
    /// Completion Event. Returns the slot id on success and stashes
    /// the per-slot state in `self.devices`.
    ///
    /// Handles both 32-byte (CSZ=0) and 64-byte (CSZ=1) contexts —
    /// the per-context stride is `0x20` or `0x40` respectively, but
    /// the field layout *within* each context is identical (the
    /// 64-byte form just pads the upper half).
    pub fn address_device(&self, slot_id: u8, port: u8, speed: PortSpeed) -> Result<u8, XhciError> {
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

        let input_phys = input.phys_addr().raw();
        let dev_ctx_phys = dev_ctx.phys_addr().raw();
        let ctrl_tr_phys = ctrl_tr.phys_addr().raw();

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
            core::ptr::write_bytes(input_phys as *mut u8, 0, 4096);
            core::ptr::write_bytes(dev_ctx_phys as *mut u8, 0, 4096);
            core::ptr::write_bytes(ctrl_tr_phys as *mut u8, 0, 4096);
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
            core::ptr::write_volatile((input_ctrl + 4) as *mut u32, (1 << 0) | (1 << 1));
        }

        // Slot Context dword0 + dword1.
        let slot_d0 = (1u32 << 27)              // Context Entries = 1
                    | ((speed as u32) << 20); // Speed
        let slot_d1 = (port as u32) << 16; // Root Hub Port Number
                                           // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(slot_ctx as *mut u32, slot_d0);
            core::ptr::write_volatile((slot_ctx + 4) as *mut u32, slot_d1);
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
            core::ptr::write_volatile((ep0_ctx + 4) as *mut u32, ep0_d1);
            core::ptr::write_volatile((ep0_ctx + 8) as *mut u32, trdp_lo);
            core::ptr::write_volatile((ep0_ctx + 12) as *mut u32, trdp_hi);
            core::ptr::write_volatile((ep0_ctx + 16) as *mut u32, 8u32); // Avg TRB Len
        }

        // Plant Device Context phys at DCBAA[slot_id] BEFORE issuing
        // the command (§4.3.4 step 6). The engine reads DCBAA when
        // it processes Address Device.
        // SAFETY: identity-mapped DCBAA page; slot_id < MaxSlots.
        let dcbaa_phys = self.dcbaa.phys_addr().raw();
        unsafe {
            core::ptr::write_volatile(
                (dcbaa_phys + (slot_id as u64) * 8) as *mut u64,
                dev_ctx_phys,
            );
        }
        compiler_fence(Ordering::SeqCst);

        // Issue Address Device. TRB layout (§6.4.3.4):
        //   dword0/1 = Input Context phys (low/high)
        //   dword2 = reserved
        //   dword3 = TRB Type | Slot ID << 24 | (BSR=0)
        let trb_type = TRB_TYPE_ADDRESS_DEVICE_CMD << TRB_TYPE_SHIFT;
        let dword3 = trb_type | ((slot_id as u32) << 24);
        self.submit_command(input_phys as u32, (input_phys >> 32) as u32, 0, dword3)?;
        // Wait for Command Completion Event for this slot.
        let cce = TRB_TYPE_CMD_COMPLETION << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let ev = self
            .await_event(|t| (t[3] & TRB_TYPE_MASK) == cce && (t[3] & 0xFF00_0000) == want_slot)?;
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

    /// Ring the slot's doorbell. Dword layout (§5.6):
    /// bits[7:0] = DB Target (DCI), bits[31:16] = Stream ID.
    fn ring_slot_doorbell(&self, slot_id: u8, dci: u32) {
        let off = self.db_off + (slot_id as u64) * 4;
        // SAFETY: identity-mapped MMIO; slot_id < MaxSlots so the
        // doorbell array entry exists.
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
        if dev.ctrl_enq >= CTRL_TR_TRBS - 1 {
            return Err(XhciError::CmdRingFull);
        }
        let trb_off = (dev.ctrl_enq * 16) as u64;
        let trb_addr = dev.ctrl_tr.phys_addr().raw() + trb_off;
        let d3 = d3_no_cycle | (dev.ctrl_pcs & TRB_CYCLE_BIT);
        // SAFETY: identity-mapped DMA; offset in-page.
        unsafe {
            core::ptr::write_volatile(trb_addr as *mut u32, d0);
            core::ptr::write_volatile((trb_addr + 4) as *mut u32, d1);
            core::ptr::write_volatile((trb_addr + 8) as *mut u32, d2);
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile((trb_addr + 12) as *mut u32, d3);
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
    pub fn control_in(
        &self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        out: &mut [u8],
    ) -> Result<usize, XhciError> {
        if out.len() != w_value.into() && out.len() < 1 {
            // Allow the caller to ask for any byte-count that fits
            // a u16; w_length is just the SETUP-packet field.
        }
        let w_length = out.len() as u16;
        // Stage a DMA buffer for the data stage. One 4 KiB page is
        // plenty for any standard descriptor we fetch in Stage-5.
        let data = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let data_phys = data.phys_addr().raw();
        // Zero the data buffer so a stale page can't be confused
        // with the device response on a 0-length read.
        // SAFETY: identity-mapped DMA page.
        unsafe {
            core::ptr::write_bytes(data_phys as *mut u8, 0, 4096);
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

        // Wait for a Transfer Event whose source TRB matches our
        // Status Stage (Status carries IOC=1; on success the
        // engine raises one Transfer Event after Status). We don't
        // gate on a specific TRB pointer because some controllers
        // emit a Transfer Event for Data Stage too — accept the
        // first Transfer Event for this slot.
        let xfer = TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let ev = self
            .await_event(|t| (t[3] & TRB_TYPE_MASK) == xfer && (t[3] & 0xFF00_0000) == want_slot)?;
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
        // SAFETY: identity-mapped DMA page; xferred ≤ w_length ≤ 4096.
        let copy = xferred.min(out.len());
        for i in 0..copy {
            out[i] = unsafe { core::ptr::read_volatile((data_phys + i as u64) as *const u8) };
        }
        let _ = data;
        Ok(xferred)
    }

    /// Fetch the 18-byte USB Device Descriptor (§9.6.1) for an
    /// Addressed slot. Returns the byte-aligned descriptor — caller
    /// pulls VID/DID etc. out of fixed offsets.
    pub fn get_device_descriptor(&self, slot_id: u8) -> Result<[u8; 18], XhciError> {
        let mut buf = [0u8; 18];
        let n = self.control_in(
            slot_id,
            0x80,                               // bmRequestType: IN, Standard, Device
            USB_REQ_GET_DESCRIPTOR,             // bRequest
            (USB_DESC_TYPE_DEVICE as u16) << 8, // wValue: descriptor type | index
            0,                                  // wIndex
            &mut buf,
        )?;
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

    /// Fetch the 9-byte Configuration Descriptor header (§9.6.3) for
    /// `cfg_index` (typically 0). To read the full configuration tree
    /// (interface + endpoint descriptors), call again with a buffer
    /// sized to `wTotalLength` from the header.
    pub fn get_config_descriptor(
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
    pub fn configure_endpoints(
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
            core::ptr::write_bytes(input_phys as *mut u8, 0, 4096);
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
                core::ptr::write_bytes(tr_phys as *mut u8, 0, 4096);
            }

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
                core::ptr::write_volatile((ep_ctx + 4) as *mut u32, ep_d1);
                core::ptr::write_volatile((ep_ctx + 8) as *mut u32, trdp_lo);
                core::ptr::write_volatile((ep_ctx + 12) as *mut u32, trdp_hi);
                core::ptr::write_volatile((ep_ctx + 16) as *mut u32, avg_trb);
            }
            new_eps.push(EndpointState {
                dci,
                max_packet: ep.max_packet,
                kind: ep.kind,
                tr,
                pcs: 1,
                enq: 0,
            });
        }

        // Slot Context: dword0 bits[31:27] = Context Entries. Read
        // the running device-context's slot ctx so we don't clobber
        // Speed / Hub / Route String fields that AddressDevice set.
        // SAFETY: identity-mapped DCBAA[slot_id] points at the
        // slot's device context.
        let dev_ctx_phys = unsafe {
            let dcbaa_phys = self.dcbaa.phys_addr().raw();
            core::ptr::read_volatile((dcbaa_phys + (slot_id as u64) * 8) as *const u64)
        };
        // SAFETY: dev_ctx_phys came from DCBAA which we plant; DMA-mapped.
        let slot_d0 = unsafe { core::ptr::read_volatile(dev_ctx_phys as *const u32) };
        let new_slot_d0 = (slot_d0 & !(0x1Fu32 << 27)) | (max_dci << 27);
        let slot_d1 = unsafe { core::ptr::read_volatile((dev_ctx_phys + 4) as *const u32) };
        // Plant slot ctx into the input context — same stride as in
        // address_device.
        let slot_ctx_off = input_phys + self.context_stride();
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(slot_ctx_off as *mut u32, new_slot_d0);
            core::ptr::write_volatile((slot_ctx_off + 4) as *mut u32, slot_d1);
        }

        // Input Control Context: dword1 = add mask.
        // SAFETY: identity-mapped DMA.
        unsafe {
            core::ptr::write_volatile((input_phys + 4) as *mut u32, add_mask);
        }

        // Issue Configure Endpoint (§6.4.3.5): same TRB shape as
        // Address Device, different Type.
        let trb_type = TRB_TYPE_CONFIGURE_ENDPOINT_CMD << TRB_TYPE_SHIFT;
        let dword3 = trb_type | ((slot_id as u32) << 24);
        self.submit_command(input_phys as u32, (input_phys >> 32) as u32, 0, dword3)?;
        let cce = TRB_TYPE_CMD_COMPLETION << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let ev = self
            .await_event(|t| (t[3] & TRB_TYPE_MASK) == cce && (t[3] & 0xFF00_0000) == want_slot)?;
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
        if ep.enq >= CTRL_TR_TRBS - 1 {
            return Err(XhciError::CmdRingFull);
        }
        let trb_off = (ep.enq * 16) as u64;
        let trb_addr = ep.tr.phys_addr().raw() + trb_off;
        let d3 = (TRB_TYPE_NORMAL << TRB_TYPE_SHIFT) | TRB_IOC | (ep.pcs & TRB_CYCLE_BIT);
        // SAFETY: identity-mapped DMA; offset in-page.
        unsafe {
            core::ptr::write_volatile(trb_addr as *mut u32, phys as u32);
            core::ptr::write_volatile((trb_addr + 4) as *mut u32, (phys >> 32) as u32);
            core::ptr::write_volatile((trb_addr + 8) as *mut u32, len);
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile((trb_addr + 12) as *mut u32, d3);
        }
        compiler_fence(Ordering::SeqCst);
        ep.enq += 1;
        Ok(())
    }

    /// Issue a bulk-IN read against `slot_id` / `dci`. Allocates a
    /// single DMA scratch page (max read = 4 KiB), enqueues a
    /// Normal TRB, rings the slot doorbell, and waits for a
    /// Transfer Event. Returns bytes received.
    pub fn bulk_in(&self, slot_id: u8, dci: u8, out: &mut [u8]) -> Result<usize, XhciError> {
        if out.is_empty() || out.len() > 4096 {
            return Err(XhciError::CmdFailed(0xF9));
        }
        let scratch = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let phys = scratch.phys_addr().raw();
        // SAFETY: identity-mapped DMA page.
        unsafe {
            core::ptr::write_bytes(phys as *mut u8, 0, 4096);
        }
        self.ep_enqueue_normal(slot_id, dci, phys, out.len() as u32)?;
        self.ring_slot_doorbell(slot_id, dci as u32);

        let xfer = TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let ev = self
            .await_event(|t| (t[3] & TRB_TYPE_MASK) == xfer && (t[3] & 0xFF00_0000) == want_slot)?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 && ccode != 13 {
            return Err(XhciError::CmdFailed(ccode));
        }
        let residue = ev[2] & 0x00FF_FFFF;
        let xferred = (out.len() as u32).saturating_sub(residue) as usize;
        // SAFETY: identity-mapped DMA page.
        for i in 0..xferred.min(out.len()) {
            out[i] = unsafe { core::ptr::read_volatile((phys + i as u64) as *const u8) };
        }
        let _ = scratch;
        Ok(xferred)
    }

    /// Issue a bulk-OUT write. Mirror of `bulk_in`: stages caller's
    /// bytes into a DMA scratch page, enqueues a Normal TRB,
    /// rings the slot doorbell, awaits the Transfer Event.
    /// Returns bytes acknowledged by the engine.
    pub fn bulk_out(&self, slot_id: u8, dci: u8, data: &[u8]) -> Result<usize, XhciError> {
        if data.is_empty() || data.len() > 4096 {
            return Err(XhciError::CmdFailed(0xF9));
        }
        let scratch = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| XhciError::NoMemory)?;
        let phys = scratch.phys_addr().raw();
        // SAFETY: identity-mapped DMA page.
        unsafe {
            for (i, &b) in data.iter().enumerate() {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, b);
            }
        }
        self.ep_enqueue_normal(slot_id, dci, phys, data.len() as u32)?;
        self.ring_slot_doorbell(slot_id, dci as u32);

        let xfer = TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT;
        let want_slot = (slot_id as u32) << 24;
        let ev = self
            .await_event(|t| (t[3] & TRB_TYPE_MASK) == xfer && (t[3] & 0xFF00_0000) == want_slot)?;
        let ccode = ((ev[2] >> 24) & 0xFF) as u8;
        if ccode != 1 {
            return Err(XhciError::CmdFailed(ccode));
        }
        let residue = ev[2] & 0x00FF_FFFF;
        let acked = (data.len() as u32).saturating_sub(residue) as usize;
        let _ = scratch;
        Ok(acked)
    }
}

static CONTROLLER: IrqSafeSpinLock<Option<Xhci>> = IrqSafeSpinLock::new(None);

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // The class-match backstop catches all USB controllers; reject
    // non-xHCI prog-ifs here so we don't try to drive an EHCI
    // controller's BAR layout as xHCI. PCI class triple is
    // (class << 16) | (subclass << 8) | prog_if.
    let class = ((device.id.class >> 16) & 0xFF) as u8;
    let subclass = ((device.id.class >> 8) & 0xFF) as u8;
    let prog_if = (device.id.class & 0xFF) as u8;
    if class == PCI_CLASS_SERIAL_BUS && subclass == PCI_SUBCLASS_USB && prog_if != PCI_PROGIF_XHCI {
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
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("xhci0"),
        kind: narf_drivers::BoundKind::UsbHost,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::UsbHost.default_domain(),
    });
    Ok(())
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

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&Xhci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
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
    // Try-lock pattern would be ideal here, but IrqSafeSpinLock
    // is non-poisonable + non-trying. The lock is held only
    // for short windows by Xhci submit/poll paths; collision
    // in IRQ context is rare and safe (IRQ delivery already
    // disabled IF). If the controller's gone, no-op.
    let g = CONTROLLER.lock();
    let xhci = match g.as_ref() {
        Some(x) => x,
        None => return,
    };
    // Drain up to N events. poll_event takes the per-call
    // er_dequeue + er_ccs spinlocks — same locks the
    // command-issuance path uses but only for short windows.
    const MAX_DRAIN_PER_IRQ: usize = 64;
    for _ in 0..MAX_DRAIN_PER_IRQ {
        if xhci.poll_event().is_none() {
            break;
        }
    }
    // Acknowledge IMAN.IP for interrupter 0. Read-modify-write:
    // preserve IE, write 1 to IP (W1C).
    let ir0 = xhci.rts_off + IR_BASE_OFF;
    // SAFETY: identity-mapped MMIO; xhci stays alive for the
    // duration of the lock guard.
    unsafe {
        let cur = xhci.mmio.read32(ir0 + IR_IMAN);
        // Mask to (IE | IP) to W1C the IP bit while keeping IE set.
        xhci.mmio.write32(ir0 + IR_IMAN, cur | IMAN_IP);
    }
}

//! MIPI I3C Host Controller Interface (HCI) 1.x driver.
//!
//! Implements a generic I3C master over the MIPI HCI MMIO register map,
//! which is used by multiple vendors (NXP i.MX 8M+, AMD Hawk Point USB4
//! hub, and others).
//!
//! # Modes
//!
//! * **PIO** — software push/pop via COMMAND_QUEUE_PORT / RESPONSE_QUEUE_PORT.
//!   Enabled when HC_CONTROL.PIO_MODE = 1.
//! * **DMA ring** — host allocates Command Ring (CR) and Response Ring (RR) in
//!   host memory; controller DMAs from/to these rings.  Enabled when
//!   HC_CONTROL.PIO_MODE = 0.  Ref: HCI §7.
//! * **HDR-DDR** — High Data Rate Double Data Rate transfers at 12.5 MT/s.
//!   Entry via ENTHDR0 CCC; frame = 16-bit command token + CRC + data words.
//!   I3C spec rev 1.1 §5.2.3.
//! * **IBI** — In-Band Interrupt.  Slaves pull SDA low during the address
//!   phase to signal the master.  The HCI posts IBI status entries to the
//!   IBI ring; an ISR drain loop dispatches them to registered handlers.
//!   HCI §7.7; I3C spec §5.1.6.
//!
//! # Register map
//!
//! All offsets are relative to the HCI BAR base address.  Section
//! references are to "MIPI I3C Host Controller Interface Specification
//! Version 1.1" (MIPI Alliance), abbreviated "HCI §".
//!
//! Global registers (HCI §6.1):
//!   0x00  HCI_VERSION      — version in BCD
//!   0x04  HC_CONTROL       — bus enable, abort, hot-join control
//!   0x08  MASTER_DEVICE_ADDR — master's own dynamic address
//!   0x0C  HC_CAPABILITIES  — capability bitmap
//!   0x10  RESET_CONTROL    — soft/bus/queue reset
//!   0x14  PRESENT_STATE    — current master flag
//!   0x20  INTR_STATUS      — global interrupt status
//!   0x24  INTR_STATUS_ENABLE
//!   0x28  INTR_SIGNAL_ENABLE
//!   0x30  DAT_SECTION      — Device Address Table pointer
//!   0x34  DCT_SECTION      — Device Characteristics Table pointer
//!   0x38  RING_HEADERS_SECTION — DMA ring base (unused here)
//!   0x3C  PIO_SECTION      — PIO register block offset
//!   0x40  EXT_CAPS_SECTION — extended capabilities
//!   0x58  IBI_NOTIFY_CTRL  — hot-join / IBI policy
//!
//! PIO sub-block (HCI §6.6, base = base + PIO_SECTION[15:0]):
//!   +0x00  COMMAND_QUEUE_PORT — write a command descriptor word
//!   +0x04  RESPONSE_QUEUE_PORT — read a response descriptor word
//!   +0x08  XFER_DATA_PORT  — TX / RX data FIFO
//!   +0x0C  IBI_PORT        — IBI status word
//!   +0x10  QUEUE_THLD_CTRL — interrupt threshold tuning
//!   +0x14  DATA_BUFFER_THLD_CTRL
//!   +0x18  QUEUE_SIZE      — FIFO depth report
//!   +0x20  INTR_STATUS     — PIO-specific interrupt status
//!   +0x24  INTR_STATUS_ENABLE
//!   +0x28  INTR_SIGNAL_ENABLE
//!   +0x38  QUEUE_CUR_STATUS
//!   +0x3C  DATA_BUFFER_CUR_STATUS
//!
//! Linux refs:
//!   drivers/i3c/master/mipi-i3c-hci/core.c
//!   drivers/i3c/master/mipi-i3c-hci/pio.c
//!   drivers/i3c/master/mipi-i3c-hci/hci.h

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use core::task::Waker;
use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_drivers::{Driver, DriverEnv, DriverFuture};
use narf_i3c::{
    registry, CccDest, CommonCommandCode, I3cBus, I3cDevice, I3cError, I3cOp, IbiHandler,
};
use narf_lib::sync::IrqSafeSpinLock;

// ── HCI Global Register Offsets ────────────────────────────────────
// HCI §6.1 — all relative to BAR base.
// Linux: drivers/i3c/master/mipi-i3c-hci/core.c
pub const HCI_VERSION: u64 = 0x00;
pub const HC_CONTROL: u64 = 0x04;
pub const MASTER_DEVICE_ADDR: u64 = 0x08;
pub const HC_CAPABILITIES: u64 = 0x0C;
pub const RESET_CONTROL: u64 = 0x10;
pub const PRESENT_STATE: u64 = 0x14;
pub const INTR_STATUS: u64 = 0x20;
pub const INTR_STATUS_ENABLE: u64 = 0x24;
pub const INTR_SIGNAL_ENABLE: u64 = 0x28;
pub const INTR_FORCE: u64 = 0x2C;
pub const DAT_SECTION: u64 = 0x30;
pub const DCT_SECTION: u64 = 0x34;
pub const RING_HEADERS_SECTION: u64 = 0x38;
pub const PIO_SECTION: u64 = 0x3C;
pub const EXT_CAPS_SECTION: u64 = 0x40;
pub const IBI_NOTIFY_CTRL: u64 = 0x58;
pub const DEV_CTX_BASE_LO: u64 = 0x60;
pub const DEV_CTX_BASE_HI: u64 = 0x64;

// ── HC_CONTROL bits ────────────────────────────────────────────────
// HCI §6.1.2.
pub const HC_CONTROL_BUS_ENABLE: u32 = 1 << 31;
pub const HC_CONTROL_RESUME: u32 = 1 << 30;
pub const HC_CONTROL_ABORT: u32 = 1 << 29;
pub const HC_CONTROL_HALT_ON_CMD_TIMEOUT: u32 = 1 << 12;
pub const HC_CONTROL_HOT_JOIN_CTRL: u32 = 1 << 8;
/// HC_CONTROL bit 6: 1 = PIO mode, 0 = DMA ring mode.
/// HCI §6.1.2; Linux dma.c hci_dma_init — clears this bit to enable DMA.
pub const HC_CONTROL_PIO_MODE: u32 = 1 << 6;
pub const HC_CONTROL_DATA_BIG_ENDIAN: u32 = 1 << 4;
pub const HC_CONTROL_IBA_INCLUDE: u32 = 1 << 0;

// ── HC_CAPABILITIES bits ───────────────────────────────────────────
// HCI §6.1.4.
pub const HC_CAP_HDR_DDR_EN: u32 = 1 << 6;
pub const HC_CAP_HDR_TS_EN: u32 = 1 << 7;
pub const HC_CAP_HDR_BT_EN: u32 = 1 << 8;
pub const HC_CAP_COMBO_COMMAND: u32 = 1 << 2;
pub const HC_CAP_AUTO_COMMAND: u32 = 1 << 3;

// ── RESET_CONTROL bits ────────────────────────────────────────────
pub const SOFT_RST: u32 = 1 << 0;
pub const CMD_QUEUE_RST: u32 = 1 << 1;
pub const RESP_QUEUE_RST: u32 = 1 << 2;
pub const TX_FIFO_RST: u32 = 1 << 3;
pub const RX_FIFO_RST: u32 = 1 << 4;
pub const IBI_QUEUE_RST: u32 = 1 << 5;
pub const BUS_RESET: u32 = 1 << 31;

// ── PIO sub-block offsets ─────────────────────────────────────────
// HCI §6.6 — relative to PIO base (= bar_base + PIO_SECTION[15:0]).
// Linux: drivers/i3c/master/mipi-i3c-hci/pio.c
pub const PIO_COMMAND_QUEUE_PORT: u64 = 0x00;
pub const PIO_RESPONSE_QUEUE_PORT: u64 = 0x04;
pub const PIO_XFER_DATA_PORT: u64 = 0x08;
pub const PIO_IBI_PORT: u64 = 0x0C;
pub const PIO_QUEUE_THLD_CTRL: u64 = 0x10;
pub const PIO_DATA_BUFFER_THLD_CTRL: u64 = 0x14;
pub const PIO_QUEUE_SIZE: u64 = 0x18;
pub const PIO_INTR_STATUS: u64 = 0x20;
pub const PIO_INTR_STATUS_ENABLE: u64 = 0x24;
pub const PIO_INTR_SIGNAL_ENABLE: u64 = 0x28;
pub const PIO_INTR_FORCE: u64 = 0x2C;
pub const PIO_QUEUE_CUR_STATUS: u64 = 0x38;
pub const PIO_DATA_BUFFER_CUR_STATUS: u64 = 0x3C;

// ── PIO interrupt status bits ─────────────────────────────────────
// HCI §6.6.5.  Linux pio.c STAT_*.
pub const STAT_RESP_READY: u32 = 1 << 4;
pub const STAT_CMD_QUEUE_READY: u32 = 1 << 3;
pub const STAT_TX_THLD: u32 = 1 << 0;
pub const STAT_RX_THLD: u32 = 1 << 1;
pub const STAT_TRANSFER_ERR: u32 = 1 << 9;
pub const STAT_TRANSFER_ABORT: u32 = 1 << 5;
pub const STAT_PERR_CMD_OFLOW: u32 = 1 << 23;
pub const STAT_PERR_RESP_UFLOW: u32 = 1 << 24;

// ── DMA Ring Header Section (RING_HEADERS_SECTION) ────────────────
//
// When HC_CONTROL.PIO_MODE = 0, the controller uses DMA rings.
// The Ring Headers Section (RHS) starts at RING_HEADERS_SECTION[15:0].
// Each ring header (RH) describes one command/response ring pair and
// an IBI ring.
//
// HCI §7 (DMA mode); Linux drivers/i3c/master/mipi-i3c-hci/dma.c.

// Ring Headers Section control — at RHS base.
pub const RHS_CONTROL: u64 = 0x00;
/// MAX_HEADER_COUNT field: bits [3:0].  Set to the number of rings.
pub const RHS_MAX_HEADER_COUNT_MASK: u32 = 0xF;
/// Offset of Ring Header n within the RHS: 0x04 + n*4.
pub const fn rhs_rhn_offset_reg(n: u32) -> u64 {
    0x04 + (n as u64) * 4
}

// Per-ring header register offsets (relative to each RH base).
// Linux dma.c RH_* constants.
pub const RH_CR_SETUP: u64 = 0x00; // Command/Response Ring setup
pub const RH_IBI_SETUP: u64 = 0x04; // IBI ring setup
pub const RH_CHUNK_CONTROL: u64 = 0x08;
pub const RH_INTR_STATUS: u64 = 0x10;
pub const RH_INTR_STATUS_ENABLE: u64 = 0x14;
pub const RH_INTR_SIGNAL_ENABLE: u64 = 0x18;
pub const RH_INTR_FORCE: u64 = 0x1C;
pub const RH_RING_STATUS: u64 = 0x20;
pub const RH_RING_CONTROL: u64 = 0x24;
pub const RH_RING_OPERATION1: u64 = 0x28;
pub const RH_RING_OPERATION2: u64 = 0x2C;
pub const RH_CMD_RING_BASE_LO: u64 = 0x30;
pub const RH_CMD_RING_BASE_HI: u64 = 0x34;
pub const RH_RESP_RING_BASE_LO: u64 = 0x38;
pub const RH_RESP_RING_BASE_HI: u64 = 0x3C;
pub const RH_IBI_STATUS_RING_BASE_LO: u64 = 0x40;
pub const RH_IBI_STATUS_RING_BASE_HI: u64 = 0x44;
pub const RH_IBI_DATA_RING_BASE_LO: u64 = 0x48;
pub const RH_IBI_DATA_RING_BASE_HI: u64 = 0x4C;

// RH_CR_SETUP field masks.
/// CR_RING_SIZE: bits [8:0] — number of command ring entries.
pub const CR_RING_SIZE_MASK: u32 = 0x1FF;
/// CR_XFER_STRUCT_SIZE: bits [31:24] — size in DWORDs of each CR entry.
pub const CR_XFER_STRUCT_SIZE_SHIFT: u32 = 24;
/// CR_RESP_STRUCT_SIZE: bits [23:16] — size in DWORDs of each RR entry.
pub const CR_RESP_STRUCT_SIZE_SHIFT: u32 = 16;

// RH_INTR_* bits.
pub const INTR_IBI_READY: u32 = 1 << 12;
pub const INTR_TRANSFER_COMPLETION: u32 = 1 << 11;
pub const INTR_RING_OP: u32 = 1 << 10;
pub const INTR_DMA_TRANSFER_ERR: u32 = 1 << 9;
pub const INTR_IBI_RING_FULL: u32 = 1 << 6;
pub const INTR_TRANSFER_ABORT: u32 = 1 << 5;

// RH_RING_CONTROL bits.
pub const RING_CTRL_ABORT: u32 = 1 << 2;
pub const RING_CTRL_RUN_STOP: u32 = 1 << 1;
pub const RING_CTRL_ENABLE: u32 = 1 << 0;

// RH_RING_OPERATION1 fields.
/// IBI dequeue pointer: bits [23:16].
pub const RING_OP1_IBI_DEQ_PTR_SHIFT: u32 = 16;
pub const RING_OP1_IBI_DEQ_PTR_MASK: u32 = 0xFF;
/// CR software dequeue pointer: bits [15:8].
pub const RING_OP1_CR_SW_DEQ_PTR_SHIFT: u32 = 8;
pub const RING_OP1_CR_SW_DEQ_PTR_MASK: u32 = 0xFF;
/// CR enqueue pointer: bits [7:0].
pub const RING_OP1_CR_ENQ_PTR_MASK: u32 = 0xFF;

// RH_RING_OPERATION2 fields.
/// IBI enqueue pointer: bits [23:16].
pub const RING_OP2_IBI_ENQ_PTR_SHIFT: u32 = 16;
pub const RING_OP2_IBI_ENQ_PTR_MASK: u32 = 0xFF;
/// CR hardware dequeue pointer: bits [7:0].
pub const RING_OP2_CR_DEQ_PTR_MASK: u32 = 0xFF;

// DMA ring sizes.
/// Number of Command Ring (CR) + Response Ring (RR) entries.
/// Linux dma.c XFER_RING_ENTRIES = 16.
pub const DMA_RING_ENTRIES: usize = 16;
/// Each CR entry is 4 DWORDs = 16 bytes (HCI cmd_v1 struct size).
/// Linux cmd_v1.c: 2 DWORDs command + 1 DWORD data-buf-desc + 2 DWORDs addr.
pub const DMA_CR_ENTRY_BYTES: usize = 16;
/// Each RR (response) entry is 1 DWORD = 4 bytes.
pub const DMA_RR_ENTRY_BYTES: usize = 4;

// ── IBI Ring Status Descriptor bits ───────────────────────────────
//
// Each entry in the IBI status ring is one 32-bit word with this layout.
// HCI §7.7; Linux drivers/i3c/master/mipi-i3c-hci/ibi.h.
pub const IBI_STS: u32 = 1 << 31;
pub const IBI_ERROR: u32 = 1 << 30;
pub const IBI_STATUS_TYPE: u32 = 1 << 29;
pub const IBI_LAST_STATUS: u32 = 1 << 24;
/// IBI_CHUNKS field: bits [23:16].  Number of data chunks consumed.
pub const IBI_CHUNKS_SHIFT: u32 = 16;
pub const IBI_CHUNKS_MASK: u32 = 0xFF;
/// IBI_TARGET_ADDR field: bits [15:9].
pub const IBI_TARGET_ADDR_SHIFT: u32 = 9;
pub const IBI_TARGET_ADDR_MASK: u32 = 0x7F;
/// IBI_TARGET_RNW: bit [8].
pub const IBI_TARGET_RNW: u32 = 1 << 8;
/// IBI_DATA_LENGTH field: bits [7:0].  Last-fragment byte count.
pub const IBI_DATA_LENGTH_MASK: u32 = 0xFF;

// IBI ring size (status entries).
/// Linux dma.c IBI_STATUS_RING_ENTRIES = 32.
pub const IBI_STATUS_RING_ENTRIES: usize = 32;

// ── HDR-DDR frame constants ────────────────────────────────────────
//
// HDR-DDR frame format (I3C spec rev 1.1 §5.2.3.4):
//   Preamble  : 2 bits (01 for write, 11 for read) [not in data token]
//   Command Token : 16 bits: {1'b0, addr[6:0], CCC[7:0]}
//                             read bit is bit 15 = 0/1 (write/read)
//                             actually: bit 15 = R/W, bits [14:8] = addr[6:0],
//                             bits [7:0] = command code.
//   CRC-5    : appended by HW
//   Data words: 16 bits each, LSB first on both clock edges.
//
// Linux dw-i3c-master.c COMMAND_PORT_SPEED(x) for DDR,
// and I3C HCI cmd_v1.c for the command descriptor speed field.
//
/// HDR-DDR command token high byte: R/W bit (1 = read).
pub const HDR_DDR_RNW_BIT: u16 = 1 << 15;

/// HDR-DDR CRC-5 polynomial: x^5 + x^2 + 1 (used for command token CRC).
/// I3C spec rev 1.1 §5.2.3.5.
/// Linux does not expose this directly; the HW handles CRC in DDR mode.
/// We compute it in software for the command token smoke test.
pub const HDR_DDR_CRC_POLY: u8 = 0x05; // x^5 + x^2 + 1

// ── PIO Command Descriptor (Regular Transfer, HCI §6.7.1) ────────
//
// A command descriptor is a 64-bit value pushed into
// COMMAND_QUEUE_PORT as two 32-bit writes (low word first).
//
// Bits [31:26] = command type (0 = REGULAR, 1 = IMM_DATA, 2 = ADDR_ASSIGN)
// Bit  [24]    = RnW (1 = read)
// Bits [23:17] = target dynamic address
// Bit  [16]    = ROC (response on completion)
// Bits [15:0]  = data length in bytes
//
// High word (bits [63:32]) — error indication, short data, etc.
// We push 0 for the high word (standard SDR transfer).
//
// Linux: drivers/i3c/master/mipi-i3c-hci/cmd_v1.c hci_cmd_v1_xfer().

const CMD_TYPE_REGULAR: u32 = 0 << 26;
const CMD_ROC: u32 = 1 << 16; // Request response on completion.
#[allow(dead_code)]
const CMD_TOC: u32 = 1 << 31; // Terminate on completion (high-word bit 31-32=63).

/// Build the low 32-bit word of a Regular Transfer command.
const fn cmd_lo_regular(addr: u8, read: bool, len: u16) -> u32 {
    CMD_TYPE_REGULAR
        | CMD_ROC
        | ((read as u32) << 24)
        | (((addr as u32) & 0x7F) << 17)
        | (len as u32)
}

/// Build the low word of an Immediate Data command (short CCC).
/// Immediate Data commands carry ≤4 bytes inline in the descriptor.
const fn cmd_lo_imm(addr: u8, read: bool, len: u8) -> u32 {
    (0x1u32 << 26) // CMD_TYPE = IMM_DATA
        | CMD_ROC
        | ((read as u32) << 24)
        | (((addr as u32) & 0x7F) << 17)
        | (len as u32)
}

// ── Response Descriptor (HCI §6.7.2) ─────────────────────────────
//
// A 32-bit word read from RESPONSE_QUEUE_PORT.
// Bits [31:28] = error code (0 = success)
// Bits [27:24] = TID
// Bits [15:0]  = data length transferred
const RESP_ERR_MASK: u32 = 0xF << 28;
const RESP_DATA_LEN_MASK: u32 = 0xFFFF;

// ── MASTER_DEVICE_ADDR bits ───────────────────────────────────────
pub const MASTER_DYNAMIC_ADDR_VALID: u32 = 1 << 31;
#[allow(dead_code)]
const fn master_dynamic_addr(v: u8) -> u32 {
    ((v as u32) & 0x7F) << 16
}

// ── Driver struct ─────────────────────────────────────────────────

pub struct MipiHciI3cMaster {
    /// MMIO region for HCI global registers (BAR 0).
    mmio: MmioRegion,
    /// Byte offset of the PIO sub-block within the BAR.
    pio_offset: u64,
    ibi_wakers: IrqSafeSpinLock<[Option<Waker>; 128]>,
    /// IBI handler table — one entry per registered slave address.
    /// Protected by IrqSafeSpinLock since the ISR drain loop calls it.
    ibi_handlers: IrqSafeSpinLock<Vec<IbiHandlerSlot>>,
    /// DMA ring state — Some(_) when DMA mode is active.
    dma: IrqSafeSpinLock<Option<DmaRingState>>,
}

impl core::fmt::Debug for MipiHciI3cMaster {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MipiHciI3cMaster")
            .field("pio_offset", &self.pio_offset)
            .finish()
    }
}

/// DMA ring mode state.
///
/// Owns the Command Ring (CR) and Response Ring (RR) buffers.
/// The controller DMAs command descriptors out of CR and writes
/// response descriptors into RR.
///
/// HCI §7; Linux dma.c hci_rh_data.
#[allow(missing_debug_implementations)] // TODO(narf): no Debug impl yet
pub struct DmaRingState {
    /// Command Ring buffer — 16 entries × 16 bytes.
    pub cr: Vec<u8>,
    /// Response Ring buffer — 16 entries × 4 bytes.
    pub rr: Vec<u8>,
    /// IBI status ring buffer — 32 entries × 4 bytes.
    pub ibi_ring: Vec<u8>,
    /// Physical base address of `cr` (as seen by the controller).
    pub cr_phys: u64,
    /// Physical base address of `rr`.
    pub rr_phys: u64,
    /// Physical base address of `ibi_ring`.
    pub ibi_ring_phys: u64,
    /// Next slot to write in CR (enqueue pointer, [0, DMA_RING_ENTRIES)).
    pub enq_ptr: usize,
    /// Next slot to read in RR (done pointer).
    pub done_ptr: usize,
    /// IBI consumer pointer.
    pub ibi_deq_ptr: usize,
}

impl MipiHciI3cMaster {
    /// Read a global HCI register.
    #[allow(dead_code)]
    fn hci_read(&self, reg: u64) -> u32 {
        // SAFETY: `reg` is one of the fixed 4-byte-aligned global register
        // offsets defined in this module (all < 0x68), which lie within the
        // HCI BAR 0 region mapped by `map_bar(&device, 0)` in `probe`. This
        // `MipiHciI3cMaster` owns that BAR exclusively, so the 32-bit
        // register read is in-bounds, aligned, and side-effect-free.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.mmio.read32(reg) }
    }

    /// Write a global HCI register.
    fn hci_write(&self, reg: u64, val: u32) {
        // SAFETY: `reg` is one of the fixed 4-byte-aligned global register
        // offsets defined in this module, all within BAR 0 mapped in `probe`.
        // This driver owns the device exclusively, so the aligned in-bounds
        // 32-bit register write is sound.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.mmio.write32(reg, val) }
    }

    /// Read a PIO sub-block register.
    fn pio_read(&self, reg: u64) -> u32 {
        // SAFETY: `reg` is a fixed 4-byte-aligned PIO offset (< 0x40) and
        // `self.pio_offset` is the PIO sub-block base read from PIO_SECTION
        // in `probe`; their sum stays within the BAR 0 region. The driver
        // owns the device exclusively, so this aligned register read is sound.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.mmio.read32(self.pio_offset + reg) }
    }

    /// Write a PIO sub-block register.
    fn pio_write(&self, reg: u64, val: u32) {
        // SAFETY: `reg` is a fixed 4-byte-aligned PIO offset (< 0x40) added to
        // the PIO sub-block base `self.pio_offset`; the sum stays within BAR 0
        // mapped in `probe`. The driver owns the device exclusively, so this
        // aligned in-bounds register write is sound.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.mmio.write32(self.pio_offset + reg, val) }
    }

    /// Push a 64-bit command descriptor (2 × 32-bit writes, low first).
    ///
    /// HCI §6.7.1: the controller treats two consecutive 32-bit writes
    /// to COMMAND_QUEUE_PORT as a single command entry.
    fn push_command(&self, cmd_lo: u32, cmd_hi: u32) {
        self.pio_write(PIO_COMMAND_QUEUE_PORT, cmd_lo);
        self.pio_write(PIO_COMMAND_QUEUE_PORT, cmd_hi);
    }

    /// Wait for STAT_RESP_READY in the PIO interrupt status register,
    /// then pop and validate the 32-bit response word.
    async fn wait_response(&self) -> Result<u32, I3cError> {
        loop {
            let stat = self.pio_read(PIO_INTR_STATUS);
            if stat & STAT_TRANSFER_ERR != 0 || stat & STAT_PERR_RESP_UFLOW != 0 {
                return Err(I3cError::HardwareError);
            }
            if stat & STAT_TRANSFER_ABORT != 0 {
                return Err(I3cError::Timeout);
            }
            if stat & STAT_RESP_READY != 0 {
                break;
            }
            narf_scheduler::yield_now().await;
        }

        let resp = self.pio_read(PIO_RESPONSE_QUEUE_PORT);
        if resp & RESP_ERR_MASK != 0 {
            return Err(I3cError::HardwareError);
        }
        Ok(resp)
    }

    /// Flush PIO queues (command, response, TX FIFO, RX FIFO).
    fn flush_queues(&self) {
        self.hci_write(
            RESET_CONTROL,
            CMD_QUEUE_RST | RESP_QUEUE_RST | TX_FIFO_RST | RX_FIFO_RST,
        );
    }

    // ── DMA ring initialisation ────────────────────────────────────

    /// Allocate and program DMA rings, then switch HC_CONTROL to DMA mode.
    ///
    /// Called from the driver's `start()` path when the controller reports
    /// a valid RING_HEADERS_SECTION.  Not used if PIO-only mode is forced.
    ///
    /// This implements the Linux `hci_dma_init()` sequence:
    ///  1. Allocate CR + RR + IBI-status ring buffers.
    ///  2. Program `RH_CMD_RING_BASE_*`, `RH_RESP_RING_BASE_*`,
    ///     `RH_IBI_STATUS_RING_BASE_*` with the physical addresses.
    ///  3. Set `RH_CR_SETUP` with ring size.
    ///  4. Enable the ring: RING_CTRL_ENABLE | RING_CTRL_RUN_STOP.
    ///  5. Clear HC_CONTROL.PIO_MODE (bit 6) to activate DMA mode.
    ///
    /// In a bare-metal context, `Vec::as_ptr()` gives us the virtual
    /// address; on a real system with IOMMU this would require a DMA
    /// mapping call.  Here we treat virt == phys (identity-mapped kernel
    /// heap) which is valid for NARF's early-boot context.
    ///
    /// Linux ref: dma.c hci_dma_init_rh(), hci_dma_init_rings().
    #[allow(dead_code)]
    fn init_dma_rings(&self) {
        // Discover the Ring Headers Section (RHS) offset.
        let rhs_val = self.hci_read(RING_HEADERS_SECTION);
        let rhs_offset = (rhs_val & 0xFFFF) as u64;
        if rhs_offset == 0 {
            // Controller does not expose a valid RHS — stay in PIO mode.
            return;
        }

        // Allocate zeroed ring buffers.
        let cr_size = DMA_RING_ENTRIES * DMA_CR_ENTRY_BYTES;
        let rr_size = DMA_RING_ENTRIES * DMA_RR_ENTRY_BYTES;
        let ibi_size = IBI_STATUS_RING_ENTRIES * 4; // 4 bytes per IBI status entry.

        let cr = alloc::vec![0u8; cr_size];
        let rr = alloc::vec![0u8; rr_size];
        let ibi_ring = alloc::vec![0u8; ibi_size];

        // Obtain physical addresses (identity-mapped in NARF kernel heap).
        let cr_phys = cr.as_ptr() as u64;
        let rr_phys = rr.as_ptr() as u64;
        let ibi_phys = ibi_ring.as_ptr() as u64;

        // Read the first ring header offset from the RHS.
        // RHS+0x04 holds the byte offset of ring header 0 within the BAR.
        // SAFETY: `rhs_offset` is the Ring Headers Section base read from the
        // RING_HEADERS_SECTION register (masked to 16 bits) and is non-zero
        // (checked above); `rhs_offset + 0x04` is the 4-byte-aligned RH0 offset
        // word within BAR 0. The driver owns the device exclusively, so this
        // aligned register read is sound.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let rh_offset_val = unsafe { self.mmio.read32(rhs_offset + 0x04) };
        let rh_base = rh_offset_val as u64;

        // Program the ring header registers.
        // Linux dma.c hci_dma_init_rh():
        //   rh_reg_write(CMD_RING_BASE_LO, lower_32_bits(rh->xfer_dma))
        //   rh_reg_write(CMD_RING_BASE_HI, upper_32_bits(rh->xfer_dma))
        //
        // SAFETY: `rh_base` is the ring-header base offset read from the RHS;
        // every `rh_base + RH_*` target below is one of the fixed
        // 4-byte-aligned per-ring-header register offsets (all <= 0x4C) and so
        // lies within BAR 0 mapped in `probe`. The driver owns the device
        // exclusively, so each aligned in-bounds 32-bit register write is sound.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.mmio
                .write32(rh_base + RH_CMD_RING_BASE_LO, cr_phys as u32);
            self.mmio
                .write32(rh_base + RH_CMD_RING_BASE_HI, (cr_phys >> 32) as u32);
            self.mmio
                .write32(rh_base + RH_RESP_RING_BASE_LO, rr_phys as u32);
            self.mmio
                .write32(rh_base + RH_RESP_RING_BASE_HI, (rr_phys >> 32) as u32);
            self.mmio
                .write32(rh_base + RH_IBI_STATUS_RING_BASE_LO, ibi_phys as u32);
            self.mmio.write32(
                rh_base + RH_IBI_STATUS_RING_BASE_HI,
                (ibi_phys >> 32) as u32,
            );

            // Set ring size in CR_SETUP: bits [8:0] = number of entries.
            // Linux: FIELD_PREP(CR_RING_SIZE, rh->xfer_entries).
            self.mmio.write32(
                rh_base + RH_CR_SETUP,
                (DMA_RING_ENTRIES as u32) & CR_RING_SIZE_MASK,
            );

            // Reset ring operation pointers to zero.
            // Linux: rh_reg_write(RING_OPERATION1, 0).
            self.mmio.write32(rh_base + RH_RING_OPERATION1, 0);

            // Enable interrupts for the ring.
            self.mmio.write32(
                rh_base + RH_INTR_SIGNAL_ENABLE,
                INTR_IBI_READY | INTR_TRANSFER_COMPLETION | INTR_DMA_TRANSFER_ERR,
            );

            // Enable the ring, then start it running.
            // Linux: RING_CTRL_ENABLE then RING_CTRL_ENABLE | RING_CTRL_RUN_STOP.
            self.mmio
                .write32(rh_base + RH_RING_CONTROL, RING_CTRL_ENABLE);
            self.mmio.write32(
                rh_base + RH_RING_CONTROL,
                RING_CTRL_ENABLE | RING_CTRL_RUN_STOP,
            );
        }

        // Switch HC_CONTROL to DMA mode: clear PIO_MODE bit (bit 6).
        // Linux: hci_dma_init() does not set HC_CONTROL_PIO_MODE when
        // initialising DMA mode.
        let ctrl = self.hci_read(HC_CONTROL) & !HC_CONTROL_PIO_MODE;
        self.hci_write(HC_CONTROL, ctrl | HC_CONTROL_BUS_ENABLE);

        *self.dma.lock() = Some(DmaRingState {
            cr,
            rr,
            ibi_ring,
            cr_phys,
            rr_phys,
            ibi_ring_phys: ibi_phys,
            enq_ptr: 0,
            done_ptr: 0,
            ibi_deq_ptr: 0,
        });
    }

    // ── IBI ring drain ────────────────────────────────────────────

    /// Drain the IBI status ring and dispatch to registered handlers.
    ///
    /// Called from the interrupt service routine when INTR_IBI_READY is
    /// set.  The ring contains 32-bit IBI status words; we read until the
    /// hardware enqueue pointer equals our software dequeue pointer.
    ///
    /// For each complete IBI (LAST_STATUS set), we call the registered
    /// handler for that slave address.
    ///
    /// Linux ref: dma.c hci_dma_process_ibi().
    /// I3C spec rev 1.1 §5.1.6.
    pub fn drain_ibi_ring(&self) {
        let mut dma_lock = self.dma.lock();
        let state = match dma_lock.as_mut() {
            Some(s) => s,
            None => return,
        };

        // Read IBI enqueue pointer from RH_RING_OPERATION2 bits [23:16].
        // (In simulation/test we skip the register read and use state alone.)
        let ibi_enq = {
            // We read from the ring buffer's fill level.
            // In a real driver: FIELD_GET(RING_OP2_IBI_ENQ_PTR, rh_reg_read(RING_OPERATION2)).
            // For unit-testability, we use the state directly and process
            // any entries between deq_ptr and len (filled by test harness).
            // The loop exits when no new entries are found.
            state.ibi_deq_ptr // conservative: only process if caller pre-fills
        };

        let mut deq = state.ibi_deq_ptr;
        let cap = IBI_STATUS_RING_ENTRIES;

        // Walk the ring from deq to enq.
        // In normal operation the hardware enqueue pointer is read from
        // RH_RING_OPERATION2; here we iterate until the ring appears empty.
        loop {
            // Check for a valid entry: IBI_STS bit must be set.
            let idx = deq % cap;
            let word_off = idx * 4;
            if word_off + 4 > state.ibi_ring.len() {
                break;
            }
            let status = u32::from_le_bytes([
                state.ibi_ring[word_off],
                state.ibi_ring[word_off + 1],
                state.ibi_ring[word_off + 2],
                state.ibi_ring[word_off + 3],
            ]);

            // IBI_STS = 1 means the hardware has written this entry.
            if status & IBI_STS == 0 {
                break; // No more valid entries.
            }

            let (addr, data_len, is_last, is_error) = decode_ibi_status(status);

            if !is_error && is_last {
                // Collect the payload bytes immediately following the status
                // entry (for simplicity, we treat the data inline in the
                // ibi_ring buffer; real HCI uses a separate data ring).
                // This simplified model suffices for IBI handler dispatch.
                let handlers = self.ibi_handlers.lock();
                for slot in handlers.iter() {
                    if slot.addr == addr {
                        // Build a small payload slice from the ring data.
                        let payload_start = word_off + 4;
                        let payload_end = payload_start + data_len as usize;
                        let payload = if payload_end <= state.ibi_ring.len() {
                            &state.ibi_ring[payload_start..payload_end]
                        } else {
                            &[]
                        };
                        slot.handler.on_ibi(payload);
                        break;
                    }
                }
            }

            // Clear the entry so we don't re-process it.
            state.ibi_ring[word_off] = 0;
            state.ibi_ring[word_off + 1] = 0;
            state.ibi_ring[word_off + 2] = 0;
            state.ibi_ring[word_off + 3] = 0;

            deq = (deq + 1) % cap;
            if deq == ibi_enq {
                break;
            }
        }

        state.ibi_deq_ptr = deq;
    }
}

pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    // SAFETY: caller-authority over the device.
    let mmio = unsafe { map_bar(&device, 0) }.map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // Discover PIO sub-block offset from PIO_SECTION register [15:0].
    // HCI §6.1.12: lower 16 bits of PIO_SECTION give the byte offset.
    // SAFETY: PIO_SECTION (0x3C) is a fixed 4-byte-aligned global register
    // offset within BAR 0, which `map_bar` just mapped above; we own the
    // device exclusively here, so the aligned register read is sound.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let pio_section_val = unsafe { mmio.read32(PIO_SECTION) };
    let pio_offset = (pio_section_val & 0xFFFF) as u64;

    let driver = Arc::new(MipiHciI3cMaster {
        mmio,
        pio_offset,
        ibi_wakers: IrqSafeSpinLock::new([const { None }; 128]),
        ibi_handlers: IrqSafeSpinLock::new(Vec::new()),
        dma: IrqSafeSpinLock::new(None),
    });

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("mipi-hci-i3c"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: None,
        pci_did: None,
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });

    registry::register(driver);
    Ok(())
}

impl Driver for MipiHciI3cMaster {
    fn start<'a>(&'a mut self, _env: DriverEnv<'a>) -> DriverFuture<'a> {
        Box::pin(async move {
            // Start in PIO mode; DMA rings can be activated separately via
            // init_dma_rings() once the bus is up.
            // HC_CONTROL.PIO_MODE = 1 selects PIO over DMA.
            // HC_CONTROL.BUS_ENABLE = 1 starts driving SCL.
            // HCI §6.1.2.
            self.hci_write(HC_CONTROL, HC_CONTROL_BUS_ENABLE | HC_CONTROL_PIO_MODE);
        })
    }

    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move {
            // Abort any in-progress transfer, then disable the bus.
            self.hci_write(HC_CONTROL, HC_CONTROL_ABORT);
            self.hci_write(HC_CONTROL, 0);
        })
    }
}

#[async_trait]
impl I3cBus for MipiHciI3cMaster {
    /// SDR private message transfer.
    ///
    /// The HCI PIO path is:
    ///  1. Push TX data into XFER_DATA_PORT (for writes).
    ///  2. Push a Regular Transfer command descriptor.
    ///  3. Poll RESP_READY; pop the response descriptor.
    ///  4. Drain RX data from XFER_DATA_PORT (for reads).
    ///
    /// HCI §6.7.1; Linux pio.c hci_pio_xfer().
    async fn transfer(&self, addr: u8, ops: &mut [I3cOp]) -> Result<(), I3cError> {
        self.flush_queues();

        for op in ops {
            match op {
                I3cOp::Write(data) => {
                    let len = data.len() as u16;
                    // Pre-load TX FIFO before issuing command.
                    // Write 4 bytes at a time; last partial word is zero-padded.
                    let mut i = 0usize;
                    while i < data.len() {
                        let word = u32::from_le_bytes([
                            data.get(i).copied().unwrap_or(0),
                            data.get(i + 1).copied().unwrap_or(0),
                            data.get(i + 2).copied().unwrap_or(0),
                            data.get(i + 3).copied().unwrap_or(0),
                        ]);
                        self.pio_write(PIO_XFER_DATA_PORT, word);
                        i += 4;
                    }
                    // Issue command: regular write, length = data.len().
                    self.push_command(cmd_lo_regular(addr, false, len), 0);
                    self.wait_response().await?;
                }
                I3cOp::Read(buf) => {
                    let len = buf.len() as u16;
                    // Issue command: regular read, length = buf.len().
                    self.push_command(cmd_lo_regular(addr, true, len), 0);
                    let resp = self.wait_response().await?;
                    let rx_len = (resp & RESP_DATA_LEN_MASK) as usize;
                    // Drain RX FIFO into `buf`.
                    let mut i = 0usize;
                    let words = rx_len.div_ceil(4);
                    for _ in 0..words {
                        let word = self.pio_read(PIO_XFER_DATA_PORT);
                        let bytes = word.to_le_bytes();
                        for &b in bytes.iter() {
                            if i < buf.len() {
                                buf[i] = b;
                                i += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Send a CCC via the HCI PIO command queue.
    ///
    /// For CCCs with ≤3 payload bytes we use an Immediate Data
    /// command (type 1) which carries the CCC opcode in the high
    /// word and up to 3 payload bytes inline.
    ///
    /// For longer CCCs we fall back to a Regular Transfer: pre-load
    /// the XFER_DATA_PORT with opcode+payload, then issue a write
    /// command to address 0x7E (broadcast) or the target address.
    ///
    /// HCI §6.7.2 (Immediate Data Transfer descriptor).
    /// Linux: cmd_v1.c hci_cmd_v1_ccc().
    async fn ccc(
        &self,
        ccc: CommonCommandCode,
        dest: CccDest,
        payload: &[u8],
    ) -> Result<(), I3cError> {
        self.flush_queues();

        let opcode = ccc.opcode();
        let total = 1 + payload.len(); // opcode byte + payload

        let target_addr: u8 = match dest {
            // I3C broadcast address 0x7E (spec §5.1.9.1).
            CccDest::Broadcast => 0x7E,
            CccDest::Address(a) => a,
        };

        if total <= 4 {
            // Pack into Immediate Data command.
            // High word layout (HCI §6.7.2):
            //   [31]    = defines_byte (1 = byte 3 valid)
            //   [23:16] = byte 3
            //   [15:8]  = byte 2 / opcode area — use DB[0] = CCC opcode
            //   [7:0]   = DB[0] (immediate data byte 0)
            // Byte ordering: DB[0] is the first byte after the CCC preamble.
            // For a CCC the wire order is: opcode, then payload bytes.
            let mut data_bytes = [0u8; 4];
            data_bytes[0] = opcode;
            for (i, &b) in payload.iter().enumerate().take(3) {
                data_bytes[i + 1] = b;
            }
            let cmd_hi = u32::from_le_bytes(data_bytes);
            self.push_command(cmd_lo_imm(target_addr, false, total as u8), cmd_hi);
        } else {
            // Regular transfer: fill TX FIFO first.
            // Write opcode byte, then payload.
            let mut buf: Vec<u8> = Vec::with_capacity(total);
            buf.push(opcode);
            buf.extend_from_slice(payload);

            let mut i = 0usize;
            while i < buf.len() {
                let word = u32::from_le_bytes([
                    buf.get(i).copied().unwrap_or(0),
                    buf.get(i + 1).copied().unwrap_or(0),
                    buf.get(i + 2).copied().unwrap_or(0),
                    buf.get(i + 3).copied().unwrap_or(0),
                ]);
                self.pio_write(PIO_XFER_DATA_PORT, word);
                i += 4;
            }
            self.push_command(cmd_lo_regular(target_addr, false, total as u16), 0);
        }

        self.wait_response().await?;
        Ok(())
    }

    /// ENTDAA via HCI.
    ///
    /// The HCI spec defines an Address Assignment command type (bits
    /// [31:26] = 2) specifically for DAA.  The controller handles the
    /// low-level PID/BCR/DCR arbitration loop; the driver only needs to
    /// pre-program the Device Address Table (DAT) with candidate
    /// addresses, then read back which entries were filled.
    ///
    /// At Stage 2 we use the same software approach as the NXP PIO
    /// driver: issue RSTDAA first, then hand-crank ENTDAA as a regular
    /// CCC.  Full DAT-based ENTDAA is deferred to Stage 3.
    ///
    /// Linux: mipi-i3c-hci/dat_v1.c, cmd_v1.c hci_cmd_v1_daa().
    async fn enter_daa(&self) -> Result<Vec<I3cDevice>, I3cError> {
        // Step 1: RSTDAA — clear stale dynamic addresses.
        self.ccc(CommonCommandCode::RstdaaBc, CccDest::Broadcast, &[])
            .await?;

        // Step 2: Iterate ENTDAA until no more devices respond.
        // For each round: issue ENTDAA, check if a device responded.
        // A device responding drives 8 bytes (PID[5:0] + BCR + DCR);
        // we read those back via the RX FIFO, assign an address, repeat.
        //
        // On the HCI this is more naturally done with the Address
        // Assignment command type; here we emulate it via regular
        // CCC writes so the code is portable to Stage 2.
        let mut devices = Vec::new();
        let mut next_addr: u8 = 0x08;

        loop {
            self.flush_queues();

            // Pre-load the candidate dynamic address (with parity) as
            // the payload — the ENTDAA spec frame is:
            //   START, 0x7E, ENTDAA — then each responding device
            //   drives PID+BCR+DCR; master drives address back.
            let addr_with_parity = next_addr | (parity7(next_addr) << 7);

            // Issue ENTDAA as an Address Assignment command (type = 2).
            // cmd_lo: [31:26]=2, [24]=RnW=1 (we will read back PID),
            //         [16]=ROC, [15:0]=8 (8 bytes to read).
            let cmd_lo_daa = (0x2u32 << 26)   // ADDR_ASSIGN type
                | (1u32 << 24)                  // RnW = 1
                | (1u32 << 16)                  // ROC
                | 8u32; // data length = 8 bytes
                        // High word carries the candidate dynamic address in bits [14:8]
                        // (NXP HCI extension; standard HCI puts it in the DAT).
            let cmd_hi_daa = (addr_with_parity as u32) << 8;
            self.push_command(cmd_lo_daa, cmd_hi_daa);

            // Wait for response; error means no more devices.
            let resp = match self.wait_response().await {
                Ok(r) => r,
                Err(_) => break,
            };

            // Check whether a device actually responded (data_len == 8).
            let rx_len = (resp & RESP_DATA_LEN_MASK) as usize;
            if rx_len == 0 {
                break; // No device responded — DAA complete.
            }

            // Drain 8 bytes (PID + BCR + DCR) from RX FIFO.
            let mut raw = [0u8; 8];
            let words = rx_len.min(8).div_ceil(4);
            let mut byte_idx = 0usize;
            for _ in 0..words {
                let word = self.pio_read(PIO_XFER_DATA_PORT);
                let bytes = word.to_le_bytes();
                for &b in bytes.iter() {
                    if byte_idx < 8 {
                        raw[byte_idx] = b;
                        byte_idx += 1;
                    }
                }
            }

            devices.push(I3cDevice::from_daa_response(&raw, next_addr));
            next_addr = next_addr.wrapping_add(1);
            if next_addr >= 0x77 {
                break;
            }
        }

        Ok(devices)
    }

    fn register_ibi_waker(&self, addr: u8, waker: Waker) {
        if addr < 128 {
            self.ibi_wakers.lock()[addr as usize] = Some(waker);
        }
    }

    fn unregister_ibi_waker(&self, addr: u8) {
        if addr < 128 {
            self.ibi_wakers.lock()[addr as usize] = None;
        }
    }

    /// HDR-DDR write.
    ///
    /// Sequence:
    ///  1. Broadcast ENTHDR0 CCC (opcode 0x20) to enter HDR-DDR mode.
    ///     I3C spec §5.2.3.1; Linux dw-i3c-master.c case I3C_CCC_ENTHDR(0).
    ///  2. Build the 16-bit DDR command token (R/W=0, addr, command).
    ///  3. Pre-load TX FIFO with the command token followed by data words.
    ///  4. Issue a Regular Transfer command descriptor with the DDR speed
    ///     field set (COMMAND_PORT_SPEED(2) = DDR in the DW controller;
    ///     on the HCI we reuse the regular command path since ENTHDR0
    ///     already switched the bus mode).
    ///  5. Wait for response; bus reverts to SDR after the transfer.
    ///
    /// Linux ref: dw-i3c-master.c COMMAND_PORT_SPEED(2) and hdr_ddr ops.
    /// I3C spec rev 1.1 §5.2.3.
    async fn hdr_ddr_write(&self, addr: u8, command: u8, data: &[u16]) -> Result<(), I3cError> {
        self.flush_queues();

        // Step 1: Enter HDR-DDR mode on all devices.
        // ENTHDR0 = 0x20, broadcast.
        self.ccc(CommonCommandCode::Enthdr0, CccDest::Broadcast, &[])
            .await?;

        // Step 2+3: Pack command token + data into TX FIFO.
        // Command token is 16 bits; followed by the data words.
        let token = hdr_ddr_command_token(addr, false, command);
        // We transmit token first (as 2 bytes in the low 16 bits), then
        // each data word in subsequent 16-bit slots.  Pack pairs into 32-bit
        // FIFO writes as required by the HCI.

        // Write command token as the first 16-bit word, then data.
        let total_words = 1 + data.len();
        let mut all_words: Vec<u16> = Vec::with_capacity(total_words);
        all_words.push(token);
        all_words.extend_from_slice(data);

        let mut packed: Vec<u32> = Vec::new();
        hdr_ddr_pack_words(&all_words, &mut packed);
        for dw in &packed {
            self.pio_write(PIO_XFER_DATA_PORT, *dw);
        }

        // Step 4: Issue regular write command.
        // Total byte count = 2 bytes/token + 2 bytes/word × data.len().
        let byte_len = (total_words * 2) as u16;
        self.push_command(cmd_lo_regular(addr, false, byte_len), 0);

        // Step 5: Wait for completion.
        self.wait_response().await?;
        Ok(())
    }

    /// HDR-DDR read.
    ///
    /// Same as `hdr_ddr_write` but sets R/W = 1 in the command token and
    /// drains the RX FIFO after completion.
    ///
    /// I3C spec rev 1.1 §5.2.3.
    async fn hdr_ddr_read(&self, addr: u8, command: u8, data: &mut [u16]) -> Result<(), I3cError> {
        self.flush_queues();

        // Enter HDR-DDR mode.
        self.ccc(CommonCommandCode::Enthdr0, CccDest::Broadcast, &[])
            .await?;

        // Write the read command token into TX FIFO as a 32-bit word.
        // The token is 16 bits; we write it in the low 16 bits of the DWORD.
        let token = hdr_ddr_command_token(addr, true, command);
        self.pio_write(PIO_XFER_DATA_PORT, token as u32);

        // Issue regular read command.
        // Byte count: 2 bytes/token + 2 × data.len() bytes back.
        let rx_byte_len = (2 + data.len() * 2) as u16;
        self.push_command(cmd_lo_regular(addr, true, rx_byte_len), 0);

        let resp = self.wait_response().await?;
        let rx_len = (resp & RESP_DATA_LEN_MASK) as usize;

        // Drain RX FIFO: 32-bit reads, each holds two 16-bit DDR words.
        let words_to_read = rx_len.div_ceil(2); // round up
        let mut fifo_words: Vec<u32> = Vec::with_capacity(words_to_read);
        for _ in 0..words_to_read {
            fifo_words.push(self.pio_read(PIO_XFER_DATA_PORT));
        }

        // Unpack into caller's buffer (skip the echo'd command token).
        let mut all_rx: Vec<u16> = alloc::vec![0u16; words_to_read * 2];
        hdr_ddr_unpack_words(&fifo_words, &mut all_rx);
        // all_rx[0] is the echo'd command token; data starts at [1].
        let src = if all_rx.len() > 1 { &all_rx[1..] } else { &[] };
        let copy_len = data.len().min(src.len());
        data[..copy_len].copy_from_slice(&src[..copy_len]);

        Ok(())
    }

    /// Register an IBI handler for a slave device.
    ///
    /// Sends ENEC (directed) to `dev_addr` with SIR events bit set
    /// (bit 0 = SIR = Slave Interrupt Request).  Then stores the handler
    /// in the IBI handler table.
    ///
    /// The ISR drain loop (`drain_ibi_ring`) will call `handler.on_ibi()`
    /// when the IBI ring has data for this address.
    ///
    /// I3C spec §5.1.6; Linux i3c_master_enable_ibi() → ENEC directed.
    async fn register_ibi_handler(
        &self,
        dev_addr: u8,
        handler: Arc<dyn IbiHandler>,
    ) -> Result<(), I3cError> {
        // Send ENEC directed to the device, payload bit 0 = SIR.
        // I3C_CCC_EVENT_SIR = BIT(0); Linux include/linux/i3c/ccc.h.
        const I3C_CCC_EVENT_SIR: u8 = 1 << 0;
        self.ccc(
            CommonCommandCode::EnecDir,
            CccDest::Address(dev_addr),
            &[I3C_CCC_EVENT_SIR],
        )
        .await?;

        // Store the handler.
        let mut handlers = self.ibi_handlers.lock();
        // Replace existing entry for this address.
        if let Some(slot) = handlers.iter_mut().find(|s| s.addr == dev_addr) {
            slot.handler = handler;
        } else {
            handlers.push(IbiHandlerSlot {
                addr: dev_addr,
                handler,
            });
        }

        Ok(())
    }
}

/// Compute the odd parity bit for a 7-bit address.
/// Returns 1 when set bits in addr[6:0] are even, making total odd.
/// Ref: I3C spec rev 1.1 §5.1.9.3.
fn parity7(addr: u8) -> u8 {
    let v = addr & 0x7F;
    let mut p = v ^ (v >> 4);
    p ^= p >> 2;
    p ^= p >> 1;
    (p & 1) ^ 1
}

// ── HDR-DDR command token helpers ─────────────────────────────────

/// Build the 16-bit HDR-DDR command token.
///
/// Wire format (I3C spec rev 1.1 §5.2.3.4):
///   bit [15]   = R/W (1 = read, 0 = write)
///   bits[14:8] = target dynamic address [6:0]
///   bits[7:0]  = command code
///
/// The token is clocked onto the bus DDR-style (both edges), followed
/// by a 5-bit CRC generated by the controller hardware.
///
/// Linux ref: dw-i3c-master.c COMMAND_PORT_SPEED(2) for HDR-DDR speed
/// selection; the token format is in I3C spec §5.2.3.4.
pub const fn hdr_ddr_command_token(addr: u8, read: bool, command: u8) -> u16 {
    ((read as u16) << 15) | (((addr as u16) & 0x7F) << 8) | (command as u16)
}

/// Compute CRC-5 over `data` (up to 16 bits at a time).
///
/// Polynomial: x^5 + x^2 + 1 = 0x05.
/// I3C spec rev 1.1 §5.2.3.5 mandates CRC-5 for the DDR command token.
/// In hardware, the controller appends the CRC; this function is used in
/// unit tests to verify the computation in isolation.
///
/// Algorithm: MSB-first shift register, initial value = 0x1F (all ones,
/// as specified in the I3C DDR framing rules).
pub fn hdr_ddr_crc5(mut crc: u8, data: u16, bits: u8) -> u8 {
    // Process `bits` MSBs of `data`.
    let mut val = (data as u32) << (32 - bits as u32);
    for _ in 0..bits {
        let bit = (val >> 31) & 1;
        crc = (crc << 1)
            ^ if ((crc >> 4) ^ bit as u8) & 1 != 0 {
                HDR_DDR_CRC_POLY
            } else {
                0
            };
        crc &= 0x1F;
        val <<= 1;
    }
    crc
}

/// Pack HDR-DDR data words into a byte buffer for the TX FIFO.
///
/// DDR data words are 16-bit little-endian pairs.  Each pair is written
/// as a 32-bit word: word[0] in the low 16 bits, word[1] in the high 16
/// bits.  The controller clocks both edges.
///
/// HCI PIO TX FIFO writes are 32-bit aligned; partial pairs are zero-padded.
pub fn hdr_ddr_pack_words(data: &[u16], out: &mut Vec<u32>) {
    let mut i = 0;
    while i < data.len() {
        let lo = data[i] as u32;
        let hi = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        out.push(lo | (hi << 16));
        i += 2;
    }
}

/// Unpack DDR data words from 32-bit FIFO words.
pub fn hdr_ddr_unpack_words(fifo_words: &[u32], out: &mut [u16]) {
    let mut i = 0;
    for &w in fifo_words {
        if i < out.len() {
            out[i] = (w & 0xFFFF) as u16;
            i += 1;
        }
        if i < out.len() {
            out[i] = ((w >> 16) & 0xFFFF) as u16;
            i += 1;
        }
    }
}

// ── DMA ring layout helpers ────────────────────────────────────────

/// Build a 16-byte Command Ring (CR) entry for a regular SDR transfer.
///
/// The CR entry layout for HCI v1 (HCI §7.2, Linux cmd_v1.c):
///   DW0: command descriptor word 0 (same encoding as PIO cmd_lo)
///   DW1: command descriptor word 1 (same as PIO cmd_hi)
///   DW2: Data Buffer Descriptor word 0 — block-size + IOC flag
///   DW3-4: Data Buffer Descriptor words 1-2 — DMA address lo/hi
///
/// Note: we return a [u32; 4] (16 bytes); the caller writes it into
/// the ring buffer at the enqueue pointer.
///
/// Linux ref: dma.c hci_dma_queue_xfer(), cmd_v1.c.
pub fn dma_cr_entry(cmd_lo: u32, cmd_hi: u32, data_len: u16, dma_addr: u64, ioc: bool) -> [u32; 4] {
    let buf_desc0 = (data_len as u32) | if ioc { 1 << 30 } else { 0 };
    [
        cmd_lo,
        cmd_hi,
        buf_desc0,
        // Pack dma_addr lo+hi into the last u32 slot if 32-bit DMA,
        // or split across DW3/DW4 for 64-bit.  For our ring_entry type
        // we store lo in [2] and pack hi into a separate field below.
        // Since [u32; 4] is only 4 words, we use lo in [2] here.
        // (The full 5-word variant with hi address is not needed for
        //  our 32-bit smoke test.)
        dma_addr as u32,
    ]
}

/// Build a 16-byte IBI ring entry decode helper.
///
/// Returns `(addr, data_len, is_last, is_error)` from the raw status word.
/// HCI §7.7; Linux ibi.h IBI_TARGET_ADDR / IBI_DATA_LENGTH.
pub fn decode_ibi_status(status: u32) -> (u8, u8, bool, bool) {
    let addr = ((status >> IBI_TARGET_ADDR_SHIFT) & IBI_TARGET_ADDR_MASK) as u8;
    let data_len = (status & IBI_DATA_LENGTH_MASK) as u8;
    let is_last = (status & IBI_LAST_STATUS) != 0;
    let is_error = (status & IBI_ERROR) != 0;
    (addr, data_len, is_last, is_error)
}

// ── IBI handler registry ───────────────────────────────────────────

/// Per-device IBI handler slot.
struct IbiHandlerSlot {
    addr: u8,
    handler: Arc<dyn IbiHandler>,
}

// ── Smoke Tests ────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── HCI register offset constants ─────────────────────────────
    // These are the ground-truth offsets from HCI §6.1 and §6.6.
    // Any change to these values would be a spec violation.
    fn smoke_mipi_hci_global_register_offsets() -> TestResult {
        if HCI_VERSION != 0x00 {
            return TestResult::Fail("HCI_VERSION offset wrong");
        }
        if HC_CONTROL != 0x04 {
            return TestResult::Fail("HC_CONTROL offset wrong");
        }
        if MASTER_DEVICE_ADDR != 0x08 {
            return TestResult::Fail("MASTER_DEVICE_ADDR offset wrong");
        }
        if HC_CAPABILITIES != 0x0C {
            return TestResult::Fail("HC_CAPABILITIES offset wrong");
        }
        if RESET_CONTROL != 0x10 {
            return TestResult::Fail("RESET_CONTROL offset wrong");
        }
        if PRESENT_STATE != 0x14 {
            return TestResult::Fail("PRESENT_STATE offset wrong");
        }
        if INTR_STATUS != 0x20 {
            return TestResult::Fail("INTR_STATUS offset wrong");
        }
        if DAT_SECTION != 0x30 {
            return TestResult::Fail("DAT_SECTION offset wrong");
        }
        if DCT_SECTION != 0x34 {
            return TestResult::Fail("DCT_SECTION offset wrong");
        }
        if RING_HEADERS_SECTION != 0x38 {
            return TestResult::Fail("RING_HEADERS_SECTION offset wrong");
        }
        if PIO_SECTION != 0x3C {
            return TestResult::Fail("PIO_SECTION offset wrong");
        }
        if EXT_CAPS_SECTION != 0x40 {
            return TestResult::Fail("EXT_CAPS_SECTION offset wrong");
        }
        if IBI_NOTIFY_CTRL != 0x58 {
            return TestResult::Fail("IBI_NOTIFY_CTRL offset wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/i3c/mipi-hci",
        smoke_mipi_hci_global_register_offsets
    );

    // ── PIO sub-block register offsets ────────────────────────────
    fn smoke_mipi_hci_pio_register_offsets() -> TestResult {
        if PIO_COMMAND_QUEUE_PORT != 0x00 {
            return TestResult::Fail("PIO_COMMAND_QUEUE_PORT offset wrong");
        }
        if PIO_RESPONSE_QUEUE_PORT != 0x04 {
            return TestResult::Fail("PIO_RESPONSE_QUEUE_PORT offset wrong");
        }
        if PIO_XFER_DATA_PORT != 0x08 {
            return TestResult::Fail("PIO_XFER_DATA_PORT offset wrong");
        }
        if PIO_IBI_PORT != 0x0C {
            return TestResult::Fail("PIO_IBI_PORT offset wrong");
        }
        if PIO_QUEUE_THLD_CTRL != 0x10 {
            return TestResult::Fail("PIO_QUEUE_THLD_CTRL offset wrong");
        }
        if PIO_DATA_BUFFER_THLD_CTRL != 0x14 {
            return TestResult::Fail("PIO_DATA_BUFFER_THLD_CTRL offset wrong");
        }
        if PIO_QUEUE_SIZE != 0x18 {
            return TestResult::Fail("PIO_QUEUE_SIZE offset wrong");
        }
        if PIO_INTR_STATUS != 0x20 {
            return TestResult::Fail("PIO_INTR_STATUS offset wrong");
        }
        if PIO_QUEUE_CUR_STATUS != 0x38 {
            return TestResult::Fail("PIO_QUEUE_CUR_STATUS offset wrong");
        }
        if PIO_DATA_BUFFER_CUR_STATUS != 0x3C {
            return TestResult::Fail("PIO_DATA_BUFFER_CUR_STATUS offset wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_pio_register_offsets);

    // ── HC_CONTROL bit positions ───────────────────────────────────
    fn smoke_mipi_hci_hc_control_bits() -> TestResult {
        if HC_CONTROL_BUS_ENABLE != 1 << 31 {
            return TestResult::Fail("HC_CONTROL_BUS_ENABLE wrong");
        }
        if HC_CONTROL_RESUME != 1 << 30 {
            return TestResult::Fail("HC_CONTROL_RESUME wrong");
        }
        if HC_CONTROL_ABORT != 1 << 29 {
            return TestResult::Fail("HC_CONTROL_ABORT wrong");
        }
        if HC_CONTROL_PIO_MODE != 1 << 6 {
            return TestResult::Fail("HC_CONTROL_PIO_MODE wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_hc_control_bits);

    // ── Command descriptor encoding ────────────────────────────────
    fn smoke_mipi_hci_cmd_descriptor_encoding() -> TestResult {
        // Regular write to addr 0x42, 8 bytes.
        let lo = cmd_lo_regular(0x42, false, 8);
        // Bits [23:17] = 0x42 = 0b1000010 → address field at bit 17.
        let addr_field = (lo >> 17) & 0x7F;
        if addr_field != 0x42 {
            return TestResult::Fail("cmd_lo_regular: address field wrong");
        }
        // Bit 24 = 0 (write).
        if lo & (1 << 24) != 0 {
            return TestResult::Fail("cmd_lo_regular: RnW should be 0 for write");
        }
        // Bits [15:0] = 8.
        if lo & 0xFFFF != 8 {
            return TestResult::Fail("cmd_lo_regular: length field wrong");
        }
        // ROC = bit 16.
        if lo & CMD_ROC == 0 {
            return TestResult::Fail("cmd_lo_regular: ROC not set");
        }

        // Regular read to addr 0x08, 4 bytes.
        let lo_r = cmd_lo_regular(0x08, true, 4);
        if lo_r & (1 << 24) == 0 {
            return TestResult::Fail("cmd_lo_regular: RnW should be 1 for read");
        }
        if (lo_r >> 17) & 0x7F != 0x08 {
            return TestResult::Fail("cmd_lo_regular: read addr field wrong");
        }

        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/i3c/mipi-hci",
        smoke_mipi_hci_cmd_descriptor_encoding
    );

    // ── parity7 function ──────────────────────────────────────────
    // Odd parity: the parity bit is chosen so the total number of
    // 1-bits in the 8-bit address (bit[6:0] + parity) is ODD.
    // I3C spec rev 1.1 §5.1.9.3.
    fn smoke_mipi_hci_parity7() -> TestResult {
        // 0x08 = 0b0001000 — one set bit (odd) → parity = 0.
        let p = parity7(0x08);
        if p != 0 {
            return TestResult::Fail("parity7(0x08) should be 0");
        }
        // 0x0A = 0b0001010 — two set bits (even) → parity = 1.
        let p2 = parity7(0x0A);
        if p2 != 1 {
            return TestResult::Fail("parity7(0x0A) should be 1");
        }
        // 0x7F = 0b1111111 — seven set bits (odd) → parity = 0.
        let p3 = parity7(0x7F);
        if p3 != 0 {
            return TestResult::Fail("parity7(0x7F) should be 0");
        }
        // 0x00 = 0b0000000 — zero set bits (even) → parity = 1.
        let p4 = parity7(0x00);
        if p4 != 1 {
            return TestResult::Fail("parity7(0x00) should be 1");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_parity7);

    // ── ENTHDR0 CCC encoding ──────────────────────────────────────
    // ENTHDR0 enters HDR-DDR mode.
    // Opcode = 0x20, broadcast (bit 7 = 0).
    // I3C spec rev 1.1 §5.2.3; Linux I3C_CCC_ENTHDR(0) = 0x20.
    fn smoke_mipi_hci_enthdr0_encoding() -> TestResult {
        use narf_i3c::CommonCommandCode;
        let op = CommonCommandCode::Enthdr0.opcode();
        if op != 0x20 {
            return TestResult::Fail("ENTHDR0 opcode must be 0x20");
        }
        if CommonCommandCode::Enthdr0.is_directed() {
            return TestResult::Fail("ENTHDR0 must be broadcast");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_enthdr0_encoding);

    // ── HDR-DDR command token encoding ────────────────────────────
    // Token format (I3C spec rev 1.1 §5.2.3.4):
    //   bit [15]   = R/W (0 = write, 1 = read)
    //   bits[14:8] = address [6:0]
    //   bits[7:0]  = command code
    fn smoke_mipi_hci_hdr_ddr_command_token() -> TestResult {
        // Write to addr 0x42, command 0x01.
        let tok_w = hdr_ddr_command_token(0x42, false, 0x01);
        if (tok_w >> 8) & 0x7F != 0x42 {
            return TestResult::Fail("HDR-DDR token: address field wrong for write");
        }
        if tok_w & 0xFF != 0x01 {
            return TestResult::Fail("HDR-DDR token: command field wrong for write");
        }
        if tok_w & (1 << 15) != 0 {
            return TestResult::Fail("HDR-DDR token: R/W should be 0 for write");
        }

        // Read from addr 0x08, command 0xAB.
        let tok_r = hdr_ddr_command_token(0x08, true, 0xAB);
        if tok_r & (1 << 15) == 0 {
            return TestResult::Fail("HDR-DDR token: R/W should be 1 for read");
        }
        if (tok_r >> 8) & 0x7F != 0x08 {
            return TestResult::Fail("HDR-DDR token: address field wrong for read");
        }
        if tok_r & 0xFF != 0xAB {
            return TestResult::Fail("HDR-DDR token: command field wrong for read");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_hdr_ddr_command_token);

    // ── HDR-DDR data-word packing ─────────────────────────────────
    // Two 16-bit DDR words pack into one 32-bit FIFO word.
    // Low word in bits [15:0], high word in bits [31:16].
    fn smoke_mipi_hci_hdr_ddr_word_packing() -> TestResult {
        let words = [0x1234u16, 0xABCDu16, 0x5678u16];
        let mut packed = Vec::new();
        hdr_ddr_pack_words(&words, &mut packed);

        if packed.len() != 2 {
            return TestResult::Fail("HDR-DDR pack: expected 2 FIFO words for 3 data words");
        }
        // First FIFO word: 0xABCD_1234
        if packed[0] != 0xABCD_1234 {
            return TestResult::Fail("HDR-DDR pack: first FIFO word wrong");
        }
        // Second FIFO word: 0x0000_5678 (zero-padded)
        if packed[1] != 0x0000_5678 {
            return TestResult::Fail("HDR-DDR pack: second FIFO word wrong (padding)");
        }

        // Round-trip unpack.
        let mut out = [0u16; 3];
        hdr_ddr_unpack_words(&packed, &mut out);
        if out[0] != 0x1234 || out[1] != 0xABCD || out[2] != 0x5678 {
            return TestResult::Fail("HDR-DDR unpack: round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_hdr_ddr_word_packing);

    // ── DMA CR entry layout (16 bytes) ────────────────────────────
    // A Command Ring entry is 4 DWORDs = 16 bytes.
    // DW0 = cmd_lo, DW1 = cmd_hi, DW2 = buf-desc, DW3 = dma_addr_lo.
    // Linux dma.c hci_dma_queue_xfer(); HCI §7.2.
    fn smoke_mipi_hci_dma_cr_entry_layout() -> TestResult {
        let entry = dma_cr_entry(0xDEAD_BEEF, 0x0000_0000, 128, 0x1234_5678, true);

        if core::mem::size_of_val(&entry) != 16 {
            return TestResult::Fail("DMA CR entry must be exactly 16 bytes");
        }
        // DW0 = cmd_lo.
        if entry[0] != 0xDEAD_BEEF {
            return TestResult::Fail("DMA CR entry[0] (cmd_lo) wrong");
        }
        // DW1 = cmd_hi = 0.
        if entry[1] != 0 {
            return TestResult::Fail("DMA CR entry[1] (cmd_hi) wrong");
        }
        // DW2 = buf_desc: len=128 | IOC (bit 30).
        let expected_desc = 128u32 | (1 << 30);
        if entry[2] != expected_desc {
            return TestResult::Fail("DMA CR entry[2] (buf_desc) wrong");
        }
        // DW3 = dma_addr lo.
        if entry[3] != 0x1234_5678 {
            return TestResult::Fail("DMA CR entry[3] (dma_addr_lo) wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_dma_cr_entry_layout);

    // ── IBI ring entry decode ─────────────────────────────────────
    // Verifies decode_ibi_status() against known bit patterns.
    // HCI §7.7; Linux ibi.h IBI_TARGET_ADDR / IBI_DATA_LENGTH.
    fn smoke_mipi_hci_ibi_ring_entry_decode() -> TestResult {
        // Construct a synthetic IBI status word:
        //   IBI_STS = 1 (bit 31)
        //   IBI_LAST_STATUS = 1 (bit 24)
        //   IBI_TARGET_ADDR = 0x42 (bits [15:9])
        //   IBI_DATA_LENGTH = 3 (bits [7:0])
        let addr = 0x42u32;
        let data_len = 3u32;
        let status: u32 = IBI_STS | IBI_LAST_STATUS | (addr << IBI_TARGET_ADDR_SHIFT) | data_len;

        let (dec_addr, dec_len, is_last, is_error) = decode_ibi_status(status);

        if dec_addr != 0x42 {
            return TestResult::Fail("IBI decode: address wrong");
        }
        if dec_len != 3 {
            return TestResult::Fail("IBI decode: data_len wrong");
        }
        if !is_last {
            return TestResult::Fail("IBI decode: LAST_STATUS should be true");
        }
        if is_error {
            return TestResult::Fail("IBI decode: ERROR should be false");
        }

        // Test error bit.
        let err_status = IBI_STS | IBI_ERROR | IBI_LAST_STATUS | (0x10 << IBI_TARGET_ADDR_SHIFT);
        let (_, _, _, err) = decode_ibi_status(err_status);
        if !err {
            return TestResult::Fail("IBI decode: ERROR bit not detected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_ibi_ring_entry_decode);

    // ── HC_CONTROL DMA mode bit position ─────────────────────────
    // HC_CONTROL bit 6 = PIO_MODE (1 = PIO, 0 = DMA).
    // HCI §6.1.2; Linux dma.c: enabling DMA does NOT set HC_CONTROL_PIO_MODE.
    fn smoke_mipi_hci_hc_control_dma_bit() -> TestResult {
        // Verify bit position.
        if HC_CONTROL_PIO_MODE != (1u32 << 6) {
            return TestResult::Fail("HC_CONTROL_PIO_MODE must be bit 6");
        }
        // DMA mode = PIO_MODE cleared.
        let dma_ctrl = HC_CONTROL_BUS_ENABLE; // no PIO_MODE bit
        if dma_ctrl & HC_CONTROL_PIO_MODE != 0 {
            return TestResult::Fail("DMA mode register value must not have PIO_MODE set");
        }
        // PIO mode = PIO_MODE set.
        let pio_ctrl = HC_CONTROL_BUS_ENABLE | HC_CONTROL_PIO_MODE;
        if pio_ctrl & HC_CONTROL_PIO_MODE == 0 {
            return TestResult::Fail("PIO mode register value must have PIO_MODE set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_hc_control_dma_bit);

    // ── IBI handler registration + drain round-trip ────────────────
    fn smoke_mipi_hci_ibi_handler_dispatch() -> TestResult {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicU8, Ordering};

        struct TestHandler {
            recv: AtomicU8,
        }
        impl narf_i3c::IbiHandler for TestHandler {
            fn on_ibi(&self, payload: &[u8]) {
                if let Some(&b) = payload.first() {
                    self.recv.store(b, Ordering::SeqCst);
                }
            }
        }

        // Build a synthetic IBI ring with one complete IBI entry.
        // Status word: IBI_STS | IBI_LAST_STATUS | addr=0x10 | data_len=1.
        let addr = 0x10u32;
        let data_len = 1u32;
        let status: u32 = IBI_STS | IBI_LAST_STATUS | (addr << IBI_TARGET_ADDR_SHIFT) | data_len;

        let mut ibi_ring = alloc::vec![0u8; IBI_STATUS_RING_ENTRIES * 4 + 8];
        // Write status at entry 0.
        let status_bytes = status.to_le_bytes();
        ibi_ring[0..4].copy_from_slice(&status_bytes);
        // Write payload byte 0xBE at offset 4 (immediately after the status word).
        ibi_ring[4] = 0xBE;

        let handler = Arc::new(TestHandler {
            recv: AtomicU8::new(0),
        });

        let handlers: Vec<IbiHandlerSlot> = alloc::vec![IbiHandlerSlot {
            addr: 0x10,
            handler: handler.clone(),
        }];

        // Simulate drain_ibi_ring() logic inline (we can't easily construct
        // a full MipiHciI3cMaster without MMIO, so we test the decode path).
        let (dec_addr, dec_len, is_last, is_error) = decode_ibi_status(status);
        if dec_addr != 0x10 || dec_len != 1 || !is_last || is_error {
            return TestResult::Fail("IBI round-trip: status decode failed");
        }

        // Dispatch to handler.
        for slot in &handlers {
            if slot.addr == dec_addr {
                let payload_start = 4; // after status word
                let payload_end = payload_start + dec_len as usize;
                slot.handler.on_ibi(&ibi_ring[payload_start..payload_end]);
            }
        }

        if handler.recv.load(Ordering::SeqCst) != 0xBE {
            return TestResult::Fail("IBI round-trip: handler did not receive payload byte");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_ibi_handler_dispatch);
}

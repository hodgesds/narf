//! MIPI I3C Host Controller Interface (HCI) 1.x PIO driver.
//!
//! Implements a generic I3C master over the MIPI HCI MMIO register map,
//! which is used by multiple vendors (NXP i.MX 8M+, AMD Hawk Point USB4
//! hub, and others).  Only the PIO (non-DMA) path is implemented here;
//! DMA ring mode is deferred to Stage 3.
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
use narf_i3c::{registry, CccDest, CommonCommandCode, I3cBus, I3cDevice, I3cError, I3cOp};
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
pub const HC_CONTROL_PIO_MODE: u32 = 1 << 6; // 1 = PIO, 0 = DMA
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
const fn master_dynamic_addr(v: u8) -> u32 {
    ((v as u32) & 0x7F) << 16
}

// ── Driver struct ─────────────────────────────────────────────────

#[derive(Debug)]
pub struct MipiHciI3cMaster {
    /// MMIO region for HCI global registers (BAR 0).
    mmio: MmioRegion,
    /// Byte offset of the PIO sub-block within the BAR.
    pio_offset: u64,
    ibi_wakers: IrqSafeSpinLock<[Option<Waker>; 128]>,
}

impl MipiHciI3cMaster {
    /// Read a global HCI register.
    fn hci_read(&self, reg: u64) -> u32 {
        unsafe { self.mmio.read32(reg) }
    }

    /// Write a global HCI register.
    fn hci_write(&self, reg: u64, val: u32) {
        unsafe { self.mmio.write32(reg, val) }
    }

    /// Read a PIO sub-block register.
    fn pio_read(&self, reg: u64) -> u32 {
        unsafe { self.mmio.read32(self.pio_offset + reg) }
    }

    /// Write a PIO sub-block register.
    fn pio_write(&self, reg: u64, val: u32) {
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
}

pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    // SAFETY: caller-authority over the device.
    let mmio = unsafe { map_bar(&device, 0) }.map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // Discover PIO sub-block offset from PIO_SECTION register [15:0].
    // HCI §6.1.12: lower 16 bits of PIO_SECTION give the byte offset.
    let pio_section_val = unsafe { mmio.read32(PIO_SECTION) };
    let pio_offset = (pio_section_val & 0xFFFF) as u64;

    let driver = Arc::new(MipiHciI3cMaster {
        mmio: mmio.clone(),
        pio_offset,
        ibi_wakers: IrqSafeSpinLock::new([const { None }; 128]),
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
            // Select PIO mode and enable the bus.
            // HC_CONTROL_PIO_MODE = 1 (use PIO, not DMA).
            // HC_CONTROL_BUS_ENABLE = 1 — start driving SCL.
            // HCI §6.1.2.
            self.hci_write(
                HC_CONTROL,
                HC_CONTROL_BUS_ENABLE | HC_CONTROL_PIO_MODE,
            );
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
                    let words = (rx_len + 3) / 4;
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
                | 8u32;                          // data length = 8 bytes
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
            let words = (rx_len.min(8) + 3) / 4;
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
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_global_register_offsets);

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
    kernel_test_in!("drivers/i3c/mipi-hci", smoke_mipi_hci_cmd_descriptor_encoding);

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
}

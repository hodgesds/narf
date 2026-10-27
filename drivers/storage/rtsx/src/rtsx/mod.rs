//! Realtek RTSX PCIe SD/microSD card-reader driver.
//!
//! ## Architecture
//!
//! The RTSX chip presents a single PCIe function (Realtek vendor 0x10EC)
//! that embeds an SD card reader (and optionally MS/XD readers on older
//! revisions).  The driver maps BAR0 and uses two mechanisms:
//!
//! 1. **Host command buffer** — a DMA-coherent page holding a batch of
//!    up to 256 4-byte `(type, addr, mask, data)` tuples, dispatched by
//!    writing HCBAR + HCBCTLR (trigger | hardware-auto-response |
//!    byte length).  Completion is BIPR.TRANS_OK / BIPR.TRANS_FAIL.
//!    READ/CHECK results land at the start of the same page.
//!
//! 2. **Ping-pong buffer (PPBUF)** — a 512-byte on-chip staging buffer
//!    used for R2 (CID/CSD) responses and single-block data transfers
//!    (CMD17 / CMD24), matching Linux's "normal_rw" path in
//!    `rtsx_pci_sdmmc.c`.  The ADMA ring-buffer path (HDBAR/HDBCTLR)
//!    for multi-block transfers is not programmed by this driver.
//!
//! Single internal registers are also reachable through HAIMR
//! (Linux `rtsx_pci_read_register` / `rtsx_pci_write_register`).
//!
//! All hardware access goes through [`RtsxTransport`]: production
//! implements it over the BAR0 mapping + command DMA page, and the
//! kernel-test fixtures implement it over a register-level model of
//! the chip + SD card (see `fixture_tests`).
//!
//! ## SD card sequence
//!
//! ```text
//! power-on → CMD0 → CMD8 → CMD55+ACMD41 (loop until OCR.BUSY) →
//!   CMD2 (CID) → CMD3 (RCA) → CMD9 (CSD → real capacity) →
//!   CMD7 (SELECT) → CMD16 (SDSC block length) → ready
//! ```
//!
//! ## References
//!
//! - Linux `drivers/mfd/rtsx_pcr.c` (GPL-2.0-or-later)
//! - Linux `drivers/mmc/host/rtsx_pci_sdmmc.c` (GPL-2.0-or-later)
//! - Linux `include/linux/mfd/rtsx_pci.h` (GPL-2.0-or-later)
//!
//! Cited and adapted under NARF's GPL-2.0-or-later licence.

pub mod block_bridge;
pub mod card;
pub mod cmd;
pub mod regs;

#[cfg(any(test, feature = "kernel-test"))]
mod fixture_tests;

use alloc::sync::Arc;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{
    map_bar, register_pci_driver as bus_register_pci_driver, BusDevice, BusDeviceCap, MatchKind,
    MmioRegion, PciMatch, ProbeError,
};
use narf_capabilities::{Cap, Write};
use narf_drivers_storage_core::sd_proto::Csd;
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use card::{SdCardInfo, SdCmd, SdResponse, SlotState};
use cmd::{build_sd_cmd_frame, CmdBuf};
use regs::*;

// ── PCI device IDs ────────────────────────────────────────────────

/// Realtek vendor ID.
/// Linux `rtsx_pcr.c` — `PCI_DEVICE(0x10EC, ...)`
pub const RTSX_VENDOR: u16 = 0x10EC;

/// Supported Realtek RTSX PCIe card-reader device IDs.
/// Linux `drivers/mfd/rtsx_pcr.c` pci_device_id table (GPL-2.0-or-later),
/// extended with the later RTS52xx IDs from `drivers/misc/cardreader`.
pub const RTSX_DEVICE_IDS: &[(u16, &str)] = &[
    (0x5209, "RTS5209"),
    (0x5229, "RTS5229"),
    (0x5289, "RTS5289"),
    (0x5227, "RTS5227"),
    (0x522A, "RTS522A"),
    (0x5249, "RTS5249"),
    (0x5287, "RTS5287"),
    (0x5286, "RTS5286"),
    (0x524A, "RTS524A"),
    (0x525A, "RTS525A"),
    (0x5260, "RTS5260"),
    (0x5261, "RTS5261"),
    (0x5228, "RTS5228"),
    (0x5264, "RTS5264"),
];

/// BAR index for the RTSX MMIO window.
const RTSX_BAR: u8 = 0;

// ── Driver global state ───────────────────────────────────────────

/// Global RTSX controller instance (first probed device).
static RTSX: IrqSafeSpinLock<Option<RtsxController>> = IrqSafeSpinLock::new(None);

/// How many RTSX devices have been successfully probed.
static PROBE_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

// ── Error type ────────────────────────────────────────────────────

/// Errors returned by the RTSX driver.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RtsxError {
    /// BAR mapping failed.
    BarMapFailed,
    /// DMA allocation failed.
    DmaAllocFailed,
    /// Hardware did not complete within the timeout.
    Timeout,
    /// A transfer reported an error in BIPR (TRANS_FAIL).
    TransferFailed,
    /// The card's response failed its CRC7 check (SD_STAT1).
    CrcError,
    /// The card answered with garbage: bad response header, a zero
    /// RCA, or a CSD that does not parse. Surfaced as a typed error —
    /// never papered over with invented values.
    BadResponse,
    /// Command buffer overflow.
    CmdBufFull,
    /// No card present or card not ready.
    NoCard,
}

// ── Transport seam ────────────────────────────────────────────────

/// Hardware-access seam for the RTSX controller.
///
/// Production implements this over the BAR0 MMIO mapping and the
/// host-command-buffer DMA page; the kernel-test fixtures implement
/// it over a register-level model of the chip and an SD card model,
/// so the full probe → identify → block-I/O conversation is
/// exercised end to end without silicon.
pub trait RtsxTransport: Send + Sync + core::fmt::Debug {
    /// Read a 32-bit HBA register at BAR0 `offset`.
    fn read_hba(&self, offset: u64) -> u32;
    /// Write a 32-bit HBA register at BAR0 `offset`.
    fn write_hba(&self, offset: u64, val: u32);
    /// Physical (DMA) address of the host command buffer page,
    /// programmed into HCBAR on every dispatch.
    fn cmd_buf_dma_addr(&self) -> u32;
    /// Write bytes into the host command buffer page at `offset`.
    fn cmd_buf_write(&self, offset: usize, data: &[u8]);
    /// Read bytes from the host command buffer page at `offset`
    /// (after a dispatch, the response area lives at offset 0).
    fn cmd_buf_read(&self, offset: usize, out: &mut [u8]);
}

/// Production transport: BAR0 MMIO + one DMA-coherent command page.
#[derive(Debug)]
pub struct MmioTransport {
    mmio: MmioRegion,
    cmd_buf: DmaBuffer,
}

impl RtsxTransport for MmioTransport {
    fn read_hba(&self, offset: u64) -> u32 {
        // SAFETY: offsets are the fixed HBA register offsets from
        // regs.rs; the region is the device's BAR0, exclusively owned.
        unsafe { self.mmio.read32(offset) }
    }

    fn write_hba(&self, offset: u64, val: u32) {
        // SAFETY: same as `read_hba`.
        unsafe { self.mmio.write32(offset, val) }
    }

    fn cmd_buf_dma_addr(&self) -> u32 {
        self.cmd_buf.dma_addr().raw() as u32
    }

    fn cmd_buf_write(&self, offset: usize, data: &[u8]) {
        // SAFETY: the command page is a 4 KiB DMA-coherent allocation
        // owned by this transport; callers keep offset + len in range.
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.cmd_buf.as_mut_ptr().add(offset),
                data.len(),
            );
        }
    }

    fn cmd_buf_read(&self, offset: usize, out: &mut [u8]) {
        // SAFETY: same allocation as `cmd_buf_write`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.cmd_buf.as_ptr().add(offset),
                out.as_mut_ptr(),
                out.len(),
            );
        }
    }
}

// ── Controller ────────────────────────────────────────────────────

/// Live RTSX card-reader controller.
pub struct RtsxController {
    transport: Arc<dyn RtsxTransport>,
    /// Device ID (used for chip-specific quirks).
    pub device_id: u16,
    /// SD slot state.
    pub sd_slot: SlotState,
}

impl core::fmt::Debug for RtsxController {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RtsxController")
            .field("device_id", &format_args!("{:#06x}", self.device_id))
            .field("sd_slot", &self.sd_slot)
            .finish_non_exhaustive()
    }
}

/// SD_CFG2 byte for a single-block data transfer (CMD17/CMD24):
/// calculate CRC7, check data CRC16, no busy-end wait, check response
/// CRC7, 6-byte response — i.e. the flag composition Linux
/// `sd_read_data` / `sd_write_data` in `rtsx_pci_sdmmc.c` programs,
/// which sums to the R1 composite value.
const SD_CFG2_DATA_R1: u8 = SD_CFG2_RSP_LEN_6;

impl RtsxController {
    /// Map BAR0 and allocate the command DMA buffer.
    ///
    /// # Safety
    /// Caller must own the device's BAR0 exclusively.
    pub unsafe fn new(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
        device_id: u16,
    ) -> Result<Self, RtsxError> {
        // SAFETY: caller-authority.
        let mmio = unsafe { map_bar(device, RTSX_BAR) }.map_err(|_| RtsxError::BarMapFailed)?;

        let cmd_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| RtsxError::DmaAllocFailed)?;

        Ok(RtsxController {
            transport: Arc::new(MmioTransport { mmio, cmd_buf }),
            device_id,
            sd_slot: SlotState::Empty,
        })
    }

    /// Build a controller over an arbitrary transport (fixtures).
    pub fn with_transport(transport: Arc<dyn RtsxTransport>, device_id: u16) -> Self {
        RtsxController {
            transport,
            device_id,
            sd_slot: SlotState::Empty,
        }
    }

    /// Read a 32-bit HBA register at `offset` from BAR0.
    #[inline]
    pub fn read32(&self, offset: u64) -> u32 {
        self.transport.read_hba(offset)
    }

    /// Write a 32-bit HBA register.
    #[inline]
    pub fn write32(&self, offset: u64, val: u32) {
        self.transport.write_hba(offset, val)
    }

    /// Write an internal register via the HAIMR single-access path.
    ///
    /// Encoding per Linux `rtsx_pci_write_register`: TRANS_START |
    /// WRITE | (addr & 0x3FFF) << 16 | mask << 8 | data; the hardware
    /// clears TRANS_START on completion and echoes the written byte
    /// in bits[7:0], which Linux verifies.
    pub fn haimr_write(&self, addr: u16, mask: u8, data: u8) -> Result<(), RtsxError> {
        let val = HAIMR_TRANS_START
            | HAIMR_WRITE
            | (((addr as u32) & HAIMR_ADDR_MASK) << 16)
            | ((mask as u32) << 8)
            | (data as u32);
        self.write32(HAIMR, val);

        // Poll until TRANS_START clears — hardware done.
        // Linux bounds this with MAX_RW_REG_CNT (1024).
        for _ in 0..1024 {
            let r = self.read32(HAIMR);
            if r & HAIMR_TRANS_START == 0 {
                if (r & 0xFF) as u8 != data {
                    return Err(RtsxError::TransferFailed);
                }
                return Ok(());
            }
        }
        Err(RtsxError::Timeout)
    }

    /// Read an internal register via HAIMR.
    ///
    /// Encoding per Linux `rtsx_pci_read_register`: TRANS_START |
    /// (addr & 0x3FFF) << 16 (WRITE bit clear); on completion
    /// bits[7:0] hold the register value.
    pub fn haimr_read(&self, addr: u16) -> Result<u8, RtsxError> {
        let val = HAIMR_TRANS_START | (((addr as u32) & HAIMR_ADDR_MASK) << 16);
        self.write32(HAIMR, val);
        for _ in 0..1024 {
            let r = self.read32(HAIMR);
            if r & HAIMR_TRANS_START == 0 {
                return Ok((r & 0xFF) as u8);
            }
        }
        Err(RtsxError::Timeout)
    }

    /// Dispatch a pre-built `CmdBuf` via the host-command-buffer engine.
    ///
    /// The serialised entries are written into the DMA page, HCBAR is
    /// loaded with the page's physical address, and HCBCTLR is written
    /// with TRIGGER | HW_AUTO_RSP | byte-length — the exact
    /// programming of Linux `rtsx_pci_send_cmd_no_wait`.  Completion
    /// is polled via BIPR.TRANS_OK / BIPR.TRANS_FAIL (the bits
    /// `rtsx_pci_send_cmd` waits on through its IRQ handler).
    ///
    /// On success the batch's response area (READ/CHECK results, in
    /// entry order) is copied into `resp` from the start of the page.
    pub fn dispatch_cmd_buf(&self, buf: &CmdBuf, resp: &mut [u8]) -> Result<(), RtsxError> {
        if buf.is_empty() {
            return Ok(());
        }
        let n = buf.len();

        // Serialise entries into the DMA page.
        let mut bytes = [0u8; cmd::CMD_BUF_ENTRIES * 4];
        buf.serialise(&mut bytes[..n * 4]);
        self.transport.cmd_buf_write(0, &bytes[..n * 4]);

        compiler_fence(Ordering::SeqCst);

        // Clear stale completion bits (W1C) so the poll below cannot
        // observe a previous batch's result.
        self.write32(BIPR, BIPR_CMD_DONE | BIPR_TRANS_OK | BIPR_TRANS_FAIL);

        // Program HCBAR + trigger the engine.
        self.write32(HCBAR, self.transport.cmd_buf_dma_addr());
        let ctl = HCBCTLR_TRIGGER | HCBCTLR_HW_AUTO_RSP | ((n as u32 * 4) & HCBCTLR_LEN_MASK);
        self.write32(HCBCTLR, ctl);

        compiler_fence(Ordering::SeqCst);

        // Poll BIPR for completion — bounded spin.
        for _ in 0..500_000 {
            let bipr = self.read32(BIPR);
            if bipr & BIPR_TRANS_FAIL != 0 {
                self.write32(BIPR, BIPR_TRANS_FAIL);
                return Err(RtsxError::TransferFailed);
            }
            if bipr & BIPR_TRANS_OK != 0 {
                self.write32(BIPR, BIPR_TRANS_OK);
                if !resp.is_empty() {
                    self.transport.cmd_buf_read(0, resp);
                }
                return Ok(());
            }
        }
        Err(RtsxError::Timeout)
    }

    /// Controller-level hardware init (the SD-relevant subset of
    /// Linux `rtsx_pci_init_hw`): unmask the completion/card
    /// interrupts in BIER (this driver polls BIPR, but the enable
    /// state matches Linux `rtsx_pci_enable_bus_int`) and power the
    /// SSC clock source via FPDCTL. Chip-specific PHY/SSC tuning from
    /// the per-chip `pcr_ops` is out of scope for this driver.
    pub fn init_controller(&self) -> Result<(), RtsxError> {
        self.write32(BIER, BIER_TRANS_OK_EN | BIER_TRANS_FAIL_EN | BIER_SD_INT_EN);
        // Power on SSC (clear SSC_POWER_DOWN).
        self.haimr_write(FPDCTL, SSC_POWER_DOWN, 0)?;
        Ok(())
    }

    /// Enable the SD slot: two-step card power ramp (partial → full,
    /// the per-chip `card_power_on` pattern from `rts5227.c`), then
    /// select mux / output enable / clock enable, then the
    /// identification bus configuration (1-bit, divided clock).
    pub fn enable_sd_slot(&self) -> Result<(), RtsxError> {
        // Power step 1: partial power on.
        let mut buf = CmdBuf::new();
        buf.push_write(CARD_PWR_CTL, SD_POWER_MASK, SD_PARTIAL_POWER_ON);
        self.dispatch_cmd_buf(&buf, &mut [])?;

        // Power step 2: full power on + connect the SD interface.
        let mut buf = CmdBuf::new();
        buf.push_write(CARD_PWR_CTL, SD_POWER_MASK, SD_POWER_ON);
        for (addr, mask, data) in card::enable_sd_slot_cmds().iter().copied() {
            buf.push_write(addr, mask, data);
        }
        self.dispatch_cmd_buf(&buf, &mut [])?;

        // Identification bus state: 1-bit width, SD_CLK_DIVIDE_128.
        let mut buf = CmdBuf::new();
        for (addr, mask, data) in card::init_bus_width_cmds().iter().copied() {
            buf.push_write(addr, mask, data);
        }
        buf.push_write(SD_CFG1, SD_CLK_DIVIDE_MASK, SD_CLK_DIVIDE_128);
        self.dispatch_cmd_buf(&buf, &mut [])
    }

    /// Disable the SD slot: clock off, power off.
    pub fn disable_sd_slot(&self) -> Result<(), RtsxError> {
        let mut buf = CmdBuf::new();
        buf.push_write(CARD_CLK_EN, SD_CLK_EN, 0);
        buf.push_write(CARD_PWR_CTL, SD_POWER_MASK, SD_POWER_OFF);
        self.dispatch_cmd_buf(&buf, &mut [])
    }

    /// Program the SD_CFG1 clock divider field (identification uses
    /// SD_CLK_DIVIDE_128; data transfers run at SD_CLK_DIVIDE_0).
    fn set_clock_divide(&self, divide: u8) -> Result<(), RtsxError> {
        self.haimr_write(SD_CFG1, SD_CLK_DIVIDE_MASK, divide)
    }

    /// Issue a single SD command via the host-command-buffer engine
    /// and decode its response.
    ///
    /// The batch is the one Linux `sd_send_cmd_get_rsp`
    /// (`rtsx_pci_sdmmc.c`) builds: SD_CMD0..SD_CMD4 ← command frame
    /// (the controller generates CRC7 — SD_CMD5 is never written),
    /// SD_CFG2 ← the response-type byte, CARD_DATA_SOURCE ←
    /// PINGPONG_BUFFER, SD_TRANSFER ← SD_TM_CMD_RSP | START, then a
    /// CHECK_REG on SD_TRANSFER for (END | IDLE).  Short responses are
    /// read back from SD_CMD0..SD_CMD4 (the controller overwrites them
    /// with the response frame) plus SD_STAT1 for the CRC7 verdict;
    /// R2 responses are read from the ping-pong buffer plus SD_STAT1.
    ///
    /// The response area layout in the command page is therefore:
    /// `[check_result, read_results..., stat1]` — the check byte is
    /// skipped, exactly as Linux skips rsp_buf[0].
    pub fn issue_sd_cmd(&self, cmd: &SdCmd) -> Result<SdResponse, RtsxError> {
        let frame = build_sd_cmd_frame(cmd.index, cmd.arg);

        let mut buf = CmdBuf::new();
        // Command frame: header + argument only (5 bytes).
        buf.push_write(SD_CMD0, 0xFF, frame[0]);
        buf.push_write(SD_CMD1, 0xFF, frame[1]);
        buf.push_write(SD_CMD2, 0xFF, frame[2]);
        buf.push_write(SD_CMD3, 0xFF, frame[3]);
        buf.push_write(SD_CMD4, 0xFF, frame[4]);
        // Response configuration + data source.
        buf.push_write(SD_CFG2, 0xFF, cmd.rsp.cfg2());
        buf.push_write(CARD_DATA_SOURCE, CARD_DATA_SOURCE_MASK, PINGPONG_BUFFER);
        // Kick the command/response transfer.
        buf.push_write(SD_TRANSFER, 0xFF, SD_TM_CMD_RSP | SD_TRANSFER_START);
        buf.push_check(
            SD_TRANSFER,
            SD_TRANSFER_END | SD_STAT_IDLE,
            SD_TRANSFER_END | SD_STAT_IDLE,
        );
        // Response readback.
        if cmd.rsp.is_long() {
            for i in 0..16u16 {
                buf.push_read(PPBUF_BASE2 + i);
            }
            buf.push_read(SD_STAT1);
        } else if !matches!(cmd.rsp, card::RspType::None) {
            buf.push_read(SD_CMD0);
            buf.push_read(SD_CMD1);
            buf.push_read(SD_CMD2);
            buf.push_read(SD_CMD3);
            buf.push_read(SD_CMD4);
            buf.push_read(SD_STAT1);
        }

        // Response area: 1 check byte + read results.
        let mut resp = [0u8; 20];
        let resp_len = match cmd.rsp {
            card::RspType::None => 1,
            card::RspType::R2 => 18,
            _ => 7,
        };
        self.dispatch_cmd_buf(&buf, &mut resp[..resp_len])?;

        match cmd.rsp {
            card::RspType::None => Ok(SdResponse::None),
            card::RspType::R2 => {
                // resp[1] = first PPBUF byte (response header).
                if resp[1] & 0xC0 != 0 {
                    return Err(RtsxError::BadResponse);
                }
                if cmd.rsp.crc_checked() && (resp[17] & SD_STAT1_CRC7_ERR) != 0 {
                    return Err(RtsxError::CrcError);
                }
                let mut frame16 = [0u8; 16];
                frame16.copy_from_slice(&resp[1..17]);
                Ok(SdResponse::Long(card::r2_frame_to_shifted_words(&frame16)))
            }
            _ => {
                // resp[1] = response header byte (SD_CMD0 echo).
                if resp[1] & 0xC0 != 0 {
                    return Err(RtsxError::BadResponse);
                }
                // R3's header is the all-ones 0x3F; every other short
                // response echoes its command index in the header.
                if !matches!(cmd.rsp, card::RspType::R3) && (resp[1] & 0x3F) != cmd.index {
                    return Err(RtsxError::BadResponse);
                }
                if cmd.rsp.crc_checked() && (resp[6] & SD_STAT1_CRC7_ERR) != 0 {
                    return Err(RtsxError::CrcError);
                }
                let value = ((resp[2] as u32) << 24)
                    | ((resp[3] as u32) << 16)
                    | ((resp[4] as u32) << 8)
                    | (resp[5] as u32);
                Ok(SdResponse::Short(value))
            }
        }
    }

    /// Read `out.len()` bytes (≤ 512) from the ping-pong buffer, in
    /// ≤ 256-byte command batches — Linux `rtsx_pci_read_ppbuf`.
    fn read_ppbuf(&self, out: &mut [u8]) -> Result<(), RtsxError> {
        let mut done = 0usize;
        while done < out.len() {
            let chunk = core::cmp::min(256, out.len() - done);
            let mut buf = CmdBuf::new();
            for i in 0..chunk {
                buf.push_read(PPBUF_BASE2 + (done + i) as u16);
            }
            self.dispatch_cmd_buf(&buf, &mut out[done..done + chunk])?;
            done += chunk;
        }
        Ok(())
    }

    /// Write `data` (≤ 512 bytes) into the ping-pong buffer, in
    /// ≤ 256-byte command batches — Linux `rtsx_pci_write_ppbuf`.
    fn write_ppbuf(&self, data: &[u8]) -> Result<(), RtsxError> {
        let mut done = 0usize;
        while done < data.len() {
            let chunk = core::cmp::min(256, data.len() - done);
            let mut buf = CmdBuf::new();
            for i in 0..chunk {
                buf.push_write(PPBUF_BASE2 + (done + i) as u16, 0xFF, data[done + i]);
            }
            self.dispatch_cmd_buf(&buf, &mut [])?;
            done += chunk;
        }
        Ok(())
    }

    /// Build the shared staging writes for a single-block data
    /// transfer (command frame, CFG2, byte/block counts, data source).
    fn stage_data_transfer(buf: &mut CmdBuf, cmd: &SdCmd) {
        let frame = build_sd_cmd_frame(cmd.index, cmd.arg);
        buf.push_write(SD_CMD0, 0xFF, frame[0]);
        buf.push_write(SD_CMD1, 0xFF, frame[1]);
        buf.push_write(SD_CMD2, 0xFF, frame[2]);
        buf.push_write(SD_CMD3, 0xFF, frame[3]);
        buf.push_write(SD_CMD4, 0xFF, frame[4]);
        buf.push_write(SD_CFG2, 0xFF, SD_CFG2_DATA_R1);
        // 512 bytes per block, 1 block.
        buf.push_write(SD_BYTE_CNT_L, 0xFF, 0x00);
        buf.push_write(SD_BYTE_CNT_H, 0xFF, 0x02);
        buf.push_write(SD_BLOCK_CNT_L, 0xFF, 0x01);
        buf.push_write(SD_BLOCK_CNT_H, 0xFF, 0x00);
        buf.push_write(CARD_DATA_SOURCE, CARD_DATA_SOURCE_MASK, PINGPONG_BUFFER);
    }

    /// Read one 512-byte block from the card at `addr` into `out`.
    ///
    /// CMD17 via SD_TM_NORMAL_READ with the ping-pong buffer as the
    /// data source (Linux `sd_read_data` in `rtsx_pci_sdmmc.c`), then
    /// the block is drained from PPBUF.  For SDHC/SDXC `addr` is the
    /// block address; for SDSC it is the byte address (the block
    /// bridge performs the ×512 conversion).
    pub fn read_block(&self, addr: u32, out: &mut [u8; 512]) -> Result<(), RtsxError> {
        if !self.sd_slot.is_ready() {
            return Err(RtsxError::NoCard);
        }
        let mut buf = CmdBuf::new();
        Self::stage_data_transfer(&mut buf, &SdCmd::read_single_block(addr));
        buf.push_write(SD_TRANSFER, 0xFF, SD_TM_NORMAL_READ | SD_TRANSFER_START);
        buf.push_check(
            SD_TRANSFER,
            SD_TRANSFER_END | SD_STAT_IDLE,
            SD_TRANSFER_END | SD_STAT_IDLE,
        );
        self.dispatch_cmd_buf(&buf, &mut [])?;
        self.read_ppbuf(out)
    }

    /// Write one 512-byte block from `data` to the card at `addr`.
    ///
    /// The block is staged into PPBUF first, then CMD24 runs via
    /// SD_TM_AUTO_WRITE_2 (Linux `sd_write_data` in
    /// `rtsx_pci_sdmmc.c`).  Addressing rules match `read_block`.
    pub fn write_block(&self, addr: u32, data: &[u8; 512]) -> Result<(), RtsxError> {
        if !self.sd_slot.is_ready() {
            return Err(RtsxError::NoCard);
        }
        self.write_ppbuf(data)?;
        let mut buf = CmdBuf::new();
        Self::stage_data_transfer(&mut buf, &SdCmd::write_block(addr));
        buf.push_write(SD_TRANSFER, 0xFF, SD_TM_AUTO_WRITE_2 | SD_TRANSFER_START);
        buf.push_check(
            SD_TRANSFER,
            SD_TRANSFER_END | SD_STAT_IDLE,
            SD_TRANSFER_END | SD_STAT_IDLE,
        );
        self.dispatch_cmd_buf(&buf, &mut [])
    }

    /// Run the SD card identification sequence.
    ///
    /// Fails with a typed error when the card does not answer, never
    /// becomes ready, answers garbage, or presents a CSD that does not
    /// parse — capacity always comes from the card's real CMD9/CSD.
    pub fn identify_sd_card(&mut self) -> Result<SdCardInfo, RtsxError> {
        // CMD0: reset card to idle (no response).
        match self.issue_sd_cmd(&SdCmd::go_idle())? {
            SdResponse::None => {}
            _ => return Err(RtsxError::BadResponse),
        }

        // CMD8: SD 2.0+ interface-condition check. A v1.x card does
        // not answer; that is a version signal, not an error.
        let is_v2 = match self.issue_sd_cmd(&SdCmd::send_if_cond()) {
            Ok(SdResponse::Short(r)) => {
                let (v_ok, pat_ok) = card::decode_r7(r);
                v_ok && pat_ok
            }
            _ => false,
        };

        // CMD55 + ACMD41 loop until OCR.BUSY (bit 31) is set.
        let mut ocr: u32 = 0;
        for _ in 0..1000 {
            let _ = self.issue_sd_cmd(&SdCmd::app_cmd_prefix());
            ocr = match self.issue_sd_cmd(&SdCmd::acmd41(is_v2)) {
                Ok(SdResponse::Short(r)) => r,
                _ => 0,
            };
            if ocr & (1 << 31) != 0 {
                break;
            }
        }
        if ocr & (1 << 31) == 0 {
            return Err(RtsxError::Timeout);
        }
        let high_capacity = (ocr & (1 << 30)) != 0;

        // CMD2: capture the real CID (identity for sysfs + fixtures).
        let cid = match self.issue_sd_cmd(&SdCmd::all_send_cid())? {
            SdResponse::Long(w) => w,
            _ => return Err(RtsxError::BadResponse),
        };

        // CMD3: get RCA. A zero RCA is a garbage answer.
        let rca = match self.issue_sd_cmd(&SdCmd::send_relative_addr())? {
            SdResponse::Short(r) => card::r6_rca(r),
            _ => return Err(RtsxError::BadResponse),
        };
        if rca == 0 {
            return Err(RtsxError::BadResponse);
        }

        // CMD9: read the CSD and decode the REAL capacity. An
        // unparseable CSD is a typed failure — never a default.
        let csd_words = match self.issue_sd_cmd(&SdCmd::send_csd(rca))? {
            SdResponse::Long(w) => w,
            _ => return Err(RtsxError::BadResponse),
        };
        let csd = Csd::parse_shifted(&csd_words).ok_or(RtsxError::BadResponse)?;
        if csd.capacity_bytes < 512 {
            return Err(RtsxError::BadResponse);
        }
        let capacity_blocks = csd.capacity_bytes / 512;

        // CMD7: select the card (transfer state).
        match self.issue_sd_cmd(&SdCmd::select_card(rca))? {
            SdResponse::Short(_) => {}
            _ => return Err(RtsxError::BadResponse),
        }

        // SDSC cards are byte-addressed; pin the block length to 512
        // so the block layer's addressing is uniform.
        if !high_capacity {
            match self.issue_sd_cmd(&SdCmd::set_blocklen(512))? {
                SdResponse::Short(_) => {}
                _ => return Err(RtsxError::BadResponse),
            }
        }

        // Identification is done: run the bus at full clock.
        self.set_clock_divide(SD_CLK_DIVIDE_0)?;

        Ok(SdCardInfo {
            rca,
            high_capacity,
            capacity_blocks,
            selected: true,
            cid,
        })
    }

    /// Check whether an SD card is currently inserted (reads BIPR).
    pub fn card_inserted(&self) -> bool {
        card::sd_card_detected(self.read32(BIPR))
    }

    /// Device ID of this controller.
    pub fn device_id(&self) -> u16 {
        self.device_id
    }

    /// One card-detect service step: reconcile `sd_slot` with the
    /// physical slot.  On insertion this enables the slot, identifies
    /// the card, and returns the registration action for the caller
    /// (registration happens outside the controller lock); on removal
    /// of a ready card it powers the slot down and returns the
    /// unregistration action.
    pub fn service_slot(&mut self) -> Option<SlotAction> {
        if self.card_inserted() {
            if self.sd_slot.is_ready() {
                return None;
            }
            match self.enable_sd_slot().and_then(|_| self.identify_sd_card()) {
                Ok(info) => {
                    self.sd_slot = SlotState::Ready(info);
                    Some(SlotAction::Register(info))
                }
                Err(_) => {
                    self.sd_slot = SlotState::Error;
                    None
                }
            }
        } else {
            match self.sd_slot {
                SlotState::Ready(info) => {
                    let _ = self.disable_sd_slot();
                    self.sd_slot = SlotState::Empty;
                    Some(SlotAction::Unregister(info))
                }
                SlotState::Error => {
                    let _ = self.disable_sd_slot();
                    self.sd_slot = SlotState::Empty;
                    None
                }
                _ => None,
            }
        }
    }
}

/// Registration action produced by `RtsxController::service_slot`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlotAction {
    /// A card was identified; publish it in the block registry.
    Register(SdCardInfo),
    /// A previously published card was removed; unpublish it.
    Unregister(SdCardInfo),
}

// ── Card-detect polling ─────────────────────────────────────────────

/// Service the global controller's slot once, performing any block
/// registry registration/unregistration the service step produced.
/// Called from the probe path (a card may already be inserted at
/// boot) and from the card-poll task.
pub fn poll_card_slot() {
    let action = {
        let mut g = RTSX.lock();
        match g.as_mut() {
            Some(c) => c.service_slot(),
            None => None,
        }
    };
    match action {
        Some(SlotAction::Register(info)) => block_bridge::register_card(info),
        Some(SlotAction::Unregister(info)) => block_bridge::unregister_card(info),
        None => {}
    }
}

/// Spawn the card-detect poll task (Stage::Late; production wiring
/// lives in the storage facade).  Linux `rtsx_pcr` learns about
/// insertion from the SD_INT interrupt + a 200 ms debounce work item;
/// this driver has no IRQ handler registered, so it polls BIPR's
/// SD_EXIST level on a 500 ms cadence instead.
pub fn spawn_card_poll_task() {
    narf_scheduler::spawn_stackful(async {
        loop {
            poll_card_slot();
            narf_time::sleep_cycles(narf_time::ns_to_cycles(500_000_000)).await;
        }
    });
}

// ── PCI driver registration ───────────────────────────────────────

/// Register all supported RTSX device IDs with the PCI bus driver.
pub fn register_pci_driver() {
    for (did, name) in RTSX_DEVICE_IDS.iter().copied() {
        bus_register_pci_driver(PciMatch {
            name,
            kind: MatchKind::VendorDevice {
                vendor: RTSX_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// PCI probe callback — called when the bus matches an RTSX device.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError> {
    // Check the device ID matches one we know.
    let did = device.id.device;
    if !RTSX_DEVICE_IDS.iter().any(|(id, _)| *id == did) {
        return Err(ProbeError::NotForThisDriver);
    }

    let controller =
        // SAFETY: we own the device; PCI enumeration provides exclusive access.
        unsafe { RtsxController::new(&device, &cap, did) }.map_err(|_| ProbeError::BadDevice)?;

    controller
        .init_controller()
        .map_err(|_| ProbeError::BadDevice)?;

    *RTSX.lock() = Some(controller);
    PROBE_COUNT.fetch_add(1, Ordering::Relaxed);

    // A card may already be inserted at probe time (no card-detect
    // interrupt will fire for it — the same caveat Linux `rtsx_pci_init_hw`
    // documents), so service the slot once synchronously.
    poll_card_slot();
    Ok(())
}

/// Execute a closure with the global RTSX controller, returning `None`
/// if the controller has not been probed.
pub fn with_controller<R>(f: impl FnOnce(&mut RtsxController) -> R) -> Option<R> {
    let mut g = RTSX.lock();
    g.as_mut().map(f)
}

/// Returns `true` if at least one RTSX controller has been probed.
pub fn is_probed() -> bool {
    PROBE_COUNT.load(Ordering::Relaxed) > 0
}

/// Test-only: reset probe state.
#[doc(hidden)]
pub fn __reset_for_test() {
    *RTSX.lock() = None;
    PROBE_COUNT.store(0, Ordering::Relaxed);
}

/// Test-only: install a controller over a fixture transport and run
/// controller init against it, so tests drive the same global
/// registration paths production uses.
#[doc(hidden)]
pub fn __install_for_test(transport: Arc<dyn RtsxTransport>, device_id: u16) {
    let controller = RtsxController::with_transport(transport, device_id);
    let _ = controller.init_controller();
    *RTSX.lock() = Some(controller);
    PROBE_COUNT.fetch_add(1, Ordering::Relaxed);
}

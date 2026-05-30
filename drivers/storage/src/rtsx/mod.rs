//! Realtek RTSX PCIe SD/microSD card-reader driver.
//!
//! ## Architecture
//!
//! The RTSX chip presents a single PCIe function (Realtek vendor 0x10EC)
//! that embeds an SD card reader (and optionally MS/XD readers on older
//! revisions).  The driver maps BAR0 and uses two mechanisms:
//!
//! 1. **Host command buffer** — a DMA-coherent page that holds a batch
//!    of up to 256 4-byte `(type, addr, mask, data)` tuples.  The
//!    entire batch is dispatched atomically by writing the entry count
//!    to HCBCTLR.  The hardware writes BIPR.CMD_DONE when finished.
//!
//! 2. **Host data buffer** — a second DMA-coherent page used for DMA
//!    transfers (SD block reads / writes).  The hardware walks this
//!    page as a scatter-gather list; BIPR.TRANS_OK / BIPR.TRANS_FAIL
//!    signal completion.
//!
//! ## SD card sequence
//!
//! ```text
//! power-on → CMD0 → CMD8 → CMD55+ACMD41 (loop until OCR.BUSY) →
//!   CMD2 (CID) → CMD3 (RCA) → CMD7 (SELECT) → ready
//! ```
//!
//! ## References
//!
//! - Linux `drivers/misc/cardreader/rtsx_pcr.c` (GPL-2.0-or-later)
//! - Linux `drivers/mmc/host/rtsx_pci_sdmmc.c` (GPL-2.0-or-later)
//! - Linux `include/linux/rtsx_pci.h` (GPL-2.0-or-later)
//!
//! Cited and adapted under NARF's GPL-2.0-or-later licence.

pub mod card;
pub mod cmd;
pub mod regs;

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{
    map_bar, register_pci_driver as bus_register_pci_driver, BusDevice, BusDeviceCap, MatchKind,
    MmioRegion, PciMatch, ProbeError,
};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use card::{SlotState, SdCardInfo, SdCmd};
use cmd::{build_sd_cmd_frame, CmdBuf};
use regs::*;

// ── PCI device IDs ────────────────────────────────────────────────

/// Realtek vendor ID.
/// Linux `rtsx_pcr.c:44` — `PCI_DEVICE(0x10EC, ...)`
pub const RTSX_VENDOR: u16 = 0x10EC;

/// Supported Realtek RTSX PCIe card-reader device IDs.
/// Linux `drivers/misc/cardreader/rtsx_pcr.c:44–62` (GPL-2.0-or-later).
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
static PROBE_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

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
    /// A data transfer reported an error in BIPR.
    TransferFailed,
    /// Command buffer overflow.
    CmdBufFull,
    /// No card present or card not ready.
    NoCard,
}

// ── Controller ────────────────────────────────────────────────────

/// Live RTSX card-reader controller.
pub struct RtsxController {
    mmio: MmioRegion,
    /// Device ID (used for chip-specific quirks).
    pub device_id: u16,
    /// DMA-coherent page for the host command buffer.
    cmd_buf: DmaBuffer,
    /// DMA-coherent page for the host data buffer.
    data_buf: DmaBuffer,
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

impl RtsxController {
    /// Map BAR0 and allocate DMA buffers.
    ///
    /// # Safety
    /// Caller must own the device's BAR0 exclusively.
    pub unsafe fn new(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
        device_id: u16,
    ) -> Result<Self, RtsxError> {
        // SAFETY: caller-authority.
        let mmio = unsafe { map_bar(device, RTSX_BAR) }
            .map_err(|_| RtsxError::BarMapFailed)?;

        let cmd_buf = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| RtsxError::DmaAllocFailed)?;
        let data_buf = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| RtsxError::DmaAllocFailed)?;

        Ok(RtsxController {
            mmio,
            device_id,
            cmd_buf,
            data_buf,
            sd_slot: SlotState::Empty,
        })
    }

    /// Read a 32-bit HBA register at `offset` from BAR0.
    ///
    /// # Safety
    /// `offset` must be a valid BAR0 register offset.
    #[inline]
    pub unsafe fn read32(&self, offset: u64) -> u32 {
        // SAFETY: identity-mapped MMIO; caller-validated offset.
        unsafe { self.mmio.read32(offset) }
    }

    /// Write a 32-bit HBA register.
    ///
    /// # Safety
    /// `offset` must be a valid BAR0 register offset.
    #[inline]
    pub unsafe fn write32(&self, offset: u64, val: u32) {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.write32(offset, val) }
    }

    /// Write to an internal register via the HAIMR single-access path.
    ///
    /// The HAIMR register holds `write=1 | (addr << 16) | (mask << 8) | data`
    /// and the hardware clears bit 31 when the write completes.
    ///
    /// # Safety
    /// Caller must not issue concurrent HAIMR or cmd-buffer transactions.
    pub unsafe fn haimr_write(&self, addr: u16, mask: u8, data: u8) -> Result<(), RtsxError> {
        let val = HAIMR_WRITE
            | ((addr as u32) << 16)
            | ((mask as u32) << 8)
            | (data as u32);
        // SAFETY: identity-mapped MMIO.
        unsafe { self.write32(HAIMR, val) }

        // Poll until HAIMR_VALID (bit 31) clears — hardware done.
        // Bounded by 10 000 iterations (~10 µs at 1 GHz).
        for _ in 0..10_000 {
            // SAFETY: same.
            let r = unsafe { self.read32(HAIMR) };
            if r & HAIMR_VALID == 0 {
                return Ok(());
            }
        }
        Err(RtsxError::Timeout)
    }

    /// Read an internal register via HAIMR.
    ///
    /// # Safety
    /// Same as `haimr_write`.
    pub unsafe fn haimr_read(&self, addr: u16) -> Result<u8, RtsxError> {
        let val = HAIMR_READ | ((addr as u32) << 16);
        // SAFETY: identity-mapped MMIO.
        unsafe { self.write32(HAIMR, val) }
        for _ in 0..10_000 {
            // SAFETY: same.
            let r = unsafe { self.read32(HAIMR) };
            if r & HAIMR_READ == 0 {
                // Bits[7:0] hold the read result.
                return Ok((r & 0xFF) as u8);
            }
        }
        Err(RtsxError::Timeout)
    }

    /// Dispatch a pre-built `CmdBuf` via the host-command-buffer engine.
    ///
    /// The serialised entries are written into the DMA page, then
    /// HCBAR is loaded with the physical address and HCBCTLR is
    /// written with the entry count to start the engine.  Completion
    /// is polled via BIPR.CMD_DONE (W1C).
    ///
    /// # Safety
    /// `buf.len() > 0`.  Caller must serialise; no concurrent engine use.
    pub unsafe fn dispatch_cmd_buf(&self, buf: &CmdBuf) -> Result<(), RtsxError> {
        if buf.len() == 0 {
            return Ok(());
        }
        let n = buf.len();
        let phys = self.cmd_buf.phys_addr().raw();

        // Serialise entries into the DMA page.
        // SAFETY: identity-mapped DMA page; exclusive access.
        unsafe {
            let ptr = self.cmd_buf.as_mut_ptr() as *mut u8;
            let slice = core::slice::from_raw_parts_mut(ptr, n * 4);
            buf.serialise(slice);
        }

        compiler_fence(Ordering::SeqCst);

        // Program HCBAR with the physical address of the command buffer.
        // SAFETY: identity-mapped MMIO.
        unsafe { self.write32(HCBAR, phys as u32) }

        // Start engine: write entry count to HCBCTLR.
        // Linux `rtsx_pcr.c::rtsx_pci_send_cmd`: writes (n & 0xFF)
        // to trigger, plus the CMD_DONE_INT_EN bit if interrupts are
        // wired. We poll BIPR for simplicity (same as the sync path
        // in the Linux driver on init).
        // SAFETY: identity-mapped MMIO.
        unsafe { self.write32(HCBCTLR, (n as u32) & 0xFF) }

        compiler_fence(Ordering::SeqCst);

        // Poll BIPR.CMD_DONE — bounded spin (≤ 5 ms for internal regs).
        for _ in 0..500_000 {
            // SAFETY: identity-mapped MMIO.
            let bipr = unsafe { self.read32(BIPR) };
            if bipr & BIPR_CMD_DONE != 0 {
                // W1C: clear the bit.
                // SAFETY: same.
                unsafe { self.write32(BIPR, BIPR_CMD_DONE) }
                return Ok(());
            }
        }
        Err(RtsxError::Timeout)
    }

    /// Poll `BIPR` until `BIPR_TRANS_OK` or `BIPR_TRANS_FAIL` is set,
    /// then clear it.  Called after kicking off a data DMA.
    ///
    /// # Safety
    /// A DMA data transfer must have been started before calling this.
    pub unsafe fn wait_data_done(&self) -> Result<(), RtsxError> {
        for _ in 0..5_000_000 {
            // SAFETY: identity-mapped MMIO.
            let bipr = unsafe { self.read32(BIPR) };
            if bipr & BIPR_TRANS_FAIL != 0 {
                // Clear W1C bits.
                // SAFETY: same.
                unsafe { self.write32(BIPR, BIPR_TRANS_FAIL | BIPR_TRANS_OK) }
                return Err(RtsxError::TransferFailed);
            }
            if bipr & BIPR_TRANS_OK != 0 {
                // SAFETY: same.
                unsafe { self.write32(BIPR, BIPR_TRANS_OK) }
                return Ok(());
            }
        }
        Err(RtsxError::Timeout)
    }

    /// Enable the SD slot: card-select mux, output enable, clock.
    ///
    /// # Safety
    /// Controller must be in a quiescent state.
    pub unsafe fn enable_sd_slot(&self) -> Result<(), RtsxError> {
        let cmds = card::enable_sd_slot_cmds();
        let mut buf = CmdBuf::new();
        for (addr, mask, data) in cmds.iter().copied() {
            buf.push_write(addr, mask, data);
        }
        // SAFETY: delegated contract.
        unsafe { self.dispatch_cmd_buf(&buf) }
    }

    /// Issue a single SD command via the host-command-buffer engine
    /// and return the first 32 bits of the response.
    ///
    /// The command frame is written into SD_CMD0..SD_CMD5 via
    /// WRITE_REG entries, then SD_TRANSFER is kicked.  The engine
    /// polls SD_CMD_STATE internally; we wait for BIPR.CMD_DONE.
    ///
    /// # Safety
    /// SD slot must be enabled; `cmd.index < 64`.
    pub unsafe fn issue_sd_cmd(
        &self,
        cmd: &SdCmd,
    ) -> Result<u32, RtsxError> {
        let frame = build_sd_cmd_frame(cmd.index, cmd.arg);

        let mut buf = CmdBuf::new();

        // Write the 6-byte command frame.
        buf.push_write(SD_CMD0, 0xFF, frame[0]);
        buf.push_write(SD_CMD1, 0xFF, frame[1]);
        buf.push_write(SD_CMD2, 0xFF, frame[2]);
        buf.push_write(SD_CMD3, 0xFF, frame[3]);
        buf.push_write(SD_CMD4, 0xFF, frame[4]);
        buf.push_write(SD_CMD5, 0xFF, frame[5]);

        // Set the transfer-mode byte: send command, no data phase for
        // a pure command/response exchange.
        let tf = SD_TRANSFER_START | SD_TF_NORMAL | SD_SEND_CMD;
        buf.push_write(SD_TRANSFER, 0xFF, tf);

        // Append a CHECK_REG for SD_CMD_STATE: wait until bit 7 = 0
        // (idle).  The engine stalls here until the SD PHY finishes.
        buf.push_check(SD_CMD_STATE, SD_CMD_BUSY, 0x00);

        // Read back SD_CMD2..SD_CMD5 to capture the response.
        buf.push_read(SD_CMD2);
        buf.push_read(SD_CMD3);
        buf.push_read(SD_CMD4);
        buf.push_read(SD_CMD5);

        // SAFETY: delegated contract.
        unsafe { self.dispatch_cmd_buf(&buf) }?;

        // The response bytes are written back to the read-result slots
        // in the DMA page (starting at byte n_writes * 4 per Linux
        // rtsx_pci_add_cmd layout).  For simplicity we re-read via HAIMR.
        // SAFETY: HAIMR read is safe here (no concurrent engine use).
        let b2 = unsafe { self.haimr_read(SD_CMD2)? };
        let b3 = unsafe { self.haimr_read(SD_CMD3)? };
        let b4 = unsafe { self.haimr_read(SD_CMD4)? };
        let b5 = unsafe { self.haimr_read(SD_CMD5)? };

        Ok(((b2 as u32) << 24)
            | ((b3 as u32) << 16)
            | ((b4 as u32) << 8)
            | (b5 as u32))
    }

    /// Run the SD card identification sequence.
    ///
    /// # Safety
    /// SD slot must be enabled and powered.
    pub unsafe fn identify_sd_card(&mut self) -> Result<SdCardInfo, RtsxError> {
        // CMD0: reset card to idle.
        // SAFETY: delegated.
        unsafe { self.issue_sd_cmd(&SdCmd::go_idle()) }.ok(); // no response expected

        // CMD8: check if SD 2.0+.  Ignore error (SD 1.x won't respond).
        let is_v2 = unsafe { self.issue_sd_cmd(&SdCmd::send_if_cond()) }
            .map(|r| {
                let (v_ok, pat_ok) = card::decode_r7(r);
                v_ok && pat_ok
            })
            .unwrap_or(false);

        // CMD55 + ACMD41 loop until OCR.BUSY (bit 31) is set.
        let mut ocr: u32 = 0;
        for _ in 0..1000 {
            let _ = unsafe { self.issue_sd_cmd(&SdCmd::app_cmd_prefix()) };
            ocr = unsafe { self.issue_sd_cmd(&SdCmd::acmd41(is_v2)) }
                .unwrap_or(0);
            if ocr & (1 << 31) != 0 {
                break;
            }
        }
        if ocr & (1 << 31) == 0 {
            return Err(RtsxError::Timeout);
        }
        let high_capacity = (ocr & (1 << 30)) != 0;

        // CMD2: get CID (we don't parse it but it advances the state machine).
        let _ = unsafe { self.issue_sd_cmd(&SdCmd::all_send_cid()) };

        // CMD3: get RCA.
        let r6 = unsafe { self.issue_sd_cmd(&SdCmd::send_relative_addr()) }?;
        let rca = card::r6_rca(r6);

        // CMD7: select card.
        unsafe { self.issue_sd_cmd(&SdCmd::select_card(rca)) }?;

        Ok(SdCardInfo {
            rca,
            high_capacity,
            capacity_blocks: 0, // deferred — parsed from CSD by upper layer
            selected: true,
        })
    }

    /// Read one 512-byte sector from the card at `lba` into `out`.
    ///
    /// Uses CMD17 (READ_SINGLE_BLOCK) via the command engine + data
    /// DMA path.  For SDHC/SDXC `lba` is the block address; for SDSC
    /// it must be multiplied by 512 (the MMC layer handles this).
    ///
    /// # Safety
    /// Card must be selected and ready (`sd_slot == SlotState::Ready`).
    /// `out.len() >= 512`.
    pub unsafe fn read_block_dma(&self, lba: u32, out: &mut [u8]) -> Result<(), RtsxError> {
        if out.len() < 512 {
            return Err(RtsxError::NoCard);
        }
        let data_phys = self.data_buf.phys_addr().raw();

        // Issue CMD17.
        let mut buf = CmdBuf::new();
        let frame = build_sd_cmd_frame(17, lba);
        buf.push_write(SD_CMD0, 0xFF, frame[0]);
        buf.push_write(SD_CMD1, 0xFF, frame[1]);
        buf.push_write(SD_CMD2, 0xFF, frame[2]);
        buf.push_write(SD_CMD3, 0xFF, frame[3]);
        buf.push_write(SD_CMD4, 0xFF, frame[4]);
        buf.push_write(SD_CMD5, 0xFF, frame[5]);
        // Block count = 1, byte count = 512.
        buf.push_write(SD_BYTE_CNT_L, 0xFF, 0x00);
        buf.push_write(SD_BYTE_CNT_H, 0xFF, 0x02); // 0x0200 = 512
        buf.push_write(SD_BLOCK_CNT_L, 0xFF, 0x01);
        buf.push_write(SD_BLOCK_CNT_H, 0xFF, 0x00);
        // Start data read: SEND_CMD | BLOCK_XFER (no WRITE bit = read).
        let tf = SD_TRANSFER_START | SD_TF_NORMAL | SD_SEND_CMD | SD_BLOCK_XFER;
        buf.push_write(SD_TRANSFER, 0xFF, tf);
        buf.push_check(SD_CMD_STATE, SD_CMD_BUSY, 0x00);

        // SAFETY: delegated.
        unsafe { self.dispatch_cmd_buf(&buf) }?;

        // Configure DMA data buffer address and start the read.
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.write32(HDBAR, data_phys as u32);
            self.write32(HDBCTLR, HDBCTLR_START | HDBCTLR_DMA_READ | 512);
        }

        // SAFETY: delegated.
        unsafe { self.wait_data_done() }?;

        // Copy out from DMA page.
        // SAFETY: identity-mapped DMA page, 512 bytes filled by hardware.
        unsafe {
            let src = self.data_buf.as_ptr() as *const u8;
            core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), 512);
        }
        Ok(())
    }

    /// Check whether an SD card is currently inserted (reads BIPR).
    pub fn card_inserted(&self) -> bool {
        // SAFETY: identity-mapped MMIO; read-only.
        let bipr = unsafe { self.read32(BIPR) };
        card::sd_card_detected(bipr)
    }

    /// Device ID of this controller.
    pub fn device_id(&self) -> u16 {
        self.device_id
    }
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
pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), ProbeError> {
    // Check the device ID matches one we know.
    let did = device.id.device;
    if !RTSX_DEVICE_IDS.iter().any(|(id, _)| *id == did) {
        return Err(ProbeError::NotForThisDriver);
    }

    // SAFETY: we own the device; PCI enumeration provides exclusive access.
    let controller = unsafe { RtsxController::new(&device, &cap, did) }
        .map_err(|_| ProbeError::BadDevice)?;

    *RTSX.lock() = Some(controller);
    PROBE_COUNT.fetch_add(1, Ordering::Relaxed);
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

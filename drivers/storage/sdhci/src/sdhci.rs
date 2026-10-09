//! SD Host Controller — clean-room.
//!
//! Reference: **"SD Host Controller Simplified Specification"
//! Version 3.00**, SD Association (free PDF, sdcard.org). Section
//! numbers in comments below refer to this spec. The SD Physical
//! Layer Simplified Specification (also free) covers the protocol
//! sequence (CMD0 / CMD8 / ACMD41 / CMD2 / CMD3 / CMD7 / CMD17 /
//! CMD24).
//!   <https://www.sdcard.org/downloads/pls/>
//!
//! ## Layout
//!
//! BAR0 is the SDHCI MMIO window. The first 0x100 bytes are the
//! standard register block:
//!
//! | offset | name              | width |
//! |--------|-------------------|-------|
//! | 0x00   | SDMA System Addr  | u32   |
//! | 0x04   | Block Size        | u16   |
//! | 0x06   | Block Count       | u16   |
//! | 0x08   | Argument          | u32   |
//! | 0x0C   | Transfer Mode     | u16   |
//! | 0x0E   | Command           | u16   |
//! | 0x10   | Response 0..3     | u32×4 |
//! | 0x20   | Buffer Data Port  | u32   |
//! | 0x24   | Present State     | u32   |
//! | 0x28   | Host Control 1    | u8    |
//! | 0x29   | Power Control     | u8    |
//! | 0x2A   | Block Gap Control | u8    |
//! | 0x2B   | Wakeup Control    | u8    |
//! | 0x2C   | Clock Control     | u16   |
//! | 0x2E   | Timeout Control   | u8    |
//! | 0x2F   | Software Reset    | u8    |
//! | 0x30   | Normal Int Status | u16   |
//! | 0x32   | Error Int Status  | u16   |
//! | 0x40   | Capabilities      | u64   |
//!
//! Stage cut: bring up the host controller, supply a 400 kHz init
//! clock, run the SD identification sequence (CMD0 / CMD8 /
//! ACMD41 / CMD2 / CMD3 / CMD7), surface a `read_block(lba)` /
//! `write_block(lba, data)` API on top of CMD17 / CMD24 with PIO
//! transfer (no SDMA / ADMA scatter-gather yet — single 512-byte
//! block per call through the Buffer Data Port).

use core::sync::atomic::AtomicBool;

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::req_gate::ReqGate;

// SDHCI is a PCI class 0x08 / subclass 0x05 device. Each silicon
// vendor has its own VID/DID, but the class triple is universally
// matched by the "SD host" backstop. We list the most common
// QEMU + real-hardware ids explicitly so the bus probe can pick
// them by name.

/// "Generic" SD Host Controller PCI class triple (08:05:01 —
/// SDHCI). Matched as a class backstop.
pub const SDHCI_PCI_CLASS: u8 = 0x08;
pub const SDHCI_PCI_SUBCLASS: u8 = 0x05;

/// Standard register offsets (SDHCI 3.00 §2).
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const REG_SDMA_ADDR: u64 = 0x00;
const REG_BLOCK_SIZE: u64 = 0x04;
const REG_BLOCK_COUNT: u64 = 0x06;
const REG_ARGUMENT: u64 = 0x08;
const REG_TRANSFER_MODE: u64 = 0x0C;
const REG_COMMAND: u64 = 0x0E;
const REG_RESPONSE_0: u64 = 0x10;
const REG_BUFFER_PORT: u64 = 0x20;
const REG_PRESENT_STATE: u64 = 0x24;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const REG_HOST_CONTROL_1: u64 = 0x28;
const REG_POWER_CONTROL: u64 = 0x29;
const REG_CLOCK_CONTROL: u64 = 0x2C;
const REG_TIMEOUT_CTRL: u64 = 0x2E;
const REG_SOFT_RESET: u64 = 0x2F;
const REG_NORMAL_INT_STS: u64 = 0x30;
const REG_ERROR_INT_STS: u64 = 0x32;
const REG_NORMAL_INT_EN: u64 = 0x34;
const REG_ERROR_INT_EN: u64 = 0x36;
const REG_CAPABILITIES: u64 = 0x40;

// Software-reset bits (§2.2.16): write-1 self-clearing.
const SRST_ALL: u8 = 1 << 0;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const SRST_CMD: u8 = 1 << 1;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const SRST_DAT: u8 = 1 << 2;

// Clock control bits (§2.2.14).
const CLK_INTERNAL_EN: u16 = 1 << 0; // Internal clock enable.
const CLK_INTERNAL_STABLE: u16 = 1 << 1;
const CLK_SD_EN: u16 = 1 << 2; // SD-clock to card output.

// Power control bits (§2.2.10).
const POWER_ON: u8 = 1 << 0;
const POWER_3V3: u8 = 0b111 << 1; // 3.3V

// Present state bits (§2.2.9).
const PSTATE_CMD_INHIBIT: u32 = 1 << 0;
const PSTATE_DAT_INHIBIT: u32 = 1 << 1;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const PSTATE_BUFFER_READ_EN: u32 = 1 << 11;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const PSTATE_BUFFER_WRITE_EN: u32 = 1 << 10;
const PSTATE_CARD_INSERTED: u32 = 1 << 16;

// Normal interrupt status bits (§2.2.18).
const NIS_CMD_COMPLETE: u16 = 1 << 0;
const NIS_TRANSFER_COMPLETE: u16 = 1 << 1;
const NIS_BUFFER_READ_READY: u16 = 1 << 5;
const NIS_BUFFER_WRITE_READY: u16 = 1 << 4;
const NIS_ERROR: u16 = 1 << 15;

// Command response types (§2.2.6).
const RESP_NONE: u16 = 0b00;
const RESP_136: u16 = 0b01;
const RESP_48: u16 = 0b10;
const RESP_48_BUSY: u16 = 0b11;

// Command flags (§2.2.6 cont).
const CMD_CRC_EN: u16 = 1 << 3;
const CMD_INDEX_EN: u16 = 1 << 4;
const CMD_DATA_PRES: u16 = 1 << 5;

// Transfer mode bits (§2.2.5).
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const TM_BLOCK_COUNT_EN: u16 = 1 << 1;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const TM_AUTO_CMD12: u16 = 1 << 2;
const TM_DATA_DIR_READ: u16 = 1 << 4;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const TM_MULTI_BLOCK: u16 = 1 << 5;

/// SD command index → encoded register write per §2.2.6.
fn make_cmd(idx: u8, resp_kind: u16, has_data: bool) -> u16 {
    let mut v = (idx as u16) << 8 | resp_kind;
    // CRC + index check are required for most R1/R3/R6 paths; the
    // spec says they're enabled per response-type table 2-19.
    match resp_kind {
        RESP_136 => v |= CMD_CRC_EN,
        RESP_48 => v |= CMD_CRC_EN | CMD_INDEX_EN,
        RESP_48_BUSY => v |= CMD_CRC_EN | CMD_INDEX_EN,
        _ => {}
    }
    if has_data {
        v |= CMD_DATA_PRES;
    }
    v
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SdhciError {
    BarMapFailed,
    /// Software reset never cleared within the spin budget.
    ResetTimeout,
    /// Card-presence bit was 0 after power-up.
    NoCard,
    /// CMD line stayed busy past CMD_INHIBIT.
    CmdInhibitTimeout,
    /// CMD didn't complete within the bounded poll.
    CmdTimeout,
    /// Hardware reported an error in Error Int Status.
    DeviceError(u16),
    /// Buffer ready never asserted on a PIO transfer.
    PioStall,
    /// Caller-supplied buffer is the wrong size.
    BadLength,
}

#[derive(Copy, Clone, Debug)]
pub struct SdCard {
    /// Card RCA (relative card address) negotiated via CMD3.
    pub rca: u16,
    /// CID register read via CMD2 (response 136).
    pub cid: [u32; 4],
    /// Response from CMD8 — non-zero implies SD spec ≥ 2.0 (the
    /// card supports CMD8 and matches our voltage check).
    pub if_cond_match: bool,
    /// CCS bit from ACMD41 — 1 = SDHC/SDXC (block-addressed),
    /// 0 = SDSC (byte-addressed).
    pub ccs: bool,
    /// Card capacity in 512-byte blocks.
    pub capacity_blocks: u64,
}

pub struct Sdhci {
    mmio: MmioRegion,
    pub card: IrqSafeSpinLock<Option<SdCard>>,
    /// Serialises polled SD transfers across callers. Spun on WITHOUT
    /// masking interrupts — see [`crate::req_gate::ReqGate`] for why
    /// this replaces holding `CONTROLLER` across a multi-block PIO
    /// loop (each block issues polled commands with 100 ms–1 s
    /// deadlines; the aggregate hold scales with the block count).
    req_gate: AtomicBool,
}

impl core::fmt::Debug for Sdhci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sdhci")
            .field("probed_card", &self.card.lock().is_some())
            .finish_non_exhaustive()
    }
}

impl Sdhci {
    /// Bring up the host controller: software reset, supply 400 kHz
    /// init clock, set 3.3V, run the SD identification sequence.
    /// Returns the populated `SdCard`.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively for the duration of init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, SdhciError> {
        // SAFETY: caller-asserted.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| SdhciError::BarMapFailed)?;
        let me = Sdhci {
            mmio,
            card: IrqSafeSpinLock::new(None),
            req_gate: AtomicBool::new(false),
        };

        // AMD FCH SDHCI quirk: on Renoir / Phoenix / older FCH parts
        // (1022:7906 / 1022:1611 / 1022:1612 / 1022:14CC / 1022:14E7
        // and friends), SRST_ALL does NOT self-clear from certain
        // sticky DATA-line states. The controller hangs the bring-up
        // path with a ResetTimeout. Linux works around this in
        // `drivers/mmc/host/sdhci-pci-core.c:amd_sdhci_reset` with a
        // full PCI power-state cycle BEFORE the soft reset — we do
        // the same here, scoped to AMD vendor.
        //
        // D3hot is sufficient; D3cold (which Linux uses) would need
        // ACPI _PS3/_PS0 power-resource manipulation that NARF
        // doesn't wire today. D3hot clears the controller's volatile
        // state without dropping the link, and is enough on the AMD
        // FCH parts in practice.
        if device.id.vendor == 0x1022 {
            // Power-cycle errors are non-fatal — fall through to the
            // soft-reset attempt regardless. The user-visible signal
            // is "no PM cap" (CapNotPresent), which can happen on
            // QEMU's emulated SDHCI.
            if let Err(e) = narf_bus::pci::pm_d3hot_cycle(cap, device) {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  sdhci: AMD pre-reset PM cycle skipped: {:?}",
                    e,
                );
            }
        }

        // 1. Software reset — Reset All (§3.6).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            me.mmio.write8(REG_SOFT_RESET, SRST_ALL);
        }
        // responsive_spin_until ticks sleep_pumps every ~4096 iters
        // so the FB cursor / serial drain stay alive during the
        // reset. SDHCI 4.20 §3.6 says SRST_ALL self-clears within
        // 100 ms on a healthy controller.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { me.mmio.read8(REG_SOFT_RESET) } & SRST_ALL == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !done {
            return Err(SdhciError::ResetTimeout);
        }

        // 2. Capabilities snapshot — informational only at this stage.
        // SAFETY: same.
        let _caps_lo = unsafe { me.mmio.read32(REG_CAPABILITIES) };
        // SAFETY: same.
        let _caps_hi = unsafe { me.mmio.read32(REG_CAPABILITIES + 4) };

        // 3. Power-on at 3.3V.
        // SAFETY: same.
        unsafe {
            me.mmio.write8(REG_POWER_CONTROL, POWER_3V3 | POWER_ON);
        }

        // 4. Internal clock enable + supply 400 kHz init clock.
        //    Base clock comes from caps[15:8]; we use a divider that
        //    targets ~400 kHz across the typical 25–100 MHz range.
        //    SDHCI 3.00 §2.2.14 uses 10-bit divider field; pick 0x80
        //    for a generous safety margin.
        let div = 0x80u16;
        let clk = ((div & 0xFF) << 8) | ((div >> 8) & 0x3) << 6 | CLK_INTERNAL_EN;
        // SAFETY: same.
        unsafe {
            me.mmio.write16(REG_CLOCK_CONTROL, clk);
        }
        // responsive_spin_until keeps cursor/FB/serial alive while
        // waiting for the internal clock to stabilise. SDHCI 4.20
        // §2.2.14 caps stable-bit assertion at 150 ms. Timeout
        // ignored — original code fell through to SD_EN regardless.
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { me.mmio.read16(REG_CLOCK_CONTROL) } & CLK_INTERNAL_STABLE != 0,
            narf_time::Deadline::after_ms(150),
        );
        // SAFETY: same.
        let v = unsafe { me.mmio.read16(REG_CLOCK_CONTROL) };
        // SAFETY: same.
        unsafe {
            me.mmio.write16(REG_CLOCK_CONTROL, v | CLK_SD_EN);
        }

        // 5. Default DTOCV = 0xE (max timeout).
        // SAFETY: same.
        unsafe {
            me.mmio.write8(REG_TIMEOUT_CTRL, 0x0E);
        }

        // 6. Enable normal + error interrupt status reporting (we
        //    poll, but the status bits only set when enabled).
        // SAFETY: same.
        unsafe {
            me.mmio.write16(REG_NORMAL_INT_EN, 0xFFFF);
            me.mmio.write16(REG_ERROR_INT_EN, 0xFFFF);
        }

        // 7. Card-present check.
        // SAFETY: same.
        let pstate = unsafe { me.mmio.read32(REG_PRESENT_STATE) };
        if pstate & PSTATE_CARD_INSERTED == 0 {
            return Err(SdhciError::NoCard);
        }

        // 8. Run the SD identification sequence.
        // SAFETY: `me.mmio` is the identity-mapped SDHCI register window set
        // up above and `identify_sequence` runs exactly once here at
        // bring-up, satisfying its single-call ownership precondition.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let card = unsafe { me.identify_sequence() }?;
        *me.card.lock() = Some(card);
        Ok(me)
    }

    /// Wait for both CMD_INHIBIT and (when issuing a data-bearing
    /// command) DAT_INHIBIT to clear.
    fn wait_idle(&self, with_data: bool) -> Result<(), SdhciError> {
        let mask = if with_data {
            PSTATE_CMD_INHIBIT | PSTATE_DAT_INHIBIT
        } else {
            PSTATE_CMD_INHIBIT
        };
        // responsive_spin_until keeps cursor/FB/serial alive on a
        // stuck controller. SDHCI 4.20 §3.7: any in-flight command
        // must complete within the data-timeout window programmed
        // in REG_TIMEOUT_CTRL. 1 s is a comfortable upper bound for
        // the longest plausible card response.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read32(REG_PRESENT_STATE) } & mask == 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if done {
            Ok(())
        } else {
            Err(SdhciError::CmdInhibitTimeout)
        }
    }

    /// Issue a command + poll until cmd-complete.
    /// Returns the 32-bit response (low 32 bits for R1/R3/R6/R7;
    /// for R2, callers read all four response registers via
    /// `read_response_136`).
    // Wide signature mirrors the SDHCI command/transfer register set
    // (idx, arg, response kind, data flag, transfer mode, block size/count).
    #[allow(clippy::too_many_arguments)]
    fn cmd(
        &self,
        idx: u8,
        arg: u32,
        resp_kind: u16,
        has_data: bool,
        transfer: u16,
        block_size: u16,
        block_cnt: u16,
    ) -> Result<u32, SdhciError> {
        self.wait_idle(has_data)?;
        // Clear status bits (write-1-clear).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write16(REG_NORMAL_INT_STS, 0xFFFF);
            self.mmio.write16(REG_ERROR_INT_STS, 0xFFFF);
        }
        // Program block size / count first when there's data.
        if has_data {
            // SAFETY: same.
            unsafe {
                self.mmio.write16(REG_BLOCK_SIZE, block_size);
                self.mmio.write16(REG_BLOCK_COUNT, block_cnt);
                self.mmio.write16(REG_TRANSFER_MODE, transfer);
            }
        }
        // SAFETY: same.
        unsafe {
            self.mmio.write32(REG_ARGUMENT, arg);
            self.mmio
                .write16(REG_COMMAND, make_cmd(idx, resp_kind, has_data));
        }
        // Poll for command-complete (or error). responsive_spin_until
        // ticks sleep_pumps so cursor/FB/serial stay alive. 1 s
        // wall-clock budget is comfortably above the longest
        // plausible single-command latency.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read16(REG_NORMAL_INT_STS) } & (NIS_CMD_COMPLETE | NIS_ERROR) != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::CmdTimeout);
        }
        // SAFETY: identity-mapped MMIO.
        let nis = unsafe { self.mmio.read16(REG_NORMAL_INT_STS) };
        if nis & NIS_ERROR != 0 {
            // SAFETY: same.
            let eis = unsafe { self.mmio.read16(REG_ERROR_INT_STS) };
            return Err(SdhciError::DeviceError(eis));
        }
        // Clear cmd-complete; preserve other bits for the data path.
        // SAFETY: same.
        unsafe {
            self.mmio.write16(REG_NORMAL_INT_STS, NIS_CMD_COMPLETE);
        }
        // SAFETY: same.
        let r0 = unsafe { self.mmio.read32(REG_RESPONSE_0) };
        Ok(r0)
    }

    /// Read all four 32-bit response slots (R2 / CID / CSD).
    fn read_response_136(&self) -> [u32; 4] {
        let mut r = [0u32; 4];
        for (i, slot) in r.iter_mut().enumerate() {
            // SAFETY: identity-mapped MMIO; `REG_RESPONSE_0 + i*4` for
            // `i` in 0..4 covers the four contiguous 32-bit response
            // registers (`R2`/CID/CSD).
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *slot = unsafe { self.mmio.read32(REG_RESPONSE_0 + (i as u64) * 4) };
        }
        r
    }

    /// Run the SD identification sequence.
    ///
    /// # Safety
    /// MMIO ownership; called only once at bring-up.
    unsafe fn identify_sequence(&self) -> Result<SdCard, SdhciError> {
        // CMD0 (GO_IDLE_STATE) — no response.
        let _ = self.cmd(0, 0, RESP_NONE, false, 0, 0, 0)?;

        // CMD8 (SEND_IF_COND) — checks SD spec ≥ 2.0 + voltage.
        // Argument: 0x1AA = (3.3V supplied) | (check pattern 0xAA).
        // R7 response. Cards that don't support it fail with timeout
        // — we treat that as if_cond_match=false.
        let if_cond_match = match self.cmd(8, 0x1AA, RESP_48, false, 0, 0, 0) {
            Ok(r) => (r & 0xFF) == 0xAA,
            Err(_) => false,
        };

        // ACMD41 (SD_SEND_OP_COND): repeat CMD55 + CMD41 until
        // the response's busy bit (bit 31) is set.
        let mut acmd41_arg = 0x4000_0000u32; // HCS=1 (host supports SDHC).
        if if_cond_match {
            acmd41_arg |= 0x0030_0000;
        } // 3.3V window.
        let mut ocr = 0u32;
        for _ in 0..1_000u32 {
            // CMD55 (APP_CMD).
            let _ = self.cmd(55, 0, RESP_48, false, 0, 0, 0)?;
            ocr = self.cmd(41, acmd41_arg, RESP_48, false, 0, 0, 0)?;
            if ocr & 0x8000_0000 != 0 {
                break;
            }
            for _ in 0..10_000 {
                core::hint::spin_loop();
            }
        }
        if ocr & 0x8000_0000 == 0 {
            return Err(SdhciError::CmdTimeout);
        }
        let ccs = ocr & 0x4000_0000 != 0;

        // CMD2 (ALL_SEND_CID) — 136-bit response.
        let _ = self.cmd(2, 0, RESP_136, false, 0, 0, 0)?;
        let cid = self.read_response_136();

        // CMD3 (SEND_RELATIVE_ADDR) — RCA in R6 high half.
        let r6 = self.cmd(3, 0, RESP_48, false, 0, 0, 0)?;
        let rca = (r6 >> 16) as u16;

        // CMD9 (SEND_CSD) — 136-bit response. Addressed by RCA in Standby state.
        let _ = self.cmd(9, (rca as u32) << 16, RESP_136, false, 0, 0, 0)?;
        let csd_raw = self.read_response_136();
        let csd = crate::sd_proto::Csd::parse_shifted(&csd_raw).unwrap_or_default();
        let capacity_blocks = csd.capacity_bytes / 512;

        // CMD7 (SELECT/DESELECT_CARD) — move card to TRAN state so
        // subsequent CMD17/24 are accepted.
        let _ = self.cmd(7, (rca as u32) << 16, RESP_48_BUSY, false, 0, 0, 0)?;

        // Set block size to 512 (CMD16). SDHC ignores this for block
        // addressing but sending it is harmless.
        let _ = self.cmd(16, 512, RESP_48, false, 0, 0, 0)?;

        Ok(SdCard {
            rca,
            cid,
            if_cond_match,
            ccs,
            capacity_blocks,
        })
    }

    /// Read a single 512-byte block via PIO. `lba` is the block
    /// number for SDHC cards; for SDSC cards (`ccs=0`) it's
    /// pre-multiplied by 512 to produce a byte address.
    pub fn read_block(&self, lba: u32, out: &mut [u8; 512]) -> Result<(), SdhciError> {
        let card = self.card.lock().ok_or(SdhciError::NoCard)?;
        let arg = if card.ccs { lba } else { lba * 512 };

        // CMD17 (READ_SINGLE_BLOCK) with data-direction read.
        let tm = TM_DATA_DIR_READ;
        let _ = self.cmd(17, arg, RESP_48, true, tm, 512, 1)?;

        // Wait for buffer-read-ready, then drain 512 / 4 = 128
        // u32 words from the buffer port. responsive_spin_until keeps
        // the FB cursor / serial drain alive on a slow controller.
        // 1 s budget covers the worst plausible read latency.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read16(REG_NORMAL_INT_STS) } & (NIS_BUFFER_READ_READY | NIS_ERROR) != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::PioStall);
        }
        // SAFETY: identity-mapped MMIO.
        let nis = unsafe { self.mmio.read16(REG_NORMAL_INT_STS) };
        if nis & NIS_ERROR != 0 {
            // SAFETY: same.
            let eis = unsafe { self.mmio.read16(REG_ERROR_INT_STS) };
            return Err(SdhciError::DeviceError(eis));
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write16(REG_NORMAL_INT_STS, NIS_BUFFER_READ_READY);
        }
        for i in 0..128usize {
            // SAFETY: same.
            let w = unsafe { self.mmio.read32(REG_BUFFER_PORT) };
            let bytes = w.to_le_bytes();
            out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        // Wait for transfer-complete. 1 s wall-clock budget.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read16(REG_NORMAL_INT_STS) } & NIS_TRANSFER_COMPLETE != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::PioStall);
        }
        // SAFETY: same.
        unsafe {
            self.mmio.write16(REG_NORMAL_INT_STS, NIS_TRANSFER_COMPLETE);
        }
        Ok(())
    }

    /// Write a single 512-byte block via PIO. Mirror of `read_block`.
    pub fn write_block(&self, lba: u32, data: &[u8; 512]) -> Result<(), SdhciError> {
        let card = self.card.lock().ok_or(SdhciError::NoCard)?;
        let arg = if card.ccs { lba } else { lba * 512 };
        let _ = self.cmd(24, arg, RESP_48, true, /*tm*/ 0, 512, 1)?;

        // Wait for buffer-write-ready, push 128 u32 words.
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay
        // alive. 1 s wall-clock budget.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read16(REG_NORMAL_INT_STS) } & (NIS_BUFFER_WRITE_READY | NIS_ERROR) != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::PioStall);
        }
        // SAFETY: identity-mapped MMIO.
        let nis = unsafe { self.mmio.read16(REG_NORMAL_INT_STS) };
        if nis & NIS_ERROR != 0 {
            // SAFETY: same.
            let eis = unsafe { self.mmio.read16(REG_ERROR_INT_STS) };
            return Err(SdhciError::DeviceError(eis));
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio
                .write16(REG_NORMAL_INT_STS, NIS_BUFFER_WRITE_READY);
        }
        for i in 0..128usize {
            let bytes: [u8; 4] = [
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ];
            let w = u32::from_le_bytes(bytes);
            // SAFETY: identity-mapped MMIO.
            unsafe {
                self.mmio.write32(REG_BUFFER_PORT, w);
            }
        }
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read16(REG_NORMAL_INT_STS) } & NIS_TRANSFER_COMPLETE != 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(SdhciError::PioStall);
        }
        // SAFETY: same.
        unsafe {
            self.mmio.write16(REG_NORMAL_INT_STS, NIS_TRANSFER_COMPLETE);
        }
        Ok(())
    }
}

// ── Driver-match registration ────────────────────────────────────────

/// Slot for the live host controller produced by `probe`. Held only
/// long enough to read the installed device's address
/// (`probed_sdhci`) — NEVER across a transfer, whose polled SD
/// commands run 100 ms–1 s deadlines per block. See
/// [`crate::req_gate`] for the livelock this prevents.
static CONTROLLER: IrqSafeSpinLock<Option<Sdhci>> = IrqSafeSpinLock::new(None);

/// The probed host controller, WITHOUT holding `CONTROLLER` for the
/// caller's use of it.
///
/// `CONTROLLER` is taken only long enough to read the address of the
/// installed device, then released, so a multi-block PIO loop runs
/// with interrupts enabled.
///
/// # Why the reference stays valid
///
/// The `Option` is written exactly once: [`probe`] returns early when
/// a controller is already installed, and nothing ever stores `None`
/// back. The `Sdhci` therefore is never moved, replaced or dropped
/// after its single install, so a shared reference to it stays valid
/// for the rest of the boot. `smoke_sdhci_device_address_is_stable`
/// pins that invariant, because it is the kind of assumption a later
/// "support hot-unplug" change would silently invalidate. There is no
/// `&mut` path into the slot at all — every `Sdhci` method takes
/// `&self` (card state lives behind its own inner lock).
fn probed_sdhci() -> Option<&'static Sdhci> {
    let ptr: *const Sdhci = {
        let g = CONTROLLER.lock();
        match g.as_ref() {
            Some(d) => d as *const Sdhci,
            None => return None,
        }
    };
    // SAFETY: install-once, never-moved, never-dropped — see above.
    Some(unsafe { &*ptr })
}

/// The installed controller's address, or `None` before probe. Test
/// hook for the install-once invariant `probed_sdhci` relies on.
#[doc(hidden)]
pub fn dbg_device_addr() -> Option<usize> {
    CONTROLLER
        .lock()
        .as_ref()
        .map(|d| d as *const Sdhci as usize)
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    use core::fmt::Write as _;
    // Class match catches all of class 0x08 (system peripheral).
    // Filter to subclass 0x05 (SD host controller) here.
    let subclass = ((device.id.class >> 8) & 0xFF) as u8;
    if subclass != SDHCI_PCI_SUBCLASS {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over BAR0.
    let dev = match unsafe { Sdhci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(e) => {
            // Surface the specific bring-up failure mode so a real-HW
            // "BadDevice" trace tells us whether it's BAR map / reset
            // timeout / etc. instead of the generic bus log line.
            let _ = writeln!(
                narf_console::Writer,
                "  sdhci: {:04x}:{:04x} bring_up failed: {:?}",
                device.id.vendor,
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };
    *CONTROLLER.lock() = Some(dev);

    if let Some(card) = CONTROLLER.lock().as_ref().unwrap().card.lock().as_ref() {
        if card.capacity_blocks > 0 {
            let block_dev = alloc::sync::Arc::new(SdhciBlockDevice {
                capacity_blocks: card.capacity_blocks,
                ccs: card.ccs,
            });
            narf_block::registry::register_block_device("sdhci0", block_dev);
        }
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("sd0"),
        kind: narf_drivers::BoundKind::Block,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Block.default_domain(),
    });
    Ok(())
}

struct SdhciBlockDevice {
    capacity_blocks: u64,
    ccs: bool,
}

impl narf_block::registry::BlockDeviceSync for SdhciBlockDevice {
    fn lba_size(&self) -> u32 {
        512
    }

    fn capacity(&self) -> u64 {
        self.capacity_blocks
    }

    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::registry::BlockIoError> {
        if n_blocks == 0 {
            return Ok(());
        }
        let needed = n_blocks as usize * 512;
        if out.len() < needed {
            return Err(narf_block::registry::BlockIoError::BufferTooSmall);
        }
        let max_lba = self.capacity_blocks.saturating_sub(n_blocks as u64);
        if lba > max_lba {
            return Err(narf_block::registry::BlockIoError::OutOfRange);
        }

        with_controller(|ctrl| {
            for i in 0..n_blocks as u64 {
                let block_addr = if self.ccs {
                    (lba + i) as u32
                } else {
                    ((lba + i) as u32).saturating_mul(512)
                };
                let offset = i as usize * 512;
                let mut buf = [0u8; 512];
                ctrl.read_block(block_addr, &mut buf)
                    .map_err(|_| narf_block::registry::BlockIoError::DriverError)?;
                out[offset..offset + 512].copy_from_slice(&buf);
            }
            Ok(())
        })
        .unwrap_or(Err(narf_block::registry::BlockIoError::DriverError))
    }

    fn write(
        &self,
        lba: u64,
        n_blocks: u16,
        data: &[u8],
    ) -> Result<(), narf_block::registry::BlockIoError> {
        if n_blocks == 0 {
            return Ok(());
        }
        let needed = n_blocks as usize * 512;
        if data.len() < needed {
            return Err(narf_block::registry::BlockIoError::BufferTooSmall);
        }
        let max_lba = self.capacity_blocks.saturating_sub(n_blocks as u64);
        if lba > max_lba {
            return Err(narf_block::registry::BlockIoError::OutOfRange);
        }

        with_controller(|ctrl| {
            for i in 0..n_blocks as u64 {
                let block_addr = if self.ccs {
                    (lba + i) as u32
                } else {
                    ((lba + i) as u32).saturating_mul(512)
                };
                let offset = i as usize * 512;
                let mut buf = [0u8; 512];
                buf.copy_from_slice(&data[offset..offset + 512]);
                ctrl.write_block(block_addr, &buf)
                    .map_err(|_| narf_block::registry::BlockIoError::DriverError)?;
            }
            Ok(())
        })
        .unwrap_or(Err(narf_block::registry::BlockIoError::DriverError))
    }
}

pub fn register_pci_driver() {
    // Class-match backstop covers every SDHCI implementation. The
    // probe itself filters to subclass 0x05 (SD host controller)
    // since MatchKind::Class only checks the base class byte.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "sdhci",
        kind: narf_bus::MatchKind::Class {
            class: SDHCI_PCI_CLASS,
            mask: 0xFF,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Run `f` against the probed controller, if any.
///
/// Holds the device's request gate — not the `CONTROLLER` spinlock —
/// for the duration of `f`, so a multi-block PIO closure waits out
/// its 100 ms–1 s per-command polls with interrupts enabled while
/// still excluding every other user of the controller. Callers must
/// not re-enter `with_controller` from inside `f` — the gate is not
/// reentrant.
pub fn with_controller<R>(f: impl FnOnce(&Sdhci) -> R) -> Option<R> {
    let ctrl = probed_sdhci()?;
    let _gate = ReqGate::acquire(&ctrl.req_gate);
    Some(f(ctrl))
}

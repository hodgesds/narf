//! Register-level fixture for the SDHCI driver: a modelled SDHCI
//! register file + SD card behind the [`SdhciTransport`] seam, so
//! the identify → publish → partition-scan conversation runs end
//! to end in kernel tests without silicon.
//!
//! The model implements the hardware contract the driver programs,
//! from the **SD Host Controller Simplified Specification 3.00**:
//!
//! - Normal / Error Interrupt Status are write-1-to-clear
//!   (§2.2.18 / §2.2.19); Software Reset's bits are self-clearing
//!   (§2.2.16); the internal-clock stable bit asserts when the
//!   internal clock is enabled (§2.2.14).
//! - A Command register write (§2.2.6) executes the staged
//!   command: Command Complete sets; a data command also sets
//!   Buffer Read / Write Ready and Transfer Complete. Responses
//!   land in the Response registers in the layout §2.2.7 defines
//!   for R2 — the register content with CRC7 + end bit stripped,
//!   which is the shifted layout `sd_proto` parses.
//! - The Buffer Data Port (§2.2.4) streams the addressed card
//!   block word-by-word on CMD17 and captures it on CMD24; on
//!   CMD18/CMD25 it streams/captures the whole multi-block run,
//!   re-asserting Buffer Read / Write Ready per block.
//! - Present State (§2.2.9) reports a card inserted.
//! - Capabilities (§2.2.24) report a 50 MHz base clock with SDMA
//!   + ADMA2; the Host Version register reports spec 3.00.
//! - ACMD51 stages the card's 8-byte SCR (SD Physical Layer Spec
//!   Table 5-17/5-21: 4-bit bus supported).
//! - DMA data commands are executed against the driver's real
//!   `narf_io` bounce buffer (identity bus addresses): SDMA from
//!   the SDMA System Address register, ADMA2 by walking the
//!   descriptor table the driver built — the sdio `dma_tests`
//!   model. An SDMA transfer can be made to stop at a 512 KiB
//!   boundary once (`set_sdma_boundary_once`), completing only
//!   when the driver reprograms the address, as real silicon does.
//!
//! The card model speaks the SD identification conversation (SD
//! Physical Layer Simplified Specification §4) and stores blocks
//! sparsely, so an 8 GiB SDHC fixture costs a few KiB.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::*;

/// CMD19 tuning block, 4-bit bus (SD Physical Layer Spec
/// §4.2.4.5; Linux `drivers/mmc/core/mmc_ops.c`
/// `tuning_blk_pattern_4bit`, the spec's fixed pattern the card
/// returns for CMD19). The driver drains it via the Buffer Data
/// Port; the host tuning engine — not the driver — verifies it.
const TUNING_PATTERN_4BIT: [u8; 64] = [
    0xff, 0x0f, 0xff, 0x00, 0xff, 0xcc, 0xc3, 0xcc, 0xc3, 0x3c, 0xcc, 0xff, 0xfe, 0xff, 0xfe, 0xef,
    0xff, 0xdf, 0xff, 0xdd, 0xff, 0xfb, 0xff, 0xfb, 0xbf, 0xff, 0x7f, 0xff, 0x77, 0xf7, 0xbd, 0xef,
    0xff, 0xf0, 0xff, 0xf0, 0x0f, 0xfc, 0xcc, 0x3c, 0xcc, 0x33, 0xcc, 0xcf, 0xff, 0xef, 0xff, 0xee,
    0xff, 0xfd, 0xff, 0xfd, 0xdf, 0xff, 0xbf, 0xff, 0xbb, 0xff, 0xf7, 0xff, 0xf7, 0x7f, 0x7b, 0xde,
];

/// Build a 64-byte CMD6 switch status block (SD Physical Layer
/// Spec §4.3.10 layout, as `sd_proto::SwitchStatus` parses it):
/// `support` in byte 13 (Function Group 1 support bitmask),
/// `current_function` in byte 16's low nibble; every other field
/// is zero (no current-limit claim, no other function groups).
fn switch_status_bytes(support: u8, current_function: u8) -> [u8; 64] {
    let mut status = [0u8; 64];
    status[13] = support;
    status[16] = current_function & 0x0F;
    status
}

/// RCA the fixture card answers CMD3 with.
const FIXTURE_RCA: u16 = 0x0001;

/// SCR register bytes (8, wire order) of the fixture card: SD_SPEC
/// 2 (v2.00), SD_BUS_WIDTHS 0x5 (1-bit + 4-bit) — SD Physical
/// Layer Spec Table 5-17/5-21.
const FIXTURE_SCR: [u8; 8] = [0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// Default fixture Capabilities: 50 MHz base clock, SDMA +
/// ADMA2, VDD 3.3 V (SDHCI 3.00 §2.2.24; bit values shared with
/// `drivers/sdio/src/sdhci/regs.rs`).
const FIXTURE_CAPS: u32 = (50u32 << 8) | 0x0040_0000 | 0x0008_0000 | 0x0100_0000;
/// Fixture Capabilities with a 1.8 V signalling rail (UHS-I host).
const FIXTURE_CAPS_UHS: u32 = FIXTURE_CAPS | 0x0400_0000;
/// Fixture Capabilities_1 bits (SDHCI 3.00 §2.2.25): UHS mode
/// support + "Use Tuning for SDR50" (bit 45 → CAPS1 bit 13).
const FIXTURE_CAPS1_SDR50: u32 = 0x0000_0001;
const FIXTURE_CAPS1_SDR104: u32 = 0x0000_0002;
const FIXTURE_CAPS1_DDR50: u32 = 0x0000_0004;
const FIXTURE_CAPS1_TUNING_SDR50: u32 = 0x0000_2000;
/// Fixture Capabilities with 64-bit DMA addressing.
const FIXTURE_CAPS_64BIT: u32 = FIXTURE_CAPS | 0x1000_0000;
/// Fixture Capabilities with SDMA only (no ADMA2).
const FIXTURE_CAPS_SDMA_ONLY: u32 = (50u32 << 8) | 0x0040_0000 | 0x0100_0000;
/// Fixture Capabilities with no DMA at all.
const FIXTURE_CAPS_PIO_ONLY: u32 = (50u32 << 8) | 0x0100_0000;
/// Fixture host spec version: 2 = SDHCI 3.00.
const FIXTURE_SPEC_VERSION: u8 = 2;

/// HOST_CONTROL DMA select field + 64-bit value (SDHCI 3.00 §2.2.8).
const FIXTURE_CTRL_DMA_MASK: u8 = 0x18;
const FIXTURE_CTRL_ADMA64: u8 = 0x18;

/// ADMA2 descriptor walk constants (SDHCI 3.00 §1.13).
const FIXTURE_ADMA_ATTR_END: u16 = 0x02;
const FIXTURE_ADMA_ATTR_ACT_TRAN: u16 = 0x20;
/// SDMA buffer boundary (512 KiB).
const FIXTURE_SDMA_BOUNDARY: u64 = 512 * 1024;

/// CID register bytes (15; the CRC7 + end byte are the
/// controller's to strip) of the fixture card: MID 0x03,
/// OID "SD", PNM "SU08G" — the same card identity the RTSX
/// fixture carries.
const FIXTURE_CID: [u8; 15] = [
    0x03, b'S', b'D', b'S', b'U', b'0', b'8', b'G', 0x80, 0x12, 0x34, 0x56, 0x78, 0x01, 0x42,
];

/// CSD register bytes (15): CSD v2.0 with C_SIZE = 16383 →
/// (16383 + 1) × 512 KiB = 8 GiB = 16,777,216 blocks (SD Physical
/// Layer Spec §5.3.2) — the same CSD the RTSX fixture card
/// carries.
const FIXTURE_CSD: [u8; 15] = [
    0x40, 0x0E, 0x00, 0x32, 0x5B, 0x59, 0x00, 0x00, 0x3F, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Convert a 15-byte R2 register (CID / CSD) into the four
/// Response register words the controller presents: the register
/// shifted so the stripped CRC7 + end bit leave the top byte of
/// word 3 zero — the layout `sd_proto::Cid::parse_shifted` /
/// `Csd::parse_shifted` consume (SDHCI 3.00 §2.2.7). Mirrors the
/// RTSX fixture's frame conversion.
fn r2_to_response_words(reg: &[u8; 15]) -> [u32; 4] {
    // Frame the register as the on-wire R2 response: header byte
    // 0x3F, then the 15 register bytes.
    let b = |i: usize| -> u32 {
        if i == 0 {
            0x3F
        } else {
            reg[i - 1] as u32
        }
    };
    [
        (b(12) << 24) | (b(13) << 16) | (b(14) << 8) | b(15),
        (b(8) << 24) | (b(9) << 16) | (b(10) << 8) | b(11),
        (b(4) << 24) | (b(5) << 16) | (b(6) << 8) | b(7),
        (b(1) << 16) | (b(2) << 8) | b(3),
    ]
}

/// One card block filled with an offset-sensitive pattern derived
/// from `tag`: byte `i` is `tag ^ i`, so reading the right block
/// at the wrong offset (or the wrong block) cannot pass.
fn partition_pattern(tag: u8) -> [u8; 512] {
    let mut b = [0u8; 512];
    for (i, x) in b.iter_mut().enumerate() {
        *x = tag ^ (i as u8);
    }
    b
}

/// Write one 16-byte partition entry into an MBR sector image —
/// the classic MBR partition-table layout (sector 0, entries at
/// bytes 446..510): boot flag, CHS-first, type, CHS-last, LBA
/// start (LE), sector count (LE). The CHS fields carry the
/// 0xFEFFFF "beyond CHS range" sentinel fdisk writes for
/// LBA-addressed entries; the scanner (like Linux) reads only
/// type + LBA fields.
fn write_mbr_entry(sector: &mut [u8; 512], slot: usize, ty: u8, start: u32, count: u32) {
    let off = 446 + slot * 16;
    sector[off] = 0x00; // not bootable
    sector[off + 1..off + 4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    sector[off + 4] = ty;
    sector[off + 5..off + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    sector[off + 8..off + 12].copy_from_slice(&start.to_le_bytes());
    sector[off + 12..off + 16].copy_from_slice(&count.to_le_bytes());
}

/// The partitioned card image: LBA 0 is a classic MBR with two
/// primary partitions and the 0x55AA boot signature (the layout
/// `narf_block::partition::parse_mbr` consumes, written here from
/// the MBR layout itself, not from the parser); partition bodies
/// are offset-sensitive patterns at the blocks the entries point
/// at:
/// - p1: type 0x83 (Linux), start LBA 2048, 4096 sectors —
///   pattern 0xA1 at its first block, 0xA2 at its last (card
///   block 6143).
/// - p2: type 0x0C (FAT32, LBA), start LBA 8192, 2048 sectors —
///   pattern 0xB1 at its first block.
fn partitioned_image() -> BTreeMap<u32, [u8; 512]> {
    let mut mbr = [0u8; 512];
    write_mbr_entry(&mut mbr, 0, 0x83, 2048, 4096);
    write_mbr_entry(&mut mbr, 1, 0x0C, 8192, 2048);
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    let mut image = BTreeMap::new();
    image.insert(0, mbr);
    image.insert(2048, partition_pattern(0xA1));
    image.insert(6143, partition_pattern(0xA2));
    image.insert(8192, partition_pattern(0xB1));
    image
}

// ── Register-file model ─────────────────────────────────────────

/// A pending SDMA transfer stopped at a 512 KiB boundary: the
/// bytes moved so far, and what is left for the restart.
#[derive(Debug)]
struct SdmaPending {
    addr: u64,
    total: usize,
    read: bool,
    lba: u32,
    moved: usize,
}

#[derive(Debug)]
struct FixtureState {
    /// The 0x100-byte register file, byte-addressed.
    regs: [u8; 0x100],
    /// Sparse card storage, keyed by block index.
    image: BTreeMap<u32, [u8; 512]>,
    /// Bytes staged for the Buffer Data Port by the current read
    /// command (one block for CMD17, N blocks for CMD18, 8 bytes
    /// for ACMD51).
    read_stage: Vec<u8>,
    /// Byte cursor into `read_stage`.
    read_cursor: usize,
    /// Buffer Data Port capture for the current write command.
    write_stage: Vec<u8>,
    /// Byte cursor into `write_stage`.
    write_cursor: usize,
    /// Block address of the in-flight CMD24/CMD25.
    write_lba: u32,
    /// Every command index issued, in order.
    cmd_log: Vec<u8>,
    /// Every register write, in order: (offset, value).
    writes: Vec<(u64, u32)>,
    /// (length, bus address) pairs the DMA engine walked, in
    /// order — SDMA records the whole transfer, ADMA one entry
    /// per TRAN descriptor.
    walked: Vec<(usize, u64)>,
    /// Make the next SDMA transfer stop at a 512 KiB boundary
    /// once (DMA interrupt, no transfer complete) instead of
    /// completing.
    sdma_boundary_once: bool,
    /// SDMA transfer waiting on a boundary restart.
    sdma_pending: Option<SdmaPending>,
    /// ACMD41 answers with S18A (OCR bit 24): the card accepts
    /// a 1.8 V switch.
    s18a: bool,
    /// Function Group 1 support bitmask the card reports in a
    /// CMD6 switch-status block (byte 13).
    switch_support: u8,
    /// The card's current Function Group 1 function, installed
    /// by a mode-1 CMD6 (0 = SDR12 after power-on / power cycle).
    current_function: u8,
    /// DAT[3:0] level the PRESENT_STATE register reports.
    dat_level: u8,
    /// CMD11 ran and the card is waiting for the clock restart
    /// to drive DAT[3:0] high.
    voltage_switch_pending: bool,
    /// CMD19 executions before the tuning engine reports done.
    tuning_iters: u32,
    /// CMD19 executions so far.
    tuning_count: u32,
    /// The tuning engine never completes.
    tuning_never: bool,
    /// DAT[3:0] stay low after the clock restart.
    voltage_switch_fail: bool,
    /// CMD11 answers with an R1 error instead of switching.
    cmd11_r1_error: bool,
}

impl FixtureState {
    fn get16(&self, off: u64) -> u16 {
        let o = off as usize;
        u16::from_le_bytes([self.regs[o], self.regs[o + 1]])
    }

    fn get32(&self, off: u64) -> u32 {
        let o = off as usize;
        u32::from_le_bytes(self.regs[o..o + 4].try_into().unwrap())
    }

    fn set16(&mut self, off: u64, v: u16) {
        let o = off as usize;
        self.regs[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn set32(&mut self, off: u64, v: u32) {
        let o = off as usize;
        self.regs[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn set_response_136(&mut self, words: [u32; 4]) {
        for (i, w) in words.iter().enumerate() {
            self.set32(REG_RESPONSE_0 + (i as u64) * 4, *w);
        }
    }

    fn raise_nis(&mut self, bits: u16) {
        let cur = self.get16(REG_NORMAL_INT_STS);
        self.set16(REG_NORMAL_INT_STS, cur | bits);
    }

    /// Bytes at identity-mapped physical address `addr`: the
    /// driver's live `narf_io` bounce buffer / ADMA table, owned
    /// by the controller under test.
    fn phys_slice(addr: u64, len: usize) -> Vec<u8> {
        let ptr = narf_memory::PhysAddr::new(addr).kernel_mut_ptr::<u8>();
        // SAFETY: identity bus addresses of live narf_io buffers
        // owned by the controller under test; the model runs
        // synchronously inside its COMMAND write, as the device
        // would between doorbell and completion (sdio dma_tests).
        let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
        slice.to_vec()
    }

    /// Move `total` bytes between the card image at `lba` and host
    /// memory at `phys`: card → memory for a read, memory → card
    /// for a write. Missing image blocks read as zeros; written
    /// blocks are created.
    fn dma_move(&mut self, phys: u64, total: usize, read: bool, lba: u32) {
        let ptr = narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>();
        if read {
            // SAFETY: same as `phys_slice`.
            let dst = unsafe { core::slice::from_raw_parts_mut(ptr, total) };
            for (i, b) in dst.iter_mut().enumerate() {
                let blk = lba + (i / 512) as u32;
                *b = self.image.get(&blk).map(|blk| blk[i % 512]).unwrap_or(0);
            }
        } else {
            // SAFETY: same as `phys_slice`.
            let src = unsafe { core::slice::from_raw_parts(ptr, total) };
            for (i, b) in src.iter().enumerate() {
                let blk = lba + (i / 512) as u32;
                let off = i % 512;
                self.image.entry(blk).or_insert([0u8; 512])[off] = *b;
            }
        }
    }

    /// Execute a DMA data command: SDMA from the SDMA System
    /// Address register, ADMA2 by walking the descriptor table.
    /// `total` is the transfer length in bytes, `read` the
    /// direction, `lba` the first card block.
    fn run_dma(&mut self, read: bool, total: usize, lba: u32) {
        let select = self.regs[REG_HOST_CONTROL_1 as usize] & FIXTURE_CTRL_DMA_MASK;
        if select == 0 {
            // SDMA.
            let addr = u64::from(self.get32(REG_SDMA_ADDR));
            if self.sdma_boundary_once {
                self.sdma_boundary_once = false;
                // Move only up to the next 512 KiB boundary, then
                // stop with a DMA interrupt; the rest moves when
                // the driver reprograms the address.
                let upto = (FIXTURE_SDMA_BOUNDARY - (addr % FIXTURE_SDMA_BOUNDARY)) as usize;
                let moved = upto.min(total);
                self.dma_move(addr, moved, read, lba);
                self.sdma_pending = Some(SdmaPending {
                    addr,
                    total,
                    read,
                    lba,
                    moved,
                });
                self.raise_nis(NIS_DMA_INTERRUPT);
                return;
            }
            self.walked.push((total, addr));
            self.dma_move(addr, total, read, lba);
            self.raise_nis(NIS_TRANSFER_COMPLETE);
            return;
        }
        // ADMA2.
        let desc_size = if select == FIXTURE_CTRL_ADMA64 { 12 } else { 8 };
        let mut at = u64::from(self.get32(REG_ADMA_ADDR));
        if select == FIXTURE_CTRL_ADMA64 {
            at |= u64::from(self.get32(REG_ADMA_ADDR_HI)) << 32;
        }
        let mut done = 0usize;
        for _ in 0..256 {
            let raw = Self::phys_slice(at, desc_size);
            let Some((attr, len, addr)) = read_adma_desc(&raw, 0, desc_size) else {
                break;
            };
            if attr & 0x1 == 0 {
                break;
            }
            if attr & FIXTURE_ADMA_ATTR_ACT_TRAN == FIXTURE_ADMA_ATTR_ACT_TRAN {
                let l = if len == 0 { 65_536 } else { len as usize };
                self.walked.push((l, addr));
                self.dma_move(addr, l, read, lba + (done / 512) as u32);
                done += l;
            }
            if attr & FIXTURE_ADMA_ATTR_END != 0 {
                break;
            }
            at += desc_size as u64;
        }
        self.raise_nis(NIS_TRANSFER_COMPLETE);
    }

    /// Stage `count` card blocks starting at `arg` for a PIO read.
    fn stage_read(&mut self, arg: u32, count: u16) {
        let mut stage = Vec::new();
        for i in 0..count as u32 {
            stage.extend_from_slice(
                self.image
                    .get(&(arg + i))
                    .copied()
                    .unwrap_or([0u8; 512])
                    .as_slice(),
            );
        }
        self.read_stage = stage;
        self.read_cursor = 0;
    }

    /// Execute the command staged by a Command-register write.
    fn exec_cmd(&mut self, index: u8) {
        let arg = self.get32(REG_ARGUMENT);
        self.cmd_log.push(index);
        let transfer = self.get16(REG_TRANSFER_MODE);
        let is_dma = transfer & TM_DMA != 0;
        let block_size = (self.get16(REG_BLOCK_SIZE) & 0x0FFF) as usize;
        let block_count = self.get16(REG_BLOCK_COUNT) as usize;
        let mut nis = NIS_CMD_COMPLETE;
        match index {
            // CMD8 — R7 echoes the voltage + check-pattern bits.
            8 => self.set32(REG_RESPONSE_0, arg & 0x0000_0FFF),
            // ACMD41 — R3 OCR: busy set, CCS set (SDHC), the
            // 3.3 V operating window; S18A (bit 24) when the
            // card accepts a 1.8 V switch.
            41 => {
                let mut ocr = 0x8000_0000 | 0x4000_0000 | 0x00FF_8000;
                if self.s18a {
                    ocr |= 0x0100_0000;
                }
                self.set32(REG_RESPONSE_0, ocr);
            }
            // CMD11 — R1: the card drives DAT[3:0] low and waits
            // for the clock restart; an R1 error (knob) rejects
            // the switch outright.
            11 => {
                if self.cmd11_r1_error {
                    self.set32(REG_RESPONSE_0, 1 << 22);
                } else {
                    self.set32(REG_RESPONSE_0, 0);
                    self.voltage_switch_pending = true;
                    self.dat_level = 0;
                }
            }
            // CMD6 — stage the 64-byte switch status; a mode-1
            // switch installs the Function Group 1 value
            // (argument bits [3:0]) first.
            6 => {
                if arg & 0x8000_0000 != 0 {
                    self.current_function = (arg & 0x0F) as u8;
                }
                self.read_stage =
                    switch_status_bytes(self.switch_support, self.current_function).to_vec();
                self.read_cursor = 0;
                nis |= NIS_BUFFER_READ_READY | NIS_TRANSFER_COMPLETE;
            }
            // CMD19 — stage the 64-byte tuning block; the tuning
            // engine clears EXEC_TUNING and sets TUNED_CLK once
            // the modelled iteration count is reached.
            19 => {
                self.read_stage = TUNING_PATTERN_4BIT.to_vec();
                self.read_cursor = 0;
                self.tuning_count += 1;
                if !self.tuning_never && self.tuning_count >= self.tuning_iters {
                    let hc2 = self.get16(REG_HOST_CONTROL_2);
                    self.set16(REG_HOST_CONTROL_2, (hc2 & !HC2_EXEC_TUNING) | HC2_TUNED_CLK);
                }
                nis |= NIS_BUFFER_READ_READY | NIS_TRANSFER_COMPLETE;
            }
            // CMD2 — R2 CID.
            2 => self.set_response_136(r2_to_response_words(&FIXTURE_CID)),
            // CMD3 — R6: RCA in the high half.
            3 => self.set32(REG_RESPONSE_0, (FIXTURE_RCA as u32) << 16),
            // CMD9 — R2 CSD.
            9 => self.set_response_136(r2_to_response_words(&FIXTURE_CSD)),
            // ACMD51 — stage the 8-byte SCR at the Buffer Data Port.
            51 => {
                self.read_stage = FIXTURE_SCR.to_vec();
                self.read_cursor = 0;
                nis |= NIS_BUFFER_READ_READY | NIS_TRANSFER_COMPLETE;
            }
            // CMD17 / CMD18 — stage the addressed block(s).
            17 | 18 => {
                if is_dma {
                    let total = block_size * block_count;
                    self.run_dma(true, total, arg);
                    // run_dma raised Transfer Complete itself.
                    let cur = self.get16(REG_NORMAL_INT_STS);
                    self.set16(REG_NORMAL_INT_STS, cur | nis);
                    return;
                }
                let count = if index == 17 { 1 } else { block_count as u16 };
                self.stage_read(arg, count);
                nis |= NIS_BUFFER_READ_READY | NIS_TRANSFER_COMPLETE;
            }
            // CMD24 / CMD25 — arm the Buffer Data Port capture.
            24 | 25 => {
                if is_dma {
                    let total = block_size * block_count;
                    self.run_dma(false, total, arg);
                    let cur = self.get16(REG_NORMAL_INT_STS);
                    self.set16(REG_NORMAL_INT_STS, cur | nis);
                    return;
                }
                self.write_lba = arg;
                self.write_cursor = 0;
                self.write_stage = alloc::vec![0u8; block_size * block_count.max(1)];
                nis |= NIS_BUFFER_WRITE_READY | NIS_TRANSFER_COMPLETE;
            }
            // CMD0 / CMD7 / CMD16 / CMD55 and everything else:
            // a plain completion with a zero response.
            _ => {}
        }
        let cur = self.get16(REG_NORMAL_INT_STS);
        self.set16(REG_NORMAL_INT_STS, cur | nis);
    }
}

/// Fixture transport: a modelled SDHCI register file + card
/// behind the seam.
pub struct FixtureTransport {
    state: IrqSafeSpinLock<FixtureState>,
}

impl core::fmt::Debug for FixtureTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FixtureTransport").finish_non_exhaustive()
    }
}

impl FixtureTransport {
    /// A controller with a card whose storage is `image`.
    pub fn with_image(image: BTreeMap<u32, [u8; 512]>) -> Self {
        let mut regs = [0u8; 0x100];
        regs[0x40..0x44].copy_from_slice(&FIXTURE_CAPS.to_le_bytes());
        regs[0xFE] = FIXTURE_SPEC_VERSION;
        FixtureTransport {
            state: IrqSafeSpinLock::new(FixtureState {
                regs,
                image,
                read_stage: Vec::new(),
                read_cursor: 0,
                write_stage: Vec::new(),
                write_cursor: 0,
                write_lba: 0,
                cmd_log: Vec::new(),
                writes: Vec::new(),
                walked: Vec::new(),
                sdma_boundary_once: false,
                sdma_pending: None,
                s18a: false,
                switch_support: 0,
                current_function: 0,
                dat_level: 0xF,
                voltage_switch_pending: false,
                tuning_iters: 1,
                tuning_count: 0,
                tuning_never: false,
                voltage_switch_fail: false,
                cmd11_r1_error: false,
            }),
        }
    }

    /// Override the modelled Capabilities / spec version (the
    /// registers the driver reads at negotiate time).
    pub fn set_caps(&self, caps: u32, spec_version: u8) {
        let mut st = self.state.lock();
        st.regs[0x40..0x44].copy_from_slice(&caps.to_le_bytes());
        st.regs[0xFE] = spec_version;
    }

    /// Override the modelled Capabilities_1 register (the
    /// UHS-mode support / tuning bits the driver reads).
    pub fn set_caps1(&self, caps1: u32) {
        let mut st = self.state.lock();
        st.regs[0x44..0x48].copy_from_slice(&caps1.to_le_bytes());
    }

    /// The card answers ACMD41 with S18A set and CMD6 with
    /// `group1_support` (Function Group 1 support bitmask).
    pub fn set_uhs_card(&self, group1_support: u8) {
        let mut st = self.state.lock();
        st.s18a = true;
        st.switch_support = group1_support;
    }

    /// The tuning engine needs `iters` CMD19 executions before
    /// it reports EXEC_TUNING clear + TUNED_CLK set.
    pub fn set_tuning_iters(&self, iters: u32) {
        self.state.lock().tuning_iters = iters;
    }

    /// The tuning engine never completes (EXEC_TUNING stays set).
    pub fn set_tuning_never(&self) {
        self.state.lock().tuning_never = true;
    }

    /// DAT[3:0] stay low after the voltage-switch clock restart.
    pub fn set_voltage_switch_fail(&self) {
        self.state.lock().voltage_switch_fail = true;
    }

    /// CMD11 answers with an R1 error (ILLEGAL_COMMAND) instead
    /// of completing the switch.
    pub fn set_cmd11_r1_error(&self) {
        self.state.lock().cmd11_r1_error = true;
    }

    /// Make the next SDMA transfer stop at a 512 KiB boundary
    /// once (see `run_dma`).
    pub fn set_sdma_boundary_once(&self) {
        self.state.lock().sdma_boundary_once = true;
    }

    /// Every SD command index the controller ran, in order.
    pub fn cmd_indices(&self) -> Vec<u8> {
        self.state.lock().cmd_log.clone()
    }

    /// Every register write, in order: (offset, value).
    pub fn writes(&self) -> Vec<(u64, u32)> {
        self.state.lock().writes.clone()
    }

    /// True if the driver wrote `value` to register `offset`.
    pub fn wrote(&self, offset: u64, value: u32) -> bool {
        self.state
            .lock()
            .writes
            .iter()
            .any(|&(a, v)| a == offset && v == value)
    }

    /// (length, bus address) pairs the DMA engine walked.
    pub fn walked(&self) -> Vec<(usize, u64)> {
        self.state.lock().walked.clone()
    }

    /// Current 32-bit register value.
    pub fn reg32(&self, offset: u64) -> u32 {
        self.state.lock().get32(offset)
    }

    /// Current 16-bit register value.
    pub fn reg16(&self, offset: u64) -> u16 {
        self.state.lock().get16(offset)
    }

    /// Current 8-bit register value.
    pub fn reg8(&self, offset: u64) -> u8 {
        self.state.lock().regs[offset as usize]
    }

    /// Bytes at identity-mapped physical address `addr` (the
    /// driver's bounce buffer / ADMA table, for assertions).
    pub fn phys_bytes(&self, addr: u64, len: usize) -> Vec<u8> {
        FixtureState::phys_slice(addr, len)
    }

    /// A block from the modelled card's storage, if ever written.
    pub fn stored_block(&self, block: u32) -> Option<[u8; 512]> {
        self.state.lock().image.get(&block).copied()
    }
}

impl SdhciTransport for FixtureTransport {
    fn read8(&self, offset: u64) -> u8 {
        self.state.lock().regs[offset as usize]
    }

    fn read16(&self, offset: u64) -> u16 {
        self.state.lock().get16(offset)
    }

    fn read32(&self, offset: u64) -> u32 {
        let mut st = self.state.lock();
        match offset {
            // The Buffer Data Port streams the staged transfer.
            REG_BUFFER_PORT => {
                let len = st.read_stage.len();
                if len == 0 {
                    return 0;
                }
                let cur = st.read_cursor;
                let w = u32::from_le_bytes(st.read_stage[cur..cur + 4].try_into().unwrap());
                let next = (cur + 4) % len;
                st.read_cursor = next;
                // Re-assert buffer-read-ready at each 512-byte
                // boundary while staged bytes remain: real
                // hardware refills the buffer per block.
                if next % 512 == 0 && next != 0 && next < len {
                    let nis = st.get16(REG_NORMAL_INT_STS);
                    st.set16(REG_NORMAL_INT_STS, nis | NIS_BUFFER_READ_READY);
                }
                w
            }
            // A card is always inserted in the fixture; the DAT
            // level bits track the modelled card state (low
            // during a voltage switch, high otherwise).
            REG_PRESENT_STATE => {
                let base = st.get32(offset) & !PSTATE_DAT_LVL_MASK;
                base | ((st.dat_level as u32) << PSTATE_DAT_LVL_SHIFT) | PSTATE_CARD_INSERTED
            }
            _ => st.get32(offset),
        }
    }

    fn write8(&self, offset: u64, value: u8) {
        let mut st = self.state.lock();
        st.writes.push((offset, u32::from(value)));
        if offset == REG_SOFT_RESET {
            // All software-reset bits are self-clearing (§2.2.16).
            st.regs[offset as usize] = value & !(SRST_ALL | SRST_CMD | SRST_DAT);
        } else {
            st.regs[offset as usize] = value;
        }
        // Power off resets the card's UHS state: the card comes
        // back at 3.3 V, SDR12, DAT[3:0] high.
        if offset == REG_POWER_CONTROL && value & POWER_ON == 0 {
            st.dat_level = 0xF;
            st.current_function = 0;
            st.voltage_switch_pending = false;
            st.tuning_count = 0;
        }
    }

    fn write16(&self, offset: u64, value: u16) {
        let mut st = self.state.lock();
        st.writes.push((offset, u32::from(value)));
        match offset {
            // Interrupt status registers are write-1-to-clear.
            REG_NORMAL_INT_STS | REG_ERROR_INT_STS => {
                let cur = st.get16(offset);
                st.set16(offset, cur & !value);
            }
            // Enabling the internal clock asserts the stable bit.
            // A clock restart after CMD11 completes the voltage
            // switch: the card drives DAT[3:0] high (unless the
            // failure knob holds them low).
            REG_CLOCK_CONTROL => {
                let mut v = value;
                if v & CLK_INTERNAL_EN != 0 {
                    v |= CLK_INTERNAL_STABLE;
                }
                st.set16(offset, v);
                if v & CLK_SD_EN != 0
                    && st.voltage_switch_pending
                    && st.get16(REG_HOST_CONTROL_2) & HC2_VDD_180 != 0
                    && !st.voltage_switch_fail
                {
                    st.dat_level = 0xF;
                    st.voltage_switch_pending = false;
                }
            }
            // A Command write runs the staged command.
            REG_COMMAND => {
                st.set16(offset, value);
                st.exec_cmd((value >> 8) as u8);
            }
            _ => st.set16(offset, value),
        }
    }

    fn write32(&self, offset: u64, value: u32) {
        let mut st = self.state.lock();
        st.writes.push((offset, value));
        if offset == REG_BUFFER_PORT {
            // CMD24/CMD25 capture: commit the blocks once the
            // whole staged run has landed.
            if st.write_stage.is_empty() {
                return;
            }
            let cur = st.write_cursor;
            if cur + 4 > st.write_stage.len() {
                return;
            }
            st.write_stage[cur..cur + 4].copy_from_slice(&value.to_le_bytes());
            st.write_cursor += 4;
            let next = st.write_cursor;
            if next % 512 == 0 && next != 0 && next < st.write_stage.len() {
                let nis = st.get16(REG_NORMAL_INT_STS);
                st.set16(REG_NORMAL_INT_STS, nis | NIS_BUFFER_WRITE_READY);
            }
            if next == st.write_stage.len() {
                let lba = st.write_lba;
                let stage = core::mem::take(&mut st.write_stage);
                for (i, blk) in stage.chunks_exact(512).enumerate() {
                    let mut block = [0u8; 512];
                    block.copy_from_slice(blk);
                    st.image.insert(lba + i as u32, block);
                }
            }
        } else if offset == REG_SDMA_ADDR {
            st.set32(offset, value);
            // A boundary restart completes the pending SDMA
            // transfer: the remaining bytes land at the bounce
            // continuation, and transfer complete raises.
            if let Some(pending) = st.sdma_pending.take() {
                let rest = pending.total - pending.moved;
                let addr = pending.addr + pending.moved as u64;
                let lba = pending.lba + (pending.moved / 512) as u32;
                let read = pending.read;
                st.dma_move(addr, rest, read, lba);
                let cur = st.get16(REG_NORMAL_INT_STS);
                st.set16(REG_NORMAL_INT_STS, cur | NIS_TRANSFER_COMPLETE);
            }
        } else {
            st.set32(offset, value);
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────

/// Install a fixture controller as the global controller and
/// snapshot the block registry; returns the transport + snapshot.
fn install(
    image: BTreeMap<u32, [u8; 512]>,
) -> (
    Arc<FixtureTransport>,
    Vec<narf_block::registry::RegisteredBlockDevice>,
) {
    let saved = narf_block::registry::__snapshot_for_test();
    narf_block::registry::__reset_for_test();
    let transport = Arc::new(FixtureTransport::with_image(image));
    __install_for_test(transport.clone());
    (transport, saved)
}

fn restore(saved: Vec<narf_block::registry::RegisteredBlockDevice>) {
    narf_block::registry::__restore_for_test(saved);
    __reset_for_test();
}

/// Identify the fixture card through the production sequence and
/// publish it exactly as `probe` does after bring-up (identify,
/// store the card, publish + partition scan).
fn identify_and_publish() -> Result<SdCard, &'static str> {
    let ctrl = probed_sdhci().ok_or("fixture controller not installed")?;
    // SAFETY: the fixture transport is exclusively owned by this
    // test and `identify_sequence` runs exactly once against it,
    // as it does at bring-up.
    let card = unsafe { ctrl.identify_sequence() }.map_err(|_| "identify_sequence failed")?;
    *ctrl.card.lock() = Some(card);
    publish_card(card.capacity_blocks);
    Ok(card)
}

/// Identify the fixture card, negotiate the data path exactly as
/// `bring_up` does after identify, then publish. Returns the card
/// and the negotiated profile.
fn identify_negotiate_and_publish() -> Result<(SdCard, DataPath), &'static str> {
    let ctrl = probed_sdhci().ok_or("fixture controller not installed")?;
    // SAFETY: same as `identify_and_publish`.
    let card = unsafe { ctrl.identify_sequence() }.map_err(|_| "identify_sequence failed")?;
    *ctrl.card.lock() = Some(card);
    let path = ctrl.negotiate_data_path();
    publish_card(card.capacity_blocks);
    Ok((card, path))
}

fn fixture_sdhci_partitioned_card() -> TestResult {
    let (transport, saved) = install(partitioned_image());

    let result = (|| {
        let card = identify_and_publish()?;
        // Capacity comes from the card's real CSD (v2.0 formula),
        // and the identify conversation really ran end to end.
        if card.capacity_blocks != 16_777_216 {
            return Err("capacity must come from the CSD (16,777,216 blocks)");
        }
        if !card.ccs || card.rca != FIXTURE_RCA {
            return Err("identified card info wrong (ccs / rca)");
        }
        if card.cid != r2_to_response_words(&FIXTURE_CID) {
            return Err("captured CID does not match the card's CID");
        }
        let indices = transport.cmd_indices();
        for want in [0u8, 2, 3, 7, 8, 9, 16, 41, 55] {
            if !indices.contains(&want) {
                return Err("identify conversation missing a required command");
            }
        }
        // Both MBR partitions appear as sdhci0p<N> children with
        // the windows the MBR entries declare.
        let p1 = narf_block::registry::find_block_device("sdhci0p1")
            .ok_or("sdhci0p1 not registered after publish")?;
        if p1.capacity() != 4096 {
            return Err("sdhci0p1 capacity must be the MBR sector count (4096)");
        }
        let p2 = narf_block::registry::find_block_device("sdhci0p2")
            .ok_or("sdhci0p2 not registered after publish")?;
        if p2.capacity() != 2048 {
            return Err("sdhci0p2 capacity must be the MBR sector count (2048)");
        }
        if narf_block::registry::find_block_device("sdhci0p3").is_some() {
            return Err("empty MBR slots must not register partitions");
        }
        // Reads through a partition land on the card blocks its
        // MBR entry points at — first block, last block, and the
        // second partition's distinct pattern.
        let mut buf = [0u8; 512];
        p1.read(0, 1, &mut buf)
            .map_err(|_| "p1 first-block read failed")?;
        if buf != partition_pattern(0xA1) {
            return Err("sdhci0p1 block 0 must be card block 2048");
        }
        p1.read(4095, 1, &mut buf)
            .map_err(|_| "p1 last-block read failed")?;
        if buf != partition_pattern(0xA2) {
            return Err("sdhci0p1 last block must be card block 6143");
        }
        p2.read(0, 1, &mut buf)
            .map_err(|_| "p2 first-block read failed")?;
        if buf != partition_pattern(0xB1) {
            return Err("sdhci0p2 block 0 must be card block 8192");
        }
        // The partition window is a bound, not a suggestion.
        if p1.read(4096, 1, &mut buf).is_ok() {
            return Err("read past sdhci0p1's end must fail");
        }
        // A write through p2 lands at the translated card block.
        let wpat = partition_pattern(0xC3);
        p2.write(1, 1, &wpat).map_err(|_| "p2 write failed")?;
        match transport.stored_block(8193) {
            Some(b) if b == wpat => {}
            _ => return Err("sdhci0p2 block 1 write must land on card block 8193"),
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_partitioned_card
);

fn fixture_sdhci_unpartitioned_card() -> TestResult {
    // Blank storage: block 0 reads as zeros, so there is no MBR
    // signature — the scan must fail soft and leave the bare card.
    let (_transport, saved) = install(BTreeMap::new());

    let result = (|| {
        let card = identify_and_publish()?;
        if card.capacity_blocks != 16_777_216 {
            return Err("capacity must come from the CSD (16,777,216 blocks)");
        }
        if narf_block::registry::find_block_device("sdhci0").is_none() {
            return Err("sdhci0 must register even without a partition table");
        }
        if narf_block::registry::find_block_device("sdhci0p1").is_some() {
            return Err("unpartitioned card must not gain partition devices");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_unpartitioned_card
);

// ── Data path (#837) ────────────────────────────────────────────────

fn fixture_sdhci_clock_divisor_pure() -> TestResult {
    // 50 MHz base, 400 kHz init (spec 3.00): ceil(125) → next even
    // 126 → 50 MHz / 126 ≈ 397 kHz ≤ 400 kHz.
    if clock_divisor(50_000_000, 400_000, true) != 126 {
        return TestResult::Fail("spec 3.00 divisor for 400 kHz must be 126");
    }
    // 50 MHz base, 25 MHz data clock: divisor 2 either way.
    if clock_divisor(50_000_000, 25_000_000, true) != 2
        || clock_divisor(50_000_000, 25_000_000, false) != 2
    {
        return TestResult::Fail("divisor for 25 MHz from 50 MHz must be 2");
    }
    // Spec ≤ 2.00 rounds up to a power of two: 125 → 128.
    if clock_divisor(50_000_000, 400_000, false) != 128 {
        return TestResult::Fail("spec 2.00 divisor for 400 kHz must be 128");
    }
    // Base already meets the target: divider 1.
    if clock_divisor(25_000_000, 25_000_000, true) != 1 {
        return TestResult::Fail("divisor must be 1 when the base meets the target");
    }
    // Divider field encoding: d = divisor / 2, low 8 bits in
    // [15:8], high 2 bits in [7:6].
    if clock_control_word(2) != 0x0100 || clock_control_word(126) != 0x3F00 {
        return TestResult::Fail("clock control word encoding wrong");
    }
    // DMA mode selection (sdio adma::select rule).
    let adma = CAPS_CAN_DO_ADMA2 | CAPS_CAN_DO_SDMA;
    if select_dma_mode(SPEC_300, adma) != Some(DmaMode::Adma32) {
        return TestResult::Fail("spec 3.00 + ADMA2 must select Adma32");
    }
    if select_dma_mode(SPEC_300, adma | CAPS_CAN_64BIT) != Some(DmaMode::Adma64) {
        return TestResult::Fail("64-bit host + ADMA2 must select Adma64");
    }
    if select_dma_mode(SPEC_200, adma) != Some(DmaMode::Sdma) {
        return TestResult::Fail("spec 2.00 host must fall back to SDMA");
    }
    if select_dma_mode(SPEC_300, CAPS_CAN_DO_SDMA) != Some(DmaMode::Sdma) {
        return TestResult::Fail("SDMA-only host must select Sdma");
    }
    if select_dma_mode(SPEC_300, CAPS_CAN_DO_SDMA | CAPS_CAN_64BIT).is_some() {
        return TestResult::Fail("64-bit host without ADMA2 must not select SDMA");
    }
    if select_dma_mode(SPEC_300, 0).is_some() {
        return TestResult::Fail("host without DMA caps must stay PIO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_clock_divisor_pure
);

fn fixture_sdhci_adma_table_pure() -> TestResult {
    let mut table = [0u8; 64];
    if write_adma_desc(&mut table, 0, 8, 0x1234_5678, 4096, ADMA_ATTR_TRAN_VALID).is_err() {
        return TestResult::Fail("table write failed");
    }
    if write_adma_desc(&mut table, 1, 8, 0, 0, ADMA_ATTR_NOP_END_VALID).is_err() {
        return TestResult::Fail("terminator write failed");
    }
    if read_adma_desc(&table, 0, 8) != Some((ADMA_ATTR_TRAN_VALID, 4096, 0x1234_5678)) {
        return TestResult::Fail("TRAN descriptor must round-trip");
    }
    if read_adma_desc(&table, 1, 8) != Some((ADMA_ATTR_NOP_END_VALID, 0, 0)) {
        return TestResult::Fail("NOP/END terminator must round-trip");
    }
    // 64-bit descriptors carry the high address; length 0 means 65536.
    let mut table64 = [0u8; 64];
    if write_adma_desc(&mut table64, 0, 12, 0x1_2345_6789, 0, ADMA_ATTR_TRAN_VALID).is_err() {
        return TestResult::Fail("64-bit table write failed");
    }
    if read_adma_desc(&table64, 0, 12) != Some((ADMA_ATTR_TRAN_VALID, 0, 0x1_2345_6789)) {
        return TestResult::Fail("64-bit descriptor must round-trip");
    }
    if write_adma_desc(&mut table, 100, 8, 0, 0, ADMA_ATTR_TRAN_VALID).is_ok() {
        return TestResult::Fail("out-of-table descriptor write must fail");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_adma_table_pure
);

fn fixture_sdhci_datapath_negotiate() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        // 50 MHz base → 25 MHz data clock, 4-bit bus, ADMA2-32.
        if path.clock_hz != 25_000_000 {
            return Err("clock must raise to 25 MHz from a 50 MHz base");
        }
        if path.bus_width != 4 {
            return Err("bus must negotiate to 4-bit");
        }
        if path.dma_mode != Some(DmaMode::Adma32) {
            return Err("DMA mode must be Adma32 for these caps");
        }
        // The negotiation conversation really ran: SCR probe +
        // bus-width switch.
        let indices = transport.cmd_indices();
        if !indices.contains(&51) {
            return Err("negotiate must read the SCR (ACMD51)");
        }
        if !indices.contains(&6) {
            return Err("negotiate must switch the bus width (ACMD6)");
        }
        // Clock register: divider field 0x01 (divisor 2) + SD clock
        // enabled; host control: 4-bit bus bit set.
        if transport.reg16(REG_CLOCK_CONTROL) & 0xFF00 != 0x0100 {
            return Err("clock divider must encode divisor 2 for 25 MHz");
        }
        if transport.reg16(REG_CLOCK_CONTROL) & CLK_SD_EN == 0 {
            return Err("SD clock must be enabled after the raise");
        }
        if transport.reg8(REG_HOST_CONTROL_1) & HC_4BIT_BUS == 0 {
            return Err("HOST_CONTROL must select the 4-bit bus");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_datapath_negotiate
);

fn fixture_sdhci_multiblock_pio() -> TestResult {
    // No negotiate: DMA stays unadmitted, so the multi-block
    // path runs over PIO.
    let (transport, saved) = install(BTreeMap::new());

    let result = (|| {
        identify_and_publish()?;
        // 4-block write + read-back through CMD25 / CMD18.
        let mut data = alloc::vec![0u8; 4 * 512];
        for b in 0..4 {
            data[b * 512..(b + 1) * 512].copy_from_slice(&partition_pattern(0x40 + b as u8));
        }
        with_controller(|c| c.write_blocks(100, &data))
            .ok_or("no controller")?
            .map_err(|_| "PIO multi-block write failed")?;
        let mut back = alloc::vec![0u8; 4 * 512];
        with_controller(|c| c.read_blocks(100, &mut back))
            .ok_or("no controller")?
            .map_err(|_| "PIO multi-block read failed")?;
        if back != data {
            return Err("PIO multi-block read-back must match the written data");
        }
        for b in 0..4 {
            match transport.stored_block(100 + b as u32) {
                Some(blk) if blk == partition_pattern(0x40 + b as u8) => {}
                _ => return Err("PIO multi-block write must land on the card blocks"),
            }
        }
        let indices = transport.cmd_indices();
        if !indices.contains(&18) || !indices.contains(&25) {
            return Err("multi-block calls must issue CMD18/CMD25");
        }
        if indices.contains(&17) || indices.contains(&24) {
            return Err("multi-block calls must not fall back to CMD17/CMD24");
        }
        // 65 blocks: a 64-block CMD18/CMD25 chunk plus a trailing
        // single-block CMD17/CMD24.
        let mut big = alloc::vec![0u8; 65 * 512];
        for b in 0..65 {
            big[b * 512..(b + 1) * 512].copy_from_slice(&partition_pattern((b & 0xFF) as u8));
        }
        with_controller(|c| c.write_blocks(1000, &big))
            .ok_or("no controller")?
            .map_err(|_| "65-block PIO write failed")?;
        let mut big_back = alloc::vec![0u8; 65 * 512];
        with_controller(|c| c.read_blocks(1000, &mut big_back))
            .ok_or("no controller")?
            .map_err(|_| "65-block PIO read failed")?;
        if big_back != big {
            return Err("65-block PIO read-back must match");
        }
        let indices = transport.cmd_indices();
        if indices.iter().filter(|&&i| i == 17).count() != 1
            || indices.iter().filter(|&&i| i == 24).count() != 1
        {
            return Err("a 65-block transfer must end with one CMD17 + one CMD24");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_multiblock_pio
);

fn fixture_sdhci_dma_adma32() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        if path.dma_mode != Some(DmaMode::Adma32) {
            return Err("DMA mode must be Adma32 for these caps");
        }
        // 8-block DMA write + read-back.
        let mut data = alloc::vec![0u8; 8 * 512];
        for b in 0..8 {
            data[b * 512..(b + 1) * 512].copy_from_slice(&partition_pattern(0x70 + b as u8));
        }
        with_controller(|c| c.write_blocks(200, &data))
            .ok_or("no controller")?
            .map_err(|_| "ADMA2 write failed")?;
        let mut back = alloc::vec![0u8; 8 * 512];
        with_controller(|c| c.read_blocks(200, &mut back))
            .ok_or("no controller")?
            .map_err(|_| "ADMA2 read failed")?;
        if back != data {
            return Err("ADMA2 read-back must match the written data");
        }
        for b in 0..8 {
            match transport.stored_block(200 + b as u32) {
                Some(blk) if blk == partition_pattern(0x70 + b as u8) => {}
                _ => return Err("ADMA2 write must land on the card blocks"),
            }
        }
        // The engine walked one 4096-byte segment per transfer,
        // at the bounce address; the host selected ADMA32 and
        // programmed the table address.
        let walked = transport.walked();
        if walked.len() != 2 || walked[0].0 != 4096 || walked[1].0 != 4096 {
            return Err("ADMA engine must walk one 4096-byte segment per transfer");
        }
        if walked[0].1 != walked[1].1 {
            return Err("both transfers must use the same bounce buffer");
        }
        if transport.reg8(REG_HOST_CONTROL_1) & HC_DMA_MASK != HC_DMA_ADMA32 {
            return Err("HOST_CONTROL must select ADMA32");
        }
        let table = u64::from(transport.reg32(REG_ADMA_ADDR));
        if !transport.wrote(REG_ADMA_ADDR, table as u32) {
            return Err("ADMA table address must be programmed");
        }
        let raw = transport.phys_bytes(table, 24);
        if read_adma_desc(&raw, 0, 8) != Some((ADMA_ATTR_TRAN_VALID, 4096, walked[0].1)) {
            return Err("descriptor 0 must be TRAN/VALID for the bounce buffer");
        }
        if read_adma_desc(&raw, 1, 8) != Some((ADMA_ATTR_NOP_END_VALID, 0, 0)) {
            return Err("descriptor 1 must be the NOP/END terminator");
        }
        let indices = transport.cmd_indices();
        if !indices.contains(&18) || !indices.contains(&25) {
            return Err("DMA transfers must issue CMD18/CMD25");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/storage/sdhci/fixture", fixture_sdhci_dma_adma32);

fn fixture_sdhci_dma_adma64() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(FIXTURE_CAPS_64BIT, FIXTURE_SPEC_VERSION);

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        if path.dma_mode != Some(DmaMode::Adma64) {
            return Err("DMA mode must be Adma64 for 64-bit caps");
        }
        let mut data = alloc::vec![0u8; 2 * 512];
        for b in 0..2 {
            data[b * 512..(b + 1) * 512].copy_from_slice(&partition_pattern(0x90 + b as u8));
        }
        with_controller(|c| c.write_blocks(300, &data))
            .ok_or("no controller")?
            .map_err(|_| "ADMA64 write failed")?;
        let mut back = alloc::vec![0u8; 2 * 512];
        with_controller(|c| c.read_blocks(300, &mut back))
            .ok_or("no controller")?
            .map_err(|_| "ADMA64 read failed")?;
        if back != data {
            return Err("ADMA64 read-back must match");
        }
        if transport.reg8(REG_HOST_CONTROL_1) & HC_DMA_MASK != HC_DMA_ADMA64 {
            return Err("HOST_CONTROL must select ADMA64");
        }
        let table = u64::from(transport.reg32(REG_ADMA_ADDR))
            | (u64::from(transport.reg32(REG_ADMA_ADDR_HI)) << 32);
        if !transport.wrote(REG_ADMA_ADDR_HI, (table >> 32) as u32) {
            return Err("ADMA64 must program the high table address");
        }
        let raw = transport.phys_bytes(table, 24);
        let walked = transport.walked();
        if walked.len() != 2 || walked[0].0 != 1024 {
            return Err("ADMA64 engine must walk one 1024-byte segment per transfer");
        }
        if read_adma_desc(&raw, 0, 12) != Some((ADMA_ATTR_TRAN_VALID, 1024, walked[0].1)) {
            return Err("64-bit descriptor 0 must be TRAN/VALID for the bounce buffer");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/storage/sdhci/fixture", fixture_sdhci_dma_adma64);

fn fixture_sdhci_dma_sdma() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(FIXTURE_CAPS_SDMA_ONLY, FIXTURE_SPEC_VERSION);

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        if path.dma_mode != Some(DmaMode::Sdma) {
            return Err("DMA mode must be Sdma for SDMA-only caps");
        }
        let mut data = alloc::vec![0u8; 4 * 512];
        for b in 0..4 {
            data[b * 512..(b + 1) * 512].copy_from_slice(&partition_pattern(0x50 + b as u8));
        }
        with_controller(|c| c.write_blocks(400, &data))
            .ok_or("no controller")?
            .map_err(|_| "SDMA write failed")?;
        let mut back = alloc::vec![0u8; 4 * 512];
        with_controller(|c| c.read_blocks(400, &mut back))
            .ok_or("no controller")?
            .map_err(|_| "SDMA read failed")?;
        if back != data {
            return Err("SDMA read-back must match");
        }
        if transport.reg8(REG_HOST_CONTROL_1) & HC_DMA_MASK != HC_DMA_SDMA {
            return Err("HOST_CONTROL must select SDMA");
        }
        let walked = transport.walked();
        if walked.len() != 2 || walked[0].0 != 2048 {
            return Err("SDMA engine must walk one 2048-byte transfer per call");
        }
        if transport.reg32(REG_SDMA_ADDR) as u64 != walked[1].1 {
            return Err("SDMA address register must hold the bounce address");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/storage/sdhci/fixture", fixture_sdhci_dma_sdma);

fn fixture_sdhci_dma_sdma_boundary() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(FIXTURE_CAPS_SDMA_ONLY, FIXTURE_SPEC_VERSION);
    transport.set_sdma_boundary_once();

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        if path.dma_mode != Some(DmaMode::Sdma) {
            return Err("DMA mode must be Sdma for SDMA-only caps");
        }
        let mut data = alloc::vec![0u8; 4 * 512];
        for b in 0..4 {
            data[b * 512..(b + 1) * 512].copy_from_slice(&partition_pattern(0x60 + b as u8));
        }
        with_controller(|c| c.write_blocks(500, &data))
            .ok_or("no controller")?
            .map_err(|_| "SDMA boundary write failed")?;
        let mut back = alloc::vec![0u8; 4 * 512];
        with_controller(|c| c.read_blocks(500, &mut back))
            .ok_or("no controller")?
            .map_err(|_| "SDMA boundary read failed")?;
        if back != data {
            return Err("SDMA boundary-restart transfer must still deliver the data");
        }
        // The driver reprogrammed the SDMA address to the next
        // 512 KiB boundary after the DMA interrupt.
        let writes = transport.writes();
        let first = writes
            .iter()
            .find(|&&(a, _)| a == REG_SDMA_ADDR)
            .ok_or("SDMA address never programmed")?
            .1 as u64;
        let next = (first & !(FIXTURE_SDMA_BOUNDARY - 1)) + FIXTURE_SDMA_BOUNDARY;
        if !transport.wrote(REG_SDMA_ADDR, next as u32) {
            return Err("SDMA address must restart at the next 512 KiB boundary");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_dma_sdma_boundary
);

fn fixture_sdhci_dma_fallback_pio() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(FIXTURE_CAPS_PIO_ONLY, FIXTURE_SPEC_VERSION);

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        if path.dma_mode.is_some() {
            return Err("host without DMA caps must stay PIO");
        }
        // Clock + bus width still negotiate; only DMA stays off.
        if path.clock_hz != 25_000_000 || path.bus_width != 4 {
            return Err("PIO-only host must still raise the clock and widen the bus");
        }
        let mut data = alloc::vec![0u8; 4 * 512];
        for b in 0..4 {
            data[b * 512..(b + 1) * 512].copy_from_slice(&partition_pattern(0x20 + b as u8));
        }
        with_controller(|c| c.write_blocks(600, &data))
            .ok_or("no controller")?
            .map_err(|_| "PIO fallback write failed")?;
        let mut back = alloc::vec![0u8; 4 * 512];
        with_controller(|c| c.read_blocks(600, &mut back))
            .ok_or("no controller")?
            .map_err(|_| "PIO fallback read failed")?;
        if back != data {
            return Err("PIO fallback read-back must match");
        }
        if transport.reg8(REG_HOST_CONTROL_1) & HC_DMA_MASK != 0 {
            return Err("PIO fallback must leave the DMA select clear");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_dma_fallback_pio
);

fn fixture_sdhci_multiblock_block_device() -> TestResult {
    let (transport, saved) = install(partitioned_image());

    let result = (|| {
        let (_card, _path) = identify_negotiate_and_publish()?;
        let p2 = narf_block::registry::find_block_device("sdhci0p2")
            .ok_or("sdhci0p2 not registered after publish")?;
        // A 4-block partition read goes through one CMD18, and a
        // 4-block write through one CMD25 — the block layer no
        // longer issues a command per block.
        let mut data = alloc::vec![0u8; 4 * 512];
        for b in 0..4 {
            data[b * 512..(b + 1) * 512].copy_from_slice(&partition_pattern(0xD0 + b as u8));
        }
        p2.write(0, 4, &data)
            .map_err(|_| "p2 4-block write failed")?;
        let mut back = alloc::vec![0u8; 4 * 512];
        p2.read(0, 4, &mut back)
            .map_err(|_| "p2 4-block read failed")?;
        if back != data {
            return Err("p2 4-block read-back must match");
        }
        let indices = transport.cmd_indices();
        let n18 = indices.iter().filter(|&&i| i == 18).count();
        let n25 = indices.iter().filter(|&&i| i == 25).count();
        if n18 != 1 || n25 != 1 {
            return Err("one CMD18 + one CMD25 must serve the 4-block partition I/O");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_multiblock_block_device
);

// ── #838: UHS-I (1.8 V switch + tuning) ─────────────────────────

/// UHS fixture Capabilities with a 100 MHz base clock.
const UHS_CAPS_100: u32 = (100u32 << 8) | 0x0040_0000 | 0x0008_0000 | 0x0100_0000 | 0x0400_0000;
/// UHS fixture Capabilities with a 208 MHz base clock.
const UHS_CAPS_208: u32 = (208u32 << 8) | 0x0040_0000 | 0x0008_0000 | 0x0100_0000 | 0x0400_0000;

fn uhs_cmd_count(indices: &[u8], want: u8) -> usize {
    indices.iter().filter(|&&i| i == want).count()
}

fn fixture_sdhci_uhs_pure() -> TestResult {
    // CMD6 argument encodings (SD Physical Layer Spec §4.3.10):
    // mode bit 31 + per-group 4-bit fields, 0xF = no change.
    if cmd6_arg(false, 0, 0) != 0x00FFFFF0 {
        return TestResult::Fail("CMD6 check of group 1 must be 0x00FFFFF0");
    }
    if cmd6_arg(true, 0, 2) != 0x80FFFFF2 {
        return TestResult::Fail("CMD6 switch to SDR50 must be 0x80FFFFF2");
    }
    if cmd6_arg(true, 0, 1) != 0x80FFFFF1 {
        return TestResult::Fail("CMD6 switch to SDR25 must be 0x80FFFFF1");
    }
    if cmd6_arg(true, 2, 3) != 0x80FFFF3F {
        return TestResult::Fail("CMD6 switch of group 2 to 3 must be 0x80FFFF3F");
    }
    // Switch-status parsing: support in byte 13, current
    // function in byte 16's low nibble.
    let status = SwitchStatus::parse(&switch_status_bytes(0x1F, 3));
    if status.group1_support() != 0x1F {
        return TestResult::Fail("SwitchStatus must report byte 13 as group-1 support");
    }
    if status.group1_function() != 3 {
        return TestResult::Fail("SwitchStatus must report byte 16 low nibble as current function");
    }
    if !status.supports_function(3) || status.supports_function(4) {
        return TestResult::Fail("SwitchStatus supports_function must match the support bits");
    }
    // Mode table: function values, max clocks, HOST_CONTROL2
    // UHS Mode Select values, tuning requirement.
    if UhsMode::Sdr25.function() != 1
        || UhsMode::Sdr25.max_clock_hz() != 50_000_000
        || UhsMode::Sdr25.host_control2() != 0x1
        || UhsMode::Sdr25.needs_tuning(false)
    {
        return TestResult::Fail("SDR25 table row wrong");
    }
    if UhsMode::Sdr50.function() != 2
        || UhsMode::Sdr50.max_clock_hz() != 100_000_000
        || UhsMode::Sdr50.host_control2() != 0x2
        || UhsMode::Sdr50.needs_tuning(false)
        || !UhsMode::Sdr50.needs_tuning(true)
    {
        return TestResult::Fail("SDR50 table row wrong");
    }
    if UhsMode::Sdr104.function() != 3
        || UhsMode::Sdr104.max_clock_hz() != 208_000_000
        || UhsMode::Sdr104.host_control2() != 0x3
        || !UhsMode::Sdr104.needs_tuning(false)
    {
        return TestResult::Fail("SDR104 table row wrong");
    }
    if UhsMode::Ddr50.function() != 4
        || UhsMode::Ddr50.max_clock_hz() != 50_000_000
        || UhsMode::Ddr50.host_control2() != 0x4
        || UhsMode::Ddr50.needs_tuning(false)
        || !UhsMode::Ddr50.needs_tuning(true)
    {
        return TestResult::Fail("DDR50 table row wrong");
    }
    if UhsMode::Sdr12.function() != 0
        || UhsMode::Sdr12.max_clock_hz() != 25_000_000
        || UhsMode::Sdr12.host_control2() != 0x0
        || UhsMode::Sdr12.needs_tuning(true)
    {
        return TestResult::Fail("SDR12 table row wrong");
    }
    // Mode selection matrix (Linux `sd_update_bus_speed_mode`
    // preference: SDR104 > DDR50 > SDR50 > SDR25).
    let cases: [(u8, u32, u32, Option<UhsMode>); 8] = [
        (0x1F, 0x7, 50_000_000, Some(UhsMode::Sdr25)),
        (0x1F, 0x7, 100_000_000, Some(UhsMode::Sdr50)),
        (0x1F, 0x7, 208_000_000, Some(UhsMode::Sdr104)),
        (0x1F, 0x4, 50_000_000, Some(UhsMode::Ddr50)),
        (0x1F, 0x5, 100_000_000, Some(UhsMode::Ddr50)),
        (0x03, 0x7, 208_000_000, Some(UhsMode::Sdr25)),
        (0x01, 0x7, 208_000_000, None),
        (0x1F, 0x0, 208_000_000, Some(UhsMode::Sdr25)),
    ];
    for (support, caps1, base, want) in cases {
        if select_uhs_mode(support, caps1, base) != want {
            return TestResult::Fail("select_uhs_mode matrix row wrong");
        }
    }
    // The tuning block is the spec's fixed 64-byte pattern.
    if TUNING_PATTERN_4BIT.len() != 64 || TUNING_PATTERN_4BIT[0] != 0xFF {
        return TestResult::Fail("tuning pattern must be the 64-byte spec pattern");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sdhci/fixture", fixture_sdhci_uhs_pure);

fn fixture_sdhci_uhs_sdr25() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(FIXTURE_CAPS_UHS, FIXTURE_SPEC_VERSION);
    transport.set_uhs_card(0x03); // SDR12 | SDR25

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        if path.uhs_mode != Some(UhsMode::Sdr25) {
            return Err("UHS mode must be SDR25 for an SDR12|SDR25 card on a 50 MHz base");
        }
        if path.clock_hz != 50_000_000 {
            return Err("SDR25 clock must be 50 MHz");
        }
        if path.bus_width != 4 || path.dma_mode != Some(DmaMode::Adma32) {
            return Err("SDR25 path must keep the 4-bit bus and ADMA2");
        }
        let indices = transport.cmd_indices();
        if !indices.contains(&11) {
            return Err("SDR25 negotiate must issue CMD11");
        }
        if uhs_cmd_count(&indices, 6) != 3 {
            return Err("SDR25 negotiate must issue three CMD6s (ACMD6 + query + switch)");
        }
        // HOST_CONTROL2: VDD_180 + SDR25.
        if transport.reg16(REG_HOST_CONTROL_2) != 0x0009 {
            return Err("HOST_CONTROL2 must be VDD_180 | SDR25 after SDR25 negotiate");
        }
        // I/O still works at the negotiated speed.
        let dev = narf_block::registry::find_block_device("sdhci0")
            .ok_or("sdhci0 not registered after publish")?;
        let mut buf = [0u8; 512];
        dev.read(0, 1, &mut buf)
            .map_err(|_| "post-UHS read failed")?;
        if buf != [0u8; 512] {
            return Err("post-UHS read of a blank card must be zeros");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/storage/sdhci/fixture", fixture_sdhci_uhs_sdr25);

fn fixture_sdhci_uhs_sdr50_tuning() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(UHS_CAPS_100, FIXTURE_SPEC_VERSION);
    transport.set_caps1(FIXTURE_CAPS1_SDR50 | FIXTURE_CAPS1_TUNING_SDR50);
    transport.set_uhs_card(0x07); // SDR12 | SDR25 | SDR50
    transport.set_tuning_iters(3);

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        if path.uhs_mode != Some(UhsMode::Sdr50) {
            return Err("UHS mode must be SDR50 for an SDR50 card on a 100 MHz base");
        }
        if path.clock_hz != 100_000_000 {
            return Err("SDR50 clock must be 100 MHz");
        }
        let indices = transport.cmd_indices();
        if uhs_cmd_count(&indices, 19) != 3 {
            return Err("SDR50 tuning must run exactly 3 CMD19s for this fixture");
        }
        // TUNED_CLK set, EXEC_TUNING clear.
        let hc2 = transport.reg16(REG_HOST_CONTROL_2);
        if hc2 & 0x0080 == 0 {
            return Err("TUNED_CLK must be set after successful SDR50 tuning");
        }
        if hc2 & 0x0040 != 0 {
            return Err("EXEC_TUNING must be clear after successful SDR50 tuning");
        }
        if hc2 & 0x0007 != 0x2 {
            return Err("HOST_CONTROL2 UHS bits must select SDR50");
        }
        // I/O still works after tuning.
        let dev = narf_block::registry::find_block_device("sdhci0")
            .ok_or("sdhci0 not registered after publish")?;
        let mut buf = [0u8; 512];
        dev.read(0, 1, &mut buf)
            .map_err(|_| "post-tuning read failed")?;
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_uhs_sdr50_tuning
);

fn fixture_sdhci_uhs_sdr104() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(UHS_CAPS_208, FIXTURE_SPEC_VERSION);
    transport.set_caps1(FIXTURE_CAPS1_SDR104);
    transport.set_uhs_card(0x1F); // SDR12 | SDR25 | SDR50 | SDR104 | DDR50
    transport.set_tuning_iters(2);

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        if path.uhs_mode != Some(UhsMode::Sdr104) {
            return Err("UHS mode must be SDR104 for a full-UHS card on a 208 MHz base");
        }
        if path.clock_hz != 208_000_000 {
            return Err("SDR104 clock must be 208 MHz");
        }
        let indices = transport.cmd_indices();
        if uhs_cmd_count(&indices, 19) != 2 {
            return Err("SDR104 tuning must run exactly 2 CMD19s for this fixture");
        }
        if transport.reg16(REG_HOST_CONTROL_2) & 0x0007 != 0x3 {
            return Err("HOST_CONTROL2 UHS bits must select SDR104");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/storage/sdhci/fixture", fixture_sdhci_uhs_sdr104);

fn fixture_sdhci_uhs_ddr50() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(FIXTURE_CAPS_UHS, FIXTURE_SPEC_VERSION);
    transport.set_caps1(FIXTURE_CAPS1_DDR50);
    transport.set_uhs_card(0x17); // SDR12 | SDR25 | SDR50 | DDR50

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        // DDR50 beats SDR50 in the preference order when both
        // are supported, and needs no tuning unless the SDR50
        // tuning bit is set.
        if path.uhs_mode != Some(UhsMode::Ddr50) {
            return Err("UHS mode must be DDR50 when card and host support it");
        }
        if path.clock_hz != 50_000_000 {
            return Err("DDR50 clock must be 50 MHz");
        }
        let indices = transport.cmd_indices();
        if indices.contains(&19) {
            return Err("DDR50 without the tuning bit must not run CMD19");
        }
        if transport.reg16(REG_HOST_CONTROL_2) != 0x000C {
            return Err("HOST_CONTROL2 must be VDD_180 | DDR50 after DDR50 negotiate");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/storage/sdhci/fixture", fixture_sdhci_uhs_ddr50);

fn fixture_sdhci_uhs_no_1v8_host() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    // Default caps: no VDD_180 bit. The card would accept a
    // switch, but the host cannot offer one.
    transport.set_uhs_card(0x03);

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        if path.uhs_mode.is_some() {
            return Err("a host without VDD_180 must not negotiate UHS");
        }
        if path.clock_hz != 25_000_000 {
            return Err("a non-UHS host must stay at the 25 MHz default speed");
        }
        let indices = transport.cmd_indices();
        if indices.contains(&11) {
            return Err("a non-UHS host must never issue CMD11");
        }
        if uhs_cmd_count(&indices, 6) != 1 {
            return Err("a non-UHS negotiate must issue only the ACMD6 bus-width CMD6");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_uhs_no_1v8_host
);

fn fixture_sdhci_uhs_no_s18a() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(FIXTURE_CAPS_UHS, FIXTURE_SPEC_VERSION);
    // No set_uhs_card: the fixture card answers ACMD41 without
    // S18A, so no switch is attempted.

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        if path.uhs_mode.is_some() {
            return Err("a card without S18A must not negotiate UHS");
        }
        if path.clock_hz != 25_000_000 {
            return Err("a non-S18A card must stay at the 25 MHz default speed");
        }
        let indices = transport.cmd_indices();
        if indices.contains(&11) {
            return Err("a non-S18A card must never see CMD11");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/storage/sdhci/fixture", fixture_sdhci_uhs_no_s18a);

fn fixture_sdhci_uhs_sdr12_only() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(FIXTURE_CAPS_UHS, FIXTURE_SPEC_VERSION);
    transport.set_uhs_card(0x01); // SDR12 only

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        // The switch itself runs (the card allows it), but there
        // is no faster mode to move to: SDR12 at 25 MHz is the
        // same rate the card already had at 3.3 V.
        if path.uhs_mode != Some(UhsMode::Sdr12) {
            return Err("an SDR12-only card must record SDR12 after the switch");
        }
        if path.clock_hz != 25_000_000 {
            return Err("an SDR12-only card must stay at 25 MHz");
        }
        let indices = transport.cmd_indices();
        if !indices.contains(&11) {
            return Err("an SDR12-only card must still see CMD11 (the switch runs)");
        }
        if uhs_cmd_count(&indices, 6) != 2 {
            return Err("an SDR12-only negotiate must issue two CMD6s (ACMD6 + query)");
        }
        // 1.8 V rail on, UHS bits SDR12.
        if transport.reg16(REG_HOST_CONTROL_2) != 0x0008 {
            return Err("HOST_CONTROL2 must be VDD_180 only for SDR12");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_uhs_sdr12_only
);

fn fixture_sdhci_uhs_voltage_switch_fail() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(FIXTURE_CAPS_UHS, FIXTURE_SPEC_VERSION);
    transport.set_uhs_card(0x03);
    transport.set_voltage_switch_fail();

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        // Recovery: the card power-cycled back to 3.3 V and was
        // re-identified without UHS — and it still works.
        if path.uhs_mode.is_some() {
            return Err("after a failed switch the card must come back with no UHS mode");
        }
        if path.clock_hz != 25_000_000 || path.bus_width != 4 {
            return Err("after a failed switch the card must come back at 25 MHz, 4-bit");
        }
        let indices = transport.cmd_indices();
        if uhs_cmd_count(&indices, 0) != 2 {
            return Err("recovery must re-run the identify sequence (two CMD0s)");
        }
        if uhs_cmd_count(&indices, 11) != 1 {
            return Err("recovery must not retry CMD11");
        }
        if !transport.wrote(REG_POWER_CONTROL, 0x0E) {
            return Err("recovery must power-cycle the card (POWER_CONTROL off)");
        }
        if transport.reg16(REG_HOST_CONTROL_2) & HC2_VDD_180 != 0 {
            return Err("recovery must leave VDD_180 clear");
        }
        let dev = narf_block::registry::find_block_device("sdhci0")
            .ok_or("sdhci0 not registered after recovery")?;
        let mut buf = [0u8; 512];
        dev.read(0, 1, &mut buf)
            .map_err(|_| "post-recovery read failed")?;
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_uhs_voltage_switch_fail
);

fn fixture_sdhci_uhs_tuning_fail_fallback() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(UHS_CAPS_100, FIXTURE_SPEC_VERSION);
    transport.set_caps1(FIXTURE_CAPS1_SDR50 | FIXTURE_CAPS1_TUNING_SDR50);
    transport.set_uhs_card(0x07);
    transport.set_tuning_never();

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        // Tuning exhausted its 40-iteration budget and fell back
        // to SDR25 — never I/O on an unproven sampling point.
        if path.uhs_mode != Some(UhsMode::Sdr25) {
            return Err("a tuning failure must fall back to SDR25");
        }
        if path.clock_hz != 50_000_000 {
            return Err("the SDR25 fallback clock must be 50 MHz");
        }
        let indices = transport.cmd_indices();
        if uhs_cmd_count(&indices, 19) != 40 {
            return Err("tuning must run exactly 40 CMD19s before giving up");
        }
        let hc2 = transport.reg16(REG_HOST_CONTROL_2);
        if hc2 & 0x0080 != 0 {
            return Err("TUNED_CLK must be clear after a tuning failure");
        }
        if hc2 & 0x0040 != 0 {
            return Err("EXEC_TUNING must be clear after a tuning failure");
        }
        let dev = narf_block::registry::find_block_device("sdhci0")
            .ok_or("sdhci0 not registered after tuning fallback")?;
        let mut buf = [0u8; 512];
        dev.read(0, 1, &mut buf)
            .map_err(|_| "post-fallback read failed")?;
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_uhs_tuning_fail_fallback
);

fn fixture_sdhci_uhs_cmd11_rejected() -> TestResult {
    let (transport, saved) = install(BTreeMap::new());
    transport.set_caps(FIXTURE_CAPS_UHS, FIXTURE_SPEC_VERSION);
    transport.set_uhs_card(0x03);
    transport.set_cmd11_r1_error();

    let result = (|| {
        let (_card, path) = identify_negotiate_and_publish()?;
        // An R1 error on CMD11 means the card refused the switch
        // and is still at 3.3 V: no power cycle, no re-identify.
        if path.uhs_mode.is_some() {
            return Err("a rejected CMD11 must leave no UHS mode");
        }
        if path.clock_hz != 25_000_000 {
            return Err("a rejected CMD11 must leave the 25 MHz default speed");
        }
        let indices = transport.cmd_indices();
        if uhs_cmd_count(&indices, 0) != 1 {
            return Err("a rejected CMD11 must not re-run identify");
        }
        if transport.wrote(REG_POWER_CONTROL, 0x0E) {
            return Err("a rejected CMD11 must not power-cycle the card");
        }
        let dev = narf_block::registry::find_block_device("sdhci0")
            .ok_or("sdhci0 not registered after a rejected CMD11")?;
        let mut buf = [0u8; 512];
        dev.read(0, 1, &mut buf)
            .map_err(|_| "read after a rejected CMD11 failed")?;
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci/fixture",
    fixture_sdhci_uhs_cmd11_rejected
);

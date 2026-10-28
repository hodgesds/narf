//! Register-level fixture for the SDHCI driver: a modelled SDHCI
//! register file + SD card behind the [`SdhciTransport`] seam, so
//! the identify → publish → partition-scan conversation runs end
//! to end in kernel tests without silicon.
//!
//! The model implements the hardware contract the driver programs,
//! from the **SD Host Controller Simplified Specification 3.00**:
//!
//! - Normal / Error Interrupt Status are write-1-to-clear
//!   (§2.2.18 / §2.2.19); Software Reset's SRST_ALL bit is
//!   self-clearing (§2.2.16).
//! - A Command register write (§2.2.6) executes the staged
//!   command: Command Complete sets; a data command also sets
//!   Buffer Read / Write Ready and Transfer Complete. Responses
//!   land in the Response registers in the layout §2.2.7 defines
//!   for R2 — the register content with CRC7 + end bit stripped,
//!   which is the shifted layout `sd_proto` parses.
//! - The Buffer Data Port (§2.2.4) streams the addressed card
//!   block word-by-word on CMD17 and captures it on CMD24.
//! - Present State (§2.2.9) reports a card inserted.
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

/// RCA the fixture card answers CMD3 with.
const FIXTURE_RCA: u16 = 0x0001;

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

#[derive(Debug)]
struct FixtureState {
    /// The 0x100-byte register file, byte-addressed.
    regs: [u8; 0x100],
    /// Sparse card storage, keyed by block index.
    image: BTreeMap<u32, [u8; 512]>,
    /// Block staged for the Buffer Data Port by CMD17.
    read_stage: [u8; 512],
    /// Byte cursor into `read_stage`.
    read_cursor: usize,
    /// Buffer Data Port capture for CMD24.
    write_stage: [u8; 512],
    /// Byte cursor into `write_stage`.
    write_cursor: usize,
    /// Block address of the in-flight CMD24.
    write_lba: u32,
    /// Every command index issued, in order.
    cmd_log: Vec<u8>,
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

    /// Execute the command staged by a Command-register write.
    fn exec_cmd(&mut self, index: u8) {
        let arg = self.get32(REG_ARGUMENT);
        self.cmd_log.push(index);
        let mut nis = NIS_CMD_COMPLETE;
        match index {
            // CMD8 — R7 echoes the voltage + check-pattern bits.
            8 => self.set32(REG_RESPONSE_0, arg & 0x0000_0FFF),
            // ACMD41 — R3 OCR: busy set, CCS set (SDHC), the
            // 3.3 V operating window.
            41 => self.set32(REG_RESPONSE_0, 0x8000_0000 | 0x4000_0000 | 0x00FF_8000),
            // CMD2 — R2 CID.
            2 => self.set_response_136(r2_to_response_words(&FIXTURE_CID)),
            // CMD3 — R6: RCA in the high half.
            3 => self.set32(REG_RESPONSE_0, (FIXTURE_RCA as u32) << 16),
            // CMD9 — R2 CSD.
            9 => self.set_response_136(r2_to_response_words(&FIXTURE_CSD)),
            // CMD17 — stage the addressed block at the Buffer
            // Data Port (the card is block-addressed, CCS = 1).
            17 => {
                self.read_stage = self.image.get(&arg).copied().unwrap_or([0u8; 512]);
                self.read_cursor = 0;
                nis |= NIS_BUFFER_READ_READY | NIS_TRANSFER_COMPLETE;
            }
            // CMD24 — arm the Buffer Data Port capture.
            24 => {
                self.write_lba = arg;
                self.write_cursor = 0;
                nis |= NIS_BUFFER_WRITE_READY | NIS_TRANSFER_COMPLETE;
            }
            // CMD0 / CMD7 / CMD16 / CMD55 and everything else: a
            // plain completion with a zero response.
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
        FixtureTransport {
            state: IrqSafeSpinLock::new(FixtureState {
                regs: [0; 0x100],
                image,
                read_stage: [0u8; 512],
                read_cursor: 0,
                write_stage: [0u8; 512],
                write_cursor: 0,
                write_lba: 0,
                cmd_log: Vec::new(),
            }),
        }
    }

    /// Every SD command index the controller ran, in order.
    pub fn cmd_indices(&self) -> Vec<u8> {
        self.state.lock().cmd_log.clone()
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
            // The Buffer Data Port streams the staged block.
            REG_BUFFER_PORT => {
                let cur = st.read_cursor;
                let w = u32::from_le_bytes(st.read_stage[cur..cur + 4].try_into().unwrap());
                st.read_cursor = (cur + 4) % 512;
                w
            }
            // A card is always inserted in the fixture.
            REG_PRESENT_STATE => st.get32(offset) | PSTATE_CARD_INSERTED,
            _ => st.get32(offset),
        }
    }

    fn write8(&self, offset: u64, value: u8) {
        let mut st = self.state.lock();
        if offset == REG_SOFT_RESET {
            // SRST_ALL is self-clearing (§2.2.16).
            st.regs[offset as usize] = value & !SRST_ALL;
        } else {
            st.regs[offset as usize] = value;
        }
    }

    fn write16(&self, offset: u64, value: u16) {
        let mut st = self.state.lock();
        match offset {
            // Interrupt status registers are write-1-to-clear.
            REG_NORMAL_INT_STS | REG_ERROR_INT_STS => {
                let cur = st.get16(offset);
                st.set16(offset, cur & !value);
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
        if offset == REG_BUFFER_PORT {
            // CMD24 capture: commit the block once all 128 words
            // have landed.
            let cur = st.write_cursor;
            st.write_stage[cur..cur + 4].copy_from_slice(&value.to_le_bytes());
            st.write_cursor += 4;
            if st.write_cursor == 512 {
                let lba = st.write_lba;
                let block = st.write_stage;
                st.image.insert(lba, block);
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
    publish_card(card.capacity_blocks, card.ccs);
    Ok(card)
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

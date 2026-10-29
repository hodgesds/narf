//! Register-level fixture for the RTSX driver: a modelled chip +
//! SD card behind the [`RtsxTransport`] seam, so the whole
//! probe → identify → block-device conversation runs end to end in
//! kernel tests without silicon.
//!
//! The model implements the hardware contract the driver programs,
//! taken from Linux `include/linux/mfd/rtsx_pci.h`,
//! `drivers/mfd/rtsx_pcr.c`, and `drivers/mmc/host/rtsx_pci_sdmmc.c`:
//!
//! - HAIMR single-register access completes immediately, echoing the
//!   written byte (write) or returning the register value (read) in
//!   bits[7:0] with TRANS_START clear.
//! - A command batch (HCBCTLR trigger) executes its entries in
//!   order; READ/CHECK results are written back to the start of the
//!   command page (hardware auto-response); BIPR gains TRANS_OK, or
//!   TRANS_FAIL when a CHECK_REG expectation is not met.
//! - An SD_TRANSFER write with START set runs the SD engine: for
//!   SD_TM_CMD_RSP the card answers the command staged in
//!   SD_CMD0..SD_CMD4 (short responses overwrite SD_CMD0..SD_CMD4;
//!   R2 responses land in the ping-pong buffer with the final
//!   CRC7/end byte offloaded, per Linux commit d1419d50c); for
//!   SD_TM_NORMAL_READ / SD_TM_AUTO_WRITE_2 one block moves between
//!   the card model and the ping-pong buffer.  A completed transfer
//!   leaves SD_TRANSFER = END | IDLE; a command the card does not
//!   answer leaves START set, so the batch's CHECK_REG fails.
//! - BIPR.SD_EXIST is a level bit driven by card presence.
//!
//! The card model speaks the SD identification conversation (SD
//! Physical Layer Simplified Spec v8.00 §4) and stores blocks
//! sparsely, so an 8 GiB SDHC fixture costs a few KiB.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::card::{r2_frame_to_shifted_words, SlotState};
use super::regs::*;
use super::{poll_card_slot, with_controller, RtsxTransport, __install_for_test, __reset_for_test};

/// Internal register addresses are 14-bit on the wire (HAIMR and the
/// command-entry encoding both mask with 0x3FFF).
const fn masked(addr: u16) -> usize {
    (addr & 0x3FFF) as usize
}

// ── Card model ────────────────────────────────────────────────────

/// A modelled SD card. `cid_reg` / `csd_reg` are the 15 register
/// bytes the controller delivers (the CRC7+end byte is offloaded).
#[derive(Debug)]
pub struct FixtureCard {
    cid_reg: [u8; 15],
    csd_reg: [u8; 15],
    high_capacity: bool,
    /// False models an SD 1.x card, which does not answer CMD8.
    answers_cmd8: bool,
    rca: u16,
    /// ACMD41 answers with OCR.BUSY clear this many times first.
    ocr_polls_until_ready: u32,
    ocr_seen: u32,
    /// Set SD_STAT1.CRC7_ERR on every response.
    bad_crc: bool,
    /// Sparse block storage, keyed by block index.
    storage: BTreeMap<u32, [u8; 512]>,
}

impl FixtureCard {
    /// An 8 GiB SDHC card: CSD v2.0 with C_SIZE = 16383 →
    /// (16383 + 1) × 512 KiB = 8 GiB = 16,777,216 blocks.
    pub fn sdhc_8gib() -> Self {
        FixtureCard {
            cid_reg: [
                0x03, b'S', b'D', b'S', b'U', b'0', b'8', b'G', 0x80, 0x12, 0x34, 0x56, 0x78, 0x01,
                0x42,
            ],
            // CSD v2: structure = 1 (byte 0 = 0x40); C_SIZE split over
            // bytes 7 (low 6 bits), 8, 9 → 0x003FFF = 16383.
            csd_reg: [
                0x40, 0x0E, 0x00, 0x32, 0x5B, 0x59, 0x00, 0x00, 0x3F, 0xFF, 0x00, 0x00, 0x00, 0x00,
                0x00,
            ],
            high_capacity: true,
            answers_cmd8: true,
            rca: 0x9ABC,
            ocr_polls_until_ready: 2,
            ocr_seen: 0,
            bad_crc: false,
            storage: BTreeMap::new(),
        }
    }

    /// A 2 MiB SDSC card: CSD v1.0 with READ_BL_LEN = 9 (512),
    /// C_SIZE = 31, C_SIZE_MULT = 5 →
    /// (31 + 1) × 2^(5+2) × 512 = 2 MiB = 4096 blocks.
    /// Deliberately a *different* capacity from the SDHC fixture:
    /// the pair defeats any masked/fabricated capacity constant.
    pub fn sdsc_2mib() -> Self {
        FixtureCard {
            cid_reg: [
                0x02, b'T', b'M', b'S', b'D', b'0', b'0', b'2', 0x10, 0xAA, 0xBB, 0xCC, 0xDD, 0x00,
                0xE9,
            ],
            // CSD v1: structure = 0; READ_BL_LEN = byte 5 low nibble
            // (0x59 → 9); C_SIZE = bytes 6/7/8 → 31; C_SIZE_MULT =
            // bytes 9/10 → 5.
            csd_reg: [
                0x00, 0x26, 0x00, 0x32, 0x5B, 0x59, 0x00, 0x07, 0xC0, 0x02, 0x80, 0x00, 0x02, 0x40,
                0x00,
            ],
            high_capacity: false,
            answers_cmd8: false,
            rca: 0x1234,
            ocr_polls_until_ready: 0,
            ocr_seen: 0,
            bad_crc: false,
            storage: BTreeMap::new(),
        }
    }

    /// The 8 GiB SDHC card carrying a two-partition MBR image
    /// (#834): partition contents are offset-sensitive patterns at
    /// the blocks the MBR entries point at, so a partition read
    /// proves both the window bounds and the LBA translation:
    /// - p1 (type 0x83): blocks 2048..6144 — pattern 0xA1 at its
    ///   first block, 0xA2 at its last (card block 6143).
    /// - p2 (type 0x0C): blocks 8192..10240 — pattern 0xB1 at its
    ///   first block.
    pub fn sdhc_partitioned() -> Self {
        let mut card = Self::sdhc_8gib();
        card.storage.insert(0, partitioned_mbr_sector());
        card.storage.insert(2048, partition_pattern(0xA1));
        card.storage.insert(6143, partition_pattern(0xA2));
        card.storage.insert(8192, partition_pattern(0xB1));
        card
    }

    /// An SDHC-shaped card whose CSD structure field is 0b10 —
    /// reserved/invalid per SD spec §5.3, so `Csd::parse_shifted`
    /// rejects it. Identification must fail with a typed error.
    pub fn garbage_csd() -> Self {
        let mut card = Self::sdhc_8gib();
        card.csd_reg[0] = 0x80;
        card
    }
}

/// One card block filled with an offset-sensitive pattern derived
/// from `tag`: byte `i` is `tag ^ i`, so reading the right block at
/// the wrong offset (or the wrong block) cannot pass.
fn partition_pattern(tag: u8) -> [u8; 512] {
    let mut b = [0u8; 512];
    for (i, x) in b.iter_mut().enumerate() {
        *x = tag ^ (i as u8);
    }
    b
}

/// Write one 16-byte partition entry into an MBR sector image.
/// Layout per the classic MBR partition table (sector 0, entries at
/// bytes 446..510): boot flag, CHS-first, type, CHS-last, LBA start
/// (LE), sector count (LE). The CHS fields carry the 0xFEFFFF
/// "beyond CHS range" sentinel fdisk writes for LBA-addressed
/// entries; the scanner (like Linux) reads only type + LBA fields.
fn write_mbr_entry(sector: &mut [u8; 512], slot: usize, ty: u8, start: u32, count: u32) {
    let off = 446 + slot * 16;
    sector[off] = 0x00; // not bootable
    sector[off + 1..off + 4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    sector[off + 4] = ty;
    sector[off + 5..off + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    sector[off + 8..off + 12].copy_from_slice(&start.to_le_bytes());
    sector[off + 12..off + 16].copy_from_slice(&count.to_le_bytes());
}

/// LBA 0 of the partitioned fixture card: a classic MBR with two
/// primary partitions and the 0x55AA boot signature at bytes
/// 510..512 (the layout `narf_block::partition::parse_mbr` consumes,
/// written here from the MBR layout itself, not from the parser):
/// - p1: type 0x83 (Linux), start LBA 2048, 4096 sectors.
/// - p2: type 0x0C (FAT32, LBA), start LBA 8192, 2048 sectors.
///
/// Slots 3 and 4 stay zeroed (empty entries).
fn partitioned_mbr_sector() -> [u8; 512] {
    let mut s = [0u8; 512];
    write_mbr_entry(&mut s, 0, 0x83, 2048, 4096);
    write_mbr_entry(&mut s, 1, 0x0C, 8192, 2048);
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

// ── Chip model ────────────────────────────────────────────────────

#[derive(Debug)]
struct FixtureState {
    hba: [u32; 8],
    haimr_result: u32,
    regs: [u8; 0x4000],
    cmd_page: [u8; 4096],
    card: Option<FixtureCard>,
    /// Every SD command the engine ran: (index, SD_CMD0..SD_CMD4).
    cmd_log: Vec<(u8, [u8; 5])>,
}

impl FixtureState {
    fn reg_write(&mut self, addr: u16, mask: u8, data: u8) {
        let slot = &mut self.regs[masked(addr)];
        *slot = (*slot & !mask) | (data & mask);
    }

    fn set_bipr(&mut self, bits: u32) {
        self.hba[(BIPR / 4) as usize] |= bits;
    }

    /// Execute one HAIMR transaction, Linux `rtsx_pci_read_register`
    /// / `rtsx_pci_write_register` semantics.
    fn run_haimr(&mut self, val: u32) {
        let addr = ((val >> 16) & 0x3FFF) as u16;
        let mask = (val >> 8) as u8;
        let data = val as u8;
        if val & HAIMR_WRITE != 0 {
            self.reg_write(addr, mask, data);
            // Completion: TRANS_START clear, written byte echoed.
            self.haimr_result = (val & 0x3FFF_0000) | ((mask as u32) << 8) | (data as u32);
        } else {
            let v = self.regs[masked(addr)];
            self.haimr_result = (val & 0x3FFF_0000) | (v as u32);
        }
    }

    /// Execute a dispatched command batch of `n` entries.
    fn run_cmd_batch(&mut self, n: usize) {
        let mut resp: Vec<u8> = Vec::new();
        let mut failed = false;
        for i in 0..n {
            let word = u32::from_le_bytes([
                self.cmd_page[i * 4],
                self.cmd_page[i * 4 + 1],
                self.cmd_page[i * 4 + 2],
                self.cmd_page[i * 4 + 3],
            ]);
            let ty = (word >> 30) as u8;
            let addr = ((word >> 16) & 0x3FFF) as u16;
            let mask = (word >> 8) as u8;
            let data = word as u8;
            match ty {
                WRITE_REG_CMD => {
                    self.reg_write(addr, mask, data);
                    // `addr` is the entry's 14-bit wire address (the
                    // command encoding masks with 0x3FFF, exactly as
                    // Linux `rtsx_pci_add_cmd` does), so the trigger
                    // comparison must use the masked register address
                    // too — comparing against the unmasked SD_TRANSFER
                    // constant (0xFDB3) can never match and the SD
                    // engine would never run.
                    if masked(addr) == masked(SD_TRANSFER) && (data & SD_TRANSFER_START) != 0 {
                        self.run_sd_transfer();
                    }
                }
                READ_REG_CMD => {
                    resp.push(self.regs[masked(addr)]);
                }
                CHECK_REG_CMD => {
                    let v = self.regs[masked(addr)] & mask;
                    resp.push(v);
                    if v != data {
                        failed = true;
                        break;
                    }
                }
                _ => {
                    failed = true;
                    break;
                }
            }
        }
        // Hardware auto-response: results overwrite the page start.
        for (i, b) in resp.iter().enumerate() {
            self.cmd_page[i] = *b;
        }
        if failed {
            self.set_bipr(BIPR_TRANS_FAIL);
        } else {
            self.set_bipr(BIPR_TRANS_OK);
        }
    }

    /// Run the SD engine for the transfer staged in SD_TRANSFER /
    /// SD_CMD0..SD_CMD4. On completion SD_TRANSFER becomes
    /// END | IDLE; an unanswered command leaves START set so the
    /// batch's CHECK_REG fails (→ TRANS_FAIL), as on hardware when a
    /// card does not respond.
    fn run_sd_transfer(&mut self) {
        let mode = self.regs[masked(SD_TRANSFER)] & 0x0F;
        let frame = [
            self.regs[masked(SD_CMD0)],
            self.regs[masked(SD_CMD1)],
            self.regs[masked(SD_CMD2)],
            self.regs[masked(SD_CMD3)],
            self.regs[masked(SD_CMD4)],
        ];
        let index = frame[0] & 0x3F;
        let arg = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        self.cmd_log.push((index, frame));

        let mut card = match self.card.take() {
            Some(c) => c,
            None => return,
        };

        let completed = match mode {
            SD_TM_CMD_RSP => self.exec_sd_cmd(&mut card, index, arg),
            SD_TM_NORMAL_READ => {
                if index == 17 {
                    let block = card_block_index(&card, arg);
                    let data = card.storage.get(&block).copied().unwrap_or([0u8; 512]);
                    for (i, b) in data.iter().enumerate() {
                        self.regs[masked(PPBUF_BASE2) + i] = *b;
                    }
                    true
                } else {
                    false
                }
            }
            SD_TM_AUTO_WRITE_2 => {
                if index == 24 {
                    let block = card_block_index(&card, arg);
                    let mut data = [0u8; 512];
                    for (i, b) in data.iter_mut().enumerate() {
                        *b = self.regs[masked(PPBUF_BASE2) + i];
                    }
                    card.storage.insert(block, data);
                    true
                } else {
                    false
                }
            }
            _ => false,
        };

        if completed {
            self.regs[masked(SD_TRANSFER)] = SD_TRANSFER_END | SD_STAT_IDLE;
        }
        self.card = Some(card);
    }

    /// Execute one SD command against the card model. Returns true
    /// when the card answered (response staged, SD_STAT1 set).
    fn exec_sd_cmd(&mut self, card: &mut FixtureCard, index: u8, arg: u32) -> bool {
        // SD_STAT1 verdict for this response.
        self.regs[masked(SD_STAT1)] = if card.bad_crc { SD_STAT1_CRC7_ERR } else { 0 };

        let cfg2 = self.regs[masked(SD_CFG2)];
        let is_r2 = (cfg2 & 0x03) == SD_CFG2_RSP_LEN_17;

        // Short-response helper: header + 32-bit argument overwrite
        // SD_CMD0..SD_CMD4, as the real controller does.
        let short = |state: &mut FixtureState, header: u8, value: u32| {
            state.regs[masked(SD_CMD0)] = header;
            state.regs[masked(SD_CMD1)] = (value >> 24) as u8;
            state.regs[masked(SD_CMD2)] = (value >> 16) as u8;
            state.regs[masked(SD_CMD3)] = (value >> 8) as u8;
            state.regs[masked(SD_CMD4)] = value as u8;
        };
        // R2 helper: header + 15 register bytes into the ping-pong
        // buffer (final CRC7/end byte offloaded by the controller).
        let long = |state: &mut FixtureState, reg: &[u8; 15]| {
            state.regs[masked(PPBUF_BASE2)] = 0x3F;
            for (i, b) in reg.iter().enumerate() {
                state.regs[masked(PPBUF_BASE2) + 1 + i] = *b;
            }
        };

        match index {
            // CMD0: no response (R0).
            0 => true,
            // CMD8: v2 cards echo voltage + check pattern; v1 cards
            // do not answer at all.
            8 => {
                if !card.answers_cmd8 {
                    return false;
                }
                short(self, index, arg & 0x0000_0FFF);
                true
            }
            // CMD55: R1 with APP_CMD + READY_FOR_DATA.
            55 => {
                short(self, index, 0x0000_0120);
                true
            }
            // ACMD41: R3 — header 0x3F, OCR with BUSY per the poll
            // count and CCS per card class.
            41 => {
                card.ocr_seen += 1;
                let busy = card.ocr_seen > card.ocr_polls_until_ready;
                let ocr = ((busy as u32) << 31)
                    | if card.high_capacity { 1 << 30 } else { 0 }
                    | 0x00FF_8000;
                short(self, 0x3F, ocr);
                true
            }
            // CMD2: R2 CID.
            2 => {
                if is_r2 {
                    long(self, &card.cid_reg);
                }
                true
            }
            // CMD3: R6 — RCA in the high half.
            3 => {
                short(self, index, (card.rca as u32) << 16);
                true
            }
            // CMD9: R2 CSD.
            9 => {
                if is_r2 {
                    long(self, &card.csd_reg);
                }
                true
            }
            // CMD7 / CMD16 / CMD13 and anything else: plain R1,
            // transfer state, ready for data.
            _ => {
                short(self, index, 0x0000_0900);
                true
            }
        }
    }
}

/// Block index for a data-transfer argument: SDHC cards are
/// block-addressed; SDSC cards are byte-addressed.
fn card_block_index(card: &FixtureCard, arg: u32) -> u32 {
    if card.high_capacity {
        arg
    } else {
        arg / 512
    }
}

// ── Transport ─────────────────────────────────────────────────────

/// Fixture transport: a modelled RTSX chip behind the seam.
pub struct FixtureTransport {
    state: IrqSafeSpinLock<FixtureState>,
}

impl core::fmt::Debug for FixtureTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FixtureTransport").finish_non_exhaustive()
    }
}

impl FixtureTransport {
    /// A chip with no card inserted.
    pub fn empty() -> Self {
        Self::with_card(None)
    }

    /// A chip with `card` inserted.
    pub fn with_card(card: Option<FixtureCard>) -> Self {
        FixtureTransport {
            state: IrqSafeSpinLock::new(FixtureState {
                hba: [0; 8],
                haimr_result: 0,
                regs: [0; 0x4000],
                cmd_page: [0; 4096],
                card,
                cmd_log: Vec::new(),
            }),
        }
    }

    /// Remove the card from the modelled slot.
    pub fn remove_card(&self) {
        self.state.lock().card = None;
    }

    /// Every SD command index the engine ran, in order.
    pub fn cmd_indices(&self) -> Vec<u8> {
        self.state.lock().cmd_log.iter().map(|(i, _)| *i).collect()
    }

    /// The staged frame (SD_CMD0..SD_CMD4) of the first run of
    /// command `index`, if it ran.
    pub fn cmd_frame(&self, index: u8) -> Option<[u8; 5]> {
        self.state
            .lock()
            .cmd_log
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, f)| *f)
    }

    /// A block from the modelled card's storage, if ever written.
    pub fn stored_block(&self, block: u32) -> Option<[u8; 512]> {
        let st = self.state.lock();
        st.card
            .as_ref()
            .and_then(|c| c.storage.get(&block).copied())
    }
}

impl RtsxTransport for FixtureTransport {
    fn read_hba(&self, offset: u64) -> u32 {
        let st = self.state.lock();
        match offset {
            HAIMR => st.haimr_result,
            BIPR => {
                let mut v = st.hba[(BIPR / 4) as usize] & !BIPR_SD_EXIST;
                if st.card.is_some() {
                    v |= BIPR_SD_EXIST;
                }
                v
            }
            _ => st.hba[(offset / 4) as usize],
        }
    }

    fn write_hba(&self, offset: u64, val: u32) {
        let mut st = self.state.lock();
        match offset {
            HAIMR => st.run_haimr(val),
            HCBCTLR => {
                st.hba[(HCBCTLR / 4) as usize] = val;
                if val & HCBCTLR_TRIGGER != 0 {
                    let n = ((val & HCBCTLR_LEN_MASK) / 4) as usize;
                    st.run_cmd_batch(n);
                }
            }
            BIPR => {
                // W1C on the completion/event bits; SD_EXIST is a
                // level bit and is not cleared by writes.
                let w1c =
                    BIPR_CMD_DONE | BIPR_DATA_DONE | BIPR_TRANS_OK | BIPR_TRANS_FAIL | BIPR_SD_INT;
                st.hba[(BIPR / 4) as usize] &= !(val & w1c);
            }
            _ => {
                st.hba[(offset / 4) as usize] = val;
            }
        }
    }

    fn cmd_buf_dma_addr(&self) -> u32 {
        0x2000_0000
    }

    fn cmd_buf_write(&self, offset: usize, data: &[u8]) {
        let mut st = self.state.lock();
        st.cmd_page[offset..offset + data.len()].copy_from_slice(data);
    }

    fn cmd_buf_read(&self, offset: usize, out: &mut [u8]) {
        let st = self.state.lock();
        out.copy_from_slice(&st.cmd_page[offset..offset + out.len()]);
    }
}

// ── Tests ─────────────────────────────────────────────────────────

/// Install a fixture chip as the global controller and snapshot the
/// block registry; returns the snapshot for `restore`.
fn install(transport: Arc<FixtureTransport>) -> Vec<narf_block::registry::RegisteredBlockDevice> {
    let saved = narf_block::registry::__snapshot_for_test();
    __reset_for_test();
    narf_filesystem::sysfs::__reset_for_test();
    __install_for_test(transport, 0x525A);
    saved
}

fn restore(saved: Vec<narf_block::registry::RegisteredBlockDevice>) {
    narf_block::registry::__restore_for_test(saved);
    __reset_for_test();
}

fn slot_state() -> SlotState {
    with_controller(|c| c.sd_slot).unwrap_or(SlotState::Empty)
}

fn fixture_sdhc_identify_capacity_and_identity() -> TestResult {
    let transport = Arc::new(FixtureTransport::with_card(Some(FixtureCard::sdhc_8gib())));
    let saved = install(transport.clone());

    poll_card_slot();

    let result = (|| {
        let dev = narf_block::registry::find_block_device("mmcblk0")
            .ok_or("mmcblk0 not registered after identify")?;
        // 8 GiB from the card's real CSD v2 (C_SIZE = 16383).
        if dev.capacity() != 16_777_216 {
            return Err("SDHC capacity must come from the CSD (16,777,216 blocks)");
        }
        // The identify conversation really ran: CMD2 (CID), CMD9
        // (CSD), CMD7 (select) all reached the card.
        let indices = transport.cmd_indices();
        for want in [2u8, 3, 7, 9] {
            if !indices.contains(&want) {
                return Err("identify conversation missing a required command");
            }
        }
        // CMD8's staged frame is byte-pinned: header 0x40|8, arg
        // 0x000001AA big-endian (SD spec §7.3.1 frame layout).
        match transport.cmd_frame(8) {
            Some([0x48, 0x00, 0x00, 0x01, 0xAA]) => {}
            _ => return Err("CMD8 frame bytes wrong"),
        }
        // The CID captured from CMD2 is the fixture card's real CID,
        // in shifted-word form.
        match slot_state() {
            SlotState::Ready(info) => {
                let mut frame = [0u8; 16];
                frame[0] = 0x3F;
                frame[1..16].copy_from_slice(&FixtureCard::sdhc_8gib().cid_reg);
                if info.cid != r2_frame_to_shifted_words(&frame) {
                    return Err("captured CID does not match the card's CID");
                }
                if info.rca != 0x9ABC || !info.high_capacity {
                    return Err("SDHC card info wrong");
                }
            }
            _ => return Err("slot not Ready after identify"),
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
    "drivers/storage/rtsx/fixture",
    fixture_sdhc_identify_capacity_and_identity
);

fn fixture_sdsc_identify_capacity_differs() -> TestResult {
    let transport = Arc::new(FixtureTransport::with_card(Some(FixtureCard::sdsc_2mib())));
    let saved = install(transport.clone());

    poll_card_slot();

    let result = (|| {
        let dev = narf_block::registry::find_block_device("mmcblk0")
            .ok_or("mmcblk0 not registered after identify")?;
        // 2 MiB from the CSD v1 formula — a different value from the
        // SDHC fixture's, so a shared constant cannot pass both.
        if dev.capacity() != 4096 {
            return Err("SDSC capacity must come from the CSD v1 formula (4096 blocks)");
        }
        match slot_state() {
            SlotState::Ready(info) => {
                if info.high_capacity {
                    return Err("SDSC card must not report high_capacity");
                }
                if info.rca != 0x1234 {
                    return Err("SDSC RCA wrong");
                }
            }
            _ => return Err("slot not Ready after identify"),
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
    "drivers/storage/rtsx/fixture",
    fixture_sdsc_identify_capacity_differs
);

fn fixture_absent_card_registers_nothing() -> TestResult {
    let transport = Arc::new(FixtureTransport::empty());
    let saved = install(transport);

    poll_card_slot();

    let result = (|| {
        if narf_block::registry::find_block_device("mmcblk0").is_some() {
            return Err("no card inserted: mmcblk0 must not be registered");
        }
        if slot_state() != SlotState::Empty {
            return Err("slot must stay Empty with no card");
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
    "drivers/storage/rtsx/fixture",
    fixture_absent_card_registers_nothing
);

fn fixture_garbage_csd_rejected() -> TestResult {
    let transport = Arc::new(FixtureTransport::with_card(
        Some(FixtureCard::garbage_csd()),
    ));
    let saved = install(transport);

    poll_card_slot();

    let result = (|| {
        if narf_block::registry::find_block_device("mmcblk0").is_some() {
            return Err("garbage CSD must not lead to registration");
        }
        if slot_state() != SlotState::Error {
            return Err("garbage CSD must land the slot in Error state");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/storage/rtsx/fixture", fixture_garbage_csd_rejected);

fn fixture_write_read_round_trip_sdhc() -> TestResult {
    let transport = Arc::new(FixtureTransport::with_card(Some(FixtureCard::sdhc_8gib())));
    let saved = install(transport);

    poll_card_slot();

    let result = (|| {
        let dev = narf_block::registry::find_block_device("mmcblk0")
            .ok_or("mmcblk0 not registered after identify")?;
        let mut pattern = [0u8; 512];
        for (i, b) in pattern.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        dev.write(5, 1, &pattern)
            .map_err(|_| "CMD24 write failed")?;
        let mut back = [0u8; 512];
        dev.read(5, 1, &mut back).map_err(|_| "CMD17 read failed")?;
        if back != pattern {
            return Err("write→read round trip data mismatch");
        }
        // A neighbouring block stays zero — addressing is not aliased.
        let mut neighbour = [0xFFu8; 512];
        dev.read(6, 1, &mut neighbour)
            .map_err(|_| "CMD17 neighbour read failed")?;
        if neighbour != [0u8; 512] {
            return Err("untouched block must read as zeros");
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
    "drivers/storage/rtsx/fixture",
    fixture_write_read_round_trip_sdhc
);

fn fixture_sdsc_byte_addressed_round_trip() -> TestResult {
    let transport = Arc::new(FixtureTransport::with_card(Some(FixtureCard::sdsc_2mib())));
    let saved = install(transport.clone());

    poll_card_slot();

    let result = (|| {
        let dev = narf_block::registry::find_block_device("mmcblk0")
            .ok_or("mmcblk0 not registered after identify")?;
        let mut pattern = [0u8; 512];
        for (i, b) in pattern.iter_mut().enumerate() {
            *b = 0xA5 ^ (i as u8);
        }
        // LBA 2 on an SDSC card is byte address 1024 on the wire; the
        // card model keys storage by block index, so the write must
        // land in block 2 — proof the bridge did the ×512 conversion.
        dev.write(2, 1, &pattern)
            .map_err(|_| "SDSC CMD24 write failed")?;
        match transport.stored_block(2) {
            Some(b) if b == pattern => {}
            _ => return Err("SDSC write did not land in block 2 (byte addressing wrong)"),
        }
        let mut back = [0u8; 512];
        dev.read(2, 1, &mut back)
            .map_err(|_| "SDSC CMD17 read failed")?;
        if back != pattern {
            return Err("SDSC write→read round trip mismatch");
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
    "drivers/storage/rtsx/fixture",
    fixture_sdsc_byte_addressed_round_trip
);

fn fixture_removal_unregisters() -> TestResult {
    let transport = Arc::new(FixtureTransport::with_card(Some(FixtureCard::sdhc_8gib())));
    let saved = install(transport.clone());

    poll_card_slot();
    let registered = narf_block::registry::find_block_device("mmcblk0").is_some();

    transport.remove_card();
    poll_card_slot();

    let result = (|| {
        if !registered {
            return Err("card was never registered before removal");
        }
        if narf_block::registry::find_block_device("mmcblk0").is_some() {
            return Err("mmcblk0 must be unregistered after removal");
        }
        if slot_state() != SlotState::Empty {
            return Err("slot must return to Empty after removal");
        }
        Ok(())
    })();

    restore(saved);
    match result {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/storage/rtsx/fixture", fixture_removal_unregisters);

fn fixture_partitioned_card_registers_partitions() -> TestResult {
    let transport = Arc::new(FixtureTransport::with_card(Some(
        FixtureCard::sdhc_partitioned(),
    )));
    let saved = install(transport.clone());

    poll_card_slot();

    let result = (|| {
        // Both MBR partitions appear as mmcblk0p<N> children with
        // the windows the MBR entries declare.
        let p1 = narf_block::registry::find_block_device("mmcblk0p1")
            .ok_or("mmcblk0p1 not registered after identify")?;
        if p1.capacity() != 4096 {
            return Err("mmcblk0p1 capacity must be the MBR sector count (4096)");
        }
        let p2 = narf_block::registry::find_block_device("mmcblk0p2")
            .ok_or("mmcblk0p2 not registered after identify")?;
        if p2.capacity() != 2048 {
            return Err("mmcblk0p2 capacity must be the MBR sector count (2048)");
        }
        if narf_block::registry::find_block_device("mmcblk0p3").is_some() {
            return Err("empty MBR slots must not register partitions");
        }
        // Reads through a partition land on the card blocks its MBR
        // entry points at — first block, last block, and the second
        // partition's distinct pattern.
        let mut buf = [0u8; 512];
        p1.read(0, 1, &mut buf)
            .map_err(|_| "p1 first-block read failed")?;
        if buf != partition_pattern(0xA1) {
            return Err("mmcblk0p1 block 0 must be card block 2048");
        }
        p1.read(4095, 1, &mut buf)
            .map_err(|_| "p1 last-block read failed")?;
        if buf != partition_pattern(0xA2) {
            return Err("mmcblk0p1 last block must be card block 6143");
        }
        p2.read(0, 1, &mut buf)
            .map_err(|_| "p2 first-block read failed")?;
        if buf != partition_pattern(0xB1) {
            return Err("mmcblk0p2 block 0 must be card block 8192");
        }
        // The partition window is a bound, not a suggestion.
        if p1.read(4096, 1, &mut buf).is_ok() {
            return Err("read past mmcblk0p1's end must fail");
        }
        // The parent's own addressing is unshifted: card block 2048
        // read through mmcblk0 is the same pattern p1 starts with.
        let parent = narf_block::registry::find_block_device("mmcblk0")
            .ok_or("mmcblk0 not registered after identify")?;
        parent
            .read(2048, 1, &mut buf)
            .map_err(|_| "parent read failed")?;
        if buf != partition_pattern(0xA1) {
            return Err("mmcblk0 block 2048 must match mmcblk0p1 block 0");
        }
        Ok(())
    })();

    // Removal withdraws the partitions together with the parent.
    transport.remove_card();
    poll_card_slot();
    let removed = result.and_then(|()| {
        for name in ["mmcblk0", "mmcblk0p1", "mmcblk0p2"] {
            if narf_block::registry::find_block_device(name).is_some() {
                return Err("partition children must be withdrawn with the card");
            }
        }
        Ok(())
    });

    restore(saved);
    match removed {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/storage/rtsx/fixture",
    fixture_partitioned_card_registers_partitions
);

fn fixture_unpartitioned_card_registers_no_partitions() -> TestResult {
    // Blank storage: block 0 reads as zeros, so there is no MBR
    // signature — the scan must fail soft and leave the bare card.
    let transport = Arc::new(FixtureTransport::with_card(Some(FixtureCard::sdhc_8gib())));
    let saved = install(transport);

    poll_card_slot();

    let result = (|| {
        if narf_block::registry::find_block_device("mmcblk0").is_none() {
            return Err("mmcblk0 must register even without a partition table");
        }
        if narf_block::registry::find_block_device("mmcblk0p1").is_some() {
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
    "drivers/storage/rtsx/fixture",
    fixture_unpartitioned_card_registers_no_partitions
);

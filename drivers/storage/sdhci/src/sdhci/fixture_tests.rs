//! Register-level fixture for the SDHCI driver: a modelled SDHCI
//! register file + SD / eMMC card behind the [`SdhciTransport`]
//! seam, so the identify → publish → partition-scan conversation
//! runs end to end in kernel tests without silicon.
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

/// CID register bytes (15) of the fixture eMMC card: MID 0x15,
/// CBX 0x00, OID "MM", PNM "MMC32G" (6 bytes — eMMC product names
/// are 6 bytes, JESD84-B51 §7.2), PRV 0x10, PSN 0x11223344.
/// (The MDT byte is the stripped low byte, as in the SD fixture.)
const FIXTURE_EMMC_CID: [u8; 15] = [
    0x15, 0x00, b'M', b'M', b'M', b'M', b'C', b'3', b'2', b'G', 0x10, 0x11, 0x22, 0x33, 0x44,
];

/// CSD register bytes (15) of the fixture eMMC card: CSD v1.0
/// with READ_BL_LEN 9 (512 B), C_SIZE 0xFFF, C_SIZE_MULT 7 →
/// (4095 + 1) × 2^(7+2) × 2^9 = 1 GiB = 2,097,152 blocks. The
/// eMMC CSD capacity fields sit at the same bit positions as the
/// SD CSD v1.0 (JESD84-B51 §7.3: C_SIZE [73:62], C_SIZE_MULT
/// [49:47], READ_BL_LEN [83:80]), so the shared `Csd` parser
/// decodes this — it is the fallback capacity when SEC_COUNT is 0.
const FIXTURE_EMMC_CSD: [u8; 15] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x03, 0xFF, 0xC0, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00,
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

/// EXT_CSD image for the fixture eMMC card, built from the
/// JESD84-B51 §7.4 Table 93 offsets written out literally (not
/// through the decoder's constants, so a wrong constant cannot
/// mask itself): REV 8 (B51) at 192, CARD_TYPE at 196, SEC_COUNT
/// at 212, BOOT_SIZE_MULT 32 (4 MiB) at 226, RPMB_SIZE_MULT 32
/// (4 MiB) at 168, GP_SIZE_MULT at 143/146/149/152, HC_WP_GRP_SIZE
/// 1 at 221, HC_ERASE_GRP_SIZE 1 at 224, ERASE_GROUP_DEF 1 at 175,
/// PARTITIONING_SUPPORT 1 at 160, PARTITION_CONFIG 0x08 (boot 1
/// enabled, user access) at 179.
///
/// GP sizes (§7.4.89: mult × HC_WP × HC_ERASE × 512 KiB) with
/// mults [8, 4, 0, 2]: GP1 4 MiB (8192 blocks), GP2 2 MiB (4096),
/// GP3 absent, GP4 1 MiB (2048).
fn fixture_ext_csd(sec_count: u32) -> [u8; 512] {
    fn put_u24(buf: &mut [u8; 512], off: usize, v: u32) {
        buf[off] = (v & 0xFF) as u8;
        buf[off + 1] = ((v >> 8) & 0xFF) as u8;
        buf[off + 2] = ((v >> 16) & 0xFF) as u8;
    }
    let mut buf = [0u8; 512];
    buf[192] = 8; // EXT_CSD_REV: JESD84-B51
    buf[196] = 0x50; // CARD_TYPE: HS200 1V8 (bit 4) + HS400 1V8 (bit 6)
    buf[212..216].copy_from_slice(&sec_count.to_le_bytes());
    buf[226] = 32; // BOOT_SIZE_MULT: 32 × 128 KiB = 4 MiB
    buf[168] = 32; // RPMB_SIZE_MULT: 32 × 128 KiB = 4 MiB
    put_u24(&mut buf, 143, 8); // GP_SIZE_MULT_1
    put_u24(&mut buf, 146, 4); // GP_SIZE_MULT_2
    put_u24(&mut buf, 149, 0); // GP_SIZE_MULT_3
    put_u24(&mut buf, 152, 2); // GP_SIZE_MULT_4
    buf[221] = 1; // HC_WP_GRP_SIZE
    buf[224] = 1; // HC_ERASE_GRP_SIZE
    buf[175] = 1; // ERASE_GROUP_DEF: high-capacity definition
    buf[160] = 1; // PARTITIONING_SUPPORT
    buf[179] = 0x08; // PARTITION_CONFIG: boot 1 enabled, user access
    buf
}

/// Sparse storage for the fixture eMMC card's hardware partitions,
/// keyed by (PARTITION_CONFIG access value, block): boot 1 is
/// access 1, boot 2 is access 2, GP1..GP4 are access 4..7
/// (JESD84-B51 §7.4.69). Each partition carries offset-sensitive
/// patterns at its first (and, for GP1, last) block.
fn fixture_part_image() -> BTreeMap<(u8, u32), [u8; 512]> {
    let mut image = BTreeMap::new();
    image.insert((1, 0), partition_pattern(0xD1)); // boot 1, first
    image.insert((1, 1), partition_pattern(0xD2)); // boot 1, second
    image.insert((2, 0), partition_pattern(0xE1)); // boot 2, first
    image.insert((4, 0), partition_pattern(0xF1)); // GP1, first
    image.insert((4, 8191), partition_pattern(0xF2)); // GP1, last
    image.insert((5, 0), partition_pattern(0x51)); // GP2, first
    image.insert((7, 0), partition_pattern(0x71)); // GP4, first
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
    /// When true, the card speaks eMMC: CMD8 (SEND_IF_COND) and
    /// CMD55 (APP_CMD) get no response in Idle state (the eMMC
    /// card ignores them), CMD1 answers the OCR, and CMD8 after
    /// selection reads EXT_CSD.
    emmc: bool,
    /// EXT_CSD image the eMMC card answers CMD8 with.
    ext_csd: [u8; 512],
    /// Whether the eMMC card needs sector addressing (CMD1 OCR
    /// bit 30). Byte-addressed cards take block×512 arguments.
    sector_mode: bool,
    /// CMD1 polls so far (busy clears on the third poll).
    cmd1_polls: u32,
    /// Card selected by CMD7 (Tran state).
    selected: bool,
    /// Current PARTITION_CONFIG access value.
    current_access: u8,
    /// Access value a SWITCH (CMD6) requested but CMD13 has not
    /// confirmed yet. The switch only takes effect on a clean
    /// CMD13: a SWITCH_ERROR report means the card refused the
    /// switch and stays on the old partition (§6.6.2.2).
    pending_access: Option<u8>,
    /// Sparse storage for non-user partitions, keyed by
    /// (access value, block).
    part_image: BTreeMap<(u8, u32), [u8; 512]>,
    /// Every SWITCH (CMD6) argument issued, in order.
    switch_args: Vec<u32>,
    /// Number of CMD6s issued so far.
    switch_count: u32,
    /// When `Some(n)`, the CMD13 after the nth CMD6 reports
    /// SWITCH_ERROR. `None` means no switch ever fails.
    switch_error_on: Option<u32>,
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
        // eMMC cards ignore SEND_IF_COND (CMD8) and APP_CMD (CMD55)
        // in Idle state: no response at all, so the driver's
        // command times out. (CMD8 after selection is SEND_EXT_CSD.)
        if self.emmc && !self.selected && (index == 8 || index == 55) {
            return;
        }
        let mut nis = NIS_CMD_COMPLETE;
        match index {
            // CMD0 — reset: deselect, back to the user area, and
            // drop any SWITCH CMD13 has not confirmed yet.
            0 => {
                self.selected = false;
                self.current_access = 0;
                self.pending_access = None;
            }
            // CMD1 — SEND_OP_COND (eMMC only): busy for the first
            // two polls, then ready. §6.4.2 fixed patterns:
            // 0x00FF8080 / 0x40FF8080 while busy, 0x80FF8080 /
            // 0xC0FF8080 when ready (bit 30 = sector mode).
            1 => {
                self.cmd1_polls += 1;
                let base = if self.sector_mode {
                    0x40FF_8080
                } else {
                    0x00FF_8080
                };
                let ocr = if self.cmd1_polls < 3 {
                    base
                } else {
                    base | 0x8000_0000
                };
                self.set32(REG_RESPONSE_0, ocr);
            }
            // CMD2 — R2 CID.
            2 => {
                let cid = if self.emmc {
                    &FIXTURE_EMMC_CID
                } else {
                    &FIXTURE_CID
                };
                self.set_response_136(r2_to_response_words(cid));
            }
            // CMD3 — R6 (SD) / R1 (eMMC): RCA in the high half.
            3 => self.set32(REG_RESPONSE_0, (FIXTURE_RCA as u32) << 16),
            // CMD6 — SWITCH (R1b). A Write-Byte SWITCH to
            // PARTITION_CONFIG (index 179) requests a new accessed
            // partition; it takes effect only on a clean CMD13
            // (see `pending_access`).
            6 => {
                self.switch_count += 1;
                self.switch_args.push(arg);
                if ((arg >> 24) & 0x3) == 3 && ((arg >> 16) & 0xFF) == 179 {
                    self.pending_access = Some(((arg >> 8) as u8) & 0x07);
                }
                self.set32(REG_RESPONSE_0, 0x900);
            }
            // CMD7 — select: the card enters Tran state.
            7 => {
                self.selected = true;
                self.set32(REG_RESPONSE_0, 0x900);
            }
            // CMD8 — R7 echoes the voltage + check-pattern bits
            // (SD), or SEND_EXT_CSD (eMMC, selected): R1 + the
            // 512-byte EXT_CSD block.
            8 => {
                if self.emmc {
                    self.set32(REG_RESPONSE_0, 0x900);
                    self.read_stage = self.ext_csd;
                    self.read_cursor = 0;
                    nis |= NIS_BUFFER_READ_READY | NIS_TRANSFER_COMPLETE;
                } else {
                    self.set32(REG_RESPONSE_0, arg & 0x0000_0FFF);
                }
            }
            // CMD9 — R2 CSD.
            9 => {
                let csd = if self.emmc {
                    &FIXTURE_EMMC_CSD
                } else {
                    &FIXTURE_CSD
                };
                self.set_response_136(r2_to_response_words(csd));
            }
            // CMD13 — SEND_STATUS: Tran + ready, or SWITCH_ERROR
            // when this is the flagged SWITCH. Error bits clear on
            // report (§6.13), so the flag is consumed here. A clean
            // report commits the pending SWITCH; an error discards
            // it — the card stays on its old partition.
            13 => {
                let mut st = 0x900u32; // CURRENT_STATE=Tran | READY_FOR_DATA
                if self.switch_error_on == Some(self.switch_count) {
                    st |= 0x80; // SWITCH_ERROR
                    self.switch_error_on = None;
                    self.pending_access = None;
                } else if let Some(p) = self.pending_access.take() {
                    self.current_access = p;
                }
                self.set32(REG_RESPONSE_0, st);
            }
            // CMD17 — stage the addressed block at the Buffer
            // Data Port (the card is block-addressed, CCS = 1;
            // a byte-addressed eMMC card takes block×512).
            17 => {
                let block_addr = if self.emmc && !self.sector_mode {
                    arg / 512
                } else {
                    arg
                };
                let block = if self.current_access == 0 {
                    self.image.get(&block_addr).copied().unwrap_or([0u8; 512])
                } else {
                    self.part_image
                        .get(&(self.current_access, block_addr))
                        .copied()
                        .unwrap_or([0u8; 512])
                };
                self.read_stage = block;
                self.read_cursor = 0;
                nis |= NIS_BUFFER_READ_READY | NIS_TRANSFER_COMPLETE;
            }
            // CMD24 — arm the Buffer Data Port capture.
            24 => {
                self.write_lba = arg;
                self.write_cursor = 0;
                nis |= NIS_BUFFER_WRITE_READY | NIS_TRANSFER_COMPLETE;
            }
            // ACMD41 — R3 OCR: busy set, CCS set (SDHC), the
            // 3.3 V operating window.
            41 => self.set32(REG_RESPONSE_0, 0x8000_0000 | 0x4000_0000 | 0x00FF_8000),
            // CMD16 / CMD55 and everything else: a plain completion
            // with a zero response.
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
                emmc: false,
                ext_csd: [0u8; 512],
                sector_mode: true,
                cmd1_polls: 0,
                selected: false,
                current_access: 0,
                pending_access: None,
                part_image: BTreeMap::new(),
                switch_args: Vec::new(),
                switch_count: 0,
                switch_error_on: None,
            }),
        }
    }

    /// A controller with an eMMC card: `image` is the user-area
    /// storage, `part_image` the boot/GP partition storage,
    /// `ext_csd` the EXT_CSD image. `sector_mode` selects the CMD1
    /// OCR access-mode bit; `switch_error_on` is the (1-based)
    /// SWITCH whose CMD13 reports SWITCH_ERROR, if any.
    pub fn with_emmc(
        image: BTreeMap<u32, [u8; 512]>,
        part_image: BTreeMap<(u8, u32), [u8; 512]>,
        ext_csd: [u8; 512],
        sector_mode: bool,
        switch_error_on: Option<u32>,
    ) -> Self {
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
                emmc: true,
                ext_csd,
                sector_mode,
                cmd1_polls: 0,
                selected: false,
                current_access: 0,
                pending_access: None,
                part_image,
                switch_args: Vec::new(),
                switch_count: 0,
                switch_error_on,
            }),
        }
    }

    /// Every SD command index the controller ran, in order.
    pub fn cmd_indices(&self) -> Vec<u8> {
        self.state.lock().cmd_log.clone()
    }

    /// Every SWITCH (CMD6) argument issued, in order.
    pub fn switch_args(&self) -> Vec<u32> {
        self.state.lock().switch_args.clone()
    }

    /// A block from the modelled card's storage, if ever written.
    pub fn stored_block(&self, block: u32) -> Option<[u8; 512]> {
        self.state.lock().image.get(&block).copied()
    }

    /// A block from a hardware partition's storage, if ever
    /// written (`access` is the PARTITION_CONFIG access value).
    pub fn stored_part_block(&self, access: u8, block: u32) -> Option<[u8; 512]> {
        self.state.lock().part_image.get(&(access, block)).copied()
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
            // have landed, into the currently accessed partition.
            let cur = st.write_cursor;
            st.write_stage[cur..cur + 4].copy_from_slice(&value.to_le_bytes());
            st.write_cursor += 4;
            if st.write_cursor == 512 {
                // The CMD24 argument is a block address, except on
                // a byte-addressed eMMC card where it is a byte
                // address (mirror the CMD17 staging above).
                let lba = if st.emmc && !st.sector_mode {
                    st.write_lba / 512
                } else {
                    st.write_lba
                };
                let block = st.write_stage;
                let access = st.current_access;
                if access == 0 {
                    st.image.insert(lba, block);
                } else {
                    st.part_image.insert((access, lba), block);
                }
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
    // test and `identify_any` runs exactly once against it,
    // as it does at bring-up.
    unsafe { ctrl.identify_any() }.map_err(|_| "identify_any failed")?;
    publish_installed();
    ctrl.card
        .lock()
        .as_ref()
        .copied()
        .ok_or("no SD card after identify")
}

/// Install a fixture eMMC controller (does not identify it).
fn install_emmc(
    image: BTreeMap<u32, [u8; 512]>,
    part_image: BTreeMap<(u8, u32), [u8; 512]>,
    ext_csd: [u8; 512],
    sector_mode: bool,
    switch_error_on: Option<u32>,
) -> (
    Arc<FixtureTransport>,
    Vec<narf_block::registry::RegisteredBlockDevice>,
) {
    let saved = narf_block::registry::__snapshot_for_test();
    narf_block::registry::__reset_for_test();
    let transport = Arc::new(FixtureTransport::with_emmc(
        image,
        part_image,
        ext_csd,
        sector_mode,
        switch_error_on,
    ));
    __install_for_test(transport.clone());
    (transport, saved)
}

/// Identify the installed fixture eMMC card through the production
/// sequence and publish it exactly as `probe` does after bring-up.
fn identify_emmc_and_publish() -> Result<super::emmc::EmmcCard, &'static str> {
    let ctrl = probed_sdhci().ok_or("fixture controller not installed")?;
    // SAFETY: the fixture transport is exclusively owned by this
    // test and `identify_any` runs exactly once against it,
    // as it does at bring-up.
    unsafe { ctrl.identify_any() }.map_err(|_| "identify_any failed")?;
    publish_installed();
    ctrl.emmc
        .lock()
        .as_ref()
        .copied()
        .ok_or("no eMMC card after identify")
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

/// eMMC identify → publish → partition I/O end to end.
///
/// The identify conversation is the production one: CMD0, then
/// CMD8/CMD55 time out (an eMMC card ignores SEND_IF_COND and
/// APP_CMD in Idle state), then CMD1 polls the OCR to ready,
/// CMD2/CMD3/CMD9/CMD7, CMD8 reads EXT_CSD, and a final CMD6 +
/// CMD13 pins PARTITION_CONFIG to the user area. The user area
/// publishes as `emmc0` with its MBR partitions, boot 1/2 as
/// `emmc0boot0`/`emmc0boot1`, GP1/GP2/GP4 as `emmc0gp0`/`emmc0gp1`/
/// `emmc0gp3`; GP3 (zero size) and RPMB (auth-only) do not appear.
fn fixture_emmc_identify_publish_partitions() -> TestResult {
    let (transport, saved) = install_emmc(
        partitioned_image(),
        fixture_part_image(),
        fixture_ext_csd(16_777_216),
        true,
        None,
    );

    let result = (|| {
        let card = identify_emmc_and_publish()?;
        if card.capacity_blocks != 16_777_216 {
            return Err("capacity must come from SEC_COUNT (16,777,216 blocks)");
        }
        if !card.sector_mode || card.rca != 1 {
            return Err("identified card info wrong (sector_mode / rca)");
        }
        if card.cid != r2_to_response_words(&FIXTURE_EMMC_CID) {
            return Err("captured CID does not match the card's CID");
        }
        if card.ext_csd.boot_partition_bytes() != 4 * 1024 * 1024 {
            return Err("boot partitions must be 4 MiB each (BOOT_SIZE_MULT 32)");
        }
        if card.ext_csd.rpmb_partition_bytes() != 4 * 1024 * 1024 {
            return Err("RPMB must be 4 MiB (RPMB_SIZE_MULT 32)");
        }
        if card.ext_csd.gp_partition_blocks(0) != 8192
            || card.ext_csd.gp_partition_blocks(1) != 4096
            || card.ext_csd.gp_partition_blocks(2) != 0
            || card.ext_csd.gp_partition_blocks(3) != 2048
        {
            return Err("GP sizes must follow the §7.4.89 formula (8192/4096/0/2048)");
        }
        // The exact identify prefix: CMD0, timed-out CMD8/CMD55,
        // CMD0, three CMD1 polls (busy, busy, ready), CMD2/3/9/7,
        // CMD8 (EXT_CSD), CMD6 + CMD13 (pin the user area).
        let indices = transport.cmd_indices();
        let prefix: [u8; 14] = [0, 8, 55, 0, 1, 1, 1, 2, 3, 9, 7, 8, 6, 13];
        if indices.len() < prefix.len() || indices[..prefix.len()] != prefix {
            return Err("identify conversation must be the eMMC sequence");
        }
        // The user area and its MBR partitions.
        let user = narf_block::registry::find_block_device("emmc0")
            .ok_or("emmc0 not registered after publish")?;
        if user.capacity() != 16_777_216 {
            return Err("emmc0 capacity must be SEC_COUNT (16,777,216 blocks)");
        }
        let p1 = narf_block::registry::find_block_device("emmc0p1")
            .ok_or("emmc0p1 not registered after publish")?;
        if p1.capacity() != 4096 {
            return Err("emmc0p1 capacity must be the MBR sector count (4096)");
        }
        let p2 = narf_block::registry::find_block_device("emmc0p2")
            .ok_or("emmc0p2 not registered after publish")?;
        if p2.capacity() != 2048 {
            return Err("emmc0p2 capacity must be the MBR sector count (2048)");
        }
        // The hardware partitions, with the sizes EXT_CSD declares.
        for (name, want) in [
            ("emmc0boot0", 8192u64),
            ("emmc0boot1", 8192),
            ("emmc0gp0", 8192),
            ("emmc0gp1", 4096),
            ("emmc0gp3", 2048),
        ] {
            let dev = narf_block::registry::find_block_device(name)
                .ok_or("hardware partition not registered after publish")?;
            if dev.capacity() != want {
                return Err("hardware partition capacity must match EXT_CSD");
            }
        }
        // GP3 is zero-sized and RPMB is auth-only: neither gets a
        // plain block device.
        if narf_block::registry::find_block_device("emmc0gp2").is_some() {
            return Err("zero-sized GP3 must not register a device");
        }
        if narf_block::registry::find_block_device("emmc0rpmb").is_some() {
            return Err("RPMB must not publish as a plain block device");
        }
        // Reads land in the partition they name: user, boot 1/2,
        // GP1 (first and last block), GP2, GP4.
        let mut buf = [0u8; 512];
        let mut read_pat = |dev: &alloc::sync::Arc<dyn narf_block::registry::BlockDeviceSync>,
                            lba: u64,
                            want: u8|
         -> Result<(), &'static str> {
            dev.read(lba, 1, &mut buf)
                .map_err(|_| "partition read failed")?;
            if buf != partition_pattern(want) {
                return Err("partition read returned the wrong block");
            }
            Ok(())
        };
        read_pat(&p1, 0, 0xA1)?;
        let boot0 =
            narf_block::registry::find_block_device("emmc0boot0").ok_or("emmc0boot0 missing")?;
        read_pat(&boot0, 0, 0xD1)?;
        read_pat(&boot0, 1, 0xD2)?;
        let boot1 =
            narf_block::registry::find_block_device("emmc0boot1").ok_or("emmc0boot1 missing")?;
        read_pat(&boot1, 0, 0xE1)?;
        let gp0 = narf_block::registry::find_block_device("emmc0gp0").ok_or("emmc0gp0 missing")?;
        read_pat(&gp0, 0, 0xF1)?;
        read_pat(&gp0, 8191, 0xF2)?;
        let gp1 = narf_block::registry::find_block_device("emmc0gp1").ok_or("emmc0gp1 missing")?;
        read_pat(&gp1, 0, 0x51)?;
        let gp3 = narf_block::registry::find_block_device("emmc0gp3").ok_or("emmc0gp3 missing")?;
        read_pat(&gp3, 0, 0x71)?;
        // The partition window is a bound, not a suggestion.
        if boot0.read(8192, 1, &mut buf).is_ok() {
            return Err("read past emmc0boot0's end must fail");
        }
        // A write through boot 1 lands in boot 1's store and does
        // not disturb the user area; a write through GP2 lands in
        // GP2's store.
        let wpat = partition_pattern(0xC3);
        boot0.write(0, 1, &wpat).map_err(|_| "boot0 write failed")?;
        match transport.stored_part_block(1, 0) {
            Some(b) if b == wpat => {}
            _ => return Err("emmc0boot0 block 0 write must land in boot 1's store"),
        }
        if transport.stored_block(2048) != Some(partition_pattern(0xA1)) {
            return Err("boot write must not disturb the user area");
        }
        gp1.write(2, 1, &wpat).map_err(|_| "gp1 write failed")?;
        match transport.stored_part_block(5, 2) {
            Some(b) if b == wpat => {}
            _ => return Err("emmc0gp1 block 2 write must land in GP2's store"),
        }
        // The SWITCH arguments are the literal CMD6 encoding
        // (access 3 = Write-Byte, index 179, value in bits [15:8]):
        // 0x08 pins the user area at identify, 0x09 selects boot 1,
        // 0x0D selects GP2.
        let switches = transport.switch_args();
        let switch_arg = |value: u8| (3u32 << 24) | (179u32 << 16) | ((value as u32) << 8);
        for value in [0x08u8, 0x09, 0x0D] {
            if !switches.contains(&switch_arg(value)) {
                return Err("missing expected CMD6 SWITCH argument");
            }
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
    fixture_emmc_identify_publish_partitions
);

/// A zero SEC_COUNT falls back to the legacy CSD capacity
/// (1 GiB here) and the card is byte-addressed: CMD17/CMD24
/// arguments are block × 512.
fn fixture_emmc_csd_capacity_fallback() -> TestResult {
    let (transport, saved) = install_emmc(
        partitioned_image(),
        fixture_part_image(),
        fixture_ext_csd(0),
        false,
        None,
    );

    let result = (|| {
        let card = identify_emmc_and_publish()?;
        if card.capacity_blocks != 2_097_152 {
            return Err("capacity must fall back to the CSD (2,097,152 blocks)");
        }
        if card.sector_mode {
            return Err("byte-addressed card must report sector_mode false");
        }
        let user = narf_block::registry::find_block_device("emmc0")
            .ok_or("emmc0 not registered after publish")?;
        if user.capacity() != 2_097_152 {
            return Err("emmc0 capacity must be the CSD fallback");
        }
        // Byte-addressed round-trip at block 5: the driver sends
        // arg 5×512 and the fixture divides it back to block 5.
        let wpat = partition_pattern(0x5A);
        user.write(5, 1, &wpat)
            .map_err(|_| "byte-mode write failed")?;
        match transport.stored_block(5) {
            Some(b) if b == wpat => {}
            _ => return Err("byte-mode write must land on card block 5"),
        }
        let mut buf = [0u8; 512];
        user.read(5, 1, &mut buf)
            .map_err(|_| "byte-mode read failed")?;
        if buf != wpat {
            return Err("byte-mode read must return the written block");
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
    fixture_emmc_csd_capacity_fallback
);

/// A SWITCH_ERROR on the identify-time CMD6 aborts identify and
/// publishes nothing.
fn fixture_emmc_switch_error_at_identify() -> TestResult {
    let (_transport, saved) = install_emmc(
        partitioned_image(),
        fixture_part_image(),
        fixture_ext_csd(16_777_216),
        true,
        Some(1),
    );

    let result = (|| {
        if identify_emmc_and_publish().is_ok() {
            return Err("identify must fail when the pin SWITCH is refused");
        }
        if narf_block::registry::find_block_device("emmc0").is_some() {
            return Err("a failed identify must not publish emmc0");
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
    fixture_emmc_switch_error_at_identify
);

/// A SWITCH_ERROR on a partition switch fails that I/O, leaves
/// the driver (and the card) on the user partition, and the next
/// user read costs no further switch.
fn fixture_emmc_switch_error_on_io() -> TestResult {
    let (transport, saved) = install_emmc(
        partitioned_image(),
        fixture_part_image(),
        fixture_ext_csd(16_777_216),
        true,
        Some(2),
    );

    let result = (|| {
        let _card = identify_emmc_and_publish()?;
        let boot0 =
            narf_block::registry::find_block_device("emmc0boot0").ok_or("emmc0boot0 missing")?;
        let mut buf = [0u8; 512];
        if boot0.read(0, 1, &mut buf).is_ok() {
            return Err("boot read after a refused SWITCH must fail");
        }
        // The card stayed on the user partition, and the cached
        // access is still user: this read finds the user-area
        // pattern with no further CMD6.
        let p1 = narf_block::registry::find_block_device("emmc0p1").ok_or("emmc0p1 missing")?;
        p1.read(0, 1, &mut buf)
            .map_err(|_| "user read after a refused SWITCH failed")?;
        if buf != partition_pattern(0xA1) {
            return Err("user read after a refused SWITCH must see the user area");
        }
        if transport.switch_args().len() != 2 {
            return Err("exactly two SWITCHes must have run (identify pin + refused boot switch)");
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
    fixture_emmc_switch_error_on_io
);

/// A blank user area publishes `emmc0` alone (no MBR partitions)
/// while the hardware partitions still appear.
fn fixture_emmc_unpartitioned_user_area() -> TestResult {
    let (_transport, saved) = install_emmc(
        BTreeMap::new(),
        fixture_part_image(),
        fixture_ext_csd(16_777_216),
        true,
        None,
    );

    let result = (|| {
        let _card = identify_emmc_and_publish()?;
        if narf_block::registry::find_block_device("emmc0").is_none() {
            return Err("emmc0 must register even without a partition table");
        }
        if narf_block::registry::find_block_device("emmc0p1").is_some() {
            return Err("unpartitioned user area must not gain partition devices");
        }
        if narf_block::registry::find_block_device("emmc0boot0").is_none()
            || narf_block::registry::find_block_device("emmc0gp0").is_none()
        {
            return Err("hardware partitions must appear even without an MBR");
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
    fixture_emmc_unpartitioned_user_area
);

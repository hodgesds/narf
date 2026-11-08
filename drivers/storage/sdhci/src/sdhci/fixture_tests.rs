//! Register-level fixture for the SDHCI driver: a modelled SDHCI
//! register file + SD / eMMC card behind the [`SdhciTransport`]
//! seam, so the identify → publish → partition-scan conversation
//! runs end to end in kernel tests without silicon.
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
//!   re-asserting Buffer Read / Write Ready per block. CMD18 /
//!   CMD25 with a CMD23 pre-defined count is how the RPMB
//!   partition moves frames (§6.6.22.4).
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
//!   block word-by-word on CMD17 and captures it on CMD24.
//! - Present State (§2.2.9) reports a card inserted — and Card
//!   State Stable with it (the model debounces instantly; the
//!   controller's debounce is what the bit models). `insert_card`
//!   / `remove_card` move the modelled card and raise the
//!   corresponding present-change edge in Normal Interrupt Status
//!   (§2.2.18) — but only when the matching enable bit is set in
//!   Normal Interrupt Status Enable, as the spec gates the status
//!   bit itself on the enable. A test that wants edges must enable
//!   them first, as `bring_up` step 5 does.
//! - Software Reset (§2.2.16) self-clears all three reset bits,
//!   not just SRST_ALL.
//!
//! The card model speaks the SD identification conversation (SD
//! Physical Layer Simplified Specification §4) and stores blocks
//! sparsely, so an 8 GiB SDHC fixture costs a few KiB.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::rpmb::{
    RpmbFrame, RPMB_FRAME_SIZE, RPMB_LEN_DATA, RPMB_REQ_CONFIG_WRITE, RPMB_REQ_KEY_PROGRAM,
    RPMB_REQ_READ, RPMB_REQ_READ_COUNTER, RPMB_REQ_RESULT_READ, RPMB_REQ_WRITE,
    RPMB_RESP_KEY_PROGRAM, RPMB_RESP_READ, RPMB_RESP_READ_COUNTER, RPMB_RESP_WRITE,
    RPMB_RESULT_ADDRESS_FAILURE, RPMB_RESULT_AUTH_FAILURE, RPMB_RESULT_COUNTER_EXPIRED,
    RPMB_RESULT_COUNTER_FAILURE, RPMB_RESULT_GENERAL_FAILURE, RPMB_RESULT_KEY_NOT_PROGRAMMED,
    RPMB_RESULT_OK, RPMB_RESULT_WRITE_FAILURE,
};

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
    /// Whether a card is in the modelled slot. Drives Present
    /// State (§2.2.9) and the present-change edges (§2.2.18).
    card_present: bool,
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
    /// RPMB authentication key, once programmed (write-once,
    /// §6.6.22.2). `None` until a key-program request lands.
    rpmb_key: Option<[u8; 32]>,
    /// RPMB write counter: increments per successful
    /// authenticated write (§6.6.22.2).
    rpmb_counter: u32,
    /// RPMB data store: 256-byte half-sectors by address
    /// (unwritten half-sectors read back as zero).
    rpmb_store: BTreeMap<u16, [u8; RPMB_LEN_DATA]>,
    /// Response frame staged for the next CMD18, if a request
    /// produced one.
    rpmb_response: Option<[u8; RPMB_FRAME_SIZE]>,
    /// Result-read response staged by the last programming
    /// access (key program / data write), fetched by a
    /// result-read request (§6.6.22.4.1/§6.6.22.4.3).
    rpmb_result_response: Option<[u8; RPMB_FRAME_SIZE]>,
    /// CMD23 pre-defined block count state (§6.6.7.1/§6.6.8.1):
    /// armed by CMD23 for the immediately following CMD18 /
    /// CMD25, with its count and reliable-write bit.
    cmd23_armed: bool,
    cmd23_count: u16,
    cmd23_reliable: bool,
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

    /// Move the modelled card and raise the present-change edge
    /// (§2.2.18) for the transition — gated on the matching Normal
    /// Interrupt Status Enable bit, as the spec gates the status
    /// bit itself on the enable. A no-op when the slot already
    /// holds (or lacks) a card: no edge, no bounce.
    fn set_card_present(&mut self, present: bool) {
        if self.card_present == present {
            return;
        }
        self.card_present = present;
        let en = self.get16(REG_NORMAL_INT_EN);
        let edge = if present {
            NIS_CARD_INSERTION
        } else {
            NIS_CARD_REMOVAL
        };
        if en & edge != 0 {
            let cur = self.get16(REG_NORMAL_INT_STS);
            self.set16(REG_NORMAL_INT_STS, cur | edge);
        }
    }

    /// Execute the command staged by a Command-register write.
    fn exec_cmd(&mut self, index: u8) {
        let arg = self.get32(REG_ARGUMENT);
        self.cmd_log.push(index);
        let transfer = self.get16(REG_TRANSFER_MODE);
        let is_dma = transfer & TM_DMA != 0;
        let block_size = (self.get16(REG_BLOCK_SIZE) & 0x0FFF) as usize;
        let block_count = self.get16(REG_BLOCK_COUNT) as usize;
        // eMMC cards ignore SEND_IF_COND (CMD8) and APP_CMD (CMD55)
        // in Idle state: no response at all, so the driver's
        // command times out. (CMD8 after selection is SEND_EXT_CSD.)
        if self.emmc && !self.selected && (index == 8 || index == 55) {
            return;
        }
        // CMD23 arms the pre-defined block count for the
        // immediately following CMD18 / CMD25 only (§6.6.7.1 /
        // §6.6.8.1): any other command in between disarms it.
        // CMD18 / CMD25 consume the arm in their own arms below
        // (CMD25's check runs at the buffer-port commit, after
        // the data lands, so its arm must survive the push).
        if index != 23 && index != 18 && index != 25 {
            self.cmd23_armed = false;
        }
        let mut nis = NIS_CMD_COMPLETE;
        match index {
            // CMD0 — reset: deselect, back to the user area, and
            // drop any SWITCH CMD13 has not confirmed yet, any
            // CMD23 arm, and any in-flight RPMB response.
            0 => {
                self.selected = false;
                self.current_access = 0;
                self.pending_access = None;
                self.cmd23_armed = false;
                self.rpmb_response = None;
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
            // CMD6 — SWITCH (eMMC, R1b) or switch-function (SD).
            // eMMC: a Write-Byte SWITCH to PARTITION_CONFIG
            // (index 179) requests a new accessed partition; it
            // takes effect only on a clean CMD13 (see
            // `pending_access`). SD: stage the 64-byte switch
            // status; a mode-1 switch installs the Function
            // Group 1 value (argument bits [3:0]) first.
            6 if self.emmc => {
                self.switch_count += 1;
                self.switch_args.push(arg);
                if ((arg >> 24) & 0x3) == 3 && ((arg >> 16) & 0xFF) == 179 {
                    self.pending_access = Some(((arg >> 8) as u8) & 0x07);
                }
                self.set32(REG_RESPONSE_0, 0x900);
            }
            6 => {
                if arg & 0x8000_0000 != 0 {
                    self.current_function = (arg & 0x0F) as u8;
                }
                self.read_stage =
                    switch_status_bytes(self.switch_support, self.current_function).to_vec();
                self.read_cursor = 0;
                nis |= NIS_BUFFER_READ_READY | NIS_TRANSFER_COMPLETE;
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
                    self.read_stage = self.ext_csd.to_vec();
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
            // ACMD51 — stage the 8-byte SCR at the Buffer Data Port.
            51 => {
                self.read_stage = FIXTURE_SCR.to_vec();
                self.read_cursor = 0;
                nis |= NIS_BUFFER_READ_READY | NIS_TRANSFER_COMPLETE;
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
            17 if self.emmc => {
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
                self.read_stage = block.to_vec();
                self.read_cursor = 0;
                nis |= NIS_BUFFER_READ_READY | NIS_TRANSFER_COMPLETE;
            }
            // CMD18 — READ MULTIPLE BLOCK with a CMD23
            // pre-defined count (§6.6.7.1), on the RPMB
            // partition: the staged block is the RPMB model's
            // pending response frame — or a General Failure
            // frame when no CMD23 (count 1) preceded it or no
            // request produced a response. (Other CMD18s fall
            // through to the 17 | 18 arm below; the guard is
            // what keeps this from shadowing main's multi-block
            // and DMA reads.)
            18 if self.current_access == 3 => {
                let armed = self.cmd23_armed;
                self.cmd23_armed = false;
                let ok = armed && self.cmd23_count == 1;
                let frame: [u8; RPMB_FRAME_SIZE] = if ok {
                    match self.rpmb_response.take() {
                        Some(frame) => frame,
                        None => {
                            self.rpmb_response_frame(RPMB_RESP_READ, RPMB_RESULT_GENERAL_FAILURE)
                                .bytes
                        }
                    }
                } else {
                    self.rpmb_response_frame(RPMB_RESP_READ, RPMB_RESULT_GENERAL_FAILURE)
                        .bytes
                };
                self.read_stage = frame.to_vec();
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
            // CMD23 — SET_BLOCK_COUNT (§6.6.7.1/§6.6.8.1): arm
            // the pre-defined block count for the immediately
            // following CMD18 / CMD25. Bits [15:0] are the
            // count; bit 31 is the reliable-write request.
            23 => {
                self.cmd23_armed = true;
                self.cmd23_count = (arg & 0xFFFF) as u16;
                self.cmd23_reliable = arg & (1 << 31) != 0;
                self.set32(REG_RESPONSE_0, 0x900);
            }
            // CMD25 — WRITE MULTIPLE BLOCK on the RPMB partition:
            // arm the Buffer Data Port capture. The commit path
            // routes the staged frame to the RPMB model; the
            // CMD23 arm survives the push and is consumed there.
            // The staging buffer is sized to one 512-byte frame
            // when empty: main's #837 Vec staging can be empty
            // after a multi-block take, where the RPMB base's
            // array form was always 512 bytes.
            25 if self.current_access == 3 => {
                self.write_lba = arg;
                self.write_cursor = 0;
                if self.write_stage.is_empty() {
                    self.write_stage = alloc::vec![0u8; 512];
                }
                nis |= NIS_BUFFER_WRITE_READY | NIS_TRANSFER_COMPLETE;
            }
            // CMD24 — single-block capture for eMMC cards
            // (a 512-byte staging buffer; the SD multi-block
            // path below does not apply — eMMC never issues
            // CMD25).
            24 if self.emmc => {
                self.write_lba = arg;
                self.write_cursor = 0;
                self.write_stage = alloc::vec![0u8; 512];
                nis |= NIS_BUFFER_WRITE_READY | NIS_TRANSFER_COMPLETE;
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
            // CMD16 / CMD55 and everything else: a plain completion
            // with a zero response.
            _ => {}
        }
        let cur = self.get16(REG_NORMAL_INT_STS);
        self.set16(REG_NORMAL_INT_STS, cur | nis);
    }

    /// RPMB capacity in 256-byte half-sectors, from the EXT_CSD
    /// RPMB_SIZE_MULT (§7.4.84: mult × 128 KiB).
    fn rpmb_capacity_half_sectors(&self) -> u32 {
        crate::emmc::ExtCsd::parse(&self.ext_csd)
            .map(|e| (e.rpmb_partition_bytes() / RPMB_LEN_DATA as u64) as u32)
            .unwrap_or(0)
    }

    /// A response frame of `resp_type` and `result`, MAC'd under
    /// the programmed key when one exists (the device MACs every
    /// response it can; before key programming the MAC field
    /// stays zero).
    fn rpmb_response_frame(&self, resp_type: u16, result: u16) -> RpmbFrame {
        let mut f = RpmbFrame::new();
        f.set_req_type(resp_type);
        f.set_result(result);
        if let Some(key) = &self.rpmb_key {
            let mac = narf_crypto::hkdf::hmac_sha256(key, f.mac_message());
            f.set_mac(&mac);
        }
        f
    }

    /// Stage a failure response for `req_type`: the matching
    /// response type (a read response when the request has
    /// none), the result, MAC'd when a key is programmed.
    fn rpmb_stage_failure(&mut self, req_type: u16, result: u16) {
        let resp_type = crate::rpmb::response_type_for(req_type).unwrap_or(RPMB_RESP_READ);
        let f = self.rpmb_response_frame(resp_type, result);
        self.rpmb_response = Some(f.bytes);
    }

    /// Stage the result-read response for a programming access:
    /// `resp_type` (0x0100 key program / 0x0300 write), the
    /// current counter, the address, the result — MAC'd under
    /// `key` when one is supplied (the key-program result is
    /// un-MAC'd, Table 24).
    fn rpmb_stage_result_response(
        &mut self,
        resp_type: u16,
        result: u16,
        address: u16,
        key: Option<&[u8; 32]>,
    ) {
        let mut f = RpmbFrame::new();
        f.set_req_type(resp_type);
        f.set_write_counter(self.rpmb_counter);
        f.set_address(address);
        f.set_result(result);
        if let Some(key) = key {
            let mac = narf_crypto::hkdf::hmac_sha256(key, f.mac_message());
            f.set_mac(&mac);
        }
        self.rpmb_result_response = Some(f.bytes);
    }

    /// Process one 512-byte RPMB request frame pushed by CMD25
    /// while the RPMB partition is accessed: validate the CMD23
    /// pre-conditions, run the request through the §6.6.22.4
    /// check order, and stage the response (or the result-read
    /// response for a programming access). The request frame
    /// itself is never stored as a plain block.
    fn rpmb_process_request(&mut self, frame: &[u8; RPMB_FRAME_SIZE]) {
        let req = RpmbFrame::from_bytes(*frame);
        // CMD23 must immediately precede the CMD25, with count
        // 1 (§6.6.22.4.1–§6.6.22.4.4); programming accesses
        // also need the reliable-write bit (§6.6.8.1).
        let reliable_needed = matches!(
            req.req_type(),
            RPMB_REQ_KEY_PROGRAM | RPMB_REQ_WRITE | RPMB_REQ_CONFIG_WRITE
        );
        if !self.cmd23_armed || self.cmd23_count != 1 || (reliable_needed && !self.cmd23_reliable) {
            self.rpmb_stage_failure(req.req_type(), RPMB_RESULT_GENERAL_FAILURE);
            return;
        }
        self.cmd23_armed = false;
        match req.req_type() {
            RPMB_REQ_KEY_PROGRAM => self.rpmb_key_program(&req),
            RPMB_REQ_READ_COUNTER => self.rpmb_counter_read(&req),
            RPMB_REQ_WRITE => self.rpmb_data_write(&req),
            RPMB_REQ_READ => self.rpmb_data_read(&req),
            RPMB_REQ_RESULT_READ => self.rpmb_result_read_req(),
            // Device-configuration accesses (0x0006/0x0007) and
            // anything else: not modelled, General failure.
            _ => self.rpmb_stage_failure(req.req_type(), RPMB_RESULT_GENERAL_FAILURE),
        }
    }

    /// Key programming (§6.6.22.4.1): the key is write-once
    /// (§6.6.22.2) — a second attempt fails. The result is
    /// reported through the result-read, not here.
    fn rpmb_key_program(&mut self, req: &RpmbFrame) {
        if self.rpmb_key.is_some() {
            self.rpmb_stage_failure(RPMB_REQ_KEY_PROGRAM, RPMB_RESULT_GENERAL_FAILURE);
            return;
        }
        self.rpmb_key = Some(req.mac());
        // The key-program result is un-MAC'd (Table 24 shows a
        // zero MAC field), so no key is passed.
        self.rpmb_stage_result_response(RPMB_RESP_KEY_PROGRAM, RPMB_RESULT_OK, 0, None);
    }

    /// Counter read (§6.6.22.4.2): the request carries no MAC;
    /// the response echoes the nonce, carries the counter, and
    /// is MAC'd. Before key programming the only valid result
    /// is 0x0007 (Table 20 note).
    fn rpmb_counter_read(&mut self, req: &RpmbFrame) {
        let Some(key) = self.rpmb_key else {
            self.rpmb_stage_failure(RPMB_REQ_READ_COUNTER, RPMB_RESULT_KEY_NOT_PROGRAMMED);
            return;
        };
        let mut f = RpmbFrame::new();
        f.set_req_type(RPMB_RESP_READ_COUNTER);
        f.set_nonce(&req.nonce());
        f.set_write_counter(self.rpmb_counter);
        let result = if self.rpmb_counter == u32::MAX {
            RPMB_RESULT_OK | RPMB_RESULT_COUNTER_EXPIRED
        } else {
            RPMB_RESULT_OK
        };
        f.set_result(result);
        let mac = narf_crypto::hkdf::hmac_sha256(&key, f.mac_message());
        f.set_mac(&mac);
        self.rpmb_response = Some(f.bytes);
    }

    /// Authenticated data write (§6.6.22.4.3), in the spec's
    /// check order: counter expired, address, MAC, counter
    /// match. The outcome is reported through the result-read
    /// (0x0300); the immediate CMD18 after a write has nothing
    /// to return.
    fn rpmb_data_write(&mut self, req: &RpmbFrame) {
        let Some(key) = self.rpmb_key else {
            self.rpmb_stage_result_response(
                RPMB_RESP_WRITE,
                RPMB_RESULT_KEY_NOT_PROGRAMMED,
                req.address(),
                None,
            );
            return;
        };
        if self.rpmb_counter == u32::MAX {
            self.rpmb_stage_result_response(
                RPMB_RESP_WRITE,
                RPMB_RESULT_WRITE_FAILURE | RPMB_RESULT_COUNTER_EXPIRED,
                req.address(),
                Some(&key),
            );
            return;
        }
        if (req.address() as u32) >= self.rpmb_capacity_half_sectors() || req.block_count() != 1 {
            self.rpmb_stage_result_response(
                RPMB_RESP_WRITE,
                RPMB_RESULT_ADDRESS_FAILURE,
                req.address(),
                Some(&key),
            );
            return;
        }
        let expect = narf_crypto::hkdf::hmac_sha256(&key, req.mac_message());
        if req.mac() != expect {
            self.rpmb_stage_result_response(
                RPMB_RESP_WRITE,
                RPMB_RESULT_AUTH_FAILURE,
                req.address(),
                Some(&key),
            );
            return;
        }
        if req.write_counter() != self.rpmb_counter {
            self.rpmb_stage_result_response(
                RPMB_RESP_WRITE,
                RPMB_RESULT_COUNTER_FAILURE,
                req.address(),
                Some(&key),
            );
            return;
        }
        let mut slot = [0u8; RPMB_LEN_DATA];
        slot.copy_from_slice(req.data());
        self.rpmb_store.insert(req.address(), slot);
        self.rpmb_counter += 1;
        self.rpmb_stage_result_response(RPMB_RESP_WRITE, RPMB_RESULT_OK, req.address(), Some(&key));
    }

    /// Authenticated data read (§6.6.22.4.4): the address is
    /// checked first, then the request MAC authenticates the
    /// reader before any data is served. The response echoes
    /// the nonce, carries the data, and is MAC'd; its write
    /// counter is 0x00 by spec.
    fn rpmb_data_read(&mut self, req: &RpmbFrame) {
        let Some(key) = self.rpmb_key else {
            self.rpmb_stage_failure(RPMB_REQ_READ, RPMB_RESULT_KEY_NOT_PROGRAMMED);
            return;
        };
        if (req.address() as u32) >= self.rpmb_capacity_half_sectors() {
            self.rpmb_stage_failure(RPMB_REQ_READ, RPMB_RESULT_ADDRESS_FAILURE);
            return;
        }
        let expect = narf_crypto::hkdf::hmac_sha256(&key, req.mac_message());
        if req.mac() != expect {
            // Authentication failure; the data is not served.
            self.rpmb_stage_failure(RPMB_REQ_READ, RPMB_RESULT_AUTH_FAILURE);
            return;
        }
        let mut f = RpmbFrame::new();
        f.set_req_type(RPMB_RESP_READ);
        f.set_nonce(&req.nonce());
        f.set_address(req.address());
        f.set_block_count(1);
        f.set_result(RPMB_RESULT_OK);
        if let Some(data) = self.rpmb_store.get(&req.address()) {
            f.set_data(data);
        }
        let mac = narf_crypto::hkdf::hmac_sha256(&key, f.mac_message());
        f.set_mac(&mac);
        self.rpmb_response = Some(f.bytes);
    }

    /// Result-register read (§6.6.22.4.1/§6.6.22.4.3): fetch
    /// the pending programming result. Without one there is
    /// nothing to report.
    fn rpmb_result_read_req(&mut self) {
        match self.rpmb_result_response.take() {
            Some(frame) => self.rpmb_response = Some(frame),
            None => self.rpmb_stage_failure(RPMB_REQ_RESULT_READ, RPMB_RESULT_GENERAL_FAILURE),
        }
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
    /// A controller with a card whose storage is `image`. The card
    /// starts present in the slot; use `insert_card` /
    /// `remove_card` to move it.
    pub fn with_image(image: BTreeMap<u32, [u8; 512]>) -> Self {
        let mut regs = [0u8; 0x100];
        regs[0x40..0x44].copy_from_slice(&FIXTURE_CAPS.to_le_bytes());
        regs[0xFE] = FIXTURE_SPEC_VERSION;
        FixtureTransport {
            state: IrqSafeSpinLock::new(FixtureState {
                regs,
                card_present: true,
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
                rpmb_key: None,
                rpmb_counter: 0,
                rpmb_store: BTreeMap::new(),
                rpmb_response: None,
                rpmb_result_response: None,
                cmd23_armed: false,
                cmd23_count: 0,
                cmd23_reliable: false,
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
                card_present: true,
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
                rpmb_key: None,
                rpmb_counter: 0,
                rpmb_store: BTreeMap::new(),
                rpmb_response: None,
                rpmb_result_response: None,
                cmd23_armed: false,
                cmd23_count: 0,
                cmd23_reliable: false,
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
    /// Insert a card into the modelled slot (raises the Card
    /// Insertion edge when the driver enabled it).
    pub fn insert_card(&self) {
        self.state.lock().set_card_present(true);
    }

    /// Remove the card from the modelled slot (raises the Card
    /// Removal edge when the driver enabled it).
    pub fn remove_card(&self) {
        self.state.lock().set_card_present(false);
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

    /// A half-sector from the modelled RPMB store, if written.
    pub fn stored_rpmb_half_sector(&self, address: u16) -> Option<[u8; RPMB_LEN_DATA]> {
        self.state.lock().rpmb_store.get(&address).copied()
    }

    /// The modelled RPMB write counter.
    pub fn rpmb_counter(&self) -> u32 {
        self.state.lock().rpmb_counter
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
            // Present State (§2.2.9): Card Inserted + Card State
            // Stable follow the modelled card; both clear when the
            // slot is empty. The DAT level bits track the modelled
            // card state (low during a voltage switch, high
            // otherwise).
            REG_PRESENT_STATE => {
                let base = st.get32(offset)
                    & !(PSTATE_CARD_INSERTED | PSTATE_CARD_STATE_STABLE | PSTATE_DAT_LVL_MASK);
                let with_dat = base | ((st.dat_level as u32) << PSTATE_DAT_LVL_SHIFT);
                if st.card_present {
                    with_dat | PSTATE_CARD_INSERTED | PSTATE_CARD_STATE_STABLE
                } else {
                    with_dat
                }
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
            // whole staged run has landed (SD multi-block), or
            // the single block into the currently accessed
            // partition (eMMC) — except on the RPMB partition,
            // where the block is a request frame for the RPMB
            // model, never a plain block.
            if st.write_stage.is_empty() {
                return;
            }
            let cur = st.write_cursor;
            if cur + 4 > st.write_stage.len() {
                return;
            }
            st.write_stage[cur..cur + 4].copy_from_slice(&value.to_le_bytes());
            st.write_cursor += 4;
            if st.emmc {
                if st.write_cursor == 512 {
                    if st.current_access == 3 {
                        let mut frame = [0u8; RPMB_FRAME_SIZE];
                        frame.copy_from_slice(&st.write_stage[..RPMB_FRAME_SIZE]);
                        st.rpmb_process_request(&frame);
                        return;
                    }
                    // The CMD24 argument is a block address, except on
                    // a byte-addressed eMMC card where it is a byte
                    // address (mirror the CMD17 staging above).
                    let lba = if st.emmc && !st.sector_mode {
                        st.write_lba / 512
                    } else {
                        st.write_lba
                    };
                    let mut block = [0u8; 512];
                    block.copy_from_slice(&st.write_stage[..512]);
                    let access = st.current_access;
                    if access == 0 {
                        st.image.insert(lba, block);
                    } else {
                        st.part_image.insert((access, lba), block);
                    }
                }
            } else {
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

// ── Card detect (#836) ────────────────────────────────────────────

/// Empty slot → insert → identify + publish → remove → unpublish
/// → re-insert → re-probe, all through the production
/// `poll_card_slot` path. The controller itself stays installed
/// throughout: only the card state toggles.
fn fixture_card_detect_insert_remove_reprobe() -> TestResult {
    let (transport, saved) = install(partitioned_image());
    // As bring_up step 5 does: enable all normal-interrupt status,
    // so the present-change edges can set.
    transport.write16(REG_NORMAL_INT_EN, 0xFFFF);
    transport.remove_card();

    let result = (|| {
        // Empty slot: the poll is a no-op.
        poll_card_slot();
        if narf_block::registry::find_block_device("sdhci0").is_some() {
            return Err("empty slot must not publish sdhci0");
        }
        // Insert: the present-change edge sets, then the poll
        // identifies the card and publishes it + partitions.
        transport.insert_card();
        if transport.read16(REG_NORMAL_INT_STS) & NIS_CARD_INSERTION == 0 {
            return Err("insertion must set the Card Insertion status bit");
        }
        poll_card_slot();
        if transport.read16(REG_NORMAL_INT_STS) & NIS_CARD_INSERTION != 0 {
            return Err("poll must acknowledge (clear) the Card Insertion status bit");
        }
        let p1 = narf_block::registry::find_block_device("sdhci0p1")
            .ok_or("sdhci0p1 not registered after insertion")?;
        if p1.capacity() != 4096 {
            return Err("sdhci0p1 capacity must be the MBR sector count (4096)");
        }
        // A read through the freshly published card lands on the
        // right card block.
        let mut buf = [0u8; 512];
        p1.read(0, 1, &mut buf)
            .map_err(|_| "p1 read after insertion failed")?;
        if buf != partition_pattern(0xA1) {
            return Err("sdhci0p1 block 0 must be card block 2048 after insertion");
        }
        // A second poll with the card already known re-identifies
        // nothing: the identify conversation runs exactly once per
        // insertion.
        let cmds_before = transport.cmd_indices().len();
        poll_card_slot();
        if transport.cmd_indices().len() != cmds_before {
            return Err("poll with a known card must not re-run identify");
        }
        // Removal withdraws parent + partitions together, and the
        // controller forgets the card — but stays installed.
        transport.remove_card();
        if transport.read16(REG_NORMAL_INT_STS) & NIS_CARD_REMOVAL == 0 {
            return Err("removal must set the Card Removal status bit");
        }
        poll_card_slot();
        for name in ["sdhci0", "sdhci0p1", "sdhci0p2"] {
            if narf_block::registry::find_block_device(name).is_some() {
                return Err("removed card's devices must be unregistered");
            }
        }
        let ctrl = probed_sdhci().ok_or("controller must stay installed after removal")?;
        if ctrl.card.lock().is_some() {
            return Err("controller must forget the card on removal");
        }
        // A further poll on the empty slot is a no-op, and
        // re-insertion re-probes the card end to end.
        poll_card_slot();
        transport.insert_card();
        poll_card_slot();
        let p1 = narf_block::registry::find_block_device("sdhci0p1")
            .ok_or("sdhci0p1 not registered after re-insertion")?;
        if p1.capacity() != 4096 {
            return Err("re-probed sdhci0p1 capacity must be the MBR sector count (4096)");
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
    fixture_card_detect_insert_remove_reprobe
);

/// A command's blanket NIS clear (`cmd()` writes 0xFFFF to
/// REG_NORMAL_INT_STS at the start of every command) can wipe a
/// pending present-change edge before the poller sees it. The
/// Present State level — not the edge — must still drive the
/// identify.
fn fixture_card_detect_level_fallback_when_edge_wiped() -> TestResult {
    let (transport, saved) = install(partitioned_image());
    transport.write16(REG_NORMAL_INT_EN, 0xFFFF);
    transport.remove_card();

    let result = (|| {
        poll_card_slot();
        transport.insert_card();
        // Simulate the race: a command clears all NIS bits.
        transport.write16(REG_NORMAL_INT_STS, 0xFFFF);
        if transport.read16(REG_NORMAL_INT_STS) & NIS_CARD_INSERTION != 0 {
            return Err("test setup: the insertion edge must be wiped before the poll");
        }
        poll_card_slot();
        if narf_block::registry::find_block_device("sdhci0").is_none() {
            return Err(
                "card must still identify from the Present State level after the edge was wiped",
            );
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
    fixture_card_detect_level_fallback_when_edge_wiped
);

/// Insertion followed by removal before any poll: no card was ever
/// identified, so the poll must publish nothing and withdraw
/// nothing — and the controller stays installed for the next card.
fn fixture_card_detect_insert_then_remove_before_poll() -> TestResult {
    let (transport, saved) = install(partitioned_image());
    transport.write16(REG_NORMAL_INT_EN, 0xFFFF);
    transport.remove_card();

    let result = (|| {
        poll_card_slot();
        transport.insert_card();
        transport.remove_card();
        poll_card_slot();
        if narf_block::registry::find_block_device("sdhci0").is_some() {
            return Err("card removed before any poll must never publish sdhci0");
        }
        if probed_sdhci().is_none() {
            return Err("controller must stay installed after an unpolled insert/remove");
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
    fixture_card_detect_insert_then_remove_before_poll
);

/// Fixed test key for the RPMB fixture: bytes 0x00..0x1F. It is
/// a test-only key for a modelled card, never a production key.
const FIXTURE_RPMB_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

/// One RPMB half-sector (256 bytes) filled with an
/// offset-sensitive pattern derived from `tag`.
fn rpmb_data_pattern(tag: u8) -> [u8; RPMB_LEN_DATA] {
    let mut b = [0u8; RPMB_LEN_DATA];
    for (i, x) in b.iter_mut().enumerate() {
        *x = tag ^ (i as u8);
    }
    b
}

/// Send one RPMB request frame on the raw command path: CMD23
/// (count 1, reliable-write when `reliable`) + CMD25
/// (argument 0). The caller must have switched the card to the
/// RPMB partition first.
fn rpmb_send_raw(
    ctrl: &Sdhci,
    frame: &[u8; RPMB_FRAME_SIZE],
    reliable: bool,
) -> Result<(), &'static str> {
    let arg = 1u32 | if reliable { 1 << 31 } else { 0 };
    let _ = ctrl
        .cmd(23, arg, RESP_48, false, 0, 0, 0)
        .map_err(|_| "CMD23 failed")?;
    ctrl.write_pio_block(25, 0, true, frame)
        .map_err(|_| "CMD25 failed")?;
    Ok(())
}

/// Receive one RPMB response frame on the raw command path:
/// CMD23 (count 1) + CMD18 (argument 0).
fn rpmb_recv_raw(ctrl: &Sdhci) -> Result<RpmbFrame, &'static str> {
    let _ = ctrl
        .cmd(23, 1, RESP_48, false, 0, 0, 0)
        .map_err(|_| "CMD23 failed")?;
    let mut raw = [0u8; RPMB_FRAME_SIZE];
    ctrl.read_pio_block(18, 0, true, &mut raw)
        .map_err(|_| "CMD18 failed")?;
    Ok(RpmbFrame::from_bytes(raw))
}

/// A raw result-register read: the type-0x0005 request, then
/// the response frame.
fn rpmb_result_read_raw(ctrl: &Sdhci) -> Result<RpmbFrame, &'static str> {
    rpmb_send_raw(ctrl, &RpmbFrame::result_read().bytes, false)?;
    rpmb_recv_raw(ctrl)
}

/// RPMB authenticated round-trip end to end: program the key,
/// read the counter (0), write one half-sector, read the
/// counter (1), read the half-sector back, and read an
/// unwritten half-sector (zero). The command conversation is
/// CMD23 + CMD18/CMD25 throughout (§6.6.22.4), the card
/// switches to the RPMB partition and back to the user area
/// for every operation, and RPMB still publishes no plain
/// block device.
fn fixture_emmc_rpmb_auth_round_trip() -> TestResult {
    let (transport, saved) = install_emmc(
        partitioned_image(),
        fixture_part_image(),
        fixture_ext_csd(16_777_216),
        true,
        None,
    );

    let result = (|| {
        let _card = identify_emmc_and_publish()?;
        if narf_block::registry::find_block_device("emmc0rpmb").is_some() {
            return Err("RPMB must not publish as a plain block device");
        }
        let key = &FIXTURE_RPMB_KEY;
        let data = rpmb_data_pattern(0x11);
        with_controller(|ctrl| -> Result<(), &'static str> {
            ctrl.rpmb_program_key(key)
                .map_err(|_| "program key failed")?;
            let counter = ctrl
                .rpmb_read_counter(key)
                .map_err(|_| "counter read failed")?;
            if counter != 0 {
                return Err("counter must start at 0");
            }
            ctrl.rpmb_write(key, 0x0010, &data)
                .map_err(|_| "authenticated write failed")?;
            let counter = ctrl
                .rpmb_read_counter(key)
                .map_err(|_| "counter read failed")?;
            if counter != 1 {
                return Err("counter must be 1 after one write");
            }
            let mut out = [0u8; RPMB_LEN_DATA];
            ctrl.rpmb_read(key, 0x0010, &mut out)
                .map_err(|_| "authenticated read failed")?;
            if out != data {
                return Err("authenticated read must return the written half-sector");
            }
            ctrl.rpmb_read(key, 0x0011, &mut out)
                .map_err(|_| "read of an unwritten half-sector failed")?;
            if out != [0u8; RPMB_LEN_DATA] {
                return Err("unwritten half-sector must read back as zero");
            }
            Ok(())
        })
        .ok_or("no controller")??;
        // The card is back on the user area after every op.
        let ctrl = probed_sdhci().ok_or("fixture controller not installed")?;
        if *ctrl.emmc_access.lock() != 0 {
            return Err("card must be back on the user area after the RPMB ops");
        }
        // The conversation, counted: program key (3×CMD23,
        // 2×CMD25, 1×CMD18), counter read (2, 1, 1), write
        // (counter 2/1/1 + send 1/1/0 + result 2/1/1), counter
        // read (2, 1, 1), read (2, 1, 1) = 14 CMD23, 8 CMD25,
        // 6 CMD18 — and no CMD17/CMD24 at all on the RPMB path.
        let indices = transport.cmd_indices();
        let count = |idx: u8| indices.iter().filter(|&&i| i == idx).count();
        if count(23) != 14 || count(25) != 8 || count(18) != 6 {
            return Err("RPMB conversation must be CMD23 + CMD18/CMD25 (14/8/6)");
        }
        // Eleven SWITCHes: the identify pin to the user area,
        // then to RPMB (0x0B) and back (0x08) for each of the
        // five operations.
        let switches = transport.switch_args();
        let switch_arg = |value: u8| (3u32 << 24) | (179u32 << 16) | ((value as u32) << 8);
        if switches.len() != 11 || !switches.contains(&switch_arg(0x0B)) {
            return Err("each RPMB op must switch to RPMB and back to the user area");
        }
        // The model saw the write land exactly once.
        match transport.stored_rpmb_half_sector(0x0010) {
            Some(b) if b == data => {}
            _ => return Err("modelled RPMB store must hold the written half-sector"),
        }
        if transport.rpmb_counter() != 1 {
            return Err("modelled RPMB counter must be 1");
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
    fixture_emmc_rpmb_auth_round_trip
);

/// A write (and a read) under the wrong key fails, the counter
/// never moves, and nothing is stored: the device's MAC check
/// rejects the request, and the driver's MAC check rejects a
/// response that is not under the caller's key.
fn fixture_emmc_rpmb_wrong_key_rejected() -> TestResult {
    let (transport, saved) = install_emmc(
        partitioned_image(),
        fixture_part_image(),
        fixture_ext_csd(16_777_216),
        true,
        None,
    );

    let result = (|| {
        let _card = identify_emmc_and_publish()?;
        let wrong = [0x77u8; 32];
        let data = rpmb_data_pattern(0x22);
        with_controller(|ctrl| -> Result<(), &'static str> {
            ctrl.rpmb_program_key(&FIXTURE_RPMB_KEY)
                .map_err(|_| "program key failed")?;
            if ctrl.rpmb_write(&wrong, 0x0010, &data).is_ok() {
                return Err("write under the wrong key must fail");
            }
            let counter = ctrl
                .rpmb_read_counter(&FIXTURE_RPMB_KEY)
                .map_err(|_| "counter read failed")?;
            if counter != 0 {
                return Err("rejected write must not advance the counter");
            }
            let mut out = [0u8; RPMB_LEN_DATA];
            if ctrl.rpmb_read(&wrong, 0x0010, &mut out).is_ok() {
                return Err("read under the wrong key must fail");
            }
            Ok(())
        })
        .ok_or("no controller")??;
        if transport.stored_rpmb_half_sector(0x0010).is_some() {
            return Err("rejected write must not store data");
        }
        if transport.rpmb_counter() != 0 {
            return Err("modelled RPMB counter must stay 0");
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
    fixture_emmc_rpmb_wrong_key_rejected
);

/// Replay protection on the raw command path: a well-formed
/// write frame succeeds once (result 0x0000, counter 1), the
/// identical frame replayed reports Counter failure (0x0003),
/// and an out-of-range write with a fresh counter and a valid
/// MAC reports Address failure (0x0004). The write-result
/// response MAC is verified under the key, proving the model's
/// MAC is a real HMAC-SHA-256 and not a placeholder.
fn fixture_emmc_rpmb_replay_and_address_rejected() -> TestResult {
    let (transport, saved) = install_emmc(
        partitioned_image(),
        fixture_part_image(),
        fixture_ext_csd(16_777_216),
        true,
        None,
    );

    let result = (|| {
        let _card = identify_emmc_and_publish()?;
        with_controller(|ctrl| -> Result<(), &'static str> {
            ctrl.rpmb_program_key(&FIXTURE_RPMB_KEY)
                .map_err(|_| "program key failed")?;
            Ok(())
        })
        .ok_or("no controller")??;
        // A well-formed write frame at counter 0.
        let mut frame = RpmbFrame::data_write(0, 0x0020, &rpmb_data_pattern(0x22));
        let mac = narf_crypto::hkdf::hmac_sha256(&FIXTURE_RPMB_KEY, frame.mac_message());
        frame.set_mac(&mac);
        let frame_bytes = frame.bytes;
        let first = with_controller(|ctrl| -> Result<RpmbFrame, &'static str> {
            ctrl.ensure_partition_access(3)
                .map_err(|_| "switch to RPMB failed")?;
            rpmb_send_raw(ctrl, &frame_bytes, true)?;
            rpmb_result_read_raw(ctrl)
        })
        .ok_or("no controller")??;
        if first.req_type() != RPMB_RESP_WRITE
            || first.result() != RPMB_RESULT_OK
            || first.write_counter() != 1
        {
            return Err("first write must report success at counter 1");
        }
        let expect = narf_crypto::hkdf::hmac_sha256(&FIXTURE_RPMB_KEY, first.mac_message());
        if first.mac() != expect {
            return Err("write result MAC must verify under the key");
        }
        // Replay the identical frame.
        let replay = with_controller(|ctrl| -> Result<RpmbFrame, &'static str> {
            rpmb_send_raw(ctrl, &frame_bytes, true)?;
            rpmb_result_read_raw(ctrl)
        })
        .ok_or("no controller")??;
        if replay.req_type() != RPMB_RESP_WRITE || replay.result() != RPMB_RESULT_COUNTER_FAILURE {
            return Err("replayed write must report counter failure (0x0003)");
        }
        // Out of range with a fresh counter and a valid MAC.
        let mut oob = RpmbFrame::data_write(1, 0x4000, &rpmb_data_pattern(0x33));
        let mac = narf_crypto::hkdf::hmac_sha256(&FIXTURE_RPMB_KEY, oob.mac_message());
        oob.set_mac(&mac);
        let oob_bytes = oob.bytes;
        let oob_resp = with_controller(|ctrl| -> Result<RpmbFrame, &'static str> {
            rpmb_send_raw(ctrl, &oob_bytes, true)?;
            rpmb_result_read_raw(ctrl)
        })
        .ok_or("no controller")??;
        if oob_resp.req_type() != RPMB_RESP_WRITE
            || oob_resp.result() != RPMB_RESULT_ADDRESS_FAILURE
        {
            return Err("out-of-range write must report address failure (0x0004)");
        }
        with_controller(|ctrl| -> Result<(), &'static str> {
            ctrl.ensure_partition_access(0)
                .map_err(|_| "switch to user failed")?;
            Ok(())
        })
        .ok_or("no controller")??;
        // The first write landed; the replay and the
        // out-of-range write did not move the counter.
        match transport.stored_rpmb_half_sector(0x0020) {
            Some(b) if b == rpmb_data_pattern(0x22) => {}
            _ => return Err("modelled RPMB store must hold the first write"),
        }
        if transport.rpmb_counter() != 1 {
            return Err("modelled RPMB counter must be 1 after one write");
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
    fixture_emmc_rpmb_replay_and_address_rejected
);

/// Before the key is programmed every RPMB access reports
/// KeyNotProgrammed (0x0007) — the only valid result until
/// the key exists (Table 20 note) — and no MAC is involved.
fn fixture_emmc_rpmb_key_not_programmed() -> TestResult {
    let (_transport, saved) = install_emmc(
        partitioned_image(),
        fixture_part_image(),
        fixture_ext_csd(16_777_216),
        true,
        None,
    );

    let result = (|| {
        let _card = identify_emmc_and_publish()?;
        with_controller(|ctrl| -> Result<(), &'static str> {
            if ctrl.rpmb_read_counter(&FIXTURE_RPMB_KEY).is_ok() {
                return Err("counter read before key programming must fail");
            }
            let mut out = [0u8; RPMB_LEN_DATA];
            if ctrl.rpmb_read(&FIXTURE_RPMB_KEY, 0, &mut out).is_ok() {
                return Err("read before key programming must fail");
            }
            if ctrl
                .rpmb_write(&FIXTURE_RPMB_KEY, 0, &[0u8; RPMB_LEN_DATA])
                .is_ok()
            {
                return Err("write before key programming must fail");
            }
            Ok(())
        })
        .ok_or("no controller")??;
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
    fixture_emmc_rpmb_key_not_programmed
);

/// The driver validates the half-sector address before
/// touching the card: reads and writes past the 4 MiB RPMB
/// partition (16384 half-sectors) fail without issuing a
/// CMD25, and the last valid half-sector (0x3FFF) writes.
/// CMD25 count: 2 for the key program + 3 for the one
/// successful write.
fn fixture_emmc_rpmb_out_of_range() -> TestResult {
    let (transport, saved) = install_emmc(
        partitioned_image(),
        fixture_part_image(),
        fixture_ext_csd(16_777_216),
        true,
        None,
    );

    let result = (|| {
        let _card = identify_emmc_and_publish()?;
        with_controller(|ctrl| -> Result<(), &'static str> {
            ctrl.rpmb_program_key(&FIXTURE_RPMB_KEY)
                .map_err(|_| "program key failed")?;
            let mut out = [0u8; RPMB_LEN_DATA];
            if ctrl.rpmb_read(&FIXTURE_RPMB_KEY, 0x4000, &mut out).is_ok() {
                return Err("read past the RPMB partition must fail");
            }
            if ctrl
                .rpmb_write(&FIXTURE_RPMB_KEY, 0x4000, &[0u8; RPMB_LEN_DATA])
                .is_ok()
            {
                return Err("write past the RPMB partition must fail");
            }
            ctrl.rpmb_write(&FIXTURE_RPMB_KEY, 0x3FFF, &[0x5Au8; RPMB_LEN_DATA])
                .map_err(|_| "write to the last half-sector failed")?;
            Ok(())
        })
        .ok_or("no controller")??;
        let indices = transport.cmd_indices();
        if indices.iter().filter(|&&i| i == 25).count() != 5 {
            return Err("out-of-range attempts must not issue CMD25");
        }
        match transport.stored_rpmb_half_sector(0x3FFF) {
            Some(b) if b == [0x5Au8; RPMB_LEN_DATA] => {}
            _ => return Err("last half-sector write must land in the model"),
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
    fixture_emmc_rpmb_out_of_range
);

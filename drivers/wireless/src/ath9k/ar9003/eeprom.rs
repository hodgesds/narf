// SPDX-License-Identifier: GPL-2.0-or-later
//! `ar9003_eeprom.c::ar9300_eeprom_restore_internal`: the compressed
//! calibration image of an AR9003 part, restored from the serial EEPROM
//! (through the `AR5416_EEPROM_OFFSET` window, `pci.c::ath_pci_eeprom_read`)
//! or the on-chip OTP into a `struct ar9300_eeprom`.
//!
//! The decode is Linux's, with one policy on top: a board value is never
//! invented. Linux starts from `ar9300_default`, overlays each valid block
//! (a `_CompressBlock` with a nonzero reference first copies that template)
//! and silently skips bad headers, bad checksums, unknown codes and bad
//! restores. This port refuses every such anomaly, refuses an image no
//! block was restored into, refuses a MAC address the board did not write,
//! and accepts template bytes only from the template whose
//! `templateVersion` the restored image itself names (the Linux-defined
//! base for that board id).

use alloc::boxed::Box;

use super::super::identity::{BringUpError, RegisterIo};
use super::templates::{AR9300_DEFAULT, AR9300_EEPROM_BYTES, TEMPLATES};
use super::Chip;

/// `ar9003_eeprom.c::COMP_HDR_LEN` / `COMP_CKSUM_LEN`.
const COMP_HDR_LEN: usize = 4;
const COMP_CKSUM_LEN: usize = 2;
/// `MSTATE`: at most this many blocks are examined.
const MSTATE: usize = 100;
/// `ar9003_eeprom.h::AR9300_EEPROM_SIZE` (bytes).
const AR9300_EEPROM_SIZE: usize = 16 * 1024;
/// `AR9300_BASE_ADDR`, `AR9300_BASE_ADDR_4K`, `AR9300_BASE_ADDR_512`.
pub(in crate::ath9k) const AR9300_BASE_ADDR: usize = 0x3ff;
pub(in crate::ath9k) const AR9300_BASE_ADDR_4K: usize = 0xfff;
pub(in crate::ath9k) const AR9300_BASE_ADDR_512: usize = 0x1ff;

const AR5416_EEPROM_OFFSET: u64 = 0x2000;
/// `reg.h::AR_EEPROM_STATUS_DATA` for `AR_SREV_9300_20_OR_LATER`.
const AR_EEPROM_STATUS_DATA: u64 = 0x4084;
const AR_EEPROM_STATUS_DATA_BUSY: u32 = 0x0001_0000;
const AR_EEPROM_STATUS_DATA_PROT_ACCESS: u32 = 0x0004_0000;
/// `AR9300_OTP_BASE`, `AR9300_OTP_STATUS`, `AR9300_OTP_READ_DATA` (non
/// AR9340/AR9550).
pub(in crate::ath9k) const AR9300_OTP_BASE: u64 = 0x14000;
pub(in crate::ath9k) const AR9300_OTP_STATUS: u64 = 0x15f18;
pub(in crate::ath9k) const AR9300_OTP_READ_DATA: u64 = 0x15f1c;
pub(in crate::ath9k) const AR9300_OTP_STATUS_TYPE: u32 = 0x7;
pub(in crate::ath9k) const AR9300_OTP_STATUS_VALID: u32 = 0x4;

/// `struct ar9300_eeprom` field offsets (packed).
pub(in crate::ath9k) mod field {
    pub const EEPROM_VERSION: usize = 0;
    pub const TEMPLATE_VERSION: usize = 1;
    pub const MAC_ADDR: usize = 2;
    pub const REG_DMN: usize = 28;
    pub const TXRX_MASK: usize = 32;
    pub const OP_FLAGS: usize = 33;
    pub const TXRX_GAIN: usize = 48;
    // `ar9300_base_eep_hdr`.
    pub const TUNING_CAPS: usize = 40;
    pub const FEATURE_ENABLE: usize = 42;
    pub const MISC_CONFIGURATION: usize = 43;
    pub const SWREG: usize = 49;
    // `struct ar9300_eeprom` sections (packed; offsets printed from the
    // compiled Linux structure).
    pub const MODAL_2G: usize = 53;
    pub const EXT1: usize = 124;
    pub const PIERS_2G: usize = 138;
    pub const CAL_2G: usize = 141;
    pub const TARGET_FBIN_CCK: usize = 195;
    pub const TARGET_FBIN_2G: usize = 197;
    pub const TARGET_FBIN_2G_HT20: usize = 200;
    pub const TARGET_CCK: usize = 206;
    pub const TARGET_2G: usize = 214;
    pub const TARGET_2G_HT20: usize = 226;
    pub const CTL_INDEX_2G: usize = 310;
    pub const CTL_FREQBIN_2G: usize = 322;
    pub const CTL_POWER_2G: usize = 370;
    pub const MODAL_5G: usize = 418;
    pub const EXT2: usize = 489;
    pub const PIERS_5G: usize = 503;
    pub const CAL_5G: usize = 511;
    pub const TARGET_FBIN_5G: usize = 655;
    pub const TARGET_FBIN_5G_HT20: usize = 663;
    pub const TARGET_5G: usize = 679;
    pub const TARGET_5G_HT20: usize = 711;
    pub const CTL_INDEX_5G: usize = 935;
    pub const CTL_FREQBIN_5G: usize = 944;
    pub const CTL_POWER_5G: usize = 1016;
    // `ar9300_BaseExtension_1` (at `EXT1`).
    pub const EXT1_ANT_DIV_CONTROL: usize = 0;
    pub const EXT1_MISC_ENABLE: usize = 3;
    pub const EXT1_TEMPSLOPE_EXTENSION: usize = 4;
    pub const EXT1_QUICK_DROP_LOW: usize = 12;
    pub const EXT1_QUICK_DROP_HIGH: usize = 13;
    // `ar9300_BaseExtension_2` (at `EXT2`).
    pub const EXT2_TEMP_SLOPE_LOW: usize = 0;
    pub const EXT2_TEMP_SLOPE_HIGH: usize = 1;
    pub const EXT2_XATTEN1_DB_LOW: usize = 2;
    pub const EXT2_XATTEN1_MARGIN_LOW: usize = 5;
    pub const EXT2_XATTEN1_DB_HIGH: usize = 8;
    pub const EXT2_XATTEN1_MARGIN_HIGH: usize = 11;
}

/// `ar9300_modal_eep_header` offsets (71 bytes, at `MODAL_2G`/`MODAL_5G`).
pub(in crate::ath9k) mod modal {
    pub const ANT_CTRL_COMMON: usize = 0;
    pub const ANT_CTRL_COMMON2: usize = 4;
    pub const ANT_CTRL_CHAIN: usize = 8;
    pub const XATTEN1_DB: usize = 14;
    pub const XATTEN1_MARGIN: usize = 17;
    pub const TEMP_SLOPE: usize = 20;
    pub const SPUR_CHANS: usize = 22;
    pub const NOISE_FLOOR_THRESH: usize = 27;
    pub const QUICK_DROP: usize = 41;
    pub const XPA_BIAS_LVL: usize = 42;
    pub const ANTENNA_GAIN: usize = 46;
    pub const TX_END_TO_XPA_OFF: usize = 49;
    pub const TX_FRAME_TO_XPA_ON: usize = 51;
    pub const SWITCH_COM_SPDT: usize = 61;
    pub const XLNA_BIAS_STRENGTH: usize = 63;
}

/// `ar9003_modal_header`: the 2 GHz or 5 GHz modal header base.
pub(in crate::ath9k) fn modal_base(five: bool) -> usize {
    if five {
        field::MODAL_5G
    } else {
        field::MODAL_2G
    }
}

/// `ath9k_hw_fbin2freq` (`AR5416_BCHAN_UNUSED` 0xff stays 255).
pub(in crate::ath9k) fn fbin2freq(fbin: u8, two_ghz: bool) -> i32 {
    if fbin == 0xff {
        255
    } else if two_ghz {
        2300 + i32::from(fbin)
    } else {
        4800 + 5 * i32::from(fbin)
    }
}

/// `enum CompressAlgorithm`.
const COMPRESS_NONE: u8 = 0;
const COMPRESS_BLOCK: u8 = 3;

/// Which non-volatile store held the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum Store {
    Eeprom,
    Otp,
}

/// Byte reads in `ar9300_read_eeprom` / `ar9300_read_otp` order:
/// `buffer[i]` is the byte at `address - i`.
pub(in crate::ath9k) trait Source {
    /// `ath9k_hw_nvram_read`: one 16-bit EEPROM word.
    fn eeprom_word(&mut self, word: usize) -> Result<u16, BringUpError>;
    /// `ar9300_otp_read_word`: one 32-bit OTP word.
    fn otp_word(&mut self, word: usize) -> Result<u32, BringUpError>;
}

/// The live `Source` of a powered AR9003 PCI part.
pub(in crate::ath9k) struct Nvram<'a, R: RegisterIo>(&'a mut R);

impl<'a, R: RegisterIo> Nvram<'a, R> {
    pub fn new(io: &'a mut R) -> Self {
        Self(io)
    }
}

impl<R: RegisterIo> Source for Nvram<'_, R> {
    fn eeprom_word(&mut self, word: usize) -> Result<u16, BringUpError> {
        if word >= AR9300_EEPROM_SIZE / 2 {
            return Err(BringUpError::BadLength);
        }
        // The *read* of the window word starts the EEPROM access.
        let _ = self.0.read32(AR5416_EEPROM_OFFSET + ((word as u64) << 2));
        self.0.wait_us(
            AR_EEPROM_STATUS_DATA,
            AR_EEPROM_STATUS_DATA_BUSY | AR_EEPROM_STATUS_DATA_PROT_ACCESS,
            0,
            100_000,
        )?;
        let value = self.0.read32(AR_EEPROM_STATUS_DATA);
        if value == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        Ok(value as u16)
    }
    fn otp_word(&mut self, word: usize) -> Result<u32, BringUpError> {
        let _ = self.0.read32(AR9300_OTP_BASE + 4 * word as u64);
        self.0.wait_us(
            AR9300_OTP_STATUS,
            AR9300_OTP_STATUS_TYPE,
            AR9300_OTP_STATUS_VALID,
            1000,
        )?;
        let value = self.0.read32(AR9300_OTP_READ_DATA);
        if value == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        Ok(value)
    }
}

/// `ar9300_read_eeprom`: `count` bytes downward from `address`, an even
/// start taking the low byte of its word first, then whole words high byte
/// first, then a trailing low byte. Reads below byte 0 (Linux would pass a
/// negative offset to the bus) are refused.
fn read_eeprom(
    source: &mut impl Source,
    address: usize,
    buffer: &mut [u8],
) -> Result<(), BringUpError> {
    let count = buffer.len();
    if (address + count) / 2 > AR9300_EEPROM_SIZE - 1 || count > address + 1 {
        return Err(BringUpError::BadLength);
    }
    let mut address = address;
    let mut at = 0;
    let mut left = count;
    if address % 2 == 0 && left > 0 {
        buffer[at] = source.eeprom_word(address / 2)? as u8;
        at += 1;
        left -= 1;
        address = address.wrapping_sub(1);
    }
    for _ in 0..left / 2 {
        let value = source.eeprom_word(address / 2)?;
        buffer[at] = (value >> 8) as u8;
        buffer[at + 1] = value as u8;
        at += 2;
        address = address.wrapping_sub(2);
    }
    if left % 2 != 0 {
        let value = source.eeprom_word(address / 2)?;
        buffer[at] = (value >> (8 * (address % 2))) as u8;
    }
    Ok(())
}

/// `ar9300_read_otp`: byte `i` is byte `(address - i) % 4` of OTP word
/// `(address - i) / 4`, each byte its own word read.
fn read_otp(
    source: &mut impl Source,
    address: usize,
    buffer: &mut [u8],
) -> Result<(), BringUpError> {
    if buffer.len() > address + 1 {
        return Err(BringUpError::BadLength);
    }
    for (i, byte) in buffer.iter_mut().enumerate() {
        let at = address - i;
        *byte = (source.otp_word(at / 4)? >> (8 * (at % 4))) as u8;
    }
    Ok(())
}

fn read(
    store: Store,
    source: &mut impl Source,
    address: usize,
    buffer: &mut [u8],
) -> Result<(), BringUpError> {
    match store {
        Store::Eeprom => read_eeprom(source, address, buffer),
        Store::Otp => read_otp(source, address, buffer),
    }
}

/// `ar9300_check_header`: neither all-zero nor all-ones.
fn header_valid(header: &[u8; 4]) -> bool {
    let word = u32::from_le_bytes(*header);
    word != 0 && word != u32::MAX
}

/// `ar9300_comp_hdr_unpack`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct BlockHeader {
    pub code: u8,
    pub reference: u8,
    pub length: usize,
    pub major: u8,
    pub minor: u8,
}

impl BlockHeader {
    pub fn unpack(best: &[u8; 4]) -> Self {
        let value = best.map(usize::from);
        Self {
            code: ((value[0] >> 5) & 0x7) as u8,
            reference: ((value[0] & 0x1f) | ((value[1] >> 2) & 0x20)) as u8,
            length: ((value[1] << 4) & 0x7f0) | ((value[2] >> 4) & 0xf),
            major: (value[2] & 0xf) as u8,
            minor: value[3] as u8,
        }
    }
}

/// `ar9300_comp_cksum`.
fn comp_checksum(data: &[u8]) -> u16 {
    data.iter()
        .fold(0u16, |sum, &byte| sum.wrapping_add(u16::from(byte)))
}

/// Per-chip restore limits (`AR_SREV_9485`: `EEPROM_DATA_LEN_9485` and the
/// 4K base first; every other part: `length < 1024`, `AR9300_BASE_ADDR`
/// first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Limits {
    /// Largest accepted block length.
    pub max_length: usize,
    /// The first EEPROM base address tried.
    pub first_eeprom_base: usize,
}

impl Limits {
    pub fn for_chip(chip: Chip) -> Self {
        match chip {
            Chip::Ar9300 | Chip::Ar9580 | Chip::Ar9462 | Chip::Ar9565 => Self {
                max_length: 1023,
                first_eeprom_base: AR9300_BASE_ADDR,
            },
            // `ar9003_eeprom.c::EEPROM_DATA_LEN_9485` (1088) and the 4K
            // base first, per the doc comment above.
            Chip::Ar9485 => Self {
                max_length: 1088,
                first_eeprom_base: AR9300_BASE_ADDR_4K,
            },
        }
    }
}

/// A restored `struct ar9300_eeprom` with its provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Restored {
    pub image: Box<[u8; AR9300_EEPROM_BYTES]>,
    pub store: Store,
    /// The base address the first block header was found at.
    pub base: usize,
    /// Blocks restored into the image.
    pub blocks: u8,
    /// `templateVersion` of the template the unrestored bytes came from
    /// (`ar9300_default` is 2).
    pub template: u8,
}

/// `ar9300_eeprom_restore_internal` + `ar9300_compress_decision` +
/// `ar9300_uncompress_block`, under the no-invented-values policy above.
pub(in crate::ath9k) fn restore(
    source: &mut impl Source,
    limits: Limits,
) -> Result<Restored, BringUpError> {
    let candidates = [
        (Store::Eeprom, limits.first_eeprom_base),
        (Store::Eeprom, AR9300_BASE_ADDR_4K),
        (Store::Eeprom, AR9300_BASE_ADDR_512),
        (Store::Otp, AR9300_BASE_ADDR),
        (Store::Otp, AR9300_BASE_ADDR_512),
    ];
    let mut found = None;
    for (store, base) in candidates {
        let mut header = [0u8; 4];
        // A failed probe read is Linux's "header invalid": try the next.
        if read(store, source, base, &mut header).is_ok() && header_valid(&header) {
            found = Some((store, base));
            break;
        }
    }
    let (store, base) = found.ok_or(BringUpError::BadMagic)?;

    let mut image = Box::new(AR9300_DEFAULT);
    let mut board = [false; AR9300_EEPROM_BYTES];
    let mut template = AR9300_DEFAULT[field::TEMPLATE_VERSION];
    let mut blocks = 0u8;
    let mut cptr = base;
    let mut word = [0u8; 2048];
    for _ in 0..MSTATE {
        let mut header = [0u8; 4];
        read(store, source, cptr, &mut header)?;
        if !header_valid(&header) {
            break;
        }
        let block = BlockHeader::unpack(&header);
        if block.length > limits.max_length || block.length > cptr {
            return Err(BringUpError::BadLength);
        }
        let total = COMP_HDR_LEN + block.length + COMP_CKSUM_LEN;
        read(store, source, cptr, &mut word[..total])?;
        let data = &word[COMP_HDR_LEN..COMP_HDR_LEN + block.length];
        let stored = u16::from_le_bytes([
            word[COMP_HDR_LEN + block.length],
            word[COMP_HDR_LEN + block.length + 1],
        ]);
        if comp_checksum(data) != stored {
            return Err(BringUpError::BadChecksum);
        }
        match block.code {
            COMPRESS_NONE => {
                if block.length != AR9300_EEPROM_BYTES {
                    return Err(BringUpError::BadLength);
                }
                image.copy_from_slice(data);
                board = [true; AR9300_EEPROM_BYTES];
            }
            COMPRESS_BLOCK => {
                if block.reference != 0 {
                    let reference = TEMPLATES
                        .iter()
                        .find(|t| t[field::TEMPLATE_VERSION] == block.reference)
                        .ok_or(BringUpError::BadVersion)?;
                    *image = **reference;
                    board = [false; AR9300_EEPROM_BYTES];
                    template = block.reference;
                }
                uncompress(&mut image, &mut board, data)?;
            }
            _ => return Err(BringUpError::BadVersion),
        }
        blocks += 1;
        cptr = cptr.checked_sub(total).ok_or(BringUpError::BadLength)?;
    }
    if blocks == 0 {
        return Err(BringUpError::BadCalibration);
    }
    let mac = field::MAC_ADDR..field::MAC_ADDR + 6;
    if !board[mac].iter().all(|&written| written) || image[field::TEMPLATE_VERSION] != template {
        return Err(BringUpError::BadIdentity);
    }
    Ok(Restored {
        image,
        store,
        base,
        blocks,
        template,
    })
}

/// `ar9300_uncompress_block`: `(offset, length, bytes...)` runs, `offset`
/// relative to the end of the previous run. A run that leaves the block or
/// the map is refused (Linux would read past the block or stop silently).
fn uncompress(
    image: &mut [u8; AR9300_EEPROM_BYTES],
    board: &mut [bool; AR9300_EEPROM_BYTES],
    block: &[u8],
) -> Result<(), BringUpError> {
    let mut spot = 0usize;
    let mut it = 0usize;
    while it < block.len() {
        let length = *block.get(it + 1).ok_or(BringUpError::BadLength)? as usize;
        spot += block[it] as usize;
        if length > 0 {
            let run = block
                .get(it + 2..it + 2 + length)
                .ok_or(BringUpError::BadLength)?;
            if spot + length > AR9300_EEPROM_BYTES {
                return Err(BringUpError::BadLength);
            }
            image[spot..spot + length].copy_from_slice(run);
            board[spot..spot + length].fill(true);
            spot += length;
        }
        it += length + 2;
    }
    Ok(())
}

/// The identity facts of a restored map (`ath9k_hw_ar9300_get_eeprom`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Identity {
    pub mac: [u8; 6],
    pub eeprom_version: u8,
    pub template_version: u8,
    /// `EEP_REG_0`, `regDmn[1]`.
    pub regulatory_domains: [u16; 2],
    /// `EEP_OP_MODE`: `AR5416_OPFLAGS_11A` 0x01, `_11G` 0x02.
    pub op_flags: u8,
    /// `ath9k_hw_fill_cap_info`: EEPROM masks within `chip_chainmask`.
    pub rx_chainmask: u8,
    pub tx_chainmask: u8,
    /// `ar9003_hw_get_tx_gain_idx` / `ar9003_hw_get_rx_gain_idx`.
    pub tx_gain: u8,
    pub rx_gain: u8,
}

impl Identity {
    /// MAC: `ath9k_hw_init_macaddr` would fall back to a random address
    /// for an invalid one — refused. Chain masks: `EEP_RX_MASK`/`EEP_TX_MASK`
    /// nibbles; `fixup_chainmask` would replace an empty or foreign mask by
    /// the chip's — refused. At least one band must be enabled.
    pub fn decode(chip: Chip, restored: &Restored) -> Result<Self, BringUpError> {
        let image = &restored.image;
        let mut mac = [0; 6];
        mac.copy_from_slice(&image[field::MAC_ADDR..field::MAC_ADDR + 6]);
        let rx = image[field::TXRX_MASK] & 0xf;
        let tx = image[field::TXRX_MASK] >> 4;
        let chip_mask = chip.chip_chainmask();
        let op_flags = image[field::OP_FLAGS];
        if mac == [0; 6]
            || mac[0] & 1 != 0
            || rx == 0
            || tx == 0
            || rx & !chip_mask != 0
            || tx & !chip_mask != 0
            || op_flags & 0x3 == 0
        {
            return Err(BringUpError::BadIdentity);
        }
        let word = |at: usize| u16::from_le_bytes([image[at], image[at + 1]]);
        Ok(Self {
            mac,
            eeprom_version: image[field::EEPROM_VERSION],
            template_version: image[field::TEMPLATE_VERSION],
            regulatory_domains: [word(field::REG_DMN), word(field::REG_DMN + 2)],
            op_flags,
            rx_chainmask: rx,
            tx_chainmask: tx,
            tx_gain: image[field::TXRX_GAIN] >> 4,
            rx_gain: image[field::TXRX_GAIN] & 0xf,
        })
    }
}

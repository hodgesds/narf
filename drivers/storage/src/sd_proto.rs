//! SD card response and register decoders (clean-room).
//!
//! References (public-only):
//! - SD Physical Layer Simplified Specification v8.00 (SD Association,
//!   free PDF on sdcard.org). §4.9 R1/R3/R6/R7 response formats.
//!   §5.1 OCR layout. §5.2 CID layout. §5.3 CSD v1.0 + v2.0 layouts.
//! - SD Host Controller Simplified Specification v3.00 — referenced
//!   only for response register layout (response shifted right by 8
//!   bits; the CRC7 + end bit are dropped by hardware).
//!
//! No GPL Linux source consulted.
//!
//! These are pure decoders. The SDHCI driver hands the raw response
//! u32 (or [u32;4] for R2) to functions here.

/// OCR bit 31 — card power-up status (1 = init complete).
pub const OCR_BUSY: u32 = 1 << 31;
/// OCR bit 30 — Card Capacity Status. 1 = SDHC/SDXC, 0 = SDSC.
pub const OCR_CCS: u32 = 1 << 30;
/// OCR voltage window 3.2..3.3 V (bit 20).
pub const OCR_3V3: u32 = 1 << 20;

/// Decoded R1 / R1b status word (§4.9.1).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct R1Status {
    pub raw: u32,
}

impl R1Status {
    pub const ERR_OUT_OF_RANGE: u32 = 1 << 31;
    pub const ERR_ADDRESS: u32 = 1 << 30;
    pub const ERR_BLOCK_LEN: u32 = 1 << 29;
    pub const ERR_ERASE_SEQ: u32 = 1 << 28;
    pub const ERR_ERASE_PARAM: u32 = 1 << 27;
    pub const ERR_WP_VIOLATION: u32 = 1 << 26;
    pub const CARD_IS_LOCKED: u32 = 1 << 25;
    pub const ERR_LOCK_UNLOCK: u32 = 1 << 24;
    pub const ERR_COM_CRC: u32 = 1 << 23;
    pub const ERR_ILLEGAL_CMD: u32 = 1 << 22;
    pub const ERR_CARD_ECC_FAIL: u32 = 1 << 21;
    pub const ERR_CARD_CTRL: u32 = 1 << 20;
    pub const APP_CMD: u32 = 1 << 5;

    /// Bit-mask covering all R1 error bits per §4.10.1.
    pub const ERROR_MASK: u32 = Self::ERR_OUT_OF_RANGE
        | Self::ERR_ADDRESS
        | Self::ERR_BLOCK_LEN
        | Self::ERR_ERASE_SEQ
        | Self::ERR_ERASE_PARAM
        | Self::ERR_WP_VIOLATION
        | Self::ERR_LOCK_UNLOCK
        | Self::ERR_COM_CRC
        | Self::ERR_ILLEGAL_CMD
        | Self::ERR_CARD_ECC_FAIL
        | Self::ERR_CARD_CTRL;

    /// Card-state field — bits [12..9].
    pub const fn current_state(self) -> u8 {
        ((self.raw >> 9) & 0x0F) as u8
    }

    pub const fn ready_for_data(self) -> bool {
        (self.raw & (1 << 8)) != 0
    }

    pub const fn has_error(self) -> bool {
        (self.raw & Self::ERROR_MASK) != 0
    }
}

/// Decoded R6 response from CMD3 (§4.9.5). The high 16 bits are the
/// negotiated RCA; the low 16 bits are a packed status word that maps
/// onto a subset of R1 bits.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct R6 {
    pub rca: u16,
    pub status: u16,
}

impl R6 {
    pub fn parse(r: u32) -> Self {
        Self {
            rca: (r >> 16) as u16,
            status: r as u16,
        }
    }
}

/// Decoded R7 response from CMD8 (§4.9.6). The check pattern in the
/// low byte must match what we sent (typically 0xAA).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct R7 {
    /// Voltage-accepted nibble (bits 11..8). 0x1 means 2.7..3.6 V.
    pub voltage: u8,
    pub check_pattern: u8,
}

impl R7 {
    pub fn parse(r: u32) -> Self {
        Self {
            voltage: ((r >> 8) & 0x0F) as u8,
            check_pattern: r as u8,
        }
    }

    pub fn matches_check(self, sent: u8) -> bool {
        self.check_pattern == sent
    }
}

/// Decoded CID register (§5.2). 16 bytes, but most controllers
/// hand back 4 × u32 with the CRC7 + end bit dropped, so we treat
/// the 128 logical bits as `[u32;4]` in big-endian word order:
/// `r[3]` = MSW (manufacturer ID), `r[0]` = LSW (manufacture date).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cid {
    pub manufacturer_id: u8,
    pub oem_id: [u8; 2],
    pub product_name: [u8; 5],
    pub product_revision: u8,
    pub product_serial: u32,
    /// Manufacture month + year (year offset from 2000 per §5.2.10).
    pub manufacture_month: u8,
    pub manufacture_year: u16,
}

impl Cid {
    /// Parse a CID hand-off in the controller-shifted layout the
    /// SDHCI returns (`r[3]` is the MSW, `r[0]` is the LSW; the
    /// CRC7 + end bit have been stripped by hardware).
    pub fn parse_shifted(r: &[u32; 4]) -> Self {
        // Reconstruct 16 bytes (big-endian — bit 127 first).
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&r[3].to_be_bytes());
        bytes[4..8].copy_from_slice(&r[2].to_be_bytes());
        bytes[8..12].copy_from_slice(&r[1].to_be_bytes());
        bytes[12..16].copy_from_slice(&r[0].to_be_bytes());

        // After hardware strips CRC7+end bit, the remaining 120 bits
        // are right-aligned in a 128-bit field (bits 127..8). The
        // Linux/SDHCI convention is to access the 120-bit logical CID
        // through `bytes[1..16]`, treating `bytes[0]` as zero.
        // Manufacturer ID lives at logical bits 127..120 → byte 0 of
        // the 15-byte field after the strip, which lands at byte 1
        // of our 16-byte buffer.
        let cid = &bytes[1..16];

        let manufacturer_id = cid[0];
        let oem_id = [cid[1], cid[2]];
        let mut product_name = [0u8; 5];
        product_name.copy_from_slice(&cid[3..8]);
        let product_revision = cid[8];
        let product_serial = u32::from_be_bytes([cid[9], cid[10], cid[11], cid[12]]);
        // bytes 13..14 hold MDT (year:8 | month:4) in the top 12 bits.
        let mdt = u16::from_be_bytes([cid[13], cid[14]]);
        let year_offset = ((mdt >> 4) & 0xFF) as u16;
        let manufacture_month = (mdt & 0x0F) as u8;
        let manufacture_year = 2000 + year_offset;

        Self {
            manufacturer_id,
            oem_id,
            product_name,
            product_revision,
            product_serial,
            manufacture_month,
            manufacture_year,
        }
    }
}

/// Decoded CSD register (§5.3). The structure version selects the
/// capacity formula. We surface only the fields a driver needs:
/// capacity in bytes + read/write block lengths.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Csd {
    /// `0` = CSD v1.0 (SDSC), `1` = CSD v2.0 (SDHC/SDXC).
    pub structure_version: u8,
    pub capacity_bytes: u64,
    pub read_block_len: u32,
    pub write_block_len: u32,
}

impl Csd {
    pub fn parse_shifted(r: &[u32; 4]) -> Option<Self> {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&r[3].to_be_bytes());
        bytes[4..8].copy_from_slice(&r[2].to_be_bytes());
        bytes[8..12].copy_from_slice(&r[1].to_be_bytes());
        bytes[12..16].copy_from_slice(&r[0].to_be_bytes());
        // After strip: 120 logical bits at `bytes[1..16]`.
        let csd = &bytes[1..16];

        // CSD_STRUCTURE = top 2 bits of logical byte 0.
        let structure = (csd[0] >> 6) & 0x03;

        match structure {
            0 => {
                // CSD v1.0 (§5.3.2).
                // READ_BL_LEN at logical bits 83..80 → low nibble of byte 5.
                let read_bl_len = (csd[5] & 0x0F) as u32;
                // C_SIZE: 12 bits at bits 73..62 → spans byte 6 lo 2 + byte 7 + byte 8 hi 2.
                let c_size = (((csd[6] as u32) & 0x03) << 10)
                    | ((csd[7] as u32) << 2)
                    | (((csd[8] as u32) & 0xC0) >> 6);
                // C_SIZE_MULT: 3 bits at 49..47 → low 2 of byte 9 + top 1 of byte 10.
                let c_size_mult = (((csd[9] as u32) & 0x03) << 1) | (((csd[10] as u32) >> 7) & 1);
                // capacity = (C_SIZE+1) × 2^(C_SIZE_MULT+2) × 2^READ_BL_LEN
                let mult = 1u64 << (c_size_mult + 2);
                let block_len = 1u64 << read_bl_len;
                let capacity_bytes = (c_size as u64 + 1) * mult * block_len;
                let write_bl_len = (((csd[12] as u32) & 0x03) << 2) | (((csd[13] as u32) >> 6) & 3);
                Some(Self {
                    structure_version: 0,
                    capacity_bytes,
                    read_block_len: 1u32 << read_bl_len,
                    write_block_len: 1u32 << write_bl_len,
                })
            }
            1 => {
                // CSD v2.0 (§5.3.3) — fixed READ/WRITE BLEN = 512.
                // C_SIZE: 22 bits at 69..48 → byte 7 low 6 | byte 8 | byte 9.
                let c_size = (((csd[7] as u32) & 0x3F) << 16)
                    | ((csd[8] as u32) << 8)
                    | (csd[9] as u32);
                // capacity = (C_SIZE + 1) × 512 KiB.
                let capacity_bytes = (c_size as u64 + 1) * 512 * 1024;
                Some(Self {
                    structure_version: 1,
                    capacity_bytes,
                    read_block_len: 512,
                    write_block_len: 512,
                })
            }
            _ => None,
        }
    }
}

//! JEDEC Serial Presence Detect (SPD5) decoder for DDR5 — clean-room.
//!
//! References (public-only):
//! - "JEDEC Standard JESD400-5 — DDR5 SPD Annex L (SPD5 Hub Device
//!   and SPD5 Memory Module Specifications)". JEDEC. Public.
//!   §1.2.3 (1024-byte EEPROM map for DDR5 UDIMM/RDIMM/SODIMM).
//!   §1.4 (manufacturer ID encoding — JEP-106 bank + ID bytes).
//!   §1.5 (timing field encodings — fields are stored in picoseconds
//!   as 16-bit little-endian values, with a 1 ps unit).
//! - "JEDEC Standard JEP106BJ — Standard Manufacturer's
//!   Identification Code". Public document; the bank+ID byte
//!   convention used at offsets 512..513.
//! - "JEDEC Standard JESD235 / JESD79-5B — DDR5 SDRAM core spec".
//!   Public. Defines the timing parameters whose minimum values
//!   appear in the SPD5 region (tCKAVGmin, tAAmin, tRCDmin, tRPmin,
//!   tRCmin, tRFC1min, tRFC2min, tRFCsbmin, tRRD_Lmin, tCCD_Lmin).
//!
//! No GPL Linux source consulted.
//!
//! ## SPD5 EEPROM map (JESD400-5 Table 5)
//!
//! 1024 bytes split into 64-byte blocks, addressed via the SPD5 Hub
//! page-select register. Decoded byte offsets used here:
//!
//! ```text
//!   0      bytes_used         (low 4 bits) | bytes_total (high 4 bits)
//!   1      spd_revision       (low 4 bits = minor; high 4 = major)
//!   2      key_byte / dram_type (0x12 = DDR5, 0x13 = LPDDR5)
//!   3      module_type
//!   4..5   sdram density + package
//!   6..7   sdram addressing (rows, cols, bank addr, bank groups)
//!   16..17 tCKAVGmin (1 ps units)
//!   18..19 tCKAVGmax
//!   20..21 tAAmin    (1 ps units)
//!   22..23 tRCDmin
//!   24..25 tRPmin
//!   26..27 tRCmin
//!   28..29 tRFC1min  (1 ns units)
//!   30..31 tRFC2min
//!   32..33 tRFCsbmin
//!   …
//!   194..199 module-serial number
//!   200..203 module-revision
//!   512..513 manufacturer JEP-106 (bank, id)
//!   514..515 manufacturer location code
//!   516..523 module part number ASCII
//!   1022..1023 CRC-16 (CCITT, polynomial 0x1021, over bytes 0..1021)
//! ```

/// Total SPD5 EEPROM size, in bytes.
pub const SPD5_SIZE: usize = 1024;

/// DRAM-type byte values (offset 2).
pub const DRAM_TYPE_DDR5: u8 = 0x12;
pub const DRAM_TYPE_LPDDR5: u8 = 0x13;

/// Module-type byte values (offset 3).
pub const MODULE_TYPE_RDIMM: u8 = 0x01;
pub const MODULE_TYPE_UDIMM: u8 = 0x02;
pub const MODULE_TYPE_SODIMM: u8 = 0x03;
pub const MODULE_TYPE_LRDIMM: u8 = 0x04;
pub const MODULE_TYPE_CUDIMM: u8 = 0x0A;
pub const MODULE_TYPE_CSODIMM: u8 = 0x0B;
pub const MODULE_TYPE_MRDIMM: u8 = 0x07;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Spd5Error {
    /// Buffer must be exactly 1024 bytes.
    BadLength,
    /// CRC-16 over bytes 0..1021 doesn't match the trailing 2 bytes.
    BadCrc,
    /// `dram_type` (offset 2) is not DDR5/LPDDR5.
    BadDramType(u8),
}

/// CRC-16/CCITT (also known as CRC-16/XMODEM): poly 0x1021, init 0,
/// no output XOR. JESD400-5 Annex C specifies this for the SPD5
/// trailer.
pub fn crc16_ccitt(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for byte in bytes {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Decoded subset of an SPD5 EEPROM image.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Spd5 {
    pub bytes_used: u8,
    pub bytes_total: u8,
    pub spd_revision_major: u8,
    pub spd_revision_minor: u8,
    pub dram_type: u8,
    pub module_type: u8,
    /// Manufacturer JEP-106 bank (offset 512), counts the number of
    /// `0x7F` continuation bytes preceding the ID byte. Combined with
    /// `manufacturer_id` it uniquely identifies the vendor.
    pub manufacturer_bank: u8,
    pub manufacturer_id: u8,
    /// Module part-number ASCII (offsets 516..524).
    pub module_part_number: [u8; 8],
    /// Picosecond timing minimums (1 ps units).
    pub tckavg_min_ps: u16,
    pub tckavg_max_ps: u16,
    pub taa_min_ps: u16,
    pub trcd_min_ps: u16,
    pub trp_min_ps: u16,
    pub trc_min_ps: u16,
    /// Refresh interval minimums (1 ns units, 16-bit LE).
    pub trfc1_min_ns: u16,
    pub trfc2_min_ns: u16,
    pub trfcsb_min_ns: u16,
}

impl Spd5 {
    pub fn parse(buf: &[u8]) -> Result<Self, Spd5Error> {
        if buf.len() != SPD5_SIZE {
            return Err(Spd5Error::BadLength);
        }

        let want_crc = u16::from_le_bytes([buf[1022], buf[1023]]);
        let calc_crc = crc16_ccitt(&buf[..1022]);
        if want_crc != calc_crc {
            return Err(Spd5Error::BadCrc);
        }

        let dram_type = buf[2];
        if dram_type != DRAM_TYPE_DDR5 && dram_type != DRAM_TYPE_LPDDR5 {
            return Err(Spd5Error::BadDramType(dram_type));
        }

        let mut module_part_number = [0u8; 8];
        module_part_number.copy_from_slice(&buf[516..524]);

        Ok(Self {
            bytes_used: buf[0] & 0x0F,
            bytes_total: (buf[0] >> 4) & 0x0F,
            spd_revision_minor: buf[1] & 0x0F,
            spd_revision_major: (buf[1] >> 4) & 0x0F,
            dram_type,
            module_type: buf[3],
            manufacturer_bank: buf[512],
            manufacturer_id: buf[513],
            module_part_number,
            tckavg_min_ps: u16::from_le_bytes([buf[16], buf[17]]),
            tckavg_max_ps: u16::from_le_bytes([buf[18], buf[19]]),
            taa_min_ps: u16::from_le_bytes([buf[20], buf[21]]),
            trcd_min_ps: u16::from_le_bytes([buf[22], buf[23]]),
            trp_min_ps: u16::from_le_bytes([buf[24], buf[25]]),
            trc_min_ps: u16::from_le_bytes([buf[26], buf[27]]),
            trfc1_min_ns: u16::from_le_bytes([buf[28], buf[29]]),
            trfc2_min_ns: u16::from_le_bytes([buf[30], buf[31]]),
            trfcsb_min_ns: u16::from_le_bytes([buf[32], buf[33]]),
        })
    }

    /// Returns the data-rate in MT/s implied by `tCKAVGmin`. For
    /// example a tCKAVGmin of 625 ps (DDR5-3200) yields 3200 MT/s.
    pub fn data_rate_mt_per_s(&self) -> u32 {
        if self.tckavg_min_ps == 0 {
            return 0;
        }
        // 1 / (tck_ps × 1e-12) × 2 (DDR) Hz = 2e12 / tck_ps Hz
        // → in MT/s: 2_000_000 / tck_ps.
        2_000_000 / (self.tckavg_min_ps as u32)
    }

    /// Module part number with ASCII whitespace trimmed.
    pub fn module_part_number_str(&self) -> &str {
        let len = self
            .module_part_number
            .iter()
            .position(|b| *b == 0 || *b == 0x20)
            .unwrap_or(self.module_part_number.len());
        core::str::from_utf8(&self.module_part_number[..len]).unwrap_or("")
    }
}

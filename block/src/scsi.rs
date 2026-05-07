//! T10 SCSI codec — clean-room.
//!
//! References (public-only):
//! - "INCITS T10 SCSI Block Commands - 3 (SBC-3), Revision 36" —
//!   T10 working group. Public document. §5.10 READ(10), §5.30
//!   WRITE(10), §5.16 READ CAPACITY(10).
//! - "INCITS T10 SCSI Primary Commands - 4 (SPC-4), Revision 37" —
//!   T10 working group. Public. §6.5 INQUIRY (standard 36-byte
//!   response: device-type byte + RMB flag + version + response-
//!   data-format + additional-length + 8-byte vendor + 16-byte
//!   product + 4-byte revision). §4.5 (Sense Data, both fixed and
//!   descriptor format — sense key / additional sense code /
//!   ASCQ).
//! - "INCITS T10 SCSI Architecture Model - 5 (SAM-5)" — public.
//!   Status byte values (§5.3.1 table 9: GOOD = 0x00, CHECK
//!   CONDITION = 0x02, BUSY = 0x08, …).
//!
//! No GPL Linux source consulted.

use alloc::string::String;

// ── Opcodes (SBC-3 + SPC-4) ────────────────────────────────────────

pub const OP_TEST_UNIT_READY: u8 = 0x00;
pub const OP_REQUEST_SENSE: u8 = 0x03;
pub const OP_INQUIRY: u8 = 0x12;
pub const OP_MODE_SENSE_6: u8 = 0x1A;
pub const OP_START_STOP_UNIT: u8 = 0x1B;
pub const OP_READ_CAPACITY_10: u8 = 0x25;
pub const OP_READ_10: u8 = 0x28;
pub const OP_WRITE_10: u8 = 0x2A;
pub const OP_SYNC_CACHE_10: u8 = 0x35;
pub const OP_READ_CAPACITY_16: u8 = 0x9E;
pub const OP_REPORT_LUNS: u8 = 0xA0;

// ── Status byte values (SAM-5 table 9) ─────────────────────────────

pub const STATUS_GOOD: u8 = 0x00;
pub const STATUS_CHECK_CONDITION: u8 = 0x02;
pub const STATUS_CONDITION_MET: u8 = 0x04;
pub const STATUS_BUSY: u8 = 0x08;
pub const STATUS_RESERVATION_CONFLICT: u8 = 0x18;
pub const STATUS_TASK_SET_FULL: u8 = 0x28;
pub const STATUS_ACA_ACTIVE: u8 = 0x30;
pub const STATUS_TASK_ABORTED: u8 = 0x40;

// ── Sense keys (SPC-4 §4.5.6, table 50) ───────────────────────────

pub const SENSE_KEY_NO_SENSE: u8 = 0x0;
pub const SENSE_KEY_RECOVERED_ERROR: u8 = 0x1;
pub const SENSE_KEY_NOT_READY: u8 = 0x2;
pub const SENSE_KEY_MEDIUM_ERROR: u8 = 0x3;
pub const SENSE_KEY_HARDWARE_ERROR: u8 = 0x4;
pub const SENSE_KEY_ILLEGAL_REQUEST: u8 = 0x5;
pub const SENSE_KEY_UNIT_ATTENTION: u8 = 0x6;
pub const SENSE_KEY_DATA_PROTECT: u8 = 0x7;
pub const SENSE_KEY_BLANK_CHECK: u8 = 0x8;
pub const SENSE_KEY_VENDOR_SPECIFIC: u8 = 0x9;
pub const SENSE_KEY_COPY_ABORTED: u8 = 0xA;
pub const SENSE_KEY_ABORTED_COMMAND: u8 = 0xB;
pub const SENSE_KEY_VOLUME_OVERFLOW: u8 = 0xD;
pub const SENSE_KEY_MISCOMPARE: u8 = 0xE;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ScsiError {
    Short,
    Truncated,
}

// ── Command-Block builders ─────────────────────────────────────────

/// 6-byte INQUIRY CDB (SPC-4 §6.5.1). `evpd` selects vital product
/// data (when 1, `page_code` selects the VPD page).
pub fn inquiry(evpd: bool, page_code: u8, alloc_length: u16) -> [u8; 6] {
    [
        OP_INQUIRY,
        if evpd { 1 } else { 0 },
        page_code,
        (alloc_length >> 8) as u8,
        (alloc_length & 0xFF) as u8,
        0,
    ]
}

/// 10-byte READ CAPACITY(10) CDB (SBC-3 §5.16). Returns 8 bytes of
/// data: 4-byte LBA of the last block + 4-byte block size, big-endian.
pub fn read_capacity_10() -> [u8; 10] {
    [OP_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// 16-byte READ CAPACITY(16) CDB (SBC-3 §5.16.2). 32-byte response:
/// 8-byte LBA + 4-byte block size + protection type bits.
pub fn read_capacity_16(alloc_length: u32) -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = OP_READ_CAPACITY_16;
    cdb[1] = 0x10; // Service Action = 0x10
    cdb[10..14].copy_from_slice(&alloc_length.to_be_bytes());
    cdb
}

/// 10-byte READ(10) CDB (SBC-3 §5.10).
pub fn read_10(lba: u32, transfer_length: u16, fua: bool) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = OP_READ_10;
    if fua {
        cdb[1] |= 1 << 3;
    }
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[7..9].copy_from_slice(&transfer_length.to_be_bytes());
    cdb
}

/// 10-byte WRITE(10) CDB (SBC-3 §5.30).
pub fn write_10(lba: u32, transfer_length: u16, fua: bool) -> [u8; 10] {
    let mut cdb = read_10(lba, transfer_length, fua);
    cdb[0] = OP_WRITE_10;
    cdb
}

/// 6-byte REQUEST SENSE CDB (SPC-4 §6.27). `desc` selects descriptor-
/// format sense data (DESC=1) vs fixed-format (DESC=0).
pub fn request_sense(desc: bool, alloc_length: u8) -> [u8; 6] {
    [
        OP_REQUEST_SENSE,
        if desc { 1 } else { 0 },
        0,
        0,
        alloc_length,
        0,
    ]
}

// ── INQUIRY response decoder (SPC-4 §6.5.2, table 142) ────────────

/// Standard INQUIRY data (first 36 bytes).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InquiryData {
    pub peripheral_qualifier: u8,
    pub peripheral_device_type: u8,
    pub removable_medium: bool,
    pub spc_version: u8,
    pub response_data_format: u8,
    pub additional_length: u8,
    pub vendor_id: String,
    pub product_id: String,
    pub product_revision: String,
}

/// Peripheral device type codes (SPC-4 §6.5.2, table 143).
pub const PDT_DIRECT_ACCESS_BLOCK: u8 = 0x00;
pub const PDT_SEQUENTIAL_ACCESS: u8 = 0x01;
pub const PDT_PRINTER: u8 = 0x02;
pub const PDT_PROCESSOR: u8 = 0x03;
pub const PDT_WRITE_ONCE: u8 = 0x04;
pub const PDT_CD_DVD: u8 = 0x05;
pub const PDT_OPTICAL_MEMORY: u8 = 0x07;
pub const PDT_MEDIUM_CHANGER: u8 = 0x08;
pub const PDT_STORAGE_ARRAY: u8 = 0x0C;
pub const PDT_ENCLOSURE_SERVICES: u8 = 0x0D;
pub const PDT_SIMPLIFIED_DIRECT_ACCESS: u8 = 0x0E;

impl InquiryData {
    pub fn parse(buf: &[u8]) -> Result<Self, ScsiError> {
        if buf.len() < 36 {
            return Err(ScsiError::Short);
        }
        let vendor_id = trim_padded(&buf[8..16]);
        let product_id = trim_padded(&buf[16..32]);
        let product_revision = trim_padded(&buf[32..36]);
        Ok(Self {
            peripheral_qualifier: (buf[0] >> 5) & 0x07,
            peripheral_device_type: buf[0] & 0x1F,
            removable_medium: (buf[1] & 0x80) != 0,
            spc_version: buf[2],
            response_data_format: buf[3] & 0x0F,
            additional_length: buf[4],
            vendor_id,
            product_id,
            product_revision,
        })
    }
}

fn trim_padded(buf: &[u8]) -> String {
    let mut s = String::new();
    for b in buf {
        s.push(*b as char);
    }
    while s.ends_with(' ') {
        s.pop();
    }
    s
}

// ── READ CAPACITY(10) decoder ──────────────────────────────────────

/// Decoded (last_lba, block_size). `block_count = last_lba + 1`.
pub fn parse_read_capacity_10(buf: &[u8]) -> Result<(u32, u32), ScsiError> {
    if buf.len() < 8 {
        return Err(ScsiError::Short);
    }
    let last_lba = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let block_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    Ok((last_lba, block_size))
}

/// Decoded READ CAPACITY(16) (last_lba, block_size, protection_type).
pub fn parse_read_capacity_16(buf: &[u8]) -> Result<(u64, u32, u8), ScsiError> {
    if buf.len() < 14 {
        return Err(ScsiError::Short);
    }
    let last_lba = u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let block_size = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let prot_type = (buf[12] >> 1) & 0x07;
    Ok((last_lba, block_size, prot_type))
}

// ── Sense data (SPC-4 §4.5.3, fixed format table 27) ──────────────

/// Fixed-format sense data (first 18 bytes).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FixedSense {
    /// Bit 7 = Valid (information bytes are valid).
    pub response_code: u8,
    pub sense_key: u8,
    pub information: u32,
    pub additional_sense_code: u8,
    pub additional_sense_code_qualifier: u8,
}

impl FixedSense {
    /// Top bit of byte 0 is the Valid flag.
    pub const RESPONSE_CODE_CURRENT: u8 = 0x70;
    pub const RESPONSE_CODE_DEFERRED: u8 = 0x71;

    pub fn parse(buf: &[u8]) -> Result<Self, ScsiError> {
        if buf.len() < 14 {
            return Err(ScsiError::Short);
        }
        Ok(Self {
            response_code: buf[0] & 0x7F,
            sense_key: buf[2] & 0x0F,
            information: u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]),
            additional_sense_code: buf[12],
            additional_sense_code_qualifier: buf[13],
        })
    }

    pub fn valid(&self, raw_byte_0: u8) -> bool {
        (raw_byte_0 & 0x80) != 0
    }
}

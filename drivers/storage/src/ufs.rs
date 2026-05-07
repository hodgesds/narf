//! UFS / UFSHCI 3.0 — clean-room.
//!
//! ## Sources (public only)
//!
//! - **JEDEC Standard JESD223D — Universal Flash Storage Host
//!   Controller Interface (UFSHCI)**, Version 3.0, January 2018.
//!   Public via JEDEC member portal; mirrored summary at
//!   <https://www.jedec.org/standards-documents/docs/jesd223d>.
//! - **JEDEC Standard JESD220D — Universal Flash Storage (UFS)**,
//!   Version 3.1, March 2020. Public.
//!   <https://www.jedec.org/standards-documents/docs/jesd220d>.
//!
//! No GPL / Linux source consulted.
//!
//! ## What this module is
//!
//! Register layout + transfer-descriptor + UPIU codecs for the
//! UFSHCI 3.0 host controller. Live MMIO bring-up + DMA submission
//! lands on top of these wire-format codecs once the platform glue
//! (clock control + LVDS PHY init) is wired; this codec layer is
//! the bytes-on-the-wire half.
//!
//! Memory model:
//!
//! - **UFSHCI Registers** at the start of the MMIO BAR.
//! - **UTP Transfer Request List** (UTRD entries, 32 bytes each) —
//!   the host programs `UTRLBA`/`UTRLBAU` with the physical address
//!   and rings the doorbell `UTRLDBR`.
//! - **UTP Task Management Request List** (UTMRD entries, similar).
//! - **PRDT (Physical Region Descriptor Table)** — DMA scatter-gather.

extern crate alloc;
use alloc::vec::Vec;

// ── UFSHCI 3.0 Register offsets (§5.2) ────────────────────────────

pub mod regs {
    /// Host Capabilities (§5.2.1).
    pub const CAP: usize = 0x00;
    /// Reserved 0x04..0x07.
    pub const VER: usize = 0x08;
    pub const HCDDID: usize = 0x10;
    pub const HCPMID: usize = 0x14;
    pub const AHIT: usize = 0x18;
    /// Interrupt Status (W1C).
    pub const IS: usize = 0x20;
    pub const IE: usize = 0x24;
    /// Host Controller Status.
    pub const HCS: usize = 0x30;
    /// Host Controller Enable (1 bit).
    pub const HCE: usize = 0x34;
    pub const UECPA: usize = 0x38;
    pub const UECDL: usize = 0x3C;
    pub const UECN: usize = 0x40;
    pub const UECT: usize = 0x44;
    pub const UECDME: usize = 0x48;
    pub const UTRIACR: usize = 0x4C;
    /// UTP Transfer Request List Base Address (low 32).
    pub const UTRLBA: usize = 0x50;
    /// UTP Transfer Request List Base Address (high 32).
    pub const UTRLBAU: usize = 0x54;
    pub const UTRLDBR: usize = 0x58; // Doorbell
    pub const UTRLCLR: usize = 0x5C;
    pub const UTRLRSR: usize = 0x60;
    pub const UTRLCNR: usize = 0x64;
    /// UTP Task Management Request List.
    pub const UTMRLBA: usize = 0x70;
    pub const UTMRLBAU: usize = 0x74;
    pub const UTMRLDBR: usize = 0x78;
    pub const UTMRLCLR: usize = 0x7C;
    pub const UTMRLRSR: usize = 0x80;
    /// UIC commands (§5.6).
    pub const UICCMDARG1: usize = 0x90;
    pub const UICCMDARG2: usize = 0x94;
    pub const UICCMDARG3: usize = 0x98;
    pub const UICCMD: usize = 0x9C;
}

/// HCS bits (§5.2.6).
pub mod hcs {
    pub const DEVICE_PRESENT: u32 = 1 << 0;
    pub const UTRLRDY: u32 = 1 << 1; // UTP Transfer Request List Ready
    pub const UTMRLRDY: u32 = 1 << 2; // UTP Task Management Request List Ready
    pub const UCRDY: u32 = 1 << 3; // UIC Command Ready
}

/// IS bits (§5.2.4) — all W1C.
pub mod is {
    pub const UTP_TRANSFER_REQ_COMPL: u32 = 1 << 0;
    pub const UIC_DME_END_PT_RESET: u32 = 1 << 1;
    pub const UIC_ERROR: u32 = 1 << 2;
    pub const UIC_TEST_MODE: u32 = 1 << 3;
    pub const UIC_POWER_MODE: u32 = 1 << 4;
    pub const UIC_HIBERNATE_EXIT: u32 = 1 << 5;
    pub const UIC_HIBERNATE_ENTER: u32 = 1 << 6;
    pub const UIC_LINK_LOST: u32 = 1 << 7;
    pub const UIC_LINK_STARTUP: u32 = 1 << 8;
    pub const UTP_TASK_REQ_COMPL: u32 = 1 << 9;
    pub const UIC_COMMAND_COMPL: u32 = 1 << 10;
    pub const DEVICE_FATAL_ERROR: u32 = 1 << 11;
    pub const CONTROLLER_FATAL_ERROR: u32 = 1 << 16;
    pub const SYSTEM_BUS_FATAL_ERROR: u32 = 1 << 17;
}

// ── UTP Transfer Request Descriptor (§6.1) ───────────────────────

/// Command Type (UTRD dword 0, bits[31:28]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandType {
    /// SCSI command via UFS UPIU.
    Scsi = 0x0,
    /// Native UFS Command Set.
    UfsNative = 0x1,
    /// Vendor-specific.
    Vendor = 0xF,
}

/// Data Direction bits (UTRD dword 0, bits[26:25]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DataDir {
    NoData = 0b00,
    HostToDevice = 0b01,
    DeviceToHost = 0b10,
}

/// Overall Command Status (§6.1.7) — UTRD dword 2 byte 0.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OcsStatus {
    Success = 0x0,
    InvalidCmdTableAttribute = 0x1,
    InvalidPrdtAttribute = 0x2,
    MismatchDataBufferSize = 0x3,
    MismatchResponseUpiuSize = 0x4,
    PeerCommunicationFailure = 0x5,
    Aborted = 0x6,
    HostControllerFatalError = 0x7,
    /// Used by tests for "unset".
    Invalid = 0xF,
}

impl OcsStatus {
    pub fn from_byte(b: u8) -> Self {
        match b & 0x0F {
            0 => Self::Success,
            1 => Self::InvalidCmdTableAttribute,
            2 => Self::InvalidPrdtAttribute,
            3 => Self::MismatchDataBufferSize,
            4 => Self::MismatchResponseUpiuSize,
            5 => Self::PeerCommunicationFailure,
            6 => Self::Aborted,
            7 => Self::HostControllerFatalError,
            _ => Self::Invalid,
        }
    }
}

/// 32-byte UTP Transfer Request Descriptor (§6.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Utrd {
    pub command_type: CommandType,
    pub data_dir: DataDir,
    /// Interrupt-aggregation control bit (bit 24 of dword 0).
    pub interrupt: bool,
    /// Crypto-enabled bit (bit 23) — UFS 2.1+. We carry but don't
    /// validate.
    pub crypto: bool,
    /// CCI (Crypto Configuration Index, bits[7:0] of dword 1) —
    /// when crypto is enabled.
    pub cci: u8,
    /// Overall Command Status (low byte of dword 2).
    pub ocs: OcsStatus,
    /// Command Descriptor Base Address — physical pointer to the
    /// 128-byte UPIU command + response area + PRDT.
    pub ucd_phys: u64,
    /// Response UPIU Offset (bytes) within the Command Descriptor
    /// (dword 6, bits[15:0] in DWords; we store as bytes).
    pub response_offset_bytes: u16,
    /// Response UPIU Length (dword 6, bits[31:16] in DWords; bytes).
    pub response_length_bytes: u16,
    /// PRD Table Offset (dword 7, bits[15:0] in DWords; bytes).
    pub prdt_offset_bytes: u16,
    /// PRD Table Length — number of PRDT entries.
    pub prdt_entry_count: u16,
}

impl Utrd {
    pub fn pack(self) -> [u8; 32] {
        let mut b = [0u8; 32];

        // dword 0
        let mut d0: u32 = 0;
        d0 |= ((self.command_type as u32) & 0xF) << 28;
        d0 |= ((self.data_dir as u32) & 0x3) << 25;
        if self.interrupt {
            d0 |= 1 << 24;
        }
        if self.crypto {
            d0 |= 1 << 23;
        }
        b[0..4].copy_from_slice(&d0.to_le_bytes());

        // dword 1: CCI in bits[7:0].
        let d1 = self.cci as u32;
        b[4..8].copy_from_slice(&d1.to_le_bytes());

        // dword 2: OCS in low byte.
        let d2 = self.ocs as u32 & 0xFF;
        b[8..12].copy_from_slice(&d2.to_le_bytes());

        // dword 3 reserved.
        // dword 4..5: UCD physical address (low/high).
        let lo = (self.ucd_phys & 0xFFFF_FFFF) as u32;
        let hi = (self.ucd_phys >> 32) as u32;
        b[16..20].copy_from_slice(&lo.to_le_bytes());
        b[20..24].copy_from_slice(&hi.to_le_bytes());

        // dword 6: response offset (low 16 bits) + length (high 16),
        // both expressed in 32-bit words on the wire. Round bytes
        // up to dwords.
        let resp_off_dw = (self.response_offset_bytes / 4) as u32;
        let resp_len_dw = (self.response_length_bytes / 4) as u32;
        let d6 = resp_off_dw | (resp_len_dw << 16);
        b[24..28].copy_from_slice(&d6.to_le_bytes());

        // dword 7: PRDT offset (low 16, dwords) + length (high 16,
        // entry count).
        let prdt_off_dw = (self.prdt_offset_bytes / 4) as u32;
        let prdt_len = self.prdt_entry_count as u32;
        let d7 = prdt_off_dw | (prdt_len << 16);
        b[28..32].copy_from_slice(&d7.to_le_bytes());

        b
    }
    pub fn unpack(b: &[u8; 32]) -> Self {
        let d0 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let d1 = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let d2 = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        let d4 = u32::from_le_bytes([b[16], b[17], b[18], b[19]]);
        let d5 = u32::from_le_bytes([b[20], b[21], b[22], b[23]]);
        let d6 = u32::from_le_bytes([b[24], b[25], b[26], b[27]]);
        let d7 = u32::from_le_bytes([b[28], b[29], b[30], b[31]]);
        Self {
            command_type: match (d0 >> 28) & 0xF {
                0 => CommandType::Scsi,
                1 => CommandType::UfsNative,
                _ => CommandType::Vendor,
            },
            data_dir: match (d0 >> 25) & 0x3 {
                0 => DataDir::NoData,
                1 => DataDir::HostToDevice,
                2 => DataDir::DeviceToHost,
                _ => DataDir::NoData,
            },
            interrupt: d0 & (1 << 24) != 0,
            crypto: d0 & (1 << 23) != 0,
            cci: (d1 & 0xFF) as u8,
            ocs: OcsStatus::from_byte(d2 as u8),
            ucd_phys: ((d5 as u64) << 32) | (d4 as u64),
            response_offset_bytes: ((d6 & 0xFFFF) * 4) as u16,
            response_length_bytes: (((d6 >> 16) & 0xFFFF) * 4) as u16,
            prdt_offset_bytes: ((d7 & 0xFFFF) * 4) as u16,
            prdt_entry_count: ((d7 >> 16) & 0xFFFF) as u16,
        }
    }
}

// ── UPIU (UFS Protocol Information Unit) — §10 ──────────────────

/// UPIU Transaction Codes (§10.6).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum UpiuType {
    NopOut = 0x00,
    Command = 0x01,
    DataOut = 0x02,
    TaskManagementRequest = 0x04,
    QueryRequest = 0x16,
    NopIn = 0x20,
    Response = 0x21,
    DataIn = 0x22,
    TaskManagementResponse = 0x24,
    ReadyToTransfer = 0x31,
    QueryResponse = 0x36,
    RejectUpiu = 0x3F,
}

impl UpiuType {
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => Self::NopOut,
            0x01 => Self::Command,
            0x02 => Self::DataOut,
            0x04 => Self::TaskManagementRequest,
            0x16 => Self::QueryRequest,
            0x20 => Self::NopIn,
            0x21 => Self::Response,
            0x22 => Self::DataIn,
            0x24 => Self::TaskManagementResponse,
            0x31 => Self::ReadyToTransfer,
            0x36 => Self::QueryResponse,
            0x3F => Self::RejectUpiu,
            _ => return None,
        })
    }
}

/// 12-byte UPIU header (§10.6.2). Common to every UPIU type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UpiuHeader {
    pub kind: UpiuType,
    /// Flags byte (§10.6.2 byte 1). Meaning depends on `kind`.
    pub flags: u8,
    pub lun: u8,
    /// Task Tag — host-assigned identifier; comes back in the
    /// Response UPIU.
    pub task_tag: u8,
    /// Initiator ID / Command Set Type (byte 4).
    pub iid_cmd_set_type: u8,
    /// Query Function (byte 5).
    pub query_function: u8,
    /// Response (byte 6).
    pub response: u8,
    /// Status (byte 7) — for Response UPIUs, this is the SCSI
    /// status byte (Good / Check Condition / etc.).
    pub status: u8,
    /// Total EHS Length (byte 8) in 32-bit words. UFS 2.0+ extension.
    pub total_ehs_length: u8,
    /// Device Information (byte 9).
    pub device_information: u8,
    /// Data Segment Length (bytes 10..12, big-endian per §10.6.2).
    pub data_segment_length: u16,
}

impl UpiuHeader {
    pub fn pack(self) -> [u8; 12] {
        [
            self.kind as u8,
            self.flags,
            self.lun,
            self.task_tag,
            self.iid_cmd_set_type,
            self.query_function,
            self.response,
            self.status,
            self.total_ehs_length,
            self.device_information,
            (self.data_segment_length >> 8) as u8,
            (self.data_segment_length & 0xFF) as u8,
        ]
    }
    pub fn unpack(b: &[u8; 12]) -> Option<Self> {
        Some(Self {
            kind: UpiuType::from_byte(b[0])?,
            flags: b[1],
            lun: b[2],
            task_tag: b[3],
            iid_cmd_set_type: b[4],
            query_function: b[5],
            response: b[6],
            status: b[7],
            total_ehs_length: b[8],
            device_information: b[9],
            data_segment_length: ((b[10] as u16) << 8) | (b[11] as u16),
        })
    }
}

/// Build a Command UPIU carrying a SCSI CDB. The SCSI command set
/// (CDB length 6/10/12/16) is identified by `iid_cmd_set_type` —
/// 0 = SCSI, 1 = UFS Native.
///
/// Wire layout (32 bytes for SCSI CDB):
///   0..12   Header (UpiuHeader::pack)
///   12..16  Expected Data Transfer Length (BE u32)
///   16..32  CDB (zero-padded if shorter)
pub fn build_command_upiu(
    lun: u8,
    task_tag: u8,
    direction_flags: u8,
    expected_data_len: u32,
    cdb: &[u8],
) -> Vec<u8> {
    let mut hdr = UpiuHeader {
        kind: UpiuType::Command,
        flags: direction_flags,
        lun,
        task_tag,
        iid_cmd_set_type: 0,
        query_function: 0,
        response: 0,
        status: 0,
        total_ehs_length: 0,
        device_information: 0,
        data_segment_length: 0,
    };
    let mut cdb_buf = [0u8; 16];
    let n = cdb.len().min(16);
    cdb_buf[..n].copy_from_slice(&cdb[..n]);
    hdr.data_segment_length = 0;

    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&hdr.pack());
    buf.extend_from_slice(&expected_data_len.to_be_bytes());
    buf.extend_from_slice(&cdb_buf);
    buf
}

/// `flags` byte direction bits (§10.7.1):
pub mod cmd_flags {
    pub const READ: u8 = 1 << 6;
    pub const WRITE: u8 = 1 << 5;
}

/// Decode a Response UPIU and return `(header, residual_count,
/// sense_data)`. Residual count is the SCSI residual; sense data
/// is present when `status == 0x02` (Check Condition).
pub fn decode_response_upiu(buf: &[u8]) -> Option<(UpiuHeader, u32, &[u8])> {
    if buf.len() < 16 {
        return None;
    }
    let mut hdr_bytes = [0u8; 12];
    hdr_bytes.copy_from_slice(&buf[..12]);
    let hdr = UpiuHeader::unpack(&hdr_bytes)?;
    if hdr.kind != UpiuType::Response {
        return None;
    }
    let residual = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let sense_off = 16;
    let sense_len = hdr.data_segment_length as usize;
    if buf.len() < sense_off + sense_len {
        return None;
    }
    Some((hdr, residual, &buf[sense_off..sense_off + sense_len]))
}

// ── PRDT — Physical Region Descriptor Table (§6.4) ───────────────

/// 16-byte PRDT entry. `byte_count` is the "Data Byte Count" field;
/// per spec this is 0-based, so a 4096-byte transfer encodes 4095.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PrdtEntry {
    pub data_addr: u64,
    pub byte_count: u32,
}

impl PrdtEntry {
    pub fn pack(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        let lo = (self.data_addr & 0xFFFF_FFFF) as u32;
        let hi = (self.data_addr >> 32) as u32;
        b[0..4].copy_from_slice(&lo.to_le_bytes());
        b[4..8].copy_from_slice(&hi.to_le_bytes());
        // bytes 8..12 reserved.
        // bytes 12..16: Data Byte Count, 0-based.
        let bc0 = self.byte_count.saturating_sub(1);
        b[12..16].copy_from_slice(&bc0.to_le_bytes());
        b
    }
    pub fn unpack(b: &[u8; 16]) -> Self {
        let lo = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let hi = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let bc0 = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
        Self {
            data_addr: ((hi as u64) << 32) | (lo as u64),
            byte_count: bc0 + 1,
        }
    }
}

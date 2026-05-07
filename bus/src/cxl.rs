//! CXL Component Register Block + CCI mailbox — clean-room.
//!
//! References (public-only):
//! - "Compute Express Link (CXL) Specification, Revision 3.1" — CXL
//!   Consortium. Public document.
//!   <https://computeexpresslink.org/cxl-specification/>
//!   §8.2.8 (Component Register Block layout — RCRB / DVSEC for CXL
//!   1.1+ devices, Memory-Mapped Component Registers).
//!   §8.2.9.1 (Mailbox Capabilities + Control + Status registers).
//!   §8.2.9.2 (Mailbox Command Format — opcode | input length |
//!     command payload | return code | output length | output
//!     payload).
//!   §8.2.9.5 (Background Command Status register).
//!   Table 8-44 (Component Command Set opcodes — Identify, Get FW
//!     Info, Get Timestamp, Set Timestamp, Health Info & Alerts,
//!     Get Supported Logs, Get Log).
//! - DSP0276 "MCTP over PCIe Vendor Defined Messages" — referenced
//!   for the MCTP+CXL message-binding, not consumed here.
//!   <https://www.dmtf.org/standards/pmci>
//!
//! No GPL Linux source consulted.
//!
//! ## Mailbox register block (§8.2.9.1)
//!
//! ```text
//!   +0x00 MB Capabilities
//!     bits 4..0  Payload Size (log2 of bytes; 8 → 256, 9 → 512, …)
//!     bit  5     Mailbox Ready
//!     bit  6     Doorbell Interrupt Capable
//!     bits 8..7  Background Operation Capable + Background Interrupt Capable
//!   +0x04 MB Control
//!     bit  0     Doorbell      (host writes 1 to start a command)
//!     bit  1     Mailbox Disable
//!     bit  2     Background Operation Abort
//!   +0x08 Command Register
//!     bits 7..0  Opcode (low byte)
//!     bits 15..8 Opcode (high byte)
//!     bits 36..16 Input Payload Length
//!   +0x10 Status Register
//!     bit  0     Background Operation
//!     bits 47..32  Return Code
//!     bits 63..48  Vendor Specific Extended Status
//!   +0x18 Background Command Status
//!     bits 47..32  Return Code
//!     bits 63..48  Vendor Specific Extended Status
//!     bit  16      Background Operation Complete
//!     bits 6..0    Percentage Complete (0..100)
//!   +0x20 Command Payload Region (variable size up to 1<<payload_size)
//! ```

use alloc::vec::Vec;

/// PCIe DVSEC Vendor ID for CXL 1.1+ devices.
pub const DVSEC_VENDOR_CXL: u16 = 0x1E98;
/// DVSEC ID for the Component Register Block locator (§8.1.3).
pub const DVSEC_ID_COMPONENT_REGISTER_LOCATOR: u16 = 0x0008;

// Mailbox register offsets (§8.2.9.1).
pub const REG_MB_CAPABILITIES: u64 = 0x00;
pub const REG_MB_CONTROL: u64 = 0x04;
pub const REG_MB_COMMAND: u64 = 0x08;
pub const REG_MB_STATUS: u64 = 0x10;
pub const REG_MB_BG_STATUS: u64 = 0x18;
pub const REG_MB_PAYLOAD: u64 = 0x20;

// MB Capabilities bits.
pub const CAP_MAILBOX_READY: u32 = 1 << 5;
pub const CAP_DOORBELL_INTR: u32 = 1 << 6;
pub const CAP_BG_OP_CAPABLE: u32 = 1 << 7;
pub const CAP_BG_INTR_CAPABLE: u32 = 1 << 8;

// MB Control bits.
pub const CTRL_DOORBELL: u32 = 1 << 0;
pub const CTRL_MAILBOX_DISABLE: u32 = 1 << 1;
pub const CTRL_ABORT_BG: u32 = 1 << 2;

// Status register fields (64-bit, low 32 carries flags + return code halfwords).
pub const STATUS_BACKGROUND_OPERATION: u64 = 1 << 0;

// ── Command opcodes (§8.2.9.5, table 8-44) ─────────────────────────

pub const OP_INFOSTAT_IDENTIFY: u16 = 0x0001;
pub const OP_INFOSTAT_BACKGROUND_OPERATION_STATUS: u16 = 0x0002;
pub const OP_INFOSTAT_GET_RESPONSE_MESSAGE_LIMIT: u16 = 0x0003;
pub const OP_INFOSTAT_SET_RESPONSE_MESSAGE_LIMIT: u16 = 0x0004;

pub const OP_EVENTS_GET_RECORDS: u16 = 0x0100;
pub const OP_EVENTS_CLEAR_RECORDS: u16 = 0x0101;
pub const OP_EVENTS_GET_INTERRUPT_POLICY: u16 = 0x0102;
pub const OP_EVENTS_SET_INTERRUPT_POLICY: u16 = 0x0103;

pub const OP_LOGS_GET_SUPPORTED_LOGS: u16 = 0x0400;
pub const OP_LOGS_GET_LOG: u16 = 0x0401;
pub const OP_LOGS_GET_SUPPORTED_LOGS_SUB_LIST: u16 = 0x0402;

pub const OP_FIRMWARE_GET_FW_INFO: u16 = 0x0200;
pub const OP_FIRMWARE_TRANSFER_FW: u16 = 0x0201;
pub const OP_FIRMWARE_ACTIVATE_FW: u16 = 0x0202;

pub const OP_TIMESTAMP_GET: u16 = 0x0300;
pub const OP_TIMESTAMP_SET: u16 = 0x0301;

pub const OP_HEALTH_GET_HEALTH_INFO: u16 = 0x4200;
pub const OP_HEALTH_GET_ALERT_CONFIG: u16 = 0x4201;
pub const OP_HEALTH_SET_ALERT_CONFIG: u16 = 0x4202;
pub const OP_HEALTH_GET_SHUTDOWN_STATE: u16 = 0x4203;

// CXL.mem device-specific (§8.2.9.8, table 8-118 selected).
pub const OP_MEM_GET_PARTITION_INFO: u16 = 0x4000;
pub const OP_MEM_SET_PARTITION_INFO: u16 = 0x4001;
pub const OP_MEM_GET_LSA: u16 = 0x4002;
pub const OP_MEM_SET_LSA: u16 = 0x4003;

// Return codes (§8.2.9.4, table 8-43 selected).
pub const RC_SUCCESS: u16 = 0x0000;
pub const RC_BACKGROUND_COMMAND_STARTED: u16 = 0x0001;
pub const RC_INVALID_INPUT: u16 = 0x0002;
pub const RC_UNSUPPORTED: u16 = 0x0003;
pub const RC_INTERNAL_ERROR: u16 = 0x0004;
pub const RC_RETRY_REQUIRED: u16 = 0x0005;
pub const RC_BUSY: u16 = 0x0006;
pub const RC_MEDIA_DISABLED: u16 = 0x0007;
pub const RC_ABORTED: u16 = 0x0011;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CxlError {
    Short,
    /// Encoded payload length doesn't match the buffer.
    BadLength,
}

// ── Command frame builder ──────────────────────────────────────────

/// Pack the Command register value: low 16 = opcode, bits 36..16 =
/// 21-bit input payload length. Returns a u64 because the field
/// crosses 32-bit boundaries.
pub const fn pack_command_register(opcode: u16, input_len: u32) -> u64 {
    (opcode as u64) | (((input_len as u64) & 0x1F_FFFF) << 16)
}

/// Decode a Command register value back into (opcode, input_len).
pub const fn unpack_command_register(reg: u64) -> (u16, u32) {
    (
        (reg & 0xFFFF) as u16,
        ((reg >> 16) & 0x1F_FFFF) as u32,
    )
}

/// Pack the Status register value: bits 47..32 = return code, bits
/// 63..48 = vendor-specific extended status.
pub const fn pack_status_register(
    background_operation: bool,
    return_code: u16,
    vendor_extended_status: u16,
) -> u64 {
    let mut v = 0u64;
    if background_operation {
        v |= STATUS_BACKGROUND_OPERATION;
    }
    v |= (return_code as u64) << 32;
    v |= (vendor_extended_status as u64) << 48;
    v
}

pub const fn unpack_status_register(reg: u64) -> (bool, u16, u16) {
    (
        (reg & STATUS_BACKGROUND_OPERATION) != 0,
        ((reg >> 32) & 0xFFFF) as u16,
        ((reg >> 48) & 0xFFFF) as u16,
    )
}

// ── Background Command Status register ─────────────────────────────

/// 64-bit Background Command Status decoder (§8.2.9.5). `percentage`
/// is a 7-bit field at bits 6..0; `complete` flag at bit 16; `return
/// code` at bits 47..32.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BackgroundStatus {
    pub percentage: u8,
    pub complete: bool,
    pub return_code: u16,
    pub vendor_extended_status: u16,
}

impl BackgroundStatus {
    pub const fn pack(self) -> u64 {
        let mut v = (self.percentage as u64) & 0x7F;
        if self.complete {
            v |= 1 << 16;
        }
        v |= (self.return_code as u64) << 32;
        v |= (self.vendor_extended_status as u64) << 48;
        v
    }

    pub const fn unpack(reg: u64) -> Self {
        Self {
            percentage: (reg & 0x7F) as u8,
            complete: (reg & (1 << 16)) != 0,
            return_code: ((reg >> 32) & 0xFFFF) as u16,
            vendor_extended_status: ((reg >> 48) & 0xFFFF) as u16,
        }
    }
}

// ── Identify response payload (§8.2.9.5.1) ─────────────────────────

/// Decoded `IDENTIFY` payload (§8.2.9.5.1, table 8-46). The full
/// payload is 56+ bytes; we surface the most useful fields.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentifyResponse {
    pub fw_revision: [u8; 16],
    pub max_supported_message_size: u8,
    pub component_type: u8,
    pub vid: u16,
    pub did: u16,
    pub subsys_vid: u16,
    pub subsys_did: u16,
    pub serial_number: u64,
}

impl IdentifyResponse {
    /// Parse the first 40 bytes of an IDENTIFY response payload.
    pub fn parse(buf: &[u8]) -> Result<Self, CxlError> {
        if buf.len() < 40 {
            return Err(CxlError::Short);
        }
        let mut fw_revision = [0u8; 16];
        fw_revision.copy_from_slice(&buf[0..16]);
        Ok(Self {
            fw_revision,
            max_supported_message_size: buf[16],
            component_type: buf[17],
            vid: u16::from_le_bytes([buf[18], buf[19]]),
            did: u16::from_le_bytes([buf[20], buf[21]]),
            subsys_vid: u16::from_le_bytes([buf[22], buf[23]]),
            subsys_did: u16::from_le_bytes([buf[24], buf[25]]),
            serial_number: u64::from_le_bytes([
                buf[26], buf[27], buf[28], buf[29], buf[30], buf[31], buf[32], buf[33],
            ]),
        })
    }
}

// ── Get Log payload (§8.2.9.5.4) ───────────────────────────────────

/// Build the `Get Log` input payload (§8.2.9.5.4). `log_uuid` is a
/// 16-byte identifier (e.g. `0xb3fa5a32...` for "Command Effects Log").
pub fn get_log_input(log_uuid: &[u8; 16], offset: u32, length: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(log_uuid);
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out
}

// ── Health Info response (§8.2.9.5.5) ──────────────────────────────

/// Decoded `Get Health Info` response (§8.2.9.5.5, table 8-49). The
/// full payload is 18 bytes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HealthInfo {
    /// Health Status — bit 0: maintenance needed, bit 1: performance
    /// degraded, bit 2: hardware-replacement needed.
    pub health_status: u8,
    /// Media Status — bit 0..1: media operational/degraded/failed.
    pub media_status: u8,
    pub additional_status: u8,
    pub life_used: u8,
    pub device_temperature: u16,
    pub dirty_shutdown_count: u32,
    pub corrected_volatile_error_count: u32,
    pub corrected_persistent_error_count: u32,
}

impl HealthInfo {
    pub const HEALTH_MAINTENANCE_NEEDED: u8 = 1 << 0;
    pub const HEALTH_PERFORMANCE_DEGRADED: u8 = 1 << 1;
    pub const HEALTH_HARDWARE_REPLACEMENT_NEEDED: u8 = 1 << 2;

    pub const MEDIA_NORMAL: u8 = 0;
    pub const MEDIA_NOT_READY: u8 = 1;
    pub const MEDIA_WRITE_PERSISTENCY_LOST: u8 = 2;
    pub const MEDIA_FAILURE: u8 = 3;

    pub fn parse(buf: &[u8]) -> Result<Self, CxlError> {
        if buf.len() < 18 {
            return Err(CxlError::Short);
        }
        Ok(Self {
            health_status: buf[0],
            media_status: buf[1],
            additional_status: buf[2],
            life_used: buf[3],
            device_temperature: u16::from_le_bytes([buf[4], buf[5]]),
            dirty_shutdown_count: u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]),
            corrected_volatile_error_count: u32::from_le_bytes([
                buf[10], buf[11], buf[12], buf[13],
            ]),
            corrected_persistent_error_count: u32::from_le_bytes([
                buf[14], buf[15], buf[16], buf[17],
            ]),
        })
    }
}

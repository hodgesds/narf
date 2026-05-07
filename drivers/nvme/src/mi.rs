//! NVMe Management Interface (NVMe-MI) — clean-room.
//!
//! References (public-only):
//! - "NVM Express Management Interface, Revision 1.2c" (2023).
//!   §3 (Message Format), §3.1 (NVMe-MI Message Header / NMH),
//!   §3.4 (Message Integrity Check / MIC, CRC-32), §5.0 (Command
//!   Set), §5.1 (Read NVMe-MI Data Structure), §5.6 (Health Status
//!   Poll), §5.8 (Subsystem Health Status Poll).
//!   <https://nvmexpress.org/specifications/>
//! - DSP0236 "Management Component Transport Protocol (MCTP) Base"
//!   v1.3.1 — DMTF, public. NVMe-MI travels as MCTP message-type
//!   0x04 (NVMe Management).
//!   <https://www.dmtf.org/dsp/DSP0235>
//!
//! No GPL Linux source consulted.
//!
//! ## NMH (NVMe Management Interface Message Header) — 4 bytes (§3.1)
//!
//! ```text
//!   byte 0: MCTP Integrity Check (1 bit) | Reserved (1 bit) |
//!           Command Slot Identifier (1 bit) | Reserved (4 bits) |
//!           Response Indicator (1 bit)
//!   byte 1: NVMe-MI Message Type (NMIMT, 4 bits) | NVMe-MI
//!           Management Endpoint Type (MET, 4 bits)
//!   byte 2..3: Reserved
//! ```
//!
//! NMIMT values (§3.1, table 4):
//!   - 0x0  Control Primitive
//!   - 0x1  NVMe-MI Command
//!   - 0x2  NVMe Admin Command (encapsulated)
//!   - 0x3  Reserved
//!   - 0x4  PCIe Command
//!   - 0x5..0xF  Reserved
//!
//! ## Message body (NVMe-MI Command, §3.5)
//!
//! Following the 4-byte NMH:
//!
//! ```text
//!   byte 0   Opcode
//!   byte 1   Reserved
//!   bytes 2..3   Reserved (carrier-specific)
//!   bytes 4..7   NVMe Management Request Doubleword 0 (CDW0)
//!   bytes 8..11  NVMe Management Request Doubleword 1 (CDW1)
//!   bytes 12..   Optional Request Data (per-opcode)
//!   ...
//!   trailing 4 bytes:  MIC (CRC-32 over the whole message, §3.4)
//! ```
//!
//! Response (§3.6) starts with a status byte then the same CDW0/1
//! layout, also tail-capped by MIC.

use alloc::vec::Vec;

// MCTP message type for NVMe-MI traffic (DSP0236 + NVMe-MI §2.2).
pub const MCTP_MSGTYPE_NVME_MI: u8 = 0x04;

// NMIMT values (§3.1 table 4).
pub const NMIMT_CONTROL_PRIMITIVE: u8 = 0x0;
pub const NMIMT_MI_COMMAND: u8 = 0x1;
pub const NMIMT_NVME_ADMIN_COMMAND: u8 = 0x2;
pub const NMIMT_PCIE_COMMAND: u8 = 0x4;

// Management endpoint types (§3.1 table 5).
pub const MET_OUT_OF_BAND: u8 = 0x0;
pub const MET_IN_BAND_PCIE_VDM: u8 = 0x1;

// NVMe-MI command opcodes (§5).
pub const MI_OPCODE_READ_DATA_STRUCTURE: u8 = 0x00;
pub const MI_OPCODE_NVM_SUBSYSTEM_HEALTH_STATUS_POLL: u8 = 0x01;
pub const MI_OPCODE_CONTROLLER_HEALTH_STATUS_POLL: u8 = 0x02;
pub const MI_OPCODE_CONFIGURATION_SET: u8 = 0x03;
pub const MI_OPCODE_CONFIGURATION_GET: u8 = 0x04;
pub const MI_OPCODE_VPD_READ: u8 = 0x05;
pub const MI_OPCODE_VPD_WRITE: u8 = 0x06;
pub const MI_OPCODE_RESET: u8 = 0x07;
pub const MI_OPCODE_SES_RECEIVE: u8 = 0x08;
pub const MI_OPCODE_SES_SEND: u8 = 0x09;

// "Read NVMe-MI Data Structure" DTYPE values (§5.1, table 124).
pub const DTYPE_NVM_SUBSYSTEM_INFO: u8 = 0x00;
pub const DTYPE_PORT_INFO: u8 = 0x01;
pub const DTYPE_CONTROLLER_LIST: u8 = 0x02;
pub const DTYPE_CONTROLLER_INFO: u8 = 0x03;

// NVMe-MI status codes (§4.0.4, table 23) — selected.
pub const MI_STATUS_SUCCESS: u8 = 0x00;
pub const MI_STATUS_MORE_PROCESSING_REQUIRED: u8 = 0x01;
pub const MI_STATUS_INTERNAL_ERROR: u8 = 0x02;
pub const MI_STATUS_INVALID_COMMAND_OPCODE: u8 = 0x03;
pub const MI_STATUS_INVALID_PARAMETER: u8 = 0x04;
pub const MI_STATUS_INVALID_COMMAND_SIZE: u8 = 0x05;
pub const MI_STATUS_INVALID_COMMAND_INPUT_DATA_SIZE: u8 = 0x06;
pub const MI_STATUS_ACCESS_DENIED: u8 = 0x07;

/// CRC-32 polynomial used for the MIC (§3.4 — same polynomial as
/// IEEE 802.3 / Ethernet, reflected, init = 0xFFFF_FFFF, output XOR
/// = 0xFFFF_FFFF). Computed bytewise; we don't keep a 256-byte table.
pub fn mic(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc ^ 0xFFFF_FFFF
}

// ── NMH ────────────────────────────────────────────────────────────

/// 4-byte NVMe-MI Message Header.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Nmh {
    /// MCTP IC bit (1 = MIC present).
    pub mctp_ic: bool,
    /// Command Slot Identifier (one bit).
    pub command_slot: bool,
    /// Response Indicator (1 = response, 0 = request).
    pub response: bool,
    /// NVMe-MI Message Type (4 bits, NMIMT_* constants).
    pub nmimt: u8,
    /// Management Endpoint Type (4 bits, MET_* constants).
    pub met: u8,
}

impl Nmh {
    pub fn encode(self) -> [u8; 4] {
        let mut b0 = 0u8;
        if self.mctp_ic {
            b0 |= 1 << 7;
        }
        if self.command_slot {
            b0 |= 1 << 5;
        }
        if self.response {
            b0 |= 1 << 0;
        }
        let b1 = ((self.nmimt & 0x0F) << 4) | (self.met & 0x0F);
        [b0, b1, 0, 0]
    }

    pub fn decode(buf: &[u8; 4]) -> Self {
        Self {
            mctp_ic: (buf[0] & 0x80) != 0,
            command_slot: (buf[0] & 0x20) != 0,
            response: (buf[0] & 0x01) != 0,
            nmimt: (buf[1] >> 4) & 0x0F,
            met: buf[1] & 0x0F,
        }
    }
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MiError {
    /// Buffer doesn't include enough bytes for NMH + opcode + 2 CDWs + MIC.
    Short,
    /// MIC (trailing CRC-32) doesn't match the payload.
    BadMic,
}

// ── Request / response builders ────────────────────────────────────

/// One NVMe-MI Command Message body (without NMH or MIC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandBody {
    pub opcode: u8,
    pub cdw0: u32,
    pub cdw1: u32,
    pub data: Vec<u8>,
}

impl CommandBody {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.opcode);
        out.push(0); // reserved
        out.push(0);
        out.push(0); // reserved (carrier-specific)
        out.extend_from_slice(&self.cdw0.to_le_bytes());
        out.extend_from_slice(&self.cdw1.to_le_bytes());
        out.extend_from_slice(&self.data);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, MiError> {
        if buf.len() < 12 {
            return Err(MiError::Short);
        }
        let opcode = buf[0];
        let cdw0 = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let cdw1 = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let data = buf[12..].to_vec();
        Ok(Self {
            opcode,
            cdw0,
            cdw1,
            data,
        })
    }
}

/// Build a fully-framed NVMe-MI Command Message (NMH + body + MIC).
pub fn build_command(nmh: Nmh, body: &CommandBody) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + body.data.len());
    out.extend_from_slice(&nmh.encode());
    body.encode_into(&mut out);
    let m = mic(&out);
    out.extend_from_slice(&m.to_le_bytes());
    out
}

/// Decode a fully-framed NVMe-MI message → (NMH, body) and verify MIC
/// when the IC bit is set in the NMH.
pub fn decode_message(buf: &[u8]) -> Result<(Nmh, CommandBody), MiError> {
    if buf.len() < 4 + 12 {
        return Err(MiError::Short);
    }
    let nmh = Nmh::decode(&[buf[0], buf[1], buf[2], buf[3]]);
    if nmh.mctp_ic {
        if buf.len() < 4 + 12 + 4 {
            return Err(MiError::Short);
        }
        let mic_pos = buf.len() - 4;
        let want = u32::from_le_bytes([
            buf[mic_pos],
            buf[mic_pos + 1],
            buf[mic_pos + 2],
            buf[mic_pos + 3],
        ]);
        let calc = mic(&buf[..mic_pos]);
        if want != calc {
            return Err(MiError::BadMic);
        }
        let body = CommandBody::decode(&buf[4..mic_pos])?;
        return Ok((nmh, body));
    }
    let body = CommandBody::decode(&buf[4..])?;
    Ok((nmh, body))
}

// ── Specific commands ──────────────────────────────────────────────

/// Build a "Read NVMe-MI Data Structure" command (§5.1, table 124).
/// CDW0 layout: [DTYPE(8) | reserved(8) | controller_id(16, LE)].
pub fn read_data_structure(dtype: u8, controller_id: u16) -> CommandBody {
    let cdw0 = (dtype as u32) | ((controller_id as u32) << 16);
    CommandBody {
        opcode: MI_OPCODE_READ_DATA_STRUCTURE,
        cdw0,
        cdw1: 0,
        data: Vec::new(),
    }
}

/// Build an "NVM Subsystem Health Status Poll" command (§5.8).
/// CDW1 bit 31 set ⇒ "Clear Status".
pub fn subsystem_health_status_poll(clear_status: bool) -> CommandBody {
    let cdw1 = if clear_status { 1u32 << 31 } else { 0 };
    CommandBody {
        opcode: MI_OPCODE_NVM_SUBSYSTEM_HEALTH_STATUS_POLL,
        cdw0: 0,
        cdw1,
        data: Vec::new(),
    }
}

/// Build a "Controller Health Status Poll" command (§5.6).
/// CDW0 bits[15:0] = controller-id.
pub fn controller_health_status_poll(controller_id: u16) -> CommandBody {
    CommandBody {
        opcode: MI_OPCODE_CONTROLLER_HEALTH_STATUS_POLL,
        cdw0: controller_id as u32,
        cdw1: 0,
        data: Vec::new(),
    }
}

/// Decoded "NVM Subsystem Health Data Structure" returned by §5.8
/// — 8 bytes (table 154).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SubsystemHealth {
    /// NVM Subsystem Status (NSS) byte. Bits include CFS (bit 1),
    /// RNR (bit 4), NSD (bit 7).
    pub nss: u8,
    /// Smart Warnings byte (table 155).
    pub smart_warnings: u8,
    pub composite_temperature: u8,
    pub percentage_used: u8,
    pub composite_controller_status: u16,
}

impl SubsystemHealth {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        Some(Self {
            nss: buf[0],
            smart_warnings: buf[1],
            composite_temperature: buf[2],
            percentage_used: buf[3],
            composite_controller_status: u16::from_le_bytes([buf[4], buf[5]]),
        })
    }
}

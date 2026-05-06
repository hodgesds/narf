//! PCIe Data Object Exchange (DOE) — clean-room.
//!
//! References (public-only):
//! - "PCI Express Base Specification, Revision 6.0" — PCI-SIG.
//!   §6.30 Data Object Exchange (DOE) Extended Capability.
//! - "PCI Express Base Specification, Revision 5.0" — first to
//!   ratify DOE; layout matches the 6.0 wording.
//! - DMTF DSP0274 "Security Protocol and Data Model (SPDM)" §A —
//!   defines the SPDM-over-DOE wrapper that runs on top of this
//!   transport.
//! - PCI-SIG public registries (Vendor ID list) — Vendor ID 0x0001
//!   is reserved as "PCI-SIG" for the DOE Discovery protocol.
//!
//! No GPL Linux source consulted.
//!
//! ## Capability layout (Base 6.0 §6.30)
//!
//! ```text
//!   +0x00   PCIe Extended Capability Header (cap-id 0x002E, version 1, next-cap)
//!   +0x04   DOE Capabilities    (32-bit; bit 0 = Interrupt Support)
//!   +0x08   DOE Control         (write-1-only triggers: Abort + Go)
//!   +0x0C   DOE Status          (Busy / Error / Object-Ready / Interrupt-Status)
//!   +0x10   DOE Write Mailbox   (32-bit DWORD write port — host writes request DWORDs)
//!   +0x14   DOE Read Mailbox    (32-bit DWORD read port — host reads response DWORDs)
//! ```
//!
//! ## Object header (§6.30.1)
//!
//! Each DOE message is a sequence of 32-bit DWORDs framed by a
//! mandatory 2-DWORD header:
//!
//! ```text
//!   DWORD 0:
//!     bits[15..0]   Vendor ID (0x0001 = PCI-SIG, ≥0x4000 = vendor-specific)
//!     bits[23..16]  Data Object Type
//!     bits[31..24]  Reserved
//!   DWORD 1:
//!     bits[17..0]   Length (in DWORDs, including the header).
//!                   A value of 0 encodes 2^18 DWORDs.
//!     bits[31..18]  Reserved
//!   DWORD 2..N:    payload
//! ```
//!
//! ## DOE Discovery (§6.30.1.1)
//!
//! Vendor 0x0001, Type 0x00. The host walks the discovery protocol
//! to learn which (vendor, type) pairs the endpoint supports.
//!
//! Request:  DWORD 0 = (0x0001 | 0x00 << 16); DWORD 1 = length 3;
//!            DWORD 2 = index (start at 0).
//! Response: DWORD 0 = (0x0001 | 0x00 << 16); DWORD 1 = length 3;
//!            DWORD 2 bits[15..0] = Vendor ID,
//!                    bits[23..16] = Data Object Type,
//!                    bits[31..24] = Next Index (0 = no more).

use alloc::vec::Vec;

/// PCIe Extended Capability ID for DOE (§6.30).
pub const DOE_EXT_CAP_ID: u16 = 0x002E;

// Cap-relative register offsets (§6.30).
pub const REG_DOE_CAP: u16 = 0x04;
pub const REG_DOE_CTRL: u16 = 0x08;
pub const REG_DOE_STATUS: u16 = 0x0C;
pub const REG_DOE_WRITE_MAILBOX: u16 = 0x10;
pub const REG_DOE_READ_MAILBOX: u16 = 0x14;

// DOE Capabilities bits.
pub const DOE_CAP_INTR_SUPPORT: u32 = 1 << 0;

// DOE Control bits (write-1).
pub const DOE_CTRL_ABORT: u32 = 1 << 0;
pub const DOE_CTRL_GO: u32 = 1 << 31;
pub const DOE_CTRL_INTR_EN: u32 = 1 << 1;

// DOE Status bits (read-only / W1C for Error).
pub const DOE_STS_BUSY: u32 = 1 << 0;
pub const DOE_STS_ERROR: u32 = 1 << 2;
pub const DOE_STS_OBJECT_READY: u32 = 1 << 31;
pub const DOE_STS_INTR_STATUS: u32 = 1 << 1;

// Reserved Vendor IDs (PCI-SIG).
pub const VENDOR_PCISIG: u16 = 0x0001;
/// Vendor-specific range (0x4000..=0xFFFF) per §6.30.1.
pub const VENDOR_VENDOR_SPECIFIC_MIN: u16 = 0x4000;

// Data Object Types within Vendor 0x0001 PCI-SIG.
pub const TYPE_DOE_DISCOVERY: u8 = 0x00;
pub const TYPE_CMA_SPDM: u8 = 0x01;
pub const TYPE_SECURED_CMA_SPDM: u8 = 0x02;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DoeError {
    /// Buffer too short for the 2-DWORD header.
    Short,
    /// Length field claims more DWORDs than the buffer contains.
    Truncated,
    /// Length field is < 2 (header is mandatory).
    BadLength,
}

/// Decoded DOE message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub vendor_id: u16,
    pub data_object_type: u8,
    /// Payload DWORDs (i.e. excluding the 2-DWORD header).
    pub payload: Vec<u32>,
}

impl Object {
    /// Build a DOE object envelope — returns the full DWORD stream
    /// (header + payload) the caller will write to `Write Mailbox`.
    pub fn encode(&self) -> Vec<u32> {
        let total_dwords = (2 + self.payload.len()) as u32;
        // Length field is 18 bits; 0 means 2^18 (encodes the maximum).
        let len_field = if total_dwords == (1u32 << 18) {
            0
        } else {
            total_dwords & 0x3_FFFF
        };
        let mut out = Vec::with_capacity(2 + self.payload.len());
        out.push((self.vendor_id as u32) | ((self.data_object_type as u32) << 16));
        out.push(len_field);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode a DOE object from the DWORD stream the caller drained
    /// from the `Read Mailbox`.
    pub fn decode(dwords: &[u32]) -> Result<Self, DoeError> {
        if dwords.len() < 2 {
            return Err(DoeError::Short);
        }
        let vendor_id = (dwords[0] & 0xFFFF) as u16;
        let data_object_type = ((dwords[0] >> 16) & 0xFF) as u8;
        let len_field = dwords[1] & 0x3_FFFF;
        let total = if len_field == 0 { 1u32 << 18 } else { len_field };
        if total < 2 {
            return Err(DoeError::BadLength);
        }
        if (total as usize) > dwords.len() {
            return Err(DoeError::Truncated);
        }
        let payload = dwords[2..total as usize].to_vec();
        Ok(Self {
            vendor_id,
            data_object_type,
            payload,
        })
    }
}

// ── DOE Discovery ──────────────────────────────────────────────────

/// Build a DOE Discovery request asking for entry `index` in the
/// endpoint's protocol table (§6.30.1.1).
pub fn build_discovery_request(index: u8) -> Vec<u32> {
    Object {
        vendor_id: VENDOR_PCISIG,
        data_object_type: TYPE_DOE_DISCOVERY,
        payload: alloc::vec![index as u32],
    }
    .encode()
}

/// One entry returned by DOE Discovery.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoveryEntry {
    pub vendor_id: u16,
    pub data_object_type: u8,
    /// 0 ⇒ this was the last entry; otherwise, ask Discovery again
    /// with `next_index` to continue walking.
    pub next_index: u8,
}

impl DiscoveryEntry {
    /// Decode one DOE Discovery response (§6.30.1.1). Caller already
    /// confirmed the response object's vendor=0x0001 / type=0x00.
    pub fn parse(payload: &[u32]) -> Option<Self> {
        let v = *payload.first()?;
        Some(Self {
            vendor_id: (v & 0xFFFF) as u16,
            data_object_type: ((v >> 16) & 0xFF) as u8,
            next_index: ((v >> 24) & 0xFF) as u8,
        })
    }
}

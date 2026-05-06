//! PCIe Integrity & Data Encryption (IDE) — clean-room.
//!
//! References (public-only):
//! - "PCI Express Base Specification, Revision 6.0" — PCI-SIG.
//!   §6.33 Integrity & Data Encryption (IDE) Extended Capability:
//!   cap-id 0x0030, capability + control + status registers, plus
//!   Selective IDE and Link IDE Stream register blocks. §6.33.4
//!   IDE Key Management (IDE_KM) message format carried over DOE
//!   (vendor 0x0001, type 0x07).
//! - DSP0277 "Component Measurement and Authentication (CMA)" —
//!   referenced for the SPDM-protected channel that wraps IDE_KM.
//! - PCI-SIG public Vendor ID list — 0x0001 = PCI-SIG.
//!
//! No GPL Linux source consulted.
//!
//! ## IDE Capability layout (§6.33.1, table 7-260)
//!
//! ```text
//!   +0x00 PCIe Extended Capability Header (cap-id 0x0030)
//!   +0x04 IDE Capability
//!     bit 0    Link IDE Supported
//!     bit 1    Selective IDE Supported
//!     bit 2    Flow-Through IDE Supported
//!     bit 3    Aggregation Supported
//!     bit 4    PCRC Supported
//!     bit 5    IDE_KM-Protocol Supported
//!     bit 6    Selective IDE for Configuration Requests Supported
//!     bits 19..16  Number of TCs Supported
//!     bits 23..20  Number of Selective IDE Streams Supported
//!     bits 27..24  Number of Link IDE Streams Supported
//!   +0x08 IDE Control
//!     bit 0    Flow-Through IDE Stream Enabled
//!   +0x0C..  Link IDE Stream Register Block (per-link, variable count)
//!   ...     Selective IDE Stream Register Block (per-stream, variable count)
//! ```
//!
//! Each Stream Register Block is 24 bytes:
//!
//! ```text
//!   +0x00 Stream Capabilities
//!   +0x04 Stream Control
//!     bit 0    Stream Enable
//!     bit 1    Tx Aggregation Enable
//!     bit 2    Rx Aggregation Enable
//!     bit 3    PCRC Enable
//!     bits 7..4  Algorithm (0 = AES-GCM-256, 1 = AES-GMAC-256)
//!     bit 8    Selected
//!     bits 15..14  TC
//!     bits 23..16  Stream ID (selective only)
//!   +0x08 Stream Status
//!     bit 0    Stream State (1 = Secure, 0 = Insecure)
//!     bits 7..4  Received Integrity-check Failures
//!   +0x0C..0x18 RID Association Register Blocks (selective only)
//! ```
//!
//! ## IDE_KM message format (§6.33.4, table 7-273)
//!
//! Each IDE_KM message rides inside a DOE object (vendor 0x0001 /
//! type 0x07). The body is:
//!
//! ```text
//!   byte 0     Object ID — KM message type:
//!     0x00 KEY_PROG     (programme a key)
//!     0x01 KP_ACK       (KEY_PROG response)
//!     0x02 K_SET_GO     (activate the key)
//!     0x03 K_SET_STOP   (suspend the key)
//!     0x04 K_GOSTOP_ACK (response to K_SET_GO / K_SET_STOP)
//!     0x05 KEY_QUERY    (query key state)
//!     0x06 K_QUERY_RESP
//!   byte 1     Reserved (0)
//!   bytes 2..3 Stream ID + sub-stream + Key Set selector
//!   bytes 4..  Message-specific payload
//! ```

use alloc::vec::Vec;

/// PCIe Extended Capability ID for IDE.
pub const IDE_EXT_CAP_ID: u16 = 0x0030;

/// DOE vendor + data-object type for IDE_KM.
pub const DOE_TYPE_IDE_KM: u8 = 0x07;
pub const DOE_VENDOR_PCISIG: u16 = 0x0001;

// IDE Capability bits (§6.33.1).
pub const IDE_CAP_LINK_SUPPORTED: u32 = 1 << 0;
pub const IDE_CAP_SELECTIVE_SUPPORTED: u32 = 1 << 1;
pub const IDE_CAP_FLOW_THROUGH_SUPPORTED: u32 = 1 << 2;
pub const IDE_CAP_AGGREGATION_SUPPORTED: u32 = 1 << 3;
pub const IDE_CAP_PCRC_SUPPORTED: u32 = 1 << 4;
pub const IDE_CAP_IDE_KM_PROTOCOL_SUPPORTED: u32 = 1 << 5;
pub const IDE_CAP_CFG_REQS_SUPPORTED: u32 = 1 << 6;

// Stream Control bits.
pub const STREAM_CTRL_ENABLE: u32 = 1 << 0;
pub const STREAM_CTRL_TX_AGGR_EN: u32 = 1 << 1;
pub const STREAM_CTRL_RX_AGGR_EN: u32 = 1 << 2;
pub const STREAM_CTRL_PCRC_EN: u32 = 1 << 3;
pub const STREAM_CTRL_SELECTED: u32 = 1 << 8;

// Algorithm field values (Stream Control bits 7..4).
pub const STREAM_ALGORITHM_AES_GCM_256: u8 = 0x0;
pub const STREAM_ALGORITHM_AES_GMAC_256: u8 = 0x1;

// Stream Status bits.
pub const STREAM_STATUS_SECURE: u32 = 1 << 0;

// IDE_KM Object IDs (§6.33.4).
pub const KM_OBJECT_KEY_PROG: u8 = 0x00;
pub const KM_OBJECT_KP_ACK: u8 = 0x01;
pub const KM_OBJECT_K_SET_GO: u8 = 0x02;
pub const KM_OBJECT_K_SET_STOP: u8 = 0x03;
pub const KM_OBJECT_K_GOSTOP_ACK: u8 = 0x04;
pub const KM_OBJECT_KEY_QUERY: u8 = 0x05;
pub const KM_OBJECT_K_QUERY_RESP: u8 = 0x06;

// KP_ACK status codes (§6.33.4 table 7-275).
pub const KP_ACK_STATUS_SUCCESS: u8 = 0x00;
pub const KP_ACK_STATUS_INCORRECT_LENGTH: u8 = 0x01;
pub const KP_ACK_STATUS_UNSUPPORTED_PORT_INDEX: u8 = 0x02;
pub const KP_ACK_STATUS_UNSUPPORTED_VALUE: u8 = 0x03;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IdeError {
    /// Buffer is too short for the requested message.
    Short,
    /// Object ID isn't one of the IDE_KM message types.
    BadObjectId(u8),
}

// ── Selector word ─────────────────────────────────────────────────

/// 16-bit Stream Selector that identifies which key on which stream
/// an IDE_KM message addresses (§6.33.4, table 7-274 — bytes 2..3 of
/// every KM message are this field):
///
/// ```text
///   bits 7..0  Stream ID
///   bit 8      Sub-Stream — 0 = PR, 1 = NPR
///   bit 9      Key Set    — 0 = Set A, 1 = Set B
///   bits 11..10 Key Direction — 0 = Rx (receive), 1 = Tx (transmit)
///   bits 15..12 reserved
/// ```
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamSelector {
    pub stream_id: u8,
    pub sub_stream_npr: bool,
    pub key_set_b: bool,
    pub direction_tx: bool,
}

impl StreamSelector {
    pub fn encode(self) -> u16 {
        let mut v = self.stream_id as u16;
        if self.sub_stream_npr {
            v |= 1 << 8;
        }
        if self.key_set_b {
            v |= 1 << 9;
        }
        if self.direction_tx {
            v |= 1 << 10;
        }
        v
    }

    pub fn decode(v: u16) -> Self {
        Self {
            stream_id: (v & 0xFF) as u8,
            sub_stream_npr: (v & (1 << 8)) != 0,
            key_set_b: (v & (1 << 9)) != 0,
            direction_tx: (v & (1 << 10)) != 0,
        }
    }
}

// ── IDE_KM message builders ────────────────────────────────────────

/// Build a KEY_PROG IDE_KM message body. `key` is 32 bytes (AES-256-GCM
/// key) and `iv` is 8 bytes (the lower portion of the 96-bit GCM IV;
/// the upper 32 bits come from the link counter, §6.33.3).
pub fn key_prog(selector: StreamSelector, key: &[u8; 32], iv: &[u8; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + 8);
    out.push(KM_OBJECT_KEY_PROG);
    out.push(0); // reserved
    out.extend_from_slice(&selector.encode().to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(iv);
    out
}

/// Build a KP_ACK reply.
pub fn kp_ack(selector: StreamSelector, status: u8) -> Vec<u8> {
    alloc::vec![
        KM_OBJECT_KP_ACK,
        0,
        (selector.encode() & 0xFF) as u8,
        (selector.encode() >> 8) as u8,
        status,
        0,
        0,
        0,
    ]
}

/// Build a K_SET_GO message.
pub fn k_set_go(selector: StreamSelector) -> Vec<u8> {
    alloc::vec![
        KM_OBJECT_K_SET_GO,
        0,
        (selector.encode() & 0xFF) as u8,
        (selector.encode() >> 8) as u8,
    ]
}

/// Build a K_SET_STOP message.
pub fn k_set_stop(selector: StreamSelector) -> Vec<u8> {
    alloc::vec![
        KM_OBJECT_K_SET_STOP,
        0,
        (selector.encode() & 0xFF) as u8,
        (selector.encode() >> 8) as u8,
    ]
}

/// Build a K_GOSTOP_ACK reply.
pub fn k_gostop_ack(selector: StreamSelector) -> Vec<u8> {
    alloc::vec![
        KM_OBJECT_K_GOSTOP_ACK,
        0,
        (selector.encode() & 0xFF) as u8,
        (selector.encode() >> 8) as u8,
    ]
}

/// Decode a generic IDE_KM message → (object id, selector, payload tail).
pub fn parse(buf: &[u8]) -> Result<(u8, StreamSelector, Vec<u8>), IdeError> {
    if buf.len() < 4 {
        return Err(IdeError::Short);
    }
    let object_id = buf[0];
    let selector = StreamSelector::decode(u16::from_le_bytes([buf[2], buf[3]]));
    let tail = buf[4..].to_vec();
    match object_id {
        KM_OBJECT_KEY_PROG | KM_OBJECT_KP_ACK | KM_OBJECT_K_SET_GO | KM_OBJECT_K_SET_STOP
        | KM_OBJECT_K_GOSTOP_ACK | KM_OBJECT_KEY_QUERY | KM_OBJECT_K_QUERY_RESP => {
            Ok((object_id, selector, tail))
        }
        other => Err(IdeError::BadObjectId(other)),
    }
}

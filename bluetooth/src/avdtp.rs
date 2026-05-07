//! AVDTP — Audio/Video Distribution Transport Protocol (clean-room).
//!
//! References (public-only):
//! - "Audio/Video Distribution Transport Protocol Specification,
//!   Version 1.3" — Bluetooth SIG. Public adopted document.
//!   §8.4 (Signalling Message format), §8.5 (Signal Identifiers,
//!   table 8.4), §8.6 (Service Capabilities), §8.7 (codec
//!   capability blob format).
//! - "Advanced Audio Distribution Profile (A2DP), Version 1.4" —
//!   Bluetooth SIG. §4.3 (SBC media codec capability layout, table
//!   4.1: sampling frequency / channel mode / block length /
//!   subbands / allocation method bitmasks).
//! - Bluetooth Core 5.3 Vol 3 Part A — L2CAP. AVDTP messages travel
//!   over a dedicated L2CAP channel (PSM 0x0019).
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! No GPL Linux source consulted.
//!
//! ## Signal-message header (§8.4)
//!
//! ```text
//!   byte 0:
//!     bits[7..4] = Transaction Label (0..15)
//!     bits[3..2] = Packet Type
//!                  0b00 Single, 0b01 Start, 0b10 Continue, 0b11 End
//!     bits[1..0] = Message Type
//!                  0b00 Command, 0b01 General Reject,
//!                  0b10 Response Accept, 0b11 Response Reject
//!   byte 1:
//!     Signal Identifier (SID) — see SID_* below.
//!   byte 2..N: command/response specific payload.
//! ```
//!
//! Start-fragmented messages place a `bytes 0..1` header on the first
//! L2CAP frame; subsequent fragments use a 1-byte continuation header.

use alloc::vec::Vec;

/// L2CAP PSM that carries AVDTP signalling (Assigned Numbers).
pub const AVDTP_PSM: u16 = 0x0019;

// Packet types (§8.4).
pub const PKT_SINGLE: u8 = 0b00;
pub const PKT_START: u8 = 0b01;
pub const PKT_CONTINUE: u8 = 0b10;
pub const PKT_END: u8 = 0b11;

// Message types (§8.4).
pub const MSG_COMMAND: u8 = 0b00;
pub const MSG_GENERAL_REJECT: u8 = 0b01;
pub const MSG_RESPONSE_ACCEPT: u8 = 0b10;
pub const MSG_RESPONSE_REJECT: u8 = 0b11;

// Signal Identifiers (§8.5, table 8.4).
pub const SID_DISCOVER: u8 = 0x01;
pub const SID_GET_CAPABILITIES: u8 = 0x02;
pub const SID_SET_CONFIGURATION: u8 = 0x03;
pub const SID_GET_CONFIGURATION: u8 = 0x04;
pub const SID_RECONFIGURE: u8 = 0x05;
pub const SID_OPEN: u8 = 0x06;
pub const SID_START: u8 = 0x07;
pub const SID_CLOSE: u8 = 0x08;
pub const SID_SUSPEND: u8 = 0x09;
pub const SID_ABORT: u8 = 0x0A;
pub const SID_SECURITY_CONTROL: u8 = 0x0B;
pub const SID_GET_ALL_CAPABILITIES: u8 = 0x0C;
pub const SID_DELAYREPORT: u8 = 0x0D;

// Service Categories (§8.6, table 8.6).
pub const CAT_MEDIA_TRANSPORT: u8 = 0x01;
pub const CAT_REPORTING: u8 = 0x02;
pub const CAT_RECOVERY: u8 = 0x03;
pub const CAT_CONTENT_PROTECTION: u8 = 0x04;
pub const CAT_HEADER_COMPRESSION: u8 = 0x05;
pub const CAT_MULTIPLEXING: u8 = 0x06;
pub const CAT_MEDIA_CODEC: u8 = 0x07;
pub const CAT_DELAY_REPORTING: u8 = 0x08;

// Media types (Assigned Numbers — Audio/Video Distribution).
pub const MEDIA_AUDIO: u8 = 0x00;
pub const MEDIA_VIDEO: u8 = 0x01;
pub const MEDIA_MULTIMEDIA: u8 = 0x02;

// Codec types (Assigned Numbers — Audio/Video Distribution).
pub const CODEC_SBC: u8 = 0x00;
pub const CODEC_MPEG12_AUDIO: u8 = 0x01;
pub const CODEC_MPEG24_AAC: u8 = 0x02;
pub const CODEC_ATRAC: u8 = 0x04;
pub const CODEC_NON_A2DP: u8 = 0xFF;

// SEP types (§8.20.1).
pub const SEP_TYPE_SOURCE: u8 = 0x00;
pub const SEP_TYPE_SINK: u8 = 0x01;

// Errors (§8.20.6, table 8.27 — selected).
pub const ERR_BAD_HEADER_FORMAT: u8 = 0x01;
pub const ERR_BAD_LENGTH: u8 = 0x11;
pub const ERR_BAD_ACP_SEID: u8 = 0x12;
pub const ERR_SEP_IN_USE: u8 = 0x13;
pub const ERR_SEP_NOT_IN_USE: u8 = 0x14;
pub const ERR_BAD_SERV_CATEGORY: u8 = 0x17;
pub const ERR_BAD_PAYLOAD_FORMAT: u8 = 0x18;
pub const ERR_NOT_SUPPORTED_COMMAND: u8 = 0x19;
pub const ERR_INVALID_CAPABILITIES: u8 = 0x1A;

// ── Header ─────────────────────────────────────────────────────────

/// Decoded AVDTP signalling header (1 or 2 bytes; SINGLE messages
/// have header + SID, fragmented messages have header + count).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub transaction: u8,
    pub packet_type: u8,
    pub message_type: u8,
    pub signal_id: u8,
}

impl Header {
    pub fn encode(self) -> [u8; 2] {
        let b0 = ((self.transaction & 0x0F) << 4)
            | ((self.packet_type & 0x03) << 2)
            | (self.message_type & 0x03);
        [b0, self.signal_id]
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 {
            return None;
        }
        Some(Self {
            transaction: (buf[0] >> 4) & 0x0F,
            packet_type: (buf[0] >> 2) & 0x03,
            message_type: buf[0] & 0x03,
            signal_id: buf[1],
        })
    }
}

// ── SBC Media Codec Capability (A2DP §4.3.2, table 4.1) ────────────

/// SBC sample-frequency bitmasks (high nibble of byte 0 in the codec
/// capability blob). The codec capability blob layout is:
///
/// ```text
///   byte 0:  bits[7..4] sampling frequency bitmap, bits[3..0] channel mode
///   byte 1:  bits[7..4] block length, bits[3..2] subbands, bits[1..0] allocation method
///   byte 2:  minimum bitpool (1..250)
///   byte 3:  maximum bitpool (1..250)
/// ```
pub const SBC_FREQ_16000: u8 = 1 << 7;
pub const SBC_FREQ_32000: u8 = 1 << 6;
pub const SBC_FREQ_44100: u8 = 1 << 5;
pub const SBC_FREQ_48000: u8 = 1 << 4;

pub const SBC_CHAN_MONO: u8 = 1 << 3;
pub const SBC_CHAN_DUAL: u8 = 1 << 2;
pub const SBC_CHAN_STEREO: u8 = 1 << 1;
pub const SBC_CHAN_JOINT_STEREO: u8 = 1 << 0;

pub const SBC_BLOCK_4: u8 = 1 << 7;
pub const SBC_BLOCK_8: u8 = 1 << 6;
pub const SBC_BLOCK_12: u8 = 1 << 5;
pub const SBC_BLOCK_16: u8 = 1 << 4;

pub const SBC_SUBBANDS_4: u8 = 1 << 3;
pub const SBC_SUBBANDS_8: u8 = 1 << 2;

pub const SBC_ALLOC_SNR: u8 = 1 << 1;
pub const SBC_ALLOC_LOUDNESS: u8 = 1 << 0;

/// One SBC capability descriptor (4 bytes).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SbcCapability {
    pub frequency: u8,
    pub channel_mode: u8,
    pub block_length: u8,
    pub subbands: u8,
    pub allocation: u8,
    pub min_bitpool: u8,
    pub max_bitpool: u8,
}

impl SbcCapability {
    pub fn encode(self) -> [u8; 4] {
        let b0 = (self.frequency & 0xF0) | (self.channel_mode & 0x0F);
        let b1 = (self.block_length & 0xF0) | ((self.subbands & 0x0C)) | (self.allocation & 0x03);
        [b0, b1, self.min_bitpool, self.max_bitpool]
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        Some(Self {
            frequency: buf[0] & 0xF0,
            channel_mode: buf[0] & 0x0F,
            block_length: buf[1] & 0xF0,
            subbands: buf[1] & 0x0C,
            allocation: buf[1] & 0x03,
            min_bitpool: buf[2],
            max_bitpool: buf[3],
        })
    }
}

/// Build a complete Media Codec Capability service descriptor for
/// SBC: `[CAT_MEDIA_CODEC | length | media_type | codec_type=SBC | sbc4]`.
pub fn sbc_media_codec_capability(media: u8, sbc: SbcCapability) -> Vec<u8> {
    let body = sbc.encode();
    let length = 2 + body.len() as u8; // media_type(1) + codec_type(1) + body
    let mut out = Vec::with_capacity(length as usize + 2);
    out.push(CAT_MEDIA_CODEC);
    out.push(length);
    out.push((media & 0x07) << 4);
    out.push(CODEC_SBC);
    out.extend_from_slice(&body);
    out
}

// ── Stream End Point (SEP) info ────────────────────────────────────

/// One Stream End Point as returned by Discover (§8.6, table 8.5).
/// 2 bytes per SEP:
///
/// ```text
///   byte 0: bits[7..2] = ACP SEID (1..62), bit[1] = In Use flag, bit[0] = RFU
///   byte 1: bits[7..4] = Media Type, bits[3] = TSEP (0=Source, 1=Sink), bits[2..0] = RFU
/// ```
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamEndPoint {
    pub seid: u8,
    pub in_use: bool,
    pub media_type: u8,
    pub tsep: u8,
}

impl StreamEndPoint {
    pub fn encode(self) -> [u8; 2] {
        let b0 = ((self.seid & 0x3F) << 2) | (if self.in_use { 0x02 } else { 0 });
        let b1 = ((self.media_type & 0x0F) << 4) | ((self.tsep & 0x01) << 3);
        [b0, b1]
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 {
            return None;
        }
        Some(Self {
            seid: (buf[0] >> 2) & 0x3F,
            in_use: (buf[0] & 0x02) != 0,
            media_type: (buf[1] >> 4) & 0x0F,
            tsep: (buf[1] >> 3) & 0x01,
        })
    }
}

// ── Signalling builders (single-fragment) ──────────────────────────

/// Build a Discover Command (§8.6). Returns the L2CAP payload bytes:
/// `[header_byte0, SID_DISCOVER]`.
pub fn discover_command(transaction: u8) -> Vec<u8> {
    Header {
        transaction,
        packet_type: PKT_SINGLE,
        message_type: MSG_COMMAND,
        signal_id: SID_DISCOVER,
    }
    .encode()
    .to_vec()
}

/// Build a Discover Response with the supplied SEP list (§8.6).
pub fn discover_response_accept(transaction: u8, seps: &[StreamEndPoint]) -> Vec<u8> {
    let mut out = Header {
        transaction,
        packet_type: PKT_SINGLE,
        message_type: MSG_RESPONSE_ACCEPT,
        signal_id: SID_DISCOVER,
    }
    .encode()
    .to_vec();
    for sep in seps {
        out.extend_from_slice(&sep.encode());
    }
    out
}

/// Build a Get Capabilities Command for the supplied SEID (§8.7).
pub fn get_capabilities_command(transaction: u8, acp_seid: u8) -> Vec<u8> {
    let mut out = Header {
        transaction,
        packet_type: PKT_SINGLE,
        message_type: MSG_COMMAND,
        signal_id: SID_GET_CAPABILITIES,
    }
    .encode()
    .to_vec();
    out.push((acp_seid & 0x3F) << 2);
    out
}

/// Build a Set Configuration Command (§8.9). Caller supplies the
/// catenated service-capability blob (e.g. a Media Transport entry +
/// a Media Codec entry). `acp_seid` and `int_seid` are 6-bit SEIDs.
pub fn set_configuration_command(
    transaction: u8,
    acp_seid: u8,
    int_seid: u8,
    capabilities: &[u8],
) -> Vec<u8> {
    let mut out = Header {
        transaction,
        packet_type: PKT_SINGLE,
        message_type: MSG_COMMAND,
        signal_id: SID_SET_CONFIGURATION,
    }
    .encode()
    .to_vec();
    out.push((acp_seid & 0x3F) << 2);
    out.push((int_seid & 0x3F) << 2);
    out.extend_from_slice(capabilities);
    out
}

/// Build an Open Stream Command (§8.10).
pub fn open_command(transaction: u8, acp_seid: u8) -> Vec<u8> {
    let mut out = Header {
        transaction,
        packet_type: PKT_SINGLE,
        message_type: MSG_COMMAND,
        signal_id: SID_OPEN,
    }
    .encode()
    .to_vec();
    out.push((acp_seid & 0x3F) << 2);
    out
}

/// Build a Start Stream Command (§8.13). Carries an optional list of
/// SEIDs; A2DP usually starts a single stream.
pub fn start_command(transaction: u8, acp_seids: &[u8]) -> Vec<u8> {
    let mut out = Header {
        transaction,
        packet_type: PKT_SINGLE,
        message_type: MSG_COMMAND,
        signal_id: SID_START,
    }
    .encode()
    .to_vec();
    for seid in acp_seids {
        out.push((seid & 0x3F) << 2);
    }
    out
}

/// Build a Suspend Stream Command (§8.14).
pub fn suspend_command(transaction: u8, acp_seids: &[u8]) -> Vec<u8> {
    let mut out = Header {
        transaction,
        packet_type: PKT_SINGLE,
        message_type: MSG_COMMAND,
        signal_id: SID_SUSPEND,
    }
    .encode()
    .to_vec();
    for seid in acp_seids {
        out.push((seid & 0x3F) << 2);
    }
    out
}

/// Build a Close Stream Command (§8.15).
pub fn close_command(transaction: u8, acp_seid: u8) -> Vec<u8> {
    let mut out = Header {
        transaction,
        packet_type: PKT_SINGLE,
        message_type: MSG_COMMAND,
        signal_id: SID_CLOSE,
    }
    .encode()
    .to_vec();
    out.push((acp_seid & 0x3F) << 2);
    out
}

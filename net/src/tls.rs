//! TLS 1.3 record-layer + handshake framing — clean-room.
//!
//! References (public-only):
//! - RFC 8446 — The Transport Layer Security (TLS) Protocol Version
//!   1.3 (E. Rescorla, Aug 2018). §5.1 (Record Layer — TLSPlaintext
//!   structure with type / legacy_record_version / length / fragment).
//!   §4 (Handshake Protocol — top-level type byte + 24-bit length
//!   + body). §6 (Alert Protocol — level + description).
//!     <https://datatracker.ietf.org/doc/html/rfc8446>
//! - RFC 5246 — TLS 1.2 (kept around for the legacy_record_version
//!   = 0x0303 invariant TLS 1.3 inherits).
//!   <https://datatracker.ietf.org/doc/html/rfc5246>
//!
//! No GPL Linux source consulted. **No crypto here** — this module
//! frames the byte stream so a higher-level library can plug in
//! AEAD + key schedule. The byte shapes alone are the compatibility
//! surface every TLS-aware kernel piece consumes.
//!
//! ## Record header (RFC 8446 §5.1)
//!
//! ```text
//!   byte 0      ContentType (0x14 ChangeCipherSpec, 0x15 Alert,
//!                            0x16 Handshake, 0x17 ApplicationData)
//!   bytes 1..2  legacy_record_version  — 0x0303 ("TLS 1.2")
//!   bytes 3..4  length (big-endian, ≤ 2^14 + 256 for encrypted)
//!   bytes 5..N  fragment
//! ```

extern crate alloc;

use alloc::vec::Vec;

/// TLS record header size.
pub const RECORD_HDR_LEN: usize = 5;

/// Maximum plaintext fragment size (RFC 8446 §5.1).
pub const MAX_PLAINTEXT_LEN: usize = 1 << 14;
/// Maximum ciphertext length (plaintext + 256 bytes of overhead).
pub const MAX_CIPHERTEXT_LEN: usize = (1 << 14) + 256;

// ── ContentType (RFC 8446 §B.1) ───────────────────────────────────

pub const CONTENT_TYPE_INVALID: u8 = 0;
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CONTENT_TYPE_ALERT: u8 = 21;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
pub const CONTENT_TYPE_HEARTBEAT: u8 = 24;

// ── ProtocolVersion values (RFC 8446 §B.1) ────────────────────────

pub const TLS_VERSION_TLS_1_2: u16 = 0x0303;
pub const TLS_VERSION_TLS_1_3: u16 = 0x0304;

// ── HandshakeType (RFC 8446 §B.3) ─────────────────────────────────

pub const HS_HELLO_REQUEST_RESERVED: u8 = 0;
pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;
pub const HS_NEW_SESSION_TICKET: u8 = 4;
pub const HS_END_OF_EARLY_DATA: u8 = 5;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HS_CERTIFICATE: u8 = 11;
pub const HS_CERTIFICATE_REQUEST: u8 = 13;
pub const HS_CERTIFICATE_VERIFY: u8 = 15;
pub const HS_FINISHED: u8 = 20;
pub const HS_KEY_UPDATE: u8 = 24;
pub const HS_MESSAGE_HASH: u8 = 254;

// ── AlertLevel (RFC 8446 §B.2) ────────────────────────────────────

pub const ALERT_LEVEL_WARNING: u8 = 1;
pub const ALERT_LEVEL_FATAL: u8 = 2;

// ── AlertDescription (RFC 8446 §B.2) ──────────────────────────────

pub const ALERT_CLOSE_NOTIFY: u8 = 0;
pub const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
pub const ALERT_BAD_RECORD_MAC: u8 = 20;
pub const ALERT_RECORD_OVERFLOW: u8 = 22;
pub const ALERT_HANDSHAKE_FAILURE: u8 = 40;
pub const ALERT_BAD_CERTIFICATE: u8 = 42;
pub const ALERT_UNSUPPORTED_CERTIFICATE: u8 = 43;
pub const ALERT_CERTIFICATE_REVOKED: u8 = 44;
pub const ALERT_CERTIFICATE_EXPIRED: u8 = 45;
pub const ALERT_CERTIFICATE_UNKNOWN: u8 = 46;
pub const ALERT_ILLEGAL_PARAMETER: u8 = 47;
pub const ALERT_UNKNOWN_CA: u8 = 48;
pub const ALERT_ACCESS_DENIED: u8 = 49;
pub const ALERT_DECODE_ERROR: u8 = 50;
pub const ALERT_DECRYPT_ERROR: u8 = 51;
pub const ALERT_PROTOCOL_VERSION: u8 = 70;
pub const ALERT_INSUFFICIENT_SECURITY: u8 = 71;
pub const ALERT_INTERNAL_ERROR: u8 = 80;
pub const ALERT_INAPPROPRIATE_FALLBACK: u8 = 86;
pub const ALERT_USER_CANCELED: u8 = 90;
pub const ALERT_MISSING_EXTENSION: u8 = 109;
pub const ALERT_UNSUPPORTED_EXTENSION: u8 = 110;
pub const ALERT_UNKNOWN_PSK_IDENTITY: u8 = 115;
pub const ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

// ── ExtensionType (RFC 8446 §B.4 — selected) ──────────────────────

pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_MAX_FRAGMENT_LENGTH: u16 = 1;
pub const EXT_STATUS_REQUEST: u16 = 5;
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_USE_SRTP: u16 = 14;
pub const EXT_HEARTBEAT: u16 = 15;
pub const EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 16;
pub const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 18;
pub const EXT_PADDING: u16 = 21;
pub const EXT_PRE_SHARED_KEY: u16 = 41;
pub const EXT_EARLY_DATA: u16 = 42;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_COOKIE: u16 = 44;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
pub const EXT_CERTIFICATE_AUTHORITIES: u16 = 47;
pub const EXT_OID_FILTERS: u16 = 48;
pub const EXT_POST_HANDSHAKE_AUTH: u16 = 49;
pub const EXT_SIGNATURE_ALGORITHMS_CERT: u16 = 50;
pub const EXT_KEY_SHARE: u16 = 51;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TlsError {
    Short,
    BadVersion(u16),
    /// Length field exceeds the ciphertext ceiling (RFC 8446 §5.1).
    RecordTooLong,
    /// Handshake message length field exceeds buffer.
    Truncated,
}

// ── Record ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub content_type: u8,
    pub legacy_version: u16,
    pub fragment: &'a [u8],
}

impl<'a> Record<'a> {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.content_type);
        out.extend_from_slice(&self.legacy_version.to_be_bytes());
        out.extend_from_slice(&(self.fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(self.fragment);
    }

    /// Decode a single record from the start of `buf`. Returns the
    /// record and the byte count consumed.
    pub fn decode(buf: &'a [u8]) -> Result<(Self, usize), TlsError> {
        if buf.len() < RECORD_HDR_LEN {
            return Err(TlsError::Short);
        }
        let content_type = buf[0];
        let legacy_version = u16::from_be_bytes([buf[1], buf[2]]);
        let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if length > MAX_CIPHERTEXT_LEN {
            return Err(TlsError::RecordTooLong);
        }
        if buf.len() < RECORD_HDR_LEN + length {
            return Err(TlsError::Short);
        }
        Ok((
            Self {
                content_type,
                legacy_version,
                fragment: &buf[RECORD_HDR_LEN..RECORD_HDR_LEN + length],
            },
            RECORD_HDR_LEN + length,
        ))
    }
}

// ── Handshake ──────────────────────────────────────────────────────

/// Handshake-message header: 1-byte msg_type + 24-bit BE length.
pub const HANDSHAKE_HDR_LEN: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeMessage<'a> {
    pub msg_type: u8,
    pub body: &'a [u8],
}

impl<'a> HandshakeMessage<'a> {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.msg_type);
        let len = self.body.len();
        out.push(((len >> 16) & 0xFF) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
        out.extend_from_slice(self.body);
    }

    pub fn decode(buf: &'a [u8]) -> Result<(Self, usize), TlsError> {
        if buf.len() < HANDSHAKE_HDR_LEN {
            return Err(TlsError::Short);
        }
        let msg_type = buf[0];
        let length = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
        if buf.len() < HANDSHAKE_HDR_LEN + length {
            return Err(TlsError::Truncated);
        }
        Ok((
            Self {
                msg_type,
                body: &buf[HANDSHAKE_HDR_LEN..HANDSHAKE_HDR_LEN + length],
            },
            HANDSHAKE_HDR_LEN + length,
        ))
    }
}

// ── Alert (RFC 8446 §6) ────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Alert {
    pub level: u8,
    pub description: u8,
}

impl Alert {
    pub fn encode(self) -> [u8; 2] {
        [self.level, self.description]
    }

    pub fn decode(buf: &[u8]) -> Result<Self, TlsError> {
        if buf.len() < 2 {
            return Err(TlsError::Short);
        }
        Ok(Self {
            level: buf[0],
            description: buf[1],
        })
    }
}

// ── Convenience builders ───────────────────────────────────────────

/// Wrap a Handshake message as a single TLS record. Per RFC 8446 the
/// record's `legacy_record_version` is 0x0303 ("TLS 1.2") even when
/// the negotiated version is TLS 1.3.
pub fn record_for_handshake(msg: &HandshakeMessage) -> Vec<u8> {
    let mut hs_bytes = Vec::with_capacity(HANDSHAKE_HDR_LEN + msg.body.len());
    msg.encode(&mut hs_bytes);
    let mut out = Vec::with_capacity(RECORD_HDR_LEN + hs_bytes.len());
    let rec = Record {
        content_type: CONTENT_TYPE_HANDSHAKE,
        legacy_version: TLS_VERSION_TLS_1_2,
        fragment: &hs_bytes,
    };
    rec.encode(&mut out);
    out
}

/// Wrap an Alert as a single TLS record.
pub fn record_for_alert(alert: Alert) -> Vec<u8> {
    let payload = alert.encode();
    let rec = Record {
        content_type: CONTENT_TYPE_ALERT,
        legacy_version: TLS_VERSION_TLS_1_2,
        fragment: &payload,
    };
    let mut out = Vec::with_capacity(RECORD_HDR_LEN + 2);
    rec.encode(&mut out);
    out
}

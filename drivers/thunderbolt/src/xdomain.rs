//! Host-to-host XDomain: the USB4 connection-manager-to-connection-
//! manager protocol, the XDomain property directory, and the
//! ThunderboltIP networking service bound on top of it.
//!
//! Wire formats follow the USB4 specification's XDomain chapter as
//! implemented by the reference connection manager (Linux
//! `drivers/thunderbolt/xdomain.c`, `property.c`, `tb_msgs.h`, and
//! `drivers/net/thunderbolt.c`); every constant in this module is
//! named from those sources. The fixtures in `xdomain_tests.rs` pin
//! the encodings against hand-computed vectors derived from the
//! same sources, never against this module's own output.
//!
//! Structure: a sans-IO [`Engine`] per NHI domain owns all peer
//! state. The CM loop (`topology::run`) drives it once per pass
//! through an [`XdChannel`] over ring 0 (frame kinds 6/7):
//! unsolicited packets are stepped through
//! [`Engine::handle_packet`], request/response work is issued as
//! exchanges the channel performs, and the data plane is pumped
//! through [`super::tbnet::NetLink`]. Keeping the engine free of
//! direct I/O lets the fixtures wire two engines back-to-back and
//! run discovery, login, data transfer, logout and reconnect
//! end-to-end without hardware.
//!
//! Fail-closed discipline, mirroring the reference CM: a packet
//! whose length field disagrees with its frame size is dropped
//! without state change; a properties request addressed to a
//! different domain UUID is answered `ERROR_UNKNOWN_DOMAIN`; a
//! property block with a bad magic, an out-of-bounds entry, or a
//! `VALUE` entry whose length is not 1 is rejected whole, and a
//! peer whose root directory lacks the mandatory `vendorid` /
//! `deviceid` values never becomes ready; a ThunderboltIP packet
//! whose initiator, target or route does not match the peer it
//! claims to be is ignored.

use super::{ring::Error, topology::Domain, topology::Router};
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::fmt;
use narf_lib::sync::IrqSafeSpinLock;

/// A UUID in XDomain wire order: the 16 bytes of a Linux `uuid_t`,
/// whose first three fields are little-endian in the byte array.
/// The canonical text form is only used for display.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid(pub [u8; 16]);

impl Uuid {
    /// Build from the canonical fields, applying the `uuid_t`
    /// little-endian field order used on the wire.
    pub const fn from_fields(a: u32, b: u16, c: u16, d: [u8; 8]) -> Self {
        let a = a.to_le_bytes();
        let b = b.to_le_bytes();
        let c = c.to_le_bytes();
        Self([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5],
            d[6], d[7],
        ])
    }

    /// The four dwords the UUID occupies in a packet or in a
    /// property directory header (plain little-endian dword view
    /// of the wire bytes).
    pub fn dwords(&self) -> [u32; 4] {
        let b = &self.0;
        [
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        ]
    }

    /// Inverse of [`Uuid::dwords`]; `words` must hold at least four
    /// dwords.
    pub fn from_dwords(words: &[u32]) -> Option<Self> {
        if words.len() < 4 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, word) in words[..4].iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Some(Self(bytes))
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        let a = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let mid = u16::from_le_bytes([b[4], b[5]]);
        let hi = u16::from_le_bytes([b[6], b[7]]);
        write!(
            f,
            "{a:08x}-{mid:04x}-{hi:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

/// Protocol UUID of the XDomain discovery protocol itself
/// (`tb_xdp_uuid` in the reference CM):
/// `b638d70e-42ff-40bb-97c2-90e2c0b2ff07`.
pub const XDP_PROTOCOL_UUID: Uuid = Uuid::from_fields(
    0xb638_d70e,
    0x42ff,
    0x40bb,
    [0x97, 0xc2, 0x90, 0xe2, 0xc0, 0xb2, 0xff, 0x07],
);

/// Directory UUID of the Thunderbolt networking service
/// (`tbnet_dir_uuid`): `c66189ca-1cce-4195-bdb8-49592e5f5a4f`.
pub const NETWORK_DIR_UUID: Uuid = Uuid::from_fields(
    0xc661_89ca,
    0x1cce,
    0x4195,
    [0xbd, 0xb8, 0x49, 0x59, 0x2e, 0x5f, 0x5a, 0x4f],
);

/// Protocol UUID of the ThunderboltIP service (`tbnet_svc_uuid`):
/// `798f589e-3616-8a47-97c6-5664a920c8dd`.
pub const THUNDERBOLT_IP_UUID: Uuid = Uuid::from_fields(
    0x798f_589e,
    0x3616,
    0x8a47,
    [0x97, 0xc6, 0x56, 0x64, 0xa9, 0x20, 0xc8, 0xdd],
);

/// Ring-0 frame kinds carrying XDomain traffic (`tb_cfg_pkg_type`:
/// `TB_CFG_PKG_XDOMAIN_REQ` / `TB_CFG_PKG_XDOMAIN_RESP`).
pub(crate) const PKG_XDOMAIN_REQ: u8 = 6;
pub(crate) const PKG_XDOMAIN_RESP: u8 = 7;

/// Bit 63 of a route marks a response when a packet is delivered;
/// matchers mask it on both sides (the reference CM's rule in
/// `tb_xdomain_match` / `tb_xdomain_handle_request`).
pub(crate) const ROUTE_REPLY_BIT: u64 = 1 << 63;

/// XDomain request timeout used by the reference CM for discovery
/// exchanges (`XDOMAIN_DEFAULT_TIMEOUT`, 5 s). The channel applies
/// it to every exchange, including ThunderboltIP login/logout
/// (whose reference timeouts are shorter — 500 ms / 100 ms); a
/// longer window is interop-safe because the match rule does not
/// depend on it.
pub(crate) const XDP_TIMEOUT_MS: u64 = 5000;

/// Maximum property block size, in dwords (`TB_XDOMAIN_PROPERTIES_MAX`).
pub(crate) const MAX_PROPERTY_BLOCK_DWORDS: usize = 500;

/// Property payload dwords one properties response can carry
/// (`TB_XDP_PROPERTIES_MAX_DATA_LENGTH` =
/// (256 − 4 − sizeof(properties response)) / 4 = 45).
pub(crate) const MAX_PROPERTIES_DATA_DWORDS: usize = 45;

/// `tb_xdp_type` values (discovery protocol message types).
pub(crate) const XDP_UUID_RESPONSE: u32 = 2;
pub(crate) const XDP_PROPERTIES_REQUEST: u32 = 3;
pub(crate) const XDP_PROPERTIES_RESPONSE: u32 = 4;
pub(crate) const XDP_PROPERTIES_CHANGED_REQUEST: u32 = 5;
pub(crate) const XDP_PROPERTIES_CHANGED_RESPONSE: u32 = 6;
pub(crate) const XDP_ERROR_RESPONSE: u32 = 7;
pub(crate) const XDP_UUID_REQUEST: u32 = 12;

/// `tb_xdp_error` values carried by an error response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum XdpError {
    Success,
    UnknownPacket,
    UnknownDomain,
    NotSupported,
    NotReady,
}

impl XdpError {
    pub(crate) fn code(self) -> u32 {
        match self {
            XdpError::Success => 0,
            XdpError::UnknownPacket => 1,
            XdpError::UnknownDomain => 2,
            XdpError::NotSupported => 3,
            XdpError::NotReady => 4,
        }
    }

    pub(crate) fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            0 => XdpError::Success,
            1 => XdpError::UnknownPacket,
            2 => XdpError::UnknownDomain,
            3 => XdpError::NotSupported,
            4 => XdpError::NotReady,
            _ => return None,
        })
    }
}

/// The 3-dword XDomain header (`tb_xdomain_header`): route, then
/// `length_sn` whose low 6 bits are the payload dword count after
/// the header and whose bits 27..=28 are the 2-bit sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct XdHead {
    pub route: u64,
    pub sequence: u8,
}

pub(crate) fn encode_xd_head(route: u64, sequence: u8, payload_dwords: usize) -> [u32; 3] {
    [
        (route >> 32) as u32,
        route as u32,
        (payload_dwords as u32 & 0x3f) | (((sequence & 3) as u32) << 27),
    ]
}

/// Decode and strictly validate an XDomain header: the reference
/// CM consumes and drops any packet whose length field disagrees
/// with the actual frame dword count (`size / 4 - 3 != length`).
pub(crate) fn decode_xd_head(words: &[u32]) -> Option<XdHead> {
    if words.len() < 3 {
        return None;
    }
    let payload_dwords = (words[2] & 0x3f) as usize;
    if words.len() != 3 + payload_dwords {
        return None;
    }
    Some(XdHead {
        route: ((words[0] as u64) << 32) | words[1] as u64,
        sequence: ((words[2] >> 27) & 3) as u8,
    })
}

/// The protocol UUID a packet is addressed to (XDomain header
/// dwords 3..7), if the packet is long enough to carry one.
pub(crate) fn packet_uuid(words: &[u32]) -> Option<Uuid> {
    Uuid::from_dwords(words.get(3..7)?)
}

/// Discovery-protocol (XDP) messages. Bodies follow
/// `tb_xdp_header` (XDomain header + protocol UUID + type dword)
/// plus the per-type fields of `tb_msgs.h`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum XdpMessage {
    UuidRequest,
    UuidResponse {
        src: Uuid,
    },
    PropertiesRequest {
        src: Uuid,
        dst: Uuid,
        offset: u16,
    },
    PropertiesResponse {
        src: Uuid,
        dst: Uuid,
        offset: u16,
        /// Total property block size in dwords.
        data_length: u16,
        generation: u32,
        data: Vec<u32>,
    },
    PropertiesChangedRequest {
        src: Uuid,
    },
    PropertiesChangedResponse,
    ErrorResponse {
        error: XdpError,
    },
}

impl XdpMessage {
    fn type_code(&self) -> u32 {
        match self {
            XdpMessage::UuidRequest => XDP_UUID_REQUEST,
            XdpMessage::UuidResponse { .. } => XDP_UUID_RESPONSE,
            XdpMessage::PropertiesRequest { .. } => XDP_PROPERTIES_REQUEST,
            XdpMessage::PropertiesResponse { .. } => XDP_PROPERTIES_RESPONSE,
            XdpMessage::PropertiesChangedRequest { .. } => XDP_PROPERTIES_CHANGED_REQUEST,
            XdpMessage::PropertiesChangedResponse => XDP_PROPERTIES_CHANGED_RESPONSE,
            XdpMessage::ErrorResponse { .. } => XDP_ERROR_RESPONSE,
        }
    }
}

/// Encode an XDP message as a full ring-0 packet body (dwords).
pub(crate) fn encode_xdp(route: u64, sequence: u8, msg: &XdpMessage) -> Vec<u32> {
    let mut body: Vec<u32> = Vec::new();
    match msg {
        XdpMessage::UuidRequest | XdpMessage::PropertiesChangedResponse => {}
        XdpMessage::UuidResponse { src } => body.extend_from_slice(&src.dwords()),
        XdpMessage::PropertiesRequest { src, dst, offset } => {
            body.extend_from_slice(&src.dwords());
            body.extend_from_slice(&dst.dwords());
            body.push(*offset as u32);
        }
        XdpMessage::PropertiesResponse {
            src,
            dst,
            offset,
            data_length,
            generation,
            data,
        } => {
            body.extend_from_slice(&src.dwords());
            body.extend_from_slice(&dst.dwords());
            body.push((*offset as u32) | ((*data_length as u32) << 16));
            body.push(*generation);
            body.extend_from_slice(data);
        }
        XdpMessage::PropertiesChangedRequest { src } => {
            body.extend_from_slice(&src.dwords());
        }
        XdpMessage::ErrorResponse { error } => body.push(error.code()),
    }
    let payload = 5 + body.len();
    let mut words = Vec::with_capacity(3 + payload);
    words.extend_from_slice(&encode_xd_head(route, sequence, payload));
    words.extend_from_slice(&XDP_PROTOCOL_UUID.dwords());
    words.push(msg.type_code());
    words.extend_from_slice(&body);
    words
}

/// Decode an XDP packet. Returns the header and message, or `None`
/// for anything malformed, addressed to a different protocol UUID,
/// or of an unknown type — the caller drops those without state
/// change, exactly like the reference CM's request dispatcher.
pub(crate) fn decode_xdp(words: &[u32]) -> Option<(XdHead, XdpMessage)> {
    let head = decode_xd_head(words)?;
    if packet_uuid(words)? != XDP_PROTOCOL_UUID {
        return None;
    }
    let ty = *words.get(7)?;
    let msg = match ty {
        XDP_UUID_REQUEST => {
            if words.len() != 8 {
                return None;
            }
            XdpMessage::UuidRequest
        }
        XDP_UUID_RESPONSE => {
            if words.len() != 12 {
                return None;
            }
            XdpMessage::UuidResponse {
                src: Uuid::from_dwords(&words[8..12])?,
            }
        }
        XDP_PROPERTIES_REQUEST => {
            if words.len() != 17 {
                return None;
            }
            XdpMessage::PropertiesRequest {
                src: Uuid::from_dwords(&words[8..12])?,
                dst: Uuid::from_dwords(&words[12..16])?,
                offset: (words[16] & 0xffff) as u16,
            }
        }
        XDP_PROPERTIES_RESPONSE => {
            if words.len() < 18 {
                return None;
            }
            XdpMessage::PropertiesResponse {
                src: Uuid::from_dwords(&words[8..12])?,
                dst: Uuid::from_dwords(&words[12..16])?,
                offset: (words[16] & 0xffff) as u16,
                data_length: ((words[16] >> 16) & 0xffff) as u16,
                generation: words[17],
                data: words[18..].to_vec(),
            }
        }
        XDP_PROPERTIES_CHANGED_REQUEST => {
            if words.len() != 12 {
                return None;
            }
            XdpMessage::PropertiesChangedRequest {
                src: Uuid::from_dwords(&words[8..12])?,
            }
        }
        XDP_PROPERTIES_CHANGED_RESPONSE => {
            if words.len() != 8 {
                return None;
            }
            XdpMessage::PropertiesChangedResponse
        }
        XDP_ERROR_RESPONSE => {
            if words.len() != 9 {
                return None;
            }
            XdpMessage::ErrorResponse {
                error: XdpError::from_code(words[8])?,
            }
        }
        _ => return None,
    };
    Some((head, msg))
}

// ---------------------------------------------------------------------
// XDomain property directory (the `property.c` block format).
//
// A block is a dword array. The root directory opens with the magic
// 0x55584401 and a length field counting only the entry dwords that
// follow it (4 per entry). Each entry is 4 dwords: the 8-byte key
// packed big-endian, a dword of `length:u16 | reserved:u8 |
// type:u8`, and a value dword. VALUE entries carry an immediate
// (length must be 1); DATA/TEXT entries point at their payload,
// stored big-endian per dword, in the data region right after the
// owning directory's entries; DIRECTORY entries point at a child
// directory (4-dword UUID header + entries) placed after the
// parent's data region plus one padding dword per directory entry,
// and their length counts only the child's header + entries.
// ---------------------------------------------------------------------

/// Maximum property key length in bytes (`TB_PROPERTY_KEY_SIZE`).
pub(crate) const PROP_KEY_SIZE: usize = 8;

/// Property entry type codes (`tb_property_type`).
pub(crate) const PROP_TYPE_DIRECTORY: u8 = 1;
pub(crate) const PROP_TYPE_DATA: u8 = 2;
pub(crate) const PROP_TYPE_TEXT: u8 = 3;
pub(crate) const PROP_TYPE_VALUE: u8 = 4;

const PROP_ROOT_MAGIC: u32 = 0x5558_4401;

/// One property entry's payload. `Text` holds the string bytes
/// without the terminating NUL (the formatter appends it and pads
/// to a dword boundary, like `tb_property_add_text`); `Data` holds
/// whole dwords' worth of bytes as parsed (payloads are stored
/// dword-aligned, zero-padded); `Unknown` preserves an entry of a
/// type this CM does not interpret, mirroring the reference parser,
/// which keeps such entries as `TB_PROPERTY_TYPE_UNKNOWN` instead
/// of rejecting the block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PropKind {
    Value(u32),
    Text(Vec<u8>),
    Data(Vec<u8>),
    Dir(Box<PropDir>),
    Unknown { length: u32, value: u32 },
}

/// One property directory: the root (`uuid == None`) or a service
/// directory identified by its UUID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PropDir {
    pub uuid: Option<Uuid>,
    pub entries: Vec<PropEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PropEntry {
    /// 8-byte key, ASCII, NUL-padded (`TB_PROPERTY_KEY_SIZE`).
    pub key: [u8; PROP_KEY_SIZE],
    pub kind: PropKind,
}

/// Pack a key string into its fixed 8-byte field. Keys longer than
/// the field are invalid in the reference implementation
/// (`tb_property_key_valid`); callers pass only valid literals.
pub(crate) fn prop_key(key: &str) -> [u8; PROP_KEY_SIZE] {
    let mut out = [0u8; PROP_KEY_SIZE];
    let bytes = key.as_bytes();
    let n = bytes.len().min(PROP_KEY_SIZE);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// The key as a string: bytes up to the first NUL.
pub(crate) fn prop_key_string(key: &[u8; PROP_KEY_SIZE]) -> String {
    let end = key.iter().position(|b| *b == 0).unwrap_or(PROP_KEY_SIZE);
    String::from_utf8_lossy(&key[..end]).into_owned()
}

fn prop_type_code(kind: &PropKind) -> u8 {
    match kind {
        PropKind::Dir(_) => PROP_TYPE_DIRECTORY,
        PropKind::Data(_) => PROP_TYPE_DATA,
        PropKind::Text(_) => PROP_TYPE_TEXT,
        PropKind::Value(_) => PROP_TYPE_VALUE,
        PropKind::Unknown { .. } => 0,
    }
}

fn dir_header_dwords(dir: &PropDir) -> usize {
    if dir.uuid.is_some() {
        4
    } else {
        2
    }
}

/// Dwords of payload a directory's entries occupy in its own data
/// region, including the one padding dword reserved per child
/// directory (the formatter's `data_len` accounting).
fn dir_data_dwords(dir: &PropDir) -> usize {
    dir.entries
        .iter()
        .map(|entry| match &entry.kind {
            PropKind::Text(bytes) => (bytes.len() + 1).div_ceil(4),
            PropKind::Data(bytes) => bytes.len() / 4,
            PropKind::Dir(_) => 1,
            PropKind::Value(_) | PropKind::Unknown { .. } => 0,
        })
        .sum()
}

/// Header + entries + data region of one directory, not counting
/// child directories' own extents beyond this directory's region.
fn dir_own_dwords(dir: &PropDir) -> usize {
    dir_header_dwords(dir) + 4 * dir.entries.len() + dir_data_dwords(dir)
}

/// Total formatted size of a directory tree, in dwords
/// (`tb_property_format_dir` with a null block).
pub(crate) fn prop_block_len(root: &PropDir) -> usize {
    fn total(dir: &PropDir) -> usize {
        dir_own_dwords(dir)
            + dir
                .entries
                .iter()
                .map(|entry| match &entry.kind {
                    PropKind::Dir(child) => total(child),
                    _ => 0,
                })
                .sum::<usize>()
    }
    total(root)
}

/// Write payload bytes big-endian per dword at `offset`.
fn write_be_payload(block: &mut [u32], offset: usize, bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let mut dword = [0u8; 4];
        dword[..chunk.len()].copy_from_slice(chunk);
        block[offset + i] = u32::from_be_bytes(dword);
    }
}

/// Read `dwords` of big-endian-packed payload starting at `offset`.
fn read_be_payload(block: &[u32], offset: usize, dwords: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(dwords * 4);
    for i in 0..dwords {
        out.extend_from_slice(&block[offset + i].to_be_bytes());
    }
    out
}

/// Format `dir` at `start` in `block`, returning the offset just
/// past the whole directory tree (the formatter's `dir_end`).
fn format_dir(block: &mut [u32], dir: &PropDir, start: usize) -> usize {
    let header = dir_header_dwords(dir);
    match dir.uuid {
        Some(uuid) => block[start..start + 4].copy_from_slice(&uuid.dwords()),
        None => {
            block[start] = PROP_ROOT_MAGIC;
            block[start + 1] = (4 * dir.entries.len()) as u32;
        }
    }
    let mut data_offset = start + header + 4 * dir.entries.len();
    let mut dir_end = data_offset + dir_data_dwords(dir);
    for (i, entry) in dir.entries.iter().enumerate() {
        let at = start + header + 4 * i;
        block[at] = u32::from_be_bytes([entry.key[0], entry.key[1], entry.key[2], entry.key[3]]);
        block[at + 1] =
            u32::from_be_bytes([entry.key[4], entry.key[5], entry.key[6], entry.key[7]]);
        let (length, value) = match &entry.kind {
            PropKind::Value(immediate) => (1u32, *immediate),
            PropKind::Text(bytes) => {
                let dwords = (bytes.len() + 1).div_ceil(4);
                let mut padded = bytes.clone();
                padded.resize(dwords * 4, 0);
                write_be_payload(block, data_offset, &padded);
                let value = data_offset as u32;
                data_offset += dwords;
                (dwords as u32, value)
            }
            PropKind::Data(bytes) => {
                write_be_payload(block, data_offset, bytes);
                let value = data_offset as u32;
                data_offset += bytes.len() / 4;
                (bytes.len() as u32 / 4, value)
            }
            PropKind::Dir(child) => {
                // The length counts only the child's header and
                // entries; the child itself is formatted at the
                // running dir_end and pushes it forward.
                let length = (dir_header_dwords(child) + 4 * child.entries.len()) as u32;
                let value = dir_end as u32;
                dir_end = format_dir(block, child, dir_end);
                (length, value)
            }
            PropKind::Unknown { length, value } => (*length, *value),
        };
        block[at + 2] = length | ((prop_type_code(&entry.kind) as u32) << 24);
        block[at + 3] = value;
    }
    dir_end
}

/// Format a root directory into a complete property block.
pub(crate) fn format_block(root: &PropDir) -> Vec<u32> {
    let mut block = alloc::vec![0u32; prop_block_len(root)];
    let end = format_dir(&mut block, root, 0);
    debug_assert_eq!(end, block.len());
    block
}

/// Why a property block was rejected. Parsing is fail-closed: any
/// of these rejects the whole block, like the reference parser
/// returning NULL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PropError {
    BadMagic,
    BadRootLength,
    OutOfBounds,
    BadValueLength,
}

/// Parse a complete property block into its root directory.
pub(crate) fn parse_block(block: &[u32]) -> Result<PropDir, PropError> {
    if block.len() < 2 {
        return Err(PropError::OutOfBounds);
    }
    if block[0] != PROP_ROOT_MAGIC {
        return Err(PropError::BadMagic);
    }
    let entries_dwords = block[1] as usize;
    // Stricter than the reference check (`length > block_len`):
    // the entries region must fit after the 2-dword root header.
    if entries_dwords % 4 != 0 || 2 + entries_dwords > block.len() {
        return Err(PropError::BadRootLength);
    }
    parse_dir(block, 0, entries_dwords, true)
}

fn parse_dir(
    block: &[u32],
    start: usize,
    entries_region: usize,
    is_root: bool,
) -> Result<PropDir, PropError> {
    let header = if is_root { 2 } else { 4 };
    let uuid = if is_root {
        None
    } else {
        Some(
            Uuid::from_dwords(block.get(start..start + 4).ok_or(PropError::OutOfBounds)?)
                .ok_or(PropError::OutOfBounds)?,
        )
    };
    let content = start + header;
    if content + entries_region > block.len() {
        return Err(PropError::OutOfBounds);
    }
    let mut entries = Vec::new();
    for i in 0..entries_region / 4 {
        let at = content + 4 * i;
        let raw = &block[at..at + 4];
        let mut key = [0u8; PROP_KEY_SIZE];
        key[..4].copy_from_slice(&raw[0].to_be_bytes());
        key[4..].copy_from_slice(&raw[1].to_be_bytes());
        let length = raw[2] & 0xffff;
        let ty = (raw[2] >> 24) as u8;
        let value = raw[3];
        // `tb_property_entry_valid`: directory/data/text entries
        // must point inside the block; value entries must have
        // length exactly 1.
        let kind = match ty {
            PROP_TYPE_DIRECTORY => {
                if length as usize > block.len() || value as usize + length as usize > block.len() {
                    return Err(PropError::OutOfBounds);
                }
                if length < 4 {
                    return Err(PropError::OutOfBounds);
                }
                let child = parse_dir(block, value as usize, (length - 4) as usize, false)?;
                PropKind::Dir(Box::new(child))
            }
            PROP_TYPE_DATA | PROP_TYPE_TEXT => {
                if length as usize > block.len() || value as usize + length as usize > block.len() {
                    return Err(PropError::OutOfBounds);
                }
                let mut bytes = read_be_payload(block, value as usize, length as usize);
                if ty == PROP_TYPE_TEXT {
                    // Force NUL termination, like the reference
                    // parser; the string runs to the first NUL.
                    if let Some(last) = bytes.last_mut() {
                        *last = 0;
                    }
                    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
                    bytes.truncate(end);
                    PropKind::Text(bytes)
                } else {
                    PropKind::Data(bytes)
                }
            }
            PROP_TYPE_VALUE => {
                if length != 1 {
                    return Err(PropError::BadValueLength);
                }
                PropKind::Value(value)
            }
            _ => PropKind::Unknown { length, value },
        };
        entries.push(PropEntry { key, kind });
    }
    Ok(PropDir { uuid, entries })
}

/// Find a root/directory entry by key and expected payload shape.
fn find_value(dir: &PropDir, key: &str) -> Option<u32> {
    let key = prop_key(key);
    dir.entries.iter().find_map(|entry| match entry {
        PropEntry {
            key: k,
            kind: PropKind::Value(v),
        } if *k == key => Some(*v),
        _ => None,
    })
}

fn find_text(dir: &PropDir, key: &str) -> Option<String> {
    let key = prop_key(key);
    dir.entries.iter().find_map(|entry| match entry {
        PropEntry {
            key: k,
            kind: PropKind::Text(bytes),
        } if *k == key => Some(String::from_utf8_lossy(bytes).into_owned()),
        _ => None,
    })
}

/// A peer host's identity from its root directory. The reference CM
/// refuses a peer whose root lacks the `vendorid` or `deviceid`
/// VALUE entries (`tb_xdomain_populate_properties`); so does this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostIdentity {
    pub vendor_id: u32,
    pub vendor_name: String,
    pub device_id: u32,
    pub device_name: String,
    pub device_revision: u32,
}

/// One advertised service: a DIRECTORY entry of the root, keyed by
/// name, carrying the `prtcid`/`prtcvers`/`prtcrevs`/`prtcstns`
/// protocol values of its directory (`tb_service` population).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceInfo {
    pub key: String,
    pub dir_uuid: Uuid,
    pub protocol_id: u32,
    pub protocol_version: u32,
    pub protocol_revision: u32,
    pub protocol_instances: u32,
}

pub(crate) fn host_identity(root: &PropDir) -> Option<HostIdentity> {
    Some(HostIdentity {
        vendor_id: find_value(root, "vendorid")?,
        vendor_name: find_text(root, "vendorid").unwrap_or_default(),
        device_id: find_value(root, "deviceid")?,
        device_name: find_text(root, "deviceid").unwrap_or_default(),
        device_revision: find_value(root, "devicerv").unwrap_or(0),
    })
}

pub(crate) fn services(root: &PropDir) -> Vec<ServiceInfo> {
    let mut out = Vec::new();
    for entry in &root.entries {
        let PropKind::Dir(child) = &entry.kind else {
            continue;
        };
        let Some(dir_uuid) = child.uuid else {
            continue;
        };
        // The protocol id is mandatory (the reference CM skips a
        // service directory without one); the rest default to 0.
        let Some(protocol_id) = find_value(child, "prtcid") else {
            continue;
        };
        out.push(ServiceInfo {
            key: prop_key_string(&entry.key),
            dir_uuid,
            protocol_id,
            protocol_version: find_value(child, "prtcvers").unwrap_or(0),
            protocol_revision: find_value(child, "prtcrevs").unwrap_or(0),
            protocol_instances: find_value(child, "prtcstns").unwrap_or(0),
        });
    }
    out
}

/// The networking service this CM binds: directory key `network`,
/// the Thunderbolt networking directory UUID, protocol id 1 —
/// the reference CM's `tbnet` service id.
pub(crate) fn network_service(root: &PropDir) -> Option<ServiceInfo> {
    services(root).into_iter().find(|svc| {
        svc.key == "network" && svc.dir_uuid == NETWORK_DIR_UUID && svc.protocol_id == 1
    })
}

/// `TBNET_MATCH_FRAGS_ID`: the peer fills the frame_id field of
/// ThunderboltIP data frames and expects ours filled in return.
pub(crate) const MATCH_FRAGS_ID: u32 = 1 << 1;

/// The root directory this CM advertises: host identity plus the
/// networking service directory, laid out exactly like the
/// reference CM's `tb_xdomain_init` + `tbnet` directory.
pub(crate) fn local_root(
    vendor_id: u32,
    vendor_name: &str,
    device_id: u32,
    device_name: &str,
) -> PropDir {
    let value = |key: &str, v: u32| PropEntry {
        key: prop_key(key),
        kind: PropKind::Value(v),
    };
    let text = |key: &str, s: &str| PropEntry {
        key: prop_key(key),
        kind: PropKind::Text(s.as_bytes().to_vec()),
    };
    let network = PropDir {
        uuid: Some(NETWORK_DIR_UUID),
        entries: alloc::vec![
            value("prtcid", 1),
            value("prtcvers", 1),
            value("prtcrevs", 1),
            value("prtcstns", MATCH_FRAGS_ID),
        ],
    };
    PropDir {
        uuid: None,
        entries: alloc::vec![
            value("vendorid", vendor_id),
            text("vendorid", vendor_name),
            value("deviceid", device_id),
            text("deviceid", device_name),
            // `TB_XDOMAIN_DEVICE_REVISION` in the reference CM.
            value("devicerv", 0x8000_0100),
            PropEntry {
                key: prop_key("network"),
                kind: PropKind::Dir(Box::new(network)),
            },
        ],
    }
}

/// Derive this host's XDomain UUID for one domain. The reference CM
/// uses the host router's firmware UUID; NARF's enumeration does not
/// surface one yet, so the UUID is derived deterministically from
/// the domain and the host router's PCI identity (FNV-1a expansion,
/// version/variant bits set). Uniqueness on the fabric is all the
/// protocol requires, and peers re-discover on every enumeration,
/// so boot-to-boot stability is not load-bearing.
pub(crate) fn local_uuid(domain: u32, host: &Router) -> Uuid {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |word: u32| {
        for byte in word.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    mix(domain);
    mix(host.vendor as u32);
    mix(host.device as u32);
    mix(0x4e41_5246); // "NARF"
    let mut bytes = [0u8; 16];
    let mut state = hash;
    for chunk in bytes.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid(bytes)
}

// ---------------------------------------------------------------------
// ThunderboltIP control protocol (the service protocol bound to
// the networking service directory): login/logout/status over the
// same ring-0 XDomain channel, all frame kinds
// TB_CFG_PKG_XDOMAIN_RESP in both directions (the reference CM's
// quirk: `tbnet_login_request` and `tbnet_logout_request` send and
// match on the response kind).
// ---------------------------------------------------------------------

/// ThunderboltIP protocol version (`TBIP_LOGIN_PROTO_VERSION`).
pub(crate) const TBIP_PROTO_VERSION: u32 = 1;

/// HopID a host announces for traffic addressed to its own NHI
/// (`TBNET_LOCAL_PATH`).
pub(crate) const TBIP_LOCAL_PATH: u32 = 0xf;

/// Login attempts before the session gives up (`TBNET_LOGIN_RETRIES`).
pub(crate) const TBIP_LOGIN_RETRIES: u8 = 60;
/// Logout attempts on teardown (`TBNET_LOGOUT_RETRIES`).
pub(crate) const TBIP_LOGOUT_RETRIES: u8 = 5;

/// `thunderbolt_ip_type` values.
pub(crate) const TBIP_LOGIN: u32 = 0;
pub(crate) const TBIP_LOGIN_RESPONSE: u32 = 1;
pub(crate) const TBIP_LOGOUT: u32 = 2;
pub(crate) const TBIP_STATUS: u32 = 3;

/// A decoded ThunderboltIP control message (the 17-dword
/// `thunderbolt_ip_header` plus the per-type body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IpMessage {
    Login {
        initiator: Uuid,
        target: Uuid,
        proto_version: u32,
        transmit_path: u32,
    },
    LoginResponse {
        initiator: Uuid,
        target: Uuid,
        status: u32,
        receiver_mac: [u8; 6],
        receiver_mac_len: u32,
    },
    Logout {
        initiator: Uuid,
        target: Uuid,
    },
    Status {
        initiator: Uuid,
        target: Uuid,
        status: u32,
    },
}

pub(crate) fn encode_ip(
    route: u64,
    sequence: u8,
    command_id: u32,
    initiator: Uuid,
    target: Uuid,
    msg: &IpMessage,
) -> Vec<u32> {
    let (ty, mut body): (u32, Vec<u32>) = match msg {
        IpMessage::Login {
            proto_version,
            transmit_path,
            ..
        } => (
            TBIP_LOGIN,
            alloc::vec![*proto_version, *transmit_path, 0, 0, 0, 0],
        ),
        IpMessage::LoginResponse {
            status,
            receiver_mac,
            receiver_mac_len,
            ..
        } => {
            let mut mac = [0u8; 8];
            mac[..6].copy_from_slice(receiver_mac);
            (
                TBIP_LOGIN_RESPONSE,
                alloc::vec![
                    *status,
                    u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]),
                    u32::from_le_bytes([mac[4], mac[5], mac[6], mac[7]]),
                    *receiver_mac_len,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        }
        IpMessage::Logout { .. } => (TBIP_LOGOUT, Vec::new()),
        IpMessage::Status { status, .. } => (TBIP_STATUS, alloc::vec![*status]),
    };
    let payload = 4 + 4 + 4 + 2 + body.len();
    let mut words = Vec::with_capacity(3 + payload);
    words.extend_from_slice(&encode_xd_head(route, sequence, payload));
    words.extend_from_slice(&THUNDERBOLT_IP_UUID.dwords());
    words.extend_from_slice(&initiator.dwords());
    words.extend_from_slice(&target.dwords());
    words.push(ty);
    words.push(command_id);
    words.append(&mut body);
    words
}

/// Decode a ThunderboltIP packet with strict per-type lengths;
/// anything else returns `None` and is dropped by the caller.
pub(crate) fn decode_ip(words: &[u32]) -> Option<(XdHead, u32, IpMessage)> {
    let head = decode_xd_head(words)?;
    if words.len() < 17 || packet_uuid(words)? != THUNDERBOLT_IP_UUID {
        return None;
    }
    let initiator = Uuid::from_dwords(&words[7..11])?;
    let target = Uuid::from_dwords(&words[11..15])?;
    let ty = *words.get(15)?;
    let command_id = *words.get(16)?;
    let msg = match ty {
        TBIP_LOGIN => {
            if words.len() != 23 {
                return None;
            }
            IpMessage::Login {
                initiator,
                target,
                proto_version: words[17],
                transmit_path: words[18],
            }
        }
        TBIP_LOGIN_RESPONSE => {
            if words.len() != 25 {
                return None;
            }
            let mut mac = [0u8; 6];
            mac[..4].copy_from_slice(&words[18].to_le_bytes());
            mac[4..].copy_from_slice(&words[19].to_le_bytes()[..2]);
            IpMessage::LoginResponse {
                initiator,
                target,
                status: words[17],
                receiver_mac: mac,
                receiver_mac_len: words[20],
            }
        }
        TBIP_LOGOUT => {
            if words.len() != 17 {
                return None;
            }
            IpMessage::Logout { initiator, target }
        }
        TBIP_STATUS => {
            if words.len() != 18 {
                return None;
            }
            IpMessage::Status {
                initiator,
                target,
                status: words[17],
            }
        }
        _ => return None,
    };
    Some((head, command_id, msg))
}

// ---------------------------------------------------------------------
// The per-domain XDomain engine.
// ---------------------------------------------------------------------

/// The ring-0 channel the CM loop lends the engine for one pass.
/// Production binds it to `control::Control` (frame kinds 6/7);
/// fixtures bind it to a second engine.
pub(crate) trait XdChannel {
    /// Send `words` as one frame of `kind` and return the matching
    /// response frame (kind 7, same masked route, same protocol
    /// UUID), or a transport/timeout error.
    async fn exchange(&mut self, kind: u8, words: &[u32]) -> Result<Vec<u32>, Error>;
    /// Send one frame without waiting for a response.
    async fn send(&mut self, kind: u8, words: &[u32]) -> Result<(), Error>;
    /// Take the unsolicited XDomain frames buffered since the last
    /// pass (requests from peers, unmatched packets).
    fn drain(&mut self) -> Vec<(u8, Vec<u32>)>;
}

/// What the engine wants the channel to exchange with a peer, and
/// the state-machine step the result feeds back into.
#[derive(Clone, Debug)]
pub(crate) struct Exchange {
    pub tag: ExchangeTag,
    pub kind: u8,
    pub words: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExchangeTag {
    Uuid { route: u64 },
    Properties { route: u64 },
    Login { route: u64 },
    Logout { route: u64 },
}

/// A peer host as published to the rest of the kernel: topology
/// consumers see the peer host and its services through this
/// snapshot (the "world view"), and the device-PM handler counts
/// live links through it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub domain: u32,
    pub route: u64,
    pub uuid: Uuid,
    pub identity: HostIdentity,
    pub services: Vec<ServiceInfo>,
    /// ThunderboltIP login completed in both directions.
    pub login_connected: bool,
    /// The netdev bound to this peer reports its link up (a data
    /// transport is bound and the session is connected).
    pub link_up: bool,
    /// The peer's netdev MAC, learned from its LOGIN_RESPONSE
    /// (zero until our login completes).
    pub peer_mac: [u8; 6],
    /// HopID the peer announced for traffic addressed to its NHI
    /// (the data path's transmit side once bound).
    pub transmit_path: u32,
}

static PEERS: IrqSafeSpinLock<Vec<PeerInfo>> = IrqSafeSpinLock::new(Vec::new());

/// Snapshot of every XDomain peer on every domain.
pub fn peers() -> Vec<PeerInfo> {
    PEERS.lock().clone()
}

/// Number of host-to-host links with a completed mutual
/// ThunderboltIP login. A live link holds fabric state exactly
/// like a tunnel, so `pm.rs` vetoes suspend while this is nonzero
/// (tunnel suspend/replay coordination: when the tunnel replay
/// records land, an XDomain session replays as a re-login after
/// the post-resume properties re-read, which the engine's
/// generation rule already treats as a fresh fetch).
pub(crate) fn live_link_count() -> usize {
    PEERS.lock().iter().filter(|p| p.login_connected).count()
}

/// Drop a domain's published peers (CM exit).
pub(crate) fn forget_domain(domain: u32) {
    PEERS.lock().retain(|p| p.domain != domain);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerState {
    /// UUID exchange not yet completed (or exhausted its probes
    /// for the current topology).
    Probing,
    /// UUID known; property block fetch in progress.
    FetchingProps,
    /// Properties parsed; identity and services known.
    Ready,
    /// Properties fetched but unusable (bad block, missing
    /// mandatory identity values). Never retried while the peer's
    /// generation stands.
    Rejected,
}

#[derive(Debug, Default)]
struct Session {
    login_sent: bool,
    login_received: bool,
    peer_mac: [u8; 6],
    /// HopID the peer announced for traffic to its NHI; the data
    /// path's transmit side once the NHI data rings are bound.
    transmit_path: u32,
}

#[derive(Debug)]
struct Peer {
    route: u64,
    state: PeerState,
    uuid: Option<Uuid>,
    probes: u8,
    generation: u32,
    identity: Option<HostIdentity>,
    services: Vec<ServiceInfo>,
    props_stale: bool,
    fetch_buf: Vec<u32>,
    fetch_offset: u16,
    fetch_generation: u32,
    session: Session,
    /// The peer advertises the networking service (protocol id 1)
    /// and, if so, whether it announced `MATCH_FRAGS_ID`.
    has_network: bool,
    net_match_frags: bool,
    net: Option<crate::tbnet::NetLink>,
    command_id: u32,
    login_retries: u8,
    logout_retries: u8,
    want_logout: bool,
    sequence: u8,
}

impl Peer {
    fn new(route: u64) -> Self {
        Self {
            route,
            state: PeerState::Probing,
            uuid: None,
            probes: 0,
            generation: 0,
            identity: None,
            services: Vec::new(),
            props_stale: false,
            fetch_buf: Vec::new(),
            fetch_offset: 0,
            fetch_generation: 0,
            session: Session::default(),
            has_network: false,
            net_match_frags: false,
            net: None,
            command_id: 0,
            login_retries: 0,
            logout_retries: 0,
            want_logout: false,
            sequence: 0,
        }
    }

    fn next_sequence(&mut self) -> u8 {
        let seq = self.sequence;
        self.sequence = (self.sequence + 1) & 3;
        seq
    }

    fn next_command_id(&mut self) -> u32 {
        self.command_id = self.command_id.wrapping_add(1);
        self.command_id
    }

    fn connected(&self) -> bool {
        self.session.login_sent && self.session.login_received
    }
}

/// UUID-exchange attempts per topology before a depth-1 router is
/// treated as not-a-host until the topology changes.
const MAX_PROBES: u8 = 3;
/// Exchanges issued per service pass; bounds one pass so the CM
/// loop stays responsive (a full property fetch is at most
/// 500 / 45 + 2 exchanges).
const MAX_EXCHANGES_PER_PASS: usize = 20;

#[derive(Debug)]
pub(crate) struct Engine {
    domain: u32,
    controls: u32,
    local_uuid: Option<Uuid>,
    local_block: Vec<u32>,
    local_generation: u32,
    peers: Vec<Peer>,
    topology_key: Vec<u64>,
    net_counter: u32,
}

impl Engine {
    pub(crate) fn new(domain: u32, controls: u32) -> Self {
        Self {
            domain,
            controls,
            local_uuid: None,
            local_block: Vec::new(),
            local_generation: 1,
            peers: Vec::new(),
            topology_key: Vec::new(),
            net_counter: 0,
        }
    }

    /// Whether firmware granted XDomain control for this domain.
    /// Without the grant the engine is inert: it never probes and
    /// never answers (answering would assert a control we were not
    /// given).
    fn granted(&self) -> bool {
        self.controls & super::firmware::CONTROL_XDOMAIN != 0
    }

    /// Install this host's identity (UUID + advertised property
    /// block), derived from the enumerated host router. Called by
    /// the CM loop once after the first scan.
    pub(crate) fn set_identity(&mut self, uuid: Uuid, root: PropDir) {
        self.local_block = format_block(&root);
        self.local_uuid = Some(uuid);
        self.local_generation = 1;
    }

    /// One CM pass: drain unsolicited packets, reconcile peers
    /// against the topology, run exchanges until the state machines
    /// quiesce (bounded), pump the data plane, and republish the
    /// world view. Peer-level errors are absorbed into peer state;
    /// a dead peer must never take the CM loop down with it (a dead
    /// ring still surfaces through scan/reconcile on the same pass).
    pub(crate) async fn service(&mut self, ch: &mut impl XdChannel, domain: &Domain) {
        if !self.granted() || self.local_uuid.is_none() {
            return;
        }
        for (kind, words) in ch.drain() {
            for (out_kind, out) in self.handle_packet(kind, &words) {
                let _ = ch.send(out_kind, &out).await;
            }
        }
        self.reconcile_topology(domain);
        for _ in 0..MAX_EXCHANGES_PER_PASS {
            let Some(exchange) = self.next_exchange() else {
                break;
            };
            let result = ch.exchange(exchange.kind, &exchange.words).await;
            for (out_kind, out) in self.exchange_done(&exchange, result) {
                let _ = ch.send(out_kind, &out).await;
            }
            for (kind, words) in ch.drain() {
                for (out_kind, out) in self.handle_packet(kind, &words) {
                    let _ = ch.send(out_kind, &out).await;
                }
            }
        }
        for peer in &mut self.peers {
            if let Some(net) = &mut peer.net {
                net.pump();
            }
        }
        self.sync_links();
        self.publish();
    }

    /// Reconcile the peer set against the enumerated topology:
    /// depth-1 routers are peer candidates (a peer host's router is
    /// always a direct child of ours); vanished routes lose their
    /// peer and its session on the spot.
    fn reconcile_topology(&mut self, domain: &Domain) {
        let mut routes: Vec<u64> = domain
            .routers
            .iter()
            .map(|r| r.route)
            .filter(|route| super::cm::route_depth(*route) == 1)
            .collect();
        routes.sort_unstable();
        if routes != self.topology_key {
            // New topology generation: routers that never answered
            // get a fresh set of probes.
            for peer in &mut self.peers {
                peer.probes = 0;
            }
            self.topology_key = routes.clone();
        }
        self.peers.retain(|peer| routes.contains(&peer.route));
        for route in routes {
            if !self.peers.iter().any(|p| p.route == route) {
                self.peers.push(Peer::new(route));
            }
        }
    }

    /// Step one unsolicited packet. Returns the frames to send in
    /// reply (usually zero or one). Malformed or misaddressed
    /// packets are dropped with no reply and no state change.
    pub(crate) fn handle_packet(&mut self, kind: u8, words: &[u32]) -> Vec<(u8, Vec<u32>)> {
        let mut out = Vec::new();
        if !self.granted() || self.local_uuid.is_none() {
            return out;
        }
        let Some(uuid) = packet_uuid(words) else {
            return out;
        };
        if uuid == XDP_PROTOCOL_UUID {
            // Only request-kind frames carry XDP requests; a
            // response-kind XDP frame here is an unmatched response
            // and is dropped like the reference dispatcher does.
            if kind != PKG_XDOMAIN_REQ {
                return out;
            }
            let Some((head, msg)) = decode_xdp(words) else {
                return out;
            };
            self.handle_xdp(head, msg, &mut out);
        } else if uuid == THUNDERBOLT_IP_UUID {
            let Some((head, command_id, msg)) = decode_ip(words) else {
                return out;
            };
            self.handle_ip(head, command_id, msg, &mut out);
        }
        out
    }

    fn handle_xdp(&mut self, head: XdHead, msg: XdpMessage, out: &mut Vec<(u8, Vec<u32>)>) {
        let local = self.local_uuid.unwrap_or(Uuid([0; 16]));
        // Responses carry the request's route with the reply bit
        // clear (the reference responder copies the extracted
        // route; matchers mask the bit on their side).
        let reply_route = head.route & !ROUTE_REPLY_BIT;
        match msg {
            XdpMessage::UuidRequest => {
                out.push((
                    PKG_XDOMAIN_RESP,
                    encode_xdp(
                        reply_route,
                        head.sequence,
                        &XdpMessage::UuidResponse { src: local },
                    ),
                ));
            }
            XdpMessage::PropertiesRequest { src, dst, offset } => {
                if dst != local {
                    out.push((
                        PKG_XDOMAIN_RESP,
                        encode_xdp(
                            reply_route,
                            head.sequence,
                            &XdpMessage::ErrorResponse {
                                error: XdpError::UnknownDomain,
                            },
                        ),
                    ));
                    return;
                }
                let offset = offset as usize;
                if offset >= self.local_block.len() {
                    // Invalid offset: the reference responder fails
                    // the request silently (no error packet).
                    return;
                }
                let end = (offset + MAX_PROPERTIES_DATA_DWORDS).min(self.local_block.len());
                out.push((
                    PKG_XDOMAIN_RESP,
                    encode_xdp(
                        reply_route,
                        head.sequence,
                        &XdpMessage::PropertiesResponse {
                            src: local,
                            dst: src,
                            offset: offset as u16,
                            data_length: self.local_block.len() as u16,
                            generation: self.local_generation,
                            data: self.local_block[offset..end].to_vec(),
                        },
                    ),
                ));
            }
            XdpMessage::PropertiesChangedRequest { src } => {
                out.push((
                    PKG_XDOMAIN_RESP,
                    encode_xdp(
                        reply_route,
                        head.sequence,
                        &XdpMessage::PropertiesChangedResponse,
                    ),
                ));
                if let Some(peer) = self
                    .peers
                    .iter_mut()
                    .find(|p| p.uuid == Some(src) && p.state == PeerState::Ready)
                {
                    peer.props_stale = true;
                }
            }
            // Responses and errors are exchange traffic; unsolicited
            // ones change nothing.
            _ => {}
        }
    }

    fn handle_ip(
        &mut self,
        head: XdHead,
        command_id: u32,
        msg: IpMessage,
        out: &mut Vec<(u8, Vec<u32>)>,
    ) {
        let local = self.local_uuid.unwrap_or(Uuid([0; 16]));
        let (initiator, target) = match &msg {
            IpMessage::Login {
                initiator, target, ..
            }
            | IpMessage::LoginResponse {
                initiator, target, ..
            }
            | IpMessage::Logout { initiator, target }
            | IpMessage::Status {
                initiator, target, ..
            } => (*initiator, *target),
        };
        // The reference handler ignores any packet whose initiator
        // is not the peer, whose target is not us, or whose route
        // does not match the peer's route.
        let route = head.route & !ROUTE_REPLY_BIT;
        let Some(peer) = self
            .peers
            .iter_mut()
            .find(|p| p.route == route && p.uuid == Some(initiator))
        else {
            return;
        };
        if target != local {
            return;
        }
        let reply_route = head.route & !ROUTE_REPLY_BIT;
        match msg {
            IpMessage::Login {
                proto_version,
                transmit_path,
                ..
            } => {
                // Answering requires a session context: the peer
                // must be Ready with the networking service (the
                // netdev exists), exactly like the reference handler
                // only runs on a bound, running netdev. A login for
                // an unknown protocol version is not answered
                // (version 1 is the only defined ThunderboltIP).
                if peer.state != PeerState::Ready
                    || peer.net.is_none()
                    || proto_version != TBIP_PROTO_VERSION
                {
                    return;
                }
                peer.session.login_received = true;
                peer.session.transmit_path = transmit_path;
                let mac = peer.net.as_ref().map(|n| n.mac()).unwrap_or([0; 6]);
                out.push((
                    PKG_XDOMAIN_RESP,
                    encode_ip(
                        reply_route,
                        head.sequence,
                        command_id,
                        local,
                        initiator,
                        &IpMessage::LoginResponse {
                            initiator: local,
                            target: initiator,
                            status: 0,
                            receiver_mac: mac,
                            receiver_mac_len: 6,
                        },
                    ),
                ));
            }
            IpMessage::Logout { .. } => {
                // The reference answers LOGOUT with STATUS (under a
                // fresh command id, not the request's) and then
                // tears the session down without a logout of its own.
                let status_id = peer.next_command_id();
                out.push((
                    PKG_XDOMAIN_RESP,
                    encode_ip(
                        reply_route,
                        head.sequence,
                        status_id,
                        local,
                        initiator,
                        &IpMessage::Status {
                            initiator: local,
                            target: initiator,
                            status: 0,
                        },
                    ),
                ));
                peer.session = Session::default();
            }
            // Responses belong to exchanges; unsolicited ones are
            // dropped.
            _ => {}
        }
    }

    /// The next request/response step any peer is waiting on, in
    /// peer order. `None` when every peer is quiescent.
    pub(crate) fn next_exchange(&mut self) -> Option<Exchange> {
        let local = self.local_uuid?;
        for peer in &mut self.peers {
            match peer.state {
                PeerState::Probing => {
                    if peer.probes >= MAX_PROBES {
                        continue;
                    }
                    let seq = peer.next_sequence();
                    return Some(Exchange {
                        tag: ExchangeTag::Uuid { route: peer.route },
                        kind: PKG_XDOMAIN_REQ,
                        words: encode_xdp(peer.route, seq, &XdpMessage::UuidRequest),
                    });
                }
                PeerState::FetchingProps => {
                    let Some(uuid) = peer.uuid else {
                        continue;
                    };
                    let seq = peer.next_sequence();
                    let offset = peer.fetch_offset;
                    return Some(Exchange {
                        tag: ExchangeTag::Properties { route: peer.route },
                        kind: PKG_XDOMAIN_REQ,
                        words: encode_xdp(
                            peer.route,
                            seq,
                            &XdpMessage::PropertiesRequest {
                                src: local,
                                dst: uuid,
                                offset,
                            },
                        ),
                    });
                }
                PeerState::Ready => {
                    if peer.props_stale {
                        peer.props_stale = false;
                        peer.state = PeerState::FetchingProps;
                        peer.fetch_buf.clear();
                        peer.fetch_offset = 0;
                        continue;
                    }
                    if peer.want_logout {
                        if peer.logout_retries > TBIP_LOGOUT_RETRIES {
                            // Logout unanswered after the full
                            // retry budget: tear down locally.
                            peer.want_logout = false;
                            peer.session = Session::default();
                            continue;
                        }
                        let id = peer.next_command_id();
                        let seq = peer.next_sequence();
                        let Some(uuid) = peer.uuid else {
                            continue;
                        };
                        return Some(Exchange {
                            tag: ExchangeTag::Logout { route: peer.route },
                            kind: PKG_XDOMAIN_RESP,
                            words: encode_ip(
                                peer.route,
                                seq,
                                id,
                                local,
                                uuid,
                                &IpMessage::Logout {
                                    initiator: local,
                                    target: uuid,
                                },
                            ),
                        });
                    }
                    if peer.has_network
                        && !peer.session.login_sent
                        && peer.login_retries <= TBIP_LOGIN_RETRIES
                    {
                        let id = peer.next_command_id();
                        let seq = peer.login_retries & 3;
                        let Some(uuid) = peer.uuid else {
                            continue;
                        };
                        return Some(Exchange {
                            tag: ExchangeTag::Login { route: peer.route },
                            kind: PKG_XDOMAIN_RESP,
                            words: encode_ip(
                                peer.route,
                                seq,
                                id,
                                local,
                                uuid,
                                &IpMessage::Login {
                                    initiator: local,
                                    target: uuid,
                                    proto_version: TBIP_PROTO_VERSION,
                                    transmit_path: TBIP_LOCAL_PATH,
                                },
                            ),
                        });
                    }
                }
                PeerState::Rejected => {}
            }
        }
        None
    }

    /// Feed one exchange result back into the state machines.
    /// Returns frames to send immediately (none today: every reply
    /// is produced by `handle_packet` or by a later exchange).
    pub(crate) fn exchange_done(
        &mut self,
        exchange: &Exchange,
        result: Result<Vec<u32>, Error>,
    ) -> Vec<(u8, Vec<u32>)> {
        let out = Vec::new();
        match exchange.tag {
            ExchangeTag::Uuid { route } => self.uuid_done(route, result),
            ExchangeTag::Properties { route } => self.properties_done(route, result),
            ExchangeTag::Login { route } => self.login_done(route, result),
            ExchangeTag::Logout { route } => self.logout_done(route, result),
        }
        out
    }

    fn peer_mut(&mut self, route: u64) -> Option<&mut Peer> {
        self.peers.iter_mut().find(|p| p.route == route)
    }

    fn uuid_done(&mut self, route: u64, result: Result<Vec<u32>, Error>) {
        let Ok(words) = result else {
            if let Some(peer) = self.peer_mut(route) {
                peer.probes = peer.probes.saturating_add(1);
            }
            return;
        };
        // An XDP error response also counts as a failed probe: the
        // router answered but is not (yet) a peer host.
        let Ok(peer_uuid) = (match decode_xdp(&words) {
            Some((_, XdpMessage::UuidResponse { src })) => Ok(src),
            _ => Err(()),
        }) else {
            if let Some(peer) = self.peer_mut(route) {
                peer.probes = peer.probes.saturating_add(1);
            }
            return;
        };
        if let Some(peer) = self.peer_mut(route) {
            peer.uuid = Some(peer_uuid);
            peer.state = PeerState::FetchingProps;
            peer.fetch_buf.clear();
            peer.fetch_offset = 0;
            peer.probes = 0;
        }
    }

    fn properties_done(&mut self, route: u64, result: Result<Vec<u32>, Error>) {
        let local = self.local_uuid.unwrap_or(Uuid([0; 16]));
        let Ok(words) = result else {
            // Transport failure mid-fetch: restart the fetch on the
            // next pass; a peer that never answers stays in
            // FetchingProps and its exchanges keep failing cheaply.
            if let Some(peer) = self.peer_mut(route) {
                peer.fetch_buf.clear();
                peer.fetch_offset = 0;
            }
            return;
        };
        let Some((_, msg)) = decode_xdp(&words) else {
            if let Some(peer) = self.peer_mut(route) {
                peer.fetch_buf.clear();
                peer.fetch_offset = 0;
            }
            return;
        };
        match msg {
            XdpMessage::PropertiesResponse {
                src,
                dst,
                offset,
                data_length,
                generation,
                data,
            } => {
                let Some(peer) = self.peer_mut(route) else {
                    return;
                };
                // Validate the chunk against the request and the
                // peer: wrong source/destination/offset, a total
                // length beyond the protocol maximum, or a chunk
                // that overruns the total all fail the fetch closed.
                if Some(src) != peer.uuid
                    || dst != local
                    || offset != peer.fetch_offset
                    || data_length as usize > MAX_PROPERTY_BLOCK_DWORDS
                    || offset as usize + data.len() > data_length as usize
                {
                    peer.fetch_buf.clear();
                    peer.fetch_offset = 0;
                    return;
                }
                if peer.fetch_buf.is_empty() {
                    peer.fetch_generation = generation;
                } else if generation != peer.fetch_generation {
                    peer.fetch_buf.clear();
                    peer.fetch_offset = 0;
                    return;
                }
                peer.fetch_buf.extend_from_slice(&data);
                peer.fetch_offset = peer.fetch_buf.len() as u16;
                if (peer.fetch_offset as usize) < data_length as usize {
                    return; // more chunks to fetch
                }
                let block = core::mem::take(&mut peer.fetch_buf);
                peer.fetch_offset = 0;
                self.properties_complete(route, generation, &block);
            }
            XdpMessage::ErrorResponse { .. } => {
                if let Some(peer) = self.peer_mut(route) {
                    peer.fetch_buf.clear();
                    peer.fetch_offset = 0;
                    peer.state = PeerState::Rejected;
                }
            }
            _ => {
                if let Some(peer) = self.peer_mut(route) {
                    peer.fetch_buf.clear();
                    peer.fetch_offset = 0;
                }
            }
        }
    }

    fn properties_complete(&mut self, route: u64, generation: u32, block: &[u32]) {
        // Generation rule: once properties stand, a re-read whose
        // generation did not advance is stale and ignored (the
        // reference CM rejects `generation <= current` outside the
        // resume path).
        let stands = self
            .peers
            .iter()
            .find(|p| p.route == route)
            .is_some_and(|p| p.identity.is_some());
        if stands {
            let current = self
                .peers
                .iter()
                .find(|p| p.route == route)
                .map(|p| p.generation)
                .unwrap_or(0);
            if generation <= current {
                if let Some(peer) = self.peer_mut(route) {
                    peer.state = PeerState::Ready;
                }
                return;
            }
        }
        let parsed = parse_block(block).ok().and_then(|root| {
            let identity = host_identity(&root)?;
            let services = services(&root);
            let network = network_service(&root);
            Some((identity, services, network))
        });
        // Field-level borrow (not `peer_mut`) so the netdev counter,
        // domain and local UUID stay readable below.
        let Some(peer) = self.peers.iter_mut().find(|p| p.route == route) else {
            return;
        };
        match parsed {
            Some((identity, svcs, network)) => {
                peer.identity = Some(identity);
                peer.services = svcs;
                peer.generation = generation;
                peer.state = PeerState::Ready;
                peer.has_network = network.is_some();
                peer.net_match_frags = network
                    .as_ref()
                    .map(|svc| svc.protocol_instances & MATCH_FRAGS_ID != 0)
                    .unwrap_or(false);
                // (Re)login from scratch against fresh properties.
                peer.session = Session::default();
                peer.login_retries = 0;
                if peer.has_network && peer.net.is_none() {
                    let index = self.net_counter;
                    self.net_counter += 1;
                    let name = format!("tbnet{}-{}", self.domain, index);
                    let mac = crate::tbnet::generate_mac(
                        self.local_uuid.unwrap_or(Uuid([0; 16])),
                        peer.route,
                    );
                    let match_frags = peer.net_match_frags;
                    peer.net = Some(crate::tbnet::NetLink::new(name, mac, match_frags));
                }
            }
            None => {
                peer.state = PeerState::Rejected;
            }
        }
    }

    fn login_done(&mut self, route: u64, result: Result<Vec<u32>, Error>) {
        let local = self.local_uuid.unwrap_or(Uuid([0; 16]));
        let Some(peer) = self.peer_mut(route) else {
            return;
        };
        let ok = match result {
            Ok(words) => match decode_ip(&words) {
                Some((
                    head,
                    _,
                    IpMessage::LoginResponse {
                        initiator,
                        target,
                        status,
                        receiver_mac,
                        receiver_mac_len,
                    },
                )) if initiator == peer.uuid.unwrap_or(Uuid([0; 16]))
                    && target == local
                    && status == 0
                    && (head.route & !ROUTE_REPLY_BIT) == route =>
                {
                    if receiver_mac_len == 6 {
                        peer.session.peer_mac = receiver_mac;
                    }
                    true
                }
                _ => false,
            },
            Err(_) => false,
        };
        if ok {
            peer.session.login_sent = true;
            peer.login_retries = 0;
        } else {
            peer.login_retries = peer.login_retries.saturating_add(1);
        }
    }

    fn logout_done(&mut self, route: u64, result: Result<Vec<u32>, Error>) {
        let Some(peer) = self.peer_mut(route) else {
            return;
        };
        match result {
            Ok(_) => {
                // The channel matched a STATUS-shaped response
                // (route + service UUID); the reference requester
                // likewise treats transport success as the answer.
                peer.want_logout = false;
                peer.logout_retries = 0;
                peer.session = Session::default();
            }
            Err(Error::Timeout) => {
                peer.logout_retries = peer.logout_retries.saturating_add(1);
            }
            Err(_) => {
                peer.want_logout = false;
                peer.session = Session::default();
            }
        }
    }

    /// Ask a connected peer session to log out (CM teardown of one
    /// peer, and the fixtures' link-down step). The LOGOUT exchange
    /// runs on the next service pass; an unanswering peer is torn
    /// down locally after the retry budget.
    // Used by the fixtures; production binding lands with the data transport.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) fn initiate_logout(&mut self, route: u64) {
        if let Some(peer) = self.peer_mut(route) {
            if peer.connected() {
                peer.want_logout = true;
                peer.logout_retries = 0;
            }
        }
    }

    /// Bind a data transport to a peer's netdev (the NHI data-ring
    /// binding on hardware; the in-memory pair in fixtures). Until
    /// a transport is bound the session still completes its login,
    /// but the netdev reports link down and no frames flow.
    // Used by the fixtures; production binding lands with the data transport.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) fn bind_data_link(&mut self, route: u64, link: Box<dyn crate::tbnet::DataLink>) {
        if let Some(peer) = self.peer_mut(route) {
            if let Some(net) = &mut peer.net {
                net.bind(link);
            }
        }
    }

    fn sync_links(&mut self) {
        for peer in &mut self.peers {
            let up = peer.connected();
            if let Some(net) = &mut peer.net {
                net.set_link(up);
            }
        }
    }

    fn publish(&mut self) {
        let snapshot: Vec<PeerInfo> = self
            .peers
            .iter()
            .filter(|p| p.state == PeerState::Ready)
            .filter_map(|p| {
                Some(PeerInfo {
                    domain: self.domain,
                    route: p.route,
                    uuid: p.uuid?,
                    identity: p.identity.clone()?,
                    services: p.services.clone(),
                    login_connected: p.connected(),
                    link_up: p.net.as_ref().map(|n| n.link_up()).unwrap_or(false),
                    peer_mac: p.session.peer_mac,
                    transmit_path: p.session.transmit_path,
                })
            })
            .collect();
        let mut peers = PEERS.lock();
        peers.retain(|p| p.domain != self.domain);
        peers.extend(snapshot);
    }
}

/// Derive the local identity for a domain from its first scan:
/// the host router's vendor/device identity and this CM's UUID.
pub(crate) fn local_identity(domain: &Domain) -> Option<(Uuid, PropDir)> {
    let host = domain.routers.iter().find(|r| r.route == 0)?;
    let uuid = local_uuid(domain.id, host);
    let root = local_root(host.vendor as u32, "NARF", host.device as u32, "narf-host");
    Some((uuid, root))
}

#[cfg(feature = "kernel-test")]
#[path = "xdomain_tests.rs"]
mod tests;

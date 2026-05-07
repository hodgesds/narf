//! FUSE wire-format builders for FUSE-on-virtio (virtio-fs §5.11.5).
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
//!
//! Source: public FUSE wire-protocol documentation
//! (`Documentation/filesystems/fuse.rst`-style content). The kernel
//! uapi numeric values (`FUSE_*` opcodes, the `fuse_in_header`
//! layout) are interface contract, not implementation, so they're
//! free to re-state here.
//!   <https://www.kernel.org/doc/html/latest/filesystems/fuse.html>
//!
//! `fuse_in_header` (40 bytes, all little-endian on virtio):
//!   * 0  u32 len      — total request length, including this header
//!   * 4  u32 opcode   — `FuseOpcode`
//!   * 8  u64 unique   — request id, echoed by the device on response
//!   * 16 u64 nodeid   — inode the op targets (1 = FUSE_ROOT_ID)
//!   * 24 u32 uid
//!   * 28 u32 gid
//!   * 32 u32 pid
//!   * 36 u32 padding  — reserved, MBZ
//!
//! Stage 2 ships only the in-header builder + decoder. The matching
//! `fuse_out_header` and per-op argument structs land with the
//! virtqueue submit path.

/// FUSE opcode (subset). Numeric values match the FUSE wire protocol.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FuseOpcode {
    Lookup = FUSE_LOOKUP,
    Getattr = FUSE_GETATTR,
    Read = FUSE_READ,
    Release = FUSE_RELEASE,
    Init = FUSE_INIT,
}

pub const FUSE_LOOKUP: u32 = 1;
pub const FUSE_GETATTR: u32 = 3;
pub const FUSE_READ: u32 = 15;
pub const FUSE_RELEASE: u32 = 18;
pub const FUSE_INIT: u32 = 26;

/// `fuse_in_header` size (FUSE wire docs).
pub const FUSE_IN_HEADER_LEN: usize = 40;
/// `fuse_out_header` size (FUSE wire docs): { u32 len; i32 error; u64 unique; }
pub const FUSE_OUT_HEADER_LEN: usize = 16;
/// `fuse_init_in`  size for protocol 7.x: major+minor+max_readahead+flags = 16 B.
pub const FUSE_INIT_IN_LEN: usize = 16;
/// `fuse_init_out` size for protocol 7.27: 64 B (reserved padding included).
pub const FUSE_INIT_OUT_LEN: usize = 64;
/// `fuse_read_in`  size: 40 B.
pub const FUSE_READ_IN_LEN: usize = 40;
/// `fuse_entry_out` size for current FUSE: 16 (top) + 88 (fuse_attr) = 104 B.
pub const FUSE_ENTRY_OUT_LEN: usize = 16 + 88;

/// FUSE wire-protocol version targeted by this driver.
pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 27;

/// `fuse_out_header`. Echoed by the device for every request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FuseOutHeader {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

impl FuseOutHeader {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < FUSE_OUT_HEADER_LEN {
            return None;
        }
        let r32 =
            |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        let r64 = |o: usize| {
            u64::from_le_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ])
        };
        Some(Self {
            len: r32(0),
            error: r32(4) as i32,
            unique: r64(8),
        })
    }
}

/// `fuse_init_in` payload: { u32 major; u32 minor; u32 max_readahead; u32 flags; }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

impl FuseInitIn {
    pub fn encode(&self) -> [u8; FUSE_INIT_IN_LEN] {
        let mut b = [0u8; FUSE_INIT_IN_LEN];
        b[0..4].copy_from_slice(&self.major.to_le_bytes());
        b[4..8].copy_from_slice(&self.minor.to_le_bytes());
        b[8..12].copy_from_slice(&self.max_readahead.to_le_bytes());
        b[12..16].copy_from_slice(&self.flags.to_le_bytes());
        b
    }
}

/// `fuse_init_out` (protocol 7.27): we keep just the leading fields
/// the driver actually surfaces; trailing reserved padding is read
/// past but discarded.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct FuseInitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub padding: u16,
}

impl FuseInitOut {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 {
            return None;
        }
        let r16 = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        let r32 =
            |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        Some(Self {
            major: r32(0),
            minor: r32(4),
            max_readahead: r32(8),
            flags: r32(12),
            max_background: r16(16),
            congestion_threshold: r16(18),
            max_write: r32(20),
            time_gran: if bytes.len() >= 28 { r32(24) } else { 0 },
            max_pages: if bytes.len() >= 30 { r16(28) } else { 0 },
            padding: if bytes.len() >= 32 { r16(30) } else { 0 },
        })
    }
}

/// `fuse_read_in` payload (40 B).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FuseReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

impl FuseReadIn {
    pub fn encode(&self) -> [u8; FUSE_READ_IN_LEN] {
        let mut b = [0u8; FUSE_READ_IN_LEN];
        b[0..8].copy_from_slice(&self.fh.to_le_bytes());
        b[8..16].copy_from_slice(&self.offset.to_le_bytes());
        b[16..20].copy_from_slice(&self.size.to_le_bytes());
        b[20..24].copy_from_slice(&self.read_flags.to_le_bytes());
        b[24..32].copy_from_slice(&self.lock_owner.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.padding.to_le_bytes());
        b
    }
}

/// `fuse_entry_out` (104 B). Surfaced as raw bytes; callers can
/// pluck out `nodeid` (offset 0, u64) etc.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct FuseEntryOut {
    pub nodeid: u64,
    pub generation: u64,
}

impl FuseEntryOut {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let r64 = |o: usize| {
            u64::from_le_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ])
        };
        Some(Self {
            nodeid: r64(0),
            generation: r64(8),
        })
    }
}

/// FUSE root inode id.
pub const FUSE_ROOT_ID: u64 = 1;

/// In-memory shape of `fuse_in_header`. Stored host-endian; the
/// `encode` / `decode` helpers convert to/from on-wire little-endian.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub padding: u32,
}

impl FuseInHeader {
    /// Build a header for `opcode` with a payload of `payload_len`
    /// bytes following. `len` is set to header + payload.
    pub fn new(
        opcode: FuseOpcode,
        unique: u64,
        nodeid: u64,
        uid: u32,
        gid: u32,
        pid: u32,
        payload_len: u32,
    ) -> Self {
        Self {
            len: FUSE_IN_HEADER_LEN as u32 + payload_len,
            opcode: opcode as u32,
            unique,
            nodeid,
            uid,
            gid,
            pid,
            padding: 0,
        }
    }

    /// Serialize to 40 little-endian bytes.
    pub fn encode(&self) -> [u8; FUSE_IN_HEADER_LEN] {
        let mut b = [0u8; FUSE_IN_HEADER_LEN];
        b[0..4].copy_from_slice(&self.len.to_le_bytes());
        b[4..8].copy_from_slice(&self.opcode.to_le_bytes());
        b[8..16].copy_from_slice(&self.unique.to_le_bytes());
        b[16..24].copy_from_slice(&self.nodeid.to_le_bytes());
        b[24..28].copy_from_slice(&self.uid.to_le_bytes());
        b[28..32].copy_from_slice(&self.gid.to_le_bytes());
        b[32..36].copy_from_slice(&self.pid.to_le_bytes());
        b[36..40].copy_from_slice(&self.padding.to_le_bytes());
        b
    }

    /// Deserialize from a 40-byte little-endian slice. Returns `None`
    /// when the slice is too short.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < FUSE_IN_HEADER_LEN {
            return None;
        }
        let r32 =
            |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        let r64 = |o: usize| {
            u64::from_le_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ])
        };
        Some(Self {
            len: r32(0),
            opcode: r32(4),
            unique: r64(8),
            nodeid: r64(16),
            uid: r32(24),
            gid: r32(28),
            pid: r32(32),
            padding: r32(36),
        })
    }
}

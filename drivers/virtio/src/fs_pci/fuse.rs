//! FUSE wire-format builders for FUSE-on-virtio (virtio-fs §5.11.5).
//!
//! Source: public FUSE wire-protocol documentation
//! (`Documentation/filesystems/fuse.rst`-style content). The kernel
//! uapi numeric values (`FUSE_*` opcodes, the `fuse_in_header`
//! layout) are interface contract, not implementation, so they're
//! free to re-state here.
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
    Lookup  = FUSE_LOOKUP,
    Getattr = FUSE_GETATTR,
    Read    = FUSE_READ,
    Release = FUSE_RELEASE,
    Init    = FUSE_INIT,
}

pub const FUSE_LOOKUP:  u32 = 1;
pub const FUSE_GETATTR: u32 = 3;
pub const FUSE_READ:    u32 = 15;
pub const FUSE_RELEASE: u32 = 18;
pub const FUSE_INIT:    u32 = 26;

/// `fuse_in_header` size (FUSE wire docs).
pub const FUSE_IN_HEADER_LEN: usize = 40;

/// In-memory shape of `fuse_in_header`. Stored host-endian; the
/// `encode` / `decode` helpers convert to/from on-wire little-endian.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FuseInHeader {
    pub len:    u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid:    u32,
    pub gid:    u32,
    pub pid:    u32,
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
            len:     FUSE_IN_HEADER_LEN as u32 + payload_len,
            opcode:  opcode as u32,
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
        if bytes.len() < FUSE_IN_HEADER_LEN { return None; }
        let r32 = |o: usize| u32::from_le_bytes([
            bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3],
        ]);
        let r64 = |o: usize| u64::from_le_bytes([
            bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3],
            bytes[o + 4], bytes[o + 5], bytes[o + 6], bytes[o + 7],
        ]);
        Some(Self {
            len:     r32(0),
            opcode:  r32(4),
            unique:  r64(8),
            nodeid:  r64(16),
            uid:     r32(24),
            gid:     r32(28),
            pid:     r32(32),
            padding: r32(36),
        })
    }
}

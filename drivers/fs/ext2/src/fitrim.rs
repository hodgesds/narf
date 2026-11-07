//! FITRIM (`fstrim`) wire format — the first discard caller (#1166).
//!
//! Clean-room implementation. The ioctl number and the `fstrim_range`
//! layout trace back to one public reference only — the Linux UAPI
//! header `include/uapi/linux/fs.h`:
//!
//! ```c
//! struct fstrim_range {
//!     __u64 start;
//!     __u64 len;
//!     __u64 minlen;
//! };
//! #define FITRIM _IOWR('X', 121, struct fstrim_range) /* Trim */
//! ```
//!
//! `_IOWR('X', 121, 24 bytes)` encodes as `0xC018_5879` (verified
//! against `/usr/include/linux/fs.h` on the build host: the header
//! carries the same `#define`, and the `_IOC` arithmetic —
//! dir `READ|WRITE` = 3, size 24, type `'X'` = 0x58, nr 121 —
//! yields exactly that word). No other Linux source was consulted.
//!
//! Semantics (Linux `fs/ioctl.c::do_vfs_ioctl` + `ext4_trim_fs`,
//! as implemented in [`super::volume::Ext2Volume::fitrim`]):
//! `start`/`len`/`minlen` are bytes; on success the `len` field
//! comes back holding the number of bytes actually trimmed. Only
//! whole filesystem blocks fully inside `[start, start + len)`
//! are candidates, and a contiguous free run is discarded only
//! when it is at least `minlen` bytes long.

use narf_filesystem::FsError;

/// Linux FITRIM ioctl number — `_IOWR('X', 121, struct fstrim_range)`.
pub const FITRIM: u32 = 0xC018_5879;

/// Wire size of `struct fstrim_range`: three little-endian `u64`s.
pub const FSTRIM_RANGE_LEN: usize = 24;

/// Decoded `struct fstrim_range`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FstrimRange {
    /// First byte to consider trimming (inclusive).
    pub start: u64,
    /// Length of the byte range to consider. On success the caller
    /// overwrites this with the bytes actually trimmed.
    pub len: u64,
    /// Minimum contiguous free run (bytes) worth discarding.
    pub minlen: u64,
}

impl FstrimRange {
    /// Decode the 24-byte little-endian wire image. Pure over the
    /// byte image so kernel tests can pin the layout without a user
    /// pointer (same pattern as the uinput-setup decoder in
    /// `narf_filesystem::devfs_input`).
    pub fn decode(image: &[u8]) -> Result<Self, FsError> {
        if image.len() < FSTRIM_RANGE_LEN {
            return Err(FsError::InvalidData);
        }
        let u64le =
            |off: usize| u64::from_le_bytes(image[off..off + 8].try_into().expect("24-byte image"));
        Ok(Self {
            start: u64le(0),
            len: u64le(8),
            minlen: u64le(16),
        })
    }

    /// Encode to the 24-byte little-endian wire image.
    pub fn encode(&self) -> [u8; FSTRIM_RANGE_LEN] {
        let mut out = [0u8; FSTRIM_RANGE_LEN];
        out[0..8].copy_from_slice(&self.start.to_le_bytes());
        out[8..16].copy_from_slice(&self.len.to_le_bytes());
        out[16..24].copy_from_slice(&self.minlen.to_le_bytes());
        out
    }
}

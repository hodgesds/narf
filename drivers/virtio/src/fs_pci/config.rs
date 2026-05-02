//! virtio-fs device-specific config (VirtIO 1.2 §5.11.4).
//!
//! Layout (little-endian):
//!   * offset 0  : `tag[36]: u8` — UTF-8 mount tag, NUL-padded.
//!   * offset 36 : `num_request_queues: u32 LE` — number of request
//!     virtqueues. Total queues on the device = 1 (hiprio) +
//!     num_request_queues.
//!
//! Decoder is pure data — no MMIO. The `VirtioRegion` reader path
//! lands with the live transport bring-up in a later stage.

/// 1AF4:105A — modern virtio-fs (virtio device type 26, §4.1.2:
/// modern PCI device id = 0x1040 + virtio_device_id).
pub const VIRTIO_FS_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_FS_PCI_DEVICE: u16 = 0x105A;

/// `tag` field width per §5.11.4.
pub const FS_TAG_LEN: usize = 36;

/// Total length of the device-specific config struct.
pub const FS_CONFIG_LEN: usize = FS_TAG_LEN + 4;

/// Decoded device-specific config. `tag_len` is the NUL-trimmed byte
/// length of the tag; bytes past `tag_len` in `tag` are zero.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FsConfig {
    pub tag:                [u8; FS_TAG_LEN],
    pub tag_len:            usize,
    pub num_request_queues: u32,
}

impl FsConfig {
    /// Tag as a `&str` if the populated prefix is valid UTF-8.
    pub fn tag_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.tag[..self.tag_len]).ok()
    }
}

/// Decode a 40-byte slice in the layout of §5.11.4. Returns `None`
/// when the slice is too short.
pub fn decode_device_config(bytes: &[u8]) -> Option<FsConfig> {
    if bytes.len() < FS_CONFIG_LEN { return None; }
    let mut tag = [0u8; FS_TAG_LEN];
    tag.copy_from_slice(&bytes[..FS_TAG_LEN]);
    // NUL-trim: tag_len = position of first NUL, or FS_TAG_LEN if none.
    let tag_len = tag.iter().position(|&b| b == 0).unwrap_or(FS_TAG_LEN);
    let nrq = u32::from_le_bytes([
        bytes[FS_TAG_LEN],
        bytes[FS_TAG_LEN + 1],
        bytes[FS_TAG_LEN + 2],
        bytes[FS_TAG_LEN + 3],
    ]);
    Some(FsConfig { tag, tag_len, num_request_queues: nrq })
}

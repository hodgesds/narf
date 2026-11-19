//! DRM HDR_OUTPUT_METADATA connector property blob (drm_mode.h).

/// sizeof(struct hdr_output_metadata): a u32 descriptor ID and the 26-byte
/// `hdr_metadata_infoframe`, padded to the u32's alignment.
pub const HDR_OUTPUT_METADATA_SIZE: usize = 32;

/// The blob is not a `struct hdr_output_metadata` (Linux: -EINVAL).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidBlob;

/// uapi `struct hdr_metadata_infoframe`, CTA-861-G's static metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HdrMetadataInfoframe {
    pub eotf: u8,
    pub metadata_type: u8,
    /// (x, y) per primary, in units of 0.00002.
    pub display_primaries: [(u16, u16); 3],
    pub white_point: (u16, u16),
    pub max_display_mastering_luminance: u16,
    pub min_display_mastering_luminance: u16,
    pub max_cll: u16,
    pub max_fall: u16,
}

/// uapi `struct hdr_output_metadata` as userspace lays it out (native,
/// little-endian on every narf target).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HdrOutputMetadata {
    /// The outer descriptor ID. DRM and amdgpu_dm never look at it.
    pub metadata_type: u32,
    pub hdmi_metadata_type1: HdrMetadataInfoframe,
}

impl HdrOutputMetadata {
    /// Decode an `HDR_OUTPUT_METADATA` blob. drm_property_replace_blob_from_id
    /// takes it only when its length is exactly
    /// `HDR_OUTPUT_METADATA_SIZE`; nothing about the values is checked (the
    /// padding is ignored).
    pub fn from_blob(blob: &[u8]) -> Result<Self, InvalidBlob> {
        if blob.len() != HDR_OUTPUT_METADATA_SIZE {
            return Err(InvalidBlob);
        }
        let u16_at = |at: usize| u16::from_le_bytes([blob[at], blob[at + 1]]);
        let pair = |at: usize| (u16_at(at), u16_at(at + 2));
        Ok(Self {
            metadata_type: u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]),
            hdmi_metadata_type1: HdrMetadataInfoframe {
                eotf: blob[4],
                metadata_type: blob[5],
                display_primaries: [pair(6), pair(10), pair(14)],
                white_point: pair(18),
                max_display_mastering_luminance: u16_at(22),
                min_display_mastering_luminance: u16_at(24),
                max_cll: u16_at(26),
                max_fall: u16_at(28),
            },
        })
    }
}

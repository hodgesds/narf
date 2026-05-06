//! VESA Display Stream Compression (DSC) PPS codec — clean-room.
//!
//! References (public-only):
//! - "VESA Display Stream Compression (DSC) Standard, Version 1.2a"
//!   (Jan 2017) — VESA. Public document.
//!   §3.4 (Picture Parameter Set / PPS — 128-byte register block sent
//!   to the decoder over the side-band before each compressed image).
//!   §3.5 (Rate Control parameters — `rc_buf_thresh[14]`,
//!   `rc_range_parameters[15]`).
//!   §4.2 (slice partitioning + slice height/width constraints).
//! - "VESA DisplayPort Standard, Version 1.4a" — VESA. Public.
//!   §3.5.5 references how DSC PPSes are conveyed in the DP SDP
//!   (Secondary Data Packet) stream that precedes a compressed
//!   video frame.
//!
//! No GPL Linux source consulted.
//!
//! ## PPS layout (DSC 1.2a §3.4, table 3-2)
//!
//! 128 bytes, big-endian where multi-byte fields appear (the spec
//! is explicit per §3.4 that all multi-byte numerics in the PPS are
//! big-endian). Only the most commonly-driven fields are surfaced
//! here:
//!
//! ```text
//!   byte 0     dsc_version_minor (low 4 bits) | dsc_version_major (high 4 bits)
//!   byte 1     pps_identifier
//!   byte 2     reserved
//!   byte 3     bits_per_component (low 4 bits) | linebuf_depth (high 4 bits)
//!   byte 4     bits_per_pixel high byte (10 bits split across 4..5)
//!   byte 5     bits_per_pixel low byte
//!   bytes 6..7 pic_height
//!   bytes 8..9 pic_width
//!   bytes 10..11 slice_height
//!   bytes 12..13 slice_width
//!   ...
//!   byte 88..117  rc_buf_thresh[14] + rc_range_parameters[15] block
//!   ...
//! ```

/// Size of the Picture Parameter Set in bytes.
pub const DSC_PPS_SIZE: usize = 128;

/// Number of RC buffer thresholds (DSC 1.2a §3.5).
pub const DSC_RC_BUF_THRESH_COUNT: usize = 14;

/// Number of RC range-parameter entries (DSC 1.2a §3.5).
pub const DSC_RC_RANGE_PARAMS_COUNT: usize = 15;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DscError {
    /// PPS buffer must be exactly 128 bytes.
    BadLength,
    /// `dsc_version_major` is not 1 or 2.
    BadVersion,
}

/// Decoded subset of the Picture Parameter Set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pps {
    pub dsc_version_major: u8,
    pub dsc_version_minor: u8,
    pub pps_identifier: u8,
    /// Bits-per-component (commonly 8, 10, 12, or 16). 4 bits wide.
    pub bits_per_component: u8,
    /// Line buffer depth in bits (typically 8..13). 4 bits wide.
    pub linebuf_depth: u8,
    /// `bits_per_pixel` × 16 — the spec encodes BPP in 1/16 units to
    /// keep it integer. So a 8.000 bpp setting is stored as 128.
    pub bits_per_pixel: u16,
    pub pic_height: u16,
    pub pic_width: u16,
    pub slice_height: u16,
    pub slice_width: u16,
    /// `chunk_size` — bytes per slice column (used by the DP DSC
    /// secondary-data-packet packer).
    pub chunk_size: u16,
    /// Initial `dec_delay`, `initial_xmit_delay`, `initial_dec_delay`
    /// fields packed together — the host typically picks these from
    /// the spec's recommended-table profile.
    pub initial_xmit_delay: u16,
    pub initial_dec_delay: u16,
    pub initial_scale_value: u8,
    pub scale_increment_interval: u16,
    pub scale_decrement_interval: u16,
    pub first_line_bpg_offset: u8,
    pub nfl_bpg_offset: u16,
    pub slice_bpg_offset: u16,
    pub initial_offset: u16,
    pub final_offset: u16,
    pub flatness_min_qp: u8,
    pub flatness_max_qp: u8,
    pub rc_model_size: u16,
    pub rc_buf_thresh: [u8; DSC_RC_BUF_THRESH_COUNT],
    /// Each entry is a 16-bit packed value: bits 15..11 = range_bpg_offset (5b signed),
    /// bits 10..6 = range_max_qp, bits 5..0 = range_min_qp.
    pub rc_range_parameters: [u16; DSC_RC_RANGE_PARAMS_COUNT],
}

impl Pps {
    /// Parse a 128-byte PPS into a decoded view.
    pub fn parse(buf: &[u8]) -> Result<Self, DscError> {
        if buf.len() != DSC_PPS_SIZE {
            return Err(DscError::BadLength);
        }
        let dsc_version_major = (buf[0] >> 4) & 0x0F;
        let dsc_version_minor = buf[0] & 0x0F;
        if dsc_version_major == 0 || dsc_version_major > 2 {
            return Err(DscError::BadVersion);
        }

        let bits_per_component = buf[3] & 0x0F;
        let linebuf_depth = (buf[3] >> 4) & 0x0F;
        // bits_per_pixel is 10 bits: high 2 bits in buf[4][1..0],
        // low 8 bits in buf[5].
        let bits_per_pixel = (((buf[4] & 0x03) as u16) << 8) | buf[5] as u16;

        let pic_height = u16::from_be_bytes([buf[6], buf[7]]);
        let pic_width = u16::from_be_bytes([buf[8], buf[9]]);
        let slice_height = u16::from_be_bytes([buf[10], buf[11]]);
        let slice_width = u16::from_be_bytes([buf[12], buf[13]]);
        let chunk_size = u16::from_be_bytes([buf[14], buf[15]]);
        // bytes 16..17 reserved
        let initial_xmit_delay = u16::from_be_bytes([buf[18] & 0x03, buf[19]]);
        let initial_dec_delay = u16::from_be_bytes([buf[20], buf[21]]);
        // byte 22 reserved
        let initial_scale_value = buf[23] & 0x3F;
        let scale_increment_interval = u16::from_be_bytes([buf[24], buf[25]]);
        let scale_decrement_interval = u16::from_be_bytes([buf[26] & 0x0F, buf[27]]);
        // byte 28 reserved
        let first_line_bpg_offset = buf[29] & 0x1F;
        let nfl_bpg_offset = u16::from_be_bytes([buf[30], buf[31]]);
        let slice_bpg_offset = u16::from_be_bytes([buf[32], buf[33]]);
        let initial_offset = u16::from_be_bytes([buf[34], buf[35]]);
        let final_offset = u16::from_be_bytes([buf[36], buf[37]]);
        let flatness_min_qp = buf[38] & 0x1F;
        let flatness_max_qp = buf[39] & 0x1F;
        let rc_model_size = u16::from_be_bytes([buf[40], buf[41]]);
        // bytes 42..56 reserved
        let mut rc_buf_thresh = [0u8; DSC_RC_BUF_THRESH_COUNT];
        rc_buf_thresh.copy_from_slice(&buf[57..57 + DSC_RC_BUF_THRESH_COUNT]);
        let mut rc_range_parameters = [0u16; DSC_RC_RANGE_PARAMS_COUNT];
        for i in 0..DSC_RC_RANGE_PARAMS_COUNT {
            let off = 88 + i * 2;
            rc_range_parameters[i] = u16::from_be_bytes([buf[off], buf[off + 1]]);
        }

        Ok(Self {
            dsc_version_major,
            dsc_version_minor,
            pps_identifier: buf[1],
            bits_per_component,
            linebuf_depth,
            bits_per_pixel,
            pic_height,
            pic_width,
            slice_height,
            slice_width,
            chunk_size,
            initial_xmit_delay,
            initial_dec_delay,
            initial_scale_value,
            scale_increment_interval,
            scale_decrement_interval,
            first_line_bpg_offset,
            nfl_bpg_offset,
            slice_bpg_offset,
            initial_offset,
            final_offset,
            flatness_min_qp,
            flatness_max_qp,
            rc_model_size,
            rc_buf_thresh,
            rc_range_parameters,
        })
    }

    /// Convenience: bits_per_pixel as a fractional value
    /// (the spec stores BPP × 16; we return integer + fractional/16).
    pub fn bpp_integer_part(&self) -> u16 {
        self.bits_per_pixel >> 4
    }
    pub fn bpp_fractional_sixteenths(&self) -> u8 {
        (self.bits_per_pixel & 0x0F) as u8
    }

    /// Encode this PPS back into a 128-byte buffer. The encoder fills
    /// only the fields surfaced above; everything else stays 0
    /// (matches the spec's "RFU = 0" requirement).
    pub fn encode(&self) -> [u8; DSC_PPS_SIZE] {
        let mut buf = [0u8; DSC_PPS_SIZE];
        buf[0] = ((self.dsc_version_major & 0x0F) << 4) | (self.dsc_version_minor & 0x0F);
        buf[1] = self.pps_identifier;
        buf[3] = ((self.linebuf_depth & 0x0F) << 4) | (self.bits_per_component & 0x0F);
        buf[4] = ((self.bits_per_pixel >> 8) & 0x03) as u8;
        buf[5] = (self.bits_per_pixel & 0xFF) as u8;
        buf[6..8].copy_from_slice(&self.pic_height.to_be_bytes());
        buf[8..10].copy_from_slice(&self.pic_width.to_be_bytes());
        buf[10..12].copy_from_slice(&self.slice_height.to_be_bytes());
        buf[12..14].copy_from_slice(&self.slice_width.to_be_bytes());
        buf[14..16].copy_from_slice(&self.chunk_size.to_be_bytes());
        buf[18..20].copy_from_slice(&self.initial_xmit_delay.to_be_bytes());
        buf[18] &= 0x03;
        buf[20..22].copy_from_slice(&self.initial_dec_delay.to_be_bytes());
        buf[23] = self.initial_scale_value & 0x3F;
        buf[24..26].copy_from_slice(&self.scale_increment_interval.to_be_bytes());
        buf[26..28].copy_from_slice(&self.scale_decrement_interval.to_be_bytes());
        buf[26] &= 0x0F;
        buf[29] = self.first_line_bpg_offset & 0x1F;
        buf[30..32].copy_from_slice(&self.nfl_bpg_offset.to_be_bytes());
        buf[32..34].copy_from_slice(&self.slice_bpg_offset.to_be_bytes());
        buf[34..36].copy_from_slice(&self.initial_offset.to_be_bytes());
        buf[36..38].copy_from_slice(&self.final_offset.to_be_bytes());
        buf[38] = self.flatness_min_qp & 0x1F;
        buf[39] = self.flatness_max_qp & 0x1F;
        buf[40..42].copy_from_slice(&self.rc_model_size.to_be_bytes());
        buf[57..57 + DSC_RC_BUF_THRESH_COUNT].copy_from_slice(&self.rc_buf_thresh);
        for i in 0..DSC_RC_RANGE_PARAMS_COUNT {
            let off = 88 + i * 2;
            buf[off..off + 2].copy_from_slice(&self.rc_range_parameters[i].to_be_bytes());
        }
        buf
    }
}

/// Pack one rc_range_parameters[] entry from its three fields
/// (DSC 1.2a §3.5, table 3-3): a 5-bit signed bpg-offset, 5-bit
/// max-qp, 5-bit min-qp. Bit layout per spec is
/// `bpg_offset[5] | max_qp[5] | min_qp[5]` packed left-aligned in 16
/// bits.
pub const fn pack_range_parameter(bpg_offset: i8, max_qp: u8, min_qp: u8) -> u16 {
    let bpg = (bpg_offset as u8) & 0x1F;
    ((bpg as u16) << 11) | (((max_qp & 0x1F) as u16) << 6) | (min_qp & 0x3F) as u16
}

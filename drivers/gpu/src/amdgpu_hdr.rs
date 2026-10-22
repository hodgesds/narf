//! HDR output metadata and output colorimetry, packed as Linux packs them for
//! DCN (no hardware access here):
//!
//! - the DRM `HDR_OUTPUT_METADATA` blob (uapi `struct hdr_output_metadata`,
//!   exactly 32 bytes as drm_atomic_connector_set_property requires) and
//!   drm_connector_atomic_hdr_metadata_equal;
//! - the CTA-861 Dynamic Range and Mastering InfoFrame:
//!   drm_hdmi_infoframe_set_hdr_metadata, hdmi_drm_infoframe_pack_only, then
//!   amdgpu_dm_fill_hdr_info_packet's HDMI InfoFrame or DP HDR SDP header;
//! - the sink's HDR Static Metadata Data Block (drm_parse_hdr_metadata_block);
//! - the "Colorspace" connector property amdgpu_dm creates, its mapping to a
//!   DC color space (amdgpu_dm_get_output_color_space), and how DC signals
//!   that color space: set_avi_info_frame's C/EC/Q/YQ, the DCN401 DIO
//!   stream encoder's MSA MISC0/MISC1 and mod_build_vsc_infopacket's VSC SDP.
//!
//! `tests/dcn401_hdr/check.sh` compiles those Linux functions on the host
//! and `tests/dcn401_hdr/vectors.txt` holds their answers, which the kernel
//! tests replay against this module.

/// sizeof(struct hdr_output_metadata): a u32 descriptor ID and the 26-byte
/// `hdr_metadata_infoframe`, padded to the u32's alignment.
pub const HDR_OUTPUT_METADATA_SIZE: usize = 32;
/// HDMI_STATIC_METADATA_TYPE1, the only Static_Metadata_Descriptor_ID.
pub const HDMI_STATIC_METADATA_TYPE1: u8 = 0;
/// enum hdmi_eotf.
pub const HDMI_EOTF_TRADITIONAL_GAMMA_SDR: u8 = 0;
pub const HDMI_EOTF_TRADITIONAL_GAMMA_HDR: u8 = 1;
pub const HDMI_EOTF_SMPTE_ST2084: u8 = 2;
pub const HDMI_EOTF_BT_2100_HLG: u8 = 3;
/// HDMI_INFOFRAME_TYPE_DRM.
pub const HDMI_INFOFRAME_TYPE_DRM: u8 = 0x87;
/// HDMI_DRM_INFOFRAME_SIZE (payload bytes).
pub const HDMI_DRM_INFOFRAME_SIZE: u8 = 26;

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

/// drm_connector_atomic_hdr_metadata_equal: both absent, or blobs of the
/// same length and bytes.
pub fn metadata_equal(old: Option<&[u8]>, new: Option<&[u8]>) -> bool {
    match (old, new) {
        (Some(a), Some(b)) => a == b,
        (a, b) => a.is_none() && b.is_none(),
    }
}

/// is_eotf_supported (drm_hdmi_helper.c): the sink's EOTF bitmap names the
/// InfoFrame's EOTF. Linux only logs a mismatch; the InfoFrame is still sent.
pub fn eotf_supported_by_sink(eotf: u8, sink_eotf: u8) -> bool {
    1u32.checked_shl(u32::from(eotf))
        .is_some_and(|bit| u32::from(sink_eotf) & bit != 0)
}

/// drm_hdmi_infoframe_set_hdr_metadata into hdmi_drm_infoframe_init's frame,
/// then hdmi_drm_infoframe_pack_only: the 4-byte header (type 0x87, version
/// 1, length 26, checksum) and the 26 little-endian payload bytes.
pub fn drm_infoframe(m: &HdrOutputMetadata) -> [u8; 30] {
    let f = &m.hdmi_metadata_type1;
    let mut p = [0u8; 30];
    p[..3].copy_from_slice(&[HDMI_INFOFRAME_TYPE_DRM, 1, HDMI_DRM_INFOFRAME_SIZE]);
    p[4] = f.eotf;
    p[5] = f.metadata_type;
    let mut at = 6;
    let mut put = |v: u16| {
        p[at..at + 2].copy_from_slice(&v.to_le_bytes());
        at += 2;
    };
    for (x, y) in f.display_primaries {
        put(x);
        put(y);
    }
    put(f.white_point.0);
    put(f.white_point.1);
    put(f.max_display_mastering_luminance);
    put(f.min_display_mastering_luminance);
    put(f.max_cll);
    put(f.max_fall);
    let sum = p.iter().fold(0u8, |s, b| s.wrapping_add(*b));
    p[3] = 0u8.wrapping_sub(sum);
    p
}

/// DC's `struct dc_info_packet`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InfoPacket {
    pub valid: bool,
    pub hb: [u8; 4],
    pub sb: [u8; 32],
}

impl InfoPacket {
    /// vpg3_update_generic_info_packet's nine VPG_GENERIC_PACKET_DATA
    /// writes as bytes: HB0..HB3, then SB0..SB31.
    pub fn bytes(&self) -> [u8; 36] {
        let mut b = [0u8; 36];
        b[..4].copy_from_slice(&self.hb);
        b[4..].copy_from_slice(&self.sb);
        b
    }
    /// The same as the nine little-endian data words.
    pub fn words(&self) -> [u32; 9] {
        let b = self.bytes();
        core::array::from_fn(|i| {
            u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
        })
    }
}

/// The connector types amdgpu_dm_fill_hdr_info_packet packs for (eDP packs
/// as DisplayPort).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HdrConnector {
    Hdmi,
    DisplayPort,
}

/// amdgpu_dm_fill_hdr_info_packet: no metadata gives an empty, invalid
/// packet; otherwise the HDMI DRM InfoFrame (header 0x87/1/0x1a, SB0 the
/// checksum) or the DP HDR metadata SDP (HB 0x00/0x87/0x1d/0x4c, SB0 version
/// 1, SB1 length 0x1a), followed by the 26 payload bytes.
pub fn hdr_info_packet(m: Option<&HdrOutputMetadata>, connector: HdrConnector) -> InfoPacket {
    let mut out = InfoPacket::default();
    let Some(m) = m else {
        return out;
    };
    let buf = drm_infoframe(m);
    let at = match connector {
        HdrConnector::Hdmi => {
            out.hb = [0x87, 0x01, 0x1a, 0];
            out.sb[0] = buf[3];
            1
        }
        HdrConnector::DisplayPort => {
            out.hb = [0x00, 0x87, 0x1d, 0x13 << 2];
            out.sb[0] = 0x01;
            out.sb[1] = 0x1a;
            2
        }
    };
    out.sb[at..at + 26].copy_from_slice(&buf[4..]);
    out.valid = true;
    out
}

/// What the sink's HDR Static Metadata Data Block declares
/// (display_info.hdr_sink_metadata.hdmi_type1) and the luminance range DRM
/// derives from it (display_info.luminance_range, zero until a block with
/// all three luminance bytes and Type 1 support was parsed).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HdrSinkMetadata {
    /// Supported EOTFs, a bitmap of HDMI_EOTF_* (bits 0..3 only).
    pub eotf: u8,
    /// Supported descriptors, a bitmap (bit 0: Static Metadata Type 1).
    pub metadata_type: u8,
    pub max_cll: u8,
    pub max_fall: u8,
    pub min_cll: u8,
    pub min_luminance: u32,
    pub max_luminance: u32,
}

/// drm_calculate_luminance_range: 50 * 2^(max_fall / 32) from Linux's
/// table, and the minimum as max * round(round(min_cll / 255)^2 / 100).
fn luminance_range(m: &mut HdrSinkMetadata) {
    const PRE_COMPUTED: [u8; 32] = [
        50, 51, 52, 53, 55, 56, 57, 58, 59, 61, 62, 63, 65, 66, 68, 69, 71, 72, 74, 75, 77, 79, 81,
        82, 84, 86, 88, 90, 92, 94, 96, 98,
    ];
    if m.metadata_type & 1 << HDMI_STATIC_METADATA_TYPE1 == 0 {
        return;
    }
    let q = u32::from(m.max_fall) >> 5;
    let r = usize::from(m.max_fall % 32);
    let max = (1u32 << q) * u32::from(PRE_COMPUTED[r]);
    let round = |x: u32, d: u32| (x + d / 2) / d;
    let q = round(u32::from(m.min_cll), 255);
    m.min_luminance = max * round(q * q, 100);
    m.max_luminance = max;
}

/// The HDR Static Metadata Data Blocks of `edid` (base block first, as
/// read), parsed as drm_add_display_info does: every CTA extension of
/// revision 3 or later with a data block collection (DTD offset 4..127),
/// every in-bounds extended-tag-6 block with at least 3 payload bytes (tag,
/// EOTF, descriptor) in order. A later block replaces EOTF and descriptor
/// bitmaps, and each luminance byte it carries (4, 5, 6 payload bytes);
/// fields a shorter later block omits keep the earlier value. Blocks with a
/// bad checksum were dropped by edid_filter_invalid_blocks. None when no
/// block was parsed (DRM then leaves everything zero). DisplayID-embedded
/// CTA blocks are not walked.
pub fn hdr_sink_metadata(edid: &[u8]) -> Option<HdrSinkMetadata> {
    use narf_edid::cta861::{CtaExtension, DataBlock};
    let mut m: Option<HdrSinkMetadata> = None;
    for block in edid.chunks_exact(128).skip(1) {
        let Ok(cta) = CtaExtension::parse(block) else {
            continue;
        };
        if cta.revision < 3 {
            continue;
        }
        for db in &cta.data_blocks {
            let DataBlock::Extended {
                ext_tag: 6,
                payload,
            } = db
            else {
                continue;
            };
            // DRM's payload length counts the extended tag byte too.
            let len = payload.len() + 1;
            if len < 3 {
                continue;
            }
            let h = m.get_or_insert_with(HdrSinkMetadata::default);
            h.eotf = payload[0] & 0x0f;
            h.metadata_type = payload[1] & 1 << HDMI_STATIC_METADATA_TYPE1;
            if len >= 4 {
                h.max_cll = payload[2];
            }
            if len >= 5 {
                h.max_fall = payload[3];
            }
            if len >= 6 {
                h.min_cll = payload[4];
                luminance_range(h);
            }
        }
    }
    m
}

/// enum drm_colorspace values (include/drm/drm_connector.h).
pub const DRM_MODE_COLORIMETRY_DEFAULT: u32 = 0;
pub const DRM_MODE_COLORIMETRY_SMPTE_170M_YCC: u32 = 1;
pub const DRM_MODE_COLORIMETRY_BT709_YCC: u32 = 2;
pub const DRM_MODE_COLORIMETRY_XVYCC_601: u32 = 3;
pub const DRM_MODE_COLORIMETRY_XVYCC_709: u32 = 4;
pub const DRM_MODE_COLORIMETRY_SYCC_601: u32 = 5;
pub const DRM_MODE_COLORIMETRY_OPYCC_601: u32 = 6;
pub const DRM_MODE_COLORIMETRY_OPRGB: u32 = 7;
pub const DRM_MODE_COLORIMETRY_BT2020_CYCC: u32 = 8;
pub const DRM_MODE_COLORIMETRY_BT2020_RGB: u32 = 9;
pub const DRM_MODE_COLORIMETRY_BT2020_YCC: u32 = 10;
pub const DRM_MODE_COLORIMETRY_DCI_P3_RGB_D65: u32 = 11;
pub const DRM_MODE_COLORIMETRY_DCI_P3_RGB_THEATER: u32 = 12;
pub const DRM_MODE_COLORIMETRY_RGB_WIDE_FIXED: u32 = 13;
pub const DRM_MODE_COLORIMETRY_RGB_WIDE_FLOAT: u32 = 14;
pub const DRM_MODE_COLORIMETRY_BT601_YCC: u32 = 15;

/// The "Colorspace" enum drm_mode_create_hdmi_colorspace_property and
/// drm_mode_create_dp_colorspace_property build from amdgpu_dm's
/// supported_colorspaces (BT709_YCC | OPRGB | BT2020_RGB | BT2020_YCC, all in
/// both the HDMI and the DP sets) plus Default, in value order. amdgpu_dm
/// attaches it to HDMI and SST DP/eDP connectors (MST connectors share
/// their root's).
pub const AMDGPU_COLORSPACES: [(u32, &str); 5] = [
    (DRM_MODE_COLORIMETRY_DEFAULT, "Default"),
    (DRM_MODE_COLORIMETRY_BT709_YCC, "BT709_YCC"),
    (DRM_MODE_COLORIMETRY_OPRGB, "opRGB"),
    (DRM_MODE_COLORIMETRY_BT2020_RGB, "BT2020_RGB"),
    (DRM_MODE_COLORIMETRY_BT2020_YCC, "BT2020_YCC"),
];
/// The HDMI connector's list (identical to the DP one for amdgpu).
pub fn hdmi_colorspaces() -> &'static [(u32, &'static str)] {
    &AMDGPU_COLORSPACES
}
/// The DP connector's list (identical to the HDMI one for amdgpu).
pub fn dp_colorspaces() -> &'static [(u32, &'static str)] {
    &AMDGPU_COLORSPACES
}
/// A value the property accepts (drm_property_change_valid_get).
pub fn colorspace_valid(value: u64) -> bool {
    AMDGPU_COLORSPACES
        .iter()
        .any(|&(v, _)| u64::from(v) == value)
}

/// enum dc_color_space, with Linux's values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DcColorSpace {
    Unknown = 0,
    Srgb = 1,
    XrRgb = 2,
    SrgbLimited = 3,
    MsrefScrgb = 4,
    Ycbcr601 = 5,
    Ycbcr709 = 6,
    XvYcc709 = 7,
    XvYcc601 = 8,
    Ycbcr601Limited = 9,
    Ycbcr709Limited = 10,
    Rgb2020Full = 11,
    Rgb2020Limited = 12,
    Ycbcr2020Limited = 13,
    Ycbcr2020Full = 14,
    AdobeRgb = 15,
    DciP3 = 16,
    DisplayNative = 17,
    DolbyVision = 18,
    AppCtrl = 19,
    CustomPoints = 20,
    Ycbcr709Black = 21,
}

impl DcColorSpace {
    /// From Linux's enum value.
    pub fn from_linux(v: u32) -> Option<Self> {
        use DcColorSpace::*;
        const ALL: [DcColorSpace; 22] = [
            Unknown,
            Srgb,
            XrRgb,
            SrgbLimited,
            MsrefScrgb,
            Ycbcr601,
            Ycbcr709,
            XvYcc709,
            XvYcc601,
            Ycbcr601Limited,
            Ycbcr709Limited,
            Rgb2020Full,
            Rgb2020Limited,
            Ycbcr2020Limited,
            Ycbcr2020Full,
            AdobeRgb,
            DciP3,
            DisplayNative,
            DolbyVision,
            AppCtrl,
            CustomPoints,
            Ycbcr709Black,
        ];
        ALL.get(usize::try_from(v).ok()?).copied()
    }
}

/// amdgpu_dm_get_output_color_space. `rgb` is the stream's pixel encoding
/// (RGB, else YCbCr), `broadcast_limited` its "Broadcast RGB" being
/// Limited 16:235. Note that BT709_YCC selects YCbCr 709 even for an RGB
/// stream, as Linux does.
pub fn output_color_space(
    colorspace: u32,
    rgb: bool,
    y_only: bool,
    pix_clk_100hz: u32,
    broadcast_limited: bool,
) -> DcColorSpace {
    use DcColorSpace::*;
    match colorspace {
        DRM_MODE_COLORIMETRY_BT601_YCC if y_only => Ycbcr601Limited,
        DRM_MODE_COLORIMETRY_BT601_YCC => Ycbcr601,
        DRM_MODE_COLORIMETRY_BT709_YCC if y_only => Ycbcr709Limited,
        DRM_MODE_COLORIMETRY_BT709_YCC => Ycbcr709,
        DRM_MODE_COLORIMETRY_OPRGB => AdobeRgb,
        DRM_MODE_COLORIMETRY_BT2020_RGB | DRM_MODE_COLORIMETRY_BT2020_YCC => {
            match (rgb, broadcast_limited) {
                (true, true) => Rgb2020Limited,
                (true, false) => Rgb2020Full,
                (false, _) => Ycbcr2020Limited,
            }
        }
        _ => match (rgb, pix_clk_100hz > 270_300, y_only) {
            (true, ..) if broadcast_limited => SrgbLimited,
            (true, ..) => Srgb,
            (false, true, true) => Ycbcr709Limited,
            (false, true, false) => Ycbcr709,
            (false, false, true) => Ycbcr601Limited,
            (false, false, false) => Ycbcr601,
        },
    }
}

/// enum dc_pixel_encoding, with Linux's values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PixelEncoding {
    Rgb = 1,
    Ycbcr422 = 2,
    Ycbcr444 = 3,
    Ycbcr420 = 4,
}

impl PixelEncoding {
    pub const fn is_420(self) -> bool {
        matches!(self, Self::Ycbcr420)
    }
    pub const fn is_422(self) -> bool {
        matches!(self, Self::Ycbcr422)
    }
    pub const fn is_rgb(self) -> bool {
        matches!(self, Self::Rgb)
    }
    /// The shared chroma filter consumes adjacent horizontal pixels.
    pub const fn subsampled(self) -> bool {
        self.is_420() || self.is_422()
    }
    /// OPTC_DATA_FORMAT and HDMI_PIXEL_ENCODING (RGB/444 share zero).
    pub const fn hardware_format(self) -> u32 {
        match self {
            Self::Ycbcr422 => 1,
            Self::Ycbcr420 => 2,
            _ => 0,
        }
    }
    /// AVI InfoFrame Y2:Y0.
    pub const fn avi(self) -> u8 {
        match self {
            Self::Rgb => 0,
            Self::Ycbcr422 => 1,
            Self::Ycbcr444 => 2,
            Self::Ycbcr420 => 3,
        }
    }
    pub const fn from_420(ycbcr420: bool) -> Self {
        if ycbcr420 {
            Self::Ycbcr420
        } else {
            Self::Rgb
        }
    }
}

/// DRM's connector "color format" values (drm_connector_color_format).
/// AUTO preserves the HDMI helper policy: RGB, then declared 4:2:0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ColorFormat {
    #[default]
    Auto = 0,
    Rgb = 1,
    Ycbcr444 = 2,
    Ycbcr422 = 3,
    Ycbcr420 = 4,
}
impl ColorFormat {
    pub const fn from_linux(value: u64) -> Option<Self> {
        Some(match value {
            0 => Self::Auto,
            1 => Self::Rgb,
            2 => Self::Ycbcr444,
            3 => Self::Ycbcr422,
            4 => Self::Ycbcr420,
            _ => return None,
        })
    }
    pub const fn encoding(self) -> Option<PixelEncoding> {
        Some(match self {
            Self::Auto => return None,
            Self::Rgb => PixelEncoding::Rgb,
            Self::Ycbcr444 => PixelEncoding::Ycbcr444,
            Self::Ycbcr422 => PixelEncoding::Ycbcr422,
            Self::Ycbcr420 => PixelEncoding::Ycbcr420,
        })
    }
}

/// The color-space-dependent AVI InfoFrame fields set_avi_info_frame fills.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AviColorimetry {
    /// C1:C0: 0 no data, 1 ITU601, 2 ITU709, 3 extended.
    pub c: u8,
    /// EC2:EC0 (with C = 3): 4 AdobeRGB, 6 BT.2020 RGB/YCbCr.
    pub ec: u8,
    /// Q1:Q0: 0 default, 1 limited, 2 full.
    pub q: u8,
    /// YQ1:YQ0: always 0 (limited).
    pub yq: u8,
}

/// set_avi_info_frame: Unknown becomes sRGB or YCbCr 709 by the encoding;
/// 709 and 601 (full or limited) name ITU709 and ITU601; BT.2020 RGB (either
/// range) and BT.2020 YCbCr name extended BT.2020; AdobeRGB extended
/// AdobeRGB; anything else no data. A YCbCr stream in BT.2020 YCbCr with an
/// output transfer function of Gamma 2.2 (`gamma22`) is signalled as ITU709.
/// Q is full for sRGB / BT.2020 RGB full, limited for their limited forms,
/// else default, and default whenever the sink lacks QS (VCDB). YQ is always
/// limited. Neither C/EC combination ever needs InfoFrame version 4.
pub fn avi_colorimetry(
    cs: DcColorSpace,
    encoding: PixelEncoding,
    qs: bool,
    gamma22: bool,
) -> AviColorimetry {
    use DcColorSpace::*;
    let ycbcr = encoding != PixelEncoding::Rgb;
    let cs = match cs {
        Unknown if ycbcr => Ycbcr709,
        Unknown => Srgb,
        cs => cs,
    };
    let (mut c, mut ec) = match cs {
        Ycbcr709 | Ycbcr709Limited => (2, 0),
        Ycbcr601 | Ycbcr601Limited => (1, 0),
        Rgb2020Full | Rgb2020Limited | Ycbcr2020Limited => (3, 6),
        AdobeRgb => (3, 4),
        _ => (0, 0),
    };
    if ycbcr && cs == Ycbcr2020Limited && gamma22 {
        (c, ec) = (2, 0);
    }
    let q = match cs {
        _ if !qs => 0,
        Srgb | Rgb2020Full => 2,
        SrgbLimited | Rgb2020Limited => 1,
        _ => 0,
    };
    AviColorimetry { c, ec, q, yq: 0 }
}

/// enc401_stream_encoder_dp_set_stream_attribute's DP_MSA_MISC0 (component
/// depth in bits 7:5 — 6, 8, 10, 12 bpc as 0..3, others 0 — bit 3 CEA
/// range, bit 4 BT.709, bits 2:1 YCbCr 4:4:4 / 4:2:2, for sRGB-limited, 601
/// and 709 only) and DP_MSA_MISC (`current_misc1`, the register's present
/// value: bit 6 set exactly when the VSC SDP carries colorimetry, bit 7 (Y
/// only) cleared for sRGB, sRGB limited, 601 and 709, else kept). BT.2020,
/// AdobeRGB and the rest leave MISC0's colorimetry bits zero: the VSC SDP
/// (or nothing) signals them.
pub fn msa_misc(
    cs: DcColorSpace,
    encoding: PixelEncoding,
    bpc: u8,
    use_vsc_sdp_for_colorimetry: bool,
    current_misc1: u32,
) -> (u32, u32) {
    use DcColorSpace::*;
    let mut misc1 = if use_vsc_sdp_for_colorimetry {
        current_misc1 | 0x40
    } else {
        current_misc1 & !0x40
    };
    let colorimetry_bpc = match bpc {
        8 => 1,
        10 => 2,
        12 => 3,
        _ => 0,
    };
    let mut misc0 = colorimetry_bpc << 5;
    let ycbcr_bits = match encoding {
        PixelEncoding::Ycbcr422 => 0x2,
        PixelEncoding::Ycbcr444 => 0x4,
        _ => 0,
    };
    match cs {
        Srgb => misc1 &= !0x80,
        SrgbLimited => {
            misc0 |= 0x8;
            misc1 &= !0x80;
        }
        Ycbcr601 | Ycbcr601Limited => {
            misc0 |= 0x8 | ycbcr_bits;
            misc1 &= !0x80;
        }
        Ycbcr709 | Ycbcr709Limited => {
            misc0 |= 0x18 | ycbcr_bits;
            misc1 &= !0x80;
        }
        _ => {}
    }
    (misc0, misc1)
}

/// dcn31_hpo_dp_stream_enc_set_stream_attribute's MISC0/MISC1 for a
/// 128b/132b stream (DP_SYM32_ENC_VID_MSA6/MSA7 lane 3). Unlike the DIO
/// encoder it starts from zero: MISC0 bits 2:1 the YCbCr 4:2:2/4:4:4
/// encoding, bits 7:5 the depth (8, 10, 12 bpc as 1..3, others 0), bit 3
/// and 4 the CEA range and BT.709 for sRGB limited, 601 and 709; MISC1 bit 6
/// set exactly when the VSC SDP carries colorimetry (4:2:0 sets it first,
/// and no VSC clears it again, as Linux's order does).
pub fn hpo_msa_misc(
    cs: DcColorSpace,
    encoding: PixelEncoding,
    bpc: u8,
    use_vsc_sdp_for_colorimetry: bool,
) -> (u32, u32) {
    use DcColorSpace::*;
    let mut misc0 = match encoding {
        PixelEncoding::Ycbcr422 => 0x2,
        PixelEncoding::Ycbcr444 => 0x4,
        _ => 0,
    };
    let mut misc1 = if encoding == PixelEncoding::Ycbcr420 {
        0x40
    } else {
        0
    };
    if use_vsc_sdp_for_colorimetry {
        misc1 |= 0x40;
    } else {
        misc1 &= !0x40;
    }
    misc0 |= match bpc {
        8 => 0x20,
        10 => 0x40,
        12 => 0x60,
        _ => 0,
    };
    let ycbcr_bits = match encoding {
        PixelEncoding::Ycbcr422 => 0x2,
        PixelEncoding::Ycbcr444 => 0x4,
        _ => 0,
    };
    match cs {
        Srgb => misc1 &= !0x80,
        SrgbLimited => {
            misc0 |= 0x8;
            misc1 &= !0x80;
        }
        Ycbcr601 | Ycbcr601Limited => {
            misc0 |= 0x8 | ycbcr_bits;
            misc1 &= !0x80;
        }
        Ycbcr709 | Ycbcr709Limited => {
            misc0 |= 0x18 | ycbcr_bits;
            misc1 &= !0x80;
        }
        _ => {}
    }
    (misc0, misc1)
}

/// DP_DPRX_FEATURE_ENUMERATION_LIST and its
/// VSC_SDP_EXTENSION_FOR_COLORIMETRY_SUPPORTED bit.
pub const DP_DPRX_FEATURE_ENUMERATION_LIST: u32 = 0x2210;
pub const DP_VSC_SDP_EXT_FOR_COLORIMETRY_SUPPORTED: u8 = 1 << 3;

/// create_stream_for_sink's use_vsc_sdp_for_colorimetry: DPCD revision 1.4
/// or later (the extended receiver capability's revision when present) and
/// the DPRX feature list's colorimetry bit (DC reads that list only with an
/// extended receiver capability field; pass 0 otherwise). No sink here
/// carries the disable_colorimetry panel patch.
pub fn use_vsc_sdp_for_colorimetry(dpcd_rev: u8, dprx_feature: u8) -> bool {
    dpcd_rev >= 0x14 && dprx_feature & DP_VSC_SDP_EXT_FOR_COLORIMETRY_SUPPORTED != 0
}

/// mod_build_vsc_infopacket for a non-3D stream on a link without PSR or
/// Panel Replay: no VSC SDP at all unless it carries colorimetry; then
/// revision 5 (HB 0x00 0x07 0x05 0x13) with set_vsc_packet_colorimetry_data:
/// DB16 = pixel encoding << 4 | colorimetry (RGB: sRGB 0 for sRGB/limited,
/// AdobeRGB 3, BT.2020 RGB 6, else 0; YCbCr: 601 0, 709 1, AdobeYCC 5,
/// BT.2020 YCbCr 7 — or 709 when the transfer function is Gamma 2.2), DB17 =
/// bpc code (6: 0, 8: 1, 10: 2, 12: 3, 16: 4, else 0) | 0x80 for limited
/// range (sRGB limited, BT.2020 RGB limited or any YCbCr), DB18 content type
/// 0. amdgpu_dm passes Gamma 2.2 (`gamma22`) only when the stream's output
/// transfer function is TRANSFER_FUNCTION_GAMMA22, which CRTC color
/// management never selects.
pub fn vsc_sdp(
    use_vsc_sdp_for_colorimetry: bool,
    cs: DcColorSpace,
    encoding: PixelEncoding,
    bpc: u8,
    gamma22: bool,
) -> Option<InfoPacket> {
    use DcColorSpace::*;
    if !use_vsc_sdp_for_colorimetry {
        return None;
    }
    let pixel: u8 = match encoding {
        PixelEncoding::Rgb => 0,
        PixelEncoding::Ycbcr444 => 1,
        PixelEncoding::Ycbcr422 => 2,
        PixelEncoding::Ycbcr420 => 3,
    };
    let colorimetry = if pixel == 0 {
        match cs {
            AdobeRgb => 3,
            Rgb2020Full | Rgb2020Limited => 6,
            _ => 0,
        }
    } else {
        match cs {
            Ycbcr709 => 1,
            AdobeRgb => 5,
            Ycbcr2020Limited if gamma22 => 1,
            Ycbcr2020Limited => 7,
            _ => 0,
        }
    };
    let mut p = InfoPacket {
        valid: true,
        hb: [0x00, 0x07, 0x05, 0x13],
        sb: [0; 32],
    };
    p.sb[16] = pixel << 4 | colorimetry;
    p.sb[17] = match bpc {
        8 => 1,
        10 => 2,
        12 => 3,
        16 => 4,
        _ => 0,
    };
    if matches!(cs, SrgbLimited | Rgb2020Limited) || pixel != 0 {
        p.sb[17] |= 0x80;
    }
    Some(p)
}

/// Hex helper shared with the tests.
#[cfg(feature = "kernel-test")]
fn unhex(s: &str) -> Option<alloc::vec::Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_hdr_tests.rs"]
mod tests;

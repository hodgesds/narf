//! `AMDGPU_INFO_VIDEO_CAPS` content for Navi22 (UVD/VCN 3.0.0), as Linux
//! `nv_query_video_codecs` reports it for bare-metal Sienna Cichlid family
//! parts: `sc_video_codecs_encode`, and `sc_video_codecs_decode_vcn0` unless
//! VCN0 is harvested (then `_vcn1`, which lacks AV1). Pure tables; the
//! ioctl does not advertise them until the media owner is published.
use crate::amdgpu_uapi::{
    DrmAmdgpuInfoVideoCaps, DrmAmdgpuInfoVideoCodecInfo, AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_AV1,
    AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_HEVC, AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_JPEG,
    AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG2, AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4,
    AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC, AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_VC1,
    AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_VP9, AMDGPU_INFO_VIDEO_CAPS_DECODE,
    AMDGPU_INFO_VIDEO_CAPS_ENCODE,
};

/// `struct amdgpu_video_codec_info` built by `codec_info_build`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Codec {
    /// AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_*.
    pub codec: u32,
    pub max_width: u32,
    pub max_height: u32,
    pub max_level: u32,
}
const fn codec(codec: u32, max_width: u32, max_height: u32, max_level: u32) -> Codec {
    Codec {
        codec,
        max_width,
        max_height,
        max_level,
    }
}
/// nv.c `sc_video_codecs_encode_array`.
// linux: n/a (struct initializers: nv.c sc_video_codecs_encode_array)
pub const ENCODE: [Codec; 2] = [
    codec(AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC, 4096, 4096, 0),
    codec(AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_HEVC, 8192, 4352, 0),
];
/// nv.c `sc_video_codecs_decode_array_vcn0`.
// linux: n/a (struct initializers: nv.c sc_video_codecs_decode_array_vcn0)
pub const DECODE_VCN0: [Codec; 8] = [
    codec(AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG2, 1920, 1088, 3),
    codec(AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4, 1920, 1088, 5),
    codec(AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC, 4096, 4096, 52),
    codec(AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_VC1, 1920, 1088, 4),
    codec(AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_HEVC, 8192, 4352, 186),
    codec(AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_JPEG, 16384, 16384, 0),
    codec(AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_VP9, 8192, 4352, 0),
    codec(AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_AV1, 8192, 4352, 0),
];
/// nv.c `sc_video_codecs_decode_array_vcn1`: VCN1 has no AV1 decoder.
// linux: n/a (struct initializers: nv.c sc_video_codecs_decode_array_vcn1)
pub const DECODE_VCN1: [Codec; 7] = [
    DECODE_VCN0[0],
    DECODE_VCN0[1],
    DECODE_VCN0[2],
    DECODE_VCN0[3],
    DECODE_VCN0[4],
    DECODE_VCN0[5],
    DECODE_VCN0[6],
];

/// Codec list for subquery `kind` (DECODE/ENCODE) given the harvested VCN
/// mask. `None` is Linux's -EINVAL: every instance harvested or an unknown
/// subquery.
pub fn codecs(kind: u32, harvested: u8) -> Option<&'static [Codec]> {
    // linux-lit: 3=AMDGPU_VCN_HARVEST_VCN0 | AMDGPU_VCN_HARVEST_VCN1
    if harvested & 3 == 3 {
        return None;
    }
    match kind {
        AMDGPU_INFO_VIDEO_CAPS_ENCODE => Some(&ENCODE),
        // linux-lit: 1=AMDGPU_VCN_HARVEST_VCN0
        AMDGPU_INFO_VIDEO_CAPS_DECODE if harvested & 1 != 0 => Some(&DECODE_VCN1),
        AMDGPU_INFO_VIDEO_CAPS_DECODE => Some(&DECODE_VCN0),
        _ => None,
    }
}
/// The `drm_amdgpu_info_video_caps` reply `amdgpu_info_ioctl` builds:
/// indexed by codec, `max_pixels_per_frame = width * height`.
pub fn caps(kind: u32, harvested: u8) -> Option<DrmAmdgpuInfoVideoCaps> {
    caps_for(kind, harvested, (3, 0, 0))
}

/// Bare-metal `nv_query_video_codecs`, selected by the discovered VCN IP.
pub fn caps_for(kind: u32, harvested: u8, version: (u8, u8, u8)) -> Option<DrmAmdgpuInfoVideoCaps> {
    if harvested & 3 == 3 {
        return None;
    }
    let codecs = match version {
        (3, 0, 0 | 64 | 192) => codecs(kind, harvested)?,
        (3, 0, 2 | 16) => codecs(kind, harvested & 2)?,
        (3, 0, 33) if harvested & 3 != 3 => match kind {
            AMDGPU_INFO_VIDEO_CAPS_ENCODE => &[][..],
            AMDGPU_INFO_VIDEO_CAPS_DECODE => &[DECODE_VCN0[2], DECODE_VCN0[4], DECODE_VCN0[6]][..],
            _ => return None,
        },
        _ => return None,
    };
    let mut caps = DrmAmdgpuInfoVideoCaps::default();
    for c in codecs {
        let slot = caps.codec_info.get_mut(c.codec as usize)?;
        *slot = DrmAmdgpuInfoVideoCodecInfo {
            valid: 1,
            max_width: c.max_width,
            max_height: c.max_height,
            max_pixels_per_frame: c.max_width * c.max_height,
            max_level: c.max_level,
            pad: 0,
        };
    }
    Some(caps)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn navi24_video_caps_exclude_absent_codecs() -> TestResult {
        let decode = caps_for(AMDGPU_INFO_VIDEO_CAPS_DECODE, 2, (3, 0, 33)).unwrap();
        let encode = caps_for(AMDGPU_INFO_VIDEO_CAPS_ENCODE, 2, (3, 0, 33)).unwrap();
        for (index, codec) in decode.codec_info.iter().enumerate() {
            let expected = [
                AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC,
                AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_HEVC,
                AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_VP9,
            ]
            .contains(&(index as u32));
            if (codec.valid != 0) != expected || encode.codec_info[index].valid != 0 {
                return TestResult::Fail("Navi24 codec capability mask");
            }
        }
        if caps_for(AMDGPU_INFO_VIDEO_CAPS_DECODE, 3, (3, 0, 33)).is_some() {
            return TestResult::Fail("harvested Navi24 decoder advertised");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/video-caps-navi22",
        navi24_video_caps_exclude_absent_codecs
    );

    fn navi22_video_caps_match_sienna_cichlid_tables() -> TestResult {
        let decode = caps(AMDGPU_INFO_VIDEO_CAPS_DECODE, 0).unwrap();
        let hevc = decode.codec_info[AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_HEVC as usize];
        let av1 = decode.codec_info[AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_AV1 as usize];
        let jpeg = decode.codec_info[AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_JPEG as usize];
        if decode.codec_info.iter().any(|c| c.valid != 1)
            || (hevc.max_width, hevc.max_height, hevc.max_level) != (8192, 4352, 186)
            || hevc.max_pixels_per_frame != 8192 * 4352
            || (av1.max_width, av1.max_height) != (8192, 4352)
            || jpeg.max_pixels_per_frame != 16384 * 16384
        {
            return TestResult::Fail("VCN0 decode caps");
        }
        let encode = caps(AMDGPU_INFO_VIDEO_CAPS_ENCODE, 2).unwrap();
        let avc = encode.codec_info[AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC as usize];
        if encode.codec_info.iter().filter(|c| c.valid == 1).count() != 2
            || (avc.max_width, avc.max_height, avc.max_level) != (4096, 4096, 0)
            || encode.codec_info[AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_HEVC as usize].max_width != 8192
        {
            return TestResult::Fail("encode caps");
        }
        let vcn1 = caps(AMDGPU_INFO_VIDEO_CAPS_DECODE, 1).unwrap();
        if vcn1.codec_info[AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_AV1 as usize].valid != 0
            || vcn1.codec_info.iter().filter(|c| c.valid == 1).count() != 7
            || caps(AMDGPU_INFO_VIDEO_CAPS_DECODE, 3).is_some()
            || caps(AMDGPU_INFO_VIDEO_CAPS_ENCODE, 3).is_some()
            || caps(2, 0).is_some()
        {
            return TestResult::Fail("harvested/invalid video caps");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/vcn-navi22",
        navi22_video_caps_match_sienna_cichlid_tables
    );
}

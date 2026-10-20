//! `AMDGPU_INFO_VIDEO_CAPS` for Navi48 (VCN 5.0.0): Linux soc24's
//! `vcn_5_0_0_video_codecs_{encode,decode}_array_vcn0`, filtered to the
//! codec directions whose native proof passed on this device. Codecs without
//! a known-stream proof stay unadvertised even though the IP supports them.
use crate::amdgpu_uapi::{
    DrmAmdgpuInfoVideoCaps, DrmAmdgpuInfoVideoCodecInfo, AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_AV1,
    AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_HEVC, AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_JPEG,
    AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC, AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_VP9,
    AMDGPU_INFO_VIDEO_CAPS_DECODE, AMDGPU_INFO_VIDEO_CAPS_ENCODE,
};

/// One table row: codec index, maximum width/height and level.
type Row = (u32, u32, u32, u32);
/// soc24.c `vcn_5_0_0_video_codecs_encode_array_vcn0`.
const ENCODE: [Row; 3] = [
    (AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC, 4096, 4096, 0),
    (AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_HEVC, 8192, 4352, 0),
    (AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_AV1, 8192, 4352, 0),
];
/// soc24.c `vcn_5_0_0_video_codecs_decode_array_vcn0`.
const DECODE: [Row; 5] = [
    (AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC, 4096, 4096, 52),
    (AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_HEVC, 8192, 4352, 186),
    (AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_JPEG, 16384, 16384, 0),
    (AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_VP9, 8192, 4352, 0),
    (AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_AV1, 8192, 4352, 0),
];
/// The fixed AVC picture decoded on the unified VCN client ring.
pub const AVC_DECODE: u8 = 1;
/// The fixed AVC IDR frame encoded on the unified VCN client ring.
pub const AVC_ENCODE: u8 = 2;
/// The fixed JPEG picture decoded on the published JPEG client ring.
pub const JPEG_DECODE: u8 = 4;

/// Linux's reply for `kind` on VCN `version`, keeping only rows in `proven`.
/// `None` is -EINVAL: another VCN version or an unknown subquery.
pub fn caps(kind: u32, version: (u8, u8, u8), proven: u8) -> Option<DrmAmdgpuInfoVideoCaps> {
    if version != (5, 0, 0) {
        return None;
    }
    let (rows, wanted): (&[Row], &[(u32, u8)]) = match kind {
        AMDGPU_INFO_VIDEO_CAPS_ENCODE => (
            &ENCODE,
            &[(AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC, AVC_ENCODE)],
        ),
        AMDGPU_INFO_VIDEO_CAPS_DECODE => (
            &DECODE,
            &[
                (AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC, AVC_DECODE),
                (AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_JPEG, JPEG_DECODE),
            ],
        ),
        _ => return None,
    };
    let mut caps = DrmAmdgpuInfoVideoCaps::default();
    for &(codec, max_width, max_height, max_level) in rows {
        if !wanted
            .iter()
            .any(|&(c, bit)| c == codec && proven & bit != 0)
        {
            continue;
        }
        caps.codec_info[codec as usize] = DrmAmdgpuInfoVideoCodecInfo {
            valid: 1,
            max_width,
            max_height,
            max_pixels_per_frame: max_width * max_height,
            max_level,
            pad: 0,
        };
    }
    Some(caps)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn navi48_video_caps_report_only_proven_linux_rows() -> TestResult {
        let valid = |c: &DrmAmdgpuInfoVideoCaps| {
            c.codec_info
                .iter()
                .enumerate()
                .filter(|(_, i)| i.valid != 0)
                .map(|(n, _)| n as u32)
                .collect::<alloc::vec::Vec<_>>()
        };
        for kind in [AMDGPU_INFO_VIDEO_CAPS_DECODE, AMDGPU_INFO_VIDEO_CAPS_ENCODE] {
            assert!(valid(&caps(kind, (5, 0, 0), 0).unwrap()).is_empty());
            assert!(caps(kind, (4, 0, 5), 7).is_none());
            assert!(caps(kind, (5, 0, 1), 7).is_none());
        }
        assert!(caps(2, (5, 0, 0), 7).is_none());
        let decode = caps(AMDGPU_INFO_VIDEO_CAPS_DECODE, (5, 0, 0), 7).unwrap();
        assert_eq!(
            valid(&decode),
            [
                AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC,
                AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_JPEG
            ]
        );
        let avc = decode.codec_info[AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC as usize];
        assert_eq!(
            (
                avc.max_width,
                avc.max_height,
                avc.max_pixels_per_frame,
                avc.max_level
            ),
            (4096, 4096, 4096 * 4096, 52)
        );
        let jpeg = decode.codec_info[AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_JPEG as usize];
        assert_eq!((jpeg.max_width, jpeg.max_height), (16384, 16384));
        let only_jpeg = caps(AMDGPU_INFO_VIDEO_CAPS_DECODE, (5, 0, 0), JPEG_DECODE).unwrap();
        assert_eq!(valid(&only_jpeg), [AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_JPEG]);
        let encode = caps(AMDGPU_INFO_VIDEO_CAPS_ENCODE, (5, 0, 0), 7).unwrap();
        assert_eq!(valid(&encode), [AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC]);
        assert_eq!(
            encode.codec_info[AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC as usize].max_level,
            0
        );
        // Encode proof alone advertises no decoder, and vice versa.
        assert!(
            valid(&caps(AMDGPU_INFO_VIDEO_CAPS_DECODE, (5, 0, 0), AVC_ENCODE).unwrap()).is_empty()
        );
        assert!(
            valid(&caps(AMDGPU_INFO_VIDEO_CAPS_ENCODE, (5, 0, 0), AVC_DECODE).unwrap()).is_empty()
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/video-caps-navi48",
        navi48_video_caps_report_only_proven_linux_rows
    );
}

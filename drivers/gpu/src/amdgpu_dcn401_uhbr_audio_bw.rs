//! UHBR LPCM budget with the stream owner's programmed minimum blank width.
use super::*;

pub(super) fn rates(
    t: &Timing,
    bpc: u32,
    settings: UhbrSettings,
    hblank_symbols: u16,
    channels: u8,
    rates: u8,
    dsc: Option<super::super::bandwidth::AudioDsc>,
) -> Option<u8> {
    super::super::bandwidth::rates(
        t,
        bpc,
        super::super::bandwidth::AudioLink::Uhbr(settings, hblank_symbols),
        channels,
        rates,
        dsc,
    )
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn dcn401_uhbr_audio_bandwidth_matches_linux() -> TestResult {
        for line in include_str!("../tests/dcn401_uhbr_audio/vectors.txt").lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (inputs, want) = line.split_once(" = ").unwrap();
            let v: alloc::vec::Vec<u32> = inputs
                .split_whitespace()
                .map(|s| s.parse().unwrap())
                .collect();
            let timing = Timing {
                pixel_clock_khz: v[0],
                h_active: v[1],
                h_total: v[2],
                h_front_porch: 1,
                h_sync_width: 1,
                v_active: 1080,
                v_total: 1125,
                v_front_porch: 1,
                v_sync_width: 1,
                h_sync_positive: true,
                v_sync_positive: true,
            };
            let settings = UhbrSettings {
                lanes: v[5] as u8,
                rate: match v[4] {
                    1000 => UhbrRate::Uhbr10,
                    1350 => UhbrRate::Uhbr13_5,
                    _ => UhbrRate::Uhbr20,
                },
                mst: false,
            };
            // The native HBLANK formula, including stream pixel padding; no
            // link-admission precondition for these arithmetic-only vectors.
            let bits = u128::from(v[1] * v[3] * 3);
            let kbps = (u128::from(v[0] * v[3] * 3) * bits.div_ceil(128) * 128).div_ceil(bits);
            let hblank = (u128::from(v[2] - v[1]) * kbps / (u128::from(v[0]) * 128)) as u16;
            assert_eq!(
                rates(&timing, v[3], settings, hblank, v[6] as u8, 127, None),
                Some(want.parse().unwrap()),
                "{line}"
            );
        }
        TestResult::Pass
    }
    /// Compressed streams: Linux's budget at the DSC bits per pixel, less
    /// the slices' EOC symbols, for the given programmed blank width.
    fn dcn401_uhbr_dsc_audio_bandwidth_matches_linux() -> TestResult {
        let mut n = 0;
        for line in include_str!("../tests/dcn401_uhbr_audio/dsc_vectors.txt").lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (inputs, want) = line.split_once(" = ").unwrap();
            let v: alloc::vec::Vec<u32> = inputs
                .split_whitespace()
                .map(|s| s.parse().unwrap())
                .collect();
            let timing = Timing {
                pixel_clock_khz: v[0],
                h_active: v[1],
                h_total: v[2],
                h_front_porch: 1,
                h_sync_width: 1,
                v_active: 2160,
                v_total: 2250,
                v_front_porch: 1,
                v_sync_width: 1,
                h_sync_positive: true,
                v_sync_positive: true,
            };
            let settings = UhbrSettings {
                lanes: v[5] as u8,
                rate: match v[4] {
                    1000 => UhbrRate::Uhbr10,
                    1350 => UhbrRate::Uhbr13_5,
                    _ => UhbrRate::Uhbr20,
                },
                mst: false,
            };
            let dsc = crate::amdgpu_dcn401_otg::hdmi_link::audio::bandwidth::AudioDsc {
                bpp_x16: v[7],
                slices: v[8],
            };
            assert_eq!(
                rates(
                    &timing,
                    v[3],
                    settings,
                    v[9] as u16,
                    v[6] as u8,
                    127,
                    Some(dsc)
                ),
                Some(want.parse().unwrap()),
                "{line}"
            );
            n += 1;
        }
        assert_eq!(n, 4536);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn401-uhbr-audio",
        dcn401_uhbr_dsc_audio_bandwidth_matches_linux
    );
    kernel_test_in!(
        "drivers/gpu/dcn401-uhbr-audio",
        dcn401_uhbr_audio_bandwidth_matches_linux
    );
}

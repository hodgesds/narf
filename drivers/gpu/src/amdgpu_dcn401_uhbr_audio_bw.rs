//! dce_audio's 128b/132b LPCM horizontal-blank budget, in Linux's 31.32
//! arithmetic. Use the native stream's programmed HBLANK_MIN_SYMBOL_WIDTH,
//! not a separately derived (and potentially differently scaled) value.
use super::*;
use crate::amdgpu_dsc::Fixed as F;

pub(super) fn rates(
    t: &Timing,
    bpc: u32,
    settings: UhbrSettings,
    hblank_symbols: u16,
    channels: u8,
    rates: u8,
) -> Option<u8> {
    let blank = t.h_total.checked_sub(t.h_active)?;
    if t.h_active == 0
        || blank == 0
        || t.h_total > 65535
        || !(1..=6_000_000).contains(&t.pixel_clock_khz)
        || !matches!(bpc, 8 | 10 | 12)
        || !matches!(settings.lanes, 1 | 2 | 4)
        || !(1..=8).contains(&channels)
    {
        return None;
    }
    // The Linux order multiplies blank duration by the symbol clock before
    // the video/link fraction cancels the pixel clock. Reject malformed low
    // clocks that exceed 31.32's integer range at that intermediate step;
    // 625 MHz bounds every supported UHBR symbol clock.
    if u64::from(blank) * 625_000 >= u64::from(t.pixel_clock_khz) * i32::MAX as u64 {
        return None;
    }
    // populate_audio_dp_link_info removes SSC from the effective link BW.
    let link_kbps = settings.rate.link_rate() * u32::from(settings.lanes) * 9641;
    let link_kbps = F::int(link_kbps as i32)
        .mul(F::fraction(10000, 9975))
        .floor();
    let sym_mhz = match settings.rate {
        UhbrRate::Uhbr10 => F::fraction(3125, 10),
        UhbrRate::Uhbr13_5 => F::fraction(421875, 1000),
        UhbrRate::Uhbr20 => F::int(625),
    };
    let hblank_ms = F::fraction(i64::from(blank), i64::from(t.pixel_clock_khz));
    let peak = F::int(t.pixel_clock_khz as i32).mul_int((bpc * 3) as i32);
    let frac = peak.div(F::int(link_kbps));
    let mut available =
        hblank_ms.mul_int(1000).mul(sym_mhz).mul(frac).floor() as u32 * u32::from(settings.lanes);
    if available < u32::from(hblank_symbols) {
        available = 4 * u32::from(hblank_symbols);
    }
    available = available.saturating_sub(12); // main-link overhead
    let line_khz = F::fraction(i64::from(t.pixel_clock_khz), i64::from(t.h_total));
    let margin = F::fraction(110, 100);
    // Four-lane AV mapping, ten 32-bit symbols/layout and ten SDP overhead
    // symbols. Conservatively use the eight-channel layout for 3..8 channels.
    let denom = if channels <= 2 { 4 } else { 1 };
    let align = |n: i32| ((n + 4) / 4 * 4) as u32;
    let full = align(F::int(20).mul(margin).ceil());
    let mut kept = rates & 0x7f;
    for (bit, hz) in [32000, 44100, 48000, 88200, 96000, 176400, 192000]
        .into_iter()
        .enumerate()
    {
        let layouts = F::fraction(hz, 1000).div(line_khz).div_int(denom);
        let count = layouts.floor();
        let mut required = count as u32 * full;
        if count != layouts.ceil() {
            required += align(
                layouts
                    .sub_int(count)
                    .mul_int(10)
                    .add_int(10)
                    .mul(margin)
                    .ceil(),
            );
        }
        if available < required {
            kept &= !(1 << bit);
        }
    }
    Some(kept)
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
            };
            // The native HBLANK formula, including stream pixel padding; no
            // link-admission precondition for these arithmetic-only vectors.
            let bits = u128::from(v[1] * v[3] * 3);
            let kbps = (u128::from(v[0] * v[3] * 3) * bits.div_ceil(128) * 128).div_ceil(bits);
            let hblank = (u128::from(v[2] - v[1]) * kbps / (u128::from(v[0]) * 128)) as u16;
            assert_eq!(
                rates(&timing, v[3], settings, hblank, v[6] as u8, 127),
                Some(want.parse().unwrap()),
                "{line}"
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn401-uhbr-audio",
        dcn401_uhbr_audio_bandwidth_matches_linux
    );
}

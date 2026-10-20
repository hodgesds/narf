//! Linux dce_audio's LPCM blanking budget for legacy MST and UHBR SST/MST.
//! Fixed-point order/rounding and 1.1 margin follow check_audio_bandwidth_dp.
//! A compressed stream budgets its DSC bits per pixel and loses four
//! symbols per slice (EOC), as build_audio_output's dsc_cfg feeds it.
use super::*;
use crate::amdgpu_dsc::Fixed as F;

pub(super) enum AudioLink {
    Mst(DpPhySettings),
    Uhbr(UhbrSettings, u16),
}
/// A compressed stream as build_audio_output describes it: dsc_cfg's
/// bits_per_pixel (1/16 bpp) and num_slices_h.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AudioDsc {
    pub bpp_x16: u32,
    pub slices: u32,
}
impl AudioDsc {
    pub(crate) fn of(cfg: Option<&crate::amdgpu_dsc::DscConfig>) -> Option<Self> {
        cfg.map(|c| Self {
            bpp_x16: c.bpp_x16,
            slices: c.slices_h,
        })
    }
}
pub(super) fn rates(
    t: &Timing,
    bpc: u32,
    link: AudioLink,
    channels: u8,
    rates: u8,
    dsc: Option<AudioDsc>,
) -> Option<u8> {
    let lanes = match link {
        AudioLink::Mst(s) => s.lanes,
        AudioLink::Uhbr(s, _) => s.lanes,
    };
    let blank = t.h_total.checked_sub(t.h_active)?;
    if t.h_active == 0
        || blank == 0
        || t.h_total > 65535
        || !(1..=6_000_000).contains(&t.pixel_clock_khz)
        || !matches!(bpc, 8 | 10 | 12)
        || !matches!(lanes, 1 | 2 | 4)
        || !(1..=8).contains(&channels)
        || dsc.is_some_and(|d| !(1..=1024).contains(&d.bpp_x16) || !(1..=64).contains(&d.slices))
    {
        return None;
    }
    // The Linux order multiplies blank duration by the symbol clock before
    // the video/link fraction cancels the pixel clock. Reject malformed low
    // clocks that exceed 31.32's integer range at that intermediate step;
    // 810 MHz bounds both legacy and UHBR symbol clocks.
    if u64::from(blank) * 810_000 >= u64::from(t.pixel_clock_khz) * i32::MAX as u64 {
        return None;
    }
    let (link_kbps, sym_mhz, hblank_symbols, layout, overhead) = match link {
        AudioLink::Mst(settings) => {
            if !settings.mst {
                return None;
            }
            let sym_mhz = settings.rate as i32 * 27;
            // Remove FEC for the pessimistic audio budget (populate_audio_dp_link_info).
            (
                sym_mhz * 8000 * i32::from(lanes),
                F::int(sym_mhz),
                0,
                40,
                16,
            )
        }
        AudioLink::Uhbr(settings, width) => {
            let kbps = settings.rate.link_rate() * u32::from(lanes) * 9641;
            let kbps = F::int(kbps as i32).mul(F::fraction(10000, 9975)).floor();
            let sym = match settings.rate {
                UhbrRate::Uhbr10 => F::fraction(3125, 10),
                UhbrRate::Uhbr13_5 => F::fraction(421875, 1000),
                UhbrRate::Uhbr20 => F::int(625),
            };
            (kbps, sym, width, 10, 10)
        }
    };
    let hblank_ms = F::fraction(i64::from(blank), i64::from(t.pixel_clock_khz));
    let peak = match dsc {
        Some(d) => F::int(t.pixel_clock_khz as i32).mul(F::fraction(i64::from(d.bpp_x16), 16)),
        None => F::int(t.pixel_clock_khz as i32).mul_int((bpc * 3) as i32),
    };
    let frac = peak.div(F::int(link_kbps));
    let mut available =
        hblank_ms.mul_int(1000).mul(sym_mhz).mul(frac).floor() as u32 * u32::from(lanes);
    // EOC overhead, in Linux's unsigned arithmetic (a wrap passes the
    // minimum-width and main-link checks below exactly as it does there).
    available = available.wrapping_sub(dsc.map_or(0, |d| d.slices * 4));
    if available < u32::from(hblank_symbols) {
        available = 4 * u32::from(hblank_symbols);
    }
    available = available.saturating_sub(12); // main-link overhead
    let line_khz = F::fraction(i64::from(t.pixel_clock_khz), i64::from(t.h_total));
    let margin = F::fraction(110, 100);
    // Both transports map AV over four lanes, independent of physical lane
    // count. Conservatively use the eight-channel layout for 3..8 channels.
    let denom = if channels <= 2 { 4 } else { 1 };
    let align = |n: i32| ((n + 4) / 4 * 4) as u32;
    let full = align(F::int(layout + overhead).mul(margin).ceil());
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
                    .mul_int(layout)
                    .add_int(overhead)
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

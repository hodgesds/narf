//! PHY bitrates as cfg80211 computes them for `struct rate_info`
//! (`cfg80211_calculate_bitrate_ht/_vht/_he`, net/wireless/util.c), in
//! units of 100 kb/s. Every index is bounds-checked: an out-of-table MCS,
//! NSS, width or GI is `None`, never a fabricated rate.

/// HT MCS 0..=7 (the per-stream index), `nss` 1..=4, 20/40 MHz.
pub fn ht_bitrate_100kbps(mcs: u8, nss: u8, width_mhz: u16, short_gi: bool) -> Option<u32> {
    const RATE: [[u32; 8]; 2] = [
        [
            6_500_000, 13_000_000, 19_500_000, 26_000_000, 39_000_000, 52_000_000, 58_500_000,
            65_000_000,
        ],
        [
            13_500_000,
            27_000_000,
            40_500_000,
            54_000_000,
            81_000_000,
            108_000_000,
            121_500_000,
            135_000_000,
        ],
    ];
    let width = match width_mhz {
        20 => 0,
        40 => 1,
        _ => return None,
    };
    if !(1..=4).contains(&nss) {
        return None;
    }
    let mut bitrate = RATE[width]
        .get(usize::from(mcs))?
        .saturating_mul(u32::from(nss));
    if short_gi {
        bitrate = bitrate / 9 * 10;
    }
    Some((bitrate + 50_000) / 100_000)
}

/// VHT MCS 0..=9, `nss` 1..=8, 20/40/80/160 MHz.
pub fn vht_bitrate_100kbps(mcs: u8, nss: u8, width_mhz: u16, short_gi: bool) -> Option<u32> {
    const RATE: [[u32; 10]; 4] = [
        [
            6_500_000, 13_000_000, 19_500_000, 26_000_000, 39_000_000, 52_000_000, 58_500_000,
            65_000_000, 78_000_000, 86_500_000,
        ],
        [
            13_500_000,
            27_000_000,
            40_500_000,
            54_000_000,
            81_000_000,
            108_000_000,
            121_500_000,
            135_000_000,
            162_000_000,
            180_000_000,
        ],
        [
            29_300_000,
            58_500_000,
            87_800_000,
            117_000_000,
            175_500_000,
            234_000_000,
            263_300_000,
            292_500_000,
            351_000_000,
            390_000_000,
        ],
        [
            58_500_000,
            117_000_000,
            175_500_000,
            234_000_000,
            351_000_000,
            468_000_000,
            526_500_000,
            585_000_000,
            702_000_000,
            780_000_000,
        ],
    ];
    let width = match width_mhz {
        20 => 0,
        40 => 1,
        80 => 2,
        160 => 3,
        _ => return None,
    };
    if !(1..=8).contains(&nss) {
        return None;
    }
    let mut bitrate = RATE[width]
        .get(usize::from(mcs))?
        .saturating_mul(u32::from(nss));
    if short_gi {
        bitrate = bitrate / 9 * 10;
    }
    Some((bitrate + 50_000) / 100_000)
}

/// HE MCS 0..=11, `nss` 1..=8, `gi` 0/1/2 = 0.8/1.6/3.2 µs, 20..160 MHz or
/// an OFDMA resource unit (`he_ru_alloc`, the nl80211 enum ordinal).
pub fn he_bitrate_100kbps(
    mcs: u8,
    nss: u8,
    gi: u8,
    width_mhz: u16,
    he_ru_alloc: Option<u8>,
) -> Option<u32> {
    // `cfg80211_calculate_bitrate_he`'s base 1SS rates in bps for
    // 0.8 / 1.6 / 3.2 µs GI, followed by its integer scaling formula.
    const MCS_DIVISOR: [u64; 12] = [
        102_399, 51_201, 34_134, 25_599, 17_067, 12_801, 11_377, 10_239, 8_532, 7_680, 6_828, 6_144,
    ];
    const RATE_160: [u64; 3] = [960_777_777, 907_400_000, 816_666_666];
    const RATE_996: [u64; 3] = [480_388_888, 453_700_000, 408_333_333];
    const RATE_484: [u64; 3] = [229_411_111, 216_666_666, 195_000_000];
    const RATE_242: [u64; 3] = [114_711_111, 108_333_333, 97_500_000];
    const RATE_106: [u64; 3] = [40_000_000, 37_777_777, 34_000_000];
    const RATE_52: [u64; 3] = [18_820_000, 17_777_777, 16_000_000];
    const RATE_26: [u64; 3] = [9_411_111, 8_888_888, 8_000_000];

    if !(1..=8).contains(&nss) {
        return None;
    }
    let gi = usize::from(gi);
    let table = match he_ru_alloc {
        Some(6) => RATE_160,
        Some(5) => RATE_996,
        Some(4) => RATE_484,
        Some(3) => RATE_242,
        Some(2) => RATE_106,
        Some(1) => RATE_52,
        Some(0) => RATE_26,
        Some(_) => return None,
        None => match width_mhz {
            20 => RATE_242,
            40 => RATE_484,
            80 => RATE_996,
            160 => RATE_160,
            _ => return None,
        },
    };
    let base = *table.get(gi)?;
    let bitrate = base
        .saturating_mul(6_144)
        .checked_div(*MCS_DIVISOR.get(usize::from(mcs))?)?
        .saturating_mul(u64::from(nss))
        / 8;
    Some((bitrate / 10_000) as u32)
}

#[cfg(feature = "kernel-test")]
#[path = "rate_tests.rs"]
mod tests;

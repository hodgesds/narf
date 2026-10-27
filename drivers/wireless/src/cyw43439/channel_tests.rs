// SPDX-License-Identifier: ISC
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_fullmac_occupied_vht80_literal_sidebands_and_exact_span() -> TestResult {
    for (primary, center, spec, low, high) in [
        (36, 42, 0xe02a, 5170, 5250),
        (40, 42, 0xe12a, 5170, 5250),
        (44, 42, 0xe22a, 5170, 5250),
        (48, 42, 0xe32a, 5170, 5250),
        (149, 155, 0xe09b, 5735, 5815),
        (153, 155, 0xe19b, 5735, 5815),
        (157, 155, 0xe29b, 5735, 5815),
        (161, 155, 0xe39b, 5735, 5815),
    ] {
        let Some(value) = Operating::eighty(primary, center) else {
            return TestResult::Fail("literal native80MHz sideband rejected");
        };
        if value.width() != 80
            || value.chanspec() != spec
            || value.span() != (low, high)
            || value.constituents()
                != [
                    Some(center - 6),
                    Some(center - 2),
                    Some(center + 2),
                    Some(center + 6),
                ]
            || Operating::decode80(spec) != Some(value)
        {
            return TestResult::Fail("native80MHz center/sideband lost full four-quarter geometry");
        }
    }
    for (primary, center) in [
        (6, 42),
        (36, 38),
        (36, 50),
        (165, 171),
        (169, 171),
        (165, 155),
        (48, 58),
    ] {
        if Operating::eighty(primary, center).is_some() {
            return TestResult::Fail("unsupported80MHz constituent/center promoted");
        }
    }
    let mut count = 0;
    for spec in 0..=u16::MAX {
        if let Some(value) = Operating::decode80(spec) {
            count += 1;
            if value.chanspec() != spec
                || value.span().1 - value.span().0 != 80
                || primary(spec, 0) != Some(value.primary)
                || value
                    .constituents()
                    .into_iter()
                    .flatten()
                    .any(|ch| frequency(ch).is_none())
            {
                return TestResult::Fail(
                    "bounded80MHz native decoder violated exact roundtrip/span",
                );
            }
        }
    }
    if count != 24 {
        return TestResult::Fail("qualified80MHz center inventory changed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/channel",
    smoke_fullmac_occupied_vht80_literal_sidebands_and_exact_span
);

fn smoke_fullmac_occupied_ht40_literal_spans_and_exact_chanspec_roundtrips() -> TestResult {
    // IEEE20MHz constituent spacing and Linux D11AC center/sideband values.
    for (primary, secondary, spec, low, high) in [
        (6, 10, 0x1808, 2427, 2467),
        (6, 2, 0x1904, 2407, 2447),
        (36, 40, 0xd826, 5170, 5210),
        (40, 36, 0xd926, 5170, 5210),
        //149+153 center151 (0x97), lower-primary sideband0.
        (149, 153, 0xd897, 5735, 5775),
    ] {
        let Some(value) = Operating::forty(primary, secondary) else {
            return TestResult::Fail("literal40MHz occupied geometry rejected");
        };
        if value.chanspec() != spec
            || value.width() != 40
            || value.span() != (low, high)
            || Operating::decode40(spec) != Some(value)
        {
            return TestResult::Fail(
                "40MHz primary/secondary lost literal native encoding or full occupied span",
            );
        }
    }
    if Operating::decode40(0xd896).is_some() {
        return TestResult::Fail("center150 aliased unsupported primary148 into149/153");
    }
    for (primary, secondary) in [
        (0, 4),
        (14, 10),
        (10, 14),
        (6, 11),
        (13, 36),
        (36, 44),
        (165, 169),
    ] {
        if Operating::forty(primary, secondary).is_some() {
            return TestResult::Fail("unsupported40MHz constituent geometry admitted");
        }
    }
    for spec in 0..=u16::MAX {
        if let Some(value) = Operating::decode40(spec) {
            let (low, high) = value.span();
            if value.chanspec() != spec
                || high - low != 40
                || primary(spec, 0) != Some(value.primary)
                || value.secondary.is_none_or(|ch| frequency(ch).is_none())
            {
                return TestResult::Fail(
                    "occupied40MHz decoder violated bounded roundtrip/span/constituent invariants",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/channel",
    smoke_fullmac_occupied_ht40_literal_spans_and_exact_chanspec_roundtrips
);

fn smoke_fullmac_d11ac_codec_exhaustive_geometry_and_round_trips() -> TestResult {
    let mut encodings = 0;
    for channel in 0..=255 {
        if let Some(spec) = encode20(channel) {
            encodings += 1;
            if primary(spec, channel) != Some(channel)
                || frequency(channel).and_then(from_frequency) != Some(channel)
                || spec & 0xff != u16::from(channel)
                || spec & 0x3800 != 0x1000
                || spec & 0x0700 != 0
            {
                return TestResult::Fail("20 MHz channel lost frequency/encoding geometry");
            }
        }
    }
    // Fourteen 2.4 GHz channels and the explicit 29-channel 5 GHz inventory.
    if encodings != 43 {
        return TestResult::Fail("supported channel inventory changed");
    }
    let mut widths = [0usize; 4];
    for spec in 0..=u16::MAX {
        if let Some(channel) = primary(spec, 0) {
            let width = match spec & 0x3800 {
                0x1000 => 0,
                0x1800 => 1,
                0x2000 => 2,
                0x2800 => 3,
                _ => return TestResult::Fail("unsupported channel width was decoded"),
            };
            widths[width] += 1;
            let expected_band = if channel <= 14 { 0 } else { 0xc000 };
            if frequency(channel).is_none()
                || spec & 0xc000 != expected_band
                || primary(spec, channel) != Some(channel)
                || primary(spec, channel.wrapping_add(1)).is_some()
                || primary(spec ^ 0xc000, 0).is_some()
            {
                return TestResult::Fail("decoded primary violated channel/band/control identity");
            }
        }
    }
    // 43 primaries at 20 MHz; 24 2.4 GHz plus 58 5 GHz 40 MHz layouts;
    // 29 5 GHz primaries with four 80 MHz or eight 160 MHz sidebands.
    if widths != [43, 82, 116, 232] {
        return TestResult::Fail("decoder lost supported width/sideband inventory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/channel",
    smoke_fullmac_d11ac_codec_exhaustive_geometry_and_round_trips
);

fn smoke_fullmac_d11ac_twenty_mhz_channel_band_and_frequency() -> TestResult {
    // Literal brcmu_d11.h encoding and cfg80211.c channel-table values.
    for (channel, mhz, spec) in [
        (1, 2412, 0x1001),
        (14, 2484, 0x100e),
        (34, 5170, 0xd022),
        (36, 5180, 0xd024),
        (149, 5745, 0xd095),
        (165, 5825, 0xd0a5),
    ] {
        if frequency(channel) != Some(mhz)
            || from_frequency(mhz) != Some(channel)
            || encode20(channel) != Some(spec)
            || primary(spec, channel) != Some(channel)
        {
            return TestResult::Fail("D11AC 2.4/5 GHz channel geometry differs from Linux");
        }
    }
    for mhz in [0, 2413, 2490, 4920, 5160, 5905, 5955, 7115] {
        if from_frequency(mhz).is_some() {
            return TestResult::Fail("unsupported band/frequency alias was admitted");
        }
    }
    for channel in 0..=255 {
        if let Some(spec) = encode20(channel) {
            if primary(spec, 0) != Some(channel) {
                return TestResult::Fail("valid 20 MHz primary did not round trip");
            }
        } else if frequency(channel).is_some() {
            return TestResult::Fail("supported channel lost its firmware encoding");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/channel",
    smoke_fullmac_d11ac_twenty_mhz_channel_band_and_frequency
);

fn smoke_fullmac_d11ac_primary_rejects_center_sideband_and_band_confusion() -> TestResult {
    for (spec, channel) in [
        (0xd826, 36),
        (0xd926, 40),
        (0xe02a, 36),
        (0xe32a, 48),
        (0xe832, 36),
        (0xef32, 64),
    ] {
        if primary(spec, 0) != Some(channel)
            || primary(spec, channel) != Some(channel)
            || primary(spec, channel + 1).is_some()
        {
            return TestResult::Fail("wide AP center/sideband was not decoded as primary");
        }
    }
    for spec in [0x1024, 0xd006, 0xd124, 0xe42a, 0xf024, 0x5024, 0x0006] {
        if primary(spec, 0).is_some() {
            return TestResult::Fail("malformed band/width/sideband was accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/channel",
    smoke_fullmac_d11ac_primary_rejects_center_sideband_and_band_confusion
);

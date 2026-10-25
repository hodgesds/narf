// SPDX-License-Identifier: ISC
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

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

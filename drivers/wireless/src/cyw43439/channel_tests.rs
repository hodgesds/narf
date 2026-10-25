// SPDX-License-Identifier: ISC
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

#[path = "channel/linux_oracle.rs"]
mod linux_oracle;

fn smoke_fullmac_d11ac_codec_matches_compiled_original_linux() -> TestResult {
    let mut hash = 0xcbf29ce484222325u64;
    let mut count = 0;
    let mut byte = |value: u8| hash = (hash ^ u64::from(value)).wrapping_mul(0x100000001b3);
    for channel in 0..=255 {
        if let Some(spec) = encode20(channel) {
            count += 1;
            byte(channel);
            for value in spec.to_le_bytes() {
                byte(value);
            }
        }
    }
    if (count, hash) != linux_oracle::ENCODE {
        return TestResult::Fail("whole 20 MHz codec differs from original Linux C");
    }
    let mut hash = 0xcbf29ce484222325u64;
    let mut count = 0;
    for spec in 0..=u16::MAX {
        if let Some(channel) = primary(spec, 0) {
            count += 1;
            for value in spec
                .to_le_bytes()
                .into_iter()
                .chain(core::iter::once(channel))
            {
                hash = (hash ^ u64::from(value)).wrapping_mul(0x100000001b3);
            }
        }
    }
    if (count, hash) != linux_oracle::DECODE {
        return TestResult::Fail("AP primary geometry differs from original Linux C");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/channel",
    smoke_fullmac_d11ac_codec_matches_compiled_original_linux
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

//! Literal Linux/mac80211 source fixtures; these never grant RF authority.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw88_ps_native_profile_and_nonreusable_clock_confirmation() -> TestResult {
    let original = Info {
        version: 9,
        subversion: 9,
        subindex: 15,
        features: 0x1e7,
        h2c: 15,
        sections: 3,
    };
    let profile = Profile::from_firmware(0xc822, original).unwrap();
    if !profile.c2h_wake
        || !profile.clock
        || profile.tx_wake
        || profile.old_pages
        || Profile::from_firmware(0xb822, original).is_some()
        || parameters(true) != [0x20, 1, 0x21, 1, 0, 0, 0, 0]
        || parameters(false) != [0x20, 0, 0, 1, 0, 12, 0, 0]
    {
        return TestResult::Fail("actual C22 firmware features or Linux power mode bytes");
    }
    for (index, old) in [(12, true), (13, false)] {
        let info = Info {
            subindex: index,
            ..original
        };
        if Profile::from_firmware(0xc822, info).unwrap().old_pages != old {
            return TestResult::Fail("Linux C22 9.9.13 reserved-page boundary");
        }
    }
    let no_signature = Profile::from_firmware(
        0xc821,
        Info {
            features: 0x16,
            ..original
        },
    )
    .unwrap();
    if no_signature.c2h_wake
        || no_signature.clock
        || no_signature.tx_wake
        || ClockRequest::prepare(no_signature, 0, 0, true).is_some()
    {
        return TestResult::Fail("unmarked firmware feature bits authorized power transition");
    }
    let first = ClockRequest::prepare(profile, 0x7f, 0x12, true).unwrap();
    let next = ClockRequest::prepare(profile, 0xc1, 0x92, false).unwrap();
    if first.wire != 0xc1
        || next.wire != 0x40
        || first.acknowledged(0x12)
        || !first.acknowledged(0x92)
        || next.acknowledged(0x92)
        || !next.acknowledged(0x12)
        || first.acknowledged(255)
        || next.acknowledged(255)
        || ClockRequest::prepare(profile, 255, 0, true).is_some()
        || ClockRequest::prepare(profile, 0, 255, true).is_some()
        || !register_awake(0x7f)
        || register_awake(0x80)
        || register_awake(u32::MAX)
        || !wake_event(&[0x32, 9])
        || wake_event(&[0x32])
        || wake_event(&[3, 9])
    {
        return TestResult::Fail(
            "stale CPWM, removed MMIO or transport completion accepted as wake",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw88_ps_native_profile_and_nonreusable_clock_confirmation
);

fn smoke_rtw88_ps_original_station_reserved_templates_and_page_offsets() -> TestResult {
    let own = [2, 1, 2, 3, 4, 5];
    let peer = [2, 6, 7, 8, 9, 10];
    for wmm in [false, true] {
        let pages = Pages::station(own, peer, 0x123, wmm).unwrap();
        let poll = [0xa4, 0, 0x23, 0xc1, 2, 6, 7, 8, 9, 10, 2, 1, 2, 3, 4, 5];
        let null = [
            0x48, 1, 0, 0, 2, 6, 7, 8, 9, 10, 2, 1, 2, 3, 4, 5, 2, 6, 7, 8, 9, 10, 0, 0,
        ];
        // Independent source descriptor bytes. In particular PS-Poll has
        // NAV_USE_HDR and no hardware sequence; Null has the inverse.
        let poll_descriptor = [0x10, 0, 0x30, 4, 0, 0x12, 8, 0, 0, 0, 0, 0, 0, 0x85, 0, 0];
        let null_descriptor = [0x18, 0, 0x30, 0x84, 0, 0x12, 8, 0, 0, 0, 0, 0, 0, 5, 0, 0];
        if pages.bytes.len() != 464
            || pages.locations != [0, 0, 1, 3, 2, 0, 0, 0]
            || pages.bytes[..80].iter().any(|b| *b != 0)
            || pages.bytes[80..96] != poll_descriptor
            || pages.bytes[112..116] != [0; 4]
            || pages.bytes[128..144] != poll
            || pages.bytes[336..352] != null_descriptor
            || pages.bytes[368..372] != [0, 0x80, 0, 0]
            || pages.bytes[384..408] != null
            || pages.bytes[256] != if wmm { 0xc8 } else { 0x48 }
            || pages.bytes[216..220] != [0, 0, 0x80, 0]
            || pages.bytes[240..244] != [0, 0x80, 0, 0]
            || wmm && pages.bytes[280..282] != [7, 0]
        {
            return TestResult::Fail(
                "native PS-Poll/Null identity, QoS TID or reserved-page geometry",
            );
        }
    }
    for (local, ap, aid) in [
        (own, peer, 0),
        (own, peer, 2008),
        (own, own, 1),
        ([0; 6], peer, 1),
        (own, [1, 6, 7, 8, 9, 10], 1),
    ] {
        if Pages::station(local, ap, aid, true).is_some() {
            return TestResult::Fail("reserved templates admitted invalid original association");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw88_ps_original_station_reserved_templates_and_page_offsets
);

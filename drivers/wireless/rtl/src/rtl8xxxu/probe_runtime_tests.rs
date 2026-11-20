//! Gen2 probe construction regressions (pure frames). Expectations follow
//! 802.11 management frame layout (Probe Request: FC + Duration + DA +
//! SA + BSSID + Sequence Control, then SSID, Supported Rates, Extended
//! Supported Rates, DS Parameter, HT Capabilities); nothing here is a
//! hardware receipt.

use narf_kernel_test::{kernel_test_in, TestResult};

use super::Prepared;

const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const CAPS: [u8; 26] = [0x5a; 26];

/// Board-HT probe (gen2 F10): the caller's caps body rides as element
/// 45 on any channel, the frame is exactly 28 bytes longer than the
/// legacy probe, and `matches` reports the HT flag.
fn smoke_rtl8xxxu_gen2_probe_with_ht_caps() -> TestResult {
    let Ok(prepared) = Prepared::new_with_ht(OWN, 6, b"narf", 7, &CAPS, &[]) else {
        return TestResult::Fail("new_with_ht on channel 6");
    };
    let Ok(legacy) = Prepared::new(OWN, 6, b"narf", 7, false, &[]) else {
        return TestResult::Fail("legacy probe on channel 6");
    };
    let bytes = prepared.bytes();
    if bytes.len() != legacy.bytes().len() + 28
        || !prepared.matches(OWN, 6, true, false)
        || legacy.matches(OWN, 6, true, false)
    {
        return TestResult::Fail("caps element length and HT flag");
    }
    // Layout: FC/Duration, broadcast DA, own SA, broadcast BSSID,
    // sequence, SSID IE, rates, extended rates, DS channel, HT caps.
    if bytes[..4] != [0x40, 0, 0, 0]
        || bytes[4..10] != [255; 6]
        || bytes[10..16] != OWN
        || bytes[16..22] != [255; 6]
        || bytes[22..24] != (7u16 << 4).to_le_bytes()
        || bytes[24..26] != [0, 4]
        || bytes[26..30] != *b"narf"
        || bytes[30..40] != [1, 8, 2, 4, 11, 22, 12, 18, 24, 36]
        || bytes[40..46] != [50, 4, 48, 72, 96, 108]
        || bytes[46..49] != [3, 1, 6]
        || bytes[49..51] != [45, 26]
        || bytes[51..77] != CAPS
    {
        return TestResult::Fail("probe layout with HT caps");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/probe",
    smoke_rtl8xxxu_gen2_probe_with_ht_caps
);

/// `new` is unchanged by the refactor: HT stays channel-1-restricted,
/// extra IEs never repeat a carried element, and `new_with_ht` shares
/// the remaining validation (channel, SSID length, sequence).
fn smoke_rtl8xxxu_gen2_probe_validation() -> TestResult {
    if Prepared::new(OWN, 6, b"narf", 0, true, &[]).is_ok() {
        return TestResult::Fail("SISO HT off channel 1 refused");
    }
    if Prepared::new(OWN, 1, b"narf", 0, true, &[]).is_err() {
        return TestResult::Fail("SISO HT on channel 1 kept");
    }
    // An extra HT Capabilities IE is refused by both constructors.
    let extra = [
        45u8, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    if Prepared::new(OWN, 1, b"narf", 0, false, &extra).is_ok()
        || Prepared::new_with_ht(OWN, 6, b"narf", 0, &CAPS, &extra).is_ok()
    {
        return TestResult::Fail("duplicate HT element refused");
    }
    if Prepared::new_with_ht(OWN, 0, b"narf", 0, &CAPS, &[]).is_ok()
        || Prepared::new_with_ht(OWN, 14, b"narf", 0, &CAPS, &[]).is_ok()
        || Prepared::new_with_ht(OWN, 6, &[b'x'; 33], 0, &CAPS, &[]).is_ok()
        || Prepared::new_with_ht(OWN, 6, b"narf", 4096, &CAPS, &[]).is_ok()
    {
        return TestResult::Fail("shared validation");
    }
    // A non-duplicate extra IE rides last, after the caps element.
    let Ok(prepared) = Prepared::new_with_ht(OWN, 6, b"narf", 0, &CAPS, &[221, 2, 9, 9]) else {
        return TestResult::Fail("extra IE accepted");
    };
    if prepared.bytes()[77..] != [221, 2, 9, 9] {
        return TestResult::Fail("extra IE last");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/probe",
    smoke_rtl8xxxu_gen2_probe_validation
);

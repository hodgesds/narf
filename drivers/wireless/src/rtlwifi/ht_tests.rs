use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};
pub(crate) fn artifact(
    base: &Calibration,
    firmware: super::super::firmware_transport::Identity,
) -> Vec<u8> {
    artifact_on_channel(base, firmware, 1)
}
pub(crate) fn artifact_on_channel(
    base: &Calibration,
    firmware: super::super::firmware_transport::Identity,
    channel: u8,
) -> Vec<u8> {
    let mut b = alloc::vec![0;LENGTH];
    b[..4].copy_from_slice(b"NEHT");
    b[4..8].copy_from_slice(&[if channel == 1 { 2 } else { 3 }, 0, 160, 0]);
    b[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x79, 0x81]);
    b[16..48].copy_from_slice(&request_on_channel(base, firmware, channel).binding);
    b[48..80].copy_from_slice(&super::super::radio::factory_identity(base.factory()));
    b[80..112].copy_from_slice(&base.digest);
    b[112..118].copy_from_slice(&base.factory().mac);
    b[118..124].copy_from_slice(&[channel, 20, 1, 1, 0, 0]);
    b[124..126].copy_from_slice(&8i16.to_le_bytes());
    b[126..128].copy_from_slice(&80i16.to_le_bytes());
    // Inert synthetic upper bounds, never registered or supplied to PCI.
    for m in 0..8 {
        for i in 0..64 {
            let at = HEADER + m * 128 + i * 2;
            b[at..at + 2]
                .copy_from_slice(&(i as i16 * 2 + i16::from(channel - 1) * 2).to_le_bytes());
        }
    }
    b
}
pub(crate) fn ap_elements(tx: u8) -> Vec<u8> {
    // Literal peer HT20/LGI, SMPS disabled, MCS0..7, factor0/density0.
    let mut b = alloc::vec![45, 26, 12, 0, 0, tx];
    b.resize(28, 0);
    b[17] = 1;
    b.extend_from_slice(&[61, 22, 1, 0, 0, 0, 0, 0, 255]);
    b.resize(52, 0);
    b
}
fn smoke_rtl8188ee_ht20_factory_signed_nibble_pg_and_gain_boundaries() -> TestResult {
    let mut f = super::super::channel_power::tests::factory();
    for (n, expected) in [
        (0x23, [33, 32, 31, 30, 29, 28, 25, 23]),
        (0xf3, [30, 29, 28, 27, 26, 25, 22, 20]),
        (0x83, [23, 22, 21, 20, 19, 18, 15, 13]),
    ] {
        f.logical[0x1b] = n;
        if factory_gains(&f, 1) != Ok(expected) {
            return TestResult::Fail(
                "EE signed HT20 high-nibble/PG gains differ from literal source cases",
            );
        }
    }
    for mode in [2, 3] {
        f.logical[0xc1] = mode;
        f.logical[0x1b] = 0x23;
        if factory_gains(&f, 1) != Ok([22; 8]) {
            return TestResult::Fail("EE regulatory HT20 base-only profile changed");
        }
    }
    f.logical[0x16] = 0;
    f.logical[0x1b] = 0x83;
    if factory_gains(&f, 1).is_ok() {
        return TestResult::Fail("negative HT20 gain wrapped into hardware range");
    }
    f.logical[0x1b] = 255;
    if factory_gains(&f, 1).is_ok() {
        return TestResult::Fail("erased HT factory data supplied a default");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_factory_signed_nibble_pg_and_gain_boundaries
);
fn smoke_rtl8188ee_ht20_signed_program_exact_legacy_identity_and_curves() -> TestResult {
    use super::super::channel_power::tests as p;
    let base = Arc::new(p::calibration(&p::factory()));
    let firmware = super::super::firmware_transport::Identity::model();
    let bytes = artifact(&base, firmware);
    let mut different_firmware = firmware;
    different_firmware.digest[0] ^= 1;
    let cap = Cap::bootstrap();
    if Grant::parse(base.clone(), different_firmware, &bytes, Some([7; 32]), cap).is_ok() {
        return TestResult::Fail("different executable inherited HT measurements");
    }
    let grant = match Grant::parse(base.clone(), firmware, &bytes, Some([7; 32]), cap) {
        Ok(g) => g,
        Err(_) => return TestResult::Fail("valid inert HT measurement rejected"),
    };
    let permission = base.permission(&p::domain(17), 1).unwrap();
    let mut old = bytes.clone();
    old[4..6].copy_from_slice(&1u16.to_le_bytes());
    if Grant::parse(base.clone(), firmware, &old, Some([7; 32]), cap).is_ok() {
        return TestResult::Fail("NEHT v1 authorized SGI20 or enlarged RX promise");
    }
    if grant.gains(&p::domain(17), permission) != Ok([30, 30, 30, 30, 29, 28, 25, 23]) {
        return TestResult::Fail("actual HT per-rate upper envelopes changed selected gains");
    }
    for at in [
        0, 4, 6, 8, 12, 14, 16, 48, 80, 112, 118, 119, 120, 121, 122, 128,
    ] {
        let mut b = bytes.clone();
        b[at] ^= 1;
        if Grant::parse(base.clone(), firmware, &b, Some([7; 32]), cap).is_ok() {
            return TestResult::Fail("malformed or old-profile HT qualification admitted");
        }
    }
    if Grant::parse(base.clone(), firmware, &bytes, None, cap).is_ok()
        || Grant::parse(
            base.clone(),
            firmware,
            &bytes[..bytes.len() - 1],
            Some([7; 32]),
            cap,
        )
        .is_ok()
    {
        return TestResult::Fail("unsigned/truncated HT qualification admitted");
    }
    let mut unknown = bytes;
    unknown[HEADER..]
        .chunks_exact_mut(2)
        .for_each(|b| b.copy_from_slice(&UNKNOWN.to_le_bytes()));
    if Grant::parse(base, firmware, &unknown, Some([7; 32]), cap)
        .unwrap()
        .gains(&p::domain(17), permission)
        .is_ok()
    {
        return TestResult::Fail("unknown MCS measurements granted a gain");
    }
    cap.revoke();
    if grant.gains(&p::domain(17), permission).is_ok() {
        return TestResult::Fail("revoked HT source authorized native gain");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_signed_program_exact_legacy_identity_and_curves
);

fn smoke_rtl8188ee_ht20_channel_factory_groups_match_literal_linux_bounds() -> TestResult {
    let mut f = super::super::channel_power::tests::factory();
    f.logical[0x16..0x1a].copy_from_slice(&[20, 23, 26, 29]);
    for (mode, channel, expected) in [
        (0, 6, [39, 38, 37, 36, 35, 34, 31, 29]),
        (1, 1, [33, 32, 31, 30, 29, 28, 25, 23]),
        (1, 3, [25; 8]),
        (1, 5, [25; 8]),
        (1, 6, [32, 32, 32, 32, 32, 32, 30, 28]),
        (1, 8, [32, 32, 32, 32, 32, 32, 30, 28]),
        (1, 11, [35, 35, 35, 35, 35, 35, 33, 31]),
        (2, 6, [28; 8]),
        (3, 11, [31; 8]),
    ] {
        f.logical[0xc1] = mode;
        if factory_gains(&f, channel) != Ok(expected) {
            return TestResult::Fail(
                "EE channel HT factory group/PG differs from literal Linux bounds",
            );
        }
    }
    if factory_gains(&f, 0).is_ok() || factory_gains(&f, 12).is_ok() {
        return TestResult::Fail("EE HT factory group admitted an unsupported channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht_channels",
    smoke_rtl8188ee_ht20_channel_factory_groups_match_literal_linux_bounds
);
fn smoke_rtl8188ee_ht20_channel_record_cannot_alias_old_or_other_channel() -> TestResult {
    use super::super::channel_power::tests as p;
    let base = Arc::new(p::calibration_for_channel(&p::factory(), 6));
    let firmware = super::super::firmware_transport::Identity::model();
    let bytes = artifact_on_channel(&base, firmware, 6);
    let cap = Cap::bootstrap();
    let grant = Grant::parse(base.clone(), firmware, &bytes, Some([7; 32]), cap).unwrap();
    let permission = base.permission(&p::domain(17), 6).unwrap();
    if grant.gains(&p::domain(17), permission) != Ok([25, 25, 25, 25, 25, 25, 25, 23]) {
        return TestResult::Fail(
            "EE HT channel qualification did not select its own measured curve",
        );
    }
    for (at, value) in [(4, 2), (118, 1), (118, 7), (118, 12)] {
        let mut wrong = bytes.clone();
        wrong[at] = value;
        if Grant::parse(base.clone(), firmware, &wrong, Some([7; 32]), cap).is_ok() {
            return TestResult::Fail(
                "EE HT channel/version mutation inherited another signed program",
            );
        }
    }
    let old = Grant::parse(
        base.clone(),
        firmware,
        &artifact(&base, firmware),
        Some([7; 32]),
        cap,
    )
    .unwrap();
    if old.gains(&p::domain(17), permission).is_ok() {
        return TestResult::Fail("EE old channel1 HT record authorized channel6");
    }
    cap.revoke();
    if grant.gains(&p::domain(17), permission).is_ok() {
        return TestResult::Fail("EE revoked exact-channel HT record remained usable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht_channels",
    smoke_rtl8188ee_ht20_channel_record_cannot_alias_old_or_other_channel
);

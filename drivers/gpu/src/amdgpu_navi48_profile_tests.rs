use super::super::profile::{parse, show};
use super::*;
fn rdna4_profile_abi_exposes_factory_and_custom_profiles() -> TestResult {
    for (text, expected) in [
        ("0", smu::PowerProfile::BootupDefault),
        ("1\n", smu::PowerProfile::Fullscreen3d),
        ("2", smu::PowerProfile::PowerSaving),
        ("3", smu::PowerProfile::Video),
        ("4", smu::PowerProfile::Vr),
        ("5", smu::PowerProfile::Compute),
        ("7", smu::PowerProfile::Window3d),
    ] {
        assert_eq!(parse(text).map(|r| r.profile), Ok(expected));
    }
    for text in ["", "-1", "8", "compute", "3 1", "0x5", "05"] {
        assert_eq!(parse(text), Err(FsError::InvalidData));
    }
    assert_eq!(parse("6").unwrap().profile, smu::PowerProfile::Custom);
    for text in [
        "6 0 1",
        "6 2 60 0 500 0 1200 1 2 3",
        "6 0 256 0 500 0 1200 1 2 3",
        "6 0 60 0 65536 0 1200 1 2 3",
        "6 0 60 0 500 0 1200 -1 2 3",
        "6 0 60 0 500 0 1200 4294967296 2 3",
    ] {
        assert_eq!(parse(text), Err(FsError::InvalidData));
    }
    let request = parse("6 1 60 0 500 1 1200 4294967295 2 3\n").unwrap();
    assert_eq!(request.custom[0], None);
    assert_eq!(request.custom[1].unwrap().limit, u32::MAX);
    let text = show(smu::PowerProfile::Compute, None);
    assert!(text.contains("COMPUTE*"));
    assert_eq!(text.matches('*').count(), 1);
    assert!(text.contains("CUSTOM"));
    assert_eq!(text.lines().count(), 9);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    rdna4_profile_abi_exposes_factory_and_custom_profiles
);

fn rdna4_profile_telemetry_keeps_the_last_applied_factory_profile() -> TestResult {
    let mut s = sample(Ok(telemetry(0, 0)), true);
    s.profile = smu::PowerProfile::Compute;
    let (snapshot, _) = update(None, s);
    assert_eq!(snapshot.profile, smu::PowerProfile::Compute);
    let mut failed = sample(Err(smu::Error::Rejected(0xfd)), true);
    failed.profile = smu::PowerProfile::Compute;
    let (snapshot, _) = update(Some(snapshot), failed);
    assert_eq!(snapshot.profile, smu::PowerProfile::Compute);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    rdna4_profile_telemetry_keeps_the_last_applied_factory_profile
);

fn rdna4_profile_show_uses_the_firmware_coefficient_cache() -> TestResult {
    let mut values = [[smu::ActivityCoefficients::default(); 2]; 8];
    values[6][1] = smu::ActivityCoefficients {
        fps: 144,
        min_type: 1,
        min_mhz: 600,
        booster_type: 0,
        booster_mhz: 2000,
        limit: 123456,
        error: 65536,
        error_rate: 7,
    };
    let text = show(smu::PowerProfile::Custom, Some(values));
    assert!(text.contains("CUSTOM*"));
    assert_eq!(text.lines().count(), 25);
    let line = text.lines().find(|line| line.contains("123456")).unwrap();
    assert_eq!(
        line.split_whitespace().collect::<Vec<_>>(),
        ["1(", "FCLK)", "144", "1", "600", "0", "2000", "123456", "65536", "7"]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    rdna4_profile_show_uses_the_firmware_coefficient_cache
);

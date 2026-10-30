use super::super::profile::{parse, show};
use super::*;
fn rdna4_profile_abi_exposes_factory_profiles_without_custom_tuning() -> TestResult {
    for (text, expected) in [
        ("0", smu::PowerProfile::BootupDefault),
        ("1\n", smu::PowerProfile::Fullscreen3d),
        ("2", smu::PowerProfile::PowerSaving),
        ("3", smu::PowerProfile::Video),
        ("4", smu::PowerProfile::Vr),
        ("5", smu::PowerProfile::Compute),
        ("7", smu::PowerProfile::Window3d),
    ] {
        assert_eq!(parse(text), Ok(expected));
    }
    for text in ["", "-1", "8", "compute", "3 1", "0x5", "05"] {
        assert_eq!(parse(text), Err(FsError::InvalidData));
    }
    for text in ["6", "6 0 1"] {
        assert_eq!(parse(text), Err(FsError::Unsupported));
    }
    let text = show(smu::PowerProfile::Compute);
    assert!(text.contains("COMPUTE*"));
    assert_eq!(text.matches('*').count(), 1);
    assert!(!text.contains("CUSTOM"));
    assert_eq!(text.lines().count(), 8);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4-policy",
    rdna4_profile_abi_exposes_factory_profiles_without_custom_tuning
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

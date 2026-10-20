use super::*;
use crate::amdgpu_navi22_power_policy::{
    Feature, SMU_DEEP_SLEEP, SMU_DPM_UCLK, SMU_GFXOFF, SMU_HUB_PG, SMU_MEM_MVDD_SCALING,
    SMU_MEM_VDDCI_SCALING,
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Level and mask parsing follow the Linux sysfs spellings; unsupported
/// Linux levels are refused rather than silently mapped.
fn rdna2_power_controls_parse_linux_spellings() -> TestResult {
    let levels = [
        ("auto\n", Ok(GfxLevel::Auto)),
        ("low", Ok(GfxLevel::Low)),
        (" high ", Ok(GfxLevel::High)),
        ("manual", Err(FsError::Unsupported)),
        ("profile_peak", Err(FsError::Unsupported)),
        ("turbo", Err(FsError::InvalidData)),
    ];
    if levels.iter().any(|(text, want)| parse_level(text) != *want) {
        return TestResult::Fail("performance level spellings");
    }
    if parse_mask("0x0000ffff\n") != Ok(0xffff)
        || parse_mask("3fff") != Ok(0x3fff)
        || parse_mask("0xzz").is_ok()
        || parse_mask("").is_ok()
    {
        return TestResult::Fail("pp_features mask parsing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-power",
    rdna2_power_controls_parse_linux_spellings
);

/// `pp_features` writes may only move policy-owned bits, whole features at a
/// time, and keep the non-PMFW parts of the current opt-in.
fn rdna2_power_controls_pp_features_mask_rules() -> TestResult {
    let protection = 1u64 << 24 | 1 << 31; // PPT, FW_CTF
    let current = OptIn::parse(Some("cg,gfxcg,wm,hubpg"));
    let running = protection | SMU_HUB_PG;
    // Turn on GFXOFF and memory DPM, turn off hub PG.
    let memdpm = SMU_DPM_UCLK | SMU_MEM_VDDCI_SCALING | SMU_MEM_MVDD_SCALING;
    let Ok(next) = requested_optin(protection | SMU_GFXOFF | memdpm, running, current) else {
        return TestResult::Fail("valid pp_features mask refused");
    };
    if !next.contains(Feature::GfxOff)
        || !next.contains(Feature::MemoryDpm)
        || next.contains(Feature::HubPowerGating)
        || !next.contains(Feature::ClockGating)
        || !next.contains(Feature::GfxClockGating)
        || !next.watermarks
        || next.smu_bits() != SMU_GFXOFF | memdpm
    {
        return TestResult::Fail("pp_features re-plan lost or added features");
    }
    // Clearing a protection bit is not a policy feature's to change.
    if requested_optin(SMU_HUB_PG, running, current) != Err(FsError::OperationNotPermitted) {
        return TestResult::Fail("protection bit change accepted");
    }
    // Half of a multi-bit feature is malformed.
    if requested_optin(
        protection | SMU_HUB_PG | (SMU_DEEP_SLEEP & (1 << 12)),
        running,
        current,
    ) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("partial deep-sleep mask accepted");
    }
    // Writing the running mask back changes nothing.
    if requested_optin(running, running, current) != Ok(current) {
        return TestResult::Fail("identity write changed the opt-in");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-power",
    rdna2_power_controls_pp_features_mask_rules
);

/// The show text is `smu_cmn_get_pp_feature_mask`'s layout.
fn rdna2_power_controls_pp_features_format_matches_linux() -> TestResult {
    let text = format_features(1 << 1 | 1 << 44 | 1 << 20);
    let mut lines = text.lines();
    let expected = [
        "features high: 0x00001000 low: 0x00100002",
        "No. Feature               Bit : State",
        "00. DPM_PREFETCHER       ( 0) : disabled",
        "01. DPM_GFXCLK           ( 1) : enabled",
    ];
    if expected.iter().any(|want| lines.next() != Some(*want)) {
        return TestResult::Fail("pp_features header or first rows");
    }
    if !text.contains("20. GFXOFF               (20) : enabled\n")
        || !text.contains("22. MM_DPM_PG            (22) : disabled\n")
        || !text.contains("23. PPT                  (24) : disabled\n")
        || !text.ends_with("42. RSMU_SMN_CG          (44) : enabled\n")
        || text.lines().count() != 2 + FEATURE_NAMES.len()
    {
        return TestResult::Fail("pp_features rows skip unmapped bits in bit order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-power",
    rdna2_power_controls_pp_features_format_matches_linux
);

/// Without a published boot, writes fail with ENODEV and reads are empty.
fn rdna2_power_controls_refuse_without_device() -> TestResult {
    if ready() {
        return TestResult::Skip("an RX 6000 boot published its controls");
    }
    if request_level("high") != Err(FsError::NoDevice)
        || request_features("0x0") != Err(FsError::NoDevice)
        || request_level("bogus") != Err(FsError::InvalidData)
        || !features().is_empty()
        || level() != "auto"
    {
        return TestResult::Fail("controls acted without a device");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-power",
    rdna2_power_controls_refuse_without_device
);

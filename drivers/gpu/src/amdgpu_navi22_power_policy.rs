//! Discrete RDNA2 power-saving policy. Linux enables GFXOFF, GC/hub clock and
//! power gating, memory/fabric DPM and deep sleep on sienna_cichlid by
//! default (`amdgpu_pp_feature_mask`, `adev->cg_flags`/`pg_flags` in nv.c,
//! `sienna_cichlid_get_allowed_feature_mask`), but on that platform DC has
//! already admitted every stream: DML validated p-state/stutter support,
//! HUBBUB watermark sets and the PMFW `TABLE_WATERMARKS` are installed, and
//! clock floors are requested through `smu_display_clock_voltage_request`.
//! This module states, as types, what each feature needs from display
//! admission and from the driver.
//!
//! `Policy::new()`/`Default` disable every feature and `request` refuses
//! everything (`HARDWARE_VALIDATED` is false). A gate opens only through
//! [`Policy::request_opted_in`] with an [`OptIn`] from `amdgpu.rdna2_pg=`;
//! when that argument is absent the boot uses
//! `amdgpu_rdna2::options::DEFAULT_POWER_SAVING` (every feature) as an
//! implicit opt-in, and `amdgpu.rdna2_pg=none` opts out. Either way every
//! display-admission and driver prerequisite still applies; only the
//! hardware-validation facts (`HARDWARE_VALIDATED`, `recovery_validated`)
//! are waived. The sequences
//! that then run live in `amdgpu_navi22_gating` (clock gating),
//! `amdgpu_navi22_gfxoff` (GFXOFF), the SMU owner (feature bits) and
//! `amdgpu_dcn30_watermarks` (the PMFW watermark table).
//!
//! `Smu::enable_display_power` (UCLK/FCLK/SOCCLK/DCEFCLK DPM) is the DCN
//! owner's own, separately contracted path and is not driven from here.

/// Bits of smu11_driver_if_sienna_cichlid.h FEATURE_*_BIT.
const fn bit(n: u32) -> u64 {
    1 << n
}
pub const SMU_DPM_UCLK: u64 = bit(3); // linux-lit: 3=FEATURE_DPM_UCLK_BIT
pub const SMU_DPM_FCLK: u64 = bit(4); // linux-lit: 4=FEATURE_DPM_FCLK_BIT
pub const SMU_MEM_VDDCI_SCALING: u64 = bit(10); // linux-lit: 10=FEATURE_MEM_VDDCI_SCALING_BIT
pub const SMU_MEM_MVDD_SCALING: u64 = bit(11); // linux-lit: 11=FEATURE_MEM_MVDD_SCALING_BIT
/// DS_GFXCLK, DS_SOCCLK, DS_FCLK, DS_LCLK, DS_DCEFCLK, DS_UCLK, GFX_ULV.
// linux-lit: 12=FEATURE_DS_GFXCLK_BIT; 13=FEATURE_DS_SOCCLK_BIT; 14=FEATURE_DS_FCLK_BIT; 15=FEATURE_DS_LCLK_BIT; 16=FEATURE_DS_DCEFCLK_BIT; 17=FEATURE_DS_UCLK_BIT; 18=FEATURE_GFX_ULV_BIT
pub const SMU_DEEP_SLEEP: u64 = bit(12) | bit(13) | bit(14) | bit(15) | bit(16) | bit(17) | bit(18);
pub const SMU_GFXOFF: u64 = bit(20); // linux-lit: 20=FEATURE_GFXOFF_BIT
pub const SMU_BACO: u64 = bit(21); // linux-lit: 21=FEATURE_BACO_BIT
pub const SMU_MM_DPM_PG: u64 = bit(22); // linux-lit: 22=FEATURE_MM_DPM_PG_BIT
/// MMHUB_PG, ATHUB_PG.
// linux-lit: 40=FEATURE_MMHUB_PG_BIT; 41=FEATURE_ATHUB_PG_BIT
pub const SMU_HUB_PG: u64 = bit(40) | bit(41);

/// Policy switches the SMU/RLC could flip once admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feature {
    /// GC power-off between submissions (`smu_v11_0_gfx_off_control`).
    GfxOff,
    /// MMHUB/ATHUB/HDP/IH/SDMA/SMUIO clock gating (nv.c cg_flags): the
    /// non-GC IP blocks of `amdgpu_device_set_cg_state`.
    ClockGating,
    /// MMHUB/ATHUB power gating (`FEATURE_MMHUB_PG/ATHUB_PG`).
    HubPowerGating,
    /// UCLK switching (`FEATURE_DPM_UCLK` with VDDCI/MVDD scaling).
    MemoryDpm,
    /// FCLK switching (`FEATURE_DPM_FCLK`).
    FabricDpm,
    /// DS_* clocks and GFX ULV.
    DeepSleep,
    /// GC MGCG/CGCG/CGLS/3D CGCG (`gfx_v10_0_update_gfx_clock_gating`).
    /// GC-internal: display fetch does not pass through GC.
    GfxClockGating,
}
pub const FEATURES: [Feature; 7] = [
    Feature::GfxOff,
    Feature::ClockGating,
    Feature::HubPowerGating,
    Feature::MemoryDpm,
    Feature::FabricDpm,
    Feature::DeepSleep,
    Feature::GfxClockGating,
];

/// What the display owner certifies for the current configuration (DML30
/// mode support plus programmed state). Produced only by the DCN owner.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayAdmission {
    /// Streams the admission covers; zero means all pipes are retired.
    pub active_streams: u8,
    /// DML `DRAMClockChangeSupport` (UCLK switch inside vblank or none).
    pub dram_clock_change: bool,
    /// DML FCLK change support for the admitted configuration.
    pub fclk_change: bool,
    /// DML stutter (self-refresh) support with its enter/exit latencies.
    pub stutter: bool,
    /// HUBBUB watermark sets A-D and the PMFW `TABLE_WATERMARKS` installed
    /// (`smu_set_watermarks_for_clock_ranges`).
    pub watermarks: bool,
    /// Bandwidth floors requested from PMFW (MHz).
    pub min_uclk_mhz: u16,
    pub min_fclk_mhz: u16,
    pub min_dcefclk_mhz: u16,
    /// Deep-sleep DCEFCLK floor (`SetMinDeepSleepDcefclk`) accepted.
    pub deep_sleep_dcefclk: bool,
}

/// Driver-side prerequisites, independent of display.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriverReadiness {
    /// Every GC register access is GFXOFF-safe (`amdgpu_gfx_off_ctrl`
    /// around MMIO, KIQ/RLCG paths), including TDR sampling.
    pub gfxoff_safe_gc_access: bool,
    /// RLC safe-mode entry/exit around CG programming.
    pub rlc_safe_mode: bool,
    /// Hang recovery has been hardware-validated (gating complicates it).
    pub recovery_validated: bool,
}

/// What one feature needs before it may be allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requirement {
    pub feature: Feature,
    /// SMU feature bits it would add to the allowed mask.
    pub smu_bits: u64,
    pub needs_watermarks: bool,
    pub needs_dram_clock_change: bool,
    pub needs_fclk_change: bool,
    pub needs_stutter: bool,
    pub needs_gfxoff_safe_access: bool,
    pub needs_rlc_safe_mode: bool,
}
pub const fn requirement(feature: Feature) -> Requirement {
    let none = Requirement {
        feature,
        smu_bits: 0,
        needs_watermarks: false,
        needs_dram_clock_change: false,
        needs_fclk_change: false,
        needs_stutter: false,
        needs_gfxoff_safe_access: false,
        needs_rlc_safe_mode: false,
    };
    match feature {
        // GC-internal: display fetch goes through MMHUB, not GC, but every
        // driver GC access must tolerate the powered-off state.
        Feature::GfxOff => Requirement {
            smu_bits: SMU_GFXOFF,
            needs_gfxoff_safe_access: true,
            needs_rlc_safe_mode: true,
            ..none
        },
        // Hub clock gating adds latency to display fetch: watermarks must
        // account for it.
        Feature::ClockGating => Requirement {
            needs_watermarks: true,
            needs_rlc_safe_mode: true,
            ..none
        },
        Feature::HubPowerGating => Requirement {
            smu_bits: SMU_HUB_PG,
            needs_watermarks: true,
            needs_stutter: true,
            ..none
        },
        Feature::MemoryDpm => Requirement {
            smu_bits: SMU_DPM_UCLK | SMU_MEM_VDDCI_SCALING | SMU_MEM_MVDD_SCALING,
            needs_watermarks: true,
            needs_dram_clock_change: true,
            ..none
        },
        Feature::FabricDpm => Requirement {
            smu_bits: SMU_DPM_FCLK,
            needs_watermarks: true,
            needs_fclk_change: true,
            ..none
        },
        Feature::DeepSleep => Requirement {
            smu_bits: SMU_DEEP_SLEEP,
            needs_watermarks: true,
            needs_stutter: true,
            ..none
        },
        Feature::GfxClockGating => Requirement {
            needs_rlc_safe_mode: true,
            ..none
        },
    }
}

/// Features the operator opted into with `amdgpu.rdna2_pg=a,b,...`
/// (tokens `gfxoff`, `cg`, `gfxcg`, `hubpg`, `memdpm`, `fclkdpm`, `ds`, and
/// `wm` for the PMFW watermark table). Absent or unparsable: nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OptIn {
    features: u8,
    /// Upload the PMFW `TABLE_WATERMARKS` (`dcn3_notify_wm_ranges`).
    pub watermarks: bool,
}
impl OptIn {
    pub const NONE: Self = Self {
        features: 0,
        watermarks: false,
    };
    /// Parse the boot argument's value. Any unknown or empty token rejects
    /// the whole list, so a typo never enables a different feature set.
    pub fn parse(value: Option<&str>) -> Self {
        let Some(value) = value else {
            return Self::NONE;
        };
        let mut optin = Self::NONE;
        for token in value.split(',') {
            let feature = match token.trim() {
                "gfxoff" => Feature::GfxOff,
                "cg" => Feature::ClockGating,
                "gfxcg" => Feature::GfxClockGating,
                "hubpg" => Feature::HubPowerGating,
                "memdpm" => Feature::MemoryDpm,
                "fclkdpm" => Feature::FabricDpm,
                "ds" => Feature::DeepSleep,
                "wm" => {
                    optin.watermarks = true;
                    continue;
                }
                _ => return Self::NONE,
            };
            optin.features |= 1 << feature as u8;
        }
        optin
    }
    pub fn contains(self, feature: Feature) -> bool {
        self.features & 1 << feature as u8 != 0
    }
    pub fn is_empty(self) -> bool {
        self.features == 0 && !self.watermarks
    }
    /// This opt-in with `feature` added or removed.
    pub fn with(mut self, feature: Feature, on: bool) -> Self {
        if on {
            self.features |= 1 << feature as u8;
        } else {
            self.features &= !(1 << feature as u8);
        }
        self
    }
    /// The PMFW bits of the opted-in features (`pp_features` view).
    pub fn smu_bits(self) -> u64 {
        FEATURES
            .iter()
            .filter(|f| self.contains(**f))
            .fold(0, |mask, f| mask | requirement(*f).smu_bits)
    }
    /// Replace the PMFW-backed features with exactly those whose bits are
    /// set in `mask`, keeping clock gating and watermarks. A feature must be
    /// named by all of its bits or none (`InvalidData` otherwise); bits no
    /// policy feature owns are not part of the result.
    pub fn with_smu_mask(self, mask: u64) -> Option<Self> {
        let mut optin = self;
        for feature in FEATURES {
            let bits = requirement(feature).smu_bits;
            if bits == 0 {
                continue;
            }
            match mask & bits {
                0 => optin = optin.with(feature, false),
                set if set == bits => optin = optin.with(feature, true),
                _ => return None,
            }
        }
        Some(optin)
    }
}
/// Every PMFW bit some policy feature owns: the only bits `pp_features` may
/// change.
pub fn policy_smu_bits() -> u64 {
    FEATURES
        .iter()
        .fold(0, |mask, f| mask | requirement(*f).smu_bits)
}

/// No feature here has run on an RX 6750 XT under NARF.
pub const HARDWARE_VALIDATED: bool = false;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No display admission was supplied (DCN owner absent).
    NoAdmission,
    /// The admission does not provide what the feature needs.
    Display(Feature),
    /// A driver-side prerequisite is missing.
    Driver(Feature),
    /// Requirements met, but enabling stays off until validated.
    NotValidated(Feature),
    /// `request_opted_in` for a feature the boot argument did not name.
    NotOptedIn(Feature),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Disabled,
    Allowed,
}

/// Per-feature gates. `Default` and `new` are all `Disabled`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    gates: [Gate; FEATURES.len()],
}
impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}
impl Policy {
    pub const fn new() -> Self {
        Self {
            gates: [Gate::Disabled; FEATURES.len()],
        }
    }
    pub fn gate(&self, feature: Feature) -> Gate {
        self.gates[feature as usize]
    }
    /// Check one feature against an admission. Never allows anything while
    /// `HARDWARE_VALIDATED` is false; the refusal names what is missing.
    pub fn request(
        &mut self,
        feature: Feature,
        admission: Option<&DisplayAdmission>,
        driver: &DriverReadiness,
    ) -> Result<(), Refusal> {
        check(feature, admission, driver)?;
        if !driver.recovery_validated {
            return Err(Refusal::Driver(feature));
        }
        if !HARDWARE_VALIDATED {
            return Err(Refusal::NotValidated(feature));
        }
        self.gates[feature as usize] = Gate::Allowed;
        Ok(())
    }
    /// The explicit opt-in path: `optin` must name `feature`, and every
    /// display-admission and driver-software prerequisite still applies.
    /// Only the hardware-validation facts are waived by the opt-in.
    pub fn request_opted_in(
        &mut self,
        feature: Feature,
        admission: Option<&DisplayAdmission>,
        driver: &DriverReadiness,
        optin: OptIn,
    ) -> Result<(), Refusal> {
        if !optin.contains(feature) {
            return Err(Refusal::NotOptedIn(feature));
        }
        check(feature, admission, driver)?;
        self.gates[feature as usize] = Gate::Allowed;
        Ok(())
    }
    /// Close a gate again (the feature was turned off).
    pub fn revoke(&mut self, feature: Feature) {
        self.gates[feature as usize] = Gate::Disabled;
    }
    /// SMU feature bits this policy adds to the boot allowed mask.
    pub fn smu_features(&self) -> u64 {
        FEATURES
            .iter()
            .filter(|f| self.gate(**f) == Gate::Allowed)
            .fold(0, |mask, f| mask | requirement(*f).smu_bits)
    }
    pub fn gfxoff(&self) -> bool {
        self.gate(Feature::GfxOff) == Gate::Allowed
    }
    pub fn clock_gating(&self) -> bool {
        self.gate(Feature::ClockGating) == Gate::Allowed
    }
    pub fn gfx_clock_gating(&self) -> bool {
        self.gate(Feature::GfxClockGating) == Gate::Allowed
    }
}

/// Display and driver-software prerequisites shared by both request paths.
fn check(
    feature: Feature,
    admission: Option<&DisplayAdmission>,
    driver: &DriverReadiness,
) -> Result<(), Refusal> {
    let r = requirement(feature);
    let display_needed =
        r.needs_watermarks || r.needs_dram_clock_change || r.needs_fclk_change || r.needs_stutter;
    if display_needed {
        let a = admission.ok_or(Refusal::NoAdmission)?;
        // Retired pipes impose no display constraint.
        if a.active_streams != 0
            && ((r.needs_watermarks && !a.watermarks)
                || (r.needs_dram_clock_change && !a.dram_clock_change)
                || (r.needs_fclk_change && !a.fclk_change)
                || (r.needs_stutter && !(a.stutter && a.deep_sleep_dcefclk)))
        {
            return Err(Refusal::Display(feature));
        }
    }
    if (r.needs_gfxoff_safe_access && !driver.gfxoff_safe_gc_access)
        || (r.needs_rlc_safe_mode && !driver.rlc_safe_mode)
    {
        return Err(Refusal::Driver(feature));
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn navi22_power_policy_defaults_to_everything_disabled() -> TestResult {
        let policy = Policy::default();
        if FEATURES.iter().any(|f| policy.gate(*f) != Gate::Disabled)
            || policy.smu_features() != 0
            || policy.gfxoff()
            || policy.clock_gating()
            || Policy::new() != policy
        {
            return TestResult::Fail("a power-saving feature is enabled by default");
        }
        // The cold-boot SMU policy (even with every board feature present)
        // and the display transition exclude GFXOFF, gating and deep sleep;
        // only the DCN-owned display transition may add UCLK/FCLK DPM.
        let boot = crate::amdgpu_power_navi22::BootPolicy::from_features(u64::MAX).unwrap();
        let gated = SMU_GFXOFF | SMU_DEEP_SLEEP | SMU_HUB_PG | SMU_BACO | SMU_MM_DPM_PG;
        if boot.allowed() & (gated | SMU_DPM_UCLK | SMU_DPM_FCLK) != 0 {
            return TestResult::Fail("boot policy allows a gated feature");
        }
        if boot.display_allowed().unwrap() & gated != 0 {
            return TestResult::Fail("display transition allows GFXOFF/gating/deep sleep");
        }
        // Bits match smu11_driver_if_sienna_cichlid.h (tests/smu11_metrics.c).
        if SMU_GFXOFF != 1 << 20 || SMU_DPM_UCLK != 1 << 3 || SMU_HUB_PG != 3 << 40 {
            return TestResult::Fail("feature bit numbering");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi22-power",
        navi22_power_policy_defaults_to_everything_disabled
    );

    fn navi22_power_policy_never_enables_and_names_what_is_missing() -> TestResult {
        let full = DisplayAdmission {
            active_streams: 1,
            dram_clock_change: true,
            fclk_change: true,
            stutter: true,
            watermarks: true,
            min_uclk_mhz: 1000,
            min_fclk_mhz: 1200,
            min_dcefclk_mhz: 600,
            deep_sleep_dcefclk: true,
        };
        let ready = DriverReadiness {
            gfxoff_safe_gc_access: true,
            rlc_safe_mode: true,
            recovery_validated: true,
        };
        let mut policy = Policy::new();
        for feature in FEATURES {
            if policy.request(feature, Some(&full), &ready) != Err(Refusal::NotValidated(feature)) {
                return TestResult::Fail("fully admitted feature was not refused");
            }
        }
        if policy != Policy::new() || policy.smu_features() != 0 {
            return TestResult::Fail("a refused request changed the policy");
        }
        // Display-dependent features need an admission and its guarantees.
        if policy.request(Feature::MemoryDpm, None, &ready) != Err(Refusal::NoAdmission) {
            return TestResult::Fail("memory DPM without admission");
        }
        let no_pstate = DisplayAdmission {
            dram_clock_change: false,
            ..full
        };
        if policy.request(Feature::MemoryDpm, Some(&no_pstate), &ready)
            != Err(Refusal::Display(Feature::MemoryDpm))
            || policy.request(Feature::FabricDpm, Some(&no_pstate), &ready)
                != Err(Refusal::NotValidated(Feature::FabricDpm))
        {
            return TestResult::Fail("p-state requirement");
        }
        let no_watermarks = DisplayAdmission {
            watermarks: false,
            ..full
        };
        for feature in [Feature::ClockGating, Feature::DeepSleep, Feature::FabricDpm] {
            if policy.request(feature, Some(&no_watermarks), &ready)
                != Err(Refusal::Display(feature))
            {
                return TestResult::Fail("watermark requirement");
            }
        }
        // GFXOFF needs no display admission, but GFXOFF-safe GC access.
        let unsafe_gc = DriverReadiness {
            gfxoff_safe_gc_access: false,
            ..ready
        };
        if policy.request(Feature::GfxOff, None, &unsafe_gc)
            != Err(Refusal::Driver(Feature::GfxOff))
            || policy.request(Feature::GfxOff, None, &ready)
                != Err(Refusal::NotValidated(Feature::GfxOff))
        {
            return TestResult::Fail("GFXOFF prerequisites");
        }
        // Without validated recovery nothing passes the driver check.
        let unrecovered = DriverReadiness {
            recovery_validated: false,
            ..ready
        };
        if FEATURES
            .iter()
            .any(|f| policy.request(*f, Some(&full), &unrecovered) != Err(Refusal::Driver(*f)))
        {
            return TestResult::Fail("recovery validation prerequisite");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi22-power",
        navi22_power_policy_never_enables_and_names_what_is_missing
    );

    fn navi22_power_policy_opt_in_is_explicit_and_keeps_prerequisites() -> TestResult {
        // A default boot has no `amdgpu.navi22_pg`: nothing is opted in and
        // every opted-in request is refused without touching the policy.
        let none = OptIn::parse(None);
        if none != OptIn::NONE || !none.is_empty() {
            return TestResult::Fail("absent boot argument opted in");
        }
        for bad in ["", "gfxoff,", "gfxoff,bogus", "GFXOFF", "all", "gfxoff;cg"] {
            if OptIn::parse(Some(bad)) != OptIn::NONE {
                return TestResult::Fail("malformed opt-in accepted");
            }
        }
        let ready = DriverReadiness {
            gfxoff_safe_gc_access: true,
            rlc_safe_mode: true,
            recovery_validated: false,
        };
        let full = DisplayAdmission {
            active_streams: 1,
            dram_clock_change: true,
            fclk_change: true,
            stutter: true,
            watermarks: true,
            min_uclk_mhz: 1000,
            min_fclk_mhz: 1200,
            min_dcefclk_mhz: 600,
            deep_sleep_dcefclk: true,
        };
        let mut policy = Policy::new();
        for feature in FEATURES {
            if policy.request_opted_in(feature, Some(&full), &ready, none)
                != Err(Refusal::NotOptedIn(feature))
            {
                return TestResult::Fail("feature allowed without opt-in");
            }
        }
        if policy != Policy::new() {
            return TestResult::Fail("refused opt-in changed the policy");
        }
        let optin = OptIn::parse(Some("gfxoff, cg,gfxcg,hubpg,memdpm,fclkdpm,ds,wm"));
        if FEATURES.iter().any(|f| !optin.contains(*f)) || !optin.watermarks {
            return TestResult::Fail("opt-in tokens");
        }
        if OptIn::parse(Some("gfxcg")).contains(Feature::ClockGating) {
            return TestResult::Fail("gfxcg opted into SoC gating");
        }
        // The kms admission today: DML DRAM change only, no watermarks.
        let kms = DisplayAdmission {
            fclk_change: false,
            stutter: false,
            watermarks: false,
            deep_sleep_dcefclk: false,
            ..full
        };
        for feature in [
            Feature::ClockGating,
            Feature::HubPowerGating,
            Feature::MemoryDpm,
            Feature::FabricDpm,
            Feature::DeepSleep,
        ] {
            if policy.request_opted_in(feature, Some(&kms), &ready, optin)
                != Err(Refusal::Display(feature))
                || policy.request_opted_in(feature, None, &ready, optin)
                    != Err(Refusal::NoAdmission)
            {
                return TestResult::Fail("opt-in bypassed display admission");
            }
        }
        let unsafe_gc = DriverReadiness {
            gfxoff_safe_gc_access: false,
            ..ready
        };
        let no_safe_mode = DriverReadiness {
            rlc_safe_mode: false,
            ..ready
        };
        if policy.request_opted_in(Feature::GfxOff, None, &unsafe_gc, optin)
            != Err(Refusal::Driver(Feature::GfxOff))
            || policy.request_opted_in(Feature::GfxClockGating, None, &no_safe_mode, optin)
                != Err(Refusal::Driver(Feature::GfxClockGating))
        {
            return TestResult::Fail("opt-in bypassed driver readiness");
        }
        if policy != Policy::new() {
            return TestResult::Fail("refusal changed the policy");
        }
        // GC-only features need no display admission.
        if policy.request_opted_in(Feature::GfxClockGating, None, &ready, optin) != Ok(())
            || policy.request_opted_in(Feature::GfxOff, None, &ready, optin) != Ok(())
            || !policy.gfx_clock_gating()
            || !policy.gfxoff()
            || policy.clock_gating()
            || policy.smu_features() != SMU_GFXOFF
        {
            return TestResult::Fail("admitted GC features");
        }
        policy.revoke(Feature::GfxOff);
        if policy.gfxoff() || policy.smu_features() != 0 {
            return TestResult::Fail("revoke");
        }
        // The validated path still refuses everything.
        if policy.request(Feature::GfxClockGating, None, &ready)
            != Err(Refusal::Driver(Feature::GfxClockGating))
        {
            return TestResult::Fail("validated path allowed unvalidated recovery");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi22-power",
        navi22_power_policy_opt_in_is_explicit_and_keeps_prerequisites
    );
}

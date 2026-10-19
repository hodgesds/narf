//! The explicit `amdgpu.rdna2_pg=` opt-in path (`navi22_pg` alias): Linux's late-init power
//! saving for sienna_cichlid, applied to a completed discrete RDNA2 boot only for
//! the features the operator named and the policy admitted.
//!
//! Order, as Linux reaches the same state (`dcn30_init_hw` →
//! `amdgpu_device_ip_late_init`'s `set_cg_state(GATE)` then
//! `set_pg_state(GATE)` → DC clock updates):
//!
//! 1. `wm`: the PMFW watermark range table (`dcn3_notify_wm_ranges`).
//! 2. Clock gating over the admitted blocks (`amdgpu_navi22_gating`).
//! 3. PMFW feature bits: MMHUB/ATHUB PG, DS_* and FEATURE_GFXOFF, then the
//!    initial `DisallowGfxOff` (Linux's `gfx_off_req_count = 1`).
//! 4. UCLK/FCLK hard minimums lowered to what the display admission
//!    validated (`dcn3_update_clocks`).
//! 5. After the owner lock is released, the platform starts the GFXOFF
//!    controller, which gates GFX (`amdgpu_gfx_off_ctrl(true)`).
//!
//! [`remove`] undoes it in reverse. A default boot never reaches this file:
//! the boot argument is absent, so [`OptIn::NONE`] plans nothing.
use crate::amdgpu_navi22_gating::{self as gating, Blocks, Gating};
use crate::amdgpu_navi22_power_policy::{
    self as policy, DisplayAdmission, DriverReadiness, Feature, OptIn, Policy, Refusal, FEATURES,
};
use crate::{amdgpu::AmdGpu, amdgpu_smu_navi22 as smu};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a completed boot, or power saving was already applied/removed.
    Busy,
    /// A feature needs the native display pipeline, which is absent.
    NoDisplay,
    Allocation,
    Smu(smu::Error),
    Gating(gating::Error),
    Clocks(crate::amdgpu_dcn_clk::Error),
    GfxOff(crate::amdgpu_navi22_gfxoff::Error),
}

/// The decision for one opt-in: which gates opened and why the rest did not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub policy: Policy,
    pub refusals: [Option<Refusal>; FEATURES.len()],
}
impl Plan {
    /// Clock-gating blocks the plan admits.
    pub fn blocks(&self) -> Blocks {
        let mut blocks = Blocks::NONE;
        if self.policy.gfx_clock_gating() {
            blocks = blocks.union(Blocks::GFX);
        }
        if self.policy.clock_gating() {
            blocks = blocks.union(Blocks::SOC);
        }
        blocks
    }
    /// PMFW bits this path enables. UCLK/FCLK DPM and their rails are the
    /// display transition's (`Smu::enable_display_power`); here only their
    /// floors move.
    pub fn smu_enable(&self) -> u64 {
        self.policy.smu_features()
            & (policy::SMU_GFXOFF | policy::SMU_HUB_PG | policy::SMU_DEEP_SLEEP)
    }
    pub fn is_empty(&self) -> bool {
        self.policy == Policy::new()
    }
}
/// Evaluate every feature against the opt-in, the display admission and the
/// driver's readiness. Pure; no I/O.
pub fn plan(optin: OptIn, admission: Option<&DisplayAdmission>, driver: &DriverReadiness) -> Plan {
    let mut policy = Policy::new();
    let mut refusals = [None; FEATURES.len()];
    for (slot, feature) in refusals.iter_mut().zip(FEATURES) {
        *slot = policy
            .request_opted_in(feature, admission, driver, optin)
            .err();
    }
    Plan { policy, refusals }
}
/// What the driver can certify: RLC safe mode is implemented by the gating
/// owner; GC access is GFXOFF-safe only once the uapi/CS owner declared its
/// GC MMIO paths guarded. Recovery is not hardware-validated.
pub fn readiness() -> DriverReadiness {
    DriverReadiness {
        gfxoff_safe_gc_access: crate::amdgpu_navi22_gfxoff::gc_access_guarded(),
        rlc_safe_mode: true,
        recovery_validated: false,
    }
}

/// What one opt-in applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applied {
    pub plan: Plan,
    /// The PMFW watermark table was uploaded.
    pub watermarks: bool,
    /// PMFW bits enabled here (and disabled again by `remove`).
    pub smu_bits: u64,
    pub blocks: Blocks,
    /// UCLK/FCLK hard minimums in MHz after the change, when moved.
    pub uclk_floor_mhz: Option<u16>,
    pub fclk_floor_mhz: Option<u16>,
}

/// Retained across the boot: the gating owner and the watermark buffer
/// PMFW was given (never reused once published).
#[derive(Debug)]
pub(crate) struct Retained {
    gating: Option<Gating>,
    _watermarks: Option<crate::amdgpu_vram::Reservation>,
    applied: Applied,
    removed: bool,
}
impl Retained {
    pub(crate) fn applied(&self) -> Option<Applied> {
        (!self.removed).then_some(self.applied)
    }
}

/// The completed boot's owners this path drives.
pub(crate) struct Parts<'a> {
    pub gpu: &'a AmdGpu,
    pub authority: Cap<BusDeviceCap, Write>,
    pub pool: &'a crate::amdgpu_vram::Pool,
    pub smu: &'a mut smu::Smu,
    pub pipeline: Option<&'a mut crate::amdgpu_navi22_modeset::Pipeline>,
    pub admission: Option<DisplayAdmission>,
}

async fn upload_watermarks(
    parts: &mut Parts<'_>,
) -> Result<crate::amdgpu_vram::Reservation, Error> {
    use crate::amdgpu_dcn30_watermarks as wm;
    let clocks = parts
        .pipeline
        .as_deref_mut()
        .ok_or(Error::NoDisplay)?
        .clock_manager();
    let levels = clocks.levels().ok_or(Error::NoDisplay)?;
    let min_uclk = *levels
        .range(crate::amdgpu_dcn30_clk::Clock::Memory)
        .mhz()
        .first()
        .ok_or(Error::NoDisplay)?;
    let table = wm::encode(&wm::navi22_ranges(min_uclk));
    let nbio = crate::amdgpu_psp_ring::bank(
        parts.gpu,
        crate::amdgpu_discovery::HW_ID_NBIF,
        &[(3, 3, 1)],
        2,
        0x12d,
    )
    .map_err(|_| Error::Clocks(crate::amdgpu_dcn_clk::Error::Unsupported))?;
    let mut memory = parts
        .pool
        .reserve(wm::BYTES as u64)
        .map_err(|_| Error::Allocation)?;
    // SAFETY: retained reservation of this GPU's pool, its BAR5 mapping and
    // NBIF base-2 bank bounded above; Parts' owner holds the GPU exclusively.
    unsafe { wm::stage(&memory, parts.gpu.regs, nbio, &table) }.map_err(Error::Clocks)?;
    // From here PMFW may read it: never return it to the pool.
    memory.publish();
    let address = memory.address();
    wm::notify(clocks, address).await.map_err(Error::Clocks)?;
    Ok(memory)
}

/// Apply the opt-in once.
///
/// # Safety
/// `parts` are the owners of one completed Navi22 boot under its owner lock;
/// no queue submission or GC MMIO client runs without a GFXOFF reference;
/// GFXOFF is not running (the controller starts after this returns).
pub(crate) async unsafe fn apply(
    mut parts: Parts<'_>,
    optin: OptIn,
    retained: &mut Option<Retained>,
) -> Result<Applied, Error> {
    if retained.is_some() || optin.is_empty() {
        return Err(Error::Busy);
    }
    let watermarks = if optin.watermarks {
        Some(upload_watermarks(&mut parts).await?)
    } else {
        None
    };
    // `DisplayAdmission::watermarks` means HUBBUB and PMFW sets; the PMFW
    // half is only certified once this path uploaded it.
    let admission = parts.admission.map(|a| DisplayAdmission {
        watermarks: a.watermarks && watermarks.is_some(),
        ..a
    });
    let plan = plan(optin, admission.as_ref(), &readiness());
    let mut applied = Applied {
        plan,
        watermarks: watermarks.is_some(),
        smu_bits: 0,
        blocks: Blocks::NONE,
        uclk_floor_mhz: None,
        fclk_floor_mhz: None,
    };
    // Retain everything that touched hardware before any later step fails.
    *retained = Some(Retained {
        gating: None,
        _watermarks: watermarks,
        applied,
        removed: false,
    });
    let r = retained.as_mut().ok_or(Error::Busy)?;
    let blocks = plan.blocks();
    if !blocks.is_empty() {
        // SAFETY: the completed boot's exclusive owner; this module is the
        // only writer of these registers.
        let gating = unsafe { Gating::new(parts.gpu, parts.authority) }.map_err(Error::Gating)?;
        let gating = r.gating.insert(gating);
        // SAFETY: GFXOFF is not running (caller contract), RLC runs after a
        // completed boot, and the plan admitted exactly these blocks.
        unsafe { gating.set_clockgating(true, blocks) }
            .await
            .map_err(Error::Gating)?;
        applied.blocks = blocks;
        r.applied = applied;
    }
    let bits = plan.smu_enable();
    if bits != 0 {
        // SAFETY: the policy admitted every feature these bits belong to.
        if let Err(e) = unsafe { parts.smu.update_gating_features(bits, true) }.await {
            // EnableSmuFeaturesLow may have succeeded before High failed:
            // retain the bits the SMU owner reports as possibly running so
            // `remove` disables them.
            applied.smu_bits = parts.smu.gating_features() & bits;
            r.applied = applied;
            return Err(Error::Smu(e));
        }
        applied.smu_bits = bits;
        r.applied = applied;
        if bits & policy::SMU_GFXOFF != 0 {
            // Linux's initial state: requests = 1, GFX powered.
            parts.smu.gfx_off_control(false).await.map_err(Error::Smu)?;
        }
    }
    let admitted = admission.unwrap_or_default();
    for (feature, clock, mhz) in [
        (
            Feature::MemoryDpm,
            crate::amdgpu_dcn30_clk::Clock::Memory,
            admitted.min_uclk_mhz,
        ),
        (
            Feature::FabricDpm,
            crate::amdgpu_dcn30_clk::Clock::Fabric,
            admitted.min_fclk_mhz,
        ),
    ] {
        if plan.policy.gate(feature) != policy::Gate::Allowed {
            continue;
        }
        if parts.smu.state() != smu::State::DisplayPowerReady || mhz == 0 {
            return Err(Error::NoDisplay);
        }
        let clocks = parts
            .pipeline
            .as_deref_mut()
            .ok_or(Error::NoDisplay)?
            .clock_manager();
        clocks
            .hard_min(clock, u32::from(mhz) * 1000)
            .await
            .map_err(Error::Clocks)?;
        if feature == Feature::MemoryDpm {
            applied.uclk_floor_mhz = Some(mhz);
        } else {
            applied.fclk_floor_mhz = Some(mhz);
        }
        r.applied = applied;
    }
    Ok(applied)
}

/// Undo [`apply`] in reverse: floors back to the top levels, PMFW bits off,
/// clock gating ungated. The PMFW watermark table stays (Linux never
/// withdraws it). The platform stops GFXOFF before calling this.
///
/// # Safety
/// As [`apply`]; the GFXOFF controller is stopped (GC powered).
pub(crate) async unsafe fn remove(
    mut parts: Parts<'_>,
    retained: &mut Option<Retained>,
) -> Result<(), Error> {
    let r = retained.as_mut().ok_or(Error::Busy)?;
    if r.removed {
        return Err(Error::Busy);
    }
    r.removed = true;
    let applied = r.applied;
    for (floor, clock) in [
        (
            applied.fclk_floor_mhz,
            crate::amdgpu_dcn30_clk::Clock::Fabric,
        ),
        (
            applied.uclk_floor_mhz,
            crate::amdgpu_dcn30_clk::Clock::Memory,
        ),
    ] {
        if floor.is_none() {
            continue;
        }
        let clocks = parts
            .pipeline
            .as_deref_mut()
            .ok_or(Error::NoDisplay)?
            .clock_manager();
        let top = clocks
            .levels()
            .ok_or(Error::NoDisplay)?
            .range(clock)
            .max_khz();
        clocks.hard_min(clock, top).await.map_err(Error::Clocks)?;
    }
    if applied.smu_bits != 0 {
        // SAFETY: switching off bits this path enabled.
        unsafe { parts.smu.update_gating_features(applied.smu_bits, false) }
            .await
            .map_err(Error::Smu)?;
    }
    if let Some(gating) = r.gating.as_mut() {
        // SAFETY: GFXOFF stopped (caller contract); same blocks as gated.
        unsafe { gating.set_clockgating(false, applied.blocks) }
            .await
            .map_err(Error::Gating)?;
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn kms_admission() -> DisplayAdmission {
        DisplayAdmission {
            active_streams: 1,
            dram_clock_change: true,
            fclk_change: false,
            stutter: false,
            watermarks: false,
            min_uclk_mhz: 1000,
            min_fclk_mhz: 1940,
            min_dcefclk_mhz: 1200,
            deep_sleep_dcefclk: false,
        }
    }
    /// A default boot (no `amdgpu.navi22_pg`) plans nothing: no clock-gating
    /// block, no PMFW bit, no floor, no GFXOFF.
    fn navi22_power_saving_default_boot_plans_nothing() -> TestResult {
        let ready = DriverReadiness {
            gfxoff_safe_gc_access: true,
            rlc_safe_mode: true,
            recovery_validated: true,
        };
        for admission in [None, Some(kms_admission())] {
            let p = plan(OptIn::parse(None), admission.as_ref(), &ready);
            if !p.is_empty()
                || !p.blocks().is_empty()
                || p.smu_enable() != 0
                || p.policy.gfxoff()
                || p.refusals != FEATURES.map(|f| Some(Refusal::NotOptedIn(f)))
            {
                return TestResult::Fail("default boot planned a power-saving feature");
            }
        }
        // The driver's own readiness never claims validated recovery, and
        // GC access stays unguarded until the CS owner declares it.
        let r = readiness();
        if r.recovery_validated || !r.rlc_safe_mode {
            return TestResult::Fail("readiness");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi22-power",
        navi22_power_saving_default_boot_plans_nothing
    );

    fn navi22_power_saving_plan_enforces_admission() -> TestResult {
        let all = OptIn::parse(Some("gfxoff,cg,gfxcg,hubpg,memdpm,fclkdpm,ds,wm"));
        let unguarded = DriverReadiness {
            gfxoff_safe_gc_access: false,
            rlc_safe_mode: true,
            recovery_validated: false,
        };
        // Today's kms admission (no watermarks/stutter/FCLK) with the CS path
        // unguarded: only GC clock gating passes; memory DPM still needs the
        // watermarks even though DML supports the DRAM clock change.
        let p = plan(all, Some(&kms_admission()), &unguarded);
        if p.blocks() != Blocks::GFX
            || p.smu_enable() != 0
            || p.refusals[Feature::GfxOff as usize] != Some(Refusal::Driver(Feature::GfxOff))
            || p.refusals[Feature::MemoryDpm as usize] != Some(Refusal::Display(Feature::MemoryDpm))
            || p.refusals[Feature::ClockGating as usize]
                != Some(Refusal::Display(Feature::ClockGating))
        {
            return TestResult::Fail("kms admission plan");
        }
        // With watermarks and a guarded CS path: SoC CG, GFXOFF, memory DPM.
        let wm = DisplayAdmission {
            watermarks: true,
            ..kms_admission()
        };
        let guarded = DriverReadiness {
            gfxoff_safe_gc_access: true,
            ..unguarded
        };
        let p = plan(all, Some(&wm), &guarded);
        if p.blocks() != Blocks::GFX.union(Blocks::SOC)
            || p.smu_enable() != policy::SMU_GFXOFF
            || p.policy.gate(Feature::MemoryDpm) != policy::Gate::Allowed
            || p.policy.gate(Feature::FabricDpm) == policy::Gate::Allowed
            || p.policy.gate(Feature::DeepSleep) == policy::Gate::Allowed
        {
            return TestResult::Fail("watermarked plan");
        }
        // No display admission (GOP scanout, native display off): only the
        // GC-internal features.
        let p = plan(all, None, &guarded);
        if p.blocks() != Blocks::GFX || p.smu_enable() != policy::SMU_GFXOFF {
            return TestResult::Fail("GOP plan");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi22-power",
        navi22_power_saving_plan_enforces_admission
    );
}

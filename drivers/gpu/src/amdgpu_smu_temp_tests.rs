use super::*;
use crate::amdgpu_navi22_power::{Sample as Sample22, Snapshot as Snapshot22};
use crate::amdgpu_navi48_power::Snapshot as Snapshot48;
use crate::amdgpu_smu_navi22_telemetry::{Layout, Metrics as Metrics22, Telemetry as Telemetry22};
use crate::amdgpu_smu_navi48_telemetry::{Metrics as Metrics48, Telemetry as Telemetry48};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Fixture telemetry in the spec's own units: `Metrics.edge_milli`
/// is milli-degrees Celsius (`METRICS_TEMPERATURE_EDGE`, as the
/// telemetry modules document), so the literal is the reading —
/// the provider must pass it through unchanged, never rescale it.
/// Edge and hotspot deliberately differ so the test proves the
/// provider reads the package (edge) sensor, not the junction one.
fn telemetry22(edge_mc: i32, hotspot_mc: i32) -> Telemetry22 {
    Telemetry22 {
        layout: Layout::V2,
        metrics: Metrics22 {
            edge_milli: edge_mc,
            hotspot_milli: hotspot_mc,
            mem_milli: 60_000,
            ..Metrics22::default()
        },
        enabled: 0,
        ppt_limit_w: 186,
        vddgfx_mv: 1150,
        fan_pwm: Some(96),
    }
}

fn telemetry48(edge_mc: i32, hotspot_mc: i32) -> Telemetry48 {
    Telemetry48 {
        metrics: Metrics48 {
            edge_milli: edge_mc,
            hotspot_milli: hotspot_mc,
            mem_milli: 64_000,
            ..Metrics48::default()
        },
        enabled: 0,
        ppt_limit_w: 304,
    }
}

fn snapshot22(telemetry: Option<Telemetry22>) -> Snapshot22 {
    Snapshot22 {
        telemetry,
        limits: None,
        protected: true,
        ppt_default_w: None,
        error: None,
        samples: 1,
    }
}

fn snapshot48(telemetry: Option<Telemetry48>) -> Snapshot48 {
    Snapshot48 {
        telemetry,
        limits: None,
        protected: true,
        gfx_level: crate::amdgpu_smu_navi48::GfxLevel::Auto,
        profile: crate::amdgpu_smu_navi48::PowerProfile::BootupDefault,
        coefficients: None,
        error: None,
        samples: 1,
    }
}

/// Selection over the last published samples: edge, never hotspot;
/// a snapshot without telemetry never shadows a live reading from
/// the other generation; no sample anywhere stays unknown.
fn smu_temp_provider_reads_last_edge_sample() -> TestResult {
    if gpu_temp_mc_from(None, None).is_some() {
        return TestResult::Fail("no published sample must stay unknown");
    }
    if gpu_temp_mc_from(Some(snapshot22(None)), None).is_some() {
        return TestResult::Fail("snapshot without telemetry must stay unknown");
    }
    if gpu_temp_mc_from(Some(snapshot22(Some(telemetry22(52_000, 70_000)))), None) != Some(52_000) {
        return TestResult::Fail("Navi22 edge must pass through unchanged, not hotspot");
    }
    if gpu_temp_mc_from(None, Some(snapshot48(Some(telemetry48(61_000, 75_000))))) != Some(61_000) {
        return TestResult::Fail("Navi48 edge must pass through unchanged, not hotspot");
    }
    if gpu_temp_mc_from(
        Some(snapshot22(Some(telemetry22(52_000, 70_000)))),
        Some(snapshot48(Some(telemetry48(61_000, 75_000)))),
    ) != Some(52_000)
    {
        return TestResult::Fail("first live owner wins when both publish");
    }
    if gpu_temp_mc_from(
        Some(snapshot22(None)),
        Some(snapshot48(Some(telemetry48(61_000, 75_000)))),
    ) != Some(61_000)
    {
        return TestResult::Fail("empty Navi22 snapshot must not shadow live Navi48");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-temp",
    smu_temp_provider_reads_last_edge_sample
);

/// Restore a `None`-returning GPU provider after the end-to-end
/// test, mirroring the hwmon CPU-provider tests: the fused
/// snapshot must not keep a test's provider afterwards.
fn restore_none_gpu_provider() {
    use alloc::sync::Arc;
    let cap = narf_power::bootstrap_power_authority();
    let providers = narf_power::service::StateProviders {
        ac_adapter: None,
        lid: None,
        battery: None,
        cpu_temp_mc: None,
        gpu_temp_mc: Some(Arc::new(|| None)),
    };
    let _ = narf_power::service::register_state_providers(&cap, providers);
}

/// End to end: a synthetic Navi22 refresh published through the
/// owner's live handle reaches the power service's fused snapshot
/// as `gpu_temp_mc` once the provider is registered.
fn smu_temp_provider_fuses_into_power_snapshot() -> TestResult {
    crate::amdgpu_navi22_power::publish_sample(Sample22 {
        telemetry: Ok(telemetry22(52_000, 70_000)),
        limits: None,
        protected: true,
    });
    if gpu_temp_mc() != Some(52_000) {
        return TestResult::Fail("provider must read the published Navi22 edge sample");
    }
    register_gpu_temp_provider();
    let got = narf_power::service::snapshot().gpu_temp_mc;
    restore_none_gpu_provider();
    if got != Some(52_000) {
        return TestResult::Fail("snapshot gpu_temp_mc must carry the published edge reading");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-temp",
    smu_temp_provider_fuses_into_power_snapshot
);

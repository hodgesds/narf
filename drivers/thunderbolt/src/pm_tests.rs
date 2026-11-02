//! Device-PM fixtures for the native CM (#1028).
//!
//! The handler production registers (via `super::register`, exactly
//! as `runtime::start` calls it) is driven through the real
//! `narf_power::device_pm` fan-out — the same `suspend_all_devices`
//! / `resume_all_devices` pair both system-sleep paths gate on (S3
//! in `power::suspend`, s2idle in `power::s2idle`) — against CM
//! states established through the production publication paths:
//! tunnels activated by `reconcile` against the config-device
//! model, drained by teardown, and the orphan mark recorded the way
//! `topology::run`'s exit path records it after a poisoned
//! teardown. Nothing here pokes the handler's inputs through a
//! back door: if the published tunnel state or the orphan registry
//! is wrong, the fan-out verdict is wrong and this fixture fails.
use super::*;
use crate::topology::Domain;
use crate::tunnel;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_power::device_pm::{DeviceSuspendError, FanoutReport};

fn cm_outcome(report: &FanoutReport) -> Option<Result<(), DeviceSuspendError>> {
    report
        .outcomes
        .iter()
        .find(|o| o.name == "usb4-native-cm")
        .map(|o| o.result)
}

fn usb4_cm_pm_state_checked_fanout() -> TestResult {
    use narf_power::device_pm::{resume_all_devices, suspend_all_devices};

    // Establish a known-empty world: these registries are global
    // and shared with other fixtures in the boot. For the duration
    // of this fixture the device-PM registry holds only the CM.
    let _pm_registry = narf_power::device_pm::__test_isolate_registry();
    tunnel::__reset_orphaned_for_test();
    tunnel::__reset_pm_for_test();
    tunnel::forget_domain(u32::MAX);

    // Production registration, as `runtime::start` performs it.
    register();

    // Phase 1 — CM registered, no tunnels: the fan-out proceeds and
    // the paired resume is clean. This is the state the old blanket
    // veto made indistinguishable from a busy CM.
    let report = suspend_all_devices();
    if !report.ok() || cm_outcome(&report) != Some(Ok(())) {
        return TestResult::Fail("registered CM with no tunnels vetoed suspend");
    }
    if !resume_all_devices().ok() {
        return TestResult::Fail("resume fan-out failed with no tunnels");
    }

    // Phase 2 — live tunnels, activated and published through the
    // production reconcile path (USB3 + DisplayPort): the first
    // fan-out latches a quiesce request and is refused, attributed
    // to the CM as Busy (#1035). The CM service pass — driven here
    // exactly as `topology::run` drives it — drains the paths
    // through the journaled teardown and records them for replay;
    // the retried fan-out then proceeds, and resume replays the
    // paths back to live.
    let (domain, mut model) = tunnel::tests::model();
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(tunnel::reconcile(&mut model, &domain, &mut tunnels, 3))
        .is_err()
        || tunnels.len() != 2
    {
        return TestResult::Fail("model did not activate USB3 + DP tunnels");
    }
    if tunnel::live_tunnel_count() != 2 || !tunnel::orphaned_path_domains().is_empty() {
        return TestResult::Fail("live tunnels not published");
    }
    let report = suspend_all_devices();
    if report.ok() || cm_outcome(&report) != Some(Err(DeviceSuspendError::Busy)) {
        return TestResult::Fail("live tunnels did not latch a quiesce as Busy");
    }
    if tunnel::live_tunnel_count() != 2 || !tunnel::suspended_tunnels().is_empty() {
        return TestResult::Fail("quiesce ran before the CM service pass");
    }
    if narf_scheduler::block_on_spin(tunnel::service_pm_suspend(
        &mut model,
        &domain,
        &mut tunnels,
    ))
    .is_err()
        || !tunnels.is_empty()
        || tunnel::live_tunnel_count() != 0
        || tunnel::suspended_tunnels().len() != 2
    {
        return TestResult::Fail("CM quiesce did not drain and record live tunnels");
    }
    let report = suspend_all_devices();
    if !report.ok() || cm_outcome(&report) != Some(Ok(())) {
        return TestResult::Fail("quiesced CM still vetoed suspend");
    }
    if !resume_all_devices().ok() {
        return TestResult::Fail("resume fan-out failed with quiesced tunnels");
    }
    if narf_scheduler::block_on_spin(tunnel::service_pm_resume(&mut model, &domain, &mut tunnels))
        .is_err()
        || tunnels.len() != 2
        || tunnel::live_tunnel_count() != 2
        || !tunnel::suspended_tunnels().is_empty()
    {
        return TestResult::Fail("resume did not replay quiesced tunnels");
    }
    if !resume_all_devices().ok() {
        return TestResult::Fail("resume fan-out failed after replay");
    }

    // Phase 3 — tunnels torn down (an unmanaged reconcile pass
    // against an empty topology drains them, as detach does):
    // suspend proceeds again. The registration outliving the
    // tunnels must not, by itself, veto anything.
    let empty = Domain {
        id: u32::MAX,
        routers: Vec::new(),
    };
    if narf_scheduler::block_on_spin(tunnel::reconcile(&mut model, &empty, &mut tunnels, 0))
        .is_err()
        || !tunnels.is_empty()
        || tunnel::live_tunnel_count() != 0
    {
        return TestResult::Fail("teardown did not drain live tunnels");
    }
    if !suspend_all_devices().ok() {
        return TestResult::Fail("suspend still vetoed after teardown");
    }

    // Phase 4 — the CM exits with path writes unrolled-back: the
    // transport dies during teardown (the adapter-disable write
    // fails), the journal is retained, and the exit path records
    // the orphan mark. The published snapshots are drained, yet the
    // scoped veto persists for that domain — the one fault state
    // where refusing sleep remains honest.
    let (domain, mut model) = tunnel::tests::model();
    let mut tunnels = Vec::new();
    if narf_scheduler::block_on_spin(tunnel::reconcile(&mut model, &domain, &mut tunnels, 2))
        .is_err()
        || tunnels.len() != 1
    {
        return TestResult::Fail("model did not activate a DP tunnel");
    }
    // The display drops (HPD clears), so the next pass tears the
    // tunnel down — and the teardown write fails mid-rollback.
    model.put(1, 5, crate::cm::CfgSpace::Port, 34, 0);
    model.set_fail_disable();
    if narf_scheduler::block_on_spin(tunnel::reconcile(&mut model, &domain, &mut tunnels, 0))
        .is_ok()
        || tunnels.len() != 1
        || !tunnels[0].has_unrolled_writes()
    {
        return TestResult::Fail("poisoned teardown did not retain unrolled-back writes");
    }
    tunnel::note_orphaned_paths(domain.id, tunnels.iter().any(|t| t.has_unrolled_writes()));
    tunnel::forget_domain(domain.id);
    if tunnel::live_tunnel_count() != 0 || tunnel::orphaned_path_domains() != [u32::MAX] {
        return TestResult::Fail("orphan state not recorded as expected");
    }
    let report = suspend_all_devices();
    if report.ok() || cm_outcome(&report) != Some(Err(DeviceSuspendError::Busy)) {
        return TestResult::Fail("orphaned paths did not veto suspend");
    }
    if !resume_all_devices().ok() {
        return TestResult::Fail("resume rollback failed with orphaned paths");
    }

    // Hygiene: leave every registry as the fixture found it.
    tunnel::forget_domain(u32::MAX);
    tunnel::__reset_orphaned_for_test();
    tunnel::__reset_pm_for_test();
    narf_power::device_pm::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/pm", usb4_cm_pm_state_checked_fanout);

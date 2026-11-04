// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained native power transitions and fresh post-wake RSNA/DHCP.
use super::super::super::super::super::super::interface::supervisor::Operation;
use super::*;

fn idle_receipt(h: &Harness) {
    h.packet.radio.hardware_byte(0x286, 2);
    for reg in 0x5f8..=0x5fb {
        h.packet.radio.hardware_byte(reg, 0);
    }
}
fn fresh_peer(h: &Harness) {
    let mut peer = h.peer.lock();
    let fresh = Peer::new(peer.ap.protected());
    peer.ap = fresh.ap;
    peer.ptk = fresh.ptk;
    peer.replay = fresh.replay;
    peer.pn = fresh.pn;
}
fn smoke_rtl8188ee_system_suspend_retained_waiter_and_fresh_wpa2_dhcp() -> TestResult {
    let h = Harness::new(true);
    h.join();
    idle_receipt(&h);
    let generation = h.device.generation_for_test();
    let mut waiter = Box::pin(h.device.schedule(Operation::Suspend).unwrap());
    h.packet.model.lock().wait = true;
    if waiter
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
    {
        return TestResult::Fail("EE suspend did not wait for actual power transition");
    }
    drop(waiter);
    h.packet.model.lock().wait = false;
    if complete(h.device.schedule(Operation::Suspend).unwrap()).is_err()
        || h.device.generation_for_test() != generation + 1
        || h.device.power_flags_for_test() != (true, false, true)
        || h.packet.model.lock().master
        || !h.closed()
        || h.device
            .prepared
            .try_lock()
            .is_none_or(|owner| owner.is_some())
        || h.packet.radio.hardware_read8(3) & 4 != 0
        || h.packet.radio.hardware_read8(0x80) != 0
        || complete(h.device.associate(h.request())).is_ok()
    {
        return TestResult::Fail("EE suspend completion lacked actual stopped/disabled owner");
    }
    if complete(h.device.schedule(Operation::Resume).unwrap()).is_err()
        || h.device.power_flags_for_test() != (false, false, false)
        || !h.passive()
    {
        return TestResult::Fail("EE system resume did not install fresh passive owner");
    }
    fresh_peer(&h);
    h.join();
    let plan = h.peer.lock().plan;
    match narf_net::dhcp::dhcp_acquire(h.device.name(), 0) {
        Ok(lease) if plan.matches_lease(&lease) => TestResult::Pass,
        _ => TestResult::Fail("EE post-suspend fresh WPA2/DHCP failed"),
    }
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/power",
    smoke_rtl8188ee_system_suspend_retained_waiter_and_fresh_wpa2_dhcp
);

fn smoke_rtl8188ee_ips_only_passive_scan_wake_and_system_handoff() -> TestResult {
    let h = Harness::new(false);
    h.join();
    idle_receipt(&h);
    if complete(h.device.schedule(Operation::Idle).unwrap()).is_err() || !h.device.link_up() {
        return TestResult::Fail("EE IPS stopped an associated station");
    }
    complete(h.device.disassociate()).unwrap();
    if complete(h.device.schedule(Operation::Idle).unwrap()).is_err()
        || h.device.power_flags_for_test() != (false, true, true)
        || h.packet.model.lock().master
    {
        return TestResult::Fail("EE passive IPS did not actually disable the native card");
    }
    // A valid scan must wake via a fresh owner; no old cache is restored.
    h.scan();
    if !h.passive() || h.device.power_flags_for_test() != (false, false, false) {
        return TestResult::Fail("EE passive scan did not wake from IPS");
    }
    idle_receipt(&h);
    complete(h.device.schedule(Operation::Idle).unwrap()).unwrap();
    if complete(h.device.schedule(Operation::Suspend).unwrap()).is_err()
        || h.device.power_flags_for_test() != (true, true, true)
    {
        return TestResult::Fail("EE IPS to system-suspend handoff lost disabled-state proof");
    }
    if complete(h.device.schedule(Operation::Resume).unwrap()).is_err() || !h.passive() {
        return TestResult::Fail("EE system resume from IPS failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/power",
    smoke_rtl8188ee_ips_only_passive_scan_wake_and_system_handoff
);

fn smoke_rtl8188ee_system_suspend_missing_idle_cannot_ack_or_free() -> TestResult {
    let h = Harness::new(false);
    h.join();
    let drops = h.packet.drops.load(Ordering::Acquire);
    h.packet.radio.hardware_byte(0x286, 0);
    if complete(h.device.schedule(Operation::Suspend).unwrap()).is_ok()
        || complete(h.device.schedule(Operation::Suspend).unwrap()).is_ok()
        || h.packet.drops.load(Ordering::Acquire) != drops
        || h.device.power_flags_for_test().2
        || !h.closed()
    {
        return TestResult::Fail("EE missing DMA idle became suspend ACK or reclamation");
    }
    idle_receipt(&h);
    if complete(h.device.schedule(Operation::Resume).unwrap()).is_err() || !h.passive() {
        return TestResult::Fail("EE resume did not retry actual missing idle receipt");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/power",
    smoke_rtl8188ee_system_suspend_missing_idle_cannot_ack_or_free
);

fn smoke_rtl8188ee_cancelled_pm_prepare_finishes_then_resumes() -> TestResult {
    let h = Harness::new(true);
    h.join();
    idle_receipt(&h);
    let generation = h.device.generation_for_test();
    h.packet.model.lock().wait = true;
    let mut prepare = Box::pin(h.device.prepare_sleep());
    if prepare
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
    {
        return TestResult::Fail("EE PM prepare missed held native power operation");
    }
    if complete(h.device.prepare_sleep()).is_ok() {
        return TestResult::Fail("EE concurrent PM prepare replaced pending owner");
    }
    drop(prepare);
    h.packet.model.lock().wait = false;
    for _ in 0..20000 {
        h.device
            .poll_transition(&mut Context::from_waker(Waker::noop()));
        h.device.service_sleep_rollback();
        if h.device.generation_for_test() >= generation + 2 && h.passive() {
            break;
        }
    }
    if !h.passive()
        || h.device.power_flags_for_test() != (false, false, false)
        || h.device.generation_for_test() != generation + 2
    {
        return TestResult::Fail(
            "EE cancelled PM request stranded disabled card or reopened old owner",
        );
    }
    fresh_peer(&h);
    h.join();
    let plan = h.peer.lock().plan;
    match narf_net::dhcp::dhcp_acquire(h.device.name(), 0) {
        Ok(lease) if plan.matches_lease(&lease) => TestResult::Pass,
        _ => TestResult::Fail("EE cancelled PM cleanup failed fresh WPA2/DHCP"),
    }
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/power",
    smoke_rtl8188ee_cancelled_pm_prepare_finishes_then_resumes
);

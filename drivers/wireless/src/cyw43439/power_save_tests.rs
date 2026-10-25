// SPDX-License-Identifier: GPL-2.0-or-later
//! Native SDPCM/BCDC power policy, receipts, cancellation and port ownership.
use super::*;

fn policy() -> Result<(), &'static str> {
    let harness = Harness::new(false)?;
    if harness.device.power_save_default() != Some(false) {
        return Err("FullMAC power-save capability/default missing");
    }
    for enabled in [true, false] {
        harness
            .device
            .set_power_save(enabled)
            .map_err(|_| "PS request")?;
    }
    ready(harness.device.apply_power_save())?;
    if harness.bus.firmware.lock().power_commands() != [(86, vec![0; 4])] {
        return Err("coalesced awake policy unnecessarily touched firmware");
    }
    for enabled in [true, true, false] {
        harness
            .device
            .set_power_save(enabled)
            .map_err(|_| "PS request")?;
        ready(harness.device.apply_power_save())?;
        if harness
            .device
            .state
            .try_lock()
            .unwrap()
            .station
            .power_save()
            != enabled
            || harness.device.link_up()
            || harness.device.connected_bssid().is_some()
        {
            return Err("power policy was not applied or authorized an unassociated port");
        }
    }
    // Literal Linux BRCMF_C_SET_PM, PM_FAST/PM_OFF and default sleep-retention
    // bytes are checked independently of the driver's encoder constants.
    let mut timeout = b"pm2_sleep_ret\0".to_vec();
    timeout.extend_from_slice(&[0xd0, 0x07, 0, 0]);
    if harness.bus.firmware.lock().power_commands()
        != [
            (86, vec![0; 4]),
            (86, vec![2, 0, 0, 0]),
            (263, timeout.clone()),
            (86, vec![0; 4]),
            (263, timeout),
        ]
    {
        return Err("native SDPCM power commands differ from Linux wire contract");
    }
    Ok(())
}
fn smoke_cyw_power_save_native_policy_wire_coalescing_and_closed_port() -> TestResult {
    policy().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/power",
    smoke_cyw_power_save_native_policy_wire_coalescing_and_closed_port
);

fn rejected() -> Result<(), &'static str> {
    for command in [86, 263] {
        let harness = Harness::new(true)?;
        harness.scan_and_associate(true)?;
        let plan = network_plan();
        let bytes = udp_ipv4(
            AP,
            OWN,
            plan.lease_ip,
            plan.server_ip,
            49152,
            7,
            b"held-before-PS",
        );
        harness
            .device
            .enqueue(&bytes)
            .map_err(|_| "pre-failure TX queue")?;
        harness.bus.firmware.lock().reject_power_save(command);
        harness
            .device
            .set_power_save(true)
            .map_err(|_| "PS request")?;
        ready(harness.device.apply_power_save())?;
        if harness.device.link_up()
            || harness.device.connected_bssid().is_some()
            || harness.device.enqueue(&bytes).is_ok()
            || harness.device.set_power_save(false) != Err(19)
            || !harness.bus.ap.lock().uplink.is_empty()
        {
            return Err("rejected/partially applied power transition retained admission");
        }
        let mut state = harness.device.state.try_lock().unwrap();
        if state.pending.is_some()
            || !matches!(state.tx.try_recv(), Ok(None))
            || state.station.power_save()
            || state.station.poll() != Err(Error::Failed)
        {
            return Err("failed power transition retained TX, applied state or reusable runtime");
        }
    }
    Ok(())
}
fn smoke_cyw_power_save_firmware_rejection_closes_port_and_queued_tx() -> TestResult {
    rejected().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/power",
    smoke_cyw_power_save_firmware_rejection_closes_port_and_queued_tx
);

fn cancelled_at(command: u32) -> Result<(), &'static str> {
    let harness = Harness::new(true)?;
    harness.scan_and_associate(true)?;
    harness.bus.firmware.lock().hold_power_save(command);
    harness
        .device
        .set_power_save(true)
        .map_err(|_| "PS request")?;
    {
        let mut transition = pin!(harness.device.apply_power_save());
        if transition
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return Err("power transition finished without its native control receipt");
        }
        if harness.device.state.try_lock().is_some() {
            return Err("pending power IOCTL lost exclusive station ownership");
        }
    }
    harness.bus.firmware.lock().hold_power_save(0);
    // A stale success is now queued. A dropped IOCTL is still terminal.
    harness.device.drain();
    if harness.device.link_up()
        || harness.device.connected_bssid().is_some()
        || harness.device.set_power_save(false) != Err(19)
        || harness
            .device
            .state
            .try_lock()
            .unwrap()
            .station
            .power_save()
    {
        return Err("cancelled power IOCTL reused late success or retained carrier");
    }
    Ok(())
}
fn smoke_cyw_power_save_cancelled_receipt_cannot_reauthorize() -> TestResult {
    for command in [86, 263] {
        if let Err(error) = cancelled_at(command) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/power",
    smoke_cyw_power_save_cancelled_receipt_cannot_reauthorize
);

fn superseded() -> Result<(), &'static str> {
    let harness = Harness::new(false)?;
    harness.bus.firmware.lock().hold_power_save(86);
    harness
        .device
        .set_power_save(true)
        .map_err(|_| "PS request")?;
    {
        let mut transition = pin!(harness.device.apply_power_save());
        if transition
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return Err("held power receipt completed");
        }
        harness
            .device
            .set_power_save(false)
            .map_err(|_| "superseding awake request")?;
        harness.bus.firmware.lock().hold_power_save(0);
        narf_scheduler::block_on(transition);
    }
    if !harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .power_save()
    {
        return Err("held PM_FAST receipt did not commit its own applied state");
    }
    ready(harness.device.apply_power_save())?;
    if harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .power_save()
        || harness.device.power_save.load(Ordering::Acquire) != 0
    {
        return Err("in-flight power completion overwrote the newer desired policy");
    }
    Ok(())
}
fn smoke_cyw_power_save_inflight_completion_preserves_newer_request() -> TestResult {
    superseded()
        .and_then(|()| disconnect_during_power_save())
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/power",
    smoke_cyw_power_save_inflight_completion_preserves_newer_request
);

fn disconnect_during_power_save() -> Result<(), &'static str> {
    let harness = Harness::new(true)?;
    harness.scan_and_associate(true)?;
    harness.bus.firmware.lock().hold_power_save(86);
    harness
        .device
        .set_power_save(true)
        .map_err(|_| "PS request")?;
    let mut transition = pin!(harness.device.apply_power_save());
    if transition
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
    {
        return Err("PS receipt was not held before disconnect");
    }
    let mut disconnect = pin!(harness.device.disassociate());
    if disconnect
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
        || harness.device.link_up()
    {
        return Err("disconnect failed to close admission before waiting on PS");
    }
    harness.bus.firmware.lock().hold_power_save(0);
    narf_scheduler::block_on(transition);
    if harness.device.link_up() || harness.device.connected_bssid().is_some() {
        return Err("older power receipt reopened a concurrently disconnecting port");
    }
    ready(disconnect)?.map_err(|_| "disconnect after held power receipt")?;
    Ok(())
}

fn peer_loss() -> Result<(), &'static str> {
    let harness = Harness::new(true)?;
    harness.scan_and_associate(true)?;
    harness
        .device
        .set_power_save(true)
        .map_err(|_| "PS request")?;
    harness.bus.lose_link();
    {
        // Drive the actual retained worker, including its packet step and
        // power policy application; it then waits on its ordinary timer.
        let mut worker = pin!(harness.device.clone().receive_worker());
        if worker
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return Err("retained FullMAC worker terminated");
        }
    }
    if harness.device.link_up()
        || harness.device.connected_bssid().is_some()
        || !harness
            .device
            .state
            .try_lock()
            .unwrap()
            .station
            .power_save()
    {
        return Err("power worker reopened a peer lost before the native PS receipt");
    }
    Ok(())
}
fn smoke_cyw_power_save_worker_observes_peer_loss_before_publication() -> TestResult {
    peer_loss().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/power",
    smoke_cyw_power_save_worker_observes_peer_loss_before_publication
);

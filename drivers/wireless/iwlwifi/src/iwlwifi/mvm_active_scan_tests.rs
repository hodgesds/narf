//! Active probes over the public retained API77 Device and actual TFH/RFH
//! command transport. Firmware sees literal probe, SAR and device-power bytes.
use super::*;

fn request() -> ScanRequest {
    ScanRequest {
        ssids: vec![b"net".to_vec()],
        frequencies_mhz: vec![2412],
        channels: vec![1],
        active: true,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: vec![],
    }
}
fn smoke_mvm_active_scan_native_power_probe_and_terminal_receipt() -> TestResult {
    check(|| {
        let h = Harness::new(false)?;
        let before = h.actor.lock().commands.len();
        let result = run(h.device.scan(request()))?.map_err(|_| "qualified active scan failed")?;
        if result.len() != 1 || result[0].bssid != AP || result[0].ssid != b"net" {
            return Err("active scan lost original BSS");
        }
        let commands = h.actor.lock().commands[before..].to_vec();
        let power: Vec<_> = commands
            .iter()
            .filter(|(g, c, _)| *g == 1 && *c == 0x9f)
            .collect();
        if power.len() != 2
            || power[0].2[0] != 2
            || power[1].2[0] != 1
            || commands
                .iter()
                .any(|(g, c, _)| *g == 1 && matches!(*c, 8 | 0x18))
        {
            return Err("active scan used station link power or added a peer/PHY");
        }
        // Repeated scan reuses slot0 only after its terminal completion,
        // reprograms both power owners and then performs the regular join.
        run(h.device.scan(request()))?.map_err(|_| "second active scan failed")?;
        if h.device
            .state
            .try_lock()
            .unwrap()
            .owner
            .as_ref()
            .unwrap()
            .phase()
            != Phase::Configured
        {
            return Err("active scan did not return exact owner to Configured");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/active_scan",
    smoke_mvm_active_scan_native_power_probe_and_terminal_receipt
);

fn smoke_mvm_active_scan_missing_or_revoked_asset_and_no_ir_never_publish() -> TestResult {
    check(|| {
        for fault in 0..4 {
            let h = Harness::new(false)?;
            let before = h.actor.lock().commands.len();
            match fault {
                0 => h.available.store(false, Ordering::Release),
                1 => h.scan_power.revoke(),
                2 | 3 => {
                    let mut policy = domain();
                    policy.rules[0].flags = if fault == 2 {
                        RegFlags::NO_IR
                    } else {
                        RegFlags::DFS
                    };
                    h.db.install(policy);
                }
                _ => unreachable!(),
            }
            if run(h.device.scan(request()))?.is_ok() || h.actor.lock().commands.len() != before {
                return Err("active scan published without asset or probe permission");
            }
            if h.device
                .state
                .try_lock()
                .unwrap()
                .owner
                .as_ref()
                .unwrap()
                .phase()
                != Phase::Configured
            {
                return Err("active-scan preflight refusal consumed the native owner");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/active_scan",
    smoke_mvm_active_scan_missing_or_revoked_asset_and_no_ir_never_publish
);

fn smoke_mvm_active_scan_policy_or_qualification_loss_at_power_wait_stops_probes() -> TestResult {
    check(|| {
        for stage in [10, 11, 12] {
            for revoke in [false, true] {
                let h = Harness::new(false)?;
                h.actor.lock().hold_phy = Some(stage);
                let mut operation = Box::pin(h.device.scan(request()));
                let mut held = false;
                for _ in 0..64 {
                    if once(operation.as_mut()).is_ready() {
                        return Err("active scan skipped held native receipt");
                    }
                    h.actor.lock().serve()?;
                    if h.actor.lock().held.is_some() {
                        held = true;
                        break;
                    }
                }
                if !held {
                    return Err("active scan did not reach held receipt");
                }
                if stage != 12
                    && h.actor
                        .lock()
                        .commands
                        .iter()
                        .any(|(g, c, _)| *g == 1 && *c == 0xd)
                {
                    return Err("probes published before both native power receipts");
                }
                if revoke {
                    h.scan_power.revoke();
                } else {
                    let mut policy = domain();
                    policy.rules[0].max_power_dbm = 1;
                    h.db.install(policy);
                }
                h.actor.lock().release();
                if run(operation)?.is_ok() || !h.device.terminal.load(Ordering::Acquire) {
                    return Err("active scan remained usable after live authority tightened");
                }
                if stage != 12
                    && h.actor
                        .lock()
                        .commands
                        .iter()
                        .any(|(g, c, _)| *g == 1 && *c == 0xd)
                {
                    return Err("late power receipt authorized probes after revocation");
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/active_scan",
    smoke_mvm_active_scan_policy_or_qualification_loss_at_power_wait_stops_probes
);

fn smoke_mvm_active_scan_dropped_waiter_retains_worker_and_stops_on_revocation() -> TestResult {
    check(|| {
        for outer in [false, true] {
            let h = Harness::new(false)?;
            h.actor.lock().hold_phy = Some(12);
            let mut operation = Box::pin(h.device.scan(request()));
            let mut held = false;
            for _ in 0..64 {
                if once(operation.as_mut()).is_ready() {
                    return Err("dropped-waiter fixture skipped native scan receipt");
                }
                h.actor.lock().serve()?;
                if h.actor.lock().held.is_some() {
                    held = true;
                    break;
                }
            }
            if !held {
                return Err("dropped-waiter fixture never published scan");
            }
            drop(operation);
            if h.device.control.try_lock().unwrap().is_none() || h.device.state.try_lock().is_some()
            {
                return Err("dropping public waiter dropped native scan Work/state");
            }
            if outer {
                // The Device fence refuses before polling active_scan_using;
                // the Work's orphan-scan repair must perform the stop.
                h.db.clear();
            } else {
                h.scan_power.revoke();
            }
            h.actor.lock().release();
            h.pump()?;
            if !h.device.terminal.load(Ordering::Acquire)
                || h.device.link_up()
                || h.device.control.try_lock().unwrap().is_some()
                || h.retained().0 != 1
                || h.actor
                    .lock()
                    .commands
                    .iter()
                    .filter(|(g, c, _)| *g == 1 && *c == 0xd)
                    .count()
                    != 1
            {
                return Err("cancelled active scan lost terminal stop or uncertain command DMA");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/active_scan",
    smoke_mvm_active_scan_dropped_waiter_retains_worker_and_stops_on_revocation
);

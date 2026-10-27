//! Gen2 firmware/transport recovery. A terminal, failed native owner is
//! restarted through `Owner::recover` (DMA-stopped transport, fresh queue and
//! command owners, actual NVM/default replay) before the next scan, then a
//! completely new scan/join/DHCP conversation runs on the same publication.
use super::*;

/// Terminal failure with retained (uncertain) native queues: the AP sends
/// a deauthentication to the joined station, exactly as the liveness smoke.
fn fail_station(h: &Harness) -> Result<(), &'static str> {
    let mut frame = vec![0xc0, 0, 0, 0];
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0, 3, 0]);
    h.actor.lock().inject(0xc1, 0, 0x8000, &envelope(&frame));
    h.pump()?;
    if h.device.link_up() || !h.device.terminal.load(Ordering::Acquire) || h.retained().1 != 2 {
        return Err("fixture AP close did not leave a terminal owner with retained queues");
    }
    Ok(())
}

/// The independent AP forgets the old association (its own state; the
/// station side is reset only by the native restart under test).
fn restart_ap(h: &Harness) -> Result<(), &'static str> {
    let mut a = h.actor.lock();
    if !a.batch.is_empty() || a.held.is_some() {
        return Err("AP restart hid uncertain native packets/control");
    }
    a.security.ap = ap(false)?;
    a.m1_sent = false;
    a.data_added = false;
    a.closing = false;
    a.server = DhcpServer::new(NETWORK);
    Ok(())
}

fn phase(h: &Harness) -> Phase {
    h.device
        .state
        .try_lock()
        .unwrap()
        .owner
        .as_ref()
        .unwrap()
        .phase()
}

fn nvm_commands(h: &Harness) -> usize {
    h.actor
        .lock()
        .commands
        .iter()
        .filter(|(g, c, _)| *g == 12 && *c == 2)
        .count()
}

fn smoke_mvm_gen2_recovery_restarts_failed_owner_and_rejoins_with_dhcp() -> TestResult {
    check(|| {
        let h = Harness::new(false)?;
        h.join()?;
        fail_station(&h)?;
        // A terminal station refuses ordinary control until restarted.
        if run(h.device.associate(h.request()))?.is_ok() {
            return Err("terminal failed owner accepted association");
        }
        restart_ap(&h)?;
        let before = nvm_commands(&h);
        h.join()?;
        if nvm_commands(&h) != before + 1 {
            return Err("recovery did not replay actual unified NVM exactly once");
        }
        if h.device.terminal.load(Ordering::Acquire) || h.retained().1 != 2 {
            return Err("recovered owner did not rebuild exactly the new station queues");
        }
        let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
            .map_err(|_| "recovered native kernel DHCP")?;
        if !NETWORK.matches_lease(&lease) {
            return Err("recovered native DHCP leased wrong address");
        }
        h.actor.lock().closing = true;
        run(h.device.disassociate())?.map_err(|_| "recovered station ordered close")?;
        if h.retained() != (0, 0, 0) || phase(&h) != Phase::Configured {
            return Err("recovered station close left native receipts");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/recovery",
    smoke_mvm_gen2_recovery_restarts_failed_owner_and_rejoins_with_dhcp
);

fn smoke_mvm_gen2_recovery_changed_nvm_stays_failed_then_retries() -> TestResult {
    check(|| {
        let h = Harness::new(false)?;
        h.join()?;
        fail_station(&h)?;
        restart_ap(&h)?;
        // The restarted device reports a different PHY profile: the owner
        // must not adopt it and the publication stays terminal.
        h.actor.lock().ht = true;
        if h.scan().is_ok() {
            return Err("recovery accepted a changed NVM identity");
        }
        if !h.device.terminal.load(Ordering::Acquire) || phase(&h) != Phase::Failed {
            return Err("failed recovery reopened control");
        }
        if run(h.device.associate(h.request()))?.is_ok() {
            return Err("failed recovery admitted association");
        }
        // A later restart reporting the original identity succeeds.
        h.actor.lock().ht = false;
        h.scan()?;
        if h.device.terminal.load(Ordering::Acquire) || phase(&h) != Phase::Configured {
            return Err("retried recovery did not reopen the configured owner");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/recovery",
    smoke_mvm_gen2_recovery_changed_nvm_stays_failed_then_retries
);

fn smoke_mvm_gen2_recovery_waiter_drop_keeps_retained_restart() -> TestResult {
    check(|| {
        let h = Harness::new(false)?;
        // A live (non-failed) station is never restarted.
        if h.device.begin(Operation::Recover).is_ok() {
            return Err("recovery started without a terminal failed owner");
        }
        h.join()?;
        fail_station(&h)?;
        restart_ap(&h)?;
        {
            let mut scan = Box::pin(h.device.scan(ScanRequest {
                ssids: vec![],
                frequencies_mhz: vec![2412],
                channels: vec![1],
                active: false,
                random_mac: None,
                colocated_6ghz: false,
                duration_tu: None,
                duration_mandatory: false,
                extra_ies: vec![],
            }));
            let _ = once(scan.as_mut());
        }
        // The dropped waiter left the retained restart in the control slot;
        // the synchronous drain cannot start a competing operation.
        if h.device.begin(Operation::Recover).is_ok() {
            return Err("second recovery raced the retained restart");
        }
        for _ in 0..256 {
            h.actor.lock().serve()?;
            let _ = progress::poll_work(&h.device.control, &mut Context::from_waker(Waker::noop()));
            if !h.device.terminal.load(Ordering::Acquire) {
                break;
            }
        }
        if h.device.terminal.load(Ordering::Acquire) || phase(&h) != Phase::Configured {
            return Err("dropped waiter cancelled the retained restart");
        }
        h.join()?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/recovery",
    smoke_mvm_gen2_recovery_waiter_drop_keeps_retained_restart
);

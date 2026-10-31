use super::*;

fn smoke_mvm_shared_memory_native_query_retains_owner_and_reports_opaque_fifos() -> TestResult {
    check(|| {
        let h = Harness::new(false)?;
        let before = h.actor.lock().commands.len();
        // Read-only firmware geometry requires no regulatory/RF authority.
        h.db.clear();
        let memory = run(h.device.shared_memory())??;
        if memory.lmac_count() != 2
            || memory.edca_payload_ceiling(0, 0) != Some(3840)
            || memory.edca_payload_ceiling(1, 0) != Some(1792)
            || h.device.link_up()
            || h.device.terminal.load(Ordering::Acquire)
        {
            return Err("live shared-memory query changed radio admission or geometry");
        }
        let actor = h.actor.lock();
        let new = &actor.commands[before..];
        if new.len() != 1
            || !matches!((new[0].0, new[0].1), (2, 0) | (1, 0x25))
            || !new[0].2.is_empty()
        {
            return Err("shared-memory query synthesized another native command");
        }
        drop(actor);
        h.db.install(domain());
        h.scan()?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/smem",
    smoke_mvm_shared_memory_native_query_retains_owner_and_reports_opaque_fifos
);

fn smoke_mvm_shared_memory_dropped_waiter_keeps_exact_native_reply_and_dma() -> TestResult {
    check(|| {
        let h = Harness::new(false)?;
        h.actor.lock().hold_phy = Some(13);
        let mut operation = Box::pin(h.device.shared_memory());
        if !once(operation.as_mut()).is_pending() {
            return Err("shared-memory query skipped native command");
        }
        h.actor.lock().serve()?;
        if h.actor.lock().held.is_none() {
            return Err("shared-memory fixture did not hold receipt");
        }
        drop(operation);
        if h.device.control.try_lock().unwrap().is_none() || h.device.state.try_lock().is_some() {
            return Err("public query cancellation dropped retained native Work");
        }
        h.actor.lock().release();
        h.pump()?;
        if h.retained().0 != 0
            || h.device
                .state
                .try_lock()
                .unwrap()
                .owner
                .as_ref()
                .unwrap()
                .phase()
                != Phase::Configured
        {
            return Err("late shared-memory reply did not finish its exact retained owner");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/smem",
    smoke_mvm_shared_memory_dropped_waiter_keeps_exact_native_reply_and_dma
);

fn smoke_mvm_tlc_amsdu_native_feedback_is_consumed_without_packet_or_radio_grant() -> TestResult {
    check(|| {
        let h = Harness::profile(true, true)?;
        h.join()?;
        let before = h.actor.lock().commands.len();
        let report = [
            0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe, 0, 0, 0x21, 0, 0, 0,
        ];
        h.actor.lock().inject(0xf7, 5, 0x8000, &report);
        if !h.device.step(None).is_empty() {
            return Err("TLC feedback became an Ethernet frame");
        }
        {
            let state = h.device.state.try_lock().unwrap();
            let owner = state.owner.as_ref().unwrap();
            if owner.firmware_amsdu_limit(0) != Some(3839)
                || owner.firmware_amsdu_limit(5) != Some(3839)
                || owner.firmware_amsdu_limit(1).is_some()
            {
                return Err("native TLC feedback missed its exact station/TID owner");
            }
        }
        h.actor.lock().inject(0xf7, 5, 0x8000, &report[..19]);
        h.device.step(None);
        if h.device
            .state
            .try_lock()
            .unwrap()
            .owner
            .as_ref()
            .unwrap()
            .firmware_amsdu_limit(0)
            .is_some()
            || h.actor.lock().commands.len() != before
            || !h.device.link_up()
        {
            return Err("malformed TLC kept stale size or feedback created native emission");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/tx_amsdu",
    smoke_mvm_tlc_amsdu_native_feedback_is_consumed_without_packet_or_radio_grant
);

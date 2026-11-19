//! Native CONFIG v1/v2 BAIDs compose the same recipient reorder/PN owner
//! and exact DEL_BA RX marker as the original ADD_STA48 dialect.
use super::*;

fn smoke_mvm_ml_baid_v1_v2_native_allocation_reorder_and_retirement() -> TestResult {
    check(|| {
        for version in [1, 2] {
            for protected in [false, true] {
                let h = Harness::build_nvm_baid(protected, true, 3, 3, true, true, 0, 0, version)?;
                h.join()?;
                start(&h, 5, 4094, 32)?;
                if !receive(&h, rx(&h, 5, 4095, 4094, 502, 6, 42)?).is_empty() {
                    return Err("ML BAID future escaped reorder hole");
                }
                if receive(&h, rx(&h, 5, 4094, 4094, 501, 6, 41)?) != [ip(41, false), ip(42, false)]
                {
                    return Err("ML BAID did not release SN and PN in order");
                }
                action(&h, &[3, 2, 0, 0x58, 39, 0]);
                h.pump()?;
                if !receive(&h, rx(&h, 5, 4094, 0, 503, 6, 43)?).is_empty() {
                    return Err("retired ML BAID reopened receive");
                }
                let actor = h.actor.lock();
                let add = actor
                    .commands
                    .iter()
                    .position(|(g, c, b)| *g == 5 && *c == 0x16 && b[0] == 0)
                    .ok_or("native ML BAID ADD absent")?;
                let remove = actor
                    .commands
                    .iter()
                    .position(|(g, c, b)| *g == 5 && *c == 0x16 && b[0] == 2)
                    .ok_or("native ML BAID REMOVE absent")?;
                if remove <= add
                    || actor
                        .commands
                        .iter()
                        .any(|(g, c, b)| *g == 1 && *c == 0x18 && matches!(b[17], 8 | 16))
                {
                    return Err("ML BAID used legacy ADD_STA allocation ABI");
                }
                let expected = if version == 1 {
                    [2, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                } else {
                    [2, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0]
                };
                if actor.commands[remove].2 != expected
                    || !actor.commands[remove + 1..].iter().any(|(g, c, b)| {
                        *g == 5 && *c == 2 && b.len() == 24 && b[20..24] == [6, 0, 0, 0]
                    })
                    || actor.rx_ba[5].is_some()
                {
                    return Err("ML BAID removal was not followed by exact RX retirement marker");
                }
                drop(actor);
                start(&h, 5, 100, 32)?;
                if receive(&h, rx(&h, 5, 100, 101, 504, 6, 44)?) != [ip(44, false)] {
                    return Err("fresh ML BAID agreement failed after terminal retirement");
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ml_baid_v1_v2_native_allocation_reorder_and_retirement
);

fn smoke_mvm_ml_baid_unknown_profile_never_uses_legacy_allocator() -> TestResult {
    check(|| {
        let h = Harness::build_nvm_baid(false, true, 2, 3, true, true, 0, 0, 3)?;
        h.join()?;
        add(&h, 0, 100, 32);
        h.pump()?;
        if h.actor
            .lock()
            .commands
            .iter()
            .any(|(g, c, b)| (*g == 5 && *c == 0x16) || (*g == 1 && *c == 0x18 && b[17] == 8))
            || h.actor.lock().tx_ba_enabled
        {
            return Err("unknown ML BAID version fell through to station allocator");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ml_baid_unknown_profile_never_uses_legacy_allocator
);

fn smoke_mvm_ml_baid_malformed_receipt_keeps_native_dma_and_closes_port() -> TestResult {
    check(|| {
        for version in [1, 2] {
            let h = Harness::build_nvm_baid(true, true, 3, 3, true, true, 0, 0, version)?;
            h.join()?;
            h.actor.lock().fail_phy = Some(1);
            add(&h, 0, 100, 32);
            h.pump()?;
            if h.device.link_up()
                || !h.device.terminal.load(Ordering::Acquire)
                || h.retained().1 != 2
                || h.actor
                    .lock()
                    .action_responses
                    .iter()
                    .any(|body| body[3..5] == [0, 0])
            {
                return Err("malformed ML BAID allocation reopened port or freed queue ownership");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ml_baid_malformed_receipt_keeps_native_dma_and_closes_port
);

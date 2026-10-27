//! Actual retained Gen2 worker + TFH/RFH BA conversations; no caller receipt
//! or decrypted flag substitutes for native DMA and the independent CCM/AP.
use super::*;
#[path = "mvm_nested_tests.rs"]
mod nested_tests;
fn fixture(protected: bool) -> Result<Harness, &'static str> {
    Harness::build_profile(protected, true, 3, 3, true)
}
fn ip(n: u8, up: bool) -> Vec<u8> {
    udp_ipv4(
        if up { AP } else { OWN },
        if up { OWN } else { AP },
        if up {
            NETWORK.lease_ip
        } else {
            NETWORK.server_ip
        },
        if up {
            NETWORK.server_ip
        } else {
            NETWORK.lease_ip
        },
        if up { 49152 } else { 7 },
        if up { 7 } else { 49152 },
        &[n; 16],
    )
}
fn action(h: &Harness, body: &[u8]) {
    let mut frame = vec![0; 24];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend_from_slice(body);
    h.actor.lock().inject(0xc1, 0, 0x8000, &envelope(&frame));
}
fn add(h: &Harness, tid: u8, ssn: u16, window: u16) {
    let mut body = vec![3, 0, 9, 0, 0, 0, 0, 0, 0];
    body[3..5].copy_from_slice(&((window << 6) | (u16::from(tid) << 2) | 2).to_le_bytes());
    body[7..9].copy_from_slice(&(ssn << 4).to_le_bytes());
    action(h, &body);
}
fn start(h: &Harness, tid: u8, ssn: u16, window: u16) -> Result<(), &'static str> {
    add(h, tid, ssn, window);
    h.pump()?;
    let expected = (window.min(32) << 6) | (u16::from(tid) << 2) | 2;
    if !h
        .actor
        .lock()
        .action_responses
        .iter()
        .any(|b| b.len() == 9 && b[..5] == [3, 1, 9, 0, 0] && b[5..7] == expected.to_le_bytes())
    {
        return Err("native allocation/positive management completion absent");
    }
    Ok(())
}
fn receive(h: &Harness, bytes: Vec<u8>) -> Vec<Vec<u8>> {
    h.actor.lock().inject(0xc1, 0, 0x8000, &bytes);
    h.device.step(None).into_iter().map(|p| p.0).collect()
}
fn rx(
    h: &Harness,
    tid: u8,
    sn: u16,
    nssn: u16,
    pn: u64,
    baid: u8,
    n: u8,
) -> Result<Vec<u8>, &'static str> {
    let ethernet = ip(n, false);
    let mut bytes = if h.actor.lock().protected {
        h.actor
            .lock()
            .security
            .encrypted_rx_profile(&ethernet, pn, false, Some(tid))?
    } else {
        let mut frame = from_ap(&ethernet, sn);
        frame[0] = 0x88;
        frame.splice(24..24, [tid, 0]);
        envelope(&frame)
    };
    bytes[48 + 22..48 + 24].copy_from_slice(&(sn << 4).to_le_bytes());
    bytes[16..20].copy_from_slice(
        &((u32::from(baid) << 24) | (u32::from(sn) << 12) | u32::from(nssn)).to_le_bytes(),
    );
    bytes[28..32].copy_from_slice(&0x00100207u32.to_le_bytes());
    Ok(bytes)
}
fn enqueue(h: &Harness, count: u8) -> Result<(), &'static str> {
    for n in 0..count {
        h.device
            .enqueue(&ip(n, true), narf_net::TxMeta::default())
            .map_err(|_| "native pipeline enqueue")?;
    }
    Ok(())
}
fn held(h: &Harness) -> Result<(), &'static str> {
    for _ in 0..256 {
        h.device.step(None);
        h.actor.lock().serve()?;
        if h.actor.lock().held.is_some()
            || h.actor.lock().security.holding()
            || !h.actor.lock().batch.is_empty()
        {
            if h.device.control.try_lock().unwrap().is_none() || h.device.state.try_lock().is_some()
            {
                return Err("native uncertainty lost retained Work/state ownership");
            }
            return Ok(());
        }
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    Err("native held BA boundary missing")
}
fn c5(pointer: u16) -> Vec<u8> {
    let mut b = vec![0; 40];
    b[28] = 1;
    b[32] = 24;
    b[34..36].copy_from_slice(&pointer.to_le_bytes());
    b
}

fn conversation(protected: bool) -> Result<(), &'static str> {
    let h = fixture(protected)?;
    h.join()?;
    start(&h, 0, 100, 32)?;
    let lease =
        narf_net::dhcp::dhcp_acquire(h.device.name(), 0).map_err(|_| "BA native kernel DORA")?;
    if !NETWORK.matches_lease(&lease) {
        return Err("BA DORA lease mismatch");
    }
    enqueue(&h, 8)?;
    h.pump()?;
    for n in 0..8 {
        if !h.actor.lock().security.data.contains(&ip(n, true)) {
            return Err("pipelined native Ethernet mismatch");
        }
    }
    let a = h.actor.lock();
    let (request, response) = a
        .tx_dialog
        .as_ref()
        .ok_or("firmware manager did not exchange on-air ADDBA")?;
    if request[7..] != [0x50, 0x73] || response[3..5] != [0, 0] || a.batch_dma.len() < 8 {
        return Err("firmware BA dialog/actual descriptors absent");
    }
    drop(a);
    h.actor.lock().downlink(&ip(99, false))?;
    h.pump()?;
    let mut found = false;
    while let Ok(Some(frame)) = h.device.rx.lock().as_mut().unwrap().try_recv() {
        found |= frame.payload() == ip(99, false);
    }
    if !found {
        return Err("BA native Ethernet missing from RX IPC");
    }
    h.actor.lock().closing = true;
    run(h.device.disassociate())?.map_err(|_| "BA ordered native close")?;
    if h.device.link_up() || h.retained() != (0, 0, 0) {
        return Err("BA close released incorrectly or reopened carrier");
    }
    Ok(())
}
fn smoke_mvm_ba_open_native_worker_dhcp_pipeline_ip_and_close() -> TestResult {
    check(|| conversation(false))
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_open_native_worker_dhcp_pipeline_ip_and_close
);
fn smoke_mvm_ba_wpa2_native_worker_dhcp_pipeline_ip_and_close() -> TestResult {
    check(|| conversation(true))
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_wpa2_native_worker_dhcp_pipeline_ip_and_close
);

fn smoke_mvm_ba_tag1_tag2_cannot_authorize_aggregation_program() -> TestResult {
    check(|| {
        for tag in [1, 2] {
            let h = Harness::build_profile(true, true, tag, 3, true)?;
            h.scan()?;
            let before = h.actor.lock().commands.len();
            if run(h.device.associate(h.request()))?.is_ok()
                || h.actor.lock().commands.len() != before
                || h.retained() != (0, 0, 0)
            {
                return Err(
                    "old measured emitter authorized aggregation or consumed native lifecycle",
                );
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_tag1_tag2_cannot_authorize_aggregation_program
);

fn smoke_mvm_ba_native_all_tids_ssn_window_and_peer_masks() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        for tid in 0..8 {
            start(&h, tid, 4094, 3)?;
        }
        let actor = h.actor.lock();
        for tid in 0..8 {
            let b = &actor
                .commands
                .iter()
                .find(|(g, c, b)| *g == 1 && *c == 0x18 && b[17] == 8 && b[28] == tid)
                .ok_or("TID BA allocation absent")?
                .2;
            let mut expected = [0; 48];
            expected[0] = 1;
            expected[17] = 8;
            expected[28] = tid;
            expected[30..32].copy_from_slice(&4094u16.to_le_bytes());
            expected[44] = 3;
            if b.as_slice() != expected {
                return Err("native RX BA allocation overwrote peer fields/SSN/window");
            }
        }
        drop(actor);
        for tid in 0..8 {
            if !receive(&h, rx(&h, tid, 4095, 4094, 52, tid + 1, 2)?).is_empty() {
                return Err("BA hole released ahead of actual SSN");
            }
            if receive(&h, rx(&h, tid, 4094, 4094, 51, tid + 1, 1)?) != [ip(1, false), ip(2, false)]
            {
                return Err("nonpower-of-two/wrap BA reorder-before-PN");
            }
            if receive(&h, rx(&h, tid, 0, 1, 53, tid + 1, 3)?) != [ip(3, false)] {
                return Err("BA4095 to0 lost packet/PN owner");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_native_all_tids_ssn_window_and_peer_masks
);

fn smoke_mvm_ba_native_nssn_bar_and_hole_releases_precede_pn() -> TestResult {
    check(|| {
        for kind in [0xc2, 0xc3] {
            let h = fixture(true)?;
            h.join()?;
            start(&h, 3, 100, 32)?;
            if !receive(&h, rx(&h, 3, 102, 100, 502, 4, 2)?).is_empty() {
                return Err("BA consumed future PN before release");
            }
            let release = if kind == 0xc3 {
                vec![4, 0, 102, 0]
            } else {
                let mut b = 3u32.to_le_bytes().to_vec();
                b.extend_from_slice(&(4u32 << 24 | 102).to_le_bytes());
                b
            };
            h.actor.lock().inject(kind, 0, 0x8000, &release);
            let output: Vec<_> = h.device.step(None).into_iter().map(|p| p.0).collect();
            if output != [ip(2, false)] {
                return Err("genuine native C2/C3 failed ordered release");
            }
            if !receive(&h, rx(&h, 3, 101, 100, 501, 4, 1)?).is_empty() {
                return Err("old sequence advanced past firmware release");
            }
            if !receive(&h, rx(&h, 3, 103, 104, 502, 4, 3)?).is_empty() {
                return Err("released native PN floor not committed");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_native_nssn_bar_and_hole_releases_precede_pn
);

fn smoke_mvm_ba_native_foreign_old_malformed_and_nested_never_consume_pn() -> TestResult {
    check(|| {
        for fault in 0..8 {
            let h = fixture(true)?;
            h.join()?;
            start(&h, 2, 200, 32)?;
            let mut p = rx(&h, 2, 200, 201, 601, 3, 1)?;
            match fault {
                0 => p[19] = 31,
                1 => p[19] |= 0x80,
                2 => p[48 + 24] = 3,
                3 => p[34] = 2,
                4 => p[12] &= !1,
                5 => p[48 + 22..48 + 24].copy_from_slice(&(201u16 << 4).to_le_bytes()),
                6 => {
                    p[3] |= 0x40;
                    p[48 + 24] |= 0x80;
                }
                _ => p[48 + 1] |= 0x80,
            }
            if !receive(&h, p).is_empty() {
                return Err("foreign/old/nested native BA escaped");
            }
            if receive(&h, rx(&h, 2, 200, 201, 601, 3, 2)?) != [ip(2, false)] {
                return Err("rejected BA packet consumed sequence/PN");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_native_foreign_old_malformed_and_nested_never_consume_pn
);

fn smoke_mvm_ba_native_duplicate_dialog_does_not_allocate_again() -> TestResult {
    check(|| {
        let h = fixture(false)?;
        h.join()?;
        start(&h, 0, 345, 64)?;
        let before = h
            .actor
            .lock()
            .commands
            .iter()
            .filter(|(_, c, b)| *c == 0x18 && b[17] == 8)
            .count();
        start(&h, 0, 345, 64)?;
        if h.actor
            .lock()
            .commands
            .iter()
            .filter(|(_, c, b)| *c == 0x18 && b[17] == 8)
            .count()
            != before
        {
            return Err("duplicate ADDBA allocated new native BAID");
        }
        add(&h, 0, 346, 32);
        h.pump()?;
        if !h
            .actor
            .lock()
            .action_responses
            .iter()
            .any(|b| b[3..5] == [37, 0])
        {
            return Err("changed live agreement silently replaced original SSN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_native_duplicate_dialog_does_not_allocate_again
);

fn smoke_mvm_ba_each_allocation_response_remove_marker_wait_is_retained() -> TestResult {
    check(|| {
        for stage in [4, 6, 7, 8] {
            let h = fixture(true)?;
            h.join()?;
            if stage >= 6 && stage != 8 {
                start(&h, 0, 77, 32)?;
            }
            if stage == 8 {
                h.actor.lock().hold_action = true;
            } else {
                h.actor.lock().hold_phy = Some(stage);
            }
            if stage == 6 || stage == 7 {
                action(&h, &[3, 2, 0, 8, 39, 0]);
            } else {
                add(&h, 0, 77, 32);
            }
            held(&h)?;
            if stage == 8 {
                let p = rx(&h, 0, 77, 78, 701, 1, 1)?;
                h.actor.lock().inject(0xc1, 0, 0x8000, &p);
                // The native packet is queued while response delivery is uncertain;
                // it cannot be read by an independent owner or published early.
                if h.device.state.try_lock().is_some() {
                    return Err("positive response waiter lost exclusive owner");
                }
            }
            h.actor.lock().release();
            h.pump()?;
            if !h.device.link_up() || h.retained() != (0, 2, 0) {
                return Err("retained BA native boundary failed to finish same owner");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_each_allocation_response_remove_marker_wait_is_retained
);

fn smoke_mvm_ba_current_source_power_policy_loss_cannot_enable_or_resurrect() -> TestResult {
    check(|| {
        for fault in 0..3 {
            for stage in [4, 5] {
                let h = fixture(true)?;
                h.join()?;
                h.actor.lock().hold_phy = Some(stage);
                if stage == 4 {
                    add(&h, 0, 1, 32);
                } else {
                    enqueue(&h, 8)?;
                }
                held(&h)?;
                match fault {
                    0 => h.firmware.revoke(),
                    1 => h.power.revoke(),
                    _ => {
                        h.db.clear();
                    }
                }
                h.actor.lock().release();
                h.pump()?;
                h.db.install(domain());
                h.pump()?;
                if h.device.link_up()
                    || !h.device.terminal.load(Ordering::Acquire)
                    || h.retained().1 == 0
                {
                    return Err("BA enabling crossed revoked source/power/current-policy or reclaimed uncertain DMA");
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_current_source_power_policy_loss_cannot_enable_or_resurrect
);

fn smoke_mvm_ba_pipeline_eight_native_buffers_partial_prefix_and_no_slot_reuse() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        h.actor.lock().hold_batch = true;
        enqueue(&h, 8)?;
        held(&h)?;
        let pointers = h.actor.lock().batch.clone();
        let buffers = h.actor.lock().batch_dma.clone();
        if pointers.len() != 8
            || buffers.len() != 8
            || buffers
                .iter()
                .enumerate()
                .any(|(i, (dma, _))| buffers[..i].iter().any(|p| p.0 == *dma))
        {
            return Err("pipeline reused DMA or failed to publish eight real packets");
        }
        h.actor.lock().inject(0xc5, 0, 0x8000, &c5(pointers[2]));
        h.device.step(None);
        if h.device.state.try_lock().is_some() || h.device.control.try_lock().unwrap().is_none() {
            return Err("partial C5 prefix retired unacked tail");
        }
        h.actor.lock().batch.clear();
        h.actor.lock().inject(0xc5, 0, 0x8000, &c5(pointers[7]));
        h.pump()?;
        if !h.device.link_up() || h.retained() != (0, 2, 0) {
            return Err("terminal C5 prefix failed to retire DMA");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_pipeline_eight_native_buffers_partial_prefix_and_no_slot_reuse
);

fn smoke_mvm_ba_compressed_bad_tail_is_atomic_and_pins_packet_dma() -> TestResult {
    check(|| {
        for fault in 0..6 {
            let h = fixture(true)?;
            h.join()?;
            h.actor.lock().hold_batch = true;
            enqueue(&h, 8)?;
            held(&h)?;
            let pointers = h.actor.lock().batch.clone();
            let mut b = c5(pointers[7]);
            match fault {
                0 => b[38] = 1,
                1 => b[37] = 1,
                2 => b[32] = 23,
                3 => b[4] = 1,
                4 => b[0] = 6,
                _ => b.push(0),
            }
            h.actor.lock().inject(0xc5, 0, 0x8000, &b);
            h.pump()?;
            if !h.device.terminal.load(Ordering::Acquire)
                || h.device.link_up()
                || h.retained().2 != 1
            {
                return Err("malformed/foreign C5 tail freed owned native packet DMA");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_compressed_bad_tail_is_atomic_and_pins_packet_dma
);

fn smoke_mvm_ba_manager_refusal_uses_real_single_terminal_fallback() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        h.actor.lock().tx_ba_refuse = true;
        enqueue(&h, 8)?;
        h.pump()?;
        if !h.device.link_up()
            || h.actor.lock().security.data.len() != 8
            || h.retained() != (0, 2, 0)
            || h.actor
                .lock()
                .tx_dialog
                .as_ref()
                .is_none_or(|d| d.1[3..5] != [37, 0])
        {
            return Err(
                "firmware manager refusal fabricated BA success or lost native single fallback",
            );
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_manager_refusal_uses_real_single_terminal_fallback
);

fn smoke_mvm_ba_single_retry_failure_is_terminal_without_freeing_unacked_tail() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        h.actor.lock().hold_batch = true;
        enqueue(&h, 8)?;
        held(&h)?;
        let pointers = h.actor.lock().batch.clone();
        let mut b = vec![0; 48];
        b[0] = 1;
        b[36] = 24;
        b[40] = 0x82;
        b[44..48].copy_from_slice(&u32::from(pointers[2]).to_le_bytes());
        h.actor.lock().inject(0x1c, 0, 0x8000, &b);
        h.pump()?;
        if h.device.link_up() || !h.device.terminal.load(Ordering::Acquire) || h.retained().2 != 1 {
            return Err("single retry failure acknowledged batch or freed uncertain unacked tail");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_single_retry_failure_is_terminal_without_freeing_unacked_tail
);

fn smoke_mvm_ba_delba_native_remove_marker_and_stale_baid_never_reopen() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        start(&h, 4, 100, 32)?;
        if !receive(&h, rx(&h, 4, 102, 100, 802, 5, 1)?).is_empty() {
            return Err("pre-DELBA future escaped");
        }
        action(&h, &[3, 2, 0, 0x48, 39, 0]);
        h.pump()?;
        let old = rx(&h, 4, 100, 103, 800, 5, 2)?;
        if !receive(&h, old).is_empty() {
            return Err("old removed BAID reopened receive");
        }
        let actor = h.actor.lock();
        let remove = actor
            .commands
            .iter()
            .position(|(g, c, b)| *g == 1 && *c == 0x18 && b[17] == 16)
            .ok_or("native remove absent")?;
        let marker = actor
            .commands
            .iter()
            .enumerate()
            .find(|(i, (g, c, b))| *i > remove && *g == 5 && *c == 2 && b.len() == 24)
            .ok_or("actual DEL_BA marker absent")?
            .1;
        if marker.2[8..16] != [12, 0, 0, 0, 1, 0, 1, 0] || marker.2[20..24] != [5, 0, 0, 0] {
            return Err("native RX epoch did not bind exact retired BAID");
        }
        drop(actor);
        start(&h, 4, 200, 32)?;
        if receive(&h, rx(&h, 4, 200, 201, 801, 5, 3)?) != [ip(3, false)] {
            return Err("retired BA prefix consumed PN or prevented actual fresh agreement");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_delba_native_remove_marker_and_stale_baid_never_reopen
);

fn smoke_mvm_ba_native_rekey_flushes_holes_before_key_epoch_and_new_agreement() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        start(&h, 6, 100, 32)?;
        if !receive(&h, rx(&h, 6, 102, 100, 902, 7, 1)?).is_empty() {
            return Err("old-key BA hole escaped");
        }
        {
            let mut a = h.actor.lock();
            let Actor {
                security, firmware, ..
            } = &mut *a;
            security.challenge(firmware, Some([0x66; 32]), 7, [0x88; 16], 20)?;
        }
        h.pump()?;
        if !h.device.link_up() || h.actor.lock().rx_ba.iter().any(Option::is_some) {
            return Err("rekey retained old native BAID or lost real M4/keys");
        }
        let old = rx(&h, 6, 100, 103, 900, 7, 2)?;
        if !receive(&h, old).is_empty() {
            return Err("key epoch accepted unallocated old BAID");
        }
        start(&h, 6, 200, 32)?;
        if receive(&h, rx(&h, 6, 200, 201, 901, 7, 3)?) != [ip(3, false)] {
            return Err("new real key/agreement did not reset only its retired PN epoch");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_native_rekey_flushes_holes_before_key_epoch_and_new_agreement
);

fn smoke_mvm_ba_native_scheduler_wrap_is_not_wifi_ssn_or_ring_slot() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        for _ in 0..34 {
            enqueue(&h, 8)?;
            for _ in 0..32 {
                h.device.step(None);
                h.actor.lock().serve()?;
                narf_scheduler::block_on_spin(narf_time::sleep_cycles(
                    narf_time::wall::ns_to_cycles(2_000_000),
                ));
            }
            if h.device.control.try_lock().unwrap().is_some() {
                return Err("wrapped batch failed to reach genuine native terminal prefix");
            }
        }
        let actor = h.actor.lock();
        if !actor.batch_dma.iter().any(|p| p.1 == 0)
            || !actor.batch_dma.iter().any(|p| p.1 == 255)
            || actor.batch_dma.iter().any(|p| p.1 > 255)
            || !h.device.link_up()
        {
            return Err(
                "Qu scheduler did not wrap at256 independently of128 storage/12-bit WLAN SSN",
            );
        }
        drop(actor);
        if h.retained() != (0, 2, 0) {
            return Err("scheduler wrap lost native packet DMA owner");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_native_scheduler_wrap_is_not_wifi_ssn_or_ring_slot
);

fn smoke_mvm_ba_forwarded_bar_release_is_single_owner_and_unknown_bar_gets_delba() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        start(&h, 3, 100, 32)?;
        if !receive(&h, rx(&h, 3, 102, 100, 502, 4, 2)?).is_empty() {
            return Err("BAR fixture hole escaped");
        }
        let mut bar = vec![0x84, 0, 0, 0];
        bar.extend_from_slice(&OWN);
        bar.extend_from_slice(&AP);
        bar.extend_from_slice(&(3u16 << 12 | 4).to_le_bytes());
        bar.extend_from_slice(&(102u16 << 4).to_le_bytes());
        if !receive(&h, envelope(&bar)).is_empty() {
            return Err("raw BAR bypassed native source release owner");
        }
        let mut native = 3u32.to_le_bytes().to_vec();
        native.extend_from_slice(&(4u32 << 24 | 102).to_le_bytes());
        h.actor.lock().inject(0xc2, 0, 0x8000, &native);
        if h.device
            .step(None)
            .into_iter()
            .map(|p| p.0)
            .collect::<Vec<_>>()
            != [ip(2, false)]
        {
            return Err("source BAR release failed to deliver once");
        }
        bar[16..18].copy_from_slice(&(5u16 << 12 | 4).to_le_bytes());
        receive(&h, envelope(&bar));
        h.pump()?;
        if !h
            .actor
            .lock()
            .action_responses
            .contains(&vec![3, 2, 0, 0x50, 38, 0])
        {
            return Err("unknown recipient BAR did not get actual REQUIRE_SETUP DELBA");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_forwarded_bar_release_is_single_owner_and_unknown_bar_gets_delba
);

fn smoke_mvm_ba_bad_native_allocation_remove_or_delba_marker_is_terminal() -> TestResult {
    check(|| {
        for stage in [4, 6, 7] {
            let h = fixture(true)?;
            h.join()?;
            if stage > 4 {
                start(&h, 0, 100, 32)?;
            }
            if stage == 7 {
                h.actor.lock().hold_phy = Some(7);
                action(&h, &[3, 2, 0, 8, 39, 0]);
                held(&h)?;
                let mut marker = vec![12, 0, 0, 0, 1, 0, 1, 0];
                marker.extend_from_slice(&2u32.to_le_bytes());
                marker.extend_from_slice(&31u32.to_le_bytes());
                h.actor.lock().inject(0xff, 5, 0x8000, &marker);
                h.actor.lock().release();
            } else {
                h.actor.lock().fail_phy = Some(stage);
                if stage == 4 {
                    add(&h, 0, 100, 32);
                } else {
                    action(&h, &[3, 2, 0, 8, 39, 0]);
                }
            }
            h.pump()?;
            if h.device.link_up()
                || !h.device.terminal.load(Ordering::Acquire)
                || h.retained().1 != 2
            {
                return Err(
                    "malformed BA native receipt/marker reopened data or dropped queue DMA",
                );
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_bad_native_allocation_remove_or_delba_marker_is_terminal
);

fn smoke_mvm_ba_alternate_ml_baid_contract_stays_unaggregated() -> TestResult {
    check(|| {
        let h = Harness::build_profile_caps(true, true, 2, 3, true, true)?;
        h.join()?;
        add(&h, 0, 100, 32);
        h.pump()?;
        enqueue(&h, 8)?;
        h.pump()?;
        if !h.device.link_up()
            || h.actor
                .lock()
                .commands
                .iter()
                .any(|(g, c, b)| *g == 1 && *c == 0x18 && b[17] == 8)
            || h.actor.lock().tx_ba_enabled
            || h.actor
                .lock()
                .action_responses
                .iter()
                .any(|b| b[3..5] == [0, 0])
        {
            return Err("unsupported alternate BAID profile fell back to legacy BA ABI");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_alternate_ml_baid_contract_stays_unaggregated
);

fn smoke_mvm_ba_c5_debug_and_failed_aggregate_never_create_completion_credit() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        h.actor.lock().hold_batch = true;
        enqueue(&h, 8)?;
        held(&h)?;
        let pointers = h.actor.lock().batch.clone();
        let mut debug = vec![0; 36];
        debug[30] = 1;
        debug[32] = 24;
        h.actor.lock().inject(0xc5, 0, 0x8000, &debug);
        h.device.step(None);
        let mut failed = c5(pointers[2]);
        failed[0] = 2;
        failed[14] = 8;
        failed[16] = 8;
        h.actor.lock().inject(0xc5, 0, 0x8000, &failed);
        h.device.step(None);
        if h.device.state.try_lock().is_some() || h.device.terminal.load(Ordering::Acquire) {
            return Err("C5 debug/stats generated tail completion or rejected valid source format");
        }
        h.actor.lock().batch.clear();
        h.actor.lock().inject(0xc5, 0, 0x8000, &c5(pointers[7]));
        h.pump()?;
        if !h.device.link_up() || h.retained() != (0, 2, 0) {
            return Err("actual terminal C5 failed after nonterminal debug/failure");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_c5_debug_and_failed_aggregate_never_create_completion_credit
);

fn smoke_mvm_ba_original_qos_block_ack_policy_requires_live_native_agreement() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        start(&h, 2, 100, 32)?;
        let mut bytes = rx(&h, 2, 100, 101, 1001, 3, 1)?;
        bytes[48 + 24] = 0x62;
        if receive(&h, bytes) != [ip(1, false)] {
            return Err("live BA did not accept original QoS BlockAck policy/TID");
        }
        for (policy, baid) in [(0x22, 3), (0x42, 3), (0x72, 3), (0x82, 3), (0x62, 31)] {
            let mut bytes = rx(&h, 2, 101, 102, 1002, baid, 2)?;
            bytes[48 + 24] = policy;
            if !receive(&h, bytes).is_empty() {
                return Err("unsupported/unallocated QoS ACK policy escaped");
            }
        }
        if receive(&h, rx(&h, 2, 101, 102, 1002, 3, 3)?) != [ip(3, false)] {
            return Err("rejected QoS ACK policy consumed native sequence/PN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ba",
    smoke_mvm_ba_original_qos_block_ack_policy_requires_live_native_agreement
);

//! Full native interface conversations and independent literal HT/WMM cases.
use super::*;

fn ethernet(n: u8) -> Vec<u8> {
    udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        7,
        49152,
        &[n; 16],
    )
}
fn packet(h: &Harness, p: Vec<u8>) -> Vec<Vec<u8>> {
    h.actor.lock().inject(0xc1, 0, 0x8000, &p);
    h.device.step(None).into_iter().map(|f| f.0).collect()
}
fn encrypted(h: &Harness, pn: u64, tid: u8) -> Result<Vec<u8>, &'static str> {
    let mut p =
        h.actor
            .lock()
            .security
            .encrypted_rx_profile(&ethernet(tid), pn, false, Some(tid))?;
    p[28..32].copy_from_slice(&0x00100207u32.to_le_bytes());
    Ok(p)
}
fn no_rx(h: &Harness) -> bool {
    h.device
        .rx
        .lock()
        .as_mut()
        .unwrap()
        .try_recv()
        .ok()
        .flatten()
        .is_none()
}
fn held(h: &Harness, stage: u8) -> Result<(), &'static str> {
    h.scan()?;
    h.actor.lock().hold_phy = Some(stage);
    {
        let mut f = Box::pin(h.device.associate(h.request()));
        let mut found = false;
        for _ in 0..256 {
            if once(f.as_mut()).is_ready() {
                return Err("HT preparation skipped held native receipt");
            }
            h.actor.lock().serve()?;
            if h.actor.lock().held.is_some() {
                found = true;
                break;
            }
        }
        if !found {
            return Err("HT held native boundary absent");
        }
    }
    if h.device.link_up()
        || h.device.control.try_lock().unwrap().is_none()
        || h.device.state.try_lock().is_some()
    {
        return Err("HT external cancellation lost native Work/owner");
    }
    Ok(())
}
fn smoke_mvm_ht20_open_native_worker_dhcp_and_ip() -> TestResult {
    check(|| conversation_profile(false, true))
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_open_native_worker_dhcp_and_ip
);
fn smoke_mvm_ht20_wpa2_native_worker_ccmp_dhcp_and_ip() -> TestResult {
    check(|| conversation_profile(true, true))
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_wpa2_native_worker_ccmp_dhcp_and_ip
);

fn smoke_mvm_ht20_native_edca_peer_tlc_and_generated_offer_are_literal() -> TestResult {
    check(|| {
        let h = Harness::profile(true, true)?;
        h.join()?;
        let actor = h.actor.lock();
        let edca = actor
            .commands
            .iter()
            .find(|(g, c, b)| *g == 3 && *c == 9 && b[24] == 8)
            .ok_or("HT EDCA absent")?;
        let expected = [
            15, 0, 255, 3, 7, 2, 0, 0, 15, 0, 255, 3, 3, 4, 0, 0, 7, 0, 15, 0, 2, 8, 192, 11, 3, 0,
            7, 0, 2, 16, 224, 5,
        ];
        if edca.2[56..60] != [3, 0, 0, 0] || edca.2[60..92] != expected {
            return Err("HT native EDCA units/order/FIFO");
        }
        let peer = actor
            .commands
            .iter()
            .find(|(g, c, b)| *g == 1 && *c == 0x18 && b[17] == 6)
            .ok_or("HT peer absent")?;
        if peer.2[2..4] != [255; 2]
            || peer.2[20..24] != [16, 0, 24, 2]
            || peer.2[24..28] != [16, 0, 250, 63]
            || peer.2[36..38] != [7, 0]
            || peer.2[46..48] != [128, 0]
        {
            return Err("HT native peer SISO/density/AID/BA/UAPSD");
        }
        let tlc = actor
            .commands
            .iter()
            .find(|(g, c, _)| *g == 5 && *c == 15)
            .ok_or("HT TLC absent")?;
        let expected = [
            0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        ];
        if tlc.2 != expected {
            return Err("HT native v3 TLC rate/SGI/no-AMSDU fields");
        }
        if !h.device.get_wireless_info().hw_caps.ht_supported {
            return Err("proved native HT capability not exposed");
        }
        let cap = h.device.phy_capabilities(2400).ok_or("HT profile absent")?;
        if cap.ht[0] != 0x2c || cap.ht[3] != 255 || cap.ht[4..13] != [0; 9] || cap.vht.is_some() {
            return Err("HT20/SISO capability broadened to wider/NSS2/VHT");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_native_edca_peer_tlc_and_generated_offer_are_literal
);

fn smoke_mvm_ht20_legacy_power_record_never_authorizes_new_program() -> TestResult {
    check(|| {
        let h = Harness::qualified_profile(true, true, 1)?;
        h.scan()?;
        let before = h.actor.lock().commands.len();
        if run(h.device.associate(h.request()))?.is_ok()
            || h.actor.lock().commands.len() != before
            || h.device.terminal.load(Ordering::Acquire)
            || h.retained() != (0, 0, 0)
        {
            return Err(
                "legacy-only signed measurement authorized HT or consumed native lifecycle",
            );
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_legacy_power_record_never_authorizes_new_program
);

fn smoke_mvm_ht20_each_native_wait_cancellation_retains_and_finishes_work() -> TestResult {
    check(|| {
        for stage in 1..=3 {
            let h = Harness::profile(true, true)?;
            held(&h, stage)?;
            h.actor.lock().release();
            h.pump()?;
            if !h.device.link_up() || h.retained() != (0, 2, 0) {
                return Err("HT retained native stage did not finish same owner");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_each_native_wait_cancellation_retains_and_finishes_work
);

fn smoke_mvm_ht20_native_receipt_failure_and_late_revocation_never_open_port() -> TestResult {
    check(|| {
        for stage in 1..=3 {
            let h = Harness::profile(true, true)?;
            h.scan()?;
            h.actor.lock().fail_phy = Some(stage);
            if run(h.device.associate(h.request()))?.is_ok()
                || h.device.link_up()
                || !h.device.terminal.load(Ordering::Acquire)
                || h.retained().1 == 0
            {
                return Err("bad HT native receipt opened port or released uncertain DMA");
            }
        }
        for fault in 0..3 {
            for stage in 1..=3 {
                let h = Harness::profile(true, true)?;
                held(&h, stage)?;
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
                    return Err("HT late receipt bypassed current source/power/policy");
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_native_receipt_failure_and_late_revocation_never_open_port
);

fn smoke_mvm_ht20_response_narrows_tx_without_narrowing_local_qos_receive() -> TestResult {
    check(|| {
        let h = Harness::profile(true, true)?;
        let mut reply = ht_ies();
        reply[2] &= !32;
        reply[5] = 1;
        h.actor.lock().response_ies = Some(reply);
        h.join()?;
        let actor = h.actor.lock();
        let tlc = actor
            .commands
            .iter()
            .find(|(g, c, _)| *g == 5 && *c == 15)
            .ok_or("narrowed HT TLC absent")?;
        if tlc.2[12..14] != [1, 0] || tlc.2[22] != 0 {
            return Err("response HT TX rate/GI not narrowed");
        }
        drop(actor);
        for tid in 0..8 {
            if packet(&h, encrypted(&h, 31, tid)?) != [ethernet(tid)] {
                return Err("local MCS7/SGI RX was incorrectly narrowed by AP RX facts");
            }
            if !packet(&h, encrypted(&h, 31, tid)?).is_empty() {
                return Err("QoS PTK/TID replay accepted");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_response_narrows_tx_without_narrowing_local_qos_receive
);

fn smoke_mvm_ht20_native_amsdu_complete_stages_all_frames_and_one_pn() -> TestResult {
    check(|| {
        let h = Harness::profile(true, true)?;
        h.join()?;
        let expected = vec![ethernet(1), ethernet(2), ethernet(3)];
        let parts = h.actor.lock().security.encrypted_amsdu(&expected, 71, 5)?;
        for part in &parts[..2] {
            if !packet(&h, part.clone()).is_empty() || !no_rx(&h) {
                return Err("native A-MSDU prefix escaped before last/MIC whole-owner");
            }
        }
        if packet(&h, parts[2].clone()) != expected {
            return Err("complete native A-MSDU did not release all checked Ethernet");
        }
        let mut replay = encrypted(&h, 71, 5)?;
        replay[48 + 22..48 + 24].copy_from_slice(&(24u16 << 4).to_le_bytes());
        if !packet(&h, replay).is_empty() {
            return Err("native A-MSDU failed to commit its complete PN floor");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_native_amsdu_complete_stages_all_frames_and_one_pn
);

fn smoke_mvm_ht20_native_amsdu_bad_suffix_never_leaks_prefix_or_pn() -> TestResult {
    check(|| {
        for fault in 0..9 {
            let h = Harness::profile(true, true)?;
            h.join()?;
            let mut frames = vec![ethernet(1), ethernet(2)];
            match fault {
                3 => frames[1][12..14].copy_from_slice(&[0x88, 0x8e]),
                4 => frames[1][6..12].copy_from_slice(&OWN),
                5 => {
                    frames[1][12..14].copy_from_slice(&[0x81, 0]);
                    frames[1].splice(14..14, [0, 0, 0x88, 0x8e]);
                }
                6 => frames[1][12..14].copy_from_slice(&[0x88, 0xc7]),
                7 => frames[1][12..14].copy_from_slice(&[0x80, 0xf3]),
                _ => {}
            }
            let mut parts = h.actor.lock().security.encrypted_amsdu(&frames, 81, 3)?;
            if !packet(&h, parts[0].clone()).is_empty() || !no_rx(&h) {
                return Err("bad-tail fixture leaked prefix");
            }
            if fault == 8 && (!packet(&h, vec![0; 48]).is_empty() || !no_rx(&h)) {
                return Err("malformed native MPDU released an A-MSDU prefix");
            }
            match fault {
                0 => parts[1][4] = 0x82,
                1 => parts[1][48 + 24] = 0x84,
                2 => parts[1][34] = 2,
                _ => {}
            }
            if !packet(&h, parts[1].clone()).is_empty() || !no_rx(&h) {
                return Err("native malformed/control suffix escaped or leaked prefix");
            }
            if packet(&h, encrypted(&h, 81, 3)?) != [ethernet(3)] {
                return Err("rejected aggregate consumed PN before complete native acceptance");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_native_amsdu_bad_suffix_never_leaks_prefix_or_pn
);

fn smoke_mvm_ht20_native_addba_decline_retains_following_ip() -> TestResult {
    check(|| {
        let h = Harness::profile(true, true)?;
        h.join()?;
        let mut request = vec![0; 24];
        request[0] = 0xd0;
        request[4..10].copy_from_slice(&OWN);
        request[10..16].copy_from_slice(&AP);
        request[16..22].copy_from_slice(&AP);
        request.extend_from_slice(&[3, 0, 9, 2, 16, 0, 0, 0, 0]);
        h.actor.lock().inject(0xc1, 0, 0x8000, &envelope(&request));
        let expected = ethernet(99);
        h.actor.lock().downlink(&expected)?;
        h.pump()?;
        let mut found = false;
        while let Ok(Some(f)) = h.device.rx.lock().as_mut().unwrap().try_recv() {
            found |= f.payload() == expected;
        }
        if !found || !h.device.link_up() || h.retained() != (0, 2, 0) {
            return Err("ADDBA decline lost following native IP or changed data/BA ownership");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_native_addba_decline_retains_following_ip
);

fn smoke_mvm_ht20_missing_or_malformed_response_never_commits_native_peer() -> TestResult {
    check(|| {
        for fault in 0..5 {
            let h = Harness::profile(true, true)?;
            h.scan()?;
            let mut ies = ht_ies();
            match fault {
                0 => ies.drain(..28).for_each(drop),
                1 => ies[30] = 2,
                2 => {
                    let dup = ies[..28].to_vec();
                    ies.extend_from_slice(&dup);
                }
                3 => ies.truncate(52),
                _ => ies[5] = 0,
            }
            h.actor.lock().response_ies = Some(ies);
            if run(h.device.associate(h.request()))?.is_ok()
                || h.device.link_up()
                || !h.device.terminal.load(Ordering::Acquire)
                || h.actor
                    .lock()
                    .commands
                    .iter()
                    .any(|(g, c, b)| *g == 1 && *c == 0x18 && b[17] == 6)
            {
                return Err("invalid HT/WMM response reached peer/TLC/port commit");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_missing_or_malformed_response_never_commits_native_peer
);

fn smoke_mvm_ht20_wmm_without_ht_uses_distinct_power_and_qos_legacy_fallback() -> TestResult {
    check(|| {
        let h = Harness::profile(false, true)?;
        let only_wmm = ht_ies()[52..].to_vec();
        {
            let mut ap = h.actor.lock();
            ap.beacon_ies = Some(only_wmm.clone());
            ap.response_ies = Some(only_wmm);
            ap.rx_rate = 0;
        }
        h.join()?;
        let actor = h.actor.lock();
        let tlc = actor
            .commands
            .iter()
            .find(|(g, c, _)| *g == 5 && *c == 15)
            .ok_or("WMM legacy TLC absent")?;
        if tlc.2[5] != 0 || tlc.2[12..24] != [0; 12] {
            return Err("WMM-only offer invented HT mode/rates");
        }
        let edca = actor
            .commands
            .iter()
            .find(|(g, c, b)| *g == 3 && *c == 9 && b[24] == 8)
            .ok_or("WMM legacy EDCA absent")?;
        if edca.2[56] != 1 {
            return Err("WMM-only offer set HT TGN flag");
        }
        drop(actor);
        h.actor.lock().downlink(&ethernet(7))?;
        if h.device
            .step(None)
            .into_iter()
            .map(|f| f.0)
            .collect::<Vec<_>>()
            != [ethernet(7)]
        {
            return Err("WMM QoS legacy receive fallback was not reachable");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_wmm_without_ht_uses_distinct_power_and_qos_legacy_fallback
);

fn smoke_mvm_ht20_native_amsdu_suffix_timeout_oversize_and_close_flush() -> TestResult {
    check(|| {
        for fault in 0..4 {
            let h = Harness::profile(true, true)?;
            h.join()?;
            let frames = if fault == 2 {
                (0..3)
                    .map(|n| {
                        let mut f = ethernet(n);
                        f.resize(1514, n);
                        f
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![ethernet(1), ethernet(2)]
            };
            let parts = h.actor.lock().security.encrypted_amsdu(&frames, 91, 4)?;
            if fault == 0 {
                if !packet(&h, parts[1].clone()).is_empty() || !no_rx(&h) {
                    return Err("index1 suffix established complete native aggregate");
                }
            } else {
                if !packet(&h, parts[0].clone()).is_empty() || !no_rx(&h) {
                    return Err("timed/large aggregate prefix escaped");
                }
                if fault == 1 {
                    h.device
                        .state
                        .try_lock()
                        .unwrap()
                        .owner
                        .as_mut()
                        .unwrap()
                        .model_expire_receive_aggregate();
                }
                if fault == 3 {
                    h.actor.lock().closing = true;
                    run(h.device.disassociate())?
                        .map_err(|_| "native close with incomplete HT aggregate")?;
                    if h.device.link_up() || !no_rx(&h) || h.retained() != (0, 0, 0) {
                        return Err("native close retained/published old aggregate");
                    }
                    continue;
                }
                for part in &parts[1..] {
                    if !packet(&h, part.clone()).is_empty() || !no_rx(&h) {
                        return Err("expired/oversize native aggregate published data");
                    }
                }
            }
            if packet(&h, encrypted(&h, 91, 4)?) != [ethernet(4)] {
                return Err("rejected/expired aggregate advanced native PN");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_native_amsdu_suffix_timeout_oversize_and_close_flush
);

fn smoke_mvm_ht20_native_rekey_flushes_pending_aggregate_and_qos_epoch() -> TestResult {
    check(|| {
        let h = Harness::profile(true, true)?;
        h.join()?;
        let parts = h
            .actor
            .lock()
            .security
            .encrypted_amsdu(&[ethernet(1), ethernet(2)], 101, 6)?;
        if !packet(&h, parts[0].clone()).is_empty() || !no_rx(&h) {
            return Err("pre-rekey aggregate prefix escaped");
        }
        {
            let mut ap = h.actor.lock();
            let Actor {
                security, firmware, ..
            } = &mut *ap;
            security.challenge(firmware, Some([0x66; 32]), 7, [0x88; 16], 20)?;
        }
        h.pump()?;
        if !h.device.link_up() || !no_rx(&h) {
            return Err("native rekey leaked old prefix or lost controlled port");
        }
        if !packet(&h, parts[1].clone()).is_empty() || !no_rx(&h) {
            return Err("old aggregate suffix survived new native key epoch");
        }
        // The new authenticator/native key must actually authenticate new
        // QoS ciphertext; unchanged TID replay state cannot stand in for it.
        if packet(&h, encrypted(&h, 121, 6)?) != [ethernet(6)] {
            return Err("new native HT key epoch cannot receive QoS data");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_native_rekey_flushes_pending_aggregate_and_qos_epoch
);

fn smoke_mvm_ht20_native_tlc_v2_v4_layouts_are_distinct_and_reachable() -> TestResult {
    check(|| {
        for version in [2, 4] {
            let h = Harness::version_profile(true, true, 2, version)?;
            h.join()?;
            let ap = h.actor.lock();
            let p = &ap
                .commands
                .iter()
                .find(|(g, c, _)| *g == 5 && *c == 15)
                .ok_or("versioned HT TLC absent")?
                .2;
            let v2 = [
                0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
            ];
            let v4 = [
                0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0,
            ];
            if p.as_slice() != if version == 2 { &v2[..] } else { &v4[..] } {
                return Err("native TLC2/4 SGI/MCS/extent copied from wrong API");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_native_tlc_v2_v4_layouts_are_distinct_and_reachable
);

fn smoke_mvm_ht20_required_selector_uses_typed_plan_and_caller_ie_stays_rejected() -> TestResult {
    check(|| {
        let h = Harness::profile(true, true)?;
        let mut ies = ht_ies();
        ies.extend_from_slice(&[50, 1, 255]);
        {
            let mut ap = h.actor.lock();
            ap.beacon_ies = Some(ies.clone());
            ap.response_ies = Some(ies);
        }
        h.scan()?;
        let before = h.actor.lock().commands.len();
        for id in [45, 61] {
            let mut request = h.request();
            request.ie = vec![id, 0];
            if run(h.device.associate(request))?.is_ok() || h.actor.lock().commands.len() != before
            {
                return Err("caller replaced the typed native PHY profile");
            }
        }
        run(h.device.associate(h.request()))?
            .map_err(|_| "actual mandatory HT selector was not admitted by typed native plan")?;
        if !h.device.link_up() {
            return Err("required HT membership did not reach native controlled port");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_required_selector_uses_typed_plan_and_caller_ie_stays_rejected
);

fn smoke_mvm_ht20_native_edca_invalid_offer_is_pre_io_and_beacon_change_is_terminal() -> TestResult
{
    check(|| {
        for fault in 0..3 {
            let h = Harness::profile(true, true)?;
            let mut ies = ht_ies();
            match fault {
                0 => ies[62] |= 16,
                1 => {
                    ies[64] = 255;
                    ies[65] = 255;
                }
                _ => ies[66] = ies[62],
            }
            h.actor.lock().beacon_ies = Some(ies);
            h.scan()?;
            let before = h.actor.lock().commands.len();
            if run(h.device.associate(h.request()))?.is_ok()
                || h.actor.lock().commands.len() != before
                || h.device.terminal.load(Ordering::Acquire)
            {
                return Err("unsupported AP EDCA consumed native HT lifecycle");
            }
        }
        let h = Harness::profile(true, true)?;
        h.join()?;
        let mut beacon = h.actor.lock().security.ap.beacon();
        let mut ies = ht_ies();
        ies[62] = 7;
        beacon.extend_from_slice(&ies);
        if !packet(&h, envelope(&beacon)).is_empty()
            || h.device.link_up()
            || !h.device.terminal.load(Ordering::Acquire)
        {
            return Err("changed AP EDCA revived/continued stale native QoS program");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_ht20_native_edca_invalid_offer_is_pre_io_and_beacon_change_is_terminal
);

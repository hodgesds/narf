//! Real retained station worker, original API4 RFH copies and independent
//! authenticator CCM. Expected Ethernet and command bits are literal inputs.
use super::*;

fn fixture(protected: bool) -> Result<Harness, &'static str> {
    Harness::build_profile(protected, true, 4, 3, true)
}
fn add_nested(h: &Harness, tid: u8, ssn: u16) {
    let mut body = vec![3, 0, 9, 0, 0, 0, 0, 0, 0];
    body[3..5].copy_from_slice(&(32u16 << 6 | u16::from(tid) << 2 | 3).to_le_bytes());
    body[7..9].copy_from_slice(&(ssn << 4).to_le_bytes());
    action(h, &body);
}
fn start_nested(h: &Harness, tid: u8, ssn: u16) -> Result<(), &'static str> {
    add_nested(h, tid, ssn);
    h.pump()?;
    let expected = 32u16 << 6 | u16::from(tid) << 2 | 3;
    if !h
        .actor
        .lock()
        .action_responses
        .iter()
        .any(|b| b.len() == 9 && b[..5] == [3, 1, 9, 0, 0] && b[5..7] == expected.to_le_bytes())
    {
        return Err("tag4/native BA allocation/positive nested response receipt absent");
    }
    Ok(())
}
fn nested(
    h: &Harness,
    frames: &[Vec<u8>],
    tid: u8,
    sn: u16,
    nssn: u16,
    pn: u64,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut packets = if h.actor.lock().protected {
        h.actor.lock().security.encrypted_amsdu(frames, pn, tid)?
    } else {
        frames
            .iter()
            .enumerate()
            .map(|(index, ethernet)| {
                let mut f = from_ap(ethernet, sn);
                f[0] = 0x88;
                f.splice(24..24, [tid | 0x80, 0]);
                let mut p = envelope(&f);
                p[3] |= 0x40;
                p[4] = index as u8 | if index + 1 == frames.len() { 0x80 } else { 0 };
                p
            })
            .collect()
    };
    for p in &mut packets {
        p[48 + 22..48 + 24].copy_from_slice(&(sn << 4).to_le_bytes());
        p[16..20].copy_from_slice(
            &(u32::from(tid + 1) << 24 | u32::from(sn) << 12 | u32::from(nssn)).to_le_bytes(),
        );
        p[28..32].copy_from_slice(&0x00100207u32.to_le_bytes());
    }
    Ok(packets)
}
fn all(h: &Harness, packets: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    packets.into_iter().flat_map(|p| receive(h, p)).collect()
}
fn worker(protected: bool) -> Result<(), &'static str> {
    let h = fixture(protected)?;
    h.join()?;
    start_nested(&h, 0, 100)?;
    h.actor.lock().nested_downlink = true;
    let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
        .map_err(|_| "nested native worker DORA")?;
    if !NETWORK.matches_lease(&lease) {
        return Err("nested native DORA lease");
    }
    enqueue(&h, 8)?;
    h.pump()?;
    for n in 0..8 {
        if !h.actor.lock().security.data.contains(&ip(n, true)) {
            return Err("nested program lost independent native TX pipeline packet");
        }
    }
    let sn = h.actor.lock().rx_ba[0].unwrap().1;
    let frames = [ip(91, false), ip(92, false)];
    let packets = nested(&h, &frames, 0, sn, (sn + 1) & 4095, 1000)?;
    if all(&h, packets) != frames {
        return Err("nested native worker did not publish complete exact IP bundle");
    }
    h.actor.lock().closing = true;
    run(h.device.disassociate())?.map_err(|_| "nested native close")?;
    if h.device.link_up() || h.retained() != (0, 0, 0) {
        return Err("nested native retirement lost DMA receipt ownership");
    }
    Ok(())
}
fn smoke_mvm_nested_open_native_worker_dhcp_pipeline_ip_and_close() -> TestResult {
    check(|| worker(false))
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_open_native_worker_dhcp_pipeline_ip_and_close
);
fn smoke_mvm_nested_wpa2_native_worker_dhcp_pipeline_ip_and_close() -> TestResult {
    check(|| worker(true))
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_wpa2_native_worker_dhcp_pipeline_ip_and_close
);

fn smoke_mvm_nested_native_all_tids_wrap_reorder_then_complete_pn() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        for tid in 0..8 {
            start_nested(&h, tid, 4094)?;
            let a = [ip(1, false), ip(2, false)];
            let b = [ip(3, false), ip(4, false)];
            if !all(&h, nested(&h, &b, tid, 4095, 4094, 502)?).is_empty() {
                return Err("nested future SN/PN escaped hole");
            }
            if all(&h, nested(&h, &a, tid, 4094, 4094, 501)?)
                != [a[0].clone(), a[1].clone(), b[0].clone(), b[1].clone()]
            {
                return Err("nested same-SN bundle not reordered atomically before PN");
            }
            if all(&h, nested(&h, &a, tid, 0, 1, 503)?) != a {
                return Err("nested BA4095 to0 sequence wrap");
            }
            if !all(&h, nested(&h, &b, tid, 1, 2, 503)?).is_empty() {
                return Err("nested complete PN replay admitted");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_native_all_tids_wrap_reorder_then_complete_pn
);

fn smoke_mvm_nested_nonlast_nssn_and_interleaved_tids_keep_whole_bundles() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        start_nested(&h, 0, 100)?;
        start_nested(&h, 7, 200)?;
        let a = [ip(1, false), ip(2, false)];
        let b = [ip(3, false), ip(4, false)];
        if !receive(&h, rx(&h, 0, 102, 100, 503, 1, 5)?).is_empty() {
            return Err("future SN escaped fixture hole");
        }
        let mut first = nested(&h, &a, 0, 100, 103, 501)?;
        if !receive(&h, first.remove(0)).is_empty() {
            return Err("non-LAST NSSN released a prefix/future sequence");
        }
        if all(&h, nested(&h, &b, 7, 200, 201, 500)?) != b {
            return Err("one TID's incomplete bundle blocked another TID");
        }
        if all(&h, first) != [a[0].clone(), a[1].clone(), ip(5, false)] {
            return Err("LAST did not release complete bundle before later SN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_nonlast_nssn_and_interleaved_tids_keep_whole_bundles
);

fn smoke_mvm_nested_bad_suffix_metadata_and_inner_control_never_commit_pn() -> TestResult {
    check(|| {
        for fault in 0..11 {
            let h = fixture(true)?;
            h.join()?;
            start_nested(&h, 2, 100)?;
            let mut frames = [ip(1, false), ip(2, false)];
            if fault == 7 {
                frames[1][12..14].copy_from_slice(&[0x88, 0x8e]);
            }
            if fault == 8 {
                frames[1][6..12].copy_from_slice(&OWN);
            }
            if fault == 9 {
                frames[1][12..14].copy_from_slice(&[0x88, 0xc7]);
            }
            let mut packets = nested(&h, &frames, 2, 100, 101, 600)?;
            match fault {
                0 => packets[1][4] = 0x82,
                1 => packets[1][19] = 30,
                2 => packets[1][12] &= !1,
                3 => packets[1][48 + 24] = 0x83,
                4 => packets[1][48 + 26] ^= 1,
                5 => packets[1].truncate(20),
                6 => {
                    packets.remove(0);
                }
                10 => packets[1][48 + 24] = 0xe2, // Changed original QoS within one MPDU.
                _ => {}
            }
            if !all(&h, packets).is_empty() {
                return Err("malformed/incomplete/control nested aggregate exposed a prefix");
            }
            if receive(&h, rx(&h, 2, 101, 102, 600, 3, 3)?) != [ip(3, false)] {
                return Err("rejected nested aggregate consumed replay PN");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_bad_suffix_metadata_and_inner_control_never_commit_pn
);

fn smoke_mvm_nested_malformed_native_middle_and_release_discard_only_partial() -> TestResult {
    check(|| {
        for release in [false, true] {
            let h = fixture(true)?;
            h.join()?;
            start_nested(&h, 0, 100)?;
            let frames = [ip(1, false), ip(2, false)];
            let mut packets = nested(&h, &frames, 0, 100, 101, 601)?;
            if !receive(&h, packets.remove(0)).is_empty() {
                return Err("nested prefix escaped");
            }
            if release {
                h.actor.lock().inject(0xc3, 0, 0x8000, &[1, 0, 101, 0]);
                h.device.step(None);
            } else {
                receive(&h, vec![0; 48]);
            }
            if !all(&h, packets).is_empty() {
                return Err("suffix crossed missing native prefix");
            }
            if receive(&h, rx(&h, 0, 101, 102, 601, 1, 3)?) != [ip(3, false)] {
                return Err("dropped native partial advanced PN");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_malformed_native_middle_and_release_discard_only_partial
);

fn smoke_mvm_nested_tag3_and_nonrequesting_peer_cannot_negotiate_nested() -> TestResult {
    check(|| {
        for tag in [3, 4] {
            let h = Harness::build_profile(true, true, tag, 3, true)?;
            h.join()?;
            if tag == 3 {
                add_nested(&h, 1, 100);
                h.pump()?;
            } else {
                start(&h, 1, 100, 32)?; // Tag4 alone is not peer consent.
            }
            let response = h
                .actor
                .lock()
                .action_responses
                .last()
                .cloned()
                .ok_or("non-nested native response absent")?;
            if response != [3, 1, 9, 0, 0, 6, 8, 0, 0] {
                return Err("tag3/peer permission silently broadened native agreement");
            }
            if !all(
                &h,
                nested(&h, &[ip(1, false), ip(2, false)], 1, 100, 101, 700)?,
            )
            .is_empty()
            {
                return Err("unnegotiated nested native packet escaped");
            }
            if receive(&h, rx(&h, 1, 100, 101, 700, 2, 3)?) != [ip(3, false)] {
                return Err("denied nested packet consumed ordinary agreement PN");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_tag3_and_nonrequesting_peer_cannot_negotiate_nested
);

fn smoke_mvm_nested_3839_boundary_and_partial_timeout_do_not_consume_pn() -> TestResult {
    check(|| {
        for size in [1271, 1272] {
            let h = fixture(true)?;
            h.join()?;
            start_nested(&h, 4, 100)?;
            let mut ethernet = ip(7, false);
            ethernet.resize(size, 0x55);
            let frames = [ethernet.clone(), ethernet.clone(), ethernet];
            let output = all(&h, nested(&h, &frames, 4, 100, 101, 800)?);
            // 1271-byte Ethernet restores three source subheaders/LLC extents:
            // aligned1279 + aligned1279 +1279 =3839;1272 makes3840.
            if (size == 1271 && output != frames) || (size == 1272 && !output.is_empty()) {
                return Err("native nested3839 aggregate extent boundary");
            }
            let pn = if size == 1271 { 801 } else { 800 };
            if receive(&h, rx(&h, 4, 101, 102, pn, 5, 8)?) != [ip(8, false)] {
                return Err("nested size rejection committed PN or lost ordinary successor");
            }
        }
        let h = fixture(true)?;
        h.join()?;
        start_nested(&h, 0, 100)?;
        let mut packets = nested(&h, &[ip(1, false), ip(2, false)], 0, 100, 101, 850)?;
        if !receive(&h, packets.remove(0)).is_empty() {
            return Err("timed native prefix escaped");
        }
        h.device
            .state
            .try_lock()
            .unwrap()
            .owner
            .as_mut()
            .unwrap()
            .model_expire_ba_partials();
        if !all(&h, packets).is_empty() {
            return Err("native suffix survived bounded partial expiry");
        }
        if receive(&h, rx(&h, 0, 101, 102, 850, 1, 3)?) != [ip(3, false)] {
            return Err("expired native aggregate consumed PN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_3839_boundary_and_partial_timeout_do_not_consume_pn
);

fn smoke_mvm_nested_native_rekey_delba_and_close_flush_partial_epochs() -> TestResult {
    check(|| {
        for change in 0..3 {
            let h = fixture(true)?;
            h.join()?;
            start_nested(&h, 6, 100)?;
            let mut packets = nested(&h, &[ip(1, false), ip(2, false)], 6, 100, 101, 901)?;
            if !receive(&h, packets.remove(0)).is_empty() {
                return Err("epoch prefix escaped");
            }
            match change {
                0 => {
                    let mut a = h.actor.lock();
                    let Actor {
                        security, firmware, ..
                    } = &mut *a;
                    security.challenge(firmware, Some([0x66; 32]), 7, [0x88; 16], 20)?;
                }
                1 => action(&h, &[3, 2, 0, 0x68, 39, 0]),
                _ => {
                    h.actor.lock().closing = true;
                    run(h.device.disassociate())?.map_err(|_| "nested partial native close")?;
                }
            }
            h.pump()?;
            if change == 2 {
                if h.device.link_up() || h.retained() != (0, 0, 0) {
                    return Err("nested close missed actual ordered retirement");
                }
                continue;
            }
            if !all(&h, packets).is_empty() || h.actor.lock().rx_ba[6].is_some() {
                return Err("old nested raw prefix/BAID survived native marker/key retirement");
            }
            start_nested(&h, 6, 200)?;
            let expected = [ip(3, false), ip(4, false)];
            if all(&h, nested(&h, &expected, 6, 200, 201, 901)?) != expected {
                return Err("native new agreement inherited discarded nested replay floor");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_native_rekey_delba_and_close_flush_partial_epochs
);

fn smoke_mvm_nested_positive_native_response_cancel_retains_same_owner() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        h.actor.lock().hold_action = true;
        add_nested(&h, 0, 100);
        held(&h)?;
        let packets = nested(&h, &[ip(1, false), ip(2, false)], 0, 100, 101, 950)?;
        for p in packets {
            h.actor.lock().inject(0xc1, 0, 0x8000, &p);
        }
        if !h.device.step(None).is_empty() || h.device.state.try_lock().is_some() {
            return Err("unreceived positive nested TX lost retained native owner");
        }
        h.actor.lock().release();
        h.pump()?;
        let mut output = Vec::new();
        while let Ok(Some(frame)) = h.device.rx.lock().as_mut().unwrap().try_recv() {
            output.push(frame.payload().to_vec());
        }
        if output != [ip(1, false), ip(2, false)] || h.retained() != (0, 2, 0) {
            return Err("terminal native response failed to activate original nested owner");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_positive_native_response_cancel_retains_same_owner
);

fn smoke_mvm_nested_source_power_policy_loss_at_enable_or_publication_is_terminal() -> TestResult {
    check(|| {
        for fault in 0..3 {
            for enabling in [false, true] {
                let h = fixture(true)?;
                h.join()?;
                if enabling {
                    h.actor.lock().hold_action = true;
                    add_nested(&h, 0, 100);
                    held(&h)?;
                } else {
                    start_nested(&h, 0, 100)?;
                    let mut p = nested(&h, &[ip(1, false), ip(2, false)], 0, 100, 101, 1000)?;
                    if !receive(&h, p.remove(0)).is_empty() {
                        return Err("revocation prefix escaped");
                    }
                    h.actor.lock().inject(0xc1, 0, 0x8000, &p[0]);
                }
                match fault {
                    0 => h.firmware.revoke(),
                    1 => h.power.revoke(),
                    _ => {
                        h.db.clear();
                    }
                }
                h.actor.lock().release();
                if !h.device.step(None).is_empty() {
                    return Err("nested publication crossed current grant loss");
                }
                h.pump()?;
                h.db.install(domain());
                h.pump()?;
                if h.device.link_up()
                    || !h.device.terminal.load(Ordering::Acquire)
                    || h.retained().1 == 0
                {
                    return Err(
                        "nested terminal source/power/policy loss reopened or freed uncertain DMA",
                    );
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_source_power_policy_loss_at_enable_or_publication_is_terminal
);

fn smoke_mvm_nested_block_ack_policy_and_exact_repeat_keep_original_agreement() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        start_nested(&h, 2, 100)?;
        let before = h
            .actor
            .lock()
            .commands
            .iter()
            .filter(|(g, c, b)| *g == 1 && *c == 0x18 && b[17] == 8)
            .count();
        start_nested(&h, 2, 100)?;
        if h.actor
            .lock()
            .commands
            .iter()
            .filter(|(g, c, b)| *g == 1 && *c == 0x18 && b[17] == 8)
            .count()
            != before
        {
            return Err("repeated nested dialog reallocated native BAID");
        }
        let expected = [ip(1, false), ip(2, false)];
        let mut packets = nested(&h, &expected, 2, 100, 101, 1100)?;
        for p in &mut packets {
            p[48 + 24] |= 0x60;
        }
        if all(&h, packets.clone()) != expected || !all(&h, packets).is_empty() {
            return Err("original nested BlockAck policy/duplicate PN agreement boundary");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_block_ack_policy_and_exact_repeat_keep_original_agreement
);

fn smoke_mvm_nested_128_native_subframes_are_complete_and_bounded() -> TestResult {
    check(|| {
        let h = fixture(true)?;
        h.join()?;
        start_nested(&h, 0, 100)?;
        let frames: Vec<_> = (0..128)
            .map(|_| {
                let mut f = OWN.to_vec();
                f.extend_from_slice(&AP);
                f.extend_from_slice(&[8, 0]);
                f
            })
            .collect();
        let mut packets = nested(&h, &frames, 0, 100, 101, 1200)?;
        let last = packets.pop().unwrap();
        if !all(&h, packets).is_empty() {
            return Err("128 native subframes exposed an early prefix");
        }
        let mut output = receive(&h, last);
        output.extend(h.device.step(None).into_iter().map(|p| p.0));
        if output != frames {
            return Err("complete128-subframe native bundle lost ownership");
        }
        if !receive(&h, rx(&h, 0, 101, 102, 1200, 1, 3)?).is_empty() {
            return Err("128-subframe completion failed to commit exactly its PN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nested",
    smoke_mvm_nested_128_native_subframes_are_complete_and_bounded
);

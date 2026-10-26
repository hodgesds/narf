//! Firmware offload BA events and original RAW DMA MPDUs, before software PN.
use super::*;

fn htt_note(h: &Harness, bytes: &[u8]) {
    h.model(|m| {
        m.inner
            .inner
            .rx
            .push_back((m.inner.receive_pipe, header(1, bytes)))
    });
    h.pump();
}
fn agreement(h: &Harness, kind: u8, window: u8, peer: u16, tid: u8) {
    let info = (peer << 4) | u16::from(tid);
    htt_note(h, &[kind, window, info as u8, (info >> 8) as u8]);
}
fn state(h: &Harness, tid: u8) -> Option<(u16, u8, usize, Option<u16>)> {
    h.device.radio.try_lock().unwrap().receive_ba_for_test(tid)
}
fn clock(h: &Harness, now: u64) {
    h.device
        .radio
        .try_lock()
        .unwrap()
        .receive_time_for_test(now);
}
fn joined(version: u32, dialect: Dialect, secured: bool) -> Result<Harness, &'static str> {
    let h = Harness::new(version, dialect, secured);
    enable(&h);
    h.join()?;
    clock(&h, 0);
    agreement(&h, 5, 8, 1800, 0);
    if state(&h, 0) != Some((1800, 8, 0, None)) {
        return Err("native HTT ADDBA did not retain exact sparse peer/TID/window");
    }
    Ok(h)
}
fn packet(label: u8) -> Vec<u8> {
    let (_, mut ethernet) = packets();
    *ethernet.last_mut().unwrap() = label;
    ethernet
}
fn mpdu(h: &Harness, sequence: u16, pn: u64, label: u8) -> Vec<u8> {
    mpdu_tid(h, sequence, pn, label, 0)
}
fn mpdu_tid(h: &Harness, sequence: u16, pn: u64, label: u8, tid: u8) -> Vec<u8> {
    if tid != 0 {
        let mut header = vec![0; 26];
        header[0] = 0x88;
        header[1] = if h.secured { 0x42 } else { 2 };
        header[4..10].copy_from_slice(&OWN);
        header[10..16].copy_from_slice(&AP);
        header[16..22].copy_from_slice(&AP);
        header[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
        header[24] = 0x80 | tid;
        let mut body = subframes(&packet(label), 1);
        if h.secured {
            body = h.model(|m| {
                let f = m.data.as_ref().unwrap();
                narf_wireless::ccmp::protect(
                    &Ccm,
                    &header,
                    f.ptk.as_ref().unwrap().tk.as_slice().try_into().unwrap(),
                    pn,
                    0,
                    tid,
                    false,
                    &mut body,
                )
                .unwrap()
            });
        }
        header.extend_from_slice(&body);
        return header;
    }
    let mut frame = aggregate(h, subframes(&packet(label), 1), pn);
    // CCMP masks the sequence-number portion of Sequence Control in AAD.
    frame[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    frame
}
fn queue(h: &Harness, frame: Vec<u8>, flags: u8, preamble: u8) {
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.queue.push_back(frame);
        f.rx_descriptors.push_back((flags, preamble, 7, 0x80));
    });
}
fn receive(h: &Harness) -> Vec<Vec<u8>> {
    let mut ring = h.device.rx_ring().lock();
    let Some(ring) = ring.as_mut() else {
        return Vec::new();
    };
    let mut frames = Vec::new();
    for _ in 0..narf_net::RX_RING_N {
        let Ok(Some(frame)) = ring.try_recv() else {
            break;
        };
        frames.push(frame.payload().to_vec());
    }
    frames
}
fn bar(sequence: u16, tid: u8) -> Vec<u8> {
    let mut frame = vec![0x84, 0, 0, 0];
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&(4u16 | (u16::from(tid) << 12)).to_le_bytes());
    frame.extend_from_slice(&(sequence << 4).to_le_bytes());
    frame
}

fn smoke_ath10k_rx_ba_actual_dma_orders_ppdu_before_ccmp_all_dialects() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for secured in [false, true] {
            let h = match joined(version, dialect, secured) {
                Ok(h) => h,
                Err(e) => return TestResult::Fail(e),
            };
            queue(&h, mpdu(&h, 10, 1, 10), 1, 8);
            // PHY words on middle/LAST are deliberately invalid. Only the
            // validated FIRST's retained PPDU context can admit these MPDUs.
            queue(&h, mpdu(&h, 12, 3, 12), 0, 0xff);
            queue(&h, mpdu(&h, 11, 2, 11), 2, 0xff);
            h.pump();
            if receive(&h) != vec![packet(10), packet(11), packet(12)]
                || state(&h, 0) != Some((1800, 8, 0, Some(13)))
                || !h.device.link_up()
            {
                return TestResult::Fail("native multi-MPDU PPDU was not reordered before PN/MIC");
            }
            // A late duplicate/older MPDU has no authority to consume PN4.
            queue(&h, mpdu(&h, 12, 4, 90), 3, 8);
            h.pump();
            if !receive(&h).is_empty() {
                return TestResult::Fail("old BA sequence escaped native window");
            }
            queue(&h, mpdu(&h, 13, 4, 13), 3, 8);
            h.pump();
            if receive(&h) != vec![packet(13)] {
                return TestResult::Fail("dropped native duplicate consumed CCMP PN");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/rx_ba",
    smoke_ath10k_rx_ba_actual_dma_orders_ppdu_before_ccmp_all_dialects
);

fn smoke_ath10k_rx_ba_wrap_hole_duplicate_add_and_explicit_bar() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for raw_bar in [false, true] {
            let h = match joined(version, dialect, true) {
                Ok(h) => h,
                Err(e) => return TestResult::Fail(e),
            };
            queue(&h, mpdu(&h, 4094, 1, 1), 3, 8);
            queue(&h, mpdu(&h, 0, 3, 3), 3, 8);
            h.pump();
            if receive(&h) != vec![packet(1)] || state(&h, 0) != Some((1800, 8, 1, Some(4095))) {
                return TestResult::Fail("native wrap gap failed to retain encrypted original");
            }
            agreement(&h, 5, 8, 1800, 0);
            if state(&h, 0) != Some((1800, 8, 1, Some(4095))) {
                return TestResult::Fail("duplicate native ADD reset SSN or buffered ownership");
            }
            let mut forged = bar(0, 0);
            forged[10] ^= 4;
            if raw_bar {
                queue(&h, forged, 3, 8);
            } else {
                h.model(|m| management_frame(m, forged));
            }
            h.pump();
            if !receive(&h).is_empty() || state(&h, 0) != Some((1800, 8, 1, Some(4095))) {
                return TestResult::Fail("foreign BAR advanced current sparse peer sequence");
            }
            if raw_bar {
                queue(&h, bar(0, 0), 3, 8);
            } else {
                h.model(|m| management_frame(m, bar(0, 0)));
            }
            h.pump();
            if receive(&h) != vec![packet(3)] || state(&h, 0) != Some((1800, 8, 0, Some(1))) {
                return TestResult::Fail(
                    "actual native compressed BAR failed to advance wrap hole",
                );
            }
            // Delayed sequence4095 is old; its PN2 must never be considered.
            queue(&h, mpdu(&h, 4095, 2, 2), 3, 8);
            h.pump();
            if !receive(&h).is_empty() {
                return TestResult::Fail("BAR released an old late sequence");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/rx_ba",
    smoke_ath10k_rx_ba_wrap_hole_duplicate_add_and_explicit_bar
);

fn smoke_ath10k_rx_ba_idle_timeout_and_future_window_advance_are_bounded() -> TestResult {
    let h = match joined(4, Dialect::Tlv, true) {
        Ok(h) => h,
        Err(e) => return TestResult::Fail(e),
    };
    queue(&h, mpdu(&h, 100, 1, 1), 3, 8);
    queue(&h, mpdu(&h, 102, 2, 2), 3, 8);
    h.pump();
    if receive(&h) != vec![packet(1)] {
        return TestResult::Fail("native BA hole was not buffered");
    }
    clock(&h, 99_999_999);
    h.pump();
    if !receive(&h).is_empty() {
        return TestResult::Fail("native BA hole expired before deadline");
    }
    clock(&h, 100_000_000);
    h.pump();
    if receive(&h) != vec![packet(2)] || state(&h, 0) != Some((1800, 8, 0, Some(103))) {
        return TestResult::Fail("native Idle did not release bounded100ms BA hole");
    }
    queue(&h, mpdu(&h, 105, 3, 3), 3, 8);
    queue(&h, mpdu(&h, 113, 4, 4), 3, 8);
    h.pump();
    if receive(&h) != vec![packet(3)] || state(&h, 0) != Some((1800, 8, 1, Some(106))) {
        return TestResult::Fail("future native sequence did not bound window before PN");
    }
    clock(&h, 200_000_000);
    h.pump();
    if receive(&h) != vec![packet(4)] {
        return TestResult::Fail("future BA hole failed bounded expiry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/rx_ba",
    smoke_ath10k_rx_ba_idle_timeout_and_future_window_advance_are_bounded
);

fn smoke_ath10k_rx_ba_malformed_foreign_events_and_session_retirement() -> TestResult {
    for case in 0..7 {
        let h = match joined(4, Dialect::Tlv, true) {
            Ok(h) => h,
            Err(e) => return TestResult::Fail(e),
        };
        queue(&h, mpdu(&h, 1, 1, 1), 3, 8);
        queue(&h, mpdu(&h, 3, 3, 3), 3, 8);
        h.pump();
        if receive(&h) != vec![packet(1)] {
            return TestResult::Fail("BA event fixture failed native baseline");
        }
        match case {
            0 => agreement(&h, 5, 0, 1800, 0),
            1 => agreement(&h, 5, 65, 1800, 0),
            2 => agreement(&h, 5, 16, 1800, 0),
            3 => htt_note(&h, &[5, 8, 0x80, 0x70, 0]),
            4 => agreement(&h, 6, 1, 1800, 0),
            5 => agreement(&h, 6, 0, 1800, 0),
            _ => {
                agreement(&h, 5, 64, 1799, 0);
                agreement(&h, 6, 0, 1799, 0);
            }
        }
        if case < 5 {
            if !h.closed() || state(&h, 0).is_some() || !retained_native_dma(&h) {
                return TestResult::Fail(
                    "malformed/current changed BA failed to retire buffered owner",
                );
            }
        } else if case == 5 {
            if !h.device.link_up() || state(&h, 0).is_some() {
                return TestResult::Fail("native DELBA failed to retire only its sequence owner");
            }
            agreement(&h, 5, 1, 1800, 0);
            queue(&h, mpdu(&h, 2, 2, 2), 3, 8);
            h.pump();
            if receive(&h) != vec![packet(2)] || state(&h, 0) != Some((1800, 1, 0, Some(3))) {
                return TestResult::Fail("DELBA committed buffered PN or invented new ADD SSN");
            }
        } else if !h.device.link_up() || state(&h, 0) != Some((1800, 8, 1, Some(2))) {
            return TestResult::Fail("foreign native BA event changed current sparse peer owner");
        }
        if !receive(&h).is_empty() {
            return TestResult::Fail("BA retirement published buffered old prefix");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/rx_ba",
    smoke_ath10k_rx_ba_malformed_foreign_events_and_session_retirement
);

fn smoke_ath10k_rx_ba_ppdu_identity_and_phy_are_required_before_pn() -> TestResult {
    for case in 0..7 {
        let h = match joined(4, Dialect::Tlv, true) {
            Ok(h) => h,
            Err(e) => return TestResult::Fail(e),
        };
        let genuine = mpdu(&h, 10, 1, 1);
        match case {
            0 => queue(&h, genuine.clone(), 0, 0xff), // no FIRST context
            1 => queue(&h, genuine.clone(), 2, 0xff),
            2 => queue(&h, genuine.clone(), 1, 12), // unsupported VHT FIRST
            3 => {
                let mut foreign = genuine.clone();
                foreign[10] ^= 4;
                queue(&h, foreign, 1, 8);
                queue(&h, genuine.clone(), 2, 0xff);
            }
            4 => {
                let mut wrong_tid = genuine.clone();
                wrong_tid[24] |= 1;
                queue(&h, wrong_tid, 1, 8);
                queue(&h, genuine.clone(), 2, 0xff);
            }
            5 => {
                agreement(&h, 6, 0, 1800, 0);
                queue(&h, genuine.clone(), 1, 8);
                queue(&h, genuine.clone(), 2, 0xff);
            }
            _ => {
                let mut fragment = genuine.clone();
                fragment[22] |= 1;
                queue(&h, fragment, 1, 8);
                queue(&h, genuine.clone(), 2, 0xff);
            }
        }
        h.pump();
        if !receive(&h).is_empty() || !h.device.link_up() {
            return TestResult::Fail("orphan/foreign/invalid FIRST seeded native PPDU admission");
        }
        queue(&h, genuine, 3, 8);
        h.pump();
        if receive(&h) != vec![packet(1)] {
            return TestResult::Fail("rejected PPDU metadata consumed encrypted PN");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/rx_ba",
    smoke_ath10k_rx_ba_ppdu_identity_and_phy_are_required_before_pn
);

fn smoke_ath10k_rx_ba_rekey_flushes_holes_and_never_authorizes_pending_data() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let h = match joined(version, dialect, true) {
            Ok(h) => h,
            Err(e) => return TestResult::Fail(e),
        };
        queue(&h, mpdu(&h, 10, 1, 1), 3, 8);
        queue(&h, mpdu(&h, 12, 3, 3), 3, 8);
        h.pump();
        if receive(&h) != vec![packet(1)] {
            return TestResult::Fail("rekey BA gap baseline");
        }
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.pn = 2;
            let group = f.group_rekey();
            f.hold_data = true;
            f.queue.push_back(group);
        });
        h.pump();
        if state(&h, 0) != Some((1800, 8, 0, None))
            || h.device
                .radio
                .try_lock()
                .unwrap()
                .data_permission()
                .is_some()
            || !h.device.link_up()
            || !receive(&h).is_empty()
        {
            return TestResult::Fail(
                "actual ReplyReady retained prior reorder/decoded epoch or lost carrier",
            );
        }
        let pending = mpdu(&h, 40, 4, 4);
        queue(&h, pending.clone(), 3, 8);
        h.pump();
        if state(&h, 0) != Some((1800, 8, 0, None)) || !receive(&h).is_empty() {
            return TestResult::Fail("closed rekey port retained preauthorization ciphertext/SSN");
        }
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.hold_data = false;
            let id = f.held.pop_front().unwrap();
            complete(m, id, 0);
        });
        h.pump();
        if !receive(&h).is_empty() || state(&h, 0) != Some((1800, 8, 0, None)) {
            return TestResult::Fail("late rekey receipt retrospectively authorized pending data");
        }
        queue(&h, pending, 3, 8);
        h.pump();
        if receive(&h) != vec![packet(4)] || !h.device.link_up() {
            return TestResult::Fail("closed-port ciphertext consumed PN before new admission");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/rx_ba",
    smoke_ath10k_rx_ba_rekey_flushes_holes_and_never_authorizes_pending_data
);

fn smoke_ath10k_rx_ba_unmap_close_policy_and_failure_drop_originals() -> TestResult {
    for case in 0..4 {
        let h = match joined(4, Dialect::Tlv, true) {
            Ok(h) => h,
            Err(e) => return TestResult::Fail(e),
        };
        queue(&h, mpdu(&h, 10, 1, 1), 3, 8);
        queue(&h, mpdu(&h, 12, 3, 3), 3, 8);
        h.pump();
        if receive(&h) != vec![packet(1)] {
            return TestResult::Fail("terminal BA gap baseline");
        }
        match case {
            0 => htt_note(&h, &[4, 0, 8, 7]), // current sparse peer1800
            1 => {
                h.device.retire_host();
                h.pump();
            }
            2 => {
                *h.policy.lock() = None;
                h.pump();
            }
            _ => {
                h.device.radio.try_lock().unwrap().fail_station_data();
                h.pump();
            }
        }
        clock(&h, 200_000_000);
        h.pump();
        if state(&h, 0).is_some()
            || !receive(&h).is_empty()
            || h.device.link_up()
            || !retained_native_dma(&h)
        {
            return TestResult::Fail(
                "terminal native BA path retained or published buffered original",
            );
        }
        if case == 2 {
            *h.policy.lock() = Some(station_tests::policy());
            queue(&h, mpdu(&h, 11, 2, 2), 3, 8);
            h.pump();
            if h.device.link_up() || !receive(&h).is_empty() {
                return TestResult::Fail("restored policy reopened retired native BA owner");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/rx_ba",
    smoke_ath10k_rx_ba_unmap_close_policy_and_failure_drop_originals
);

fn smoke_ath10k_ht_late_positive_m4_never_authorizes_pre_receipt_ciphertext() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let h = Harness::new(version, dialect, true);
        enable(&h);
        let ethernet = packet(7);
        let key = narf_wireless::eapol::wpa_pmk_to_ptk(
            KeyMgmt::Psk,
            &PMK,
            &AP,
            &OWN,
            &ANONCE,
            &[0x73; 32],
            16,
        );
        let mut frame = vec![0; 26];
        frame[0] = 0x88;
        frame[1] = 0x42;
        frame[4..10].copy_from_slice(&OWN);
        frame[10..16].copy_from_slice(&AP);
        frame[16..22].copy_from_slice(&AP);
        frame[24] = 0x80;
        let body = narf_wireless::ccmp::protect(
            &Ccm,
            &frame,
            key.tk.as_slice().try_into().unwrap(),
            1,
            0,
            0,
            false,
            &mut subframes(&ethernet, 1),
        )
        .unwrap();
        frame.extend_from_slice(&body);
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.m4_before_receipt = Some(frame.clone());
            f.rx_phy = Some((8, 7, 0x80));
        });
        if let Err(e) = h.join() {
            return TestResult::Fail(e);
        }
        if !receive(&h).is_empty()
            || !h.device.link_up()
            || h.model(|m| m.data.as_ref().unwrap().deferred_receipt.is_some())
        {
            return TestResult::Fail(
                "late positive M4 admitted queued preauthorization ciphertext",
            );
        }
        queue(&h, frame, 3, 8);
        h.pump();
        if receive(&h) != vec![ethernet] {
            return TestResult::Fail("pre-M4 native ciphertext consumed PN before port admission");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/rx_ba",
    smoke_ath10k_ht_late_positive_m4_never_authorizes_pre_receipt_ciphertext
);

fn smoke_ath10k_rx_ba_closed_m4_first_cannot_seed_phy_after_positive_receipt() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let h = Harness::new(version, dialect, true);
        enable(&h);
        let key = narf_wireless::eapol::wpa_pmk_to_ptk(
            KeyMgmt::Psk,
            &PMK,
            &AP,
            &OWN,
            &ANONCE,
            &[0x73; 32],
            16,
        );
        let mut first = vec![0; 26];
        first[0] = 0x88;
        first[1] = 0x42;
        first[4..10].copy_from_slice(&OWN);
        first[10..16].copy_from_slice(&AP);
        first[16..22].copy_from_slice(&AP);
        first[22..24].copy_from_slice(&(10u16 << 4).to_le_bytes());
        first[24] = 0x80;
        let body = narf_wireless::ccmp::protect(
            &Ccm,
            &first,
            key.tk.as_slice().try_into().unwrap(),
            1,
            0,
            0,
            false,
            &mut subframes(&packet(1), 1),
        )
        .unwrap();
        first.extend_from_slice(&body);
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.m4_before_receipt = Some(first.clone());
            f.m4_descriptor = Some((1, 8, 7, 0x80));
            f.m4_ba_window = Some(8);
        });
        if let Err(e) = h.join() {
            return TestResult::Fail(e);
        }
        clock(&h, 0);
        if !receive(&h).is_empty() || state(&h, 0) != Some((1800, 8, 0, None)) {
            return TestResult::Fail("pre-M4 native FIRST gained sequence/admission authority");
        }
        // Same protected bytes and PN1, now an orphan LAST with invalid PHY.
        // Neither a closed-port FIRST nor the positive M4 receipt may leave
        // a retained PHY context that admits this frame retrospectively.
        queue(&h, first.clone(), 2, 0xff);
        h.pump();
        if !receive(&h).is_empty() || state(&h, 0) != Some((1800, 8, 0, None)) {
            return TestResult::Fail("held M4 FIRST bridged positive receipt into orphan LAST");
        }
        queue(&h, first, 1, 8);
        queue(&h, mpdu(&h, 11, 2, 2), 2, 0xff);
        h.pump();
        if receive(&h) != vec![packet(1), packet(2)] || !h.device.link_up() {
            return TestResult::Fail(
                "closed-port FIRST/orphan LAST consumed PN before genuine PPDU",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/rx_ba",
    smoke_ath10k_rx_ba_closed_m4_first_cannot_seed_phy_after_positive_receipt
);

fn smoke_ath10k_rx_ba_all_sixteen_native_tid_windows_and_flush_are_independent() -> TestResult {
    let h = match joined(4, Dialect::Tlv, true) {
        Ok(h) => h,
        Err(e) => return TestResult::Fail(e),
    };
    agreement(&h, 6, 0, 1800, 0);
    for tid in 0..16u8 {
        agreement(&h, 5, 64, 1800, tid);
        let base = u16::from(tid) * 100;
        queue(&h, mpdu_tid(&h, base, 1, tid, tid), 3, 8);
        h.model(|m| m.data.as_mut().unwrap().next_tid = Some(tid));
        h.pump();
        if receive(&h) != vec![packet(tid)] {
            return TestResult::Fail("native TID replay/sequence window shared another TID's PN");
        }
        queue(&h, mpdu_tid(&h, base + 2, 3, tid + 32, tid), 3, 8);
        h.model(|m| m.data.as_mut().unwrap().next_tid = Some(tid));
        h.pump();
        if !receive(&h).is_empty() || state(&h, tid) != Some((1800, 64, 1, Some(base + 1))) {
            return TestResult::Fail("native sixteen-TID heap owner did not retain a bounded hole");
        }
    }
    // Target RX_FLUSH is not an in-order authority. The native host owner
    // retains the complete originals and applies full12-bit sequence itself.
    htt_note(&h, &[2, 8, 7, 15, 0, 0, 63, 1]);
    for tid in 0..16u8 {
        let base = u16::from(tid) * 100;
        if state(&h, tid) != Some((1800, 64, 1, Some(base + 1))) {
            return TestResult::Fail("target six-bit FLUSH changed host's12-bit reorder owner");
        }
        queue(&h, mpdu_tid(&h, base + 1, 2, tid + 16, tid), 3, 8);
        h.model(|m| m.data.as_mut().unwrap().next_tid = Some(tid));
        h.pump();
        if receive(&h) != vec![packet(tid + 16), packet(tid + 32)] {
            return TestResult::Fail("native per-TID ordered CCMP/A-MSDU release failed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/rx_ba",
    smoke_ath10k_rx_ba_all_sixteen_native_tid_windows_and_flush_are_independent
);

fn smoke_ath10k_rx_ba_ppdu_tid_switch_and_last_or_deadline_retire_phy_context() -> TestResult {
    for timeout in [false, true] {
        let h = match joined(4, Dialect::Tlv, true) {
            Ok(h) => h,
            Err(e) => return TestResult::Fail(e),
        };
        agreement(&h, 5, 8, 1800, 1);
        queue(&h, mpdu(&h, 10, 1, 1), 1, 8);
        h.pump();
        if receive(&h) != vec![packet(1)] {
            return TestResult::Fail("PPDU FIRST native baseline");
        }
        if timeout {
            clock(&h, 100_000_000);
        } else {
            queue(&h, mpdu_tid(&h, 20, 1, 20, 1), 0, 0xff);
            h.model(|m| m.data.as_mut().unwrap().next_tid = Some(1));
            h.pump();
        }
        queue(&h, mpdu(&h, 11, 2, 2), 2, 0xff);
        h.pump();
        if !receive(&h).is_empty() || state(&h, 1) != Some((1800, 8, 0, None)) {
            return TestResult::Fail("foreign TID or expired FIRST seeded stale LAST admission");
        }
        queue(&h, mpdu(&h, 11, 2, 2), 1, 8);
        queue(&h, mpdu(&h, 12, 3, 3), 2, 0xff);
        queue(&h, mpdu(&h, 13, 4, 4), 0, 0xff);
        h.pump();
        if receive(&h) != vec![packet(2), packet(3)] {
            return TestResult::Fail("matching LAST failed to retire PHY or bad LAST consumed PN");
        }
        queue(&h, mpdu(&h, 13, 4, 4), 3, 8);
        h.pump();
        if receive(&h) != vec![packet(4)] {
            return TestResult::Fail("orphan middle committed PN after LAST");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/rx_ba",
    smoke_ath10k_rx_ba_ppdu_tid_switch_and_last_or_deadline_retire_phy_context
);

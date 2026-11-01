// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual SET/GET trait boundary, DMA PM notices, TSF/TIM timers, NETWORK
//! SLEEP and native buffered DATA receipts. No hardware measurements supplied.
use super::*;
use crate::ath9k::ps;
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
fn setting(h: &Harness, on: bool) -> Result<(), i32> {
    let iface: &dyn WirelessNetIface = &*h.device;
    iface.set_power_save(on)
}
fn beacon(h: &Harness, tsf: u64, unicast: bool, cab: bool) {
    let mut bytes = h.peer.lock().beacon();
    bytes[24..32].copy_from_slice(&tsf.to_le_bytes());
    bytes[32..34].copy_from_slice(&100u16.to_le_bytes());
    // The real shared FakeAp association supplies AID42: octet5, bit2.
    // Partial bitmap offset4 skips four octets; this raw beacon advertises
    // actual AID42, never a synthetic driver-side TIM receipt.
    bytes.extend_from_slice(&[
        5,
        5,
        0,
        2,
        4 | u8::from(cab),
        0,
        if unicast { 4 } else { 0 },
    ]);
    h.model.inject(&bytes, 0).unwrap();
}
fn prepared(protected: bool, sender: bool) -> (Harness, Cap<FirmwareBlob, Read>) {
    let h = Harness::new_ht(protected, 255);
    h.peer.lock().ps_test = true;
    if sender {
        crate::ath9k::tx_ba::large_tests::qualify(&h.model, 8, 65535, 64);
    }
    crate::ath9k::rx_ba::tests::qualify(&h.model, 64);
    let cap = ps::tests::qualify(&h.model);
    h.join();
    h.pump();
    let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0).unwrap();
    assert!(h.plan.matches_lease(&lease));
    (h, cap)
}
fn enable(h: &Harness) {
    setting(h, true).unwrap();
    h.pump();
    assert!(
        h.device.link_up()
            && h.model.ps_bound.get()
            && !h.model.ps_sleeping.get()
            && h.model.registers.borrow().get(&0x24) == Some(&1),
        "initial current S1 IRQ binding closed the owner before its first TIM"
    );
    beacon(h, 102400, false, false);
    h.pump();
}
fn smoke_ar9285_station_ps_signed_source_and_public_default_fail_closed() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    let h = Harness::new_ht(true, 255);
    let iface: &dyn WirelessNetIface = &*h.device;
    if iface.power_save_default().is_some() || setting(&h, true) != Err(-95) {
        return TestResult::Fail("unqualified PS advertised or set");
    }
    let base = h.model.ht.borrow().clone().unwrap();
    // Provisioning S alone cannot authorize the S1 IRQ program. Before
    // actual bind, the original HT readback must still reject IER1.
    let _source = ps::tests::qualify(&h.model);
    let unbound = crate::ath9k::packet::Port::station_ps_current(&h.model);
    h.model.registers.borrow_mut().insert(0x24, 1);
    let refused = base.readback(&h.model).is_err();
    h.model.registers.borrow_mut().insert(0x24, 0);
    if unbound != Ok(false) || !refused {
        return TestResult::Fail("unbound S asset bypassed the original HT IER0 invariant");
    }
    let good = ps::tests::record(&base);
    if ps::request(&base).identity == crate::ath9k::tx_ba::request(&base).identity {
        return TestResult::Fail("PS source aliases BA");
    }
    for at in [
        0, 4, 6, 8, 12, 16, 48, 54, 55, 56, 57, 64, 66, 68, 69, 70, 72, 74, 75, 79, 80, 111, 112,
        127,
    ] {
        let mut bad = good.clone();
        bad[at] ^= 1;
        if (ps::Source::Verified {
            bytes: bad,
            signer: Some([1; 32]),
            cap: Cap::bootstrap(),
        })
        .load(base.clone())
        .is_ok()
        {
            return TestResult::Fail("unknown/foreign PS record accepted");
        }
    }
    if (ps::Source::Verified {
        bytes: good,
        signer: None,
        cap: Cap::bootstrap(),
    })
    .load(base)
    .is_ok()
    {
        return TestResult::Fail("unsigned PS accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/station-ps",
    smoke_ar9285_station_ps_signed_source_and_public_default_fail_closed
);
fn smoke_ar9285_station_ps_native_pm_notice_ack_idle_and_actual_sleep_wake_disable() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for protected in [false, true] {
        let (h, _) = prepared(protected, false);
        h.peer.lock().hold_ps = true;
        h.peer.lock().hold_ba = true;
        setting(&h, true).unwrap();
        h.pump();
        beacon(&h, 102400, false, false);
        h.pump();
        let notices = h.peer.lock().ps_notices.clone();
        let head = h.model.tx.get().unwrap();
        if notices.len() != 1
            || notices[0].len() != 24
            || notices[0][..2] != [0x48, 0x11]
            || notices[0][1] & 0x40 != 0
            || h.model.ps_sleeping.get()
            || !h.device.link_up()
        {
            return TestResult::Fail(
                "pending genuine plaintext PM notice became sleep or lost association",
            );
        }
        h.model.complete(true).unwrap();
        // A real ADDBA arrives behind the actual PM tail. Its reply must
        // wait for the PS fresh-idle receipt without blocking RX/security,
        // and its agreement must still require the native reply ACK.
        h.model
            .inject(&crate::ath9k::rx_ba::tests::addba(3, 1, 64, 0, false), 0)
            .unwrap();
        h.model.registers.borrow_mut().insert(0x840, 1);
        h.model.registers.borrow_mut().insert(0xa00, 1);
        h.pump();
        if h.model.ps_sleeping.get() {
            return TestResult::Fail("PM tail bypassed live QCU");
        }
        h.model.registers.borrow_mut().insert(0x840, 0);
        h.model.registers.borrow_mut().insert(0xa00, 0);
        h.peer.lock().hold_ps = false;
        h.pump();
        if h.peer.lock().ba_accepts.len() != 1
            || h.model.ps_sleeping.get()
            || !h.device.link_up()
            || h.model.tx.get().is_none()
        {
            return TestResult::Fail("BA reply behind PM receipt bypassed its actual native ACK");
        }
        h.model.complete(true).unwrap();
        h.peer.lock().hold_ba = false;
        h.pump();
        if !h.model.ps_sleeping.get()
            || h.model.registers.borrow().get(&0x7044) != Some(&4)
            || h.model.word(head + 92).unwrap() & 1 == 0
            || h.model.registers.borrow()[&0x704c] != 2
            || h.model.registers.borrow()[&0xb8] & 0x10 == 0
            || h.model.registers.borrow()[&0x8240] & 0x31 != 0x31
            || h.peer.lock().ba_accepts.len() != 1
            || h.model.registers.borrow()[&0x803c] != 0x417
        {
            return TestResult::Fail("actual NETWORK_SLEEP/RTC/timer/IRQ proof missing");
        }
        // A native descriptor/queue receipt, not SET success, controls actual
        // PM state. Desired off is visible while its real notice is pending.
        h.peer.lock().hold_ps = true;
        setting(&h, false).unwrap();
        h.pump();
        let iface: &dyn WirelessNetIface = &*h.device;
        if iface.power_save_default() != Some(false)
            || h.model.ps_sleeping.get()
            || h.peer.lock().ps_notices.last().unwrap()[..2] != [0x48, 1]
        {
            return TestResult::Fail("desired off did not own actual awake notice");
        }
        h.model.complete(true).unwrap();
        h.peer.lock().hold_ps = false;
        h.pump();
        if h.model.registers.borrow()[&0x7044] != 2
            || h.model.registers.borrow()[&0x8240] & 0x31 != 0
            || h.model.registers.borrow()[&0xb8] & 0x10 != 0
            || h.peer.lock().ps_asleep
        {
            return TestResult::Fail("completed off failed actual AWAKE/timer restore");
        }
        // Re-enabling after actual off cannot reuse the old, now-disarmed
        // timer receipt. Only a fresh current beacon can authorize PM1.
        let before = h.peer.lock().ps_notices.len();
        setting(&h, true).unwrap();
        h.pump();
        if h.peer.lock().ps_notices.len() != before || h.model.ps_sleeping.get() {
            return TestResult::Fail("re-enable reused stale disarmed TIM receipt");
        }
        beacon(&h, 204800, false, false);
        h.pump();
        if h.peer.lock().ps_notices.len() != before + 1 || !h.model.ps_sleeping.get() {
            return TestResult::Fail("fresh re-enable failed native timer/PM/sleep continuation");
        }
        h.device.retire_host();
        h.pump();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/station-ps",
    smoke_ar9285_station_ps_native_pm_notice_ack_idle_and_actual_sleep_wake_disable
);
fn smoke_ar9285_station_ps_tim_pspoll_moredata_empty_null_and_kernel_data_receipts() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for protected in [false, true] {
        let (h, _) = prepared(protected, false);
        enable(&h);
        let frames: Vec<Vec<u8>> = (0..3)
            .map(|index| {
                udp_ipv4(
                    h.plan.station,
                    AP,
                    h.plan.server_ip,
                    h.plan.lease_ip,
                    7,
                    4900 + index,
                    &[index as u8; 32],
                )
            })
            .collect();
        h.peer.lock().ps_buffered.extend(frames.clone());
        h.model.fire_tim();
        h.pump();
        if h.model.ps_sleeping.get() || h.model.registers.borrow()[&0x8048] & 0x02000020 != 0 {
            return TestResult::Fail("TIM IRQ did not actually wake/unabort RX");
        }
        beacon(&h, 204800, true, false);
        h.pump();
        let received = h.received();
        if h.peer.lock().ps_polls.len() != 3
            || !h.model.ps_sleeping.get()
            || !frames.iter().all(|frame| received.contains(frame))
        {
            return TestResult::Fail(
                "native PS-Poll/MoreData chain did not deliver buffered current originals",
            );
        }
        let poll = h.peer.lock().ps_polls.last().unwrap().clone();
        let descriptor = h.model.registers.borrow()[&0x800];
        if poll != ps::poll(h.plan.station, AP, 42)
            || h.model.word(descriptor + 12).unwrap() >> 20 & 15 != 2
            || h.model.word(descriptor + 16).unwrap() & 0x8000 != 0
        {
            return TestResult::Fail("PS-Poll type/Duration AID/DONT_ENCRYPT descriptor mismatch");
        }
        // Advertised bit but no queued data: actual plaintext AP Null ends
        // the wait without creating an Ethernet/key/PN receipt.
        h.model.fire_tim();
        h.pump();
        beacon(&h, 307200, true, false);
        h.pump();
        if h.peer.lock().ps_polls.len() != 4 || !h.model.ps_sleeping.get() {
            return TestResult::Fail("empty PS-Poll Null did not complete native power wait");
        }
        h.device.retire_host();
        h.pump();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/station-ps",
    smoke_ar9285_station_ps_tim_pspoll_moredata_empty_null_and_kernel_data_receipts
);
fn smoke_ar9285_station_ps_dtim_cab_current_gtk_and_next_beacon_fallback() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for protected in [false, true] {
        let (h, _) = prepared(protected, false);
        enable(&h);
        h.model.fire_tim();
        h.pump();
        beacon(&h, 204800, false, true);
        h.pump();
        if h.model.ps_sleeping.get() {
            return TestResult::Fail("DTIM CAB wait slept before group data");
        }
        let down = udp_ipv4(
            [255; 6],
            AP,
            h.plan.server_ip,
            [255; 4],
            7,
            4990,
            b"actual CAB multicast",
        );
        let mut wire = h.peer.lock().downlink(&down).unwrap();
        if protected {
            // The actual shared FakeAp M3 installs GTK keyid1=[0x77;16]
            // (verification/wifi-fixtures/src/ap.rs). Use that delivered key,
            // not the pairwise TK, for this current multicast original.
            let header = wire[..26].to_vec();
            let pn = narf_wireless::ccmp::decode_ccmp_header(wire[26..34].try_into().unwrap())
                .unwrap()
                .0;
            let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0];
            body.extend_from_slice(&down[12..]);
            wire = header.clone();
            wire.extend_from_slice(
                &narf_wireless::ccmp::protect(
                    &tests::Ccm,
                    &header,
                    &[0x77; 16],
                    pn,
                    1,
                    0,
                    false,
                    &mut body,
                )
                .unwrap(),
            );
        }
        h.model.inject(&wire, 0).unwrap();
        h.pump();
        if !h.received().contains(&down) || !h.model.ps_sleeping.get() {
            return TestResult::Fail("current GTK CAB original missed native completion/sleep");
        }
        h.model.fire_tim();
        h.pump();
        beacon(&h, 307200, false, true);
        h.pump();
        if h.model.ps_sleeping.get() {
            return TestResult::Fail("new CAB indication did not hold awake");
        }
        beacon(&h, 409600, false, false);
        h.pump();
        if !h.model.ps_sleeping.get() {
            return TestResult::Fail("next real beacon did not retire missing CAB wait");
        }
        h.device.retire_host();
        h.pump();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/station-ps",
    smoke_ar9285_station_ps_dtim_cab_current_gtk_and_next_beacon_fallback
);
fn smoke_ar9285_station_ps_eight_original_pm_pn_sequence_and_actual_rekey_receipt() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    let (h, _) = prepared(true, true);
    let previous = h
        .model
        .transmitted
        .borrow()
        .iter()
        .rev()
        .find(|frame| frame.first() == Some(&0x88))
        .unwrap()
        .clone();
    let last_pn = narf_wireless::ccmp::decode_ccmp_header(previous[26..34].try_into().unwrap())
        .unwrap()
        .0;
    let next_seq = ((u16::from_le_bytes([previous[22], previous[23]]) >> 4) + 1) & 4095;
    enable(&h);
    let frames: Vec<Vec<u8>> = (0..8)
        .map(|index| {
            udp_ipv4(
                AP,
                h.plan.station,
                h.plan.lease_ip,
                h.plan.server_ip,
                4970 + index,
                7,
                &[index as u8; 32],
            )
        })
        .collect();
    for frame in &frames {
        narf_net::iface::send_on(h.device.name(), frame).unwrap();
    }
    h.pump();
    let data: Vec<Vec<u8>> = h
        .model
        .transmitted
        .borrow()
        .iter()
        .filter(|frame| frame.first() == Some(&0x88))
        .rev()
        .take(8)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if data.len() != 8
        || h.model.last_chain.borrow().len() != 8
        || !h.peer.lock().uplink.ends_with(&frames)
        || !h.model.ps_sleeping.get()
    {
        return TestResult::Fail("dozing sender did not own eight real original DATA frames");
    }
    for (index, frame) in data.iter().enumerate() {
        let pn = narf_wireless::ccmp::decode_ccmp_header(frame[26..34].try_into().unwrap())
            .unwrap()
            .0;
        if frame[1] & 0x10 == 0
            || pn != last_pn + 1 + index as u64
            || u16::from_le_bytes([frame[22], frame[23]]) >> 4 != (next_seq + index as u16) & 4095
        {
            return TestResult::Fail(
                "PS control consumed PN/QoS SC or DATA PM/immutable CCMP changed",
            );
        }
    }
    h.model.fire_tim();
    h.pump();
    h.peer.lock().hold_group = true;
    let group = h.peer.lock().group_rekey();
    h.model.inject(&group, 0).unwrap();
    h.pump();
    let reply = h.model.transmitted.borrow().last().unwrap().clone();
    if reply[1] & 0x50 != 0x50 || h.model.ps_sleeping.get() || h.peer.lock().group_replies != 1 {
        return TestResult::Fail("rekey did not hold awake with actual old-key PM Group2");
    }
    h.model.complete(true).unwrap();
    h.peer.lock().hold_group = false;
    h.pump();
    beacon(&h, 204800, false, false);
    h.pump();
    if !h.device.link_up() || !h.model.ps_sleeping.get() {
        return TestResult::Fail(
            "exact shared original/security reply receipt lost after PM mutation",
        );
    }
    h.device.retire_host();
    h.pump();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/station-ps",
    smoke_ar9285_station_ps_eight_original_pm_pn_sequence_and_actual_rekey_receipt
);
fn smoke_ar9285_station_ps_revoked_source_ignored_wake_shutdown_and_bad_notice_quarantine(
) -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for fault in 0..9 {
        let (h, cap) = prepared(true, false);
        enable(&h);
        let before = h.model.transmitted.borrow().len();
        match fault {
            0 => {
                cap.revoke();
            }
            1 => {
                h.model.ignore.set(Some(0x704c));
            }
            2 => {
                h.model.registers.borrow_mut().insert(0x7044, 1);
            }
            3 => {
                h.model.fire_tim();
                h.pump();
                h.peer.lock().hold_ps = true;
                setting(&h, false).unwrap();
                h.pump();
                h.model.complete(false).unwrap();
            }
            4 | 5 => {
                h.model.fire_tim();
                h.pump();
                let mut bytes = h.peer.lock().beacon();
                bytes[24..32].copy_from_slice(&204800u64.to_le_bytes());
                if fault == 4 {
                    // Actual current beacon with duplicate TIM is ambiguous.
                    bytes.extend_from_slice(&[5, 4, 0, 2, 0, 0, 5, 4, 0, 2, 0, 0]);
                } //fault5 genuinely omits TIM.
                h.model.inject(&bytes, 0).unwrap();
            }
            6 => {
                h.model.fire_tim();
                h.pump();
                h.model.ignore.set(Some(0x8200));
                beacon(&h, 204800, false, false);
            }
            7 => {
                h.model.registers.borrow_mut().insert(0x9874, 0);
            }
            _ => {
                h.model.fire_tim();
                h.pump();
                h.peer.lock().hold_ps = true;
                setting(&h, false).unwrap();
                h.pump();
                // Source notice bound is100ms, shorter than the ordinary
                // Packet1s timeout. No tail receipt exists to commit here.
                h.env.now.fetch_add(101, Ordering::AcqRel);
            }
        }
        let frame = udp_ipv4(
            AP,
            h.plan.station,
            h.plan.lease_ip,
            h.plan.server_ip,
            4991,
            7,
            b"must not escape failed power",
        );
        if fault != 3 && fault != 8 {
            let _ = h.device.enqueue(&frame, narf_net::TxMeta::plain());
        }
        h.pump();
        if h.device.link_up()
            || h.model.master.get()
            || fault != 3 && fault != 8 && h.model.transmitted.borrow().len() != before
        {
            return TestResult::Fail(
                "failed current source/wake/control receipt retained live DATA authority",
            );
        }
        if fault < 3 && !h.model.released.borrow().is_empty() {
            return TestResult::Fail("unproven sleeping/failed hardware freed published DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/station-ps",
    smoke_ar9285_station_ps_revoked_source_ignored_wake_shutdown_and_bad_notice_quarantine
);
fn smoke_ar9285_station_ps_source_timer_words_and_owned_policy_reversal() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    let (h, _) = prepared(true, false);
    h.peer.lock().hold_ps = true;
    setting(&h, true).unwrap();
    h.pump();
    beacon(&h, 102400, false, false);
    h.pump();
    for (register, expected) in [
        (0x8200, 204800),
        (0x8220, 102400),
        (0x8224, 102400),
        (0x8210, 201728),
        (0x8214, 201728),
        (0x80d4, 0x0a080000),
        (0x80d8, 0x200000),
        (0x8230, 102400),
        (0x8234, 204800),
        (0x813c, 0x4240),
    ] {
        if h.model.registers.borrow().get(&register) != Some(&expected) {
            return TestResult::Fail("actual source TSF/TU/DTIM timer words incorrect");
        }
    }
    // Returning from/changing the setter cannot discard the published notice.
    setting(&h, false).unwrap();
    h.pump();
    if h.peer.lock().ps_notices.len() != 1 || h.model.ps_sleeping.get() {
        return TestResult::Fail("policy reversal discarded in-flight PM notice");
    }
    h.model.complete(true).unwrap();
    h.pump();
    if h.peer.lock().ps_notices.len() != 2
        || h.peer.lock().ps_notices[1][1] != 1
        || h.model.ps_sleeping.get()
    {
        return TestResult::Fail("late PM1 receipt skipped owned PM0 continuation");
    }
    h.model.complete(true).unwrap();
    h.peer.lock().hold_ps = false;
    h.pump();
    if h.peer.lock().ps_asleep || h.model.registers.borrow()[&0x7044] != 2 {
        return TestResult::Fail("owned policy reversal fabricated final AWAKE");
    }
    h.device.retire_host();
    h.pump();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/station-ps",
    smoke_ar9285_station_ps_source_timer_words_and_owned_policy_reversal
);

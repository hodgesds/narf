//! Actual retained Session generations across unlocked packet callbacks.
use super::*;
use crate::mt7921::association::Security;
use core::cell::RefCell;
use narf_wireless::WirelessError;
const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];

fn reset_open_peer(session: &mut Session<Model>) {
    // The authored AP is a single-dialog authenticator. A fresh peer starts
    // the next real MLME exchange after actual native disconnect receipts.
    session.backend.access_point =
        Some(narf_wifi_fixtures::FakeAp::open(super::wmm_tests::NETWORK, b"narf", 6, 42).unwrap());
}

fn joined(
    secure: bool,
) -> Result<
    (
        Session<Model>,
        ScanBss,
        crate::mt7921::association::TxPermission,
    ),
    &'static str,
> {
    let (mut session, bss, permission) = super::vht_tests::prepared(2, secure);
    let mode = if secure {
        Security::Wpa2Psk { psk: [0x55; 32] }
    } else {
        Security::Open
    };
    run(session.associate_station(&bss, b"narf", mode, permission, &[]))
        .map_err(|_| "receive epoch real native association")?;
    Ok((session, bss, permission))
}
fn challenge(session: &mut Session<Model>) -> Result<(), &'static str> {
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    let mut packet = descriptor(&ap_eapol_frame(OWN, AP, &m1.into_eapol()));
    packet[12..16].copy_from_slice(&(36u32 << 8).to_le_bytes());
    session.backend.packets.push_back(packet);
    if session.receive_ethernet() != Ok(None) {
        return Err("receive epoch real M1 capture");
    }
    Ok(())
}
fn replace_key(session: &mut Session<Model>) -> Result<(), &'static str> {
    challenge(session)?;
    session.backend.access_point = None;
    session.backend.psk = [0x55; 32];
    session.backend.own_mac = OWN;
    session.backend.ap_mac = AP;
    session.backend.anonce = [0x55; 32];
    run(session.service_keys()).map_err(|_| "receive epoch native M2/retirement")?;
    if session.receive_ethernet() != Ok(None) || !session.keys_pending() {
        return Err("receive epoch real replacement M3");
    }
    run(session.service_keys()).map_err(|_| "receive epoch native key receipts")?;
    Ok(())
}
fn batch(session: &mut Session<Model>, secure: bool) -> Result<PacketStep, &'static str> {
    for pn in [9, 10] {
        session
            .backend
            .packets
            .push_back(super::vht_tests::data(secure, 2, 7, 1, pn));
    }
    let step = session
        .step_network(None)
        .map_err(|_| "native receive batch")?;
    if step.received.len() != 2
        || step.receive_epoch == 0
        || session.receive_current(step.receive_epoch) != Ok(true)
    {
        return Err("genuine receive batch lacks its actual current owner");
    }
    Ok(step)
}

fn reentrant() -> Result<(), &'static str> {
    for secure in [false, true] {
        let (mut session, bss, permission) = joined(secure)?;
        let step = batch(&mut session, secure)?;
        let old_epoch = step.receive_epoch;
        let native = RefCell::new(session);
        let callbacks = Cell::new(0);
        let published = Cell::new(0);
        let failure = Cell::new(None);
        crate::iface::deliver_received_batch(
            step,
            |epoch| {
                native
                    .borrow()
                    .receive_current(epoch)
                    .map_err(|_| WirelessError::HardwareError)
            },
            |_| {
                callbacks.set(callbacks.get() + 1);
                let mut session = native.borrow_mut();
                let result = if secure {
                    replace_key(&mut session)
                } else {
                    run(session.disassociate_station())
                        .map_err(|_| "reentrant native Open retirement")
                        .and_then(|()| {
                            reset_open_peer(&mut session);
                            run(session.associate_station(
                                &bss,
                                b"narf",
                                Security::Open,
                                permission,
                                &[],
                            ))
                            .map(|_| ())
                            .map_err(|_| "reentrant native Open replacement")
                        })
                };
                failure.set(result.err());
            },
            |_, epoch| {
                native
                    .borrow()
                    .publish_receive(epoch, || published.set(published.get() + 1))
                    .map(|_| ())
                    .map_err(|_| WirelessError::HardwareError)
            },
        )
        .map_err(|_| "native reentrant batch dispatch")?;
        if let Some(error) = failure.get() {
            return Err(error);
        }
        let mut session = native.into_inner();
        if callbacks.get() != 1
            || published.get() != 0
            || session.receive_current(old_epoch) != Ok(false)
            || session.receive_current(session.receive_epoch) != Ok(true)
            || session.receive_epoch == old_epoch
        {
            return Err(
                "old batch reached IPC/second callback or closed a replacement peer/key owner",
            );
        }
        session
            .backend
            .packets
            .push_back(super::vht_tests::data(secure, 2, 7, 1, 1));
        let fresh = session
            .step_network(None)
            .map_err(|_| "new owner native data step")?;
        if fresh.received.len() != 1 || fresh.receive_epoch == old_epoch {
            return Err("fresh key/peer inherited an old batch or replay epoch");
        }
    }
    Ok(())
}
fn mt76_receive_batch_reentrant_rekey_and_rejoin_drop_only_the_retired_epoch() -> TestResult {
    reentrant().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/receive_epoch",
    mt76_receive_batch_reentrant_rekey_and_rejoin_drop_only_the_retired_epoch
);

fn pending() -> Result<(), &'static str> {
    let (mut session, _, _) = joined(true)?;
    let old = session.receive_epoch;
    session.backend.tx_stall = true;
    let mut tx = vec![0x55; 60];
    tx[..6].copy_from_slice(&AP);
    tx[6..12].copy_from_slice(&OWN);
    tx[12..14].copy_from_slice(&[8, 0]);
    session
        .start_ethernet(&tx)
        .map_err(|_| "native outstanding TX before key challenge")?;
    challenge(&mut session)?;
    if session.keys_pending() || session.receive_current(old) != Ok(false) {
        return Err("TX-credit wait incorrectly kept challenged receive publication open");
    }
    let published = Cell::new(false);
    if session.publish_receive(old, || published.set(true)) != Ok(false) || published.get() {
        return Err("pending receive key owner published a stale batch");
    }
    let (mut session, _, _) = joined(true)?;
    session
        .backend
        .packets
        .push_back(super::vht_tests::data(true, 2, 7, 1, 9));
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    let mut packet = descriptor(&ap_eapol_frame(OWN, AP, &m1.into_eapol()));
    packet[12..16].copy_from_slice(&(36u32 << 8).to_le_bytes());
    session.backend.packets.push_back(packet);
    if !session
        .step_network(None)
        .map_err(|_| "same-drain key challenge")?
        .received
        .is_empty()
    {
        return Err("same-drain M1 allowed earlier collected data to escape its old epoch");
    }
    let (other, _, _) = joined(false)?;
    if other.receive_epoch == session.receive_epoch
        || other.receive_current(session.receive_epoch) != Ok(false)
    {
        return Err("replacement transport reused another retained receive epoch");
    }
    Ok(())
}
fn mt76_receive_epoch_closes_pending_keys_independently_of_tx_and_same_drain_batches() -> TestResult
{
    pending().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/receive_epoch",
    mt76_receive_epoch_closes_pending_keys_independently_of_tx_and_same_drain_batches
);

fn capture_admission() -> Result<(), &'static str> {
    for secure in [false, true] {
        let (mut session, _, _) = joined(secure)?;
        for (epoch, open, pn) in [
            (session.receive_epoch, false, 9),
            (session.receive_epoch - 1, true, 10),
        ] {
            session.backend.captured_packets.push_back(CapturedData {
                bytes: super::vht_tests::data(secure, 2, 7, 1, pn),
                epoch,
                port_open: open,
            });
            if session.receive_ethernet() != Ok(None) {
                return Err("closed or previous-owner native copy gained current admission");
            }
            session
                .backend
                .packets
                .push_back(super::vht_tests::data(secure, 2, 7, 1, pn));
            if session.receive_ethernet().ok().flatten().is_none() {
                return Err("rejected capture consumed PN before a fresh current copy");
            }
        }
        run(session.disassociate_station()).map_err(|_| "capture epoch retirement")?;
    }
    let (mut session, _, _) = joined(true)?;
    let old = session.receive_epoch;
    let old_copy = CapturedData {
        bytes: super::vht_tests::data(true, 2, 7, 1, 1),
        epoch: old,
        port_open: true,
    };
    replace_key(&mut session)?;
    if old == session.receive_epoch || session.receive_current(session.receive_epoch) != Ok(true) {
        return Err("capture replacement did not establish a distinct current receive owner");
    }
    session.backend.captured_packets.push_back(old_copy);
    session.backend.captured_packets.push_back(CapturedData {
        bytes: super::vht_tests::data(true, 2, 7, 1, 1),
        epoch: session.receive_epoch,
        port_open: false,
    });
    if session.receive_ethernet() != Ok(None) {
        return Err("retained old-key or closed-M4 copy inherited successor authorization");
    }
    session
        .backend
        .packets
        .push_back(super::vht_tests::data(true, 2, 7, 1, 1));
    if session.receive_ethernet().ok().flatten().is_none() {
        return Err("retained copies consumed successor PN1");
    }
    Ok(())
}
fn mt76_receive_capture_epoch_and_closed_port_cannot_inherit_rekey_authorization() -> TestResult {
    capture_admission().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/receive_epoch",
    mt76_receive_capture_epoch_and_closed_port_cannot_inherit_rekey_authorization
);

fn pending_message3() -> Result<(), &'static str> {
    let (mut session, _, _) = joined(true)?;
    challenge(&mut session)?;
    session.backend.access_point = None;
    session.backend.psk = [0x55; 32];
    session.backend.own_mac = OWN;
    session.backend.ap_mac = AP;
    session.backend.anonce = [0x55; 32];
    run(session.service_keys()).map_err(|_| "pending-M3 native M2 terminal")?;
    let epoch = session.receive_epoch;
    if session.receive_current(epoch) != Ok(false) || session.backend.receive_open {
        return Err("replacement M2 terminal reopened the receive controlled port before M3");
    }
    let mut ethernet = vec![0x77; 60];
    ethernet[..6].copy_from_slice(&AP);
    ethernet[6..12].copy_from_slice(&OWN);
    ethernet[12..14].copy_from_slice(&[8, 0]);
    if session.start_ethernet(&ethernet) != Err(Error::Busy) {
        return Err("replacement M2 terminal reopened ordinary TX before M3");
    }
    let m3 = session
        .backend
        .packets
        .pop_front()
        .ok_or("real replacement M3 missing")?;
    let mut frame = super::super::scan::rx_native_with_amsdu(&m3)
        .ok_or("replacement M3 native frame")?
        .frame
        .to_vec();
    frame[1] |= 0x40;
    let mut protected_m3 = vec![0; 40];
    protected_m3[..4].copy_from_slice(&((2u32 << 27) | (40 + frame.len()) as u32).to_le_bytes());
    protected_m3[4..8].copy_from_slice(&(1u32 | (4 << 16) | (1 << 11)).to_le_bytes());
    protected_m3[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes());
    protected_m3[12..16].copy_from_slice(&(36u32 << 8).to_le_bytes());
    protected_m3[24..30].copy_from_slice(&99u64.to_le_bytes()[..6]);
    protected_m3.extend_from_slice(&frame);
    // A descriptor captured with an earlier open port cannot bypass the
    // currently closed handshake even if its epoch happens to match.
    session.backend.captured_packets.push_back(CapturedData {
        bytes: super::vht_tests::data(true, 2, 7, 1, 99),
        epoch,
        port_open: true,
    });
    // Native CCMP may carry a valid EAPOL under the old installed PTK while
    // ordinary traffic is closed. Preserve its actual protected header and
    // the real authenticator M3 PDU/MIC; no plaintext fallback is granted.
    session.backend.captured_packets.push_back(CapturedData {
        bytes: protected_m3,
        epoch,
        port_open: false,
    });
    if session.receive_ethernet() != Ok(None) || !session.keys_pending() {
        return Err("pending-M3 data escaped or prevented real M3 service");
    }
    run(session.service_keys()).map_err(|_| "pending-M3 native M4/key terminals")?;
    if session.receive_current(session.receive_epoch) != Ok(true) || !session.backend.receive_open {
        return Err("actual M4/key terminals did not reopen their current port");
    }
    session
        .backend
        .packets
        .push_back(super::vht_tests::data(true, 2, 7, 1, 1));
    if session.receive_ethernet().ok().flatten().is_none() {
        return Err("pre-M3 ordinary data consumed the replacement key PN");
    }
    Ok(())
}
fn mt76_receive_and_tx_port_stay_closed_between_actual_replacement_m2_and_m3() -> TestResult {
    pending_message3().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/receive_epoch",
    mt76_receive_and_tx_port_stay_closed_between_actual_replacement_m2_and_m3
);

fn direct_receive_after_service() -> Result<(), &'static str> {
    for secure in [false, true] {
        for replace in [false, true] {
            let (mut session, bss, permission) = joined(secure)?;
            session
                .backend
                .packets
                .push_back(super::vht_tests::data(secure, 2, 7, 1, 9));
            let epoch = session.receive_epoch;
            let frame = session
                .receive_ethernet()
                .map_err(|_| "direct native receive")?
                .ok_or("direct native frame missing")?;
            let expected = frame.clone();
            let owner = RefCell::new(session);
            let yielded = Cell::new(false);
            let failure = Cell::new(None);
            let mut receive = pin!(finish_received_data(
                Some(frame),
                Some(epoch),
                async {
                    // Exercise the exact production post-extraction await seam,
                    // then drive genuine native key or association replacement.
                    core::future::poll_fn(|cx| {
                        if !yielded.replace(true) {
                            cx.waker().wake_by_ref();
                            core::task::Poll::Pending
                        } else {
                            core::task::Poll::Ready(())
                        }
                    })
                    .await;
                    if replace {
                        let mut session = owner.borrow_mut();
                        let result = if secure {
                            replace_key(&mut session)
                        } else {
                            run(session.disassociate_station())
                                .map_err(|_| "direct Open retirement")
                                .and_then(|()| {
                                    reset_open_peer(&mut session);
                                    run(session.associate_station(
                                        &bss,
                                        b"narf",
                                        Security::Open,
                                        permission,
                                        &[],
                                    ))
                                    .map(|_| ())
                                    .map_err(|_| "direct Open replacement")
                                })
                        };
                        if let Err(message) = result {
                            failure.set(Some(message));
                            return Err(Error::MalformedEvent);
                        }
                    }
                    Ok(())
                },
                |epoch| owner.borrow().receive_current(epoch)
            ));
            if receive
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return Err("direct receive published before deferred key service completed");
            }
            let result = run(receive);
            if let Some(message) = failure.get() {
                return Err(message);
            }
            if result != Ok(if replace { None } else { Some(expected) }) {
                return Err("direct receive did not retain its original owner across key service");
            }
            if replace {
                let mut session = owner.borrow_mut();
                session
                    .backend
                    .packets
                    .push_back(super::vht_tests::data(secure, 2, 7, 1, 1));
                if session.receive_ethernet().ok().flatten().is_none() {
                    return Err("stale direct return consumed successor receive PN");
                }
            }
        }
    }
    Ok(())
}
fn mt76_direct_receive_rechecks_native_owner_after_deferred_key_service() -> TestResult {
    direct_receive_after_service().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/receive_epoch",
    mt76_direct_receive_rechecks_native_owner_after_deferred_key_service
);

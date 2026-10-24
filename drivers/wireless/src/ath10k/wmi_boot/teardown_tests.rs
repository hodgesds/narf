// SPDX-License-Identifier: GPL-2.0-or-later
//! Native CE/HTC/WMI/HTT teardown composition, without radio emulation.
use super::*;
use narf_wireless::association::SecurityMode;
include!("../wmi_runtime/teardown/golden.rs");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    MissingUnmap,
    MissingAck,
    WrongAck,
    MalformedAck,
    MissingStop,
    WrongStop,
    MalformedStop,
    LateMap,
    Rebind,
}
#[derive(Debug)]
pub(super) struct Fixture {
    phase: u8,
    fault: Fault,
    sync: bool,
    ack_first: bool,
    fail: Option<u8>,
    progress: usize,
}

fn expected(dialect: Dialect, phase: u8) -> &'static [u8] {
    match (dialect, phase) {
        (Dialect::Main, 0) => DOWN_MAIN,
        (Dialect::Main, 1) => DELETE_MAIN,
        (Dialect::Main, 2) => STOP_MAIN,
        (Dialect::Main, _) => STOPPED_MAIN,
        (Dialect::TenOne, 0) => DOWN_10X,
        (Dialect::TenOne, 1) => DELETE_10X,
        (Dialect::TenOne, 2) => STOP_10X,
        (Dialect::TenOne, _) => STOPPED_10X,
        (Dialect::TenTwo | Dialect::TenTwoFour, 0) => DOWN_102,
        (Dialect::TenTwo | Dialect::TenTwoFour, 1) => DELETE_102,
        (Dialect::TenTwo | Dialect::TenTwoFour, 2) => STOP_102,
        (Dialect::TenTwo | Dialect::TenTwoFour, _) => STOPPED_102,
        (Dialect::TenFour, 0) => DOWN_104,
        (Dialect::TenFour, 1) => DELETE_104,
        (Dialect::TenFour, 2) => STOP_104,
        (Dialect::TenFour, _) => STOPPED_104,
        (Dialect::Tlv, 0) => DOWN_TLV,
        (Dialect::Tlv, 1) => DELETE_TLV,
        (Dialect::Tlv, 2) => STOP_TLV,
        (Dialect::Tlv, _) => STOPPED_TLV,
    }
}
fn event(model: &mut RadioModel, bytes: &[u8]) {
    add_event(
        model,
        u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        &bytes[4..],
    );
}
fn mapped(model: &mut RadioModel, id: u16, mac: [u8; 6]) {
    let mut body = vec![3, 0];
    body.extend_from_slice(&id.to_le_bytes());
    body.extend_from_slice(&mac);
    body.extend_from_slice(&[0; 2]);
    model
        .inner
        .inner
        .rx
        .push_back((model.inner.receive_pipe, header(1, &body)));
}
fn unmapped(model: &mut RadioModel, id: u16) {
    let mut body = vec![4, 0];
    body.extend_from_slice(&id.to_le_bytes());
    model
        .inner
        .inner
        .rx
        .push_back((model.inner.receive_pipe, header(1, &body)));
}
fn acknowledge(model: &mut RadioModel, fault: Fault) {
    if fault == Fault::MissingAck {
        return;
    }
    if fault == Fault::MalformedAck {
        event(model, &DELETE_RESPONSE_TLV[..DELETE_RESPONSE_TLV.len() - 1]);
        return;
    }
    // Neither another vdev nor another BSSID can confirm this peer's DELETE.
    let mut wrong = DELETE_RESPONSE_TLV.to_vec();
    u32at(&mut wrong, 8, 1);
    event(model, &wrong);
    let mut wrong = DELETE_RESPONSE_TLV.to_vec();
    wrong[12] = 4;
    event(model, &wrong);
    if fault != Fault::WrongAck {
        event(model, DELETE_RESPONSE_TLV);
    }
}
pub(super) async fn send(model: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let fixture = model.teardown.as_ref().unwrap();
    let (phase, fault, sync, ack_first, progress) = (
        fixture.phase,
        fixture.fault,
        fixture.sync,
        fixture.ack_first,
        fixture.progress,
    );
    let dialect = model.inner.inner.dialect;
    if phase > 2 || bytes[8..] != *expected(dialect, phase) {
        return Err(BmiError::BadResponse);
    }
    model.sent.push(bytes.to_vec());
    model.teardown.as_mut().unwrap().phase += 1;
    if model.teardown.as_ref().unwrap().fail == Some(phase) {
        return Err(BmiError::Pci);
    }
    // A command CE receipt only returns HTC credits. Actual firmware events
    // below travel over the native destination CE path independently.
    model.inner.inner.rx.push_back((
        2,
        vec![
            2,
            2,
            8,
            0,
            8,
            0,
            0,
            0,
            1,
            4,
            0,
            0,
            2,
            bytes.len().div_ceil(256) as u8,
            0,
            0,
        ],
    ));
    if phase == 1 {
        if fault == Fault::Rebind {
            mapped(model, 1900, [4, 8, 9, 10, 11, 12]);
        }
        if sync && ack_first {
            acknowledge(model, fault);
        }
        // A matching MAP still in flight during deletion becomes another
        // owned ID and must receive its own UNMAP before STOP is submitted.
        mapped(model, 1950, [2, 8, 9, 10, 11, 12]);
        unmapped(model, 1800);
        unmapped(model, 1800); // Duplicate cannot retire1900 or1950.
        unmapped(model, 1950);
        if fault != Fault::MissingUnmap {
            unmapped(model, 1900);
        }
        if sync && !ack_first {
            acknowledge(model, fault);
        }
        // A pre-STOP event cannot be replayed as the later STOP response.
        event(model, expected(dialect, 3));
        for _ in 0..progress {
            model.inner.inner.rx.push_back((2, header(2, &[])));
        }
    } else if phase == 2 {
        if fault == Fault::LateMap {
            mapped(model, 1800, [2, 8, 9, 10, 11, 12]);
        }
        if fault == Fault::MissingStop {
            return Ok(());
        }
        let stopped = expected(dialect, 3);
        if fault == Fault::MalformedStop {
            event(model, &stopped[..stopped.len() - 1]);
        } else {
            let mut wrong = stopped.to_vec();
            u32at(&mut wrong, if dialect == Dialect::Tlv { 8 } else { 4 }, 1);
            event(model, &wrong);
            if fault != Fault::WrongStop {
                event(model, stopped);
                event(model, stopped); // Duplicate is not a second stop proof.
            }
        }
    }
    Ok(())
}
fn prepared(
    version: u32,
    dialect: Dialect,
    hardware: HwRev,
    sync: bool,
) -> radio::Radio<RadioModel> {
    let mut radio = mlme_tests::prepared(version, dialect, true);
    assert!(matches!(
        drive(radio.associate_station(
            &station_tests::policy(),
            b"narf",
            SecurityMode::Wpa2Psk,
            &[]
        )),
        Poll::Ready(Ok(_))
    ));
    mapped(
        &mut radio.htt.wmi.htc.transport,
        1900,
        [2, 8, 9, 10, 11, 12],
    );
    assert!(matches!(
        drive(radio.poll_station()),
        Poll::Ready(Ok(htt::Event::Progress))
    ));
    if sync {
        let caps = radio.htt.wmi.caps.as_mut().unwrap();
        // This literal64-byte bitmap stores raw TLV service92 as the
        // extension's bit28 in word0, not an out-of-range original-map word.
        assert_eq!(SYNC_SERVICE, 92);
        assert_eq!(caps.bitmap.len(), 64);
        let previous = u32::from_le_bytes(caps.bitmap[..4].try_into().unwrap());
        u32at(&mut caps.bitmap, 0, previous | (1 << 28));
        assert!(caps.service(Dialect::Tlv, SYNC_SERVICE));
    }
    let model = &mut radio.htt.wmi.htc.transport;
    model.mlme = None;
    model.station = None;
    model.teardown = Some(Fixture {
        phase: 0,
        fault: Fault::None,
        sync,
        ack_first: false,
        fail: None,
        progress: 0,
    });
    model.ce = Some(crate::ath10k::boot::CeFixture::new(hardware));
    radio
}
fn closed(radio: &mut radio::Radio<RadioModel>) -> bool {
    let sent = radio.htt.wmi.htc.transport.ce.as_ref().unwrap().sent;
    radio.associated_station().is_none()
        && radio.prepared_peer().is_none()
        && drive(radio.disconnect_station()) == Poll::Ready(Err(radio::Error::Failed))
        && matches!(
            drive(radio.passive_scan(&[2412])),
            Poll::Ready(Err(radio::Error::Failed))
        )
        && radio.htt.wmi.htc.transport.ce.as_ref().unwrap().sent == sent
        && radio.htt.wmi.htc.transport.ce.as_ref().unwrap().retained()
        && radio.htt.wmi.htc.transport.inner.storage.is_some()
}

fn smoke_ath10k_disconnect_native_commands_events_and_sparse_ids_all_dialects() -> TestResult {
    for (version, dialect, hardware) in [
        (1, Dialect::Main, HwRev::Qca988x),
        (2, Dialect::TenOne, HwRev::Qca988x),
        (3, Dialect::TenTwo, HwRev::Qca988x),
        (4, Dialect::Tlv, HwRev::Qca6174),
        (5, Dialect::TenTwoFour, HwRev::Qca988x),
        (6, Dialect::TenFour, HwRev::Qca9984),
    ] {
        for sync in [false, true] {
            if sync && dialect != Dialect::Tlv {
                continue;
            }
            for ack_first in [false, true] {
                let mut radio = prepared(version, dialect, hardware, sync);
                radio
                    .htt
                    .wmi
                    .htc
                    .transport
                    .teardown
                    .as_mut()
                    .unwrap()
                    .ack_first = ack_first;
                let receipt = radio::StationDisconnected {
                    bssid: [2, 8, 9, 10, 11, 12],
                    frequency: 2412,
                    synchronous_delete: sync,
                };
                if drive(radio.disconnect_station()) != Poll::Ready(Ok(receipt))
                    || radio.htt.wmi.htc.transport.teardown.as_ref().unwrap().phase != 3
                    || radio.htt.wmi.htc.transport.ce.as_ref().unwrap().sent != 3
                    || radio.htt.wmi.htc.transport.ce.as_ref().unwrap().received < 7
                    || !closed(&mut radio)
                {
                    return TestResult::Fail("native DOWN/DELETE/all UNMAP/conditional ACK/STOP/STOPPED retirement failed");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_disconnect_native_commands_events_and_sparse_ids_all_dialects
);

fn smoke_ath10k_disconnect_missing_or_foreign_receipts_never_retire() -> TestResult {
    for fault in [
        Fault::MissingUnmap,
        Fault::MissingAck,
        Fault::WrongAck,
        Fault::MissingStop,
        Fault::WrongStop,
    ] {
        let mut radio = prepared(4, Dialect::Tlv, HwRev::Qca6174, true);
        radio.htt.wmi.htc.transport.teardown.as_mut().unwrap().fault = fault;
        if drive(radio.disconnect_station()) != Poll::Pending || !closed(&mut radio) {
            return TestResult::Fail(
                "missing/foreign firmware receipt retired or reopened peer resources",
            );
        }
        let commands = radio.htt.wmi.htc.transport.teardown.as_ref().unwrap().phase;
        if commands
            != if matches!(fault, Fault::MissingStop | Fault::WrongStop) {
                3
            } else {
                2
            }
        {
            return TestResult::Fail("STOP was submitted before complete peer retirement");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_disconnect_missing_or_foreign_receipts_never_retire
);

fn smoke_ath10k_disconnect_malformed_rebind_or_late_map_stays_closed() -> TestResult {
    for fault in [
        Fault::MalformedAck,
        Fault::MalformedStop,
        Fault::LateMap,
        Fault::Rebind,
    ] {
        let mut radio = prepared(4, Dialect::Tlv, HwRev::Qca6174, true);
        radio.htt.wmi.htc.transport.teardown.as_mut().unwrap().fault = fault;
        if drive(radio.disconnect_station()) != Poll::Ready(Err(radio::Error::Malformed))
            || !closed(&mut radio)
        {
            return TestResult::Fail(
                "malformed teardown or peer identity rebound did not retain a closed native owner",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_disconnect_malformed_rebind_or_late_map_stays_closed
);

fn smoke_ath10k_disconnect_stale_prerequest_ack_and_stop_do_not_complete() -> TestResult {
    for fault in [Fault::MissingAck, Fault::MissingStop] {
        let mut radio = prepared(4, Dialect::Tlv, HwRev::Qca6174, true);
        let model = &mut radio.htt.wmi.htc.transport;
        model.teardown.as_mut().unwrap().fault = fault;
        event(model, DELETE_RESPONSE_TLV);
        event(model, STOPPED_TLV);
        if drive(radio.disconnect_station()) != Poll::Pending || !closed(&mut radio) {
            return TestResult::Fail(
                "stale event received before command satisfied native teardown",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_disconnect_stale_prerequest_ack_and_stop_do_not_complete
);

fn smoke_ath10k_disconnect_cancel_or_send_error_retains_native_dma() -> TestResult {
    for (version, dialect, hardware) in [
        (1, Dialect::Main, HwRev::Qca988x),
        (4, Dialect::Tlv, HwRev::Qca6174),
    ] {
        for phase in 0..3 {
            for fail in [false, true] {
                let mut radio = prepared(version, dialect, hardware, dialect == Dialect::Tlv);
                let model = &mut radio.htt.wmi.htc.transport;
                if fail {
                    model.teardown.as_mut().unwrap().fail = Some(phase);
                } else {
                    model.ce.as_mut().unwrap().stall = Some(phase as usize);
                }
                let result = drive(radio.disconnect_station());
                if (fail && !matches!(result, Poll::Ready(Err(_))))
                    || (!fail && result != Poll::Pending)
                    || !closed(&mut radio)
                {
                    return TestResult::Fail(
                        "cancelled or failed teardown command allowed ownership replay/release",
                    );
                }
                if radio.htt.wmi.htc.transport.ce.as_ref().unwrap().sent != phase as usize + 1 {
                    return TestResult::Fail(
                        "teardown failure did not stop at the exact native publication",
                    );
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_disconnect_cancel_or_send_error_retains_native_dma
);

fn smoke_ath10k_disconnect_progress_flood_yields_and_cancel_stays_closed() -> TestResult {
    use alloc::{sync::Arc, task::Wake};
    use core::sync::atomic::{AtomicUsize, Ordering};
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let mut radio = prepared(4, Dialect::Tlv, HwRev::Qca6174, true);
    radio
        .htt
        .wmi
        .htc
        .transport
        .teardown
        .as_mut()
        .unwrap()
        .progress = 8192;
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    {
        let mut future = core::pin::pin!(radio.disconnect_station());
        let mut cx = Context::from_waker(&waker);
        for _ in 0..64 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return TestResult::Fail(
                    "credit-only teardown flood escaped cooperative bounded progression",
                );
            }
        }
    }
    let model = &radio.htt.wmi.htc.transport;
    if counter.0.load(Ordering::Relaxed) < 64
        || model.teardown.as_ref().unwrap().phase != 2
        || model.inner.inner.rx.len() < 8000
        || !closed(&mut radio)
    {
        return TestResult::Fail(
            "cancelled teardown progress flood lost wakeups, DMA or closed peer state",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_disconnect_progress_flood_yields_and_cancel_stays_closed
);

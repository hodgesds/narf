use super::*;
use narf_wireless::association::SecurityMode;
include!("../wmi_runtime/mlme/golden.rs");

#[derive(Debug)]
pub(super) struct Fixture {
    phase: u8,
    protected: bool,
    stall: Option<u8>,
    bad_assoc: bool,
    unmap: bool,
    final_progress: usize,
    fail: Option<u8>,
    downgrade: bool,
}
fn expected(phase: u8, dialect: Dialect, protected: bool, downgrade: bool) -> &'static [u8] {
    if phase == 2 && downgrade {
        return match dialect {
            Dialect::Main => DOWNGRADE_MAIN,
            Dialect::TenOne => DOWNGRADE_10X,
            Dialect::TenTwo | Dialect::TenTwoFour => DOWNGRADE_102,
            Dialect::TenFour => DOWNGRADE_104,
            Dialect::Tlv => DOWNGRADE_TLV,
        };
    }
    match (phase, dialect, protected) {
        (0, Dialect::Main, _) => AUTH_MAIN,
        (0, Dialect::TenOne, _) => AUTH_10X,
        (0, Dialect::TenTwo | Dialect::TenTwoFour, _) => AUTH_102,
        (0, Dialect::TenFour, _) => AUTH_104,
        (0, Dialect::Tlv, _) => AUTH_TLV,
        (1, Dialect::Main, false) => AIR_OPEN_MAIN,
        (1, Dialect::TenOne, false) => AIR_OPEN_10X,
        (1, Dialect::TenTwo | Dialect::TenTwoFour, false) => AIR_OPEN_102,
        (1, Dialect::TenFour, false) => AIR_OPEN_104,
        (1, Dialect::Tlv, false) => AIR_OPEN_TLV,
        (1, Dialect::Main, true) => AIR_SEC_MAIN,
        (1, Dialect::TenOne, true) => AIR_SEC_10X,
        (1, Dialect::TenTwo | Dialect::TenTwoFour, true) => AIR_SEC_102,
        (1, Dialect::TenFour, true) => AIR_SEC_104,
        (1, Dialect::Tlv, true) => AIR_SEC_TLV,
        (2, Dialect::Main, false) => OPEN_MAIN,
        (2, Dialect::TenOne, false) => OPEN_10X,
        (2, Dialect::TenTwo | Dialect::TenTwoFour, false) => OPEN_102,
        (2, Dialect::TenFour, false) => OPEN_104,
        (2, Dialect::Tlv, false) => OPEN_TLV,
        (2, Dialect::Main, true) => SEC_MAIN,
        (2, Dialect::TenOne, true) => SEC_10X,
        (2, Dialect::TenTwo | Dialect::TenTwoFour, true) => SEC_102,
        (2, Dialect::TenFour, true) => SEC_104,
        (2, Dialect::Tlv, true) => SEC_TLV,
        (3, Dialect::Main, _) => UP_MAIN,
        (3, Dialect::TenOne, _) => UP_10X,
        (3, Dialect::TenTwo | Dialect::TenTwoFour, _) => UP_102,
        (3, Dialect::TenFour, _) => UP_104,
        (3, Dialect::Tlv, _) => UP_TLV,
        _ => panic!("unexpected MLME fixture phase"),
    }
}
pub(super) async fn send(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let fixture = m.mlme.as_ref().unwrap();
    let phase = fixture.phase;
    let protected = fixture.protected;
    let bad_assoc = fixture.bad_assoc;
    let unmap = fixture.unmap;
    let dialect = m.inner.inner.dialect;
    if phase >= 4 || bytes[8..] != *expected(phase, dialect, protected, fixture.downgrade) {
        return Err(BmiError::BadResponse);
    }
    if phase < 2 {
        let command = &bytes[8..];
        let word = |at: usize| u32::from_le_bytes(command[at..at + 4].try_into().unwrap());
        let frame = if dialect == Dialect::Tlv {
            // Linux's referenced command contains at most64 prefetch bytes.
            // The full72-byte WPA2 association lives in retained DMA, not
            // after that prefix. Consume it before its real WMI completion.
            let length = word(28) as usize;
            let (address, payload) = m
                .management_memory
                .as_ref()
                .ok_or(BmiError::BadResponse)?
                .snapshot(word(12))
                .ok_or(BmiError::BadResponse)?;
            let prefix = length.min(64).next_multiple_of(4);
            if address != u64::from(word(20)) | (u64::from(word(24)) << 32)
                || word(32) as usize != prefix
                || command.len() != 40 + prefix
                || command.get(40..40 + length.min(64)) != payload.get(..length.min(64))
            {
                return Err(BmiError::BadResponse);
            }
            payload.get(..length).ok_or(BmiError::BadResponse)?.to_vec()
        } else {
            command
                .get(28..28 + word(24) as usize)
                .ok_or(BmiError::BadResponse)?
                .to_vec()
        };
        m.native_management.push(frame);
    }
    m.sent.push(bytes.to_vec());
    m.mlme.as_mut().unwrap().phase += 1;
    if m.mlme.as_ref().unwrap().fail == Some(phase) {
        return Err(BmiError::Pci);
    }
    if m.mlme.as_ref().unwrap().stall == Some(phase) {
        core::future::pending::<()>().await;
    }
    m.inner.inner.rx.push_back((
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
    if phase < 2 {
        if dialect == Dialect::Tlv {
            let mut terminal = vec![16, 0, 0xa7, 1];
            terminal.extend_from_slice(&u32::from(phase).to_le_bytes());
            terminal.extend_from_slice(&[0; 12]);
            add_event(m, 0x7006, &terminal);
        }
        let mut response = vec![0; 30];
        response[0] = if phase == 0 { 0xb0 } else { 0x10 };
        response[4..10].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
        response[10..16].copy_from_slice(&[2, 8, 9, 10, 11, 12]);
        response[16..22].copy_from_slice(&[2, 8, 9, 10, 11, 12]);
        if phase == 0 {
            response[26] = 2;
        } else {
            let capability = if protected ^ bad_assoc {
                0x431u16
            } else {
                0x421
            };
            response[24..26].copy_from_slice(&capability.to_le_bytes());
            response[28..30].copy_from_slice(&0xc007u16.to_le_bytes());
            response.extend_from_slice(&[1, 8, 0x82, 0x84, 0x8b, 0x96, 12, 18, 24, 36]);
            response.extend_from_slice(if m.mlme.as_ref().unwrap().downgrade {
                &[50, 3, 48, 72, 96]
            } else {
                &[50, 4, 48, 72, 96, 108]
            });
        }
        let mut head = vec![
            0;
            if dialect == Dialect::Tlv {
                40
            } else if dialect == Dialect::TenFour {
                28
            } else {
                24
            }
        ];
        u32at(&mut head, 0, 1);
        u32at(&mut head, 4, 31);
        u32at(
            &mut head,
            16 + usize::from(dialect == Dialect::TenFour) * 4,
            response.len() as u32,
        );
        let body = if dialect == Dialect::Tlv {
            let mut b = Vec::new();
            item(&mut b, 44, &head);
            item(&mut b, 17, &response);
            b
        } else {
            head.extend_from_slice(&response);
            head
        };
        add_event(
            m,
            match dialect {
                Dialect::Main | Dialect::Tlv => 0x7001,
                Dialect::TenOne => 0x900c,
                _ => 0x900b,
            },
            &body,
        );
    } else if phase == 3 {
        for _ in 0..m.mlme.as_ref().unwrap().final_progress {
            m.inner.inner.rx.push_back((2, header(2, &[])));
        }
        if unmap {
            m.inner
                .inner
                .rx
                .push_back((m.inner.receive_pipe, header(1, &[4, 0, 8, 7]))); // peer1800
        }
    }
    Ok(())
}
pub(super) fn prepared(
    version: u32,
    dialect: Dialect,
    protected: bool,
) -> radio::Radio<RadioModel> {
    prepared_profile(version, dialect, protected, false)
}
pub(super) fn prepared_profile(
    version: u32,
    dialect: Dialect,
    protected: bool,
    raw: bool,
) -> radio::Radio<RadioModel> {
    let features = (1 << 2)
        | if dialect == Dialect::Tlv { 1 << 18 } else { 0 }
        | if raw { 1 << 10 } else { 0 };
    let mut r = radio_boot_features(version, dialect, features);
    r.htt.wmi.htc.transport.mlme_beacon = Some(protected);
    assert!(matches!(drive(r.start(&[2412, 5180])), Poll::Ready(Ok(_))));
    assert!(matches!(
        drive(r.passive_scan(&[2412, 5180])),
        Poll::Ready(Ok(_))
    ));
    r.htt.wmi.htc.transport.station = Some(StationFixture::new());
    assert!(matches!(
        drive(r.prepare_station(&station_tests::policy(), [2, 8, 9, 10, 11, 12], 2412)),
        Poll::Ready(Ok(_))
    ));
    r.htt.wmi.htc.transport.mlme = Some(Fixture {
        phase: 0,
        protected,
        stall: None,
        bad_assoc: false,
        unmap: false,
        final_progress: 0,
        fail: None,
        downgrade: false,
    });
    r
}
fn smoke_ath10k_join_plan_auth_assoc_peer_assoc_and_vdev_up_all_native_dialects() -> TestResult {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        for protected in [false, true] {
            let mut r = prepared(version, dialect, protected);
            let mode = if protected {
                SecurityMode::Wpa2Psk
            } else {
                SecurityMode::Open
            };
            let expected = radio::StationAssociated {
                bssid: [2, 8, 9, 10, 11, 12],
                frequency: 2412,
                aid: 7,
                protected,
            };
            if drive(r.associate_station(&station_tests::policy(), b"narf", mode, &[]))
                != Poll::Ready(Ok(expected))
                || r.associated_station() != Some(expected)
                || r.htt.wmi.htc.transport.mlme.as_ref().unwrap().phase != 4
                || r.htt
                    .wmi
                    .htc
                    .transport
                    .management_memory
                    .as_ref()
                    .is_some_and(|p| p.pending() != 0)
                || !matches!(
                    drive(r.associate_station(&station_tests::policy(), b"narf", mode, &[])),
                    Poll::Ready(Err(radio::Error::Failed))
                )
            {
                return TestResult::Fail("actual JoinPlan/air RX/PEER_ASSOC/VDEV_UP chain failed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_join_plan_auth_assoc_peer_assoc_and_vdev_up_all_native_dialects
);

fn smoke_ath10k_assoc_response_rate_downgrade_reaches_native_peer_all_dialects() -> TestResult {
    for (version, dialect, hardware) in [
        (1, Dialect::Main, HwRev::Qca988x),
        (2, Dialect::TenOne, HwRev::Qca988x),
        (3, Dialect::TenTwo, HwRev::Qca988x),
        (4, Dialect::Tlv, HwRev::Qca6174),
        (5, Dialect::TenTwoFour, HwRev::Qca988x),
        (6, Dialect::TenFour, HwRev::Qca9984),
    ] {
        let mut r = prepared(version, dialect, false);
        r.htt.wmi.htc.transport.mlme.as_mut().unwrap().downgrade = true;
        r.htt.wmi.htc.transport.ce = Some(crate::ath10k::boot::CeFixture::new(hardware));
        if !matches!(
            drive(r.associate_station(&station_tests::policy(), b"narf", SecurityMode::Open, &[])),
            Poll::Ready(Ok(_))
        ) {
            return TestResult::Fail(
                "native PEER_ASSOC did not use the literal AP response's eleven-rate intersection",
            );
        }
        let transport = &r.htt.wmi.htc.transport;
        let actual = &transport.sent[transport.sent.len() - 2][8..];
        if actual != expected(2, dialect, false, true)
            || actual == expected(2, dialect, false, false)
            || transport.ce.as_ref().unwrap().sent != 4
        {
            return TestResult::Fail(
                "AP rate downgrade bypassed exact Linux PEER_ASSOC or native CE publication",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_assoc_response_rate_downgrade_reaches_native_peer_all_dialects
);

fn smoke_ath10k_join_plan_rejects_policy_or_sme_before_new_publication() -> TestResult {
    let mut r = prepared(4, Dialect::Tlv, false);
    let domain = station_tests::policy();
    let initial = r.htt.wmi.htc.transport.sent.len();
    for (ssid, ies) in [
        (b"wrong".as_slice(), &[][..]),
        (b"narf".as_slice(), &[48, 0][..]),
    ] {
        if !matches!(
            drive(r.associate_station(&domain, ssid, SecurityMode::Open, ies)),
            Poll::Ready(Err(_))
        ) || r.htt.wmi.htc.transport.sent.len() != initial
            || r.htt.wmi.htc.transport.management_memory.is_some()
            || r.associated_station().is_some()
        {
            return TestResult::Fail("invalid shared JoinPlan input published management or state");
        }
    }
    let mut changed = station_tests::policy();
    changed.rules[0].max_power_dbm = 1;
    if drive(r.associate_station(&changed, b"narf", SecurityMode::Open, &[]))
        != Poll::Ready(Err(radio::Error::Unsupported))
        || r.htt.wmi.htc.transport.sent.len() != initial
        || r.htt.wmi.htc.transport.management_memory.is_some()
    {
        return TestResult::Fail("changed channel/power policy published authentication");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_join_plan_rejects_policy_or_sme_before_new_publication
);

fn smoke_ath10k_join_rejection_unmap_or_cancel_never_reopens_peer() -> TestResult {
    for case in 0..4 {
        let mut r = prepared(4, Dialect::Tlv, true);
        let fixture = r.htt.wmi.htc.transport.mlme.as_mut().unwrap();
        fixture.bad_assoc = case == 0;
        fixture.unmap = case == 1;
        fixture.stall = if case >= 2 { Some(case) } else { None };
        let domain = station_tests::policy();
        if case < 2 {
            if !matches!(
                drive(r.associate_station(&domain, b"narf", SecurityMode::Wpa2Psk, &[])),
                Poll::Ready(Err(_))
            ) {
                return TestResult::Fail(
                    "invalid association or peer unmap reported configured station",
                );
            }
        } else if drive(r.associate_station(&domain, b"narf", SecurityMode::Wpa2Psk, &[]))
            != Poll::Pending
        {
            return TestResult::Fail("native command cancellation never reached a pending waiter");
        }
        let transport = &r.htt.wmi.htc.transport;
        let phase = transport.mlme.as_ref().unwrap().phase;
        if phase
            != if case == 0 {
                2
            } else if case == 2 {
                3
            } else {
                4
            }
            || transport.inner.storage.is_none()
            || r.associated_station().is_some()
            || r.prepared_peer().is_some()
        {
            return TestResult::Fail(
                "failed/dropped association lost ownership or advertised a peer",
            );
        }
        let sent = transport.sent.len();
        if drive(r.associate_station(&domain, b"narf", SecurityMode::Wpa2Psk, &[]))
            != Poll::Ready(Err(radio::Error::Failed))
            || r.htt.wmi.htc.transport.sent.len() != sent
        {
            return TestResult::Fail("failed/dropped MLME allowed new command publication");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_join_rejection_unmap_or_cancel_never_reopens_peer
);

fn smoke_ath10k_join_native_ce_dma_htc_wmi_composition_all_dialects() -> TestResult {
    for (version, dialect, hardware) in [
        (1, Dialect::Main, HwRev::Qca988x),
        (2, Dialect::TenOne, HwRev::Qca988x),
        (3, Dialect::TenTwo, HwRev::Qca988x),
        (4, Dialect::Tlv, HwRev::Qca6174),
        (5, Dialect::TenTwoFour, HwRev::Qca988x),
        (6, Dialect::TenFour, HwRev::Qca9984),
    ] {
        let mut r = prepared(version, dialect, true);
        r.htt.wmi.htc.transport.ce = Some(crate::ath10k::boot::CeFixture::new(hardware));
        if !matches!(
            drive(r.associate_station(
                &station_tests::policy(),
                b"narf",
                SecurityMode::Wpa2Psk,
                &[]
            )),
            Poll::Ready(Ok(_))
        ) {
            return TestResult::Fail(
                "actual CE descriptors/HTC/WMI association composition failed",
            );
        }
        let ce = r.htt.wmi.htc.transport.ce.as_ref().unwrap();
        if ce.sent != 4 || ce.received < 6 || !ce.retained() || r.associated_station().is_none() {
            return TestResult::Fail(
                "composed association bypassed retained native CE transfer/repost",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_join_native_ce_dma_htc_wmi_composition_all_dialects
);

fn smoke_ath10k_join_native_ce_cancel_after_peer_or_up_publication() -> TestResult {
    for (version, dialect, hardware) in [
        (1, Dialect::Main, HwRev::Qca988x),
        (4, Dialect::Tlv, HwRev::Qca6174),
    ] {
        for stall in [2, 3] {
            let mut r = prepared(version, dialect, true);
            let mut ce = crate::ath10k::boot::CeFixture::new(hardware);
            ce.stall = Some(stall);
            r.htt.wmi.htc.transport.ce = Some(ce);
            let policy = station_tests::policy();
            if drive(r.associate_station(&policy, b"narf", SecurityMode::Wpa2Psk, &[]))
                != Poll::Pending
            {
                return TestResult::Fail(
                    "native CE cancellation did not reach published descriptor",
                );
            }
            let transport = &r.htt.wmi.htc.transport;
            let ce = transport.ce.as_ref().unwrap();
            if ce.sent != stall + 1
                || !ce.retained()
                || transport.mlme.as_ref().unwrap().phase as usize != stall
                || transport.inner.storage.is_none()
                || r.associated_station().is_some()
                || r.prepared_peer().is_some()
            {
                return TestResult::Fail(
                    "cancelled native CE command lost owner or advertised association",
                );
            }
            let sent = ce.sent;
            if drive(r.associate_station(&policy, b"narf", SecurityMode::Wpa2Psk, &[]))
                != Poll::Ready(Err(radio::Error::Failed))
                || r.htt.wmi.htc.transport.ce.as_ref().unwrap().sent != sent
            {
                return TestResult::Fail("cancelled native CE command permitted DMA reuse");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_join_native_ce_cancel_after_peer_or_up_publication
);

fn smoke_ath10k_join_post_up_credit_flood_yields_and_cancel_keeps_peer_closed() -> TestResult {
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
    let mut r = prepared(4, Dialect::Tlv, true);
    let fixture = r.htt.wmi.htc.transport.mlme.as_mut().unwrap();
    fixture.final_progress = 64;
    fixture.unmap = true;
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    let policy = station_tests::policy();
    {
        let mut future =
            core::pin::pin!(r.associate_station(&policy, b"narf", SecurityMode::Wpa2Psk, &[]));
        for _ in 0..16 {
            if future.as_mut().poll(&mut cx) != Poll::Pending {
                return TestResult::Fail(
                    "credit-only input claimed quiescence or monopolized poll",
                );
            }
        }
    }
    let transport = &r.htt.wmi.htc.transport;
    if counter.0.load(Ordering::Relaxed) < 16
        || transport.mlme.as_ref().unwrap().phase != 4
        || transport.inner.storage.is_none()
        || r.associated_station().is_some()
        || r.prepared_peer().is_some()
    {
        return TestResult::Fail("cancelled post-UP drain lost owner, wake or closed peer state");
    }
    let sent = transport.sent.len();
    if drive(r.associate_station(&policy, b"narf", SecurityMode::Wpa2Psk, &[]))
        != Poll::Ready(Err(radio::Error::Failed))
        || r.htt.wmi.htc.transport.sent.len() != sent
    {
        return TestResult::Fail("cancelled post-UP drain published another command");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_join_post_up_credit_flood_yields_and_cancel_keeps_peer_closed
);

fn smoke_ath10k_join_native_peer_or_up_send_error_retains_owner() -> TestResult {
    for fail in [2, 3] {
        let mut r = prepared(4, Dialect::Tlv, true);
        r.htt.wmi.htc.transport.mlme.as_mut().unwrap().fail = Some(fail);
        let policy = station_tests::policy();
        if !matches!(
            drive(r.associate_station(&policy, b"narf", SecurityMode::Wpa2Psk, &[])),
            Poll::Ready(Err(_))
        ) || r.htt.wmi.htc.transport.inner.storage.is_none()
            || r.associated_station().is_some()
            || r.prepared_peer().is_some()
        {
            return TestResult::Fail("failed peer/UP command discarded ownership or reopened peer");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_join_native_peer_or_up_send_error_retains_owner
);

fn smoke_ath10k_last_peer_unmap_then_remap_does_not_revive_association() -> TestResult {
    let mut r = prepared(4, Dialect::Tlv, false);
    if !matches!(
        drive(r.associate_station(&station_tests::policy(), b"narf", SecurityMode::Open, &[])),
        Poll::Ready(Ok(_))
    ) {
        return TestResult::Fail("peer-unmap fixture did not associate");
    }
    for body in [
        vec![4, 0, 8, 7],
        vec![3, 0, 8, 7, 2, 8, 9, 10, 11, 12, 0, 0],
    ] {
        let p = r.htt.wmi.htc.transport.inner.receive_pipe;
        r.htt
            .wmi
            .htc
            .transport
            .inner
            .inner
            .rx
            .push_back((p, header(1, &body)));
        if !matches!(drive(r.poll_station()), Poll::Ready(Ok(_)))
            || r.associated_station().is_some()
        {
            return TestResult::Fail("last peer UNMAP or later MAP revived stale AP association");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_last_peer_unmap_then_remap_does_not_revive_association
);

use super::*;
include!("../wmi_runtime/management_golden.rs");
#[derive(Debug)]
pub(super) struct ManagementFixture {
    expected: Vec<u8>,
    stall: bool,
    terminal: bool,
    response: bool,
}
pub(super) async fn management_send(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let fixture = m.management.as_ref().unwrap();
    if bytes[8..] != fixture.expected {
        return Err(BmiError::BadResponse);
    }
    let reference = m.inner.inner.dialect == Dialect::Tlv;
    if reference && m.management_memory.as_ref().unwrap().pending() != 1 {
        return Err(BmiError::BadResponse);
    }
    m.sent.push(bytes.to_vec());
    if fixture.stall {
        core::future::pending::<()>().await;
    }
    let terminal = fixture.terminal;
    let response = fixture.response;
    // Only the CE/HTC command receipt returns a WMI credit. This must never
    // retire the independently referenced management payload.
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
    if reference && terminal {
        // Literal single-completion TLV: descriptor0, status0, pdev/PPDU0.
        add_event(
            m,
            0x7006,
            &[
                16, 0, 0xa7, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        );
    }
    if response {
        let request = m.sent.last().unwrap();
        let offset = if reference { 48 } else { 36 }; // HTC8 + command frame offset40/28.
        let mut f = [
            0xb0, 0, 0, 0, 2, 3, 4, 5, 6, 7, 2, 8, 9, 10, 11, 12, 2, 8, 9, 10, 11, 12, 0, 0, 0, 0,
            2, 0, 0, 0,
        ];
        if request[offset] == 0 {
            f[0] = 0x10;
            f[24] = 1;
            f[26] = 0;
            f[28] = 1;
            f[29] = 0xc0;
        }
        let tlv = m.inner.inner.dialect == Dialect::Tlv;
        let tenfour = m.inner.inner.dialect == Dialect::TenFour;
        let mut head = vec![
            0;
            if tlv {
                40
            } else if tenfour {
                28
            } else {
                24
            }
        ];
        u32at(&mut head, 0, 1);
        u32at(&mut head, 4, 31);
        u32at(&mut head, 16 + usize::from(tenfour) * 4, 30);
        let body = if tlv {
            let mut body = Vec::new();
            item(&mut body, 44, &head);
            item(&mut body, 17, &f);
            body
        } else {
            head.extend_from_slice(&f);
            head
        };
        let id = match m.inner.inner.dialect {
            Dialect::Main | Dialect::Tlv => 0x7001,
            Dialect::TenOne => 0x900c,
            _ => 0x900b,
        };
        let mut wrong_recipient = body.clone();
        wrong_recipient[if tlv {
            52
        } else if tenfour {
            32
        } else {
            28
        }] ^= 2;
        add_event(m, id, &wrong_recipient);
        add_event(m, id, &body);
    }
    Ok(())
}
fn auth() -> [u8; 30] {
    [
        0xb0, 0, 0, 0, 2, 8, 9, 10, 11, 12, 2, 3, 4, 5, 6, 7, 2, 8, 9, 10, 11, 12, 0, 0, 0, 0, 1,
        0, 0, 0,
    ]
}
fn prepared(version: u32, dialect: Dialect, features: u64) -> radio::Radio<RadioModel> {
    prepared_major(version, dialect, features, 3)
}
fn prepared_major(
    version: u32,
    dialect: Dialect,
    features: u64,
    major: u8,
) -> radio::Radio<RadioModel> {
    let mut r = radio_boot_options(version, dialect, features, major);
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
    r
}
fn smoke_ath10k_initial_management_dispatch_over_retained_native_runtime() -> TestResult {
    for (version, dialect, expected) in [
        (1, Dialect::Main, AUTH_MAIN),
        (2, Dialect::TenOne, AUTH_10X),
        (3, Dialect::TenTwo, AUTH_102),
        (5, Dialect::TenTwoFour, AUTH_102),
        (6, Dialect::TenFour, AUTH_104),
        (4, Dialect::Tlv, AUTH_TLV),
    ] {
        let reference = dialect == Dialect::Tlv;
        let features = (1 << 2) | if reference { 1 << 18 } else { 0 };
        let mut r = prepared(version, dialect, features);
        r.htt.wmi.htc.transport.management = Some(ManagementFixture {
            expected: expected.to_vec(),
            stall: false,
            terminal: true,
            response: false,
        });
        let receipt = match drive(r.transmit_management(&station_tests::policy(), &auth())) {
            Poll::Ready(Ok(receipt)) => receipt,
            _ => return TestResult::Fail("prepared station failed actual WMI management path"),
        };
        if receipt.terminal_expected != reference
            || receipt.token
                != if reference {
                    radio::ManagementToken::Wmi(0)
                } else {
                    radio::ManagementToken::Inline
                }
        {
            return TestResult::Fail(
                "inline submission fabricated terminal ACK or reference lost ID",
            );
        }
        if reference {
            if r.htt
                .wmi
                .htc
                .transport
                .management_memory
                .as_ref()
                .unwrap()
                .pending()
                != 1
            {
                return TestResult::Fail("CE receipt freed referenced WMI DMA");
            }
            for _ in 0..4 {
                if !matches!(drive(r.poll_station()), Poll::Ready(Ok(_))) {
                    return TestResult::Fail("WMI terminal event did not progress");
                }
            }
            if r.take_management_completion()
                != Some(radio::ManagementCompletion { id: 0, status: 0 })
                || r.htt
                    .wmi
                    .htc
                    .transport
                    .management_memory
                    .as_ref()
                    .unwrap()
                    .pending()
                    != 0
            {
                return TestResult::Fail("WMI terminal failed exact payload retirement");
            }
        }
        if r.prepared_peer().is_none() {
            return TestResult::Fail("valid management transport detached prepared peer");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_initial_management_dispatch_over_retained_native_runtime
);
fn smoke_ath10k_referenced_management_cancellation_retains_and_closes_owner() -> TestResult {
    let mut r = prepared(4, Dialect::Tlv, (1 << 2) | (1 << 18));
    r.htt.wmi.htc.transport.management = Some(ManagementFixture {
        expected: AUTH_TLV.to_vec(),
        stall: true,
        terminal: false,
        response: false,
    });
    if once(r.transmit_management(&station_tests::policy(), &auth())) != Poll::Pending {
        return TestResult::Fail("reference cancellation fixture did not reach actual publication");
    }
    let sent = r.htt.wmi.htc.transport.sent.len();
    if r.htt
        .wmi
        .htc
        .transport
        .management_memory
        .as_ref()
        .unwrap()
        .pending()
        != 1
        || !matches!(
            drive(r.transmit_management(&station_tests::policy(), &auth())),
            Poll::Ready(Err(radio::Error::Failed))
        )
        || r.htt.wmi.htc.transport.sent.len() != sent
    {
        return TestResult::Fail(
            "cancelled management owner freed DMA or permitted new publication",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_referenced_management_cancellation_retains_and_closes_owner
);

pub(super) async fn management_htt_send(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let fixture = m.management.as_ref().unwrap();
    if bytes.len() < 8
        || bytes[0] != 1
        || bytes[1] != 0
        || bytes[5] != m.inner.sequence
        || bytes[2..4] != (bytes.len() as u16 - 8).to_le_bytes()
        || m.inner.storage.as_ref().unwrap().tx.pending() != 1
    {
        return Err(BmiError::BadResponse);
    }
    m.inner.sequence = m.inner.sequence.wrapping_add(1);
    // Linux htt_tx.c packed layouts, DMA0x800000/ID0/vdev0/extTID17;
    // all auth bytes and padding literal, independently of the encoder.
    let expected = if m.inner.version >= 3 {
        vec![
            1, 0x65, 0x40, 0x0c, 30, 0, 0, 0, 0, 0, 0x80, 0, 0xff, 0xff, 0, 0, 0xb0, 0, 0, 0, 2, 8,
            9, 10, 11, 12, 2, 3, 4, 5, 6, 7, 2, 8, 9, 10, 11, 12, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        ]
    } else {
        vec![
            7, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0xb0, 0, 0, 0, 2, 8, 9,
            10, 11, 12, 2, 3, 4, 5, 6, 7, 2, 8, 9, 10, 11, 12, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
        ]
    };
    if bytes[8..] != expected {
        return Err(BmiError::BadResponse);
    }
    m.sent.push(bytes.to_vec());
    if fixture.stall {
        core::future::pending::<()>().await;
    }
    if fixture.terminal {
        let terminal = if m.inner.version >= 3 {
            vec![7, 0, 1, 0, 0, 0, 0, 0]
        } else {
            vec![0xe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        };
        m.inner
            .inner
            .rx
            .push_back((m.inner.receive_pipe, header(1, &terminal)));
    }
    Ok(())
}
fn smoke_ath10k_initial_management_htt2_and_htt3_dispatch_and_terminal() -> TestResult {
    for major in [2, 3] {
        let mut r = prepared_major(4, Dialect::Tlv, 0, major);
        r.htt.wmi.htc.transport.management = Some(ManagementFixture {
            expected: Vec::new(),
            stall: false,
            terminal: true,
            response: false,
        });
        if drive(r.transmit_management(&station_tests::policy(), &auth()))
            != Poll::Ready(Ok(radio::ManagementReceipt {
                token: radio::ManagementToken::Htt(0),
                terminal_expected: true,
            }))
        {
            return TestResult::Fail("runtime did not choose actual HTT2/3 management transport");
        }
        if r.htt
            .wmi
            .htc
            .transport
            .inner
            .storage
            .as_ref()
            .unwrap()
            .tx
            .pending()
            != 1
        {
            return TestResult::Fail("CE receipt released HTT management payload");
        }
        let mut terminal = false;
        for _ in 0..4 {
            match drive(r.poll_station()) {
                Poll::Ready(Ok(htt::Event::Tx(0))) => terminal = true,
                Poll::Ready(Ok(_)) => {}
                _ => return TestResult::Fail("HTT management terminal could not progress"),
            }
        }
        if !terminal
            || r.htt
                .wmi
                .htc
                .transport
                .inner
                .storage
                .as_ref()
                .unwrap()
                .tx
                .pending()
                != 0
        {
            return TestResult::Fail("HTT management payload not retired by terminal event");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_initial_management_htt2_and_htt3_dispatch_and_terminal
);

fn smoke_ath10k_native_initial_auth_assoc_response_progress_without_data_admission() -> TestResult {
    let mut r = prepared(4, Dialect::Tlv, (1 << 2) | (1 << 18));
    r.htt.wmi.htc.transport.management = Some(ManagementFixture {
        expected: AUTH_TLV.to_vec(),
        stall: false,
        terminal: true,
        response: true,
    });
    let auth_reply = match drive(r.exchange_initial_management(&station_tests::policy(), &auth())) {
        Poll::Ready(Ok(f)) => f,
        _ => {
            return TestResult::Fail(
                "native Open authentication failed real command/completion/RX path",
            )
        }
    };
    if auth_reply[24..30] != [0, 0, 2, 0, 0, 0] || auth_reply[4..10] != [2, 3, 4, 5, 6, 7] {
        return TestResult::Fail("wrong peer authentication body");
    }
    let mut assoc = vec![0; 101];
    assoc[..24].copy_from_slice(&auth()[..24]);
    assoc[0] = 0;
    assoc[24] = 1;
    assoc[26] = 10;
    assoc[29] = 4;
    assoc[30..34].copy_from_slice(b"narf");
    assoc[34..40].copy_from_slice(&[1, 4, 0x82, 0x84, 0x8b, 0x96]);
    assoc[40..42].copy_from_slice(&[221, 59]);
    for (i, b) in assoc.iter_mut().enumerate().skip(42) {
        *b = (i * 5) as u8;
    }
    let mut expected = ASSOC_TLV.to_vec();
    u32at(&mut expected, 12, 1);
    u32at(&mut expected, 20, 0x901000);
    r.htt.wmi.htc.transport.management = Some(ManagementFixture {
        expected,
        stall: false,
        terminal: false,
        response: true,
    });
    let response = match drive(r.exchange_initial_management(&station_tests::policy(), &assoc)) {
        Poll::Ready(Ok(f)) => f,
        _ => return TestResult::Fail("native association response failed retained WMI/CE path"),
    };
    if response[0] != 0x10
        || response[26..30] != [0, 0, 1, 0xc0]
        || r.htt
            .wmi
            .htc
            .transport
            .management_memory
            .as_ref()
            .unwrap()
            .pending()
            != 1
        || !matches!(
            drive(r.exchange_initial_management(&station_tests::policy(), &assoc)),
            Poll::Ready(Err(radio::Error::Unsupported))
        )
    {
        return TestResult::Fail(
            "response manufactured DMA completion or reopened one-shot MLME phase",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_native_initial_auth_assoc_response_progress_without_data_admission
);

fn smoke_ath10k_initial_management_rejects_unbound_frames_and_policy_before_dma() -> TestResult {
    let mut r = prepared(4, Dialect::Tlv, (1 << 2) | (1 << 18));
    r.htt.wmi.htc.transport.management = Some(ManagementFixture {
        expected: AUTH_TLV.to_vec(),
        stall: false,
        terminal: false,
        response: false,
    });
    let sent = r.htt.wmi.htc.transport.sent.len();
    for (at, mask) in [
        (1, 0x40),
        (4, 2),
        (10, 2),
        (16, 2),
        (22, 1),
        (24, 1),
        (26, 3),
    ] {
        let mut bad = auth();
        bad[at] ^= mask;
        if !matches!(
            drive(r.transmit_management(&station_tests::policy(), &bad)),
            Poll::Ready(Err(radio::Error::Malformed | radio::Error::Unsupported))
        ) {
            return TestResult::Fail("unbound or protected/fragmented initial management accepted");
        }
    }
    let mut lower = station_tests::policy();
    lower.rules[0].max_power_dbm = 16;
    if drive(r.transmit_management(&lower, &auth())) != Poll::Ready(Err(radio::Error::Unsupported))
        || r.htt.wmi.htc.transport.sent.len() != sent
        || r.htt.wmi.htc.transport.management_memory.is_some()
        || r.prepared_peer().is_none()
    {
        return TestResult::Fail(
            "changed policy or bad management caused DMA publication/state loss",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_initial_management_rejects_unbound_frames_and_policy_before_dma
);
fn smoke_ath10k_malformed_wmi_management_terminal_retains_native_owner() -> TestResult {
    let mut r = prepared(4, Dialect::Tlv, (1 << 2) | (1 << 18));
    r.htt.wmi.htc.transport.management = Some(ManagementFixture {
        expected: AUTH_TLV.to_vec(),
        stall: false,
        terminal: false,
        response: false,
    });
    if !matches!(
        drive(r.transmit_management(&station_tests::policy(), &auth())),
        Poll::Ready(Ok(_))
    ) {
        return TestResult::Fail("reference setup");
    }
    let m = &mut r.htt.wmi.htc.transport;
    add_event(
        m,
        0x7006,
        &[
            16, 0, 0xa7, 1, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    let mut bad = false;
    for _ in 0..4 {
        if matches!(
            drive(r.poll_station()),
            Poll::Ready(Err(radio::Error::Htt(htt::Error::Malformed)))
        ) {
            bad = true;
            break;
        }
    }
    if !bad
        || !matches!(
            drive(r.poll_station()),
            Poll::Ready(Err(radio::Error::Failed))
        )
        || r.htt
            .wmi
            .htc
            .transport
            .management_memory
            .as_ref()
            .unwrap()
            .pending()
            != 1
    {
        return TestResult::Fail("invalid terminal freed payload or reopened native owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_malformed_wmi_management_terminal_retains_native_owner
);
fn smoke_ath10k_cancelled_initial_response_wait_keeps_reference_owned() -> TestResult {
    let mut r = prepared(4, Dialect::Tlv, (1 << 2) | (1 << 18));
    r.htt.wmi.htc.transport.management = Some(ManagementFixture {
        expected: AUTH_TLV.to_vec(),
        stall: false,
        terminal: false,
        response: false,
    });
    if once(r.exchange_initial_management(&station_tests::policy(), &auth())) != Poll::Pending {
        return TestResult::Fail("response wait did not yield after real submission");
    }
    let sent = r.htt.wmi.htc.transport.sent.len();
    if !matches!(
        drive(r.exchange_initial_management(&station_tests::policy(), &auth())),
        Poll::Ready(Err(radio::Error::Failed))
    ) || r.htt.wmi.htc.transport.sent.len() != sent
        || r.htt
            .wmi
            .htc
            .transport
            .management_memory
            .as_ref()
            .unwrap()
            .pending()
            != 1
    {
        return TestResult::Fail("cancelled peer response wait freed DMA or retried auth");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_cancelled_initial_response_wait_keeps_reference_owned
);

fn smoke_ath10k_management_service76_selects_reference_and_incompatible_dialects_stay_closed(
) -> TestResult {
    let mut r = prepared(4, Dialect::Tlv, 1 << 18);
    // Independent C enum: TLV MGMT_TX_WMI=76; after the first64 bitmap
    // byte-indexed services it is extended word0/bit12, not service-number76
    // directly in a conventional 32-bit bitmap.
    r.htt.wmi.caps.as_mut().unwrap().bitmap[1] |= 0x10;
    r.htt.wmi.htc.transport.management = Some(ManagementFixture {
        expected: AUTH_TLV.to_vec(),
        stall: false,
        terminal: false,
        response: false,
    });
    if drive(r.transmit_management(&station_tests::policy(), &auth()))
        != Poll::Ready(Ok(radio::ManagementReceipt {
            token: radio::ManagementToken::Wmi(0),
            terminal_expected: true,
        }))
    {
        return TestResult::Fail("native raw service76 did not select referenced WMI management");
    }
    for (version, dialect, features) in [
        (4, Dialect::Tlv, 1 << 2),
        (1, Dialect::Main, (1 << 2) | (1 << 18)),
    ] {
        let mut r = prepared(version, dialect, features);
        let before = r.htt.wmi.htc.transport.sent.len();
        if drive(r.transmit_management(&station_tests::policy(), &auth()))
            != Poll::Ready(Err(radio::Error::Unsupported))
            || r.htt.wmi.htc.transport.sent.len() != before
            || r.htt.wmi.htc.transport.management_memory.is_some()
        {
            return TestResult::Fail(
                "incompatible management generator advertised a fake supported path",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_management_service76_selects_reference_and_incompatible_dialects_stay_closed
);

fn smoke_ath10k_initial_exchange_rx_flood_yields_and_cancel_retains() -> TestResult {
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
    let mut r = prepared(4, Dialect::Tlv, (1 << 2) | (1 << 18));
    r.htt.wmi.htc.transport.management = Some(ManagementFixture {
        expected: AUTH_TLV.to_vec(),
        stall: false,
        terminal: false,
        response: false,
    });
    r.htt.wmi.htc.transport.mismatch_rx = true;
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    {
        let domain = station_tests::policy();
        let request = auth();
        let mut future = core::pin::pin!(r.exchange_initial_management(&domain, &request));
        for _ in 0..8 {
            if future.as_mut().poll(&mut cx) != Poll::Pending {
                return TestResult::Fail(
                    "continuous wrong-recipient RX completed instead of cooperatively yielding",
                );
            }
        }
    }
    let model = &r.htt.wmi.htc.transport;
    if counter.0.load(Ordering::Relaxed) < 8
        || model.mismatched == 0
        || model.mismatched > 8
        || model.management_memory.as_ref().unwrap().pending() != 1
    {
        return TestResult::Fail(
            "native RX flood monopolized one poll or lost retained management DMA",
        );
    }
    let publications = model.sent.len();
    if !matches!(
        drive(r.exchange_initial_management(&station_tests::policy(), &auth())),
        Poll::Ready(Err(radio::Error::Failed))
    ) || r.htt.wmi.htc.transport.sent.len() != publications
    {
        return TestResult::Fail("cancelled flood wait reopened initial management publication");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_initial_exchange_rx_flood_yields_and_cancel_retains
);

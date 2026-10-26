use super::*;
include!("../wmi_runtime/station_wire_golden.rs");
#[derive(Debug)]
pub(super) struct StationFixture {
    pub phase: u8,
    pub stall: Option<u8>,
    pub status: u32,
    pub bad_map: bool,
    pub wrong_start: usize,
}
impl StationFixture {
    pub(super) fn new() -> Self {
        Self {
            phase: 0,
            stall: None,
            status: 0,
            bad_map: false,
            wrong_start: 1,
        }
    }
}
pub(super) async fn station_send(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let fixture = m.station.as_ref().unwrap();
    let phase = fixture.phase;
    let dialect = m.inner.inner.dialect;
    let mut expected = match (phase, dialect) {
        (0, Dialect::Main) => RD_MAIN,
        (0, Dialect::Tlv) => RD_TLV,
        (0, Dialect::TenFour) => RD_104,
        (0, _) => RD_10X,
        (1, Dialect::Main) => POWER_MAIN,
        (1, Dialect::Tlv) => POWER_TLV,
        (1, Dialect::TenFour) => POWER_104,
        (1, _) => POWER_10X,
        (2, Dialect::Main) => START_MAIN,
        (2, Dialect::Tlv) => START_TLV,
        (2, Dialect::TenFour) => START_104,
        (2, Dialect::TenOne) => START_10X,
        (2, _) => START_102,
        (3, Dialect::Main) => PEER_MAIN,
        (3, Dialect::Tlv) => PEER_TLV,
        (3, Dialect::TenFour) => PEER_104,
        (3, Dialect::TenOne) => PEER_10X,
        (3, _) => PEER_102,
        _ => return Err(BmiError::BadResponse),
    }
    .to_vec();
    if m.frequency > 3000 {
        // Independent source facts for the fixed US factory5GHz profile.
        // Retain the full reviewed packet and replace only authored fields.
        let at = if dialect == Dialect::Tlv { 12 } else { 4 };
        match phase {
            0 => {
                for (i, value) in [0x3a, 0x3a, 0x3a, 0x10, 0x10].into_iter().enumerate() {
                    u32at(&mut expected, at + i * 4, value);
                }
            }
            1 => {
                u32at(&mut expected, at, 4);
                u32at(&mut expected, at + 4, 54);
            }
            2 => {
                let chan = if dialect == Dialect::Tlv { 84 } else { 4 };
                u32at(&mut expected, chan, u32::from(m.frequency));
                u32at(&mut expected, chan + 4, u32::from(m.frequency));
                u32at(&mut expected, chan + 12, 0);
                for offset in [17, 18, 21] {
                    expected[chan + offset] = 54;
                }
            }
            _ => {}
        }
    }
    if bytes[8..] != expected {
        return Err(BmiError::BadResponse);
    }
    m.sent.push(bytes.to_vec());
    m.station.as_mut().unwrap().phase += 1;
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
    if m.station.as_ref().unwrap().stall == Some(phase) {
        core::future::pending::<()>().await;
    }
    if phase == 2 {
        let status = m.station.as_ref().unwrap().status;
        for vdev in core::iter::repeat_n(1u32, m.station.as_ref().unwrap().wrong_start)
            .chain(core::iter::once(0))
        {
            let mut body = Vec::new();
            for v in [vdev, 0, 0, status] {
                body.extend_from_slice(&v.to_le_bytes());
            }
            let id = match m.inner.inner.dialect {
                Dialect::Main | Dialect::Tlv => 0x5001,
                Dialect::TenOne => 0x9005,
                _ => 0x9004,
            };
            if m.inner.inner.dialect == Dialect::Tlv {
                let mut tagged = Vec::new();
                item(&mut tagged, 40, &body);
                body = tagged;
            }
            add_event(m, id, &body);
        }
    } else if phase == 3 {
        // Firmware IDs are sparse and need not be below resource peer count.
        let id = if m.station.as_ref().unwrap().bad_map {
            2048u16
        } else {
            1800u16
        };
        for vdev in [1u8, 0] {
            let mut body = vec![3, vdev];
            body.extend_from_slice(&id.to_le_bytes());
            body.extend_from_slice(&[2, 8, 9, 10, 11, 12, 0, 0]);
            m.inner
                .inner
                .rx
                .push_back((m.inner.receive_pipe, header(1, &body)));
        }
    }
    Ok(())
}
pub(super) fn policy() -> narf_wireless::reg::RegulatoryDomain {
    narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }
}
fn scanned(version: u32, dialect: Dialect) -> radio::Radio<RadioModel> {
    let mut r = radio_boot(version, dialect);
    assert!(matches!(drive(r.start(&[2412, 5180])), Poll::Ready(Ok(_))));
    assert!(matches!(
        drive(r.passive_scan(&[2412, 5180])),
        Poll::Ready(Ok(_))
    ));
    r.htt.wmi.htc.transport.station = Some(StationFixture::new());
    r
}
fn smoke_ath10k_scan_policy_vdev_ack_peer_map_composed_all_dialects() -> TestResult {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        let mut r = scanned(version, dialect);
        let domain = policy();
        let tx = htt::tx::Parameters {
            kind: htt::tx::Kind::Ethernet,
            vdev: 0,
            tid: 16,
            hardware_crypto: false,
        };
        if drive(
            r.htt
                .transmit(tx, &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 8, 0]),
        ) != Poll::Ready(Ok(0))
        {
            return TestResult::Fail(
                "station fixture failed to retain preexisting HTT payload owner",
            );
        }
        let expected = radio::PeerPrepared {
            bssid: [2, 8, 9, 10, 11, 12],
            frequency: 2412,
            peer_id: 1800,
            maximum_power_dbm: 17,
        };
        if drive(r.prepare_station(&domain, expected.bssid, 2412)) != Poll::Ready(Ok(expected))
            || r.prepared_peer() != Some(expected)
            || r.htt.wmi.htc.transport.station.as_ref().unwrap().phase != 4
        {
            return TestResult::Fail(
                "real scan/policy/native vdev ACK/sparse HTT peer-map chain failed",
            );
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
            != 0
            || !matches!(r.take_event(), Some(htt::Event::Tx(0)))
        {
            return TestResult::Fail("station preparation starved terminal HTT DMA retirement");
        }
        let sent = r.htt.wmi.htc.transport.sent.len();
        if !matches!(
            drive(r.passive_scan(&[2412])),
            Poll::Ready(Err(radio::Error::Failed))
        ) || drive(r.prepare_station(&domain, expected.bssid, 2412))
            != Poll::Ready(Err(radio::Error::Failed))
            || r.htt.wmi.htc.transport.sent.len() != sent
        {
            return TestResult::Fail("prepared station restarted/scanned over a live vdev owner");
        }
        // One Linux peer may own multiple IDs. Keep every mapping until its
        // own unmap; an unknown/stale unmap must not clear another ID.
        for body in [
            vec![3, 0, 0x54, 7, 2, 8, 9, 10, 11, 12, 0, 0],
            vec![4, 0, 8, 7],
            vec![4, 0, 9, 7],
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
        }
        for _ in 0..8 {
            if !matches!(drive(r.poll_station()), Poll::Ready(Ok(_))) {
                return TestResult::Fail("retained peer event owner failed after mapped startup");
            }
        }
        if r.prepared_peer().map(|p| p.peer_id) != Some(1876) {
            return TestResult::Fail(
                "sparse multi-ID/unmap ownership replaced another peer mapping",
            );
        }
        let p = r.htt.wmi.htc.transport.inner.receive_pipe;
        r.htt
            .wmi
            .htc
            .transport
            .inner
            .inner
            .rx
            .push_back((p, header(1, &[4, 0, 0x54, 7])));
        for _ in 0..2 {
            let _ = drive(r.poll_station());
        }
        if r.prepared_peer().is_some() {
            return TestResult::Fail("last peer unmap retained a prepared peer");
        }
        // Rebinding a still-owned sparse ID to a different MAC cannot
        // silently redirect the future station's firmware context.
        let p = r.htt.wmi.htc.transport.inner.receive_pipe;
        for mac in [[2, 8, 9, 10, 11, 12], [2, 8, 9, 10, 11, 13]] {
            let mut b = vec![3, 0, 8, 7];
            b.extend_from_slice(&mac);
            b.extend_from_slice(&[0, 0]);
            r.htt
                .wmi
                .htc
                .transport
                .inner
                .inner
                .rx
                .push_back((p, header(1, &b)));
        }
        if !matches!(drive(r.poll_station()), Poll::Ready(Ok(_)))
            || !matches!(
                drive(r.poll_station()),
                Poll::Ready(Err(radio::Error::Malformed))
            )
            || r.prepared_peer().is_some()
        {
            return TestResult::Fail(
                "owned peer ID was rebound to another MAC without closing context",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_scan_policy_vdev_ack_peer_map_composed_all_dialects
);
fn smoke_ath10k_station_policy_and_cached_bss_precede_publication() -> TestResult {
    let mut r = scanned(1, Dialect::Main);
    let original = r.htt.wmi.htc.transport.sent.len();
    let mut domain = policy();
    for case in 0..6 {
        let (peer, frequency) = match case {
            0 => ([2, 8, 9, 10, 11, 13], 2412),
            1 => ([2, 8, 9, 10, 11, 12], 5180),
            _ => ([2, 8, 9, 10, 11, 12], 2412),
        };
        match case {
            2 => domain.country_code = *b"00",
            3 => {
                domain.country_code = *b"US";
                domain.rules[0].flags = narf_wireless::reg::RegFlags::DFS;
            }
            4 => {
                domain.rules[0].flags = narf_wireless::reg::RegFlags::empty();
                domain.rules[0].freq_start_mhz = 2403;
            }
            5 => {
                domain = policy();
                domain.rules.push(narf_wireless::reg::RegRule {
                    freq_start_mhz: 2410,
                    freq_end_mhz: 2420,
                    max_bandwidth_mhz: 20,
                    max_power_dbm: 17,
                    flags: narf_wireless::reg::RegFlags::NO_IR,
                });
            }
            _ => {}
        }
        if !matches!(
            drive(r.prepare_station(&domain, peer, frequency)),
            Poll::Ready(Err(_))
        ) || r.htt.wmi.htc.transport.sent.len() != original
        {
            return TestResult::Fail(
                "unobserved BSS or unsupported policy published station context",
            );
        }
    }
    domain = policy();
    if !matches!(
        drive(r.prepare_station(&domain, [2, 8, 9, 10, 11, 12], 2412)),
        Poll::Ready(Ok(_))
    ) {
        return TestResult::Fail(
            "prepublication policy rejection consumed untouched station owner",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_station_policy_and_cached_bss_precede_publication
);
fn smoke_ath10k_station_failed_ack_or_map_keeps_owner_closed() -> TestResult {
    for bad_map in [false, true] {
        let mut r = scanned(1, Dialect::Main);
        let domain = policy();
        r.htt.wmi.htc.transport.station.as_mut().unwrap().bad_map = bad_map;
        r.htt.wmi.htc.transport.station.as_mut().unwrap().status = if bad_map { 0 } else { 2 };
        if !matches!(
            drive(r.prepare_station(&domain, [2, 8, 9, 10, 11, 12], 2412)),
            Poll::Ready(Err(_))
        ) || r.prepared_peer().is_some()
        {
            return TestResult::Fail(
                "failed native vdev status or invalid peer ID admitted prepared state",
            );
        }
        let sent = r.htt.wmi.htc.transport.sent.len();
        if drive(r.prepare_station(&domain, [2, 8, 9, 10, 11, 12], 2412))
            != Poll::Ready(Err(radio::Error::Failed))
            || !matches!(
                drive(r.passive_scan(&[2412])),
                Poll::Ready(Err(radio::Error::Failed))
            )
            || r.htt.wmi.htc.transport.sent.len() != sent
            || r.htt.wmi.htc.transport.inner.storage.is_none()
        {
            return TestResult::Fail(
                "ambiguous station failure reused command owner or dropped packet DMA",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_station_failed_ack_or_map_keeps_owner_closed
);
fn smoke_ath10k_station_cancel_after_actual_start_retains_owner() -> TestResult {
    let mut r = scanned(1, Dialect::Main);
    let domain = policy();
    r.htt.wmi.htc.transport.station.as_mut().unwrap().stall = Some(2);
    {
        let mut operation =
            core::pin::pin!(r.prepare_station(&domain, [2, 8, 9, 10, 11, 12], 2412));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            if operation.as_mut().poll(&mut cx).is_ready() {
                return TestResult::Fail("stalled native START unexpectedly completed");
            }
        }
    }
    let transport = &r.htt.wmi.htc.transport;
    if transport.station.as_ref().unwrap().phase != 3
        || transport.inner.storage.is_none()
        || r.prepared_peer().is_some()
    {
        return TestResult::Fail("cancel fixture never published START or lost retained owner");
    }
    let sent = transport.sent.len();
    if drive(r.prepare_station(&domain, [2, 8, 9, 10, 11, 12], 2412))
        != Poll::Ready(Err(radio::Error::Failed))
        || r.htt.wmi.htc.transport.sent.len() != sent
    {
        return TestResult::Fail("dropped START transaction permitted command or buffer reuse");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_station_cancel_after_actual_start_retains_owner
);

fn smoke_ath10k_station_policy_power_and_overlapping_restrictions() -> TestResult {
    use crate::ath10k::regulatory::Permission;
    let r = radio_boot(1, Dialect::Main);
    let caps = r.htt.wmi.caps.as_ref().unwrap();
    let mut domain = policy();
    domain.rules[0].max_power_dbm = 60;
    if !Permission::from_domain(caps, &domain, 2412).is_ok_and(|p| p.half_dbm == 40) {
        return TestResult::Fail("host ceiling bypassed strict initial factory-world power");
    }
    let mut narrow = domain.rules[0].clone();
    narrow.freq_start_mhz = 2407;
    narrow.freq_end_mhz = 2417;
    narrow.max_power_dbm = 9;
    domain.rules.push(narrow);
    if !Permission::from_domain(caps, &domain, 2412).is_ok_and(|p| p.half_dbm == 18) {
        return TestResult::Fail("overlapping lower power was ignored");
    }
    use narf_wireless::reg::RegFlags;
    for flags in [
        RegFlags::DFS,
        RegFlags::NO_IR,
        RegFlags::INDOOR_ONLY,
        RegFlags::from_bits_retain(1 << 31),
    ] {
        domain.rules[1].flags = flags;
        if Permission::from_domain(caps, &domain, 2412).is_ok() {
            return TestResult::Fail("overlapping permissive rule erased a TX restriction");
        }
    }
    domain.rules[1].flags = RegFlags::NO_P2P;
    if !Permission::from_domain(caps, &domain, 2412).is_ok_and(|p| p.half_dbm == 18) {
        return TestResult::Fail("P2P-only restriction incorrectly denied bounded station TX");
    }
    domain = policy();
    domain.rules[0].max_power_dbm = -1;
    if Permission::from_domain(caps, &domain, 2412).is_ok() {
        return TestResult::Fail("negative host power ceiling rounded upward");
    }
    for frequency in [2413, 2467, 2484, 5180, 5955] {
        if Permission::from_domain(caps, &policy(), frequency).is_ok() {
            return TestResult::Fail(
                "initial station profile inferred channel/beacon-hint/DFS/6GHz authority",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory",
    smoke_ath10k_station_policy_power_and_overlapping_restrictions
);

fn smoke_ath10k_station_start_flood_yields_and_cancel_keeps_owner() -> TestResult {
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
    for (version, dialect) in [(1, Dialect::Main), (4, Dialect::Tlv)] {
        let mut r = scanned(version, dialect);
        r.htt
            .wmi
            .htc
            .transport
            .station
            .as_mut()
            .unwrap()
            .wrong_start = 32;
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let domain = policy();
        {
            let mut future =
                core::pin::pin!(r.prepare_station(&domain, [2, 8, 9, 10, 11, 12], 2412));
            for _ in 0..8 {
                if future.as_mut().poll(&mut cx) != Poll::Pending {
                    return TestResult::Fail("wrong-vdev START flood monopolized one poll");
                }
            }
        }
        let transport = &r.htt.wmi.htc.transport;
        if counter.0.load(Ordering::Relaxed) < 8
            || transport.station.as_ref().unwrap().phase != 3
            || transport.inner.storage.is_none()
            || r.prepared_peer().is_some()
        {
            return TestResult::Fail("START flood did not self-wake or lost retained owner");
        }
        let sent = transport.sent.len();
        if drive(r.prepare_station(&domain, [2, 8, 9, 10, 11, 12], 2412))
            != Poll::Ready(Err(radio::Error::Failed))
            || r.htt.wmi.htc.transport.sent.len() != sent
        {
            return TestResult::Fail("cancelled START flood permitted further publication");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_station_start_flood_yields_and_cancel_keeps_owner
);

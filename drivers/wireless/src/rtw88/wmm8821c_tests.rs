//! Actual retained C21 reserved-page/IQK/TXAGC/awake owner through separately
//! qualified legacy12/QoS. All measured numbers here belong to inert fixtures.
use super::*;
use crate::rtw88::station_profile::{Request, Source};
use core::sync::atomic::AtomicBool;
const RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
fn parameters(be: u8) -> Vec<u8> {
    vec![
        221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x85, 0, be, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 94,
        0, 0x62, 0x32, 47, 0,
    ]
}
fn record(r: &Request, rates: u16, wmm: bool) -> Vec<u8> {
    let mut b = vec![0; 128];
    b[..4].copy_from_slice(b"N21L");
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x21, 0xc8]);
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..56].copy_from_slice(&[1, 20]);
    for (at, v) in [(56, 4i16), (58, 76), (60, 48), (62, 48)] {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    for i in 0..12 {
        b[64 + i * 2..66 + i * 2].copy_from_slice(&(40i16 + i as i16).to_le_bytes());
    }
    b[88..90].copy_from_slice(&rates.to_le_bytes());
    b[90] = u8::from(wmm);
    b
}
fn source(bytes: Vec<u8>, cap: Cap<FirmwareBlob, Read>, db: Arc<Database>) -> Source {
    Source::Verified {
        bytes,
        signer: Some([10; 32]),
        cap,
        policy: db,
    }
}
struct Extended {
    h: Harness,
    cap: Cap<FirmwareBlob, Read>,
}
fn setup(
    protected: bool,
    wmm: bool,
    qualified: bool,
    response: Option<&[u8]>,
) -> Result<Extended, &'static str> {
    let h = Harness::new(protected)?;
    let mut peer = Peer::new(protected);
    peer.ap = peer
        .ap
        .with_legacy_rates(&RATES)
        .map_err(|_| "C21 richer AP rates invalid")?;
    peer.wmm = wmm.then(|| parameters(3));
    peer.response_rates = response.map(|r| r.to_vec());
    let mut beacon = peer.ap.beacon();
    if let Some(p) = &peer.wmm {
        beacon.extend_from_slice(p);
    }
    *h.peer.lock() = peer;
    h.port.0.lock().packet_model.receive(&beacon, false, false);
    if wmm {
        h.peer.lock().response_wmm = Some(Some(parameters(4)));
    }
    let cap = Cap::bootstrap();
    if qualified {
        let request = complete(h.lifecycle.legacy_wmm_request())?
            .map_err(|_| "C21 N21L request missing actual retained N21S")?;
        if !request.filename.contains("rtw8821ce-legacy-wmm-v1-") {
            return Err("C21 request reused C22 measurement profile");
        }
        h.port
            .qualify_extension(source(record(&request, 0xfff, true), cap, h.db.clone()))
            .map_err(|_| "C21 distinct synthetic N21L qualification failed")?;
    }
    Ok(Extended { h, cap })
}
fn check(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    f().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn smoke_rtw8821ce_n21l_exact_asset_retry_and_legacy_fallback() -> TestResult {
    check(|| {
        let h = Harness::new(true)?;
        let r = complete(h.lifecycle.legacy_wmm_request())?
            .map_err(|_| "C21 optional profile metadata absent")?;
        let baseline = h.port.0.lock().calls;
        for fault in 0..9 {
            let cap = Cap::bootstrap();
            let mut bytes = record(&r, 0xfff, true);
            match fault {
                0 => bytes[..4].copy_from_slice(b"N22L"),
                1 => bytes[14] = 0x22,
                2 => bytes[16] ^= 1,
                3 => bytes[48] ^= 1,
                4 => {
                    bytes.pop();
                }
                5 => bytes[91] = 1,
                6 => bytes[64..66].copy_from_slice(&80i16.to_le_bytes()),
                7 => cap.revoke(),
                _ => (),
            }
            let mut src = source(bytes, cap, h.db.clone());
            if let (8, Source::Verified { signer, .. }) = (fault, &mut src) {
                *signer = None;
            }
            if h.port.qualify_extension(src).is_ok()
                || h.port.0.lock().calls != baseline
                || h.device.closed()
            {
                return Err("bad N21L wrote native state or consumed retryable legacy owner");
            }
        }
        drop(h);
        let e = setup(true, true, false, None)?;
        e.h.join()?;
        let lease = narf_net::dhcp::dhcp_acquire(e.h.device.name(), 0)
            .map_err(|_| "C21 unqualified-WMM legacy DHCP failed")?;
        let d =
            e.h.port
                .0
                .lock()
                .packet_model
                .last_descriptor
                .ok_or("C21 fallback native descriptor absent")?;
        if e.h.peer.lock().qos
            || !e.h.peer.lock().plan.matches_lease(&lease)
            || d[16] != 0
            || d[6] != 8
        {
            return Err("N21S alone admitted QoS or higher DATA power");
        }
        Ok(())
    })
}
fn composition(protected: bool, wmm: bool, narrow: bool) -> Result<(), &'static str> {
    let e = setup(protected, wmm, true, narrow.then_some(&[0x82, 48][..]))?;
    let (firmware_dma, packet_dma, doorbells) = {
        let m = e.h.port.0.lock();
        let bytes = m.frame.lock().bytes.clone();
        (bytes, m.packet_model.payload_identity(), m.doorbells)
    };
    e.h.join()?;
    let mask = if narrow { 0x101u16 } else { 0xfff };
    {
        let m = e.h.port.0.lock();
        if !m
            .mailboxes
            .contains(&[0x40, 0, 0x26, 0x40, mask as u8, (mask >> 8) as u8, 0, 0])
            || word(&m.bytes, 0x440) != if narrow { 0x5f } else { 0x15f }
            || [0x1d00, 0x1d04, 0x1d08].map(|r| word(&m.bytes, r))
                != [0x0b0a0908, 0x0f0e0d0c, 0x13121110]
            || m.doorbells != doorbells
            || m.frame.lock().bytes != firmware_dma
            || m.packet_model.payload_identity() != packet_dma
        {
            return Err("C21 response-bound RA/RRSR/TXAGC changed original firmware/DMA owner");
        }
        let edca = if wmm {
            [0xa55a, 0xa496, 0x005e4332, 0x002f3232]
        } else {
            [0xa532; 4]
        };
        if [0x508, 0x50c, 0x504, 0x500].map(|r| word(&m.bytes, r)) != edca {
            return Err("C21 native EDCA used beacon or C22-only power/control state");
        }
    }
    let plan = e.h.peer.lock().plan;
    let lease = narf_net::dhcp::dhcp_acquire(e.h.device.name(), 0)
        .map_err(|_| "C21 N21L real kernel DHCP DORA failed")?;
    if !plan.matches_lease(&lease) || e.h.peer.lock().qos != wmm {
        return Err("C21 N21L DHCP/negotiated QoS facts mismatch");
    }
    let uplink = narf_wifi_fixtures::udp_ipv4(
        AP,
        OWN,
        plan.lease_ip,
        plan.server_ip,
        49152,
        7,
        b"C21 native N21L legacy12/QoS uplink",
    );
    e.h.device
        .enqueue(&uplink, TxMeta::default())
        .map_err(|_| "C21 N21L IP enqueue failed")?;
    e.h.pump();
    if e.h.peer.lock().uplink.last() != Some(&uplink) {
        return Err("C21 actual native QoS/CCMP/IP data differs");
    }
    let d =
        e.h.port
            .0
            .lock()
            .packet_model
            .last_descriptor
            .ok_or("C21 qualified DATA descriptor absent")?;
    if d[16] != if narrow { 8 } else { 11 }
        || d[6] != 6
        || d[5] & 31 != 0
        || d[8..12] != [0; 4]
        || d[12..16] != 0x500u32.to_le_bytes()
    {
        return Err(
            "C21 actual DATA descriptor lost negotiated legacy rate/TID0/non-AMPDU semantics",
        );
    }
    let down = narf_wifi_fixtures::udp_ipv4(
        OWN,
        AP,
        plan.server_ip,
        plan.lease_ip,
        7,
        49152,
        b"C21 N21L native downlink",
    );
    let wire = e.h.peer.lock().downlink(&down)?;
    if wmm {
        for (a, b) in [(1, 0), (0x80, 0), (0x20, 0), (0, 1)] {
            let mut bad = wire.clone();
            bad[24] = a;
            bad[25] = b;
            e.h.port.0.lock().packet_model.receive(&bad, false, false);
        }
    }
    if protected {
        let mut bad = wire.clone();
        if let Some(last) = bad.last_mut() {
            *last ^= 1;
        }
        e.h.port.0.lock().packet_model.receive(&bad, false, false);
    }
    e.h.port.0.lock().packet_model.receive(&wire, false, false);
    e.h.pump();
    if e.h.received().iter().filter(|b| *b == &down).count() != 1 {
        return Err("C21 raw QoS/RX/CCMP failed or unsupported TID consumed valid PN");
    }
    if protected {
        e.h.port.0.lock().packet_model.receive(&wire, false, false);
        e.h.pump();
        if !e.h.received().is_empty() || !e.h.device.link_up() {
            return Err("C21 CCMP replay escaped or killed peer");
        }
    }
    if !matches!(complete(e.h.device.disassociate()), Ok(Ok(())))
        || !e.h.closed()
        || e.h.port.0.lock().packet_model.active
    {
        return Err("C21 N21L teardown retained host authority");
    }
    let drops = e.h.drops.clone();
    drop(e);
    if drops.load(Ordering::SeqCst) != 0 {
        return Err("C21 N21L lifecycle reclaimed original published firmware DMA");
    }
    Ok(())
}
fn smoke_rtw8821ce_n21l_native_open_qos_kernel_dhcp_ip() -> TestResult {
    check(|| composition(false, true, false))
}
fn smoke_rtw8821ce_n21l_native_wpa2_qos_kernel_dhcp_ip() -> TestResult {
    check(|| composition(true, true, false))
}
fn smoke_rtw8821ce_n21l_response_narrowed_and_non_wmm_headers() -> TestResult {
    check(|| {
        composition(true, true, true)?;
        composition(true, false, false)
    })
}
fn smoke_rtw8821ce_n21l_partial_edca_cancel_four_sources_policy_and_dma() -> TestResult {
    check(|| {
        for fault in 0..6 {
            let e = setup(true, true, true, None)?;
            e.h.scan()?;
            let baseline = e.h.port.0.lock().edca_writes;
            let identity = e.h.port.0.lock().packet_model.payload_identity();
            let request = e.h.request();
            let mut join = Box::pin(e.h.device.associate(request));
            let mut cx = Context::from_waker(Waker::noop());
            let mut pending = false;
            for _ in 0..100_000 {
                if join.as_mut().poll(&mut cx).is_ready() {
                    return Err("C21 N21L missed real partial EDCA await");
                }
                if e.h.port.0.lock().edca_writes >= baseline + 5 {
                    pending = true;
                    break;
                }
            }
            if !pending || !e.h.closed() {
                return Err("C21 QoS port opened at partial native EDCA");
            }
            let prefix = e.h.port.0.lock().edca_writes;
            match fault {
                0 => (),
                1..=3 => e.h.sources[fault - 1].revoke(),
                4 => e.cap.revoke(),
                _ => e.h.db.clear(),
            }
            if fault != 0 && !matches!(join.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
                return Err("C21 partial EDCA ignored one current Q/P/S/L source or live policy");
            }
            drop(join);
            e.h.db.install(domain());
            e.h.pump();
            if !e.h.closed()
                || !e.h.device.closed()
                || e.h.port.0.lock().edca_writes != prefix
                || e.h.port.0.lock().packet_model.payload_identity() != identity
            {
                return Err("C21 late EDCA wrote/reopened/replaced exact DMA after cancellation");
            }
            let drops = e.h.drops.clone();
            drop(e);
            if drops.load(Ordering::SeqCst) != 0 {
                return Err("C21 partial QoS setup freed original firmware DMA");
            }
        }
        Ok(())
    })
}
fn smoke_rtw8821ce_n21l_bound_response_and_c21_txagc_readback_required() -> TestResult {
    check(|| {
        for fault in 0..7 {
            let e = setup(true, true, true, None)?;
            e.h.scan()?;
            match fault {
                0 => e.h.peer.lock().response_wmm = Some(None),
                1 => {
                    let mut p = parameters(4);
                    p[10] |= 16;
                    e.h.peer.lock().response_wmm = Some(Some(p));
                }
                2 => {
                    let mut p = parameters(4);
                    p.extend_from_slice(&parameters(4));
                    e.h.peer.lock().response_wmm = Some(Some(p));
                }
                3 => e.h.port.0.lock().ignore_write = Some(0x508),
                4 => e.h.port.0.lock().bytes[0x1d04] ^= 1,
                5 => e.h.port.0.lock().bytes[0x1bf0] |= 1,
                _ => e.h.port.0.lock().bytes[0x2860] ^= 1,
            }
            if !matches!(complete(e.h.device.associate(e.h.request())), Ok(Err(_))) || !e.h.closed()
            {
                return Err("C21 invalid AP/EDCA/TXAGC/RF-IQK receipt opened data port");
            }
            let drops = e.h.drops.clone();
            drop(e);
            if drops.load(Ordering::SeqCst) != 0 {
                return Err("C21 failed extension released firmware DMA");
            }
        }
        Ok(())
    })
}
fn smoke_rtw8821ce_n21l_actual_m4_bytes_cancel_revocation_and_late_receipt() -> TestResult {
    check(|| {
        for fault in 0..6 {
            let e = setup(true, true, true, None)?;
            e.h.scan()?;
            e.h.peer.lock().hold_m4 = true;
            let controls = e.h.port.0.lock().packet_model.controls.clone();
            let identity = e.h.port.0.lock().packet_model.payload_identity();
            let request = e.h.request();
            let mut join = Box::pin(e.h.device.associate(request));
            let mut cx = Context::from_waker(Waker::noop());
            let mut held = false;
            for _ in 0..100_000 {
                if join.as_mut().poll(&mut cx).is_ready() {
                    return Err("C21 N21L M4 fixture skipped exact held native receipt");
                }
                if controls.held.load(Ordering::Acquire) {
                    held = true;
                    break;
                }
            }
            if !held || !e.h.closed() {
                return Err("C21 QoS published WPA2 port before real M4");
            }
            match fault {
                0 => (),
                1..=3 => e.h.sources[fault - 1].revoke(),
                4 => e.cap.revoke(),
                _ => {
                    controls.corrupt_receipt.store(true, Ordering::Release);
                    controls.release.store(true, Ordering::Release);
                }
            }
            if fault != 0 {
                let mut failed = false;
                for _ in 0..100_000 {
                    match join.as_mut().poll(&mut cx) {
                        Poll::Ready(Err(_)) => {
                            failed = true;
                            break;
                        }
                        Poll::Ready(Ok(_)) => {
                            return Err("C21 N21L fabricated M4 source/byte receipt")
                        }
                        Poll::Pending => (),
                    }
                }
                if !failed {
                    return Err("C21 revoked/modified M4 did not fail boundedly");
                }
            }
            drop(join);
            controls.release.store(true, Ordering::Release);
            e.h.pump();
            if !e.h.closed()
                || !e.h.device.closed()
                || e.h.port.0.lock().packet_model.payload_identity() != identity
                || e.h.port.0.lock().packet_model.active
            {
                return Err("C21 late M4 reopened QoS or lost retained packet owner");
            }
        }
        Ok(())
    })
}
fn smoke_rtw8821ce_n21l_native_descriptor_and_final_rx_publication_fences() -> TestResult {
    check(|| {
        for fault in 0..7 {
            let e = setup(true, true, true, None)?;
            e.h.join()?;
            let before = e.h.port.0.lock().packet_model.tx_publications;
            let fired = Arc::new(AtomicBool::new(false));
            let observed = fired.clone();
            let cap = if fault < 3 { e.h.sources[fault] } else { e.cap };
            let db = e.h.db.clone();
            let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                if !observed.swap(true, Ordering::AcqRel) {
                    if fault < 4 {
                        cap.revoke()
                    } else {
                        db.clear()
                    }
                }
            });
            let plan = e.h.peer.lock().plan;
            if fault < 5 {
                e.h.port.0.lock().packet_model.after_descriptor = Some(hook);
                let packet = narf_wifi_fixtures::udp_ipv4(
                    AP,
                    OWN,
                    plan.lease_ip,
                    plan.server_ip,
                    1,
                    2,
                    b"C21 revoke at native descriptor",
                );
                e.h.device
                    .enqueue(&packet, TxMeta::default())
                    .map_err(|_| "C21 initial live enqueue failed")?;
            } else {
                if fault == 5 {
                    e.h.port.0.lock().packet_model.after_idle = Some(hook);
                } else {
                    e.h.port.0.lock().before_publication = Some(hook);
                }
                let down = narf_wifi_fixtures::udp_ipv4(
                    OWN,
                    AP,
                    plan.server_ip,
                    plan.lease_ip,
                    2,
                    1,
                    b"C21 deny final native RX publication",
                );
                let wire = e.h.peer.lock().downlink(&down)?;
                e.h.port.0.lock().packet_model.receive(&wire, false, false);
            }
            e.h.pump();
            e.h.db.install(domain());
            e.h.pump();
            if !fired.load(Ordering::Acquire)
                || !e.h.closed()
                || !e.h.device.closed()
                || !e.h.received().is_empty()
                || e.h.port.0.lock().packet_model.tx_publications != before
            {
                return Err("C21 source/policy loss after native read/descriptor escaped final publication fence");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/wmm",
    smoke_rtw8821ce_n21l_exact_asset_retry_and_legacy_fallback
);
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/wmm",
    smoke_rtw8821ce_n21l_native_open_qos_kernel_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/wmm",
    smoke_rtw8821ce_n21l_native_wpa2_qos_kernel_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/wmm",
    smoke_rtw8821ce_n21l_response_narrowed_and_non_wmm_headers
);
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/wmm",
    smoke_rtw8821ce_n21l_partial_edca_cancel_four_sources_policy_and_dma
);
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/wmm",
    smoke_rtw8821ce_n21l_bound_response_and_c21_txagc_readback_required
);
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/wmm",
    smoke_rtw8821ce_n21l_actual_m4_bytes_cancel_revocation_and_late_receipt
);
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/wmm",
    smoke_rtw8821ce_n21l_native_descriptor_and_final_rx_publication_fences
);

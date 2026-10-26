//! C22 retained firmware/radio/packet/Device with distinct synthetic N22L
//! measurement records and an independent native AP/CCMP/DHCP actor.
use super::*;
use crate::rtw88::{
    packet_format::{self, DataProfile},
    station_profile::{Request, Source},
};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::reg::{db::Database, RegFlags};
const RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
fn parameters(be_aifs: u8) -> Vec<u8> {
    vec![
        221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x85, 0, be_aifs, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42,
        0x43, 94, 0, 0x62, 0x32, 47, 0,
    ]
}
fn domain() -> narf_wireless::reg::RegulatoryDomain {
    super::super::power_policy_tests::domain()
}
fn record(req: &Request, rates: u16, wmm: bool) -> Vec<u8> {
    let mut b = vec![0; 128];
    b[..4].copy_from_slice(b"N22L");
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x22, 0xc8]);
    b[16..48].copy_from_slice(&req.identity);
    b[48..54].copy_from_slice(&req.mac);
    b[54..56].copy_from_slice(&[1, 20]);
    for (at, value) in [(56, 4i16), (58, 76), (60, 48), (62, 48)] {
        b[at..at + 2].copy_from_slice(&value.to_le_bytes());
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
        signer: Some([8; 32]),
        cap,
        policy: db,
    }
}
struct Extended {
    h: Harness,
    cap: Cap<FirmwareBlob, Read>,
    db: Arc<Database>,
}
fn setup(
    protected: bool,
    wmm: bool,
    qualified: bool,
    response: Option<&[u8]>,
) -> Result<Extended, &'static str> {
    let h = Harness::new(protected);
    let mut peer = Peer::new(protected);
    peer.ap = peer
        .ap
        .with_legacy_rates(&RATES)
        .map_err(|_| "C22 AP richer-rate fixture invalid")?;
    peer.wmm = wmm.then(|| parameters(3));
    peer.response_rates = response.map(|r| r.to_vec());
    let mut beacon = peer.ap.beacon();
    if let Some(p) = &peer.wmm {
        beacon.extend_from_slice(p);
    }
    *h.peer.lock() = peer;
    h.model(|io| io.packets.receive(&beacon, false, false));
    // The actual association response changes BE AIFSN. The driver must use
    // its bound response, never this earlier beacon's EDCA copy.
    if wmm {
        h.peer.lock().wmm = Some(parameters(4));
    }
    let cap = Cap::bootstrap();
    let db = Arc::new(Database::new());
    db.install(domain());
    if qualified {
        let request = h
            .model(|io| io.extension_request())
            .map_err(|_| "C22 optional recipe request missing")?;
        h.model(|io| io.qualify_extension(source(record(&request, 0xfff, true), cap, db.clone())))
            .map_err(|_| "C22 distinct synthetic measurement qualification failed")?;
    }
    Ok(Extended { h, cap, db })
}
fn result(check: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    check().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn smoke_rtw8822ce_distinct_legacy_wmm_qualification_and_legacy_fallback() -> TestResult {
    result(|| {
        let h = Harness::new(false);
        let req = h
            .model(|io| io.extension_request())
            .map_err(|_| "N22L request missing")?;
        for fault in 0..10 {
            let cap = Cap::bootstrap();
            let db = Arc::new(Database::new());
            db.install(domain());
            let mut bytes = record(&req, 0xfff, true);
            match fault {
                0 => bytes[0] = b'X',
                1 => bytes[16] ^= 1,
                2 => bytes[48] ^= 1,
                3 => {
                    bytes.pop();
                }
                4 => bytes[91] = 1,
                5 => bytes[64..66].copy_from_slice(&80i16.to_le_bytes()),
                6 => cap.revoke(),
                7 => db.clear(),
                8 => {
                    let mut d = domain();
                    d.rules[0].flags = RegFlags::NO_IR;
                    db.install(d);
                }
                _ => (),
            }
            let mut source = source(bytes, cap, db);
            if let (9, Source::Verified { signer, .. }) = (fault, &mut source) {
                *signer = None;
            }
            if h.model(|io| io.qualify_extension(source)).is_ok() || h.device.closed() {
                return Err("invalid optional recipe changed legacy station admission");
            }
        }
        drop(h);
        let e = setup(true, true, false, None)?;
        e.h.join();
        let frame = udp_ipv4(
            AP,
            OWN,
            e.h.plan.lease_ip,
            e.h.plan.server_ip,
            1,
            2,
            b"C22 unqualified fallback",
        );
        if e.h.device.enqueue(&frame, TxMeta::default()).is_err() {
            return Err("unqualified WMM AP lost existing legacy connection");
        }
        e.h.pump();
        let d =
            e.h.model(|io| io.packets.last_descriptor)
                .ok_or("fallback descriptor absent")?;
        if e.h.peer.lock().qos
            || u32::from_le_bytes(d[4..8].try_into().unwrap()) != 8 << 16
            || d[16] != 0
        {
            return Err("unqualified optional asset widened CCK1 legacy descriptor");
        }
        Ok(())
    })
}
fn smoke_rtw8822ce_legacy12_descriptor_rate_order_and_wmm_register_units() -> TestResult {
    result(|| {
        let p = narf_wireless::wmm::Parameters::parse(&parameters(4))
            .map_err(|_| "literal WMM parse")?
            .ok_or("literal WMM absent")?;
        if crate::rtw88::wmm::words(p, false).map_err(|_| "literal WMM encode")?
            != [0xa55a, 0xa496, 0x005e4332, 0x002f3232]
        {
            return Err("source C22 EDCA register fields or conservative BE changed");
        }
        for (index, _) in RATES.iter().enumerate() {
            let profile = DataProfile {
                rates: 1 | (1 << index),
                qos: true,
            };
            let mut frame = vec![0x88, 1, 0, 0];
            frame.extend_from_slice(&AP);
            frame.extend_from_slice(&OWN);
            frame.extend_from_slice(&AP);
            frame.extend_from_slice(&[0, 0, 0, 0]);
            frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1]);
            let (d, q) = packet_format::transmit_profile(&frame, OWN, 0, None, profile)
                .map_err(|_| "native C22 qualified descriptor rejected")?;
            let expected_id = if index < 4 { 8 } else { 6 };
            if q != packet_format::Queue::Data
                || d[16] != index as u8
                || u32::from_le_bytes(d[4..8].try_into().unwrap()) != expected_id << 16
                || d[12..16] != (0x500u32).to_le_bytes()
                || d[8..12] != [0; 4]
                || d[20..24] != [0; 4]
                || d[32..36] != [0; 4]
            {
                return Err(
                    "native legacy12/TID0 fixed rate, no aggregation/SGI or manual sequence differ",
                );
            }
            frame[24] = 1;
            if packet_format::transmit_profile(&frame, OWN, 0, None, profile).is_ok() {
                return Err("non-BE TID admitted into one-producer native profile");
            }
        }
        // IEEE hardware numbering is not monotone in bit rate:11Mbps exceeds6/9.
        if (DataProfile {
            rates: (1 << 3) | (1 << 4) | (1 << 5),
            qos: false,
        })
        .rate()
            != 3
        {
            return Err("native legacy selection compared descriptor index instead of bit rate");
        }
        Ok(())
    })
}
fn composition(protected: bool, narrowed: bool) -> Result<(), &'static str> {
    let e = setup(protected, true, true, narrowed.then_some(&[0x82, 48][..]))?;
    e.h.join();
    let expected_mask = if narrowed { 0x101u16 } else { 0xfff };
    let expected_rate = if narrowed { 8 } else { 11 };
    if !e.h.peer.lock().qos
        || !e.h.model(|io| {
            io.mailboxes.contains(&[
                0x40,
                0,
                0x26,
                0x40,
                expected_mask as u8,
                (expected_mask >> 8) as u8,
                0,
                0,
            ])
        })
    {
        return Err("actual bound response WMM/RA mask did not reach firmware mailbox");
    }
    if e.h.model(|io| {
        [
            io.register(0x508),
            io.register(0x50c),
            io.register(0x504),
            io.register(0x500),
        ]
    }) != [0xa55a, 0xa496, 0x005e4332, 0x002f3232]
        || e.h.model(|io| io.register(0x440)) != if narrowed { 0x5f } else { 0x15f }
    {
        return Err("C22 native EDCA/RRSR used beacon or unbound rates");
    }
    let lease = narf_net::dhcp::dhcp_acquire(e.h.device.name(), 0)
        .map_err(|_| "C22 WMM actual kernel DORA failed")?;
    if !e.h.plan.matches_lease(&lease) {
        return Err("C22 WMM DHCP lease mismatch");
    }
    let uplink = udp_ipv4(
        AP,
        OWN,
        e.h.plan.lease_ip,
        e.h.plan.server_ip,
        49152,
        7,
        b"C22 real native QoS/legacy data",
    );
    if narf_net::iface::send_on(e.h.device.name(), &uplink).is_err() {
        return Err("C22 qualified native IP enqueue failed");
    }
    e.h.pump();
    if e.h.peer.lock().uplink.last() != Some(&uplink) {
        return Err("C22 actual QoS header/CCMP/IP uplink changed");
    }
    let d =
        e.h.model(|io| io.packets.last_descriptor)
            .ok_or("C22 native QoS descriptor absent")?;
    if d[16] != expected_rate
        || u32::from_le_bytes(d[4..8].try_into().unwrap()) != 6 << 16
        || d[8..12] != [0; 4]
        || d[12..16] != 0x500u32.to_le_bytes()
    {
        return Err("C22 ordinary TX used unnegotiated rate/queue/aggregation mode");
    }
    let downlink = udp_ipv4(
        OWN,
        AP,
        e.h.plan.server_ip,
        e.h.plan.lease_ip,
        7,
        49152,
        b"C22 native QoS downlink",
    );
    let wire = e.h.peer.lock().downlink(&downlink)?;
    // Unsupported QoS control and invalid CCMP never consume the valid
    // packet's replay state. The following exact native frame must survive.
    for fault in 0..5 {
        let mut bad = wire.clone();
        match fault {
            0 => bad[24] = 1,
            1 => bad[24] = 0x80,
            2 => bad[24] = 0x20,
            3 => bad[25] = 1,
            _ => bad[1] |= 0x80,
        }
        e.h.model(|io| io.packets.receive(&bad, false, false));
    }
    if protected {
        let mut bad = wire.clone();
        if let Some(last) = bad.last_mut() {
            *last ^= 1;
        }
        e.h.model(|io| io.packets.receive(&bad, false, false));
    }
    e.h.model(|io| io.packets.receive(&wire, false, false));
    e.h.pump();
    if e.h.received().iter().filter(|p| *p == &downlink).count() != 1 {
        return Err("C22 native raw QoS/CCMP downlink failed");
    }
    if protected {
        e.h.model(|io| io.packets.receive(&wire, false, false));
        e.h.pump();
        if !e.h.received().is_empty() || !e.h.device.link_up() {
            return Err("C22 native QoS CCMP replay escaped or poisoned valid peer");
        }
    }
    if complete(e.h.device.disassociate()).is_err()
        || !e.h.closed()
        || e.h.model(|io| io.packets.active)
    {
        return Err("C22 qualified QoS native teardown did not close retained owner");
    }
    Ok(())
}
fn smoke_rtw8822ce_native_wmm_open_kernel_dhcp_ip() -> TestResult {
    result(|| composition(false, false))
}
fn smoke_rtw8822ce_native_wmm_wpa2_kernel_dhcp_ip() -> TestResult {
    result(|| composition(true, false))
}
fn smoke_rtw8822ce_response_narrowed_legacy_rates_drive_native_data() -> TestResult {
    result(|| composition(true, true))
}
fn smoke_rtw8822ce_qualified_richer_rates_without_wmm_keep_legacy_headers() -> TestResult {
    result(|| {
        let e = setup(true, false, true, None)?;
        e.h.join();
        let lease = narf_net::dhcp::dhcp_acquire(e.h.device.name(), 0)
            .map_err(|_| "C22 qualified non-WMM DHCP failed")?;
        let d =
            e.h.model(|io| io.packets.last_descriptor)
                .ok_or("C22 non-WMM native data descriptor absent")?;
        if e.h.peer.lock().qos
            || !e.h.plan.matches_lease(&lease)
            || d[16] != 11
            || e.h.model(|io| io.register(0x508)) != 0xa532
        {
            return Err("qualified rates forced QoS or lost non-WMM legacy connection");
        }
        Ok(())
    })
}

fn smoke_rtw8822ce_wmm_m4_actual_receipt_cancel_source_and_late_completion() -> TestResult {
    result(|| {
        for fault in 0..3 {
            let e = setup(true, true, true, None)?;
            e.h.scan();
            e.h.peer.lock().hold_m4 = true;
            let controls = e.h.model(|io| io.packets.controls.clone());
            let identity = e.h.model(|io| io.packets.payload_identity());
            let mut join = Box::pin(e.h.device.associate(e.h.request()));
            let mut cx = Context::from_waker(Waker::noop());
            let mut held = false;
            for _ in 0..100_000 {
                if join.as_mut().poll(&mut cx).is_ready() {
                    return Err("C22 QoS/M4 fixture completed without exact held native receipt");
                }
                if controls.held.load(Ordering::Acquire) {
                    held = true;
                    break;
                }
            }
            if !held || !e.h.closed() {
                return Err("C22 QoS opened controlled port before real M4 CCX");
            }
            if fault == 1 {
                e.cap.revoke();
            } else if fault == 2 {
                controls.corrupt_receipt.store(true, Ordering::Release);
                controls.release.store(true, Ordering::Release);
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
                            return Err("C22 new QoS recipe fabricated M4 authority/byte receipt")
                        }
                        Poll::Pending => (),
                    }
                }
                if !failed {
                    return Err("C22 invalid/revoked M4 did not terminate boundedly");
                }
            }
            drop(join);
            controls.release.store(true, Ordering::Release);
            e.h.pump();
            if !e.h.closed()
                || !e.h.device.closed()
                || e.h.model(|io| io.packets.payload_identity()) != identity
                || e.h.model(|io| io.packets.active)
            {
                return Err("C22 late QoS M4 revived owner or released/replaced native DMA");
            }
        }
        Ok(())
    })
}

fn smoke_rtw8822ce_wmm_pending_edca_cancel_sources_policy_and_dma() -> TestResult {
    result(|| {
        for fault in 0..4 {
            let e = setup(true, true, true, None)?;
            e.h.scan();
            let writes = e.h.model(|io| io.edca_writes.clone());
            let base = writes.load(Ordering::Acquire);
            let storage = e.h.model(|io| io.packets.payload_identity());
            let request = e.h.request();
            let mut join = Box::pin(e.h.device.associate(request));
            let mut cx = Context::from_waker(Waker::noop());
            let mut at = false;
            for _ in 0..100_000 {
                if join.as_mut().poll(&mut cx).is_ready() {
                    return Err("C22 WMM operation missed awaited EDCA prefix");
                }
                if writes.load(Ordering::Acquire) >= base + 5 {
                    at = true;
                    break;
                }
            }
            if !at || !e.h.closed() {
                return Err("C22 WMM prefix or closed-port boundary absent");
            }
            let prefix = writes.load(Ordering::Acquire);
            match fault {
                0 => (),
                1 => e.cap.revoke(),
                2 => e.h.calibration.revoke(),
                _ => e.db.clear(),
            }
            if fault != 0 && !matches!(join.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
                return Err("C22 pending EDCA ignored current source or installed-policy loss");
            }
            drop(join);
            e.db.install(domain());
            e.h.pump();
            if !e.h.closed()
                || !e.h.device.closed()
                || writes.load(Ordering::Acquire) != prefix
                || e.h.model(|io| io.packets.payload_identity()) != storage
            {
                return Err(
                    "C22 cancelled WMM prefix wrote again/replaced native DMA/reopened owner",
                );
            }
        }
        Ok(())
    })
}
fn smoke_rtw8822ce_wmm_wrong_response_lost_edca_or_gain_never_opens_port() -> TestResult {
    result(|| {
        for fault in 0..5 {
            let e = setup(true, true, true, None)?;
            e.h.scan();
            match fault {
                0 => e.h.peer.lock().response_wmm = Some(None),
                1 => {
                    let mut p = parameters(4);
                    p[10] |= 0x10;
                    e.h.peer.lock().response_wmm = Some(Some(p));
                }
                2 => {
                    let mut p = parameters(4);
                    p.extend_from_slice(&parameters(4));
                    e.h.peer.lock().response_wmm = Some(Some(p));
                }
                3 => e.h.model(|io| io.lose_write(0x508)),
                _ => {
                    e.h.model(|io| {
                        use crate::rtw88::firmware_transport::Io;
                        io.write32(0x18e8, 0x400)
                    })
                    .map_err(|_| "C22 lost-gain fixture native mutation failed")?
                }
            }
            if complete(e.h.device.associate(e.h.request())).is_ok()
                || !e.h.closed()
                || !e.h.device.closed()
            {
                return Err("C22 missing/foreign WMM response or native programming failure admitted secured data");
            }
        }
        Ok(())
    })
}
fn smoke_rtw8822ce_wmm_descriptor_revocation_and_queued_rx_policy_are_terminal() -> TestResult {
    result(|| {
        for fault in 0..3 {
            let e = setup(true, true, true, None)?;
            e.h.join();
            let before = e.h.model(|io| io.packets.tx_publications);
            let cap = e.cap;
            let db = e.db.clone();
            if fault < 2 {
                e.h.model(|io| {
                    io.packets.after_descriptor =
                        Some(Arc::new(
                            move || if fault == 0 { cap.revoke() } else { db.clear() },
                        ))
                });
            }
            let packet = udp_ipv4(
                AP,
                OWN,
                e.h.plan.lease_ip,
                e.h.plan.server_ip,
                1,
                2,
                b"C22 revoke at native descriptor",
            );
            if fault < 2 {
                e.h.device
                    .enqueue(&packet, TxMeta::default())
                    .map_err(|_| "initial qualified enqueue failed")?;
            } else {
                let inbound = udp_ipv4(
                    OWN,
                    AP,
                    e.h.plan.server_ip,
                    e.h.plan.lease_ip,
                    2,
                    1,
                    b"queued native authorized C22 RX",
                );
                let wire = e.h.peer.lock().downlink(&inbound)?;
                e.h.model(|io| io.packets.receive(&wire, false, false));
                e.db.clear();
            }
            e.h.pump();
            e.db.install(domain());
            e.h.pump();
            if !e.h.closed()
                || !e.h.device.closed()
                || e.h.model(|io| io.packets.tx_publications) != before
                || !e.h.received().is_empty()
            {
                return Err("C22 descriptor/RX live authority loss published a packet or reopened after reinstall");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_distinct_legacy_wmm_qualification_and_legacy_fallback
);
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_legacy12_descriptor_rate_order_and_wmm_register_units
);
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_native_wmm_open_kernel_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_native_wmm_wpa2_kernel_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_response_narrowed_legacy_rates_drive_native_data
);
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_qualified_richer_rates_without_wmm_keep_legacy_headers
);
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_wmm_m4_actual_receipt_cancel_source_and_late_completion
);
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_wmm_pending_edca_cancel_sources_policy_and_dma
);
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_wmm_wrong_response_lost_edca_or_gain_never_opens_port
);
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_wmm_descriptor_revocation_and_queued_rx_policy_are_terminal
);

fn smoke_rtw8822ce_revoke_after_native_rx_idle_never_publishes_frame() -> TestResult {
    result(|| {
        for fault in 0..5 {
            let e = setup(true, true, fault < 3, None)?;
            e.h.join();
            let identity = e.h.model(|io| io.packets.payload_identity());
            let cap = if fault == 0 { e.cap } else { e.h.calibration };
            let db = e.db.clone();
            let legacy_policy = e.h.model(|io| io.policy.clone());
            let fired = Arc::new(AtomicBool::new(false));
            let observed = fired.clone();
            e.h.model(|io| {
                io.packets.after_idle = Some(Arc::new(move || {
                    if !observed.swap(true, Ordering::AcqRel) {
                        match fault {
                            0 | 1 | 3 => cap.revoke(),
                            2 => db.clear(),
                            _ => legacy_policy.lock().rules.clear(),
                        }
                    }
                }))
            });
            let ethernet = udp_ipv4(
                OWN,
                AP,
                e.h.plan.server_ip,
                e.h.plan.lease_ip,
                7,
                49152,
                b"revoke only after native RX completed",
            );
            let wire = e.h.peer.lock().downlink(&ethernet)?;
            e.h.model(|io| io.packets.receive(&wire, false, false));
            e.h.pump();
            if !fired.load(Ordering::Acquire)
                || !e.h.closed()
                || !e.h.device.closed()
                || !e.h.received().is_empty()
                || e.h.model(|io| io.packets.payload_identity()) != identity
                || e.h.model(|io| io.packets.active)
            {
                return Err("C22 source/policy revoked after native RX-idle read escaped final host-publication fence");
            }
            e.db.install(domain());
            e.h.pump();
            if e.h.device.link_up() {
                return Err("C22 publication denial reopened after policy reinstall");
            }
        }
        Ok(())
    })
}
fn smoke_rtw8822ce_revoke_after_m4_native_idle_never_publishes_carrier() -> TestResult {
    result(|| {
        for fault in 0..3 {
            let e = setup(true, true, true, None)?;
            e.h.scan();
            e.h.peer.lock().hold_m4 = true;
            let controls = e.h.model(|io| io.packets.controls.clone());
            let identity = e.h.model(|io| io.packets.payload_identity());
            let armed = Arc::new(AtomicBool::new(false));
            let fired = Arc::new(AtomicBool::new(false));
            let enabled = armed.clone();
            let observed = fired.clone();
            let cap = if fault == 0 { e.cap } else { e.h.calibration };
            let db = e.db.clone();
            e.h.model(|io| {
                io.packets.after_idle = Some(Arc::new(move || {
                    if enabled.load(Ordering::Acquire) && !observed.swap(true, Ordering::AcqRel) {
                        if fault < 2 {
                            cap.revoke()
                        } else {
                            db.clear()
                        }
                    }
                }))
            });
            let mut join = Box::pin(e.h.device.associate(e.h.request()));
            let mut cx = Context::from_waker(Waker::noop());
            let mut held = false;
            for _ in 0..100_000 {
                if join.as_mut().poll(&mut cx).is_ready() {
                    return Err("M4 publication regression missed held native receipt");
                }
                if controls.held.load(Ordering::Acquire) {
                    held = true;
                    break;
                }
            }
            if !held || fired.load(Ordering::Acquire) {
                return Err(
                    "M4 publication regression revoked before intended native-idle boundary",
                );
            }
            armed.store(true, Ordering::Release);
            controls.release.store(true, Ordering::Release);
            let mut failed = false;
            for _ in 0..100_000 {
                match join.as_mut().poll(&mut cx) {
                    Poll::Ready(Err(_)) => {
                        failed = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => {
                        return Err("revoked final M4 native read still admitted carrier")
                    }
                    Poll::Pending => (),
                }
            }
            drop(join);
            e.h.pump();
            if !failed
                || !fired.load(Ordering::Acquire)
                || !e.h.closed()
                || !e.h.device.closed()
                || e.h.model(|io| io.packets.payload_identity()) != identity
                || e.h.model(|io| io.packets.active)
            {
                return Err(
                    "current source/policy not rechecked at actual final M4/carrier publication",
                );
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_revoke_after_native_rx_idle_never_publishes_frame
);
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_revoke_after_m4_native_idle_never_publishes_carrier
);

fn smoke_rtw8822ce_enqueue_final_source_policy_denial_is_terminal_but_full_ring_retries(
) -> TestResult {
    result(|| {
        for fault in 0..3 {
            let e = setup(true, true, true, None)?;
            e.h.join();
            let packet = udp_ipv4(
                AP,
                OWN,
                e.h.plan.lease_ip,
                e.h.plan.server_ip,
                49152,
                7,
                b"loss after enqueue authority capture",
            );
            let before = e.h.model(|io| io.packets.tx_publications);
            let cap = if fault == 0 { e.cap } else { e.h.calibration };
            let db = e.db.clone();
            let fired = Arc::new(AtomicBool::new(false));
            let seen = fired.clone();
            e.h.model(|io| {
                io.before_publication = Some(Arc::new(move || {
                    if !seen.swap(true, Ordering::AcqRel) {
                        if fault < 2 {
                            cap.revoke()
                        } else {
                            db.clear()
                        }
                    }
                }))
            });
            if e.h.device.enqueue(&packet, TxMeta::default()).is_ok()
                || !fired.load(Ordering::Acquire)
                || !e.h.device.closed()
                || !e.h.closed()
                || e.h.model(|io| io.packets.tx_publications) != before
            {
                return Err("outer enqueue source/PCI publication failure remained retryable or queued a frame");
            }
            e.db.install(domain());
            e.h.pump();
            if e.h.device.enqueue(&packet, TxMeta::default()).is_ok() || e.h.device.link_up() {
                return Err("enqueue denial reopened after policy reinstall");
            }
        }
        let e = setup(true, true, true, None)?;
        e.h.join();
        let packet = udp_ipv4(
            AP,
            OWN,
            e.h.plan.lease_ip,
            e.h.plan.server_ip,
            49152,
            7,
            b"bounded full host ring",
        );
        let mut full = false;
        for _ in 0..=narf_net::TX_RING_N {
            if e.h.device.enqueue(&packet, TxMeta::default()).is_err() {
                full = true;
                break;
            }
        }
        if !full || e.h.device.closed() || !e.h.device.link_up() {
            return Err("inner host ring-full became an authority failure");
        }
        for _ in 0..narf_net::TX_RING_N + 2 {
            e.h.device.drain();
        }
        if e.h.device.enqueue(&packet, TxMeta::default()).is_err() || e.h.device.closed() {
            return Err("valid full-ring owner could not retry after native progress");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtw88/wmm",
    smoke_rtw8822ce_enqueue_final_source_policy_denial_is_terminal_but_full_ring_retries
);

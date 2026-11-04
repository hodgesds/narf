//! Actual original CLIENT8/STA7, retained peer P2P IEs and MAC CTWindow ACK.
use super::*;
use crate::iwlwifi::p2p_client_fixture as p2p;
fn data() -> Vec<u8> {
    let mut out = NETWORK.bssid.to_vec();
    out.extend_from_slice(&OWN);
    out.extend_from_slice(&[0x88, 0xb5, 1, 2, 3, 4]);
    out
}
#[inline(never)]
fn join(f: &Fixture) -> R {
    super::super::scan(f.device())?;
    let mut request = super::super::request(true);
    request.ie = p2p::request();
    run(f.device().associate(request), service)?
        .map_err(|_| "P2P client real native association/key/port")?;
    require(
        f.device().current_iftype() == 8
            && f.device().link_up()
            && f.device().connected_bssid() == Some(AP),
        "P2P client actual physical role/authorized port absent",
    )
}
fn queued_beacon(index: u8, window: Option<u8>, foreign: bool) -> R {
    let mut h = HARNESS.lock();
    let wire = &mut h.as_mut().unwrap().1;
    let mut beacon = p2p::beacon(wire.ap.beacon(), index, window);
    if foreign {
        beacon[10] = 4;
        beacon[16] = 4;
    }
    wire.mpdu(&beacon, false);
    Ok(())
}
#[inline(never)]
fn send(f: &Fixture, window: u32) -> R {
    let before = HARNESS.lock().as_ref().unwrap().1.data.len();
    f.device()
        .enqueue(&data(), narf_net::TxMeta::default())
        .map_err(|_| "P2P client real DATA enqueue")?;
    flush()?;
    let (sent, last) = {
        let h = HARNESS.lock();
        let wire = &h.as_ref().unwrap().1;
        (
            wire.data.len(),
            wire.commands
                .iter()
                .rev()
                .find(|(g, c, b)| (*g, *c) == (3, 8) && word(b, 8) == 7)
                .map(|(_, _, b)| word(b, 48)),
        )
    };
    require(
        sent > before && last == Some(window),
        "P2P client DATA crossed an unacknowledged/current CTWindow",
    )
}
#[inline(never)]
fn public_frame(f: &Fixture, frame: &[u8], both: bool, success: bool) -> R {
    let _ = narf_wireless::nl80211::register();
    let actual =
        narf_net::iface::lookup(f.device().name()).ok_or("CLIENT public original IFINDEX")?;
    let wiphy = narf_wireless::registry::wiphy_index(f.device().wiphy_id())
        .ok_or("CLIENT public actual wiphy")?;
    let request = crate::iwlwifi::p2p_go_fixture::management_request(
        actual.ifindex,
        wiphy,
        2437,
        Some(frame),
        both,
    );
    let before = f.source.messages.lock().len();
    let transmitted = HARNESS.lock().as_ref().unwrap().1.client_public.len();
    let replies = narf_net::netlink_generic::build_replies_with_endpoint(
        &request,
        Default::default(),
        narf_net::netlink_generic::RequestContext {
            admin: Some(&f.admin),
            portid: 77,
            ..Default::default()
        },
        f.source.clone(),
    )
    .map_err(|_| "CLIENT public FRAME original selector/parser")?;
    require(
        replies.is_empty(),
        "CLIENT public FRAME escaped retained deferred owner",
    )?;
    let mut done = false;
    for _ in 0..4096 {
        narf_scheduler::poll_one_round();
        service()?;
        done = {
            let messages = f.source.messages.lock();
            if success {
                crate::iwlwifi::p2p_go_fixture::management_completed(&messages[before..], true)?
            } else {
                messages[before..].iter().any(|b| {
                    b.get(4..6) == Some(&2u16.to_ne_bytes())
                        && b.get(16..20).is_some_and(|e| e != [0; 4])
                })
            }
        };
        if done {
            break;
        }
    }
    let after = HARNESS.lock().as_ref().unwrap().1.client_public.len();
    require(
        done && after == transmitted + usize::from(success),
        "CLIENT public FRAME lost native terminal or invalid frame reached radio",
    )
}
#[inline(never)]
fn register(f: &Fixture, both: bool) -> R {
    register_kind(f, both, false)
}
#[inline(never)]
fn register_kind(f: &Fixture, both: bool, probe: bool) -> R {
    let _ = narf_wireless::nl80211::register();
    let actual = narf_net::iface::lookup(f.device().name())
        .ok_or("CLIENT REGISTER actual original IFINDEX")?;
    let wiphy = narf_wireless::registry::wiphy_index(f.device().wiphy_id())
        .ok_or("CLIENT REGISTER actual wiphy")?;
    let request = if probe {
        p2p::register_probe_request(actual.ifindex, wiphy, both)
    } else {
        p2p::register_request(actual.ifindex, wiphy, both)
    };
    let before = f.source.messages.lock().len();
    let replies = narf_net::netlink_generic::build_replies_with_endpoint(
        &request,
        Default::default(),
        narf_net::netlink_generic::RequestContext {
            admin: Some(&f.admin),
            portid: 77,
            ..Default::default()
        },
        f.source.clone(),
    )
    .map_err(|_| "CLIENT REGISTER source/selector parser")?;
    require(
        replies.is_empty(),
        "CLIENT REGISTER escaped deferred original authority",
    )?;
    let mut done = false;
    for _ in 0..4096 {
        narf_scheduler::poll_one_round();
        service()?;
        done = {
            let m = f.source.messages.lock();
            crate::iwlwifi::p2p_go_fixture::management_completed(&m[before..], false)?
        };
        if done {
            break;
        }
    }
    require(
        done,
        "CLIENT metadata registration did not complete original source",
    )
}
fn inject_public(frame: &[u8]) {
    HARNESS.lock().as_mut().unwrap().1.mpdu(frame, false);
}
#[inline(never)]
fn probe_enable_source_loss() -> R {
    let f = Fixture::new_role(None, None, true)?;
    join(&f)?;
    let native = {
        f.device()
            .state
            .try_lock()
            .ok_or("CLIENT held-enable State")?
            .hardware
            .p2p_client_native()
            .ok_or("CLIENT held-enable Native")?
    };
    let before = HARNESS.lock().as_ref().unwrap().1.commands.len();
    HARNESS.lock().as_mut().unwrap().1.hold_client_filter = true;
    register_kind(&f, true, true)?;
    for _ in 0..256 {
        let _ = f.device().step(None);
        service()?;
        if HARNESS.lock().as_ref().unwrap().1.held.is_some() {
            break;
        }
    }
    require(
        !native.probe_receipt() && native.pending(),
        "CLIENT held filter enable invented native applied receipt",
    )?;
    let probe = p2p::probe_request(OWN, AP);
    inject_public(&probe);
    for _ in 0..4 {
        let _ = f.device().step(None);
        service()?;
    }
    let before_ack = { p2p::received(&f.source.messages.lock(), &probe) };
    require(
        before_ack == 0 && !native.probe_receipt(),
        "CLIENT pending filter enable authorized probe copy before actual ACK",
    )?;
    f.source.owner.retire().notify();
    {
        let mut h = HARNESS.lock();
        let wire = &mut h.as_mut().unwrap().1;
        let (cmd, group, sequence) = wire
            .held
            .take()
            .ok_or("CLIENT actual held filter enable absent")?;
        require(
            (group, cmd) == (3, 8),
            "CLIENT held wrong native filter command",
        )?;
        wire.firmware.inject(cmd, group, sequence, &[]);
    }
    flush()?;
    let ordered = {
        let h = HARNESS.lock();
        let commands = &h.as_ref().unwrap().1.commands[before..];
        let macs: Vec<_> = commands
            .iter()
            .filter(|(g, c, b)| {
                (*g, *c) == (3, 8) && word(b, 4) == 2 && word(b, 8) == 7 && b[36] == 1
            })
            .map(|(_, _, b)| word(b, 20) & 32 != 0)
            .collect();
        macs.first() == Some(&true) && macs.last() == Some(&false) && macs.len() >= 2
    };
    require(ordered && !native.probe_receipt() && !native.pending() && native.current().is_ok() && f.device().link_up(),
        "CLIENT source loss during enable ACK falsely committed clear without actual MAC7 clear receipt")
}
#[inline(never)]
fn probe_source_close() -> R {
    let f = Fixture::new_role(None, None, true)?;
    register_kind(&f, true, true)?;
    join(&f)?;
    let native = {
        f.device()
            .state
            .try_lock()
            .ok_or("CLIENT probe-close original State")?
            .hardware
            .p2p_client_native()
            .ok_or("CLIENT probe-close original Native")?
    };
    let frame = p2p::probe_request(OWN, AP);
    inject_public(&frame);
    flush()?;
    require(
        native.probe_receipt() && p2p::received(&f.source.messages.lock(), &frame) == 1,
        "CLIENT probe-close fixture lacks actual installed original subscription/filter",
    )?;
    let before = HARNESS.lock().as_ref().unwrap().1.commands.len();
    f.source.owner.retire().notify();
    // No further source request/callback: physical polling must schedule
    // the non-emitting filter clear under original device authority.
    flush()?;
    let cleared = {
        let h = HARNESS.lock();
        h.as_ref().unwrap().1.commands[before..]
            .iter()
            .any(|(g, c, b)| {
                (*g, *c) == (3, 8)
                    && word(b, 4) == 2
                    && word(b, 8) == 7
                    && b[36] == 1
                    && word(b, 20) & 32 == 0
            })
    };
    require(
        cleared
            && !native.probe_receipt()
            && !native.pending()
            && native.current().is_ok()
            && f.device().link_up(),
        "CLIENT closed probe source retained native filter or retired unrelated station owner",
    )?;
    inject_public(&frame);
    flush()?;
    let received = { p2p::received(&f.source.messages.lock(), &frame) };
    require(
        received == 1,
        "CLIENT closed probe source published a new native copy",
    )?;
    drop(f);
    probe_enable_source_loss()
}
#[inline(never)]
fn receive_retirement() -> R {
    let f = Fixture::new_role(None, None, true)?;
    // Receive-only metadata is legal before association and carries no
    // initiating NO_IR permission, native MAC7, key or controlled port.
    let mut denied = policy();
    for rule in &mut denied.rules {
        rule.flags |= narf_wireless::reg::RegFlags::NO_IR;
    }
    f.guard.policy_db.install(denied);
    register(&f, true)?;
    let frame = p2p::peer_action(OWN, AP);
    inject_public(&frame);
    let _ = f.device().step(None);
    service()?;
    require(
        p2p::received(&f.source.messages.lock(), &frame) == 0,
        "CLIENT pre-association registration fabricated native RX",
    )?;
    f.guard.policy_db.install(policy());
    join(&f)?;
    inject_public(&frame);
    let stale = {
        let mut state = f
            .device()
            .state
            .try_lock()
            .ok_or("CLIENT copied RX State")?;
        state.hardware.poll()?;
        state.hardware.take_client_events()
    };
    require(
        stale.len() == 1,
        "CLIENT physical RX was not tagged with original registration",
    )?;
    // Installing another current metadata prefix retires pending old copies;
    // it cannot retrospectively attach the old packet to the new source.
    register(&f, false)?;
    for publication in stale {
        publication.publish();
    }
    require(
        p2p::received(&f.source.messages.lock(), &frame) == 0,
        "CLIENT old RX copy acquired replacement registration",
    )?;
    inject_public(&frame);
    flush()?;
    let before = p2p::received(&f.source.messages.lock(), &frame);
    require(
        before == 2,
        "CLIENT current original metadata registrations lost actual matching native RX",
    )?;
    let mut foreign = frame.clone();
    foreign[4..10].copy_from_slice(&[2, 99, 1, 2, 3, 4]);
    inject_public(&foreign);
    flush()?;
    require(
        p2p::received(&f.source.messages.lock(), &foreign) == 0,
        "CLIENT unrelated physical RA gained public metadata authority",
    )?;
    register_kind(&f, true, true)?;
    // The new filter is maintenance under the retained physical owner;
    // its MAC7 ACK must precede copied probe eligibility.
    flush()?;
    let probe = p2p::probe_request(OWN, AP);
    inject_public(&probe);
    flush()?;
    require(
        p2p::received(&f.source.messages.lock(), &probe) == 1,
        "CLIENT post-association probe registration lacks native filter update",
    )?;
    inject_public(&frame);
    let (copies, native) = {
        let mut state = f
            .device()
            .state
            .try_lock()
            .ok_or("CLIENT callback copied RX State")?;
        state.hardware.poll()?;
        (
            state.hardware.take_client_events(),
            state
                .hardware
                .p2p_client_native()
                .ok_or("CLIENT original RX native absent")?,
        )
    };
    require(
        copies.len() == 2,
        "CLIENT callback fixture lacks original real copies",
    )?;
    *f.source.callback.lock() = Some(Callback::ClientRetire(native.clone()));
    for publication in copies {
        publication.publish();
    }
    require(
        native.current().is_err() && p2p::received(&f.source.messages.lock(), &frame) == before,
        "CLIENT prepared source callback retired native owner but published stale RX",
    )?;
    drop(f);
    probe_source_close()
}
#[inline(never)]
fn late_source(f: &Fixture) -> R {
    use core::future::Future;
    let actual = narf_net::iface::lookup(f.device().name()).ok_or("CLIENT late source IFINDEX")?;
    let iface: Arc<dyn WirelessNetIface> = f.device().clone();
    let authority = narf_wireless::ap_control::RadioControlAuthority::bind(
        f.admin.clone(),
        &iface,
        0,
        actual.ifindex,
        f.source.clone(),
    )
    .and_then(narf_wireless::ap_control::RadioControlAuthority::reserve)
    .map_err(|_| "CLIENT late source actual reservation")?;
    let native = {
        f.device()
            .state
            .try_lock()
            .ok_or("CLIENT late source State")?
            .hardware
            .p2p_client_native()
            .ok_or("CLIENT late source native owner")?
    };
    HARNESS.lock().as_mut().unwrap().1.hold_client_public = true;
    let request = narf_wireless::MgmtTxRequest {
        frame: p2p::public_frame(OWN, AP),
        frequency_mhz: 2437,
        no_cck: true,
        offchannel_ok: false,
        duration: 0,
    };
    let mut tx = Box::pin(
        f.device()
            .mgmt_tx_radio_async(&authority, 0x41434b, request),
    );
    for _ in 0..256 {
        require(
            tx.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "CLIENT FRAME escaped actual held TX receipt",
        )?;
        service()?;
        if HARNESS.lock().as_ref().unwrap().1.held_tx.is_some() {
            break;
        }
    }
    require(
        f.device().state.try_lock().is_none(),
        "CLIENT borrowed waiter released native held owner",
    )?;
    *f.source.callback.lock() = Some(Callback::ClientRetire(native.clone()));
    {
        let mut h = HARNESS.lock();
        let wire = &mut h.as_mut().unwrap().1;
        let (queue, pointer) = wire
            .held_tx
            .take()
            .ok_or("CLIENT actual held FRAME absent")?;
        wire.firmware.tx_complete(queue, pointer);
    }
    let result = run(tx, service)?;
    require(
        result.is_err() && native.current().is_err() && f.source.callback.lock().is_none(),
        "CLIENT final source callback retired native owner but FRAME succeeded",
    )
}
#[inline(never)]
fn profiles() -> R {
    for (api89, bz) in [
        (None, None),
        (Some(gen3_station_tests::Case::Ty), None),
        (Some(gen3_station_tests::Case::SoCdb), None),
        (Some(gen3_station_tests::Case::Ma), None),
        (
            None,
            Some(super::super::super::super::bz_fixture::Case::FmDiscrete),
        ),
        (
            None,
            Some(super::super::super::super::bz_fixture::Case::WhDiscrete),
        ),
    ] {
        let f = Fixture::new_role(api89, bz, true)?;
        register(&f, false)?;
        register_kind(&f, true, true)?;
        join(&f)?;
        let incoming = p2p::peer_action(OWN, AP);
        inject_public(&incoming);
        flush()?;
        require(
            p2p::received(&f.source.messages.lock(), &incoming) == 1,
            "CLIENT real original-source RX management absent",
        )?;
        let probe = p2p::probe_request(OWN, AP);
        inject_public(&probe);
        flush()?;
        let probe_filter = {
            let h = HARNESS.lock();
            h.as_ref()
                .unwrap()
                .1
                .commands
                .iter()
                .rev()
                .find(|(g, c, b)| (*g, *c) == (3, 8) && word(b, 8) == 7)
                .is_some_and(|(_, _, b)| word(b, 20) & 32 != 0 && b[36] == 1)
        };
        require(
            probe_filter && p2p::received(&f.source.messages.lock(), &probe) == 1,
            "CLIENT registered probe RX lacks actual associated MAC7 filter receipt",
        )?;
        let native = {
            let state = f.device().state.try_lock().ok_or("P2P client State")?;
            state
                .hardware
                .p2p_client_native()
                .ok_or("P2P client native role missing")?
        };
        require(
            native.plan.local_device == p2p::LOCAL_DEVICE
                && native.plan.peer_device.device == p2p::PEER_DEVICE
                && native.plan.own == OWN
                && native.plan.peer == AP
                && native.desired() == 32,
            "P2P client protocol addresses aliased physical/key ownership",
        )?;
        // A beacon to an unrelated unicast RA is not evidence for this
        // physical P2P client, even with exact peer SA/BSSID/channel/link.
        {
            let mut h = HARNESS.lock();
            let wire = &mut h.as_mut().unwrap().1;
            let mut beacon = p2p::beacon(wire.ap.beacon(), 9, Some(99));
            beacon[4..10].copy_from_slice(&[2, 0x99, 1, 2, 3, 4]);
            wire.mpdu(&beacon, false);
        }
        send(&f, 32)?;
        for _ in 0..65 {
            queued_beacon(7, Some(99), true)?;
        }
        queued_beacon(2, Some(0xa8), false)?;
        send(&f, 40)?;
        queued_beacon(3, None, false)?;
        send(&f, 0)?;
        for _ in 0..65 {
            queued_beacon(7, Some(99), true)?;
        }
        queued_beacon(4, Some(0xa8), false)?;
        let frame = p2p::public_frame(OWN, AP);
        public_frame(&f, &frame, false, true)?;
        let window = {
            let h = HARNESS.lock();
            h.as_ref()
                .unwrap()
                .1
                .commands
                .iter()
                .rev()
                .find(|(g, c, b)| (*g, *c) == (3, 8) && word(b, 8) == 7)
                .map(|(_, _, b)| word(b, 48))
        };
        require(
            window == Some(40),
            "CLIENT FRAME crossed queued native CTWindow without MAC7 ACK",
        )?;
        public_frame(&f, &frame, true, true)?;
        let before = HARNESS.lock().as_ref().unwrap().1.received.len();
        let mut eth = OWN.to_vec();
        eth.extend_from_slice(&AP);
        eth.extend_from_slice(&[0x88, 0xb5, 9, 8, 7]);
        {
            let mut h = HARNESS.lock();
            h.as_mut().unwrap().1.ethernet(&eth);
        }
        flush()?;
        require(
            HARNESS.lock().as_ref().unwrap().1.received.len() > before,
            "P2P client real key/PN RX absent",
        )?;
        run(f.device().disassociate(), service)?.map_err(|_| "P2P client terminal native close")?;
        let restored = {
            let h = HARNESS.lock();
            h.as_ref().unwrap().1.client_mac == 4
        };
        require(
            restored && native.current().is_err() && !f.device().link_up(),
            "P2P client old native role survived terminal default restoration",
        )?;
    }
    Ok(())
}
fn smoke_iwl_p2p_client_sc_bz_api89_real_station7_peer_ie_noa_and_key_data() -> TestResult {
    profiles().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/client",
    smoke_iwl_p2p_client_sc_bz_api89_real_station7_peer_ie_noa_and_key_data
);

#[inline(never)]
fn refusals() -> R {
    for malformed in 0..5 {
        let f = Fixture::new_role(None, None, true)?;
        if malformed == 4 {
            let mut h = HARNESS.lock();
            let wire = &mut h.as_mut().unwrap().1;
            wire.ap = FakeAp::wpa2(NETWORK, SSID, 6, 7, PMK, ANONCE)
                .and_then(|ap| ap.with_legacy_rates(&[2, 0x8c, 0x98, 0xb0]))
                .map_err(|_| "P2P client actual optional-CCK AP fixture")?;
        }
        super::super::scan(f.device())?;
        let mut request = super::super::request(true);
        request.ie = p2p::request();
        match malformed {
            0 => request.ie.clear(),
            1 => request.ie[10] = 1, // group capability: client cannot claim GO.
            2 => request.ie.extend_from_slice(&[0, 1, b'x']),
            3 => request.security = narf_wireless::SecurityConfig::Open,
            _ => {}
        }
        let before = HARNESS.lock().as_ref().unwrap().1.commands.len();
        require(
            run(f.device().associate(request), service)?.is_err(),
            "P2P client malformed/foreign authority reached native association",
        )?;
        let no_role = {
            let h = HARNESS.lock();
            let wire = &h.as_ref().unwrap().1;
            !wire.commands[before..]
                .iter()
                .any(|(g, c, b)| (*g, *c) == (3, 8) && word(b, 8) == 7)
        };
        require(
            no_role && !f.device().link_up(),
            "P2P client refused metadata published native role/carrier",
        )?;
    }
    let f = Fixture::new_role(None, None, true)?;
    join(&f)?;
    for malformed in 0..4 {
        let mut frame = p2p::public_frame(OWN, AP);
        match malformed {
            0 => frame[0] = 0xb0,
            1 => frame[10] = 4,
            2 => frame[1] = 0x40,
            _ => frame[24] = 8,
        }
        public_frame(&f, &frame, malformed & 1 != 0, false)?;
    }
    let old = {
        let state = f
            .device()
            .state
            .try_lock()
            .ok_or("P2P client original fence State")?;
        state.hardware.source_fence()?
    };
    let before = HARNESS.lock().as_ref().unwrap().1.data.len();
    let mut denied = policy();
    for rule in &mut denied.rules {
        rule.flags |= narf_wireless::reg::RegFlags::NO_P2P;
    }
    f.guard.policy_db.install(denied);
    let _ = f.device().enqueue(&data(), narf_net::TxMeta::default());
    for _ in 0..16 {
        f.device().step(None);
        let _ = service();
    }
    let after = HARNESS.lock().as_ref().unwrap().1.data.len();
    require(
        after == before && old.invoke(|| Ok(())).is_err(),
        "P2P client old source/program ignored current NO_P2P",
    )?;
    drop(f);
    let f = Fixture::new_role(None, None, true)?;
    join(&f)?;
    late_source(&f)?;
    drop(f);
    let f = Fixture::new_role(None, None, true)?;
    join(&f)?;
    let mut denied = policy();
    for rule in &mut denied.rules {
        rule.flags |= narf_wireless::reg::RegFlags::NO_IR;
    }
    f.guard.policy_db.install(denied);
    public_frame(&f, &p2p::public_frame(OWN, AP), true, false)?;
    drop(f);
    receive_retirement()
}
fn smoke_iwl_p2p_client_original_request_role_and_current_policy_refuse_before_rf() -> TestResult {
    check(refusals)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/client",
    smoke_iwl_p2p_client_original_request_role_and_current_policy_refuse_before_rf
);

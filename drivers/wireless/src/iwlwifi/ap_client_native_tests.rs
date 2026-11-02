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
        join(&f)?;
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
    )
}
fn smoke_iwl_p2p_client_original_request_role_and_current_policy_refuse_before_rf() -> TestResult {
    check(refusals)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/client",
    smoke_iwl_p2p_client_original_request_role_and_current_policy_refuse_before_rf
);

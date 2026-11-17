//! Original API77 GO9, separate tag9 and actual Qu/NoA/TX9 owner.
use super::*;
use crate::iwlwifi::p2p_go_fixture as wire;

/// Actual GO peer advertises OFDM6/12/24 only. API4 descriptor rate_n_flags
/// uses rates-v2 legacy OFDM format1/index0 =6Mbps (fw/api/rs.h).
fn uplink(pn: u64) -> Vec<u8> {
    let mut packet = super::uplink(pn);
    packet[28..32].copy_from_slice(&0x100u32.to_le_bytes());
    packet
}
#[inline(never)]
fn start_go(f: &Fixture) -> Result<(), &'static str> {
    f.admin.set_link(false).map_err(|_| "API77 GO DOWN")?;
    f.h.device
        .set_iftype(9)
        .map_err(|_| "API77 native GO9 mode")?;
    f.admin.set_link(true).map_err(|_| "API77 GO UP")?;
    let (config, settings) = config(true);
    let authority = f.authority()?;
    run(f
        .h
        .device
        .start_ap_with_settings_async(&authority, wire::decorate(config), settings))?
    .map_err(|_| "API77 GO tag9/native receipts")
}
#[inline(never)]
fn keys(f: &Fixture) -> Result<(), &'static str> {
    let mut peer = station(false, true);
    peer.supported_rates = vec![12, 24, 48];
    let a = f.authority()?;
    run(f.h.device.add_station_async(&a, peer))?.map_err(|_| "API77 GO OFDM peer")?;
    drop(a);
    f.key(0, TK)?;
    f.key(1, GTK)?;
    f.key(4, IGTK)?;
    let a = f.authority()?;
    run(f
        .h
        .device
        .default_key_ap_async(&a, 1, false, true, false, false))?
    .map_err(|_| "API77 GO actual GTK default")?;
    drop(a);
    let mut peer = station(true, true);
    peer.supported_rates = vec![12, 24, 48];
    let a = f.authority()?;
    run(f.h.device.set_station_async(&a, peer))?.map_err(|_| "API77 GO current key/port")
}
fn notice(f: &Fixture, mac: u32, index: u8, active: bool) {
    f.h.actor
        .lock()
        .inject(0xfc, 3, 0x8000, &wire::notice(mac, index, active));
}
#[inline(never)]
fn probe(f: &Fixture, index: Option<u8>) -> Result<(), &'static str> {
    let (config, _) = config(true);
    let request = narf_wireless::MgmtTxRequest {
        frequency_mhz: 2412,
        frame: wire::forge_probe(wire::decorate(config).probe_resp.unwrap(), PEER),
        duration: 0,
        offchannel_ok: false,
        no_cck: false,
    };
    let a = f.authority()?;
    run(f.h.device.mgmt_tx_ap_async(&a, 77, request))?.map_err(|_| "API77 GO native probe TX9")?;
    let frame = {
        f.h.actor
            .lock()
            .native_ap
            .as_ref()
            .unwrap()
            .tx
            .last()
            .ok_or("API77 GO posted native TX absent")?
            .1
            .clone()
    };
    wire::check_probe(&frame, OWN, index)
}
#[inline(never)]
fn public_probe(f: &Fixture, both: bool, index: u8) -> Result<(), &'static str> {
    let _ = narf_wireless::nl80211::register();
    let actual = narf_net::iface::lookup(f.h.device.name()).ok_or("API77 GO public IFINDEX")?;
    let wiphy = narf_wireless::registry::wiphy_index(f.h.device.wiphy_id())
        .ok_or("API77 GO public wiphy")?;
    let (config, _) = config(true);
    let frame = wire::forge_probe(wire::decorate(config).probe_resp.unwrap(), PEER);
    for sent in [None, Some(frame.as_slice())] {
        let request = wire::management_request(actual.ifindex, wiphy, 2412, sent, both);
        let before = f.source.messages.lock().len();
        let replies = narf_net::netlink_generic::build_replies_with_endpoint(
            &request,
            narf_net::netlink_generic::ReplyOptions::default(),
            narf_net::netlink_generic::RequestContext {
                admin: Some(&f.admin),
                portid: 77,
                ..Default::default()
            },
            f.source.clone(),
        )
        .map_err(|_| "API77 GO public P2P management parser")?;
        require(
            replies.is_empty(),
            "API77 GO public management escaped retained owner",
        )?;
        let mut done = false;
        for _ in 0..4096 {
            narf_scheduler::poll_one_round();
            f.h.actor.lock().serve()?;
            done = {
                let messages = f.source.messages.lock();
                wire::management_completed(&messages[before..], sent.is_some())?
            };
            if done {
                break;
            }
            // Native FRAME waits on Activity's real 1 ms fallback when
            // this RAM target supplies no IRQ. Drive that clock between
            // rounds, as once() does for the direct native conversation.
            narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
                2_000_000,
            )));
        }
        require(
            done,
            "API77 GO public management lacks native terminal receipt",
        )?;
    }
    let frame = {
        f.h.actor
            .lock()
            .native_ap
            .as_ref()
            .unwrap()
            .tx
            .last()
            .ok_or("API77 GO public FRAME missing physical TX")?
            .1
            .clone()
    };
    wire::check_probe(&frame, OWN, Some(index))
}
fn native_go() -> Result<(), &'static str> {
    // Declared first so the native fixture drops before its task graph.
    let _executor = ExecutorFixture::new();
    let _platform = Platform::new();
    let f = Fixture::new_emission(9)?;
    let result = native_go_conversation(&f);
    if result.is_err() {
        // Finish the actual retained native STOP before the fixture's
        // registration/source/Actor owners go away. This earns its own
        // firmware queue/DMA receipts; no fake owner reset hides an error.
        let stopped = run(f.h.device.stop_ap_retained());
        if !matches!(stopped, Ok(Ok(()))) {
            f.diagnose("GO first-error retained native STOP", &stopped);
        }
    }
    result
}
fn native_go_conversation(f: &Fixture) -> Result<(), &'static str> {
    f.h.actor
        .lock()
        .native_ap
        .as_mut()
        .unwrap()
        .arm_initial_noa();
    start_go(f)?;
    require(
        f.h.device.current_iftype() == 9
            && f.h.device.link_up()
            && f.h.device.p2p_interface_types().contains(&9)
            && f.h.device.p2p_interface_types().contains(&8),
        "API77 GO source scope/role",
    )?;
    keys(f)?;
    probe(f, Some(5))?;
    public_probe(f, false, 5)?;
    public_probe(f, true, 5)?;
    group_sequences(f)?;
    for _ in 0..65 {
        notice(f, 1, 8, true);
    }
    notice(f, 0, 7, true);
    probe(f, Some(7))?;
    notice(f, 1, 9, true);
    probe(f, Some(7))?;
    notice(f, 0, 0, false);
    probe(f, None)?;
    let pending = {
        let mut state = f.h.device.state.try_lock().ok_or("API77 GO prefix State")?;
        let hw = state
            .owner
            .as_mut()
            .ok_or("API77 GO prefix owner")?
            .ap_hardware();
        let foreign = hw
            .notifications
            .iter()
            .filter(|packet| {
                packet.header.group_id == 3
                    && packet.header.cmd == 0xfc
                    && packet.payload.get(..4) == Some(&1u32.to_le_bytes())
            })
            .count();
        (hw.notifications.len(), foreign)
    };
    // Final probe publication drained real RFH to observe MAC0's NoA behind
    // the65-record MAC1 prefix and one later foreign update. Those66 foreign
    // Session notifications still precede DATA; ap_step consumes at most64
    // of them in one pass. A second native pass reaches the original DATA.
    require(
        pending == (66, 66),
        "API77 GO lost actual >64 foreign NoA prefix",
    )?;
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(6));
    require(
        f.h.device.step(None).is_empty(),
        "API77 GO DATA overtook unfinished native notification prefix",
    )?;
    f.h.actor.lock().serve()?;
    let copied = f.h.device.step(None);
    let mut expected = OWN.to_vec();
    expected.extend_from_slice(&PEER);
    expected.extend_from_slice(&[0x88, 0xb5, 7]);
    require(
        copied.len() == 1 && copied[0].0 == expected,
        "API77 GO physical key/PN DATA",
    )?;
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(6));
    require(
        f.h.device.step(None).is_empty(),
        "API77 GO repeated native PN accepted",
    )?;
    let mut ethernet = PEER.to_vec();
    ethernet.extend_from_slice(&[2, 0x22, 3, 4, 5, 6]);
    ethernet.extend_from_slice(&[0x88, 0xb5, 1, 2, 3]);
    f.h.device
        .enqueue(&ethernet, narf_net::TxMeta::default())
        .map_err(|_| "API77 GO DATA enqueue")?;
    for _ in 0..64 {
        let _ = f.h.device.step(None);
        f.h.actor.lock().serve()?;
    }
    let posted = { f.h.actor.lock().native_ap.as_ref().unwrap().tx.clone() };
    require(
        posted.iter().any(|(station, frame, encrypted)| {
            *station == 2
                && *encrypted
                && frame[0] & 12 == 8
                && frame[4..10] == PEER
                && frame[16..22] == ethernet[6..12]
        }),
        "API77 GO native key-backed bridged DATA absent",
    )?;
    let a = f.authority()?;
    run(f.h.device.stop_ap_async(&a))?.map_err(|_| "API77 GO terminal native STOP")?;
    require(
        !f.h.device.link_up() && f.h.device.ap_stopped.load(Ordering::Acquire),
        "API77 GO STOP left autonomous owner armed",
    )
}
fn smoke_iwl_p2p_go_gen2_tag9_actual_qu_noa_prefix_peer_key_data_and_stop() -> TestResult {
    native_go().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/go/gen2",
    smoke_iwl_p2p_go_gen2_tag9_actual_qu_noa_prefix_peer_key_data_and_stop
);

fn wrong_purpose() -> Result<(), &'static str> {
    let _platform = Platform::new();
    // Same actual hardware/provider, but the existing AP-only record is
    // returned for the new GO binding. Tag9 parsing must refuse it before RF.
    let f = Fixture::new_emission(7)?;
    require(
        start_go(&f).is_err(),
        "API77 GO inherited ordinary tag7 qualification",
    )?;
    let native = {
        let actor = f.h.actor.lock();
        let ap = actor.native_ap.as_ref().unwrap();
        (ap.beacon, ap.tx.len(), ap.keys.len())
    };
    require(
        native == (false, 0, 0) && !f.h.device.link_up(),
        "API77 wrong-purpose GO record enabled beacon/packet/key owner",
    )
}
fn smoke_iwl_p2p_go_gen2_rejects_ordinary_ap_qualification_without_native_promotion() -> TestResult
{
    wrong_purpose().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/go/gen2",
    smoke_iwl_p2p_go_gen2_rejects_ordinary_ap_qualification_without_native_promotion
);

#[inline(never)]
fn sequence(f: &Fixture, id: u8, pn: u64) -> Result<(), &'static str> {
    {
        let a = f.authority()?;
        let result = run(f.h.device.key_sequence_ap_async(&a, id, false, None))?;
        if result.is_err() {
            f.diagnose(
                "GO key sequence (index, expected PN, result)",
                &(id, pn, &result),
            );
        }
        let seq = result.map_err(|_| "API77 GO actual group sequence")?;
        require(
            seq.seq == pn.to_le_bytes()[..6],
            "API77 GO group PN estimate/reset",
        )?;
    }
    let _ = narf_wireless::nl80211::register();
    let index = narf_net::iface::lookup(f.h.device.name())
        .ok_or("API77 GO GET_KEY IFINDEX")?
        .ifindex;
    let before = f.source.messages.lock().len();
    let replies = narf_net::netlink_generic::build_replies_with_endpoint(
        &wire::get_request(id, index),
        narf_net::netlink_generic::ReplyOptions::default(),
        narf_net::netlink_generic::RequestContext {
            admin: Some(&f.admin),
            portid: 77,
            ..Default::default()
        },
        f.source.clone(),
    )
    .map_err(|_| "API77 GO actual GET_KEY framing")?;
    require(replies.is_empty(), "API77 GO premature GET_KEY reply")?;
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
    }
    let reply = {
        let messages = f.source.messages.lock();
        messages[before..]
            .iter()
            .find(|message| message.len() >= 20 && message[16] == 11)
            .cloned()
            .ok_or("API77 GO GET_KEY result absent")?
    };
    wire::check_key_reply(&reply, id, pn)
}
#[inline(never)]
fn group_sequences(f: &Fixture) -> Result<(), &'static str> {
    sequence(f, 1, 0)?;
    sequence(f, 4, 0)?;
    {
        let a = f.authority()?;
        require(
            run(f.h.device.key_sequence_ap_async(&a, 0, true, Some(PEER)))? == Err(95),
            "API77 GO invented firmware PTK sequence",
        )?;
    }
    // Independently current admin/source/role facts do not make a second
    // Owner allocation the original Session-to-hardware START owner.
    let wrong_owner = {
        let authority = f.authority()?;
        let iface: Arc<dyn WirelessNetIface> = f.h.device.clone();
        crate::iwlwifi::ap_owner::Owner::new(
            Arc::downgrade(&iface),
            authority
                .identity()
                .map_err(|_| "API77 GO foreign owner identity")?,
            authority
                .event_authority()
                .map_err(|_| "API77 GO foreign owner event")?,
            authority
                .native_emission_for(f.h.device.as_ref())
                .map_err(|_| "API77 GO foreign current emission")?,
            f.h.device.ap_host.role.lock().observe(),
            Arc::new(AtomicBool::new(false)),
        )?
    };
    let (mcast, bcast) = {
        let actor = f.h.actor.lock();
        let model = actor
            .native_ap
            .as_ref()
            .ok_or("API77 GO native queue model")?;
        let queue = |station| {
            model
                .queues
                .iter()
                .find(|queue| queue.live && queue.station == station)
                .map(|queue| queue.id)
                .ok_or("API77 GO actual internal queue absent")
        };
        (
            queue(crate::iwlwifi::ap_wire::MCAST)?,
            queue(crate::iwlwifi::ap_wire::BCAST)?,
        )
    };
    let mut ethernet = vec![255; 6];
    ethernet.extend_from_slice(&OWN);
    ethernet.extend_from_slice(&[0x88, 0xb5, 1, 2, 3]);
    {
        let mut state = f.h.device.state.try_lock().ok_or("API77 GO group State")?;
        let State { owner, ap, .. } = &mut *state;
        let session = ap.as_mut().ok_or("API77 GO group actual role")?;
        let hw = owner
            .as_mut()
            .ok_or("API77 GO original native owner")?
            .ap_hardware();
        let (mut frame, header) =
            crate::iwlwifi::ap_wire::ethernet_qos_from_ap(OWN, 0, &ethernet, true, None)
                .ok_or("API77 GO physical group frame")?;
        let before = session
            .key_sequence(1, false, None)
            .map_err(|_| "API77 GO current host PN before queue refusal")?;
        let original = core::mem::replace(&mut session.proof, wrong_owner);
        let wrong = hw.enqueue_go_group(session, mcast, &mut frame, header, None);
        session.proof = original;
        require(
            wrong.is_err(),
            "API77 GO host GTK accepted another current Owner allocation",
        )?;
        require(
            hw.enqueue_go_group(session, bcast, &mut frame, header, None)
                .is_err(),
            "API77 GO host GTK posted through foreign BCAST queue",
        )?;
        require(
            session.key_sequence(1, false, None) == Ok(before),
            "API77 GO wrong owner/queue consumed GTK PN",
        )?;
        hw.source_fence()?
            .invoke(|| session.protect_go_group(&mut frame, header))?;
        require(
            hw.enqueue_transmit_ap(mcast, &frame, header, None, false, 0)
                .is_err(),
            "API77 GO raw protected bytes bypassed actual host key owner",
        )?;
        require(
            hw.enqueue_transmit_ap(u16::MAX, &frame, header, None, false, 0)
                .is_err(),
            "API77 GO unowned queue accepted consumed GTK PN",
        )?;
        let mut frame = wire::robust(OWN);
        hw.source_fence()?
            .invoke(|| session.protect_host_bip(&mut frame))?;
        require(
            hw.enqueue_transmit_ap(u16::MAX, &frame, 24, None, false, 0)
                .is_err(),
            "API77 GO unowned queue accepted consumed IGTK IPN",
        )?;
    }
    sequence(f, 1, 1)?;
    sequence(f, 4, 1)?;
    f.h.device
        .enqueue(&ethernet, narf_net::TxMeta::default())
        .map_err(|_| "API77 GO group enqueue")?;
    for _ in 0..64 {
        let _ = f.h.device.step(None);
        f.h.actor.lock().serve()?;
    }
    sequence(f, 1, 2)?;
    f.h.device
        .enqueue(
            &wire::udp_group(OWN),
            narf_net::TxMeta {
                csum_l4: Some(narf_net::L4CsumKind::Udp),
                ..Default::default()
            },
        )
        .map_err(|_| "API77 GO host crypto UDP partial enqueue")?;
    for _ in 0..64 {
        let _ = f.h.device.step(None);
        f.h.actor.lock().serve()?;
    }
    sequence(f, 1, 3)?;
    {
        let a = f.authority()?;
        let request = narf_wireless::MgmtTxRequest {
            frequency_mhz: 2412,
            frame: wire::robust(OWN),
            offchannel_ok: false,
            duration: 0,
            no_cck: false,
        };
        run(f.h.device.mgmt_tx_ap_async(&a, 88, request))?
            .map_err(|_| "API77 GO real host BIP TX")?;
    }
    sequence(f, 4, 2)?;
    let frame = {
        f.h.actor
            .lock()
            .native_ap
            .as_ref()
            .unwrap()
            .tx
            .last()
            .ok_or("API77 GO BIP TX absent")?
            .1
            .clone()
    };
    let mut receiver = narf_wireless::mfp::MfpKeyStore::new();
    receiver
        .install_active(IGTK, 4)
        .map_err(|_| "API77 GO independent BIP key")?;
    require(
        narf_wireless::mfp::verify_inbound(&mut receiver, &frame[..24], &frame[24..]).is_ok(),
        "API77 GO IPN query lacks real CMAC wire proof",
    )?;
    Ok(())
}

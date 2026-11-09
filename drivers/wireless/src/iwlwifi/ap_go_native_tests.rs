//! Public GO9 and actual MAC0/NoA/probe/key/data ownership, all native ABIs.
use super::*;
use crate::iwlwifi::p2p_go_fixture as wire;
#[inline(never)]
fn into_go(f: &Fixture) -> R {
    require(
        f.device().p2p_interface_types().contains(&9)
            && f.device().p2p_interface_types().contains(&8),
        "GO/CLIENT implemented subset absent",
    )?;
    f.admin.set_link(false).map_err(|_| "GO original DOWN")?;
    f.device()
        .set_iftype(9)
        .map_err(|_| "GO actual netdev role")?;
    f.admin.set_link(true).map_err(|_| "GO original UP")?;
    let (config, settings) = config(true);
    let config = wire::decorate(config);
    let authority = f.authority()?;
    run(
        f.device()
            .start_ap_with_settings_async(&authority, config, settings),
        service,
    )?
    .map_err(|_| "GO actual native START and role-qualified program")?;
    drop(authority);
    let mut peer = station(PEER, 7, true);
    peer.supported_rates = vec![12, 24, 48];
    let authority = f.authority()?;
    run(f.device().add_station_async(&authority, peer), service)?
        .map_err(|_| "GO OFDM peer/TLC receipts")?;
    drop(authority);
    f.key(0, true, Some(PEER), TK)?;
    f.key(1, false, None, GTK)?;
    f.key(4, false, None, IGTK)?;
    let authority = f.authority()?;
    run(
        f.device()
            .default_key_ap_async(&authority, 1, false, true, false, false),
        service,
    )?
    .map_err(|_| "GO native default GTK")?;
    drop(authority);
    let mut peer = station(PEER, 7, true);
    peer.supported_rates = vec![12, 24, 48];
    peer.authorized = Some(true);
    let authority = f.authority()?;
    run(f.device().set_station_async(&authority, peer), service)?
        .map_err(|_| "GO actual authorized/key port")?;
    Ok(())
}
#[inline(never)]
fn probe(f: &Fixture, index: Option<u8>) -> R {
    let (config, _) = config(true);
    let probe = wire::forge_probe(wire::decorate(config).probe_resp.unwrap(), PEER);
    let request = narf_wireless::MgmtTxRequest {
        frequency_mhz: 2437,
        frame: probe,
        offchannel_ok: false,
        duration: 0,
        no_cck: false,
    };
    let authority = f.authority()?;
    run(
        f.device().mgmt_tx_ap_async(&authority, 77, request),
        service,
    )?
    .map_err(|_| "GO actual native probe publication/status")?;
    let frame = {
        HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .native_ap
            .as_ref()
            .unwrap()
            .tx
            .last()
            .ok_or("GO native TX absent")?
            .1
            .clone()
    };
    wire::check_probe(&frame, OWN, index)
}
#[inline(never)]
fn public_probe(f: &Fixture, both: bool, index: u8) -> R {
    let _ = narf_wireless::nl80211::register();
    let actual = narf_net::iface::lookup(f.device().name()).ok_or("GO public IFINDEX")?;
    let wiphy =
        narf_wireless::registry::wiphy_index(f.device().wiphy_id()).ok_or("GO public wiphy")?;
    let iface: Arc<dyn WirelessNetIface> = f.device().clone();
    // A valid unreserved original Radio guard still cannot become an AP
    // operation. The actual native serialization receipt remains mandatory.
    let unreserved = narf_wireless::ap_control::RadioControlAuthority::bind(
        f.admin.clone(),
        &iface,
        0,
        actual.ifindex,
        f.source.clone(),
    )
    .map_err(|_| "GO public original Radio bind")?;
    require(
        unreserved.go_ap_control_for(f.device().as_ref()).is_err(),
        "GO Radio-to-AP view invented a native reservation",
    )?;
    drop(unreserved);
    let (config, _) = config(true);
    let frame = wire::forge_probe(wire::decorate(config).probe_resp.unwrap(), PEER);
    for sent in [None, Some(frame.as_slice())] {
        let request = wire::management_request(actual.ifindex, wiphy, 2437, sent, both);
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
        .map_err(|_| "GO public FRAME/REGISTER parser refused original selectors")?;
        require(
            replies.is_empty(),
            "GO public management escaped native deferred owner",
        )?;
        let mut done = false;
        for _ in 0..4096 {
            narf_scheduler::poll_one_round();
            service()?;
            done = {
                let messages = f.source.messages.lock();
                wire::management_completed(&messages[before..], sent.is_some())?
            };
            if done {
                break;
            }
        }
        require(
            done,
            "GO public management did not complete native receipts",
        )?;
    }
    let frame = {
        HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .native_ap
            .as_ref()
            .unwrap()
            .tx
            .last()
            .ok_or("GO public FRAME never reached physical TX")?
            .1
            .clone()
    };
    wire::check_probe(&frame, OWN, Some(index))
}
#[inline(never)]
fn notice(mac: u32, index: u8, active: bool) {
    HARNESS.lock().as_mut().unwrap().1.firmware.inject(
        0xfc,
        3,
        0x8000,
        &wire::notice(mac, index, active),
    );
}
#[inline(never)]
fn go_profiles() -> R {
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
        let f = Fixture::new(api89, bz)?;
        HARNESS
            .lock()
            .as_mut()
            .unwrap()
            .1
            .native_ap
            .as_mut()
            .unwrap()
            .arm_initial_noa();
        into_go(&f)?;
        // The first current NoA was copied before the new MAC ADD ACK,
        // while the original GO was still preparing and DATA RX closed.
        probe(&f, Some(5))?;
        public_probe(&f, false, 5)?;
        public_probe(&f, true, 5)?;
        group_sequences(&f)?;
        // Native END/NoA is beyond a normal64-descriptor drain. Foreign MAC
        // facts cannot qualify it; the final native publication must drain.
        for _ in 0..65 {
            notice(1, 8, true);
        }
        notice(0, 7, true);
        probe(&f, Some(7))?;
        notice(1, 9, true);
        probe(&f, Some(7))?;
        notice(0, 0, false);
        probe(&f, None)?;
        let prior = observed_data();
        f.device()
            .enqueue(&ethernet(PEER, 0x0806), narf_net::TxMeta::default())
            .map_err(|_| "GO authorized DATA enqueue")?;
        flush()?;
        require(
            observed_data() > prior,
            "GO current real key/port did not publish DATA",
        )?;
        let received = inject_uplink(1, true, true, 2, 1, 0x0800)?;
        flush()?;
        let _ = inject_uplink(1, true, true, 2, 1, 0x0800)?;
        flush()?;
        let delivered = HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .received
            .iter()
            .filter(|frame| **frame == received)
            .count();
        require(
            delivered == 1,
            "GO actual key/PN owner accepted duplicate or lost current RX",
        )?;
    }
    Ok(())
}
fn smoke_iwl_p2p_go_native_sc_bz_api89_ofdm_noa_prefix_and_secured_data_owner() -> TestResult {
    go_profiles().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/go",
    smoke_iwl_p2p_go_native_sc_bz_api89_ofdm_noa_prefix_and_secured_data_owner
);

#[inline(never)]
fn schema_denials() -> R {
    // Adjacent regulatory endpoints do not occupy the GO's20MHz span.
    let channel = crate::iwlwifi::native_band::Channel::legacy(6).unwrap();
    for high in [false, true] {
        let mut domain = policy();
        let mut rule = domain.rules[0].clone();
        rule.flags |= narf_wireless::reg::RegFlags::NO_P2P;
        if high {
            rule.freq_start_mhz = 2447;
            rule.freq_end_mhz = 2467;
        } else {
            rule.freq_start_mhz = 2407;
            rule.freq_end_mhz = 2427;
        }
        domain.rules.push(rule);
        require(
            crate::iwlwifi::p2p_go::host_allows(&domain, channel),
            "GO adjacent NO_P2P rule denied unoccupied boundary",
        )?;
        if high {
            domain.rules.last_mut().unwrap().freq_start_mhz -= 1;
        } else {
            domain.rules.last_mut().unwrap().freq_end_mhz += 1;
        }
        require(
            !crate::iwlwifi::p2p_go::host_allows(&domain, channel),
            "GO true1MHz NO_P2P overlap admitted",
        )?;
    }
    for bad in 0..3 {
        let f = Fixture::new(None, None)?;
        f.admin.set_link(false).map_err(|_| "GO malformed DOWN")?;
        f.device()
            .set_iftype(9)
            .map_err(|_| "GO malformed actual role")?;
        f.admin.set_link(true).map_err(|_| "GO malformed UP")?;
        let (config, settings) = config(true);
        let mut config = wire::decorate(config);
        if bad == 0 {
            // Actual GO flag in the capability attr, not a host role enum.
            let pos = config
                .beacon_head
                .windows(5)
                .position(|raw| raw == [2, 2, 0, 0x25, 1])
                .ok_or("GO literal capability fixture")?;
            config.beacon_head[pos + 4] = 0;
        } else if bad == 1 {
            // Protocol device address is independently bound in probe.
            let probe = config.probe_resp.as_mut().unwrap();
            let pos = probe
                .windows(6)
                .position(|raw| raw == wire::DEVICE)
                .ok_or("GO literal device info fixture")?;
            probe[pos + 5] ^= 1;
        } else {
            let pos = config
                .beacon_head
                .windows(5)
                .position(|raw| raw == [1, 3, 0x8c, 0x98, 0xb0])
                .ok_or("GO literal OFDM rates fixture")?;
            config.beacon_head[pos + 2] = 0x82;
        }
        let a = f.authority()?;
        require(
            run(
                f.device()
                    .start_ap_with_settings_async(&a, config, settings),
                service,
            )?
            .is_err(),
            "GO malformed/unsupported scope reached native START",
        )?;
        let (beacon, tx) = {
            let h = HARNESS.lock();
            let ap = h.as_ref().unwrap().1.native_ap.as_ref().unwrap();
            (ap.beacon, ap.tx.len())
        };
        require(
            !beacon && tx == 0 && !f.device().link_up(),
            "GO rejected metadata promoted beacon/packet/carrier",
        )?;
    }
    Ok(())
}
#[inline(never)]
fn source_denials() -> R {
    for boundary in 0..4 {
        let f = Fixture::new(None, None)?;
        into_go(&f)?;
        notice(0, 7, true);
        probe(&f, Some(7))?;
        let before = {
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .native_ap
                .as_ref()
                .unwrap()
                .tx
                .len()
        };
        let original = f.authority()?;
        match boundary {
            0 => f.source.owner.retire().notify(),
            1 => {
                f.admin.set_link(false).map_err(|_| "GO source DOWN")?;
                f.admin.set_link(true).map_err(|_| "GO source UP")?;
            }
            2 => {
                let mut denied = policy();
                for rule in &mut denied.rules {
                    rule.flags |= narf_wireless::reg::RegFlags::NO_P2P;
                }
                f.guard.policy_db.install(denied);
            }
            _ => {
                require(
                    f.device().set_iftype(3) == Err(WirelessError::Busy)
                        && f.device().set_iftype(8) == Err(WirelessError::Busy)
                        && f.device().supports_p2p_go_power_save(),
                    "GO active role allowed retype or lost GO PS contract",
                )?;
                f.daemon.revoke();
            }
        }
        require(
            run(
                f.device().key_sequence_ap_async(&original, 1, false, None),
                service,
            )?
            .is_err(),
            "GO stale original GET_KEY source returned a group sequence",
        )?;
        drop(original);
        // Queued old NoA and its cached predecessor cannot lend the new
        // request an original native/program/source owner.
        notice(0, 9, true);
        require(
            probe(&f, Some(9)).is_err(),
            "GO retired source/program emitted cached probe",
        )?;
        for _ in 0..16 {
            let _ = f.device().step(None);
            let _ = service();
        }
        let after = {
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .native_ap
                .as_ref()
                .unwrap()
                .tx
                .len()
        };
        require(
            after == before,
            "GO stale NoA/source/role published actual native TX",
        )?;
    }
    Ok(())
}
fn smoke_iwl_p2p_go_native_shape_no_cck_and_current_source_policy_refusals() -> TestResult {
    check(|| {
        schema_denials()?;
        source_denials()
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/go",
    smoke_iwl_p2p_go_native_shape_no_cck_and_current_source_policy_refusals
);

#[inline(never)]
fn sequence(f: &Fixture, id: u8, pn: u64) -> R {
    {
        let a = f.authority()?;
        let seq = run(
            f.device().key_sequence_ap_async(&a, id, false, None),
            service,
        )?
        .map_err(|_| "GO actual group key sequence")?;
        require(
            seq.seq == pn.to_le_bytes()[..6],
            "GO GET_KEY estimated or reset actual group PN",
        )?;
    }
    let _ = narf_wireless::nl80211::register();
    let index = narf_net::iface::lookup(f.device().name())
        .ok_or("GO key IFINDEX")?
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
    .map_err(|_| "GO actual GET_KEY netlink framing")?;
    require(
        replies.is_empty(),
        "GO GET_KEY replied before retained callback",
    )?;
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
    }
    let reply = {
        let messages = f.source.messages.lock();
        messages[before..]
            .iter()
            .find(|message| message.len() >= 20 && message[16] == 11)
            .cloned()
            .ok_or("GO public GET_KEY result absent")?
    };
    wire::check_key_reply(&reply, id, pn)
}
#[inline(never)]
fn group_sequences(f: &Fixture) -> R {
    sequence(f, 1, 0)?;
    sequence(f, 4, 0)?;
    {
        let a = f.authority()?;
        require(
            run(
                f.device().key_sequence_ap_async(&a, 0, true, Some(PEER)),
                service,
            )? == Err(95),
            "GO firmware PTK PN was invented",
        )?;
    }
    // Exercise the actual installed host key before an explicitly rejected
    // native queue. These reserved PNs never reached firmware or the air.
    {
        let mut state = f.device().state.try_lock().ok_or("GO sequence State")?;
        let State { hardware, ap, .. } = &mut *state;
        let session = ap.as_mut().ok_or("GO sequence actual owner")?;
        let (mut frame, header) = crate::iwlwifi::ap_wire::ethernet_qos_from_ap(
            OWN,
            0,
            &ethernet([255; 6], 0x88b5),
            true,
            None,
        )
        .ok_or("GO sequence frame")?;
        hardware
            .source_fence()?
            .invoke(|| session.protect_go_group(&mut frame, header))?;
        require(
            hardware
                .enqueue_transmit_ap(u16::MAX, &frame, header, None, false, 0)
                .is_err(),
            "GO unowned native queue accepted reserved GTK PN",
        )?;
        let mut frame = wire::robust(OWN);
        hardware
            .source_fence()?
            .invoke(|| session.protect_host_bip(&mut frame))?;
        require(
            hardware
                .enqueue_transmit_ap(u16::MAX, &frame, 24, None, false, 0)
                .is_err(),
            "GO unowned native queue accepted reserved IGTK IPN",
        )?;
    }
    sequence(f, 1, 1)?;
    sequence(f, 4, 1)?;
    f.device()
        .enqueue(&ethernet([255; 6], 0x88b5), narf_net::TxMeta::default())
        .map_err(|_| "GO host CCMP multicast enqueue")?;
    flush()?;
    sequence(f, 1, 2)?;
    f.device()
        .enqueue(
            &wire::udp_group(OWN),
            narf_net::TxMeta {
                csum_l4: Some(narf_net::L4CsumKind::Udp),
                ..Default::default()
            },
        )
        .map_err(|_| "GO host crypto UDP partial enqueue")?;
    flush()?;
    sequence(f, 1, 3)?;
    {
        let a = f.authority()?;
        let request = narf_wireless::MgmtTxRequest {
            frequency_mhz: 2437,
            frame: wire::robust(OWN),
            offchannel_ok: false,
            duration: 0,
            no_cck: false,
        };
        run(f.device().mgmt_tx_ap_async(&a, 88, request), service)?
            .map_err(|_| "GO actual host BIP TX")?;
    }
    sequence(f, 4, 2)?;
    let frame = {
        HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .native_ap
            .as_ref()
            .unwrap()
            .tx
            .last()
            .ok_or("GO actual host BIP radio frame absent")?
            .1
            .clone()
    };
    let mut receiver = narf_wireless::mfp::MfpKeyStore::new();
    receiver
        .install_active(IGTK, 4)
        .map_err(|_| "GO independent BIP receiver")?;
    require(
        narf_wireless::mfp::verify_inbound(&mut receiver, &frame[..24], &frame[24..]).is_ok(),
        "GO GET_KEY IPN lacks genuine on-air CMAC",
    )?;
    {
        let a = f.authority()?;
        run(f.device().del_key_ap_async(&a, 1, false, None), service)?
            .map_err(|_| "GO actual host GTK deletion")?;
    }
    {
        let a = f.authority()?;
        require(
            run(
                f.device().key_sequence_ap_async(&a, 1, false, None),
                service,
            )? == Err(2),
            "GO deleted GTK retained GET_KEY PN authority",
        )?;
    }
    require(
        f.key(1, false, None, GTK).is_err(),
        "GO retired GTK material restarted exact PN",
    )?;
    f.key(2, false, None, [0x44; 16])?;
    {
        let a = f.authority()?;
        run(
            f.device()
                .default_key_ap_async(&a, 2, false, true, false, false),
            service,
        )?
        .map_err(|_| "GO fresh host GTK default")?;
    }
    sequence(f, 2, 0)?;
    Ok(())
}

#[inline(never)]
fn template_noa(body: &[u8]) -> R<Vec<u8>> {
    // Firmware beacon template: 32-byte header, then the beacon frame
    // (36-byte 802.11 header + elements).
    let beacon = body.get(32..).ok_or("GO PS template extent")?;
    let elements = beacon.get(36..).ok_or("GO PS beacon extent")?;
    let mut attrs: Vec<u8> = Vec::new();
    let mut rest = elements;
    while !rest.is_empty() {
        let len = usize::from(*rest.get(1).ok_or("GO PS IE header")?);
        let end = 2 + len;
        let part = rest.get(2..end).ok_or("GO PS IE extent")?;
        if rest[0] == 221 && part.starts_with(&[0x50, 0x6f, 0x9a, 9]) {
            attrs.extend_from_slice(&part[4..]);
        }
        rest = rest.get(end..).ok_or("GO PS IE overrun")?;
    }
    let mut raw = attrs.as_slice();
    while !raw.is_empty() {
        let header = raw.get(..3).ok_or("GO PS attribute header")?;
        let len = usize::from(u16::from_le_bytes([header[1], header[2]]));
        let attr = raw.get(..3 + len).ok_or("GO PS attribute extent")?;
        if header[0] == 12 {
            return Ok(attr.to_vec());
        }
        raw = &raw[3 + len..];
    }
    Err("GO PS template omitted NoA attribute")
}

#[inline(never)]
fn templates() -> R<Vec<Vec<u8>>> {
    let slot = HARNESS.lock();
    let commands = &slot.as_ref().ok_or("GO PS harness")?.1.commands;
    Ok(commands
        .iter()
        .filter(|(g, c, _)| (*g, *c) == (1, 0x91))
        .map(|(_, _, body)| body.clone())
        .collect())
}

#[inline(never)]
fn go_ps() -> R {
    // Start-time setter: CTWindow 4 + opportunistic -> index 0, 0x84.
    let f = Fixture::new(None, None)?;
    f.admin.set_link(false).map_err(|_| "GO PS DOWN")?;
    f.device().set_iftype(9).map_err(|_| "GO PS role")?;
    f.admin.set_link(true).map_err(|_| "GO PS UP")?;
    require(
        f.device().supports_p2p_go_power_save(),
        "GO device lost PS contract",
    )?;
    let (config, mut settings) = config(true);
    settings.p2p_go = Some(narf_wireless::P2pGoPowerSave {
        ctwindow_tu: Some(4),
        opportunistic: Some(true),
    });
    let config = wire::decorate(config);
    let a = f.authority()?;
    run(
        f.device()
            .start_ap_with_settings_async(&a, config, settings),
        service,
    )?
    .map_err(|_| "GO PS START rejected")?;
    drop(a);
    let sent = templates()?;
    require(!sent.is_empty(), "GO PS start sent no beacon template")?;
    require(
        template_noa(sent.first().unwrap())? == [12, 2, 0, 0, 0x84],
        "GO PS start template NoA is not index 0 CTWindow 4 OPPPS",
    )?;
    // Live update: CTWindow 10, opportunistic preserved -> index 1, 0x8a.
    let a = f.authority()?;
    run(
        f.device().set_p2p_go_power_save_ap_async(
            &a,
            narf_wireless::P2pGoPowerSave {
                ctwindow_tu: Some(10),
                opportunistic: None,
            },
        ),
        service,
    )?
    .map_err(|_| "GO PS live update rejected")?;
    drop(a);
    let sent = templates()?;
    require(sent.len() >= 2, "GO PS live update sent no new template")?;
    require(
        template_noa(sent.last().unwrap())? == [12, 2, 0, 1, 0x8a],
        "GO PS live template NoA is not index 1 CTWindow 10 OPPPS",
    )?;
    // Explicit reset: CTWindow 0 + OPPPS off -> index 2, 0x00.
    let a = f.authority()?;
    run(
        f.device().set_p2p_go_power_save_ap_async(
            &a,
            narf_wireless::P2pGoPowerSave {
                ctwindow_tu: Some(0),
                opportunistic: Some(false),
            },
        ),
        service,
    )?
    .map_err(|_| "GO PS reset rejected")?;
    drop(a);
    let sent = templates()?;
    require(
        template_noa(sent.last().unwrap())? == [12, 2, 0, 2, 0x00],
        "GO PS reset template NoA is not index 2 zero",
    )?;
    // CTWindow beyond the 7-bit field is refused, not truncated.
    // Drop the previous fixture first: a `let` RHS is evaluated before
    // the old binding drops, so without this the new Guard builds while
    // the old fixture still owns the interface and its live-owner
    // require fails ("live iwlwifi owner exists").
    drop(f);
    let f = Fixture::new(None, None)?;
    f.admin.set_link(false).map_err(|_| "GO PS bad DOWN")?;
    f.device().set_iftype(9).map_err(|_| "GO PS bad role")?;
    f.admin.set_link(true).map_err(|_| "GO PS bad UP")?;
    let (config, mut settings) = self::config(true);
    settings.p2p_go = Some(narf_wireless::P2pGoPowerSave {
        ctwindow_tu: Some(200),
        opportunistic: Some(true),
    });
    let config = wire::decorate(config);
    let a = f.authority()?;
    require(
        run(
            f.device()
                .start_ap_with_settings_async(&a, config, settings),
            service,
        )?
        .is_err()
            && !f.device().link_up(),
        "GO PS CTWindow 200 reached native START",
    )?;
    // Ordinary APs still refuse GO power-save fields.
    // (See above: the previous fixture must be dropped before rebinding,
    // or the new Guard's live-owner require fails.)
    drop(f);
    let f = Fixture::new(None, None)?;
    f.admin.set_link(false).map_err(|_| "AP PS DOWN")?;
    f.admin.set_link(true).map_err(|_| "AP PS UP")?;
    let (config, mut settings) = self::config(true);
    settings.p2p_go = Some(narf_wireless::P2pGoPowerSave {
        ctwindow_tu: Some(4),
        opportunistic: Some(true),
    });
    let a = f.authority()?;
    require(
        run(
            f.device()
                .start_ap_with_settings_async(&a, config, settings),
            service,
        )?
        .is_err(),
        "ordinary AP accepted GO power-save fields",
    )?;
    Ok(())
}
fn smoke_iwl_p2p_go_native_ps_setter_beacon_template() -> TestResult {
    check(go_ps)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/go",
    smoke_iwl_p2p_go_native_ps_setter_beacon_template
);

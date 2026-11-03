// SPDX-License-Identifier: GPL-2.0-or-later
//! P2P discovery/connection owners over the scripted FullMAC seam (both
//! families): Linux 7.3-rc4 `p2p.c` request order, wire layouts, events.
//! Written cases; their execution is pending.
use super::{
    p2p::{Device, Notice},
    p2p_wire::{self as wire, DiscState, P2pIfType},
    vif_owner::{admits_counts, Counts, Owner, Role},
    vif_wire::Features,
};
use crate::cyw43439::{
    fullmac_fixture::{Firmware, Mock},
    ioctl::Direction,
    runtime::Error,
};
use alloc::{boxed::Box, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const PRIMARY: [u8; 6] = [0x00, 0x90, 0x4c, 0x11, 0x22, 0x33];
const PEER: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

fn p2p_features() -> Features {
    Features {
        p2p: true,
        mchan: true,
        ..Features::default()
    }
}

fn block<F: core::future::Future>(future: F) -> F::Output {
    narf_scheduler::block_on(future)
}

/// GO Negotiation Request public action frame from the device to PEER.
fn gon_req(device: [u8; 6]) -> Vec<u8> {
    let mut frame = alloc::vec![0u8; 24];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&PEER);
    frame[10..16].copy_from_slice(&device);
    frame[16..22].copy_from_slice(&PEER);
    frame.extend_from_slice(&[4, 9, 0x50, 0x6f, 0x9a, 9, wire::PAF_GON_REQ, 7]);
    frame
}

fn smoke_brcmf_p2p_wire_layouts_and_action_policy() -> TestResult {
    if wire::disc_state(DiscState::Listen, 0x1006, 500) != [1, 0x06, 0x10, 0xf4, 0x01]
        || wire::p2p_if(PEER, P2pIfType::Go, 0x100b)
            != [2, 0x11, 0x22, 0x33, 0x44, 0x55, 1, 0, 0x0b, 0x10]
    {
        return TestResult::Fail("p2p_state / p2p_ifadd layout");
    }
    // brcmf_p2p_generate_bss_mac: universal primary -> local admin bit;
    // connection addresses flip byte 4.
    let addresses = wire::generate_bss_mac(PRIMARY, None, [0; 6]);
    if addresses.device != [0x02, 0x90, 0x4c, 0x11, 0x22, 0x33]
        || addresses.connection != [0x02, 0x90, 0x4c, 0x11, 0xa2, 0x33]
        || addresses.connection2 != [0x02, 0x90, 0x4c, 0x11, 0xb2, 0x33]
        || wire::generate_bss_mac(PRIMARY, Some(PEER), [0; 6]).device != PEER
    {
        return TestResult::Fail("P2P address derivation");
    }
    let device = addresses.device;
    let Ok(params) = wire::af_params(&gon_req(device), 6, 300, 0x1_0000_0042) else {
        return TestResult::Fail("af_params refused a public action frame");
    };
    if params.len() != wire::AF_PARAMS_LEN
        || wire::af_channel(&params) != 6
        || wire::af_dwell(&params) != 300
        || params[8..14] != PEER
        || wire::af_da(&params) != PEER
        || params[22..24] != 8u16.to_le_bytes()
        || params[24..28] != 0x42u32.to_le_bytes()
        || wire::af_body(&params) != &gon_req(device)[24..]
    {
        return TestResult::Fail("brcmf_fil_af_params_le layout");
    }
    let Some(policy) = wire::af_policy(wire::af_body(&params)) else {
        return TestResult::Fail("GON request not classified");
    };
    if policy.mpc != Some(false)
        || !policy.search_channel
        || policy.dwell_ms != wire::AF_MED_DWELL_TIME
        || policy.next_subtype != wire::PAF_GON_RSP
        || policy.go_neg_phase != Some(true)
    {
        return TestResult::Fail("brcmf_p2p_pub_af_tx GON request policy");
    }
    // Provision discovery with a Group ID attribute does not search.
    let provdis = [
        4,
        9,
        0x50,
        0x6f,
        0x9a,
        9,
        wire::PAF_PROVDIS_REQ,
        1,
        221,
        8,
        0x50,
        0x6f,
        0x9a,
        9,
        15,
        1,
        0,
        0,
    ];
    let gas_resp = [4, wire::GAS_IRESP, 1];
    if wire::af_policy(&provdis).map(|p| p.search_channel) != Some(false)
        || wire::af_policy(&gas_resp).map(|p| p.dwell_ms) != Some(wire::AF_MIN_DWELL_TIME)
        || wire::af_policy(&[3, 0, 0, 0, 0, 0, 0, 0]).is_some()
    {
        return TestResult::Fail("provision/GAS/unknown frame policy");
    }
    let mut event = alloc::vec![0u8; 16];
    event[2..4].copy_from_slice(&0x1006u16.to_be_bytes());
    event.extend_from_slice(&[4, 9]);
    let Ok(rx) = wire::parse_rx_action(18, &event) else {
        return TestResult::Fail("rx_mgmt_data decode");
    };
    if rx.chanspec != 0x1006
        || wire::chanspec_frequency(rx.chanspec) != Some(2437)
        || rx.body != [4, 9]
        || wire::parse_rx_action(15, &event).is_ok()
        || wire::parse_rx_action(40, &event).is_ok()
    {
        return TestResult::Fail("rx_mgmt_data bounds");
    }
    // brcmf_setup_ifmodes P2P limits.
    let features = p2p_features();
    let mut device_go = Counts {
        stations: 1,
        ..Counts::default()
    };
    device_go.add(Role::P2pDevice);
    device_go.add(Role::P2pGo);
    let mut two_conn = device_go;
    two_conn.add(Role::P2pClient);
    if !admits_counts(features, device_go)
        || admits_counts(features, two_conn)
        || admits_counts(Features::default(), device_go)
    {
        return TestResult::Fail("P2P interface combinations");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/p2p",
    smoke_brcmf_p2p_wire_layouts_and_action_policy
);

/// Firmware answering the discovery bsscfg on ifidx 1 / bsscfg 1. Its IF
/// events carry NOIF + role P2P_CLIENT, which `brcmf_fweh_handle_if_event`
/// classifies as the P2P device also outside `p2pdev_setup_ongoing` (a
/// STA-role DEL would be ignored there and the removal would time out).
fn discovery_firmware(device: [u8; 6]) -> Firmware {
    let mut fw = Firmware::new();
    fw.caps = b"ap sta wme p2p mchan".to_vec();
    fw.hook = Some(Box::new(move |fw, command| {
        let set = command.direction == Direction::Set;
        match command.iovar() {
            Some(b"p2p_disc") if set && command.value() == 1u32.to_le_bytes() => {
                // Only the first enable creates the discovery bsscfg.
                if fw
                    .iovars(Direction::Set, b"p2p_disc")
                    .iter()
                    .filter(|v| v[..] == 1u32.to_le_bytes())
                    .count()
                    == 1
                {
                    fw.if_event_flags(1, 1, 1, 1, 4, device);
                }
                Some(Ok(Vec::new()))
            }
            Some(b"p2p_disc") if set => {
                fw.if_event_flags(2, 1, 1, 1, 4, device);
                Some(Ok(Vec::new()))
            }
            Some(b"p2p_dev") => Some(Ok(1u32.to_le_bytes().to_vec())),
            Some(b"bsscfg:actframe") => {
                fw.secondary_event_status(wire::E_ACTION_FRAME_COMPLETE, 1, 1, PEER, 0, 0, &[]);
                fw.secondary_event_status(
                    wire::E_ACTION_FRAME_OFF_CHAN_COMPLETE,
                    1,
                    1,
                    PEER,
                    0,
                    0,
                    &[],
                );
                Some(Ok(Vec::new()))
            }
            _ => match (command.direction, command.command) {
                // Discovery bsscfg has no BSSID.
                (Direction::Get, 23) if fw.vif_log.last().is_some_and(|(i, _)| *i == 1) => {
                    Some(Err(Error::Firmware((-17i32) as u32)))
                }
                _ => None,
            },
        }
    }));
    fw
}

fn discovery_case<const PCIE: bool>() -> Result<(), &'static str> {
    let device = wire::generate_bss_mac(PRIMARY, None, [0; 6]).device;
    let mut runtime = Mock::<PCIE>::new(discovery_firmware(device));
    let mut owner = Owner::new(PRIMARY, p2p_features());
    let entry =
        block(owner.create_p2p_device(&mut runtime, device)).map_err(|_| "create p2pdev")?;
    if !entry.p2p_device || entry.ifidx != 1 || entry.bsscfgidx != 1 || entry.mac != device {
        return Err("discovery entry does not follow the NOIF IF ADD");
    }
    // brcmf_p2p_set_firmware order, then p2p_disc 1 after BRCMF_E_IF.
    let order: Vec<(u32, Option<Vec<u8>>)> = runtime
        .fw
        .log
        .iter()
        .take(6)
        .map(|c| (c.command, c.iovar().map(<[u8]>::to_vec)))
        .collect();
    if order[0].0 != 3
        || order[1].1.as_deref() != Some(&b"apsta"[..])
        || order[2].0 != 2
        || order[3].1.as_deref() != Some(&b"p2p_disc"[..])
        || order[4].1.as_deref() != Some(&b"p2p_da_override"[..])
        || runtime.fw.iovars(Direction::Set, b"p2p_da_override") != [device.to_vec()]
        || runtime.fw.iovars(Direction::Get, b"p2p_dev").len() != 1
        || owner.role(1) != Some(Role::P2pDevice)
    {
        return Err("brcmf_p2p_create_p2pdev request order");
    }
    let mut p2p = Device::new(entry);
    block(p2p.start(&mut runtime)).map_err(|_| "start device")?;
    let state_scan = {
        let mut body = b"bsscfg:p2p_state\0".to_vec();
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&wire::disc_state(DiscState::Scan, 0, 0));
        body
    };
    if !runtime
        .fw
        .vif_log
        .iter()
        .any(|(i, c)| *i == 1 && c.body == state_scan)
        || runtime
            .fw
            .iovars(Direction::Set, b"bsscfg:wsec")
            .last()
            .map(|v| v[4..].to_vec())
            != Some(4u32.to_le_bytes().to_vec())
        || !p2p.ready()
    {
        return Err("brcmf_p2p_enable_discovery");
    }
    let mask = runtime.fw.iovars(Direction::Set, b"event_msgs");
    let Some(mask) = mask.last() else {
        return Err("P2P events not written");
    };
    if wire::DEVICE_EVENTS
        .iter()
        .any(|&e| mask[e / 8] & (1 << (e % 8)) == 0)
    {
        return Err("P2P events missing from the composed mask");
    }
    // Remain on channel 6 for 300 ms: p2p_state LISTEN chanspec/dwell.
    block(p2p.remain_on_channel(&mut runtime, 77, 2437, 300)).map_err(|_| "roc")?;
    let listen = runtime.fw.iovars(Direction::Set, b"bsscfg:p2p_state");
    if listen.last().map(|v| v[4..].to_vec())
        != Some(wire::disc_state(DiscState::Listen, 0x1006, 300).to_vec())
        || p2p.listening() != Some(77)
    {
        return Err("brcmf_p2p_discover_listen");
    }
    // Action frame RX on the discovery bsscfg, registered for action.
    p2p.set_registrations(true, false);
    let mut rx = alloc::vec![0u8; 16];
    rx[2..4].copy_from_slice(&0x1006u16.to_be_bytes());
    rx.extend_from_slice(&[4, 9, 0x50, 0x6f, 0x9a, 9, wire::PAF_PROVDIS_REQ, 3]);
    runtime
        .fw
        .secondary_event(wire::E_ACTION_FRAME_RX, 1, 1, PEER, &rx);
    // A bsscfg-0 P2P probe request is never delivered (Linux filter).
    runtime
        .fw
        .secondary_event(wire::E_P2P_PROBEREQ_MSG, 1, 0, PEER, &rx);
    runtime
        .fw
        .secondary_event(wire::E_P2P_DISC_LISTEN_COMPLETE, 1, 1, PEER, &[]);
    block(p2p.service(&mut runtime, &mut owner)).map_err(|_| "service")?;
    let Some(Notice::Rx {
        frequency_mhz: 2437,
        frame,
    }) = p2p.pop_notice()
    else {
        return Err("action frame not delivered");
    };
    if frame[0] != 0xd0
        || frame[4..10] != device
        || frame[10..16] != PEER
        || frame[16..22] != [0; 6]
        || frame[24..] != rx[16..]
    {
        return Err("action frame reconstruction");
    }
    if p2p.pop_notice()
        != Some(Notice::RocExpired {
            cookie: 77,
            frequency_mhz: 2437,
        })
        || p2p.pop_notice().is_some()
    {
        return Err("listen complete -> remain_on_channel_expired");
    }
    // Action TX: on-channel complete + off-channel complete -> ACK.
    let frame = gon_req(device);
    let ack = block(p2p.send_action_frame(&mut runtime, &mut owner, &frame, 6, 0, 9))
        .map_err(|_| "tx")?;
    let sent = runtime.fw.iovars(Direction::Set, b"bsscfg:actframe");
    if !ack
        || sent.len() != 1
        || wire::af_dwell(&sent[0][4..]) != wire::AF_MED_DWELL_TIME
        || wire::af_body(&sent[0][4..]) != &frame[24..]
        || runtime
            .fw
            .iovars(Direction::Set, b"mpc")
            .last()
            .map(Vec::as_slice)
            != Some(&0u32.to_le_bytes()[..])
    {
        return Err("brcmf_p2p_send_action_frame");
    }
    // Delete: SCAN, p2p_disc 0, IF DEL; the host entry is gone.
    block(p2p.delete(&mut runtime, &mut owner)).map_err(|_| "delete")?;
    if runtime
        .fw
        .iovars(Direction::Set, b"p2p_disc")
        .last()
        .map(Vec::as_slice)
        != Some(&0u32.to_le_bytes()[..])
        || owner.registry().by_bsscfgidx(1).is_some()
        || owner.role(1).is_some()
        || runtime.fw.vif_listening
    {
        return Err("brcmf_p2p_del_vif (device)");
    }
    Ok(())
}

fn smoke_brcmf_p2p_device_discovery_listen_and_action_frames() -> TestResult {
    match discovery_case::<false>().and_then(|_| discovery_case::<true>()) {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/p2p",
    smoke_brcmf_p2p_device_discovery_listen_and_action_frames
);

fn connection_case<const PCIE: bool>() -> Result<(), &'static str> {
    let addresses = wire::generate_bss_mac(PRIMARY, None, [0; 6]);
    let connection = addresses.connection;
    let mut fw = Firmware::new();
    fw.hook = Some(Box::new(move |fw, command| {
        match (command.direction, command.command, command.iovar()) {
            // Primary not associated: default P2P channel 11.
            (Direction::Get, 23, _) => Some(Err(Error::Firmware((-17i32) as u32))),
            (Direction::Set, _, Some(b"p2p_ifadd")) => {
                fw.if_event(1, 2, 2, 3, connection);
                Some(Ok(Vec::new()))
            }
            (Direction::Set, _, Some(b"p2p_ifdis")) => {
                fw.secondary_event_status(16, 2, 2, connection, 0, 4, &[]);
                Some(Ok(Vec::new()))
            }
            (Direction::Set, _, Some(b"p2p_ifdel")) => {
                fw.if_event(2, 2, 2, 3, connection);
                Some(Ok(Vec::new()))
            }
            _ => None,
        }
    }));
    let mut runtime = Mock::<PCIE>::new(fw);
    let mut owner = Owner::new(PRIMARY, p2p_features());
    let entry =
        block(owner.create_p2p(&mut runtime, Role::P2pGo, connection)).map_err(|_| "p2p_ifadd")?;
    if entry.ifidx != 2
        || entry.bsscfgidx != 2
        || entry.p2p_device
        || owner.role(2) != Some(Role::P2pGo)
    {
        return Err("GO entry");
    }
    if runtime.fw.iovars(Direction::Set, b"p2p_ifadd")
        != [wire::p2p_if(connection, P2pIfType::Go, 0x100b).to_vec()]
    {
        return Err("p2p_ifadd request (address, GO, temp channel 11)");
    }
    let on_vif: Vec<&crate::cyw43439::fullmac_fixture::Command> = runtime
        .fw
        .vif_log
        .iter()
        .filter(|(i, _)| *i == 2)
        .map(|(_, c)| c)
        .collect();
    if on_vif.len() != 2
        || on_vif[0].iovar() != Some(b"roam_off")
        || on_vif[1].command != 158
        || on_vif[1].body != 20u32.to_le_bytes()
    {
        return Err("roam_off / SCB timeout on the GO ifidx");
    }
    // A second connection bsscfg exceeds the P2P limits.
    if block(owner.create_p2p(&mut runtime, Role::P2pClient, addresses.connection2))
        != Err(Error::Unsupported)
    {
        return Err("second P2P connection admitted");
    }
    block(owner.remove_p2p(&mut runtime, entry)).map_err(|_| "remove GO")?;
    if runtime.fw.iovars(Direction::Set, b"p2p_ifdis") != [connection.to_vec()]
        || runtime.fw.iovars(Direction::Set, b"p2p_ifdel") != [connection.to_vec()]
        || owner.registry().by_bsscfgidx(2).is_some()
        || runtime.fw.vif_listening
    {
        return Err("GO removal: p2p_ifdis, LINK BSSCFG_DIS, p2p_ifdel, IF DEL");
    }
    // A P2P client has no p2p_ifdis.
    let mut fw = Firmware::new();
    fw.hook = Some(Box::new(move |fw, command| match command.iovar() {
        Some(b"p2p_ifadd") => {
            fw.if_event(1, 3, 4, 4, connection);
            Some(Ok(Vec::new()))
        }
        Some(b"p2p_ifdel") => {
            fw.if_event(2, 3, 4, 4, connection);
            Some(Ok(Vec::new()))
        }
        _ => None,
    }));
    let mut runtime = Mock::<PCIE>::new(fw);
    let mut owner = Owner::new(PRIMARY, p2p_features());
    let entry =
        block(owner.create_p2p(&mut runtime, Role::P2pClient, connection)).map_err(|_| "client")?;
    block(owner.remove_p2p(&mut runtime, entry)).map_err(|_| "remove client")?;
    if !runtime.fw.iovars(Direction::Set, b"p2p_ifdis").is_empty()
        || runtime.fw.vif_log.iter().any(|(_, c)| c.command == 158)
    {
        return Err("client lifecycle");
    }
    Ok(())
}

fn smoke_brcmf_p2p_connection_bsscfg_ifadd_and_ifdel() -> TestResult {
    match connection_case::<false>().and_then(|_| connection_case::<true>()) {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/p2p",
    smoke_brcmf_p2p_connection_bsscfg_ifadd_and_ifdel
);

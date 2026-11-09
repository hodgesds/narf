// SPDX-License-Identifier: GPL-2.0-or-later
//! P2P cases shared by the actual transport models: the BCM43602
//! CR4/msgbuf firmware model (`vif_msgbuf_tests.rs`) and the CYW43439
//! SDIO/SDPCM/BCDC model (`ap_native_sdio_tests.rs`). Both models answer
//! with the same firmware bytes (`station_model.rs`), so the host
//! `Owner`/`p2p::Device`/`Station` code runs unmodified over each real
//! transport: Linux 7.3-rc4 `p2p.c` `brcmf_p2p_create_p2pdev`,
//! `brcmf_p2p_enable_discovery`, `brcmf_p2p_discover_listen`,
//! `brcmf_p2p_notify_action_frame_rx`, `brcmf_p2p_send_action_frame`,
//! `brcmf_p2p_scan_prep`/`brcmf_p2p_run_escan`, `brcmf_p2p_del_vif` and
//! the P2P_CLIENT `brcmf_p2p_add_vif` + `brcmf_cfg80211_connect` on the
//! connection bsscfg.
use super::{
    p2p::{Device, Notice},
    p2p_wire::{self as wire, DiscState},
    runtime_tests::station_model::{AP, VIF},
    vif_bsscfg::{Bsscfg, Link},
    vif_owner::{Owner, Role},
    vif_wire::Features,
};
use crate::cyw43439::{
    fullmac::Fullmac,
    fullmac_fixture::{cache, request},
    station::Station,
};
use alloc::{vec, vec::Vec};

const PEER: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

/// Model hooks of one transport.
pub(crate) trait Model {
    /// One firmware event of ifidx/bsscfg 1 carrying `data`.
    fn event(&self, kind: u32, source: [u8; 6], data: &[u8]);
    /// Plain values set on ifidx 1 (`bsscfg:` prefix and index removed).
    fn sets(&self) -> Vec<(u32, Vec<u8>)>;
    /// `(ifidx, body)` of every IOCTL sent.
    fn commands(&self) -> Vec<(u8, Vec<u8>)>;
}

fn block<F: core::future::Future>(future: F) -> F::Output {
    narf_scheduler::block_on(future)
}

pub(crate) fn features() -> Features {
    Features {
        p2p: true,
        mchan: true,
        ..Features::default()
    }
}

fn named(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut body = name.to_vec();
    body.push(0);
    body.extend_from_slice(value);
    body
}

/// GO Negotiation Request public action frame from `device` to PEER.
fn gon_req(device: [u8; 6]) -> Vec<u8> {
    let mut frame = vec![0u8; 24];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&PEER);
    frame[10..16].copy_from_slice(&device);
    frame[16..22].copy_from_slice(&PEER);
    frame.extend_from_slice(&[4, 9, 0x50, 0x6f, 0x9a, 9, wire::PAF_GON_REQ, 7]);
    frame
}

/// wpa_supplicant's `p2p_find` probe IEs: P2P IE with Listen Channel
/// (attribute 6, operating class 81, `channel`) and a WPS IE.
fn p2p_scan_ies(channel: u8) -> Vec<u8> {
    let mut ies = vec![
        221, 12, 0x50, 0x6f, 0x9a, 9, 6, 5, 0, b'X', b'X', 4, 81, channel,
    ];
    ies.extend_from_slice(&[221, 7, 0x00, 0x50, 0xf2, 4, 0x10, 0x4a, 0]);
    ies
}

/// P2P_DEVICE discovery bsscfg over the transport: create, start, listen
/// with action-frame RX and listen expiry, action-frame TX with ACK, the
/// social-channel P2P escan, delete.
pub(crate) fn discovery<R: Fullmac>(
    station: &mut Station<R>,
    model: &dyn Model,
) -> Result<(), &'static str> {
    let device = wire::generate_bss_mac(station.mac, None, [0; 6]).device;
    let mut owner = Owner::new(station.mac, features());
    let entry = block(owner.create_p2p_device(&mut station.runtime, device))
        .map_err(|_| "brcmf_p2p_create_p2pdev over the transport")?;
    if !entry.p2p_device
        || entry.ifidx != 1
        || entry.bsscfgidx != 1
        || entry.mac != device
        || owner.role(1) != Some(Role::P2pDevice)
    {
        return Err("discovery entry does not follow the NOIF IF ADD");
    }
    let commands = model.commands();
    let primary = |name: &[u8], value: &[u8]| {
        commands
            .iter()
            .any(|(ifidx, body)| *ifidx == 0 && *body == named(name, value))
    };
    if !primary(b"p2p_da_override", &device)
        || !primary(b"p2p_disc", &1u32.to_le_bytes())
        || !commands
            .iter()
            .any(|(ifidx, body)| *ifidx == 0 && body.starts_with(b"p2p_dev\0"))
    {
        return Err("p2p_da_override / p2p_disc / p2p_dev on the primary");
    }
    let mut p2p = Device::new(entry);
    block(p2p.start(&mut station.runtime)).map_err(|_| "brcmf_p2p_start_device")?;
    if !p2p.ready()
        || !model
            .sets()
            .iter()
            .any(|(_, body)| *body == named(b"p2p_state", &wire::disc_state(DiscState::Scan, 0, 0)))
    {
        return Err("brcmf_p2p_enable_discovery on bsscfg 1");
    }
    // Listen on channel 6 for 300 ms.
    block(p2p.remain_on_channel(&mut station.runtime, 77, 2437, 300))
        .map_err(|_| "brcmf_p2p_discover_listen")?;
    let listen = named(
        b"p2p_state",
        &wire::disc_state(DiscState::Listen, 0x1006, 300),
    );
    if model
        .sets()
        .iter()
        .rev()
        .find(|(_, body)| body.starts_with(b"p2p_state\0"))
        .map(|(_, body)| body)
        != Some(&listen)
        || p2p.listening() != Some(77)
    {
        return Err("LISTEN p2p_state not addressed to bsscfg 1");
    }
    // Provision Discovery Request RX on the discovery bsscfg, then the
    // firmware's listen completion.
    p2p.set_registrations(true, false);
    let mut rx = vec![0u8; 16];
    rx[2..4].copy_from_slice(&0x1006u16.to_be_bytes());
    rx.extend_from_slice(&[4, 9, 0x50, 0x6f, 0x9a, 9, wire::PAF_PROVDIS_REQ, 3]);
    model.event(wire::E_ACTION_FRAME_RX, PEER, &rx);
    model.event(wire::E_P2P_DISC_LISTEN_COMPLETE, PEER, &[]);
    for _ in 0..4 {
        // Pump the transport first: `service` only drains events `poll`
        // has already moved from the firmware model to the runtime queue.
        station
            .runtime
            .poll()
            .map_err(|_| "discovery transport pump")?;
        block(p2p.service(&mut station.runtime, &mut owner)).map_err(|_| "discovery service")?;
    }
    let Some(Notice::Rx {
        frequency_mhz: 2437,
        frame,
    }) = p2p.pop_notice()
    else {
        return Err("action frame not delivered over the transport");
    };
    if frame[0] != 0xd0
        || frame[4..10] != device
        || frame[10..16] != PEER
        || frame[24..] != rx[16..]
    {
        return Err("action frame reconstruction");
    }
    if p2p.pop_notice()
        != Some(Notice::RocExpired {
            cookie: 77,
            frequency_mhz: 2437,
        })
    {
        return Err("listen complete -> remain_on_channel_expired");
    }
    // Action TX: the firmware's on/off-channel completions are the ACK.
    let frame = gon_req(device);
    let acked = block(p2p.send_action_frame(&mut station.runtime, &mut owner, &frame, 6, 0, 9))
        .map_err(|_| "brcmf_p2p_send_action_frame")?;
    let sent: Vec<_> = model
        .sets()
        .into_iter()
        .filter(|(_, body)| body.starts_with(b"actframe\0"))
        .collect();
    if !acked || sent.len() != 1 || wire::af_body(&sent[0].1[9..]) != &frame[24..] {
        return Err("actframe on bsscfg 1 / ACK");
    }
    // `p2p_find`: DIRECT- wildcard on the social channels -> SEARCH escan.
    let found = block(station.p2p_scan(
        &mut owner,
        &mut p2p,
        false,
        narf_wireless::ScanRequest {
            ssids: vec![b"DIRECT-".to_vec()],
            frequencies_mhz: vec![2412, 2437, 2462],
            channels: Vec::new(),
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: p2p_scan_ies(6),
        },
    ))
    .map_err(|_| "P2P escan over the transport")?;
    let sets = model.sets();
    if found.len() != 1
        || found[0].channel != 6
        || !sets.iter().any(|(_, body)| {
            *body == named(b"p2p_state", &wire::disc_state(DiscState::Search, 0, 0))
        })
        || !sets
            .iter()
            .any(|(_, body)| body.starts_with(b"p2p_scan\0") && body.get(9) == Some(&b'E'))
        || !sets.iter().any(|(_, body)| body.starts_with(b"vndr_ie\0"))
    {
        return Err("brcmf_p2p_run_escan SEARCH / p2p_scan 'E' / PRBREQ vndr_ie");
    }
    // Delete: p2p_disc 0 and the IF DEL of the discovery bsscfg.
    block(p2p.delete(&mut station.runtime, &mut owner)).map_err(|_| "brcmf_p2p_del_vif")?;
    if owner.role(1).is_some()
        || owner.registry().by_bsscfgidx(1).is_some()
        || !model
            .commands()
            .iter()
            .rev()
            .any(|(ifidx, body)| *ifidx == 0 && *body == named(b"p2p_disc", &0u32.to_le_bytes()))
    {
        return Err("discovery bsscfg not deleted");
    }
    Ok(())
}

/// P2P_CLIENT connection bsscfg over the transport: `p2p_ifadd` CLIENT,
/// the secondary station join on ifidx/bsscfg 1, `p2p_ifdel` + IF DEL.
pub(crate) fn client_join<R: Fullmac>(
    station: &mut Station<R>,
    model: &dyn Model,
) -> Result<(), &'static str> {
    let mut owner = Owner::new(station.mac, features());
    let entry = block(owner.create_p2p(&mut station.runtime, Role::P2pClient, VIF))
        .map_err(|_| "p2p_ifadd CLIENT over the transport")?;
    if entry.ifidx != 1 || entry.bsscfgidx != 1 || owner.role(1) != Some(Role::P2pClient) {
        return Err("CLIENT connection bsscfg entry");
    }
    let added = model
        .commands()
        .into_iter()
        .find(|(_, body)| body.starts_with(b"p2p_ifadd\0"))
        .ok_or("no p2p_ifadd")?;
    if added.0 != 0 || added.1[10..16] != VIF || added.1[16..18] != [0, 0] {
        return Err("p2p_ifadd CLIENT layout on the primary");
    }
    let before = model.commands().len();
    let parked = station.secondary(entry.mac);
    let mut link = Link::new(entry);
    let parked = {
        let adapter = Bsscfg::new(&mut station.runtime, &mut owner, &mut link);
        let (mut client, rest) = parked.rebind(adapter);
        block(client.configure_secondary()).map_err(|_| "CLIENT per-interface dcmds")?;
        cache(
            &mut client,
            AP,
            6,
            narf_wireless::scan::BssSecurity::Open,
            &[],
        );
        block(client.associate(request(
            AP,
            6,
            narf_wireless::SecurityConfig::Open,
            Vec::new(),
        )))
        .map_err(|_| "P2P_CLIENT join")?;
        client.rebind(rest).0
    };
    let joined = &model.commands()[before..];
    if joined.is_empty()
        || joined.iter().any(|(ifidx, _)| *ifidx != 1)
        || link.peer() != Some(AP)
        || parked.bssid != Some(AP)
        || station.bssid.is_some()
    {
        return Err("P2P_CLIENT join not addressed to ifidx/bsscfg 1");
    }
    block(owner.remove_p2p(&mut station.runtime, entry)).map_err(|_| "p2p_ifdel CLIENT")?;
    let commands = model.commands();
    if owner.role(1).is_some()
        || !commands
            .iter()
            .any(|(ifidx, body)| *ifidx == 0 && body.starts_with(b"p2p_ifdel\0"))
        || commands
            .iter()
            .any(|(_, body)| body.starts_with(b"p2p_ifdis\0"))
    {
        return Err("P2P_CLIENT removal is p2p_ifdel without p2p_ifdis");
    }
    Ok(())
}

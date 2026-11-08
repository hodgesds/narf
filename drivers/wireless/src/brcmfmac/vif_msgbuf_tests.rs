// SPDX-License-Identifier: GPL-2.0-or-later
//! Secondary firmware interface over the actual BCM43602 CR4/msgbuf rings:
//! Linux 7.3-rc4 `msgbuf.c` addresses IOCTLs with `msg.ifidx` and
//! correlates completions by transaction id only (the completion's ifidx
//! is zero here), creates flow rings per (ifidx, tid, da) with the
//! interface's own source address, and `fweh.c` dispatches events by the
//! event header's ifidx/bsscfgidx. Removal while data is live retires the
//! interface's flows after their TX statuses.
use super::*;
use crate::brcmfmac::{
    runtime_tests::station_model::VIF,
    vif_bsscfg::{Bsscfg, Link},
    vif_owner::{Owner, Role},
    vif_wire::Features,
};
use crate::cyw43439::fullmac_fixture::{cache, request};

fn block<F: Future>(future: F) -> F::Output {
    narf_scheduler::block_on(future)
}

fn frame() -> Vec<u8> {
    let mut bytes = AP.to_vec();
    bytes.extend_from_slice(&VIF);
    bytes.extend_from_slice(&[0x08, 0x00]);
    bytes.extend_from_slice(&[0x45; 46]);
    bytes
}

fn secondary_ifidx() -> Result<(), &'static str> {
    let (adapter, bus) = firmware::create(7, false).map_err(|_| "CR4 msgbuf attach")?;
    let mut station = block(Station::initialize(adapter, &[], firmware::domain()))
        .map_err(|_| "primary station over msgbuf")?;
    let features = Features {
        p2p: true,
        mchan: true,
        ..Features::default()
    };
    let mut owner = Owner::new(station.mac, features);
    let entry = block(owner.create(&mut station.runtime, Role::Station, Some(VIF)))
        .map_err(|_| "IF ADD over the msgbuf event ring")?;
    if entry.ifidx != 1 || entry.bsscfgidx != 1 || entry.mac != VIF {
        return Err("entry does not follow the native IF ADD");
    }
    let commands = bus.commands();
    let ifidx = bus.command_ifidx();
    let Some(mask) = commands
        .iter()
        .rev()
        .find(|(command, body, _)| *command == 263 && body.starts_with(b"event_msgs\0"))
    else {
        return Err("registry wrote no event_msgs");
    };
    if mask
        .1
        .get(11 + 54 / 8)
        .is_none_or(|byte| byte & (1 << (54 % 8)) == 0)
        || commands
            .iter()
            .zip(&ifidx)
            .any(|((_, body, _), index)| body.starts_with(b"interface_create\0") && *index != 0)
    {
        return Err("IF registration not on the primary interface");
    }
    station
        .runtime
        .vif_open(entry.ifidx)
        .map_err(|_| "vif_open")?;
    // IOCTL on the secondary: msg.ifidx 1, completion ifidx zero.
    let before = bus.commands().len();
    block(station.runtime.command_vif(
        1,
        crate::cyw43439::ioctl::Direction::Set,
        86,
        &0u32.to_le_bytes(),
        4,
    ))
    .map_err(|_| "secondary IOCTL completion")?;
    if bus.commands().len() != before + 1 || bus.command_ifidx().last() != Some(&1) {
        return Err("secondary IOCTL not addressed with msg.ifidx");
    }
    // Events of bsscfg 1 reach only its registry entry.
    bus.secondary_event(16, 1, AP);
    for _ in 0..4 {
        station.runtime.poll().map_err(|_| "event poll")?;
    }
    owner
        .service(&mut station.runtime)
        .map_err(|_| "secondary event service")?;
    if owner.pop_event(&entry).map(|e| e.header.event_type) != Some(16)
        || station.runtime.pop_event().is_some()
    {
        return Err("secondary event not dispatched by ifidx");
    }
    // Data on ifidx 1: its own (ifidx, tid, da) flow, sourced from VIF.
    // The first send on a new flow opens the ring and reports `Busy`
    // so the caller retries; the frame is only sent on the second call,
    // which finds the existing flow (`begin_data`).
    let mut sent = false;
    for _ in 0..8 {
        match station.runtime.send_vif_data(1, &frame(), 0) {
            Ok(()) => {
                sent = true;
                break;
            }
            Err(crate::cyw43439::runtime::Error::Busy) => {
                station.runtime.poll().map_err(|_| "data poll")?;
            }
            Err(_) => return Err("secondary data admission"),
        }
    }
    if !sent {
        return Err("secondary data admission");
    }
    for _ in 0..8 {
        station.runtime.poll().map_err(|_| "data poll")?;
    }
    let flows = bus.flow_ifidx();
    if flows.len() != 1 || flows[0].1 != 1 || bus.uplink_frames().last() != Some(&frame()) {
        return Err("secondary flow ring create/TX");
    }
    // Removal while running: IF DEL addressed to ifidx 1, then the flow
    // is deleted only after its TX status (the model asserts the order).
    block(owner.remove(&mut station.runtime, entry)).map_err(|_| "IF DEL / flow retirement")?;
    let commands = bus.commands();
    let ifidx = bus.command_ifidx();
    if !commands
        .iter()
        .zip(&ifidx)
        .any(|((_, body, _), index)| body.starts_with(b"bsscfg:interface_remove\0") && *index == 1)
        || !bus.flow_ifidx().is_empty()
        || station.runtime.send_vif_data(1, &frame(), 0).is_ok()
        || owner.registry().by_bsscfgidx(1).is_some()
    {
        return Err("removal left secondary state");
    }
    Ok(())
}

fn smoke_brcmf_msgbuf_secondary_ifidx_ioctl_events_flows_and_removal() -> TestResult {
    match secondary_ifidx() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_msgbuf_secondary_ifidx_ioctl_events_flows_and_removal
);

/// Linux 7.3-rc4 `cfg80211.c` `brcmf_cfg80211_connect` on an additional STA
/// `brcmf_if` over msgbuf: every join dcmd carries `msg.ifidx` 1, the
/// security iovars are `brcmf_fil_bsscfg_*` (`bsscfg:` + le32 1), and the
/// link/SET_SSID events of bsscfg 1 (`fweh.c` dispatch) open only the
/// secondary port; its deauthentication closes only that port.
fn secondary_join() -> Result<(), &'static str> {
    let (adapter, bus) = firmware::create(7, false).map_err(|_| "CR4 msgbuf attach")?;
    let mut station = block(Station::initialize(adapter, &[], firmware::domain()))
        .map_err(|_| "primary station over msgbuf")?;
    let features = Features {
        p2p: true,
        mchan: true,
        ..Features::default()
    };
    let mut owner = Owner::new(station.mac, features);
    let entry = block(owner.create(&mut station.runtime, Role::Station, Some(VIF)))
        .map_err(|_| "IF ADD over the msgbuf event ring")?;
    station
        .runtime
        .vif_open(entry.ifidx)
        .map_err(|_| "vif_open")?;
    let parked = station.secondary(entry.mac);
    let mut link = Link::new(entry);
    let before = bus.commands().len();
    let parked = {
        let adapter = Bsscfg::new(&mut station.runtime, &mut owner, &mut link);
        let (mut secondary, rest) = parked.rebind(adapter);
        block(secondary.configure_secondary()).map_err(|_| "secondary per-interface dcmds")?;
        cache(
            &mut secondary,
            AP,
            6,
            narf_wireless::scan::BssSecurity::Open,
            &[],
        );
        block(secondary.associate(request(
            AP,
            6,
            narf_wireless::SecurityConfig::Open,
            Vec::new(),
        )))
        .map_err(|_| "secondary join over msgbuf")?;
        secondary.rebind(rest).0
    };
    let commands = bus.commands();
    let ifidx = bus.command_ifidx();
    let joined: Vec<_> = commands[before..].iter().zip(&ifidx[before..]).collect();
    let mut wpa_auth = b"bsscfg:wpa_auth\0".to_vec();
    wpa_auth.extend_from_slice(&1u32.to_le_bytes());
    if joined.iter().any(|(_, index)| **index != 1)
        || ![86u32, 20, 22, 26]
            .iter()
            .all(|dcmd| joined.iter().any(|((command, _, _), _)| command == dcmd))
        || joined.iter().any(|((command, _, _), _)| *command == 134)
        || !joined
            .iter()
            .any(|((_, body, _), _)| body.starts_with(&wpa_auth))
        || joined
            .iter()
            .any(|((_, body, _), _)| body.starts_with(b"wpa_auth\0") || body.starts_with(b"wsec\0"))
    {
        return Err("secondary join not addressed to msg.ifidx 1 / bsscfg 1");
    }
    if link.peer() != Some(AP)
        || parked.bssid != Some(AP)
        || station.bssid.is_some()
        || station.runtime.pop_event().is_some()
    {
        return Err("secondary link leaked into the primary interface");
    }
    // BRCMF_E_DEAUTH (6) on bsscfg 1 closes only the secondary port.
    bus.secondary_event(6, 0, AP);
    let adapter = Bsscfg::new(&mut station.runtime, &mut owner, &mut link);
    let (mut secondary, rest) = parked.rebind(adapter);
    for _ in 0..4 {
        let _ = secondary.poll();
    }
    let (parked, _) = secondary.rebind(rest);
    if parked.bssid.is_some() || link.peer().is_some() || station.bssid.is_some() {
        return Err("secondary deauthentication kept the port open");
    }
    Ok(())
}

fn smoke_brcmf_msgbuf_secondary_station_joins_on_ifidx_one() -> TestResult {
    match secondary_join() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_msgbuf_secondary_station_joins_on_ifidx_one
);

/// Primary STA associated on ifidx 0 + a secondary firmware-SME AP on
/// ifidx 1 (Linux 7.3-rc4 combo0: `brcmf_cfg80211_add_iface` →
/// `brcmf_apsta_add_vif`, then `brcmf_cfg80211_start_ap` on the AP vif).
/// With `mchan` the AP vif skips `BRCMF_C_DOWN`/`apsta 0`, writes no
/// `nmode`/`vhtmode`/`qtxpower`, and addresses its security iovars to
/// bsscfg 1; the composed `event_msgs` keeps the primary STA's events.
/// A peer associates on bsscfg 1 and the stop leaves the primary joined.
fn primary_station_secondary_ap() -> Result<(), &'static str> {
    use super::ap_native_tests::{association, config, Source};
    use crate::brcmfmac::runtime_tests::station_model::ap_model::CLIENT;
    use narf_capabilities::{Cap, Invoke};
    use narf_wireless::ap_control::ApControlAuthority;
    const NAME: &str = "wlvap7";
    let (adapter, bus) = firmware::create(7, false).map_err(|_| "CR4 msgbuf attach")?;
    bus.enable_vif_ap();
    bus.set_caps(b"ap sta mchan");
    let database = Arc::new(narf_wireless::reg::db::Database::new());
    database.install(firmware::domain());
    let mut station = block(Station::initialize_live(adapter, &[], database.clone()))
        .map_err(|_| "primary station over msgbuf")?;
    cache(
        &mut station,
        AP,
        6,
        narf_wireless::scan::BssSecurity::Open,
        &[],
    );
    block(station.associate(request(
        AP,
        6,
        narf_wireless::SecurityConfig::Open,
        Vec::new(),
    )))
    .map_err(|_| "primary join")?;
    let owner = block(super::vif::discover(&mut station.runtime, station.mac))
        .map_err(|_| "cap discovery")?
        .ok_or("firmware cap refused")?;
    if !owner.features().mchan || owner.features().mbss {
        return Err("cap tokens not parsed as brcmf_feat_attach");
    }
    let name = narf_net::iface::register("wlan%d", OWN, send);
    let device = shell(name.clone(), station);
    device.state.try_lock().ok_or("state")?.vif = Some(owner);
    device.ap_fixture_setup(database);
    super::vif::register_primary(&device);
    let result = (|| {
        let vap = device
            .vif_new(NAME, 3, None)
            .map_err(|_| "secondary AP shell admission")?;
        block(device.vif_worker());
        if vap.ap_sme_capabilities() != Some(0) {
            return Err("secondary AP shell not attached after IF ADD");
        }
        narf_net::iface::set_link_state(NAME, true);
        let cap = narf_net::registry()
            .with_handle(NAME, |cap| *cap)
            .ok_or("secondary netdev handle")?;
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon: Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap(),
        })
        .map_err(|_| "secondary admin authority")?
        .admin;
        let iface: Arc<dyn WirelessNetIface> = vap.clone();
        let source = Arc::new(Source::new());
        let authority = ApControlAuthority::bind(
            admin,
            &iface,
            0,
            narf_net::iface::lookup(NAME).ok_or("ifindex")?.ifindex,
            source.clone(),
        )
        .map_err(|_| "AP authority bind")?
        .reserve()
        .map_err(|_| "AP control reservation")?;
        let (mut ap_config, settings) = config(false);
        ap_config.beacon_head[10..22].copy_from_slice(&[VIF, VIF].concat());
        let before = bus.commands().len();
        block(vap.start_ap_with_settings_async(&authority, ap_config, settings))
            .map_err(|_| "secondary AP START")?;
        let commands = bus.commands();
        let ifidx = bus.command_ifidx();
        let program: Vec<_> = commands[before..].iter().zip(&ifidx[before..]).collect();
        let mut wsec = b"bsscfg:wsec\0".to_vec();
        wsec.extend_from_slice(&1u32.to_le_bytes());
        let mask = program
            .iter()
            .rev()
            .find(|((command, body, _), _)| *command == 263 && body.starts_with(b"event_msgs\0"))
            .map(|((_, body, _), _)| body[11..].to_vec())
            .ok_or("secondary AP wrote no event_msgs")?;
        let sta = crate::cyw43439::station::roam::event_mask(false);
        if program.iter().any(|(_, index)| **index != 1)
            || program.iter().any(|((command, body, _), _)| {
                *command == 3
                    || body.starts_with(b"apsta\0")
                    || *command == 263
                        && (body.starts_with(b"nmode\0")
                            || body.starts_with(b"vhtmode\0")
                            || body.starts_with(b"qtxpower\0")
                            || body.starts_with(b"wsec\0"))
            })
            || !program
                .iter()
                .any(|((_, body, _), _)| body.starts_with(&wsec))
            || sta.iter().zip(&mask).any(|(s, m)| s & m != *s)
        {
            return Err("secondary AP Program not the combo0 bsscfg-1 form");
        }
        if !bus.vif_ap_change(|p| p.active && p.up && p.formed)
            || !vap.link_up()
            || device.state.try_lock().ok_or("state")?.station.bssid != Some(AP)
        {
            return Err("secondary AP not running beside the joined primary");
        }
        // A peer associates with the secondary BSS (events of bsscfg 1).
        bus.vif_ap_change(|p| p.associate(CLIENT, association(false)));
        for _ in 0..4 {
            block(device.vif_worker());
        }
        if source.count(19) != 1 {
            return Err("secondary AP NEW_STATION not observed on its shell");
        }
        block(vap.stop_ap_async(&authority)).map_err(|_| "secondary AP STOP")?;
        if bus.vif_ap_change(|p| p.active || !p.peers.is_empty())
            || vap.link_up()
            || device.state.try_lock().ok_or("state")?.station.bssid != Some(AP)
        {
            return Err("secondary AP stop disturbed the primary or kept its BSS");
        }
        Ok(())
    })();
    super::vif::withdraw_family(crate::cyw43439::fullmac::Family::Pcie);
    bus.d3_ack(true);
    let _ = block(device.teardown());
    *ACTIVE_TEST.lock() = None;
    narf_net::registry().unregister(&name);
    narf_net::iface::unregister(&name);
    result
}

fn smoke_brcmf_msgbuf_primary_station_beside_secondary_ap() -> TestResult {
    match primary_station_secondary_ap() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_msgbuf_primary_station_beside_secondary_ap
);

/// F20: a secondary AP START beside an associated primary STA on a
/// different channel is refused (Linux 7.3-rc4 combo0/p2p-combination
/// single-channel rule for STA+AP: mchan licenses STA+STA and P2P,
/// never STA+AP), before any firmware mutation, leaving the primary
/// joined and the secondary shell down. The positive control is
/// `primary_station_secondary_ap` (same channel starts).
fn primary_station_secondary_ap_channel_refusal() -> Result<(), &'static str> {
    use super::ap_native_tests::{config, Source};
    use narf_capabilities::{Cap, Invoke};
    use narf_wireless::ap_control::ApControlAuthority;
    const NAME: &str = "wlvap7";
    let (adapter, bus) = firmware::create(7, false).map_err(|_| "CR4 msgbuf attach")?;
    bus.enable_vif_ap();
    bus.set_caps(b"ap sta mchan");
    let database = Arc::new(narf_wireless::reg::db::Database::new());
    database.install(firmware::domain());
    let mut station = block(Station::initialize_live(adapter, &[], database.clone()))
        .map_err(|_| "primary station over msgbuf")?;
    cache(
        &mut station,
        AP,
        6,
        narf_wireless::scan::BssSecurity::Open,
        &[],
    );
    block(station.associate(request(
        AP,
        6,
        narf_wireless::SecurityConfig::Open,
        Vec::new(),
    )))
    .map_err(|_| "primary join")?;
    let owner = block(super::vif::discover(&mut station.runtime, station.mac))
        .map_err(|_| "cap discovery")?
        .ok_or("firmware cap refused")?;
    if !owner.features().mchan || owner.features().mbss {
        return Err("cap tokens not parsed as brcmf_feat_attach");
    }
    let name = narf_net::iface::register("wlan%d", OWN, send);
    let device = shell(name.clone(), station);
    device.state.try_lock().ok_or("state")?.vif = Some(owner);
    device.ap_fixture_setup(database);
    super::vif::register_primary(&device);
    let result = (|| {
        let vap = device
            .vif_new(NAME, 3, None)
            .map_err(|_| "secondary AP shell admission")?;
        block(device.vif_worker());
        if vap.ap_sme_capabilities() != Some(0) {
            return Err("secondary AP shell not attached after IF ADD");
        }
        narf_net::iface::set_link_state(NAME, true);
        let cap = narf_net::registry()
            .with_handle(NAME, |cap| *cap)
            .ok_or("secondary netdev handle")?;
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon: Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap(),
        })
        .map_err(|_| "secondary admin authority")?
        .admin;
        let iface: Arc<dyn WirelessNetIface> = vap.clone();
        let source = Arc::new(Source::new());
        let authority = ApControlAuthority::bind(
            admin,
            &iface,
            0,
            narf_net::iface::lookup(NAME).ok_or("ifindex")?.ifindex,
            source.clone(),
        )
        .map_err(|_| "AP authority bind")?
        .reserve()
        .map_err(|_| "AP control reservation")?;
        let (mut ap_config, settings) = config(false);
        ap_config.beacon_head[10..22].copy_from_slice(&[VIF, VIF].concat());
        // Primary STA is on channel 6 (2437 MHz); channel 1 (2412 MHz)
        // must be refused by the STA+AP single-channel rule. Channel 1
        // is in the fixture's channel list ([1, 6, 11]); any channel
        // outside it would be refused earlier by the channel-support
        // check instead of by the single-channel rule.
        ap_config.frequency_mhz = 2412;
        let before = bus.commands().len();
        match block(vap.start_ap_with_settings_async(&authority, ap_config, settings)) {
            Err(narf_wireless::WirelessError::NotSupported) => {}
            _ => return Err("off-channel secondary AP START not refused"),
        }
        if bus.commands().len() != before {
            return Err("refused secondary AP START mutated firmware state");
        }
        if vap.link_up() {
            return Err("refused secondary AP left its shell up");
        }
        if device.state.try_lock().ok_or("state")?.station.bssid != Some(AP) {
            return Err("refused secondary AP disturbed the primary");
        }
        Ok(())
    })();
    super::vif::withdraw_family(crate::cyw43439::fullmac::Family::Pcie);
    bus.d3_ack(true);
    let _ = block(device.teardown());
    *ACTIVE_TEST.lock() = None;
    narf_net::registry().unregister(&name);
    narf_net::iface::unregister(&name);
    result
}

fn smoke_brcmf_msgbuf_primary_station_secondary_ap_channel_refusal() -> TestResult {
    match primary_station_secondary_ap_channel_refusal() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_msgbuf_primary_station_secondary_ap_channel_refusal
);

/// Linux `vif->mbss` multi-AP over msgbuf: a secondary AP START beside
/// a running primary AP on the same channel (firmware `mbss` cap),
/// then secondary teardown that keeps `mbss 1` while the primary AP
/// runs, then primary teardown.
fn primary_ap_secondary_ap_mbss() -> Result<(), &'static str> {
    use super::ap_native_tests::{config, Source};
    use narf_capabilities::{Cap, Invoke};
    use narf_wireless::ap_control::ApControlAuthority;
    const NAME: &str = "wlvap7";
    let (adapter, bus) = firmware::create(7, false).map_err(|_| "CR4 msgbuf attach")?;
    bus.enable_ap();
    bus.enable_vif_ap();
    // No `mchan`: the MBSS path must skip DOWN/apsta even though a
    // lone secondary AP would perform them.
    bus.set_caps(b"ap sta mbss");
    let database = Arc::new(narf_wireless::reg::db::Database::new());
    database.install(firmware::domain());
    let mut station = block(Station::initialize_live(adapter, &[], database.clone()))
        .map_err(|_| "primary station over msgbuf")?;
    let owner = block(super::vif::discover(&mut station.runtime, station.mac))
        .map_err(|_| "cap discovery")?
        .ok_or("firmware cap refused")?;
    if !owner.features().mbss || owner.features().mchan {
        return Err("cap tokens not parsed as mbss without mchan");
    }
    let name = narf_net::iface::register("wlan%d", OWN, send);
    let device = shell(name.clone(), station);
    device.state.try_lock().ok_or("state")?.vif = Some(owner);
    device.ap_fixture_setup(database);
    super::vif::register_primary(&device);
    narf_net::iface::set_link_state(&name, false);
    device.set_iftype(3).map_err(|_| "primary AP mode")?;
    let cap = narf_net::registry()
        .register(&narf_net::bootstrap_authority(), Registered(device.clone()))
        .map_err(|_| "primary registered netdev")?;
    let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
        iface: cap,
        daemon: Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap(),
    })
    .map_err(|_| "primary admin authority")?
    .admin;
    let iface: Arc<dyn WirelessNetIface> = device.clone();
    narf_wireless::registry::register(iface.clone());
    narf_net::iface::set_link_state(&name, true);
    let result = (|| {
        let primary_source = Arc::new(Source::new());
        let primary_authority = ApControlAuthority::bind(
            admin.clone(),
            &iface,
            0,
            narf_net::iface::lookup(&name).ok_or("ifindex")?.ifindex,
            primary_source.clone(),
        )
        .map_err(|_| "primary AP authority bind")?
        .reserve()
        .map_err(|_| "primary AP control reservation")?;
        let (primary_config, primary_settings) = config(false);
        block(device.start_ap_with_settings_async(
            &primary_authority,
            primary_config,
            primary_settings,
        ))
        .map_err(|_| "primary AP START")?;
        if !bus.ap_change(|p| p.active && p.up && p.formed) {
            return Err("primary AP not running");
        }
        let vap = device
            .vif_new(NAME, 3, None)
            .map_err(|_| "secondary AP shell admission")?;
        block(device.vif_worker());
        if vap.ap_sme_capabilities() != Some(0) {
            return Err("secondary AP shell not attached after IF ADD");
        }
        narf_net::iface::set_link_state(NAME, true);
        let secondary_cap = narf_net::registry()
            .with_handle(NAME, |cap| *cap)
            .ok_or("secondary netdev handle")?;
        let secondary_admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: secondary_cap,
            daemon: Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap(),
        })
        .map_err(|_| "secondary admin authority")?
        .admin;
        let secondary_iface: Arc<dyn WirelessNetIface> = vap.clone();
        let source = Arc::new(Source::new());
        let authority = ApControlAuthority::bind(
            secondary_admin,
            &secondary_iface,
            0,
            narf_net::iface::lookup(NAME).ok_or("ifindex")?.ifindex,
            source.clone(),
        )
        .map_err(|_| "secondary AP authority bind")?
        .reserve()
        .map_err(|_| "secondary AP control reservation")?;
        let (mut ap_config, settings) = config(false);
        ap_config.beacon_head[10..22].copy_from_slice(&[VIF, VIF].concat());
        let before = bus.commands().len();
        block(vap.start_ap_with_settings_async(&authority, ap_config, settings))
            .map_err(|_| "secondary AP START beside primary AP")?;
        let commands = bus.commands();
        let ifidx = bus.command_ifidx();
        let program: Vec<_> = commands[before..].iter().zip(&ifidx[before..]).collect();
        // MBSS program on ifidx 1: no shared DOWN/apsta, `mbss 1` once.
        let mbss_set = b"mbss\0\x01\x00\x00\x00".to_vec();
        let mbss_sets = program
            .iter()
            .filter(|((command, body, _), _)| *command == 263 && **body == mbss_set)
            .count();
        if program.iter().any(|(_, index)| **index != 1)
            || program
                .iter()
                .any(|((command, body, _), _)| *command == 3 || body.starts_with(b"apsta\0"))
            || mbss_sets != 1
        {
            return Err("secondary AP Program not the MBSS bsscfg-1 form");
        }
        if !bus.vif_ap_change(|p| p.active && p.up && p.formed)
            || !bus.ap_change(|p| p.active && p.up && p.formed)
            || !vap.link_up()
        {
            return Err("secondary AP not running beside the primary AP");
        }
        let stop_before = bus.commands().len();
        block(vap.stop_ap_async(&authority)).map_err(|_| "secondary AP STOP")?;
        let stop_commands = bus.commands();
        let stop_ifidx = bus.command_ifidx();
        let mbss_clear = b"mbss\0\x00\x00\x00\x00".to_vec();
        if stop_commands[stop_before..]
            .iter()
            .zip(&stop_ifidx[stop_before..])
            .any(|((command, body, _), index)| {
                *command == 263 && *index == 1 && **body == mbss_clear
            })
            || bus.vif_ap_change(|p| p.active)
            || vap.link_up()
            || !bus.ap_change(|p| p.active && p.up && p.formed)
        {
            return Err("secondary AP stop cleared mbss or disturbed the primary AP");
        }
        block(device.stop_ap_async(&primary_authority)).map_err(|_| "primary AP STOP")?;
        if bus.ap_change(|p| p.active) {
            return Err("primary AP stop kept its BSS");
        }
        Ok(())
    })();
    super::vif::withdraw_family(crate::cyw43439::fullmac::Family::Pcie);
    bus.d3_ack(true);
    let _ = block(device.teardown());
    *ACTIVE_TEST.lock() = None;
    narf_wireless::registry::unregister(&name);
    narf_net::registry().unregister(&name);
    narf_net::iface::unregister(&name);
    result
}

fn smoke_brcmf_msgbuf_primary_ap_secondary_ap_mbss() -> TestResult {
    match primary_ap_secondary_ap_mbss() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_msgbuf_primary_ap_secondary_ap_mbss
);

/// MBSS channel agreement: a secondary AP requesting another channel
/// beside a running primary AP is refused before any firmware
/// mutation, and the primary AP is undisturbed.
fn secondary_ap_mbss_channel_mismatch() -> Result<(), &'static str> {
    use super::ap_native_tests::{config, Source};
    use narf_capabilities::{Cap, Invoke};
    use narf_wireless::ap_control::ApControlAuthority;
    const NAME: &str = "wlvap7";
    let (adapter, bus) = firmware::create(7, false).map_err(|_| "CR4 msgbuf attach")?;
    bus.enable_ap();
    bus.enable_vif_ap();
    bus.set_caps(b"ap sta mbss");
    let database = Arc::new(narf_wireless::reg::db::Database::new());
    database.install(firmware::domain());
    let mut station = block(Station::initialize_live(adapter, &[], database.clone()))
        .map_err(|_| "primary station over msgbuf")?;
    let owner = block(super::vif::discover(&mut station.runtime, station.mac))
        .map_err(|_| "cap discovery")?
        .ok_or("firmware cap refused")?;
    if !owner.features().mbss {
        return Err("cap tokens not parsed as mbss");
    }
    let name = narf_net::iface::register("wlan%d", OWN, send);
    let device = shell(name.clone(), station);
    device.state.try_lock().ok_or("state")?.vif = Some(owner);
    device.ap_fixture_setup(database);
    super::vif::register_primary(&device);
    narf_net::iface::set_link_state(&name, false);
    device.set_iftype(3).map_err(|_| "primary AP mode")?;
    let cap = narf_net::registry()
        .register(&narf_net::bootstrap_authority(), Registered(device.clone()))
        .map_err(|_| "primary registered netdev")?;
    let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
        iface: cap,
        daemon: Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap(),
    })
    .map_err(|_| "primary admin authority")?
    .admin;
    let iface: Arc<dyn WirelessNetIface> = device.clone();
    narf_wireless::registry::register(iface.clone());
    narf_net::iface::set_link_state(&name, true);
    let result = (|| {
        let primary_source = Arc::new(Source::new());
        let primary_authority = ApControlAuthority::bind(
            admin.clone(),
            &iface,
            0,
            narf_net::iface::lookup(&name).ok_or("ifindex")?.ifindex,
            primary_source.clone(),
        )
        .map_err(|_| "primary AP authority bind")?
        .reserve()
        .map_err(|_| "primary AP control reservation")?;
        let (primary_config, primary_settings) = config(false);
        block(device.start_ap_with_settings_async(
            &primary_authority,
            primary_config,
            primary_settings,
        ))
        .map_err(|_| "primary AP START")?;
        if !bus.ap_change(|p| p.active && p.up && p.formed) {
            return Err("primary AP not running");
        }
        let vap = device
            .vif_new(NAME, 3, None)
            .map_err(|_| "secondary AP shell admission")?;
        block(device.vif_worker());
        if vap.ap_sme_capabilities() != Some(0) {
            return Err("secondary AP shell not attached after IF ADD");
        }
        narf_net::iface::set_link_state(NAME, true);
        let secondary_cap = narf_net::registry()
            .with_handle(NAME, |cap| *cap)
            .ok_or("secondary netdev handle")?;
        let secondary_admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: secondary_cap,
            daemon: Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap(),
        })
        .map_err(|_| "secondary admin authority")?
        .admin;
        let secondary_iface: Arc<dyn WirelessNetIface> = vap.clone();
        let source = Arc::new(Source::new());
        let authority = ApControlAuthority::bind(
            secondary_admin,
            &secondary_iface,
            0,
            narf_net::iface::lookup(NAME).ok_or("ifindex")?.ifindex,
            source.clone(),
        )
        .map_err(|_| "secondary AP authority bind")?
        .reserve()
        .map_err(|_| "secondary AP control reservation")?;
        // Primary AP runs on channel 6 (2437 MHz); request channel 1.
        let (mut ap_config, settings) = config(false);
        ap_config.beacon_head[10..22].copy_from_slice(&[VIF, VIF].concat());
        ap_config.frequency_mhz = 2412;
        let before = bus.commands().len();
        if block(vap.start_ap_with_settings_async(&authority, ap_config, settings)).is_ok() {
            return Err("channel-mismatched secondary AP START was admitted");
        }
        let commands = bus.commands();
        let ifidx = bus.command_ifidx();
        if commands[before..]
            .iter()
            .zip(&ifidx[before..])
            .any(|((command, _, _), index)| *command == 26 && *index == 1)
            || vap.link_up()
            || !bus.ap_change(|p| p.active && p.up && p.formed)
        {
            return Err("refused secondary AP mutated firmware or disturbed the primary AP");
        }
        block(device.stop_ap_async(&primary_authority)).map_err(|_| "primary AP STOP")?;
        Ok(())
    })();
    super::vif::withdraw_family(crate::cyw43439::fullmac::Family::Pcie);
    bus.d3_ack(true);
    let _ = block(device.teardown());
    *ACTIVE_TEST.lock() = None;
    narf_wireless::registry::unregister(&name);
    narf_net::registry().unregister(&name);
    narf_net::iface::unregister(&name);
    result
}

fn smoke_brcmf_msgbuf_secondary_ap_mbss_channel_mismatch() -> TestResult {
    match secondary_ap_mbss_channel_mismatch() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_msgbuf_secondary_ap_mbss_channel_mismatch
);

/// Linux 7.3-rc4 `p2p.c` `brcmf_p2p_add_vif` (GO) and `cfg80211.c`
/// `brcmf_cfg80211_start_ap`/`_stop_ap` P2P_GO branch over msgbuf: the
/// GO connection bsscfg comes from `p2p_ifadd` on the primary, its BSS is
/// formed by bsscfg `ssid` + `bss` enable on ifidx 1 (no `SET_AP`, `UP`,
/// `SET_SSID`, `DOWN` or `apsta`), a client associates, STOP is `bss`
/// disable, and DEL is `p2p_ifdis` (LINK_BSSCFG_DIS) + `p2p_ifdel` + IF DEL.
fn p2p_go_lifecycle() -> Result<(), &'static str> {
    use super::ap_native_tests::{association, config, Source};
    use crate::brcmfmac::runtime_tests::station_model::ap_model::CLIENT;
    use narf_capabilities::{Cap, Invoke};
    use narf_wireless::ap_control::ApControlAuthority;
    const NAME: &str = "p2pgo7";
    let (adapter, bus) = firmware::create(7, false).map_err(|_| "CR4 msgbuf attach")?;
    bus.enable_vif_ap();
    bus.set_caps(b"ap sta mchan p2p");
    let database = Arc::new(narf_wireless::reg::db::Database::new());
    database.install(firmware::domain());
    let mut station = block(Station::initialize_live(adapter, &[], database.clone()))
        .map_err(|_| "primary station over msgbuf")?;
    cache(
        &mut station,
        AP,
        6,
        narf_wireless::scan::BssSecurity::Open,
        &[],
    );
    block(station.associate(request(
        AP,
        6,
        narf_wireless::SecurityConfig::Open,
        Vec::new(),
    )))
    .map_err(|_| "primary join")?;
    let owner = block(super::vif::discover(&mut station.runtime, station.mac))
        .map_err(|_| "cap discovery")?
        .ok_or("firmware cap refused")?;
    if !owner.features().p2p {
        return Err("p2p cap token not parsed");
    }
    let name = narf_net::iface::register("wlan%d", OWN, send);
    let device = shell(name.clone(), station);
    device.state.try_lock().ok_or("state")?.vif = Some(owner);
    device.ap_fixture_setup(database);
    super::vif::register_primary(&device);
    let result = (|| {
        let before_add = bus.commands().len();
        let go = device
            .vif_new(NAME, 9, None)
            .map_err(|_| "P2P_GO shell admission")?;
        block(device.vif_worker());
        let commands = bus.commands();
        let ifidx = bus.command_ifidx();
        let added: Vec<_> = commands[before_add..]
            .iter()
            .zip(&ifidx[before_add..])
            .collect();
        if go.current_iftype() != 9
            || go.ap_sme_capabilities() != Some(0)
            || !added.iter().any(|((command, body, _), index)| {
                *command == 263 && **index == 0 && body.starts_with(b"p2p_ifadd\0")
            })
            || added
                .iter()
                .any(|((_, body, _), _)| body.starts_with(b"interface_create\0"))
            || !added
                .iter()
                .any(|((command, _, _), index)| *command == 158 && **index == 1)
        {
            return Err("GO shell not created by p2p_ifadd with SCB timeout");
        }
        narf_net::iface::set_link_state(NAME, true);
        let cap = narf_net::registry()
            .with_handle(NAME, |cap| *cap)
            .ok_or("GO netdev handle")?;
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon: Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap(),
        })
        .map_err(|_| "GO admin authority")?
        .admin;
        let iface: Arc<dyn WirelessNetIface> = go.clone();
        let source = Arc::new(Source::new());
        let authority = ApControlAuthority::bind(
            admin,
            &iface,
            0,
            narf_net::iface::lookup(NAME).ok_or("ifindex")?.ifindex,
            source.clone(),
        )
        .map_err(|_| "GO authority bind")?
        .reserve()
        .map_err(|_| "GO control reservation")?;
        let (mut ap_config, settings) = config(false);
        ap_config.beacon_head[10..22].copy_from_slice(&[VIF, VIF].concat());
        let before = bus.commands().len();
        block(go.start_ap_with_settings_async(&authority, ap_config, settings))
            .map_err(|_| "P2P GO START")?;
        let commands = bus.commands();
        let ifidx = bus.command_ifidx();
        let program: Vec<_> = commands[before..].iter().zip(&ifidx[before..]).collect();
        let mut ssid = b"bsscfg:ssid\0".to_vec();
        ssid.extend_from_slice(&1u32.to_le_bytes());
        let mut enable = b"bss\0".to_vec();
        enable.extend_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0]);
        let position = |prefix: &[u8]| {
            program
                .iter()
                .position(|((_, body, _), _)| body.starts_with(prefix))
        };
        if program.iter().any(|(_, index)| **index != 1)
            || program.iter().any(|((command, body, _), _)| {
                matches!(*command, 2 | 3 | 26 | 118)
                    || body.starts_with(b"apsta\0")
                    || body.starts_with(b"mbss\0")
                    || body.starts_with(b"closednet\0")
            })
            || position(&ssid).is_none()
            || position(&enable).is_none()
            || position(b"chanspec\0") >= position(&ssid)
            || position(&ssid) >= position(&enable)
        {
            return Err("GO Program not the start_ap P2P_GO branch on bsscfg 1");
        }
        if !bus.vif_ap_change(|p| p.active && p.up && p.formed) || !go.link_up() {
            return Err("GO BSS not formed");
        }
        bus.vif_ap_change(|p| p.associate(CLIENT, association(false)));
        for _ in 0..4 {
            block(device.vif_worker());
        }
        if source.count(19) != 1 {
            return Err("GO NEW_STATION not observed on its shell");
        }
        let before = bus.commands().len();
        block(go.stop_ap_async(&authority)).map_err(|_| "P2P GO STOP")?;
        let commands = bus.commands();
        let mut disable = b"bss\0".to_vec();
        disable.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        if !commands[before..]
            .iter()
            .any(|(command, body, _)| *command == 263 && *body == disable)
            || commands[before..]
                .iter()
                .any(|(command, _, _)| matches!(*command, 2 | 3 | 26 | 118))
            || bus.vif_ap_change(|p| p.active || !p.peers.is_empty())
            || go.link_up()
            || device.state.try_lock().ok_or("state")?.station.bssid != Some(AP)
        {
            return Err("GO STOP not bss disable beside the joined primary");
        }
        let before = bus.commands().len();
        go.delete_virtual_interface()
            .map_err(|_| "GO DEL_INTERFACE")?;
        for _ in 0..6 {
            block(device.vif_worker());
        }
        let commands = bus.commands();
        let ifdis = commands[before..]
            .iter()
            .position(|(_, body, _)| body.starts_with(b"p2p_ifdis\0"));
        let ifdel = commands[before..]
            .iter()
            .position(|(_, body, _)| body.starts_with(b"p2p_ifdel\0"));
        if ifdis.is_none()
            || ifdel.is_none()
            || ifdis >= ifdel
            || narf_net::iface::lookup(NAME).is_some()
        {
            return Err("GO DEL not p2p_ifdis + p2p_ifdel + IF DEL");
        }
        Ok(())
    })();
    super::vif::withdraw_family(crate::cyw43439::fullmac::Family::Pcie);
    bus.d3_ack(true);
    let _ = block(device.teardown());
    *ACTIVE_TEST.lock() = None;
    narf_net::registry().unregister(&name);
    narf_net::iface::unregister(&name);
    result
}

fn smoke_brcmf_msgbuf_p2p_go_start_client_stop_and_delete() -> TestResult {
    match p2p_go_lifecycle() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_msgbuf_p2p_go_start_client_stop_and_delete
);

impl crate::brcmfmac::p2p_transport_cases::Model for firmware::Handle {
    fn event(&self, kind: u32, source: [u8; 6], data: &[u8]) {
        self.secondary_event_data(kind, source, data);
    }
    fn sets(&self) -> Vec<(u32, Vec<u8>)> {
        self.vif_sets()
    }
    fn commands(&self) -> Vec<(u8, Vec<u8>)> {
        self.command_ifidx()
            .into_iter()
            .zip(self.commands())
            .map(|(ifidx, (_, body, _))| (ifidx, body))
            .collect()
    }
}

/// P2P_DEVICE discovery bsscfg over the actual CR4/msgbuf rings
/// (`p2p_transport_cases::discovery`).
fn p2p_discovery() -> Result<(), &'static str> {
    let (adapter, bus) = firmware::create(7, false).map_err(|_| "CR4 msgbuf attach")?;
    let mut station = block(Station::initialize(adapter, &[], firmware::domain()))
        .map_err(|_| "primary station over msgbuf")?;
    crate::brcmfmac::p2p_transport_cases::discovery(&mut station, &bus)
}

fn smoke_brcmf_msgbuf_p2p_discovery_listen_action_and_escan() -> TestResult {
    match p2p_discovery() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_msgbuf_p2p_discovery_listen_action_and_escan
);

/// P2P_CLIENT connection bsscfg join over the actual CR4/msgbuf rings.
fn p2p_client() -> Result<(), &'static str> {
    let (adapter, bus) = firmware::create(7, false).map_err(|_| "CR4 msgbuf attach")?;
    let mut station = block(Station::initialize(adapter, &[], firmware::domain()))
        .map_err(|_| "primary station over msgbuf")?;
    crate::brcmfmac::p2p_transport_cases::client_join(&mut station, &bus)
}

fn smoke_brcmf_msgbuf_p2p_client_joins_on_ifidx_one() -> TestResult {
    match p2p_client() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_msgbuf_p2p_client_joins_on_ifidx_one
);

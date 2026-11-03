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
    vif_owner::{Owner, Role},
    vif_wire::Features,
};

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
    station
        .runtime
        .send_vif_data(1, &frame(), 0)
        .map_err(|_| "secondary data admission")?;
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

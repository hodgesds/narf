// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-bsscfg Fullmac adapter over the scripted seam: Linux 7.3-rc4
//! `fwil.c` `brcmf_fil_bsscfg_*` vs `brcmf_fil_iovar_*` addressing,
//! `fweh.c` per-bsscfg event dispatch and `brcmf_get_ifp` data routing.
use super::{
    vif_bsscfg::{wire_command, Bsscfg, Link, Parked},
    vif_owner::{Owner, Role},
    vif_wire::Features,
};
use crate::cyw43439::{
    fullmac::Fullmac,
    fullmac_fixture::{ready, Firmware, Mock},
    ioctl::Direction,
    runtime::Error,
};
use alloc::{boxed::Box, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const PRIMARY: [u8; 6] = [0x00, 0x90, 0x4c, 0x11, 0x22, 0x33];
const VIF: [u8; 6] = [0x02, 0x90, 0x4c, 0xb1, 0x22, 0x33];
const PEER: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

fn iovar(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = name.to_vec();
    out.push(0);
    out.extend_from_slice(data);
    out
}

fn smoke_brcmf_vif_bsscfg_adapter_addresses_its_own_interface() -> TestResult {
    // brcmf_create_bsscfg wire form; plain iovars and dcmds are unchanged.
    let mut prefixed = b"bsscfg:wsec\0".to_vec();
    prefixed.extend_from_slice(&2u32.to_le_bytes());
    prefixed.extend_from_slice(&4u32.to_le_bytes());
    if wire_command(2, 263, &iovar(b"wsec", &4u32.to_le_bytes())) != Ok(Some(prefixed.clone()))
        || wire_command(2, 263, &iovar(b"cur_etheraddr", &VIF)) != Ok(None)
        || wire_command(2, 20, &1u32.to_le_bytes()) != Ok(None)
        || wire_command(2, 262, b"wsec") != Err(Error::Malformed)
    {
        return TestResult::Fail("bsscfg iovar classification differs from fwil.c");
    }
    let mut fw = Firmware::new();
    fw.hook = Some(Box::new(|fw, command| {
        if command.direction == Direction::Get && command.iovar() == Some(b"interface_create") {
            fw.if_event(1, 1, 2, 1, VIF);
            return Some(Ok(Vec::new()));
        }
        None
    }));
    let mut runtime = Mock::<true>::new(fw);
    let mut owner = Owner::new(PRIMARY, Features::default());
    let Some(Ok(entry)) = ready(owner.create(&mut runtime, Role::Ap, None)) else {
        return TestResult::Fail("secondary interface create");
    };
    if runtime.vif_open(entry.ifidx).is_err() {
        return TestResult::Fail("vif_open");
    }
    let mut link = Link::new(entry);
    let before = runtime.fw.vif_log.len();
    {
        let mut adapter = Bsscfg::new(&mut runtime, &mut owner, &mut link);
        let wsec = iovar(b"wsec", &4u32.to_le_bytes());
        let mac = iovar(b"cur_etheraddr", &VIF);
        if ready(adapter.command(Direction::Set, 263, &wsec, 1502)).is_none()
            || ready(adapter.command(Direction::Set, 263, &mac, 1502)).is_none()
            || ready(adapter.command(Direction::Set, 20, &1u32.to_le_bytes(), 4)).is_none()
        {
            return TestResult::Fail("adapter command did not complete");
        }
    }
    let log = &runtime.fw.vif_log[before..];
    if log.len() != 3
        || log.iter().any(|(ifidx, _)| *ifidx != 1)
        || log[0].1.body != prefixed
        || log[1].1.body != iovar(b"cur_etheraddr", &VIF)
        || log[2].1.command != 20
    {
        return TestResult::Fail("adapter commands not addressed to ifidx/bsscfg");
    }
    // Events: only this bsscfg's; interface-0 events stay with the primary.
    runtime.fw.secondary_event(16, 1, 2, PEER, &[]);
    runtime.fw.secondary_event(16, 3, 3, PEER, &[]);
    runtime.fw.event(16, 0, 0, PEER, &[]);
    runtime.fw.vif_data.push_back((1, alloc::vec![0xaa; 20]));
    runtime.fw.vif_data.push_back((2, alloc::vec![0xbb; 20]));
    {
        let mut adapter = Bsscfg::new(&mut runtime, &mut owner, &mut link);
        if adapter.poll().is_err()
            || adapter.pop_event().map(|e| e.header.bsscfg_idx) != Some(2)
            || adapter.pop_event().is_some()
            || adapter.pop_data() != Some(alloc::vec![0xaa; 20])
            || adapter.pop_data().is_some()
            || adapter.send_data(&[0xcc; 20], 5).is_err()
        {
            return TestResult::Fail("adapter event/data routing");
        }
        adapter.set_link(Some(PEER));
    }
    if runtime.pop_event().map(|e| e.header.bsscfg_idx) != Some(0)
        || runtime.fw.vif_sent.last().map(|(i, _, p)| (*i, *p)) != Some((1, 5))
        || link.peer() != Some(PEER)
    {
        return TestResult::Fail("primary queues or link record disturbed");
    }
    // Unsolicited IF DEL: the adapter fail-stops locally, primary intact.
    runtime.fw.if_event(2, 1, 2, 1, VIF);
    let before = runtime.fw.vif_log.len();
    {
        let mut adapter = Bsscfg::new(&mut runtime, &mut owner, &mut link);
        if adapter.poll() != Err(Error::Failed)
            || ready(adapter.command(Direction::Set, 20, &1u32.to_le_bytes(), 4))
                != Some(Err(Error::Failed))
            || !adapter.transport_failed()
        {
            return TestResult::Fail("retired bsscfg kept command authority");
        }
    }
    if !link.failed()
        || link.peer().is_some()
        || runtime.fw.vif_log.len() != before
        || runtime.fw.failed
        || ready(runtime.command(Direction::Get, 1, &[0; 4], 4)).is_none()
    {
        return TestResult::Fail("bsscfg failure leaked to the primary");
    }
    let mut parked = Parked::<Mock<true>>::new();
    if parked.poll() != Err(Error::Failed)
        || ready(parked.command(Direction::Get, 1, &[], 4)) != Some(Err(Error::Failed))
    {
        return TestResult::Fail("parked runtime accepted work");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_vif_bsscfg_adapter_addresses_its_own_interface
);

/// Secondary station role over the adapter: Linux 7.3-rc4
/// `brcmf_cfg80211_connect` on an additional STA `brcmf_if` (dcmds on its
/// ifidx, `brcmf_fil_bsscfg_*` security iovars, events of its bsscfg).
fn secondary_station<const PCIE: bool>() -> Result<(), &'static str> {
    use crate::cyw43439::fullmac_fixture::{cache, init_station, request, AP};
    let mut fw = Firmware::new();
    fw.join_events = false;
    fw.hook = Some(Box::new(|fw, command| {
        if command.direction == Direction::Get && command.iovar() == Some(b"interface_create") {
            fw.if_event(1, 2, 3, 0, VIF);
            return Some(Ok(Vec::new()));
        }
        // The join addressed to ifidx 2 completes on bsscfg 3 only.
        if command.direction == Direction::Set
            && command.command == 26
            && fw
                .vif_log
                .last()
                .is_some_and(|(ifidx, last)| *ifidx == 2 && last.command == 26)
        {
            fw.associated = true;
            let peer = fw.bssid;
            fw.secondary_event(16, 2, 3, peer, &[]);
            if let Some(link) = fw.vif_events.back_mut() {
                link.header.flags = 1;
            }
            fw.secondary_event(0, 2, 3, peer, &[]);
            return Some(Ok(Vec::new()));
        }
        None
    }));
    let mut primary = init_station::<PCIE>(fw)?;
    let features = Features {
        p2p: true,
        mchan: true,
        ..Features::default()
    };
    let mut owner = Owner::new(primary.mac, features);
    let entry = ready(owner.create(&mut primary.runtime, Role::Station, Some(VIF)))
        .ok_or("create pended")?
        .map_err(|_| "secondary STA create")?;
    primary
        .runtime
        .vif_open(entry.ifidx)
        .map_err(|_| "vif_open")?;
    let parked = primary.secondary(entry.mac);
    let mut link = Link::new(entry);
    let before = primary.runtime.fw.vif_log.len();
    let primary_log = primary.runtime.fw.events.len();
    let parked = {
        let adapter = Bsscfg::new(&mut primary.runtime, &mut owner, &mut link);
        let (mut station, rest) = parked.rebind(adapter);
        ready(station.configure_secondary())
            .ok_or("configure pended")?
            .map_err(|_| "per-interface dcmds")?;
        cache(
            &mut station,
            AP,
            6,
            narf_wireless::scan::BssSecurity::Open,
            &[],
        );
        ready(station.associate(request(
            AP,
            6,
            narf_wireless::SecurityConfig::Open,
            Vec::new(),
        )))
        .ok_or("join pended")?
        .map_err(|_| "secondary join")?;
        station.rebind(rest).0
    };
    let fw = &primary.runtime.fw;
    let log = &fw.vif_log[before..];
    let mut wpa_auth = b"bsscfg:wpa_auth\0".to_vec();
    wpa_auth.extend_from_slice(&3u32.to_le_bytes());
    let mut wsec = b"bsscfg:wsec\0".to_vec();
    wsec.extend_from_slice(&3u32.to_le_bytes());
    if log.iter().any(|(ifidx, _)| *ifidx != 2)
        || ![86u32, 20, 22, 26]
            .iter()
            .all(|dcmd| log.iter().any(|(_, c)| c.command == *dcmd))
        // brcmf_set_wsec_mode: bsscfg-prefixed "wsec", never WLC_SET_WSEC.
        || log.iter().any(|(_, c)| c.command == 134)
        || !log.iter().any(|(_, c)| c.body.starts_with(&wsec))
        || !log.iter().any(|(_, c)| c.body.starts_with(&wpa_auth))
        || log
            .iter()
            .any(|(_, c)| c.iovar() == Some(b"wsec") || c.iovar() == Some(b"wpa_auth"))
    {
        return Err("secondary commands not addressed to its ifidx/bsscfg");
    }
    if link.peer() != Some(AP)
        || parked.bssid != Some(AP)
        || primary.bssid.is_some()
        || fw.link.is_some()
        || fw.events.len() != primary_log
    {
        return Err("secondary link leaked into the primary interface");
    }
    // Deauthentication on the secondary bsscfg closes only its port.
    let peer = primary.runtime.fw.bssid;
    primary.runtime.fw.secondary_event(6, 2, 3, peer, &[]);
    let adapter = Bsscfg::new(&mut primary.runtime, &mut owner, &mut link);
    let (mut station, rest) = parked.rebind(adapter);
    let _ = station.poll();
    let (parked, _) = station.rebind(rest);
    if parked.bssid.is_some() || link.peer().is_some() {
        return Err("secondary deauthentication kept the port open");
    }
    Ok(())
}

fn smoke_brcmf_vif_secondary_station_joins_on_its_own_bsscfg() -> TestResult {
    for result in [secondary_station::<true>(), secondary_station::<false>()] {
        if let Err(reason) = result {
            return TestResult::Fail(reason);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_vif_secondary_station_joins_on_its_own_bsscfg
);

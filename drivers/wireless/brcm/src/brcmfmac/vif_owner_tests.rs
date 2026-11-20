// SPDX-License-Identifier: GPL-2.0-or-later
//! Secondary-interface command owner over the scripted FullMAC seam:
//! Linux 7.3-rc4 `brcmf_apsta_add_vif`/`brcmf_cfg80211_del_apsta_iface`
//! request order, IF-event waits and `brcmf_setup_ifmodes` combinations.
use super::{
    vif_owner::{admits, Owner, Role},
    vif_wire::{self, Features},
};
use crate::cyw43439::{
    fullmac_fixture::{ready, Firmware, Mock},
    ioctl::Direction,
    runtime::Error,
};
use alloc::{boxed::Box, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const PRIMARY: [u8; 6] = [0x00, 0x90, 0x4c, 0x11, 0x22, 0x33];
const VIF: [u8; 6] = [0x02, 0x90, 0x4c, 0xb1, 0x22, 0x33];

fn smoke_brcmf_vif_combinations_follow_setup_ifmodes() -> TestResult {
    let plain = Features::default();
    let mbss = Features {
        mbss: true,
        ..Features::default()
    };
    let p2p_mchan = Features {
        p2p: true,
        mchan: true,
        ..Features::default()
    };
    // Non-P2P combo0: one STA + one AP; MBSS adds an AP-only combination.
    if !admits(plain, 1, 1)
        || admits(plain, 2, 0)
        || admits(plain, 0, 2)
        || !admits(mbss, 0, 4)
        || admits(mbss, 0, 5)
        || admits(mbss, 1, 2)
        // P2P combo0 has no AP limit; the P2P combination allows STA+AP.
        || !admits(p2p_mchan, 2, 0)
        || !admits(p2p_mchan, 1, 1)
        || admits(p2p_mchan, 1, 2)
    {
        return TestResult::Fail("combination table differs from brcmf_setup_ifmodes");
    }
    let mut owner = Owner::new(PRIMARY, plain);
    if !owner.can_add(Role::Ap) || owner.can_add(Role::Station) {
        return TestResult::Fail("primary STA accounting");
    }
    owner.set_primary_role(Role::Ap);
    if owner.can_add(Role::Ap) || !owner.can_add(Role::Station) {
        return TestResult::Fail("primary AP accounting");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_vif_combinations_follow_setup_ifmodes
);

fn smoke_brcmf_vif_create_waits_for_if_add_and_remove_for_if_del() -> TestResult {
    let mut fw = Firmware::new();
    // v1 refused (-23), v2 accepted: the IF ADD follows the accepted request.
    fw.hook = Some(Box::new(|fw, command| {
        if command.direction == Direction::Get && command.iovar() == Some(b"interface_create") {
            if command.value().first() == Some(&1) {
                return Some(Err(Error::Firmware((-23i32) as u32)));
            }
            fw.if_event(1, 1, 2, 1, VIF);
            return Some(Ok(Vec::new()));
        }
        if command.direction == Direction::Set
            && command.iovar() == Some(b"bsscfg:interface_remove")
        {
            fw.if_event(2, 1, 2, 1, VIF);
            return Some(Ok(Vec::new()));
        }
        None
    }));
    let mut runtime = Mock::<true>::new(fw);
    let mut owner = Owner::new(PRIMARY, Features::default());
    let Some(Ok(entry)) = ready(owner.create(&mut runtime, Role::Ap, None)) else {
        return TestResult::Fail("AP interface create did not complete on IF ADD");
    };
    if entry.ifidx != 1 || entry.bsscfgidx != 2 || entry.mac != VIF || entry.p2p_device {
        return TestResult::Fail("created entry does not follow the native IF event");
    }
    // Each version re-derives the alternating vif MAC (brcmf_set_vif_sta_macaddr).
    let mut index = 0;
    let first = vif_wire::vif_mac(PRIMARY, &mut index);
    let second = vif_wire::vif_mac(PRIMARY, &mut index);
    let requests = runtime.fw.iovars(Direction::Get, b"interface_create");
    if requests.len() != 2
        || requests[0] != vif_wire::interface_create_v1(vif_wire::CreateKind::Ap, first)
        || requests[1] != vif_wire::interface_create_v2(vif_wire::CreateKind::Ap, second)
        || !runtime.fw.vif_listening
    {
        return TestResult::Fail("interface_create request order/encoding");
    }
    // A second AP exceeds combo0 without MBSS; nothing is sent.
    if ready(owner.create(&mut runtime, Role::Ap, None)) != Some(Err(Error::Unsupported))
        || runtime.fw.iovars(Direction::Get, b"interface_create").len() != 2
    {
        return TestResult::Fail("combination limit not enforced before request");
    }
    // brcmf_vif_change_validate: beside the live secondary AP the primary
    // may stay a STA (combo0) but may not also become an AP.
    if !owner.can_change_primary(Role::Station) || owner.can_change_primary(Role::Ap) {
        return TestResult::Fail("primary change not validated against live roles");
    }
    // Secondary non-IF events stay with their live bsscfg entry.
    runtime.fw.secondary_event(16, 1, 2, VIF, &[]);
    runtime.fw.secondary_event(16, 3, 3, VIF, &[]);
    if owner.service(&mut runtime).is_err()
        || owner.pop_event(&entry).map(|e| e.header.event_type) != Some(16)
        || owner.pop_event(&entry).is_some()
    {
        return TestResult::Fail("secondary bsscfg event dispatch");
    }
    if ready(owner.remove(&mut runtime, entry)) != Some(Ok(())) {
        return TestResult::Fail("remove did not complete on IF DEL");
    }
    let mut expected = b"bsscfg:interface_remove\0".to_vec();
    expected.extend_from_slice(&2u32.to_le_bytes());
    if runtime.fw.vif_log.len() != 1
        || runtime.fw.vif_log[0].0 != 1
        || runtime.fw.vif_log[0].1.body != expected
        || runtime.fw.vif_listening
        || owner.registry().by_bsscfgidx(2).is_some()
        || ready(owner.remove(&mut runtime, entry)) != Some(Err(Error::Authority))
    {
        return TestResult::Fail("interface_remove wire/teardown");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_vif_create_waits_for_if_add_and_remove_for_if_del
);

fn smoke_brcmf_vif_unsolicited_del_retires_and_station_has_no_mbss_fallback() -> TestResult {
    let mut fw = Firmware::new();
    fw.hook = Some(Box::new(|fw, command| {
        if command.direction == Direction::Get && command.iovar() == Some(b"interface_create") {
            fw.if_event(1, 2, 3, 0, VIF);
            return Some(Ok(Vec::new()));
        }
        None
    }));
    let features = Features {
        p2p: true,
        mchan: true,
        ..Features::default()
    };
    let mut runtime = Mock::<false>::new(fw);
    let mut owner = Owner::new(PRIMARY, features);
    let Some(Ok(entry)) = ready(owner.create(&mut runtime, Role::Station, Some(VIF))) else {
        return TestResult::Fail("station interface create");
    };
    // A caller STA MAC is used verbatim (request_sta_if).
    let requests = runtime.fw.iovars(Direction::Get, b"interface_create");
    if requests.len() != 1
        || requests[0] != vif_wire::interface_create_v1(vif_wire::CreateKind::Station, VIF)
        || entry.ifidx != 2
        || entry.bsscfgidx != 3
    {
        return TestResult::Fail("station request");
    }
    // fweh default: an unsolicited DEL removes the interface.
    runtime.fw.if_event(2, 2, 3, 0, VIF);
    if owner.service(&mut runtime).is_err() || owner.pop_retired() != Some(entry) {
        return TestResult::Fail("unsolicited IF DEL not retired");
    }
    // Every version refused: a STA has no bsscfg:ssid fallback.
    let mut fw = Firmware::new();
    fw.hook = Some(Box::new(|_, command| {
        (command.iovar() == Some(b"interface_create"))
            .then_some(Err(Error::Firmware((-23i32) as u32)))
    }));
    let mut runtime = Mock::<false>::new(fw);
    let mut owner = Owner::new(PRIMARY, features);
    if ready(owner.create(&mut runtime, Role::Station, None)) != Some(Err(Error::Unsupported))
        || runtime.fw.vif_listening
        || !runtime.fw.iovars(Direction::Set, b"bsscfg:ssid").is_empty()
    {
        return TestResult::Fail("station fallback or listener cleanup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_vif_unsolicited_del_retires_and_station_has_no_mbss_fallback
);

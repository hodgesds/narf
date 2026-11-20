// SPDX-License-Identifier: GPL-2.0-or-later
//! Literal Linux 7.3-rc4 encodings for the shared virtual-interface wire
//! foundation. These exercise wire/registry rules only; no interface,
//! role or data path is granted or composed by them.
use super::vif_wire::*;
use crate::cyw43439::runtime::Error;
use narf_kernel_test::{kernel_test_in, TestResult};

const PRIMARY: [u8; 6] = [0x00, 0x90, 0x4c, 0x11, 0x22, 0x33];

fn smoke_brcmf_vif_cap_tokens_and_mbss_chip_exclusion() -> TestResult {
    let caps = b"ap sta mbss mchan p2p rtap\0mbss_x";
    let Ok(found) = features(caps, 768, 43602) else {
        return TestResult::Fail("valid cap string rejected");
    };
    if found
        != (Features {
            mbss: true,
            mchan: true,
            p2p: true,
            monitor_flag: true,
        })
    {
        return TestResult::Fail("exact cap tokens not mapped");
    }
    // feature.c: brcmf_feat_attach clears MBSS on 4330/43362 only.
    if features(caps, 768, 43362).map(|f| f.mbss) != Ok(false)
        || features(caps, 768, 0x4330).map(|f| f.mbss) != Ok(false)
        || features(caps, 768, 43439).map(|f| f.mbss) != Ok(true)
    {
        return TestResult::Fail("MBSS chip exclusion differs from Linux");
    }
    // Prefix/suffix tokens and bytes after the C-string terminator are no
    // capabilities; an unterminated full buffer is malformed.
    if features(b"ap mbss_ext p2p_x\0mbss p2p", 768, 43602) != Ok(Features::default())
        || features(&[b'a'; 768], 768, 43602) != Err(Error::Malformed)
        || features(b"ap\x01mbss", 768, 43602) != Err(Error::Malformed)
    {
        return TestResult::Fail("cap token boundary not strict");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_vif_cap_tokens_and_mbss_chip_exclusion
);

fn smoke_brcmf_vif_bsscfg_iovar_and_interface_create_layouts() -> TestResult {
    // fwil.c::brcmf_create_bsscfg.
    if bsscfg_iovar(0, b"ssid", &[1, 2]).as_deref() != Ok(b"ssid\0\x01\x02".as_slice())
        || bsscfg_iovar(3, b"ssid", &[9]).as_deref()
            != Ok(b"bsscfg:ssid\0\x03\0\0\0\x09".as_slice())
        || bsscfg_iovar(MAX_IFS, b"ssid", &[]).is_ok()
        || bsscfg_iovar(2, b"a\0b", &[]).is_ok()
    {
        return TestResult::Fail("bsscfg iovar differs from brcmf_create_bsscfg");
    }
    // brcmf_set_vif_sta_macaddr alternates 0xA0/0xC0 on octet 3.
    let mut idx = 0;
    let first = vif_mac(PRIMARY, &mut idx);
    let second = vif_mac(PRIMARY, &mut idx);
    if first != [0x02, 0x90, 0x4c, 0xb1, 0x22, 0x33]
        || second != [0x02, 0x90, 0x4c, 0xd1, 0x22, 0x33]
        || idx != 0
    {
        return TestResult::Fail("vif MAC derivation differs");
    }
    let v1 = interface_create_v1(CreateKind::Ap, first);
    let v2 = interface_create_v2(CreateKind::Ap, first);
    let v3 = interface_create_v3(CreateKind::Ap, first);
    if v1
        != [
            1, 0, 0, 0, 3, 0, 0, 0, 0x02, 0x90, 0x4c, 0xb1, 0x22, 0x33, 0, 0, 0, 0, 0, 0,
        ]
        || v2
            != [
                2, 0, 0, 0, 2, 0, 0, 0, 0x02, 0x90, 0x4c, 0xb1, 0x22, 0x33, 1, 0, 0, 0, 0, 0,
            ]
        || v3
            != [
                3, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0x02, 0x90, 0x4c, 0xb1, 0x22, 0x33, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ]
        || interface_create_v1(CreateKind::Station, first)[4] != 2
    {
        return TestResult::Fail("wl_interface_create layout differs");
    }
    let Ok(ssid) = mbss_ssid(2) else {
        return TestResult::Fail("legacy mbss ssid rejected");
    };
    if ssid[..13] != *b"\x02\0\0\0\x05\0\0\0ssid2"
        || ssid[13..].iter().any(|b| *b != 0)
        || mbss_ssid(1).is_ok()
        || mbss_ssid(0).is_ok()
    {
        return TestResult::Fail("brcmf_mbss_ssid_le differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_vif_bsscfg_iovar_and_interface_create_layouts
);

fn smoke_brcmf_vif_if_event_classification_and_registry() -> TestResult {
    let add = [1u8, 1, 0, 2, 1];
    let Ok(event) = IfEvent::parse(E_IF, 5, &add) else {
        return TestResult::Fail("valid IF ADD rejected");
    };
    if event.role != IfRole::Ap
        || IfEvent::parse(E_IF, 4, &add[..4]).is_ok()
        || IfEvent::parse(E_IF, 5, &[1, 9, 0, 2, 1]).is_ok()
        || IfEvent::parse(E_IF, 5, &[1, 1, 0, 2, 9]).is_ok()
        || IfEvent::parse(16, 5, &add).is_ok()
    {
        return TestResult::Fail("IF event decode not strict");
    }
    // fweh.c: NOIF is ignored unless it is the P2P device.
    let noif_sta = IfEvent::parse(E_IF, 5, &[1, 1, 1, 1, 0]).unwrap();
    let noif_client = IfEvent::parse(E_IF, 5, &[1, 1, 1, 1, 4]).unwrap();
    if classify(noif_sta, false) != Disposition::Ignore
        || classify(noif_sta, true)
            != (Disposition::Apply {
                event: noif_sta,
                p2p_device: true,
            })
        || classify(noif_client, false)
            != (Disposition::Apply {
                event: noif_client,
                p2p_device: true,
            })
        || classify(IfEvent::parse(E_IF, 5, &[16, 1, 0, 2, 1]).unwrap(), false)
            != Disposition::Invalid
    {
        return TestResult::Fail("IF event disposition differs from Linux");
    }
    let mut registry = Registry::new(PRIMARY);
    if registry.first_free_bsscfgidx() != Some(2)
        || registry.by_ifidx(0).map(|e| e.bsscfgidx) != Some(0)
    {
        return TestResult::Fail("primary registry differs");
    }
    let mac = [0x02, 0x90, 0x4c, 0xb1, 0x22, 0x33];
    let Applied::Added(first) = registry.apply(event, false, mac) else {
        return TestResult::Fail("IF ADD not applied");
    };
    if registry.by_ifidx(1) != Some(first) || registry.first_free_bsscfgidx() != Some(3) {
        return TestResult::Fail("ifidx demux missing after ADD");
    }
    // A repeated ADD on a live nonzero ifidx detaches and replaces.
    let Applied::Replaced { old, new } = registry.apply(event, false, mac) else {
        return TestResult::Fail("missed-DEL replacement not reported");
    };
    if old != first || new.generation <= first.generation {
        return TestResult::Fail("replacement revived the old identity");
    }
    // ADD with ifidx0 on an occupied bsscfg and DEL of bsscfg0 are ignored.
    let primary_add = IfEvent::parse(E_IF, 5, &[0, 1, 0, 0, 0]).unwrap();
    let primary_del = IfEvent::parse(E_IF, 5, &[0, 2, 0, 0, 0]).unwrap();
    if registry.apply(primary_add, false, mac) != Applied::Ignored
        || registry.apply(primary_del, false, mac) != Applied::Ignored
    {
        return TestResult::Fail("primary interface lifetime was changed");
    }
    let del = IfEvent::parse(E_IF, 5, &[1, 2, 0, 2, 1]).unwrap();
    if registry.apply(del, false, mac) != Applied::Removed(new)
        || registry.by_ifidx(1).is_some()
        || registry.apply(del, false, mac) != Applied::Ignored
    {
        return TestResult::Fail("IF DEL did not retire the mapping");
    }
    // P2P device bsscfg is non-netdev: no ifidx demux mapping.
    let Applied::Added(device) = registry.apply(noif_client, true, mac) else {
        return TestResult::Fail("P2P device ADD not applied");
    };
    if !device.p2p_device || registry.by_ifidx(1).is_some() {
        return TestResult::Fail("P2P device received an ifidx data mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_brcmf_vif_if_event_classification_and_registry
);

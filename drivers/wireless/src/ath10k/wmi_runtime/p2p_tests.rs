//! Per-vdev role and native P2P codec cases (mac.c `ath10k_add_interface`,
//! wmi-tlv.c P2P_NOA / P2P_GO_SET_BEACON_IE, p2p.c NoA IE); written,
//! unexecuted until the coordinated native run.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];

/// Every dialect encodes vdev id, WMI type and subtype at the Linux
/// `wmi_vdev_create_cmd` offsets; vdev0 STA/AP stay byte-identical to the
/// pre-existing station and AP builders.
fn smoke_ath10k_p2p_vdev_create_roles() -> TestResult {
    let tlv = Wire::new(Dialect::Tlv);
    let cases = [
        (Role::Station, 2, 0),
        (Role::Ap, 1, 0),
        (Role::P2pDevice, 2, 1),
        (Role::P2pClient, 2, 2),
        (Role::P2pGo, 1, 3),
    ];
    for (role, kind, subtype) in cases {
        let Ok(bytes) = Vdev::new(3, role).create(&tlv, OWN) else {
            return TestResult::Fail("TLV create refused");
        };
        if bytes.len() != 28
            || wire::word(&bytes, 0) != Ok(0x5001)
            || wire::word(&bytes, 4) != Ok((86 << 16) | 20)
            || wire::word(&bytes, 8) != Ok(3)
            || wire::word(&bytes, 12) != Ok(kind)
            || wire::word(&bytes, 16) != Ok(subtype)
            || bytes[20..26] != OWN
        {
            return TestResult::Fail("TLV create layout");
        }
        if Role::from_iftype(role.iftype()) != Some(role) {
            return TestResult::Fail("iftype round trip");
        }
    }
    for (dialect, id) in [
        (Dialect::Main, 0x5001),
        (Dialect::TenOne, 0x9011),
        (Dialect::TenTwo, 0x9010),
        (Dialect::TenFour, 0x9013),
    ] {
        let Ok(bytes) = Vdev::new(1, Role::P2pClient).create(&Wire::new(dialect), OWN) else {
            return TestResult::Fail("legacy create refused");
        };
        if bytes.len() != 24
            || wire::word(&bytes, 0) != Ok(id)
            || wire::word(&bytes, 4) != Ok(1)
            || wire::word(&bytes, 8) != Ok(2)
            || wire::word(&bytes, 12) != Ok(2)
            || bytes[16..22] != OWN
        {
            return TestResult::Fail("legacy create layout");
        }
    }
    if tlv.create(OWN) != Vdev::new(0, Role::Station).create(&tlv, OWN)
        || super::super::ap_wire::create(Vdev::new(0, Role::Ap), OWN)
            != Vdev::new(0, Role::Ap).create(&tlv, OWN)
    {
        return TestResult::Fail("vdev0 builders diverged");
    }
    if Vdev::new(0, Role::P2pGo)
        .create(&tlv, [3, 0, 0, 0, 0, 1])
        .is_ok()
    {
        return TestResult::Fail("multicast vdev address accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_vdev_create_roles
);

/// `free_vdev_map` hands out the lowest free id, refuses exhaustion and
/// rejects double/out-of-range release.
fn smoke_ath10k_p2p_vdev_map_lowest_free() -> TestResult {
    let Ok(mut map) = VdevMap::new(4) else {
        return TestResult::Fail("map");
    };
    let ids: Vec<_> = (0..4).map(|_| map.allocate()).collect();
    if ids != [Ok(0), Ok(1), Ok(2), Ok(3)] || map.allocate() != Err(Error::Exhausted) {
        return TestResult::Fail("allocation order/exhaustion");
    }
    if map.release(1).is_err() || map.release(1).is_ok() || map.release(4).is_ok() {
        return TestResult::Fail("release bookkeeping");
    }
    if map.allocated(1) || !map.allocated(2) || map.allocate() != Ok(1) {
        return TestResult::Fail("reuse of lowest free id");
    }
    if VdevMap::new(0).is_ok() || VdevMap::new(65).is_ok() || VdevMap::new(64).is_err() {
        return TestResult::Fail("resource bounds");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_vdev_map_lowest_free
);

fn beacon(ies: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x80, 0, 0, 0];
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&[0; 2 + 8]);
    frame.extend_from_slice(&[100, 0, 0x01, 0x04]);
    frame.extend_from_slice(ies);
    frame
}

/// A GO's P2P IE moves from the beacon template into the native
/// P2P_GO_SET_BEACON_IE command; the remaining elements are untouched.
fn smoke_ath10k_p2p_go_beacon_ie_moves_to_firmware() -> TestResult {
    let p2p = [221, 8, 0x50, 0x6f, 0x9a, 9, 2, 2, 0, 0x21];
    let mut ies = vec![0, 3, b'D', b'I', b'R'];
    ies.extend_from_slice(&p2p);
    ies.extend_from_slice(&[3, 1, 6]);
    let mut frame = beacon(&ies);
    let go = Vdev::new(2, Role::P2pGo);
    let Ok(Some(command)) = go_beacon_ie(go, &mut frame) else {
        return TestResult::Fail("GO P2P IE not extracted");
    };
    if wire::word(&command, 0) != Ok(0xd003)
        || wire::word(&command, 4) != Ok((90 << 16) | 8)
        || wire::word(&command, 8) != Ok(2)
        || wire::word(&command, 12) != Ok(10)
        || wire::word(&command, 16) != Ok((17 << 16) | 12)
        || command[20..30] != p2p
        || command.len() != 32
    {
        return TestResult::Fail("P2P_GO_SET_BEACON_IE layout");
    }
    if frame != beacon(&[0, 3, b'D', b'I', b'R', 3, 1, 6]) {
        return TestResult::Fail("P2P IE left in beacon template");
    }
    let mut ap = beacon(&ies);
    if go_beacon_ie(Vdev::new(0, Role::Ap), &mut ap) != Ok(None) || ap != beacon(&ies) {
        return TestResult::Fail("ordinary AP beacon changed");
    }
    let mut truncated = beacon(&[221, 9, 0x50, 0x6f, 0x9a, 9]);
    if go_beacon_ie(go, &mut truncated).is_ok() {
        return TestResult::Fail("truncated element accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_go_beacon_ie_moves_to_firmware
);

fn noa_event(vdev: u32, info: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&((223u32 << 16) | 4).to_le_bytes());
    body.extend_from_slice(&vdev.to_le_bytes());
    body.extend_from_slice(&((69u32 << 16) | info.len() as u32).to_le_bytes());
    body.extend_from_slice(info);
    body
}

fn noa_info(ctwindow_oppps: u8, descriptors: &[[u32; 4]]) -> Vec<u8> {
    let mut info = vec![1, 7, ctwindow_oppps, descriptors.len() as u8];
    for descriptor in descriptors {
        for value in descriptor {
            info.extend_from_slice(&value.to_le_bytes());
        }
    }
    info.resize(68, 0);
    info
}

/// The TLV P2P_NOA event yields the firmware schedule; p2p.c builds the
/// IEEE NoA attribute with OppPS moved to bit 7 and CTWindow kept.
fn smoke_ath10k_p2p_noa_event_builds_absence_ie() -> TestResult {
    let info = noa_info((10 << 1) | 1, &[[3, 25_000, 100_000, 0x1234_5678]]);
    let Ok((vdev, noa)) = Noa::tlv_event(&noa_event(2, &info)) else {
        return TestResult::Fail("NoA event refused");
    };
    if vdev != 2 || !noa.opportunistic() || noa.ctwindow() != 10 || noa.index != 7 {
        return TestResult::Fail("NoA fields");
    }
    let Ok(Some(ie)) = noa.information_element() else {
        return TestResult::Fail("NoA IE");
    };
    let mut expected = vec![221, 22, 0x50, 0x6f, 0x9a, 9, 12, 15, 0, 7, 0x80 | 10, 3];
    expected.extend_from_slice(&25_000u32.to_le_bytes());
    expected.extend_from_slice(&100_000u32.to_le_bytes());
    expected.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    if ie != expected {
        return TestResult::Fail("NoA IE bytes");
    }
    let Ok((_, quiet)) = Noa::tlv_event(&noa_event(2, &noa_info(10 << 1, &[]))) else {
        return TestResult::Fail("empty NoA refused");
    };
    if quiet.information_element() != Ok(None) {
        return TestResult::Fail("IE without descriptor or OppPS");
    }
    let mut over = noa_info(0, &[]);
    over[3] = 5;
    if Noa::tlv_event(&noa_event(2, &over)).is_ok() {
        return TestResult::Fail("descriptor count above four accepted");
    }
    if Noa::tlv_event(&noa_event(2, &info[..64])).is_ok() {
        return TestResult::Fail("short NOA_INFO accepted");
    }
    let mut missing = Vec::new();
    missing.extend_from_slice(&((69u32 << 16) | 68).to_le_bytes());
    missing.extend_from_slice(&info);
    if Noa::tlv_event(&missing).is_ok() {
        return TestResult::Fail("event without NOA_EVENT vdev accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_noa_event_builds_absence_ie
);

/// The NoA owner applies only its own GO vdev's report and appends the IE
/// only to Probe Responses; a later empty report clears it.
fn smoke_ath10k_p2p_noa_owner_probe_response_only() -> TestResult {
    let go = Vdev::new(1, Role::P2pGo);
    let Ok(noa) = Noa::from_info(&noa_info(1, &[[255, 1, 2, 3]])) else {
        return TestResult::Fail("info");
    };
    let mut owner = NoaOwner::default();
    if owner.update(go, 2, &noa) != Ok(false)
        || owner.update(Vdev::new(1, Role::Ap), 1, &noa) != Ok(false)
        || owner.ie().is_some()
    {
        return TestResult::Fail("foreign report applied");
    }
    if owner.update(go, 1, &noa) != Ok(true) || owner.ie().is_none() {
        return TestResult::Fail("own report ignored");
    }
    let mut probe = vec![0x50, 0, 0, 0];
    probe.resize(36, 0);
    let mut action = vec![0xd0, 0, 0, 0];
    action.resize(30, 0);
    let (probe_len, action_len) = (probe.len(), action.len());
    if owner.append_to_probe_response(&mut probe).is_err()
        || owner.append_to_probe_response(&mut action).is_err()
        || probe.len() != probe_len + owner.ie().map_or(0, <[u8]>::len)
        || action.len() != action_len
    {
        return TestResult::Fail("probe-response-only append");
    }
    let Ok(clear) = Noa::from_info(&noa_info(0, &[])) else {
        return TestResult::Fail("clear info");
    };
    if owner.update(go, 1, &clear) != Ok(true) || owner.ie().is_some() {
        return TestResult::Fail("empty report did not clear");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_noa_owner_probe_response_only
);

/// Linux TLV combinations (plain and adaptive-OCS); no P2P combination for
/// other dialects or NO_P2P firmware.
fn smoke_ath10k_p2p_tlv_combinations() -> TestResult {
    let plain = p2p_combinations(Dialect::Tlv, false, false);
    let qcs = p2p_combinations(Dialect::Tlv, true, false);
    if plain.len() != 1
        || plain[0].max_interfaces != 4
        || plain[0].max_channels != 1
        || plain[0].limits.len() != 3
        || plain[0].limits[1].iftypes != [3, 8, 9]
        || plain[0].limits[2].max != 1
        || plain[0].limits[2].iftypes != [10]
    {
        return TestResult::Fail("ath10k_tlv_if_comb");
    }
    if qcs.len() != 1
        || qcs[0].max_channels != 2
        || qcs[0].limits.len() != 4
        || qcs[0].limits[1].iftypes != [8]
        || qcs[0].limits[2].iftypes != [3, 9]
    {
        return TestResult::Fail("ath10k_tlv_qcs_if_comb");
    }
    if !p2p_combinations(Dialect::Tlv, false, true).is_empty()
        || !p2p_combinations(Dialect::Main, false, false).is_empty()
        || !p2p_combinations(Dialect::TenFour, false, false).is_empty()
    {
        return TestResult::Fail("P2P combination outside TLV");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_tlv_combinations
);

/// VDEV_DELETE follows CREATE in every dialect's command table; TLV wraps
/// it in tag 87 and the TLV AP delete is the former literal vdev0 command.
/// A ROC scan carries the requesting vdev at `wmi_start_scan_common.vdev_id`.
fn smoke_ath10k_p2p_vdev_delete_and_roc_vdev() -> TestResult {
    for (dialect, id) in [
        (Dialect::Main, 0x5002),
        (Dialect::TenOne, 0x9012),
        (Dialect::TenTwo, 0x9011),
        (Dialect::TenTwoFour, 0x9011),
        (Dialect::TenFour, 0x9014),
    ] {
        let wire = Wire::new(dialect);
        let Ok(bytes) = Vdev::new(2, Role::P2pDevice).delete(&wire) else {
            return TestResult::Fail("legacy delete refused");
        };
        if bytes.len() != 8 || wire::word(&bytes, 0) != Ok(id) || wire::word(&bytes, 4) != Ok(2) {
            return TestResult::Fail("legacy delete layout");
        }
    }
    let tlv = Wire::new(Dialect::Tlv);
    if Vdev::new(1, Role::P2pDevice).delete(&tlv)
        != Ok(vec![2, 0x50, 0, 0, 4, 0, 87, 0, 1, 0, 0, 0])
        || super::super::ap_wire::delete(Vdev::new(0, Role::Ap))
            != super::super::ap_wire::command(0x5002, 87, &[0])
    {
        return TestResult::Fail("TLV delete layout");
    }
    for dialect in [Dialect::Main, Dialect::TenTwo, Dialect::Tlv] {
        let wire = Wire::new(dialect);
        let base = if dialect == Dialect::Tlv { 8 } else { 4 };
        let (Ok(zero), Ok(one)) = (wire.roc(0, 7, 2412, 100), wire.roc(1, 7, 2412, 100)) else {
            return TestResult::Fail("roc refused");
        };
        if wire::word(&zero, base + 8) != Ok(0) || wire::word(&one, base + 8) != Ok(1) {
            return TestResult::Fail("roc vdev_id");
        }
        let mut patched = one.clone();
        patched[base + 8] = 0;
        if patched != zero {
            return TestResult::Fail("roc vdev changed other fields");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_vdev_delete_and_roc_vdev
);

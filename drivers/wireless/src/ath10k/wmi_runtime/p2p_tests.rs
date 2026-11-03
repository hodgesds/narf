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
    if qcs.len() != 2
        || qcs[0] != plain[0]
        || qcs[1].max_channels != 2
        || qcs[1].max_interfaces != 4
        || qcs[1].limits.len() != 4
        || qcs[1].limits[1].iftypes != [8]
        || qcs[1].limits[2].iftypes != [3, 9]
    {
        return TestResult::Fail("ath10k_tlv_qcs_if_comb");
    }
    if !p2p_combinations(Dialect::Tlv, false, true).is_empty()
        || !p2p_combinations(Dialect::Main, false, false).is_empty()
        || !p2p_combinations(Dialect::TenFour, false, false).is_empty()
    {
        return TestResult::Fail("P2P combination outside TLV");
    }
    // wmi-tlv.c ath10k_wmi_tlv_op_gen_adaptive_qcs: cmd 0x23001, TLV
    // {len 4, tag 207}, enable; no other dialect maps the command.
    if adaptive_qcs(Dialect::Tlv, true) != Ok(vec![1, 0x30, 2, 0, 4, 0, 207, 0, 1, 0, 0, 0])
        || adaptive_qcs(Dialect::Tlv, false).map(|c| c[8]) != Ok(0)
        || adaptive_qcs(Dialect::Main, true) != Err(Error::Unsupported)
        || SERVICE_ADAPTIVE_OCS != 39
    {
        return TestResult::Fail("adaptive QCS command");
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

/// `ath10k_add_interface` sets the vdev NSS on the new vdev's own id; the
/// managed vdev0 form stays byte-identical to the existing station command.
fn smoke_ath10k_p2p_device_vdev_nss_on_own_id() -> TestResult {
    let Ok(chains) = super::super::chains::Chains::new(3) else {
        return TestResult::Fail("two-chain mask refused");
    };
    for dialect in [
        Dialect::Main,
        Dialect::TenTwo,
        Dialect::TenFour,
        Dialect::Tlv,
    ] {
        let at = if dialect == Dialect::Tlv { 8 } else { 4 };
        let (Ok(zero), Ok(old), Ok(one)) = (
            chains.vdev_nss_for(dialect, 0),
            chains.vdev_nss(dialect),
            chains.vdev_nss_for(dialect, 1),
        ) else {
            return TestResult::Fail("nss refused");
        };
        if zero != old || wire::word(&one, at) != Ok(1) || wire::word(&one, at + 8) != Ok(2) {
            return TestResult::Fail("nss vdev layout");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_device_vdev_nss_on_own_id
);

/// The DEFAULT offchannel peer create/delete, the TLV by-reference MGMT_TX
/// and the inline MGMT_TX carry the sending vdev at their Linux `vdev_id`
/// offsets; vdev0 stays byte-identical to the former implicit builders.
fn smoke_ath10k_p2p_offchannel_builders_carry_vdev() -> TestResult {
    const DA: [u8; 6] = [2, 0, 0, 0, 0, 9];
    for dialect in [Dialect::Main, Dialect::TenFour, Dialect::Tlv] {
        let wire = Wire::new(dialect);
        let at = if dialect == Dialect::Tlv { 8 } else { 4 };
        let (Ok(create0), Ok(create2), Ok(delete0), Ok(delete2)) = (
            wire.offchannel_peer(0, DA),
            wire.offchannel_peer(2, DA),
            wire.delete_offchannel_peer(0, DA),
            wire.delete_offchannel_peer(2, DA),
        ) else {
            return TestResult::Fail("peer builder refused");
        };
        if wire::word(&create0, at) != Ok(0)
            || wire::word(&create2, at) != Ok(2)
            || wire::word(&delete2, at) != Ok(2)
            || create2[at + 4..at + 10] != DA
            || wire::word(&create2, at + 12) != Ok(0)
        {
            return TestResult::Fail("peer vdev layout");
        }
        let (mut c, mut d) = (create2.clone(), delete2.clone());
        c[at] = 0;
        d[at] = 0;
        if c != create0 || d != delete0 {
            return TestResult::Fail("peer vdev changed other fields");
        }
    }
    let frame = [0xd0u8; 40];
    let (Ok(zero), Ok(two)) = (
        super::super::management::reference(0, 5, 0x900000, &frame),
        super::super::management::reference(2, 5, 0x900000, &frame),
    ) else {
        return TestResult::Fail("reference refused");
    };
    let mut patched = two.clone();
    patched[8] = 0;
    if wire::word(&two, 8) != Ok(2) || wire::word(&two, 12) != Ok(5) || patched != zero {
        return TestResult::Fail("reference vdev layout");
    }
    let (Ok(zero), Ok(two)) = (
        super::super::management::inline(0x7008, 0, &frame),
        super::super::management::inline(0x7008, 2, &frame),
    ) else {
        return TestResult::Fail("inline refused");
    };
    let mut patched = two.clone();
    patched[4] = 0;
    if wire::word(&two, 4) != Ok(2) || patched != zero {
        return TestResult::Fail("inline vdev layout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_offchannel_builders_carry_vdev
);

/// `ath10k_hw_scan` on the P2P_DEVICE vif: the TLV start-scan is the
/// netdev's active scan with `vdev_id` (byte 16) set to the P2P_DEVICE
/// vdev and WMI_SCAN_ADD_CCK_RATES (0x4) cleared from `scan_ctrl_flags`
/// (byte 64); a passive one only changes `vdev_id`. Non-TLV dialects and
/// passive probe content are refused.
fn smoke_ath10k_p2p_device_scan_on_own_vdev_without_cck() -> TestResult {
    let tlv = Wire::new(Dialect::Tlv);
    let channels = [2412, 2437, 2462];
    let ssids = vec![b"DIRECT-".to_vec()];
    let ies = [221, 8, 0x50, 0x6f, 0x9a, 9, 2, 2, 0, 0x25];
    let (Ok(netdev), Ok(p2p)) = (
        tlv.active_scan(7, &channels, &ssids, &ies),
        tlv.p2p_device_scan(2, 7, &channels, &ssids, &ies),
    ) else {
        return TestResult::Fail("active scan refused");
    };
    if wire::word(&p2p, 16) != Ok(2)
        || wire::word(&netdev, 64) != Ok(0x5c)
        || wire::word(&p2p, 64) != Ok(0x58)
    {
        return TestResult::Fail("P2P scan vdev/flags");
    }
    let mut patched = p2p.clone();
    patched[16] = 0;
    patched[64] = 0x5c;
    if patched != netdev {
        return TestResult::Fail("P2P scan changed other fields");
    }
    let (Ok(passive), Ok(p2p_passive)) = (
        tlv.scan(7, &channels),
        tlv.p2p_device_scan(1, 7, &channels, &[], &[]),
    ) else {
        return TestResult::Fail("passive scan refused");
    };
    let mut patched = p2p_passive.clone();
    patched[16] = 0;
    if wire::word(&p2p_passive, 16) != Ok(1) || patched != passive {
        return TestResult::Fail("passive P2P scan layout");
    }
    if tlv.p2p_device_scan(1, 7, &channels, &[], &ies) != Err(Error::Unsupported)
        || Wire::new(Dialect::TenTwo).p2p_device_scan(1, 7, &channels, &ssids, &[])
            != Err(Error::Unsupported)
    {
        return TestResult::Fail("P2P scan refusals");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_device_scan_on_own_vdev_without_cck
);

/// A P2P client netdev scan (`ath10k_hw_scan` on the P2P_CLI vif) is the
/// ordinary station scan with `vdev_id` (byte 16) set to the client vdev:
/// the active flags keep WMI_SCAN_ADD_CCK_RATES. TLV only.
fn smoke_ath10k_p2p_client_scan_on_client_vdev() -> TestResult {
    let tlv = Wire::new(Dialect::Tlv);
    let channels = [2412, 5180];
    let ssids = vec![b"DIRECT-ab".to_vec()];
    let (Ok(netdev), Ok(client), Ok(passive), Ok(client_passive)) = (
        tlv.active_scan(9, &channels, &ssids, &[]),
        tlv.scan_on_vdev(1, 9, &channels, &ssids, &[]),
        tlv.scan(9, &channels),
        tlv.scan_on_vdev(1, 9, &channels, &[], &[]),
    ) else {
        return TestResult::Fail("client scan refused");
    };
    if wire::word(&client, 16) != Ok(1)
        || wire::word(&client, 64) != wire::word(&netdev, 64)
        || wire::word(&client_passive, 16) != Ok(1)
    {
        return TestResult::Fail("client scan vdev/flags");
    }
    let (mut active, mut quiet) = (client.clone(), client_passive.clone());
    active[16] = 0;
    quiet[16] = 0;
    if active != netdev || quiet != passive {
        return TestResult::Fail("client scan changed other fields");
    }
    if tlv.scan_on_vdev(1, 9, &channels, &[], &[221, 4, 0, 0x50, 0xf2, 4])
        != Err(Error::Unsupported)
        || Wire::new(Dialect::TenTwo).scan_on_vdev(1, 9, &channels, &[], &[])
            != Err(Error::Unsupported)
    {
        return TestResult::Fail("client scan refusals");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_client_scan_on_client_vdev
);

fn probe_response(capability: u16, ies: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 36];
    frame[0] = 0x50;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 7]);
    frame[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 7]);
    frame[32] = 100;
    frame[34..36].copy_from_slice(&capability.to_le_bytes());
    frame.extend_from_slice(ies);
    frame
}

/// A P2P Device in Listen answers a P2P search with a Probe Response that
/// is neither ESS nor IBSS; only the P2P_DEVICE scan admits it, and only
/// with the WFA P2P IE. ESS answers (a GO) are admitted by both scans.
fn smoke_ath10k_p2p_device_scan_admits_listen_probe_response() -> TestResult {
    let p2p_ie = [221, 6, 0x50, 0x6f, 0x9a, 9, 2, 0];
    let mut ies = vec![0, 7];
    ies.extend_from_slice(b"DIRECT-");
    ies.extend_from_slice(&[3, 1, 6]);
    let event = |frame: Vec<u8>| super::super::Management {
        channel: 6,
        snr: 30,
        status: 0,
        frame,
    };
    let mut listen = ies.clone();
    listen.extend_from_slice(&p2p_ie);
    let device = event(probe_response(0, &listen));
    let bare = event(probe_response(0, &ies));
    let go = event(probe_response(1, &listen));
    let ibss = event(probe_response(2, &listen));
    let channels = [2437];
    let admitted = |m: &super::super::Management, p2p| {
        super::super::discovered(m, &channels, p2p).is_ok_and(|bss| bss.is_some())
    };
    if !admitted(&device, true)
        || admitted(&device, false)
        || admitted(&bare, true)
        || !admitted(&go, true)
        || !admitted(&go, false)
        || admitted(&ibss, true)
    {
        return TestResult::Fail("listen admission");
    }
    let Ok(Some(bss)) = super::super::discovered(&device, &channels, true) else {
        return TestResult::Fail("listen BSS");
    };
    if bss.bssid != [2, 0, 0, 0, 0, 7]
        || bss.ssid != b"DIRECT-"
        || bss.information_elements != listen
    {
        return TestResult::Fail("listen BSS fields");
    }
    let mut beacon = device.frame.clone();
    beacon[0] = 0x80;
    if admitted(&event(beacon), true) {
        return TestResult::Fail("non-ESS beacon admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_device_scan_admits_listen_probe_response
);

/// Station WMI builders take the station's vdev (`arvif->vdev_id` in
/// `mac.c::ath10k_vdev_start`/`ath10k_peer_create`/`ath10k_peer_assoc_prepare`/
/// `ath10k_bss_assoc`/`ath10k_install_key`/`ath10k_bss_disassoc` and the
/// STA power-save/RTS helpers): `vdev_id` sits at the Linux offset in every
/// dialect, and re-zeroing it reproduces the vdev0 encoding byte for byte.
/// Start/stopped/delete responses only match their own vdev.
fn smoke_ath10k_p2p_station_builders_carry_vdev() -> TestResult {
    use crate::ath10k::regulatory::{Factory, Permission};
    const BSSID: [u8; 6] = [2, 8, 9, 10, 11, 12];
    let Ok(factory) = Factory::from_eeprom(0x64) else {
        return TestResult::Fail("factory");
    };
    let p = Permission {
        center: 2412,
        secondary: None,
        width80: false,
        center2: None,
        factory,
        country: *b"US",
        frequency: 2412,
        half_dbm: 34,
        radar: 0,
        hint: None,
    };
    let key = narf_wireless::station_security::KeyInstall {
        pairwise: true,
        key_id: 0,
        material: zeroize::Zeroizing::new([0xa5; 16]),
        token: 1,
    };
    let protection = super::super::StationProtection {
        rts_threshold: Some(2346),
        cts_protection: true,
    };
    let associated = super::super::mlme::Associated {
        bssid: BSSID,
        frequency: 2412,
        aid: 7,
        protected: false,
    };
    // `vdev_id` equals `at` (after any TLV struct header) except where the
    // struct leads with another field.
    fn same(zero: &[u8], three: &[u8], at: usize) -> bool {
        let mut patched = three.to_vec();
        patched[at] = 0;
        wire::word(three, at) == Ok(3) && wire::word(zero, at) == Ok(0) && patched == zero
    }
    for dialect in [
        Dialect::Main,
        Dialect::TenOne,
        Dialect::TenTwo,
        Dialect::TenTwoFour,
        Dialect::TenFour,
        Dialect::Tlv,
    ] {
        let w = Wire::new(dialect);
        let tlv = dialect == Dialect::Tlv;
        let at = if tlv { 8 } else { 4 };
        // `wmi_vdev_start_request_cmd` puts the channel before vdev_id.
        let start = if tlv { 8 } else { 28 };
        let built = |vdev: u8| -> Result<Vec<Vec<u8>>, Error> {
            let mut out = vec![
                w.start_station(vdev, &p, 100, 1)?,
                w.peer(vdev, BSSID)?,
                w.down_station(vdev)?,
                w.delete_peer(vdev, BSSID)?,
                w.stop_station(vdev)?,
                w.station_ps_mode(vdev, true)?,
                w.station_ps_parameter(vdev, 3, 100)?,
                super::super::mlme::up(dialect, vdev, BSSID, 7)?,
                super::super::mlme::peer_phy(dialect, vdev, associated, 0x421, 0xfff, false, None)?,
                super::super::hw_keys::install(dialect, vdev, BSSID, &key)?,
            ];
            out.extend(w.protection(vdev, protection)?);
            Ok(out)
        };
        let (Ok(zero), Ok(three)) = (built(0), built(3)) else {
            return TestResult::Fail("station builder refused");
        };
        let offsets = [start, at, at, at, at, at, at, at, at + 8, at, at, at, at];
        for ((z, t), offset) in zero.iter().zip(three.iter()).zip(offsets) {
            if !same(z, t, offset) {
                return TestResult::Fail("station builder vdev layout");
            }
        }
        // `wmi_vdev_start_response_event` / `wmi_vdev_stopped_event`.
        let mut response = vec![0u8; 16];
        response[0] = 3;
        let stopped = [3u8, 0, 0, 0];
        let (response, stopped) = if tlv {
            let mut r = vec![16, 0, 40, 0];
            r.extend_from_slice(&response);
            let mut s = vec![4, 0, 41, 0];
            s.extend_from_slice(&stopped);
            (r, s)
        } else {
            (response, stopped.to_vec())
        };
        if w.start_response(3, &response) != Ok(Some(()))
            || w.start_response(0, &response) != Ok(None)
            || w.stopped_response(3, &stopped) != Ok(true)
            || w.stopped_response(0, &stopped) != Ok(false)
        {
            return TestResult::Fail("vdev response correlation");
        }
        if tlv {
            let mut delete = vec![12u8, 0, 0xc3, 1, 3, 0, 0, 0];
            delete.extend_from_slice(&BSSID);
            delete.extend_from_slice(&[0, 0]);
            if w.delete_response(3, &delete, BSSID) != Ok(true)
                || w.delete_response(0, &delete, BSSID) != Ok(false)
            {
                return TestResult::Fail("peer delete correlation");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_station_builders_carry_vdev
);

/// TLV AP builders address the plan's AP-type vdev (`arvif->vdev_id` in
/// `mac.c::ath10k_mac_setup_bcn_tmpl`/`_prb_tmpl`, `ath10k_mac_set_*`
/// vdev params, `ath10k_peer_assoc_prepare`, `ath10k_station_assoc` peer
/// and AP-PS params): templates, vdev params, PEER_SET_PARAM and AP_PS at
/// byte 8, PEER_ASSOC after the peer address at byte 16. Re-zeroing the
/// vdev reproduces the vdev0 encoding.
fn smoke_ath10k_p2p_ap_builders_carry_vdev() -> TestResult {
    use super::super::ap_wire;
    let mut beacon = vec![0; 36];
    beacon[0] = 0x80;
    beacon[4..10].fill(255);
    beacon[10..16].copy_from_slice(&OWN);
    beacon[16..22].copy_from_slice(&OWN);
    beacon[32..34].copy_from_slice(&100u16.to_le_bytes());
    beacon[34] = 1;
    beacon.extend_from_slice(&[
        0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, 1,
    ]);
    let config = narf_wireless::ApConfig {
        ssid: b"narf".to_vec(),
        beacon_head: beacon,
        beacon_tail: Vec::new(),
        probe_resp: None,
        beacon_interval: 100,
        dtim_period: 2,
        frequency_mhz: 2412,
        channel_width: 0,
        center_freq1_mhz: None,
        center_freq2_mhz: None,
        hidden_ssid: 0,
        privacy: false,
        mbssid: None,
        mbssid_elems: Vec::new(),
        ema_rnr_elems: Vec::new(),
        fils_discovery: None,
        unsol_bcast_probe_resp: None,
        ftm_responder: None,
        twt_responder: false,
        he_obss_pd: None,
        he_bss_color: None,
    };
    const PEER: [u8; 6] = [2, 0, 0, 0, 0, 0x22];
    let station = narf_wireless::StationConfig {
        mac: PEER,
        aid: 1,
        listen_interval: 10,
        supported_rates: vec![2, 4, 11, 22],
        wme: Some(false),
        uapsd_queues: Some(0),
        uapsd_max_sp: Some(0),
        mfp: Some(false),
        capability: None,
        ext_capability: None,
        ht_capability: None,
        vht_capability: None,
        he_capability: None,
        he_6ghz_capability: None,
        authorized: Some(true),
        station_tx_power: None,
    };
    let settings = narf_wireless::ApStartSettings::default();
    let built = |vdev: u8| -> Result<Vec<(Vec<u8>, usize)>, Error> {
        let plan = ap_wire::Plan::new(vdev, config.clone(), settings.clone(), OWN, false)?;
        let mut out = vec![
            (ap_wire::beacon(&plan)?, 8),
            (ap_wire::probe(&plan)?, 8),
            (ap_wire::associate(&plan, &station, false)?, 16),
            (ap_wire::peer_parameter(vdev, PEER, 3, 1)?, 8),
        ];
        for command in ap_wire::parameters(&plan)? {
            out.push((command, 8));
        }
        for command in ap_wire::power_save(vdev, PEER, 1, 1)? {
            out.push((command, 8));
        }
        Ok(out)
    };
    let (Ok(zero), Ok(two)) = (built(0), built(2)) else {
        return TestResult::Fail("AP builder refused");
    };
    if zero.len() != two.len() || zero.len() != 16 {
        return TestResult::Fail("AP builder count");
    }
    for ((z, at), (t, _)) in zero.iter().zip(two.iter()) {
        let mut patched = t.clone();
        patched[*at] = 0;
        if wire::word(t, *at) != Ok(2) || wire::word(z, *at) != Ok(0) || patched != *z {
            return TestResult::Fail("AP builder vdev layout");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_ap_builders_carry_vdev
);

/// A P2P client station slot carries its own vdev and address, owns no
/// peer id or MSDU before association, and parks at most `SLOT_INBOX`
/// sibling-routed HTT events.
fn smoke_ath10k_p2p_station_slot_parks_bounded() -> TestResult {
    use super::super::{StationSlot, SLOT_INBOX};
    use crate::ath10k::htt_runtime as htt;
    let mut slot = StationSlot::client(1, OWN);
    if slot.vdev != Some(1) || slot.own != Some(OWN) || slot.peer.is_some() {
        return TestResult::Fail("client slot identity");
    }
    if slot.owns_peer(5) || slot.owns_msdu(5) {
        return TestResult::Fail("unassociated slot owns ids");
    }
    for _ in 0..SLOT_INBOX + 4 {
        slot.park(htt::Event::Progress);
    }
    if slot.inbox.len() != SLOT_INBOX || !slot.receipts.is_empty() {
        return TestResult::Fail("inbox bound");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_station_slot_parks_bounded
);

/// A slot claims exactly its own peer's legacy RX, its vdev+peer in-order
/// indication, its peer's ADDBA/DELBA note and its BSS's management
/// (A2/A3), so a sibling-polled event is parked for the owning slot and a
/// note it parks is never handed back to the slot that polled it.
fn smoke_ath10k_p2p_slot_claims_by_peer_vdev_and_bssid() -> TestResult {
    use super::super::station::Peer;
    use super::super::StationSlot;
    use crate::ath10k::htt_runtime::{self as htt, rx};
    use crate::ath10k::regulatory::{Factory, Permission};
    const HOME_BSSID: [u8; 6] = [2, 1, 1, 1, 1, 1];
    const GO_BSSID: [u8; 6] = [2, 9, 9, 9, 9, 9];
    let Ok(factory) = Factory::from_eeprom(0x64) else {
        return TestResult::Fail("factory");
    };
    let permission = Permission {
        center: 2412,
        secondary: None,
        width80: false,
        center2: None,
        factory,
        country: *b"US",
        frequency: 2412,
        half_dbm: 34,
        radar: 0,
        hint: None,
    };
    let mut home = StationSlot::client(0, [2, 0, 0, 0, 0, 7]);
    let mut client = StationSlot::client(1, OWN);
    let (Ok(home_peer), Ok(client_peer)) = (
        Peer::mapped_for_test(0, permission.clone(), HOME_BSSID, 5),
        Peer::mapped_for_test(1, permission, GO_BSSID, 9),
    ) else {
        return TestResult::Fail("peer map");
    };
    home.peer = Some(home_peer);
    client.peer = Some(client_peer);
    let rx = |peer| {
        htt::Event::Rx(htt::RxBatch {
            peer,
            tid: 0,
            frames: Vec::new(),
        })
    };
    let in_order = |vdev, peer| {
        htt::Event::InOrder(
            rx::InOrder {
                peer,
                vdev,
                tid: 0,
                offload: false,
                fragment: false,
                pointers: Vec::new(),
            },
            Vec::new(),
        )
    };
    // ADDBA (5) / DELBA (6): info = peer << 4 | tid.
    let note = |kind: u8, peer: u16| {
        let info = (peer << 4) | 3;
        htt::Event::Message(vec![kind, 8, info as u8, (info >> 8) as u8])
    };
    let mut frame = vec![0xd0, 0, 0, 0];
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&GO_BSSID);
    frame.extend_from_slice(&GO_BSSID);
    frame.extend_from_slice(&[0, 0]);
    let wmi = htt::Event::Wmi(Vec::new());
    if !client.claims(&rx(9), 0, None) || home.claims(&rx(9), 0, None) {
        return TestResult::Fail("legacy RX by peer id");
    }
    if !client.claims(&in_order(1, 9), 0, None)
        || client.claims(&in_order(0, 9), 0, None)
        || home.claims(&in_order(1, 9), 0, None)
    {
        return TestResult::Fail("in-order RX by vdev and peer");
    }
    if !client.claims(&note(5, 9), 0, None)
        || !client.claims(&note(6, 9), 0, None)
        || home.claims(&note(5, 9), 0, None)
        || !home.claims(&note(5, 5), 0, None)
    {
        return TestResult::Fail("BA note by peer id");
    }
    if !client.claims(&wmi, 0, Some(&frame)) || home.claims(&wmi, 0, Some(&frame)) {
        return TestResult::Fail("management by BSSID");
    }
    if client.claims(&htt::Event::Message(vec![3; 12]), 0, None)
        || client.claims(&htt::Event::Idle, 0, None)
        || client.claims(&wmi, 0, None)
    {
        return TestResult::Fail("radio-level event claimed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/p2p",
    smoke_ath10k_p2p_slot_claims_by_peer_vdev_and_bssid
);

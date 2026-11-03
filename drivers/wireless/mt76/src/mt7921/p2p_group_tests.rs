//! P2P group roles on the physical BSS0 owner. mac80211 runs P2P_CLIENT as a
//! STATION vif and P2P_GO as an AP vif with `vif->p2p` set
//! (`ieee80211_setup_sdata`); CONNAC2 changes only the BSS-basic connection
//! type (`mt76_connac_mcu_uni_add_bss`) and keeps every peer/key/data owner.
use super::*;
use crate::mt7921::p2p_wire::{group_bss, Network};

const INFRA_STA: [u8; 4] = [1, 0, 1, 0];
const INFRA_AP: [u8; 4] = [2, 0, 1, 0];
const P2P_GC: [u8; 4] = [1, 0, 2, 0];
const P2P_GO: [u8; 4] = [2, 0, 2, 0];

/// UNI BSS-basic requests (tag 0) among native unified BSS_INFO commands.
fn basic_bss(frames: &[(bool, Vec<u8>)]) -> Vec<Vec<u8>> {
    frames
        .iter()
        .filter_map(|(_, frame)| uni(frame, 2))
        .filter(|body| body.len() >= 36 && body[4..6] == [0, 0])
        .map(<[u8]>::to_vec)
        .collect()
}

fn wire() -> Result<(), &'static str> {
    let mut station = [0u8; 36];
    station[12..16].copy_from_slice(&INFRA_STA);
    let mut ap = [0u8; 44];
    ap[12..16].copy_from_slice(&INFRA_AP);
    let (mut gc, mut go) = (station, ap);
    if group_bss(&mut gc, Network::P2p).is_err()
        || group_bss(&mut go, Network::P2p).is_err()
        || gc[12..16] != P2P_GC
        || go[12..16] != P2P_GO
        || gc[..12] != station[..12]
        || gc[16..] != station[16..]
    {
        return Err("P2P client/GO did not change exactly the BSS-basic connection type");
    }
    let (mut sta_infra, mut ap_infra) = (station, ap);
    if group_bss(&mut sta_infra, Network::Infrastructure).is_err()
        || group_bss(&mut ap_infra, Network::Infrastructure).is_err()
        || sta_infra != station
        || ap_infra != ap
    {
        return Err("infrastructure role changed its BSS-basic request");
    }
    // A non-basic TLV, an already-retargeted or P2P-device record and a
    // truncated request are builder mismatches, never patched.
    let mut other = station;
    other[4] = 2;
    let mut device = station;
    device[12..16].copy_from_slice(&P2P_GO);
    if group_bss(&mut other, Network::P2p).is_ok()
        || group_bss(&mut gc, Network::P2p).is_ok()
        || group_bss(&mut device, Network::Infrastructure).is_ok()
        || group_bss(&mut station[..20], Network::P2p).is_ok()
    {
        return Err("BSS role retarget accepted a non-infrastructure BSS-basic record");
    }
    Ok(())
}
fn mt76_p2p_group_bss_connection_type_matches_connac2() -> TestResult {
    wire().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_group_bss_connection_type_matches_connac2
);

fn client() -> Result<(), &'static str> {
    for secure in [false, true] {
        for network in [Network::Infrastructure, Network::P2p] {
            let (mut session, bss) = super::super::super::ht20_tests::prepared(6, secure);
            let security = if secure {
                crate::mt7921::association::Security::Wpa2Psk { psk: [0x55; 32] }
            } else {
                crate::mt7921::association::Security::Open
            };
            let expected = if network == Network::P2p {
                P2P_GC
            } else {
                INFRA_STA
            };
            let before = session.backend.frames.len();
            run(Box::pin(session.associate_station_as(
                &bss,
                b"narf",
                security,
                test_permission(),
                &[],
                network,
            )))
            .map_err(|_| "P2P client actual Open/WPA2 association")?;
            if !matches!(session.state, State::Associated { .. })
                || session.station_network != network
            {
                return Err("P2P client did not retain the station association/key owner");
            }
            let joined = basic_bss(&session.backend.frames[before..]);
            if joined.len() < 2 || joined.iter().any(|body| body[12..16] != expected) {
                return Err("P2P client BSS-basic records used the wrong connection type");
            }
            // mt76_connac_mcu_sta_basic_tlv keeps INFRA_AP for the GO peer
            // on CONNAC2 (`vif->p2p && !is_connac2`).
            let peers: Vec<_> = session.backend.frames[before..]
                .iter()
                .filter_map(|(_, frame)| uni(frame, 3))
                .filter(|body| body.len() >= 16 && body[1] == 1 && body[8..10] == [0, 0])
                .collect();
            if peers.is_empty() || peers.iter().any(|body| body[12..16] != INFRA_AP) {
                return Err("P2P client changed the CONNAC2 peer STA_REC connection type");
            }
            let middle = session.backend.frames.len();
            run(Box::pin(session.disassociate_station()))
                .map_err(|_| "P2P client disassociation")?;
            let left = basic_bss(&session.backend.frames[middle..]);
            if !matches!(session.state, State::ScanReady(_))
                || session.station_network != Network::Infrastructure
                || !left
                    .iter()
                    .any(|body| body[16] == 1 && body[12..16] == expected)
                || left.iter().any(|body| body[12..16] != expected)
            {
                return Err("P2P client teardown did not retire its own role BSS");
            }
        }
    }
    Ok(())
}
fn mt76_p2p_client_role_reuses_station_peer_key_data_owner() -> TestResult {
    client().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_client_role_reuses_station_peer_key_data_owner
);

fn owner() -> Result<(), &'static str> {
    let (mut session, binding, source) = super::concrete()?;
    let own = binding.iface.mac();
    binding
        .iface
        .set_iftype(9)
        .map_err(|_| "down AP interface to P2P_GO")?;
    if binding.iface.current_iftype() != 9 || !binding.iface.ap_role() {
        return Err("P2P_GO was not an AP-role interface");
    }
    narf_net::iface::set_link_state(binding.iface.name(), true);
    let authority = super::bound(&binding, &source)?;
    if authority.mode() != 9 {
        return Err("START authority was not bound to P2P_GO");
    }
    let before = session.backend.frames.len();
    if super::execute(
        &mut session,
        &binding,
        authority,
        boot_ap::Request::Start(Box::new((
            config(own),
            narf_wireless::ApStartSettings::default(),
        ))),
    ) != Ok(boot_ap::Reply::Done)
    {
        return Err("P2P GO retained START/native host commit");
    }
    let started = basic_bss(&session.backend.frames[before..]);
    if !binding.iface.link_up()
        || binding.iface.rx_ring().lock().is_none()
        || session
            .ap_owner
            .as_ref()
            .is_none_or(|owner| owner.plan.network != Network::P2p)
        || !started.iter().any(|body| body[8] == 1)
        || started.iter().any(|body| body[12..16] != P2P_GO)
    {
        return Err("P2P GO did not publish the AP owner with the GO BSS type");
    }
    // The GO beacon/peer/key owner is the AP one: its BMC WTBL is unchanged.
    if !session.backend.frames[before..]
        .iter()
        .filter_map(|(_, frame)| uni(frame, 3))
        .any(|body| body.get(1) == Some(&19))
    {
        return Err("P2P GO did not install the AP BMC WTBL");
    }
    if binding.iface.set_iftype(3) != Err(WirelessError::Busy) {
        return Err("live P2P GO changed role under its native BSS");
    }
    narf_net::iface::set_link_state(binding.iface.name(), false);
    let middle = session.backend.frames.len();
    let fresh = Arc::new(Source::new());
    if super::execute(
        &mut session,
        &binding,
        super::bound(&binding, &fresh)?,
        boot_ap::Request::Stop,
    ) != Ok(boot_ap::Reply::Done)
        || session.ap_owner.is_some()
    {
        return Err("P2P GO STOP did not retire the native BSS");
    }
    let stopped = basic_bss(&session.backend.frames[middle..]);
    if stopped.iter().any(|body| body[12..16] != P2P_GO) {
        return Err("P2P GO teardown used the infrastructure AP BSS type");
    }
    binding
        .iface
        .set_iftype(8)
        .map_err(|_| "stopped P2P GO did not release the P2P client transition")?;
    if !binding.iface.station_role() || binding.iface.ap_role() {
        return Err("P2P_CLIENT was not a station-role interface");
    }
    binding
        .iface
        .set_iftype(2)
        .map_err(|_| "P2P client did not return to STATION")?;
    Ok(())
}
fn mt76_p2p_go_role_reuses_ap_owner_with_go_bss() -> TestResult {
    super::observed(owner())
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_go_role_reuses_ap_owner_with_go_bss
);

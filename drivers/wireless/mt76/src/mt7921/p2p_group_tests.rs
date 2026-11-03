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
                || session.station.network != network
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
                || session.station.network != Network::Infrastructure
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

/// Per-vif native identity for a concurrent group interface. Linux
/// `mt7921_add_interface` gives vif idx its own OMAC/HW BSS/WMM set and BMC
/// WCID 19 - idx; `mt76_connac_mcu_alloc_sta_req` stamps `bss_idx` and
/// `muar_idx`; `mt76_connac_mcu_uni_add_bss` the BSS indices and BMC WCID;
/// `mt76_connac2_mac_write_txwi` the TXD OWN_MAC and WMM queue. The HOME
/// identity reproduces the historical BSS0/WCID1/WCID19 bytes exactly.
fn vif_link() -> Result<(), &'static str> {
    use crate::mt7921::{
        ap_wire, association as assoc, packet_tx,
        vif_slots::{Link, Vif},
    };
    let peer = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let own = [0x02, 0x66, 0x77, 0x88, 0x99, 0xaa];
    let vif = Vif::new(1).map_err(|_| "vif 1")?;
    let link = Link::new(vif, 2).map_err(|_| "link 1/2")?;
    if Link::new(vif, 0).is_ok() || Link::new(vif, 15).is_ok() || Link::new(vif, 14).is_err() {
        return Err("peer WCID admission differs from mt76_wcid_alloc(MT792x_WTBL_STA)");
    }
    // HOME stays byte-identical to the historical single-vif builders.
    let home_group = assoc::group_record(peer, 1).map_err(|_| "home group")?;
    if home_group[..8] != [0, 19, 1, 0, 1, 0xe, 0, 0]
        || assoc::disconnect_record(peer)[..8] != [0, 1, 2, 0, 1, 0, 0, 0]
        || assoc::group_disconnect_record()[..8] != [0, 19, 1, 0, 1, 0xe, 0, 0]
        || ap_wire::group()[..8] != [0, 19, 1, 0, 1, 0xe, 0, 0]
    {
        return Err("HOME records left BSS0/WCID1/WCID19");
    }
    // A second vif changes exactly its header/index fields.
    let group = assoc::group_record_on(link, peer, 1).map_err(|_| "vif group")?;
    let mut expect = home_group.clone();
    expect[0] = 1;
    expect[1] = 18;
    expect[12] = 18; // WTBL request WCID
    if group != expect {
        return Err("vif BMC record differs beyond bss_idx/BMC WCID");
    }
    let gone = assoc::disconnect_record_on(link, peer);
    let mut expect = assoc::disconnect_record(peer);
    expect[0] = 1;
    expect[1] = 2;
    expect[5] = 1;
    let wtbl = expect.len() - 12;
    expect[wtbl + 4] = 2;
    if gone != expect {
        return Err("vif disconnect differs beyond bss/peer/MUAR");
    }
    let mut expect = assoc::group_disconnect_record();
    expect[0] = 1;
    expect[1] = 18;
    expect[12] = 18;
    if assoc::group_disconnect_record_on(link) != expect {
        return Err("vif BMC disconnect differs beyond bss/BMC");
    }
    // Per-vif WTBL keys: only this vif's peer (key 0) and BMC (GTKs).
    let key = [0x5a; 16];
    if assoc::key_record_on(link, 1, 0, Some(&key)).is_ok()
        || assoc::key_record_on(link, 19, 1, Some(&key)).is_ok()
        || assoc::key_record_on(link, 2, 1, Some(&key)).is_ok()
    {
        return Err("vif key reached another vif's WTBL");
    }
    let pairwise = assoc::key_record_on(link, 2, 0, Some(&key)).map_err(|_| "vif PTK")?;
    let group_key = assoc::key_record_on(link, 18, 2, Some(&key)).map_err(|_| "vif GTK")?;
    let mut home_ptk = assoc::key_record(1, 0, Some(&key)).map_err(|_| "home PTK")?;
    let mut home_gtk = assoc::key_record(19, 2, Some(&key)).map_err(|_| "home GTK")?;
    home_ptk[..2].copy_from_slice(&[1, 2]);
    home_ptk[5] = 1;
    home_gtk[..2].copy_from_slice(&[1, 18]);
    if pairwise != home_ptk || group_key != home_gtk {
        return Err("vif key records differ beyond bss/WCID/MUAR");
    }
    let igtk = assoc::igtk_record_on(link, 1, &key, &key).map_err(|_| "vif IGTK")?;
    let mut home_igtk = assoc::igtk_record(1, &key, &key).map_err(|_| "home IGTK")?;
    home_igtk[..2].copy_from_slice(&[1, 18]);
    if igtk != home_igtk {
        return Err("vif IGTK differs beyond bss/BMC");
    }
    // UNI BSS for station and AP vifs.
    let bss = crate::mt7921::firmware_transport::ScanBss {
        bssid: peer,
        ssid: b"DIRECT-xy".to_vec(),
        channel: 6,
        band: None,
        signal_dbm: Some(-50),
        capability: 1,
        beacon_interval: 100,
        information_elements: Vec::new(),
    };
    let mut home = assoc::bss_record(&bss, true).map_err(|_| "home BSS")?;
    let record = assoc::bss_record_on(link, &bss, true).map_err(|_| "vif BSS")?;
    if home[0] != 0 || home[9..11] != [0, 0] || home[17] != 0 || home[24..26] != [19, 0] {
        return Err("HOME station BSS left BSS0/OMAC0/WMM0/BMC19");
    }
    home[0] = 1;
    home[9] = 1;
    home[10] = 1;
    home[17] = 1;
    home[24] = 18;
    home[30] = 18;
    if record != home {
        return Err("vif station BSS differs beyond its indices/BMC");
    }
    let mut home = ap_wire::bss(own, 100, 2, false, true, true).map_err(|_| "home AP BSS")?;
    let record = ap_wire::bss_on(vif, own, 100, 2, false, true, true).map_err(|_| "vif AP")?;
    let (_, slot) = vif.device_payloads(own, true, true).map_err(|_| "slot")?;
    home[0] = 1;
    home[9] = 1;
    home[10] = 1;
    home[17] = 1;
    home[24] = 18;
    home[30] = 18;
    if record != home || record[..12] != slot[..12] || record[17] != slot[17] {
        return Err("vif AP BSS differs from Linux uni_add_bss indices");
    }
    let mut home = ap_wire::group();
    home[..2].copy_from_slice(&[1, 18]);
    home[12] = 18;
    if ap_wire::group_on(vif) != home {
        return Err("vif AP BMC differs beyond bss/BMC");
    }
    let station = ap_wire::PeerRecord {
        mac: peer,
        wcid: 3,
        aid: 1,
        newly: true,
        qos: true,
        five_ghz: false,
        rates: 0x0fff,
        basic_rates: 0x000f,
    };
    let mut home = ap_wire::peer(ap_wire::PeerRecord { ..station }).map_err(|_| "home peer")?;
    let record = ap_wire::peer_on(vif, station).map_err(|_| "vif peer")?;
    if home[0] != 0 || home[5] != 0 {
        return Err("HOME AP peer left BSS0/MUAR0");
    }
    home[0] = 1;
    home[5] = 1;
    // header 8 + BASIC 20 + PHY 12 + RA 16 + STATE 12 + WTBL 12.
    let generic = 80;
    if home[generic..generic + 4] != [0, 0, 20, 0] {
        return Err("AP peer WTBL generic offset");
    }
    home[generic + 10] = 1;
    if record != home {
        return Err("vif AP peer differs beyond bss/MUAR");
    }
    // Beacon offload: bss_idx header and embedded TXD1 OWN_MAC only.
    let mut frame = vec![0; 42];
    frame[0] = 0x80;
    frame[4..10].fill(0xff);
    frame[36..38].copy_from_slice(&[5, 4]);
    let rate = crate::mt7921::association::LegacyRate::ONE_MBPS;
    let mut home = ap_wire::beacon(&frame, 36, None, rate).map_err(|_| "home beacon")?;
    let record = ap_wire::beacon_on(vif, &frame, 36, None, rate).map_err(|_| "vif beacon")?;
    if home[0] != 0 || home[25] & 0x3f != 0 {
        return Err("HOME beacon left BSS0/OMAC0");
    }
    home[0] = 1;
    home[25] |= 1; // TXD1 bits 24..=29 = omac_idx 1.
    if record != home {
        return Err("vif beacon differs beyond bss/OWN_MAC");
    }
    // AP data TXD: group data rides the vif's own BMC WCID (18 on vif 1),
    // never another vif's; the TXD differs only in OWN_MAC and WMM set.
    use crate::mt7921::firmware_transport::ap_packet::{descriptor, descriptor_on};
    let mut group = vec![0; 40];
    group[..2].copy_from_slice(&[0x08, 2]);
    group[4..10].fill(0xff);
    let mut home = descriptor(&group, 0x1000, 1, 19, rate).map_err(|_| "home group TXD")?;
    let record = descriptor_on(vif, &group, 0x1000, 1, 18, rate).map_err(|_| "vif group TXD")?;
    if descriptor_on(vif, &group, 0x1000, 1, 19, rate).is_ok()
        || descriptor(&group, 0x1000, 1, 18, rate).is_ok()
    {
        return Err("AP group data accepted another vif's BMC WCID");
    }
    let queue = u32::from_le_bytes(home[..4].try_into().unwrap()) >> 25;
    home[4] = 18; // TXD1 WLAN_IDX.
    home[7] |= 1; // OWN_MAC 1.
    if queue < 4 {
        let word0 = u32::from_le_bytes(home[..4].try_into().unwrap()) + (4 << 25);
        home[..4].copy_from_slice(&word0.to_le_bytes());
    }
    if record != home {
        return Err("vif AP TXD differs beyond WCID/OWN_MAC/WMM");
    }
    // TXD: HOME no-op; vif 1 OWN_MAC 1 and WMM set 1 on AC queues only.
    let frame = [0u8; 60];
    let mut ethernet = frame;
    ethernet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let base =
        packet_tx::ethernet_tid(&ethernet, 0x1000, 7, 2, false, 0).map_err(|_| "data TXD")?;
    let mut home = base;
    packet_tx::on_vif(&mut home, Vif::HOME).map_err(|_| "home TXD")?;
    let mut data = base;
    packet_tx::on_vif(&mut data, vif).map_err(|_| "vif TXD")?;
    let w0 = |b: &[u8; 64]| u32::from_le_bytes(b[0..4].try_into().unwrap());
    let w1 = |b: &[u8; 64]| u32::from_le_bytes(b[4..8].try_into().unwrap());
    if home != base
        || w0(&data) >> 25 != 4 + (w0(&base) >> 25)
        || w1(&data) != w1(&base) | 1 << 24
        || data[8..] != base[8..]
        || packet_tx::on_vif(&mut data, vif).is_ok()
    {
        return Err("data TXD OWN_MAC/WMM queue differ from mt76_connac2_mac_write_txwi");
    }
    let mut management = frame;
    management[0] = 0xd0; // action
    management[4..10].copy_from_slice(&peer);
    let base = packet_tx::management(
        &management,
        0x1000,
        8,
        2,
        crate::mt7921::association::LegacyRate::ONE_MBPS,
    )
    .map_err(|_| "management TXD")?;
    let mut altx = base;
    packet_tx::on_vif(&mut altx, vif).map_err(|_| "vif ALTX")?;
    if w0(&altx) != w0(&base) || w1(&altx) != w1(&base) | 1 << 24 {
        return Err("ALTX0 queue was retargeted to a WMM set");
    }
    Ok(())
}
fn mt76_p2p_vif_link_records_match_connac2() -> TestResult {
    vif_link().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_vif_link_records_match_connac2
);

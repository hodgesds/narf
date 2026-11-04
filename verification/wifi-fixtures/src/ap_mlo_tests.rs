//! The MLD AP exchanges genuine MIC/AES/CCMP frames with shared Security.
use super::*;
use alloc::boxed::Box;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::association::mlo::BasicMultiLink;
use narf_wireless::station_security::{RawFrame, Rx, Security};

const PLAN: NetworkPlan = NetworkPlan {
    station: [2, 0, 0, 0, 0, 1],
    bssid: [2, 0, 0, 0, 0, 2],
    server_ip: [10, 77, 0, 1],
    lease_ip: [10, 77, 0, 42],
    netmask: [255, 255, 255, 0],
    lease_seconds: 3600,
};
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 0x11];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 0x12];
const SSID: &[u8] = b"narf-mld";
const PMK: [u8; 32] = [0x55; 32];
const AN: [u8; 32] = [0x61; 32];
const SN: [u8; 32] = [0x62; 32];
fn context() -> Context {
    let mut common = vec![0x10, 1, 10];
    common.extend_from_slice(&AP);
    common.extend_from_slice(&[3, 0, 0]);
    Local::single_link(OWN)
        .unwrap()
        .context(
            PLAN.station,
            PLAN.bssid,
            &BasicMultiLink::parse(&common).unwrap(),
        )
        .unwrap()
}
struct Raw<'a>(&'a [u8]);
impl RawFrame for Raw<'_> {
    fn bytes(&self) -> &[u8] {
        self.0
    }
    fn unmodified(&self) -> bool {
        true
    }
    fn mld_context(&self) -> Option<Context> {
        Some(context())
    }
}
fn management(subtype: u8) -> Vec<u8> {
    let mut frame = vec![subtype, 0, 0, 0];
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0]);
    frame
}
fn open_auth(ap: &mut FakeAp) -> Result<(), &'static str> {
    let mut auth = management(0xb0);
    auth.extend_from_slice(&[0, 0, 1, 0, 0, 0]);
    auth.extend_from_slice(&Local::single_link(OWN).unwrap().authentication_element());
    let mut alias = auth.clone();
    alias[10..16].copy_from_slice(&PLAN.station);
    if ap.receive(&alias) != Err(ApError::Frame) || ap.phase() != ApPhase::Authentication {
        return Err("physical alias entered logical MLD auth");
    }
    let responses = ap.receive(&auth).map_err(|_| "MLD canonical auth")?;
    let response = responses.first().ok_or("MLD auth reply absent")?;
    if response[4..10] != OWN
        || response[10..16] != AP
        || context().authentication_body(&response[30..]) != Ok([].as_slice())
    {
        return Err("MLD auth response identity/common-info layout");
    }
    Ok(())
}
fn associate(ap: &mut FakeAp, rsne: &[u8], rsnxe: Option<&[u8]>) -> Result<Vec<u8>, &'static str> {
    let beacon = ap.beacon();
    if beacon[10..16] != PLAN.bssid
        || BasicMultiLink::from_ies(&beacon[36..]).map(|m| (m.address(), m.link_id()))
            != Ok((AP, Some(3)))
    {
        return Err("MLD beacon lost physical source or strict advertised spec link");
    }
    let mut assoc = management(0);
    assoc.extend_from_slice(&[0x11, 0, 10, 0, 0, SSID.len() as u8]);
    assoc.extend_from_slice(SSID);
    assoc.extend_from_slice(&[1, 3, 0x8c, 0x98, 0xb0]);
    assoc.extend_from_slice(&[48, rsne.len() as u8]);
    assoc.extend_from_slice(rsne);
    if let Some(x) = rsnxe {
        assoc.extend_from_slice(&[244, x.len() as u8]);
        assoc.extend_from_slice(x);
    }
    let mut duplicate = assoc.clone();
    duplicate.extend_from_slice(&Local::single_link(OWN).unwrap().request_element());
    duplicate.extend_from_slice(&Local::single_link(OWN).unwrap().request_element());
    if ap.receive(&duplicate) != Err(ApError::Association) || ap.phase() != ApPhase::Association {
        return Err("duplicate MLD request changed AP admission");
    }
    assoc.extend_from_slice(&Local::single_link(OWN).unwrap().request_element());
    let responses = ap.receive(&assoc).map_err(|_| "MLD association")?;
    let [response, m1] = responses.as_slice() else {
        return Err("MLD response/M1 count");
    };
    if context().response(&response[30..]).is_err()
        || response[4..10] != OWN
        || m1[4..10] != PLAN.station
        || m1[10..16] != PLAN.bssid
        || m1[16..22] != AP
    {
        return Err("logical management and physical MLO EAPOL identities conflated");
    }
    let key = KeyFrame::decode(&m1[36..], 16).ok_or("MLD M1 decode")?;
    if key.key_data != [vec![221, 10, 0, 15, 172, 3], AP.to_vec()].concat() {
        return Err("M1 missing actual AP MLD MAC KDE");
    }
    Ok(m1.clone())
}
fn terminal(owner: &mut Security) -> Result<(), &'static str> {
    let length = owner
        .pending_frame()
        .ok_or("MLD pending terminal missing")?
        .len();
    owner
        .reply_delivered_mld(&context(), length)
        .map_err(|_| "MLD exact terminal")
}
fn m3_checks(ap: &FakeAp, frame: &[u8], ptk: &Ptk) -> Result<(), &'static str> {
    let pdu = &frame[32..];
    let profile = ap.rsn.as_ref().unwrap();
    let mut signed = pdu.to_vec();
    signed[81..97].fill(0);
    let mic = eapol::wpa_eapol_key_mic(
        profile.km.unwrap(),
        profile.key_version(),
        &ptk.kck,
        &signed,
    )
    .ok_or("M3 MIC codec")?;
    if mic[..16] != pdu[81..97] {
        return Err("M3 MIC was not generated over original MLO key data");
    }
    let key = KeyFrame::decode(&pdu[4..], 16).ok_or("M3 decode")?;
    let clear =
        narf_crypto::aes_kw::aes_unwrap(ptk.kek.as_slice().try_into().unwrap(), &key.key_data)
            .ok_or("M3 actual AES unwrap")?;
    let rsne = profile.rsne_body();
    let mut complete = vec![48, rsne.len() as u8];
    complete.extend_from_slice(&rsne);
    let rsnxe = profile.rsnxe.map(|x| vec![244, 1, x]);
    let selected = eapol::mlo::authenticated_keys(
        context(),
        eapol::mlo::Kind::Pairwise3,
        key.key_information,
        &clear,
        eapol::mlo::Profile {
            rsne: &complete,
            rsnxe: rsnxe.as_deref(),
            gtk_len: 16,
            igtk_len: Some(16),
        },
    )
    .map_err(|_| "M3 strict MLO MAC/Link/RSN/keys")?;
    if selected.link_id != 3
        || selected.gtk.key != [0x77; 16]
        || selected.gtk.key_id != 1
        || selected.gtk.rsc != [0; 8]
        || selected.igtk.as_ref().is_none_or(|k| {
            k.key.as_slice() != profile.igtk
                || k.key_id != profile.igtk_id
                || k.ipn != [1, 0, 0, 0, 0, 0]
        })
    {
        return Err("M3 selected link values differ from actual AP group material/PN");
    }
    Ok(())
}
fn complete(
    ap: &mut FakeAp,
    owner: &mut Security,
    m1: &[u8],
    pmk: &[u8; 32],
) -> Result<Ptk, &'static str> {
    if owner.receive(&Raw(m1), SN) != Ok(Rx::ReplyReady) {
        return Err("MLD M1 rejected");
    }
    let m2 = owner.pending_frame().ok_or("M2 absent")?.to_vec();
    let profile = ap.rsn.as_ref().unwrap();
    let (km, version) = (profile.km.unwrap(), profile.key_version());
    let ptk = eapol::wpa_pmk_to_ptk(km, pmk, &AP, &OWN, &AN, &SN, 16);
    let physical = eapol::wpa_pmk_to_ptk(km, pmk, &PLAN.bssid, &PLAN.station, &AN, &SN, 16);
    if ptk.kck == physical.kck {
        return Err("MLD PTK used physical link addresses");
    }
    let mut bad_mic = m2.clone();
    bad_mic[32 + 81] ^= 1;
    if ap.receive(&bad_mic) != Err(ApError::Mic) || ap.pairwise_tk().is_some() {
        return Err("bad MLO M2 MIC installed AP PTK");
    }
    let mut wrong_mac = m2.clone();
    *wrong_mac.last_mut().unwrap() ^= 1;
    wrong_mac[32 + 81..32 + 97].fill(0);
    let mic = eapol::wpa_eapol_key_mic(km, version, &ptk.kck, &wrong_mac[32..]).unwrap();
    wrong_mac[32 + 81..32 + 97].copy_from_slice(&mic[..16]);
    if ap.receive(&wrong_mac) != Err(ApError::Key) || ap.pairwise_tk().is_some() {
        return Err("authenticated foreign MLD M2 MAC KDE installed AP PTK");
    }
    let replies = ap.receive(&m2).map_err(|_| "real M2 KDE/MIC refused")?;
    let m3 = replies.first().ok_or("M3 absent")?;
    m3_checks(ap, m3, &ptk)?;
    if ap.receive(&m2).as_ref() != Ok(&replies) || ap.retransmit_mld().as_ref() != Ok(m3) {
        return Err("M2 retry changed M3 crypto/PN/replay");
    }
    terminal(owner)?;
    if owner.receive(&Raw(m3), SN) != Ok(Rx::ReplyReady) || owner.port_open() {
        return Err("M3 bypassed exact M4 terminal");
    }
    let m4 = owner.pending_frame().ok_or("M4 absent")?.to_vec();
    if !ap.receive(&m4).map_err(|_| "real M4 refused")?.is_empty() || owner.port_open() {
        return Err("AP M4 acceptance impersonated native terminal");
    }
    terminal(owner)?;
    if !owner.port_open() || ap.phase() != ApPhase::Authorized || ap.retransmit_mld().is_ok() {
        return Err("MLD authorization/terminal retry retention");
    }
    Ok(ptk)
}
fn psk_rekeys() -> Result<(), &'static str> {
    if FakeAp::open(PLAN, SSID, 6, 7)
        .and_then(|p| p.with_single_link_mld(context()))
        .is_ok()
        || FakeAp::wpa2(PLAN, SSID, 6, 7, PMK, AN)
            .and_then(|p| p.with_single_link_mld(context()))
            .is_ok()
    {
        return Err("MLD fixture admitted an Open or non-PMF key profile");
    }
    let mut ap = FakeAp::wpa2(PLAN, SSID, 6, 7, PMK, AN)
        .and_then(|p| p.with_pmf(ApPmf::Required))
        .and_then(|p| p.with_single_link_mld(context()))
        .map_err(|_| "MLD AP profile")?;
    let rsne = ap.rsn.as_ref().unwrap().rsne_body();
    open_auth(&mut ap)?;
    let m1 = associate(&mut ap, &rsne, None)?;
    let mut owner = Box::new(
        Security::new(PLAN.station, PLAN.bssid, &PMK, &rsne, &rsne, None, 0)
            .and_then(|s| s.with_mld(context()))
            .map_err(|_| "MLD Security")?,
    );
    let old = complete(&mut ap, &mut owner, &m1, &PMK)?;
    let mut ethernet = OWN.to_vec();
    ethernet.extend_from_slice(&[2, 0, 0, 0, 0, 0x77]);
    ethernet.extend_from_slice(&[8, 0, 0x45, 0, 0, 4]);
    let data = ap
        .transmit_mld_data(&ethernet)
        .map_err(|_| "actual MLD AP data producer")?;
    let admitted = match owner.receive(&Raw(&data), SN) {
        Ok(Rx::Data(frame)) => frame,
        _ => return Err("shared AP data did not authenticate logical MLD unicast AAD"),
    };
    if owner.ethernet(&admitted) != Some(ethernet.clone()) || ap.mld.as_ref().unwrap().tx_pn != 1 {
        return Err("MLD AP data lost logical DA/bridged SA or shared pairwise PN");
    }
    let mut multicast = ethernet.clone();
    multicast[..6].fill(255);
    let group_data = ap
        .transmit_mld_data(&multicast)
        .map_err(|_| "MLD physical group data")?;
    let admitted = match owner.receive(&Raw(&group_data), SN) {
        Ok(Rx::Data(frame)) => frame,
        _ => return Err("MLD AP group DATA did not retain physical GTK crypto"),
    };
    if owner.ethernet(&admitted) != Some(multicast) || ap.mld.as_ref().unwrap().keys.gtk_pn != 1 {
        return Err("MLD AP group DATA lost selected GTK PN/physical address form");
    }
    let keys = MldGroupKeys {
        gtk: [0x81; 16],
        gtk_id: 2,
        gtk_pn: 9,
        igtk: [0x82; 16],
        igtk_id: 5,
        igtk_ipn: 7,
    };
    let group = ap
        .start_mld_group_rekey(keys)
        .map_err(|_| "MLD group rekey")?;
    if ap.mld.as_ref().unwrap().tx_pn != 2 || ap.transmit_mld_data(&ethernet) != Err(ApError::Phase)
    {
        return Err("MLD AP key/data producers allocated separate pairwise PN owners");
    }
    if ap.retransmit_mld() != Ok(group.clone())
        || owner.receive(&Raw(&group), SN) != Ok(Rx::ReplyReady)
    {
        return Err("MLD group retry/actual protected handshake");
    }
    let reply = owner.pending_frame().unwrap().to_vec();
    if ap.receive(&reply).is_err() || ap.mld.as_ref().unwrap().rx_pn[16] == 0 {
        return Err("MLD group2 MIC/CCMP link PN not committed");
    }
    terminal(&mut owner)?;
    let an = [0x71; 32];
    let sn = [0x72; 32];
    let rekey = ap
        .start_mld_pairwise_rekey(an)
        .map_err(|_| "MLD pairwise rekey")?;
    if ap.retransmit_mld() != Ok(rekey.clone())
        || owner.receive(&Raw(&rekey), sn) != Ok(Rx::ReplyReady)
    {
        return Err("MLD old-key M1/retry failed");
    }
    let m2 = owner.pending_frame().unwrap().to_vec();
    let response = ap.receive(&m2).map_err(|_| "MLD old-key M2")?;
    let m3 = response.first().ok_or("MLD rekey M3 absent")?;
    if ap.receive(&m2).as_ref() != Ok(&response) || ap.retransmit_mld().as_ref() != Ok(m3) {
        return Err("rekey retry recomputed protected M3");
    }
    // Prove M3 was protected under the original packet key, not the newly
    // MIC-authenticated PTK it delivers. No post-MIC address rewrite exists.
    let mut wire = m3[24..].to_vec();
    let mut replay = narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 };
    if narf_wireless::ccmp::unprotect(
        &Ccm,
        &context()
            .data_crypto_header(&m3[..24])
            .map_err(|_| "MLD physical source projection")?,
        old.tk.as_slice().try_into().unwrap(),
        0,
        false,
        &mut replay,
        &mut wire,
    )
    .is_err()
    {
        return Err("MLD rekey M3 abandoned old packet key");
    }
    terminal(&mut owner)?;
    if owner.receive(&Raw(m3), sn) != Ok(Rx::ReplyReady) {
        return Err("MLD new-PTK M3 refused");
    }
    let m4 = owner.pending_frame().unwrap().to_vec();
    if ap.receive(&m4).is_err() {
        return Err("MLD old-key M4 refused");
    }
    terminal(&mut owner)?;
    let next = eapol::wpa_pmk_to_ptk(eapol::KeyMgmt::Psk, &PMK, &AP, &OWN, &an, &sn, 16);
    if ap.pairwise_tk() != Some(next.tk.as_slice().try_into().unwrap())
        || !owner.port_open()
        || ap.mld.as_ref().unwrap().rx_pn != [0; 17]
    {
        return Err("MLD native PTK terminal did not start exact new physical key epoch");
    }
    let current = ap
        .start_mld_group_rekey(keys)
        .map_err(|_| "new-epoch MLD group")?;
    if owner.receive(&Raw(&group), sn) != Ok(Rx::Ignored)
        || owner.receive(&Raw(&current), sn) != Ok(Rx::ReplyReady)
    {
        return Err("retired MLD packet key consumed fresh-key PN or new PN1 was lost");
    }
    Ok(())
}
fn sae() -> Result<(), &'static str> {
    let password = b"mld secret";
    let mut ap = FakeAp::wpa3_sae(PLAN, SSID, 6, 7, password, ApSaePwe::HashToElement, AN)
        .and_then(|p| p.with_single_link_mld(context()))
        .map_err(|_| "SAE MLD AP")?;
    let mut session = SaeSession::new_h2e_bytes(SSID, password, OWN, AP);
    session.try_build_commit().map_err(|_| "SAE MLD entropy")?;
    let auth = |seq: u16, status: u16, body: &[u8]| {
        let mut f = management(0xb0);
        f.extend_from_slice(&3u16.to_le_bytes());
        f.extend_from_slice(&seq.to_le_bytes());
        f.extend_from_slice(&status.to_le_bytes());
        f.extend_from_slice(body);
        f.extend_from_slice(&Local::single_link(OWN).unwrap().authentication_element());
        f
    };
    let commit = auth(1, 126, &session.commit_body(None));
    let replies = ap.receive(&commit).map_err(|_| "AP MLD SAE commit")?;
    let reply = replies.first().ok_or("AP MLD commit absent")?;
    let peer_commit = context()
        .authentication_body(&reply[30..])
        .map_err(|_| "AP SAE MLD trailer")?;
    session
        .on_commit(peer_commit)
        .map_err(|_| "MLD peer SAE crypto")?;
    let confirm = auth(2, 0, &session.build_confirm());
    let replies = ap.receive(&confirm).map_err(|_| "AP MLD SAE confirm")?;
    session
        .on_confirm(
            context()
                .authentication_body(&replies[0][30..])
                .map_err(|_| "AP confirm MLE")?,
        )
        .map_err(|_| "MLD SAE confirm crypto")?;
    let pmk = *session.pmk().ok_or("MLD SAE PMK absent")?;
    if ap.rsn.as_ref().unwrap().sae_pmk() != Some(pmk) {
        return Err("logical MLD SAE peers derived different PMKs");
    }
    let ap_rsne = ap.rsn.as_ref().unwrap().rsne_body();
    let mut station = narf_wireless::rsn::RsnIe::decode_body(&ap_rsne).unwrap();
    station.pmkids = vec![*session.pmkid().ok_or("MLD SAE PMKID absent")?];
    let station = station.encode_body();
    let rsnxe = [narf_wireless::rsn::RSNX_CAP_SAE_H2E];
    let m1 = associate(&mut ap, &station, Some(&rsnxe))?;
    let mut owner = Box::new(
        Security::new_sae(
            PLAN.station,
            PLAN.bssid,
            &pmk,
            &station,
            Some(&rsnxe),
            &ap_rsne,
            Some(&rsnxe),
            0,
        )
        .and_then(|s| s.with_mld(context()))
        .map_err(|_| "MLD SAE Security")?,
    );
    complete(&mut ap, &mut owner, &m1, &pmk)?;
    Ok(())
}
fn smoke_fake_ap_single_link_mld_kdes_retries_and_rekeys() -> TestResult {
    psk_rekeys().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "verification/wifi-fixtures",
    smoke_fake_ap_single_link_mld_kdes_retries_and_rekeys
);
fn smoke_fake_ap_single_link_mld_sae_h2e_and_logical_ptk() -> TestResult {
    sae().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "verification/wifi-fixtures",
    smoke_fake_ap_single_link_mld_sae_h2e_and_logical_ptk
);

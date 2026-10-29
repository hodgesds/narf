//! WPA3-SAE / PMF station owner: AKM 8 4-way with IGTK, CCMP-protected
//! unicast robust management frames and BIP group management frames.
use super::*;
use crate::rsn::{self, RsnIe, Suite};
const IGTK: [u8; 16] = [0x9e; 16];
const PMKID: [u8; 16] = [0x99; 16];
const RSNXE: [u8; 1] = [0x20];
const MFP: u16 = rsn::RSN_CAP_MFP_REQUIRED | rsn::RSN_CAP_MFP_CAPABLE;
fn sae_rsne(akm: u8, caps: u16, pmkid: bool) -> Vec<u8> {
    RsnIe {
        version: 1,
        group_cipher: Suite::standard(rsn::CIPHER_CCMP_128),
        pairwise_ciphers: vec![Suite::standard(rsn::CIPHER_CCMP_128)],
        akms: vec![Suite::standard(akm)],
        rsn_capabilities: caps,
        pmkids: if pmkid { vec![PMKID] } else { Vec::new() },
        group_management_cipher: None,
    }
    .encode_body()
}
fn sae_owner() -> Result<Security, Error> {
    Security::new_sae(
        OWN,
        AP,
        &PMK,
        &sae_rsne(8, MFP, true),
        Some(&RSNXE),
        &sae_rsne(8, MFP, false),
        Some(&RSNXE),
        2,
    )
}
fn sae_ptk() -> Ptk {
    eapol::wpa_pmk_to_ptk(KeyMgmt::Sae, &PMK, &AP, &OWN, &AN, &SN, 16)
}
/// hostapd-side AKM 8 EAPOL-Key frame: version 0, AES-128-CMAC MIC.
fn sae_key_frame(ki: u16, rc: u64, key_data: &[u8], ptk: Option<&Ptk>) -> Vec<u8> {
    let mut frame = KeyFrame::empty(16);
    frame.key_information = ki;
    frame.key_length = 16;
    frame.replay_counter = rc;
    frame.key_nonce = AN;
    frame.key_data = if ki & 0x1000 != 0 {
        let mut padded = key_data.to_vec();
        if padded.len() % 8 != 0 || padded.len() < 16 {
            padded.push(0xdd);
            while padded.len() % 8 != 0 || padded.len() < 16 {
                padded.push(0);
            }
        }
        narf_crypto::aes_kw::aes_wrap(ptk.unwrap().kek.as_slice().try_into().unwrap(), &padded)
            .unwrap()
    } else {
        key_data.to_vec()
    };
    let mut bytes = frame.into_eapol();
    bytes[0] = 2;
    if ki & 0x100 != 0 {
        let mic = narf_crypto::cmac_aes128::cmac_aes128(
            ptk.unwrap().kck.as_slice().try_into().unwrap(),
            &bytes,
        );
        bytes[81..97].copy_from_slice(&mic);
    }
    bytes
}
fn m3_key_data(igtk: bool) -> Vec<u8> {
    let mut kd = ie(48, &sae_rsne(8, MFP, false)).unwrap();
    kd.extend_from_slice(&ie(244, &RSNXE).unwrap());
    kd.extend_from_slice(&[0xdd, 22, 0, 0x0f, 0xac, 1, 1, 0]);
    kd.extend_from_slice(&GTK);
    if igtk {
        kd.extend_from_slice(&[0xdd, 28, 0, 0x0f, 0xac, 9, 4, 0, 7, 0, 0, 0, 0, 0]);
        kd.extend_from_slice(&IGTK);
    }
    kd
}
const M1: u16 = 0x0088;
const M3: u16 = 0x13c8;
fn sae_established() -> Result<Security, &'static str> {
    let mut s = sae_owner().map_err(|_| "SAE owner refused")?;
    let p = sae_ptk();
    if s.receive(&mpdu(native(&sae_key_frame(M1, 1, &[], None), false)), SN) != Ok(Rx::ReplyReady) {
        return Err("SAE M1");
    }
    deliver(&mut s);
    if s.receive(
        &mpdu(native(
            &sae_key_frame(M3, 2, &m3_key_data(true), Some(&p)),
            false,
        )),
        SN,
    ) != Ok(Rx::ReplyReady)
    {
        return Err("SAE M3");
    }
    deliver(&mut s);
    if !s.port_open() || !s.pmf() {
        return Err("SAE port not open with PMF");
    }
    Ok(s)
}
fn mgmt(subtype: u8, da: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut f = vec![subtype, 0, 0, 0];
    f.extend_from_slice(&da);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&[0x10, 0]);
    f.extend_from_slice(body);
    f
}
fn protect_from_ap(frame: &[u8], tk: &[u8], pn: u64) -> Vec<u8> {
    let mut header = frame[..24].to_vec();
    header[1] |= 0x40;
    let mut body = frame[24..].to_vec();
    let wire = crate::ccmp::protect(
        &Ccm,
        &header,
        tk.try_into().unwrap(),
        pn,
        0,
        0,
        true,
        &mut body,
    )
    .unwrap();
    header.extend_from_slice(&wire);
    header
}

fn sae_profile() -> Result<(), &'static str> {
    if Security::new(
        OWN,
        AP,
        &PMK,
        &sae_rsne(8, MFP, true),
        &sae_rsne(8, MFP, false),
        None,
        2,
    )
    .is_ok()
    {
        return Err("WPA2 constructor accepted an SAE profile");
    }
    if Security::new_sae(OWN, AP, &PMK, &rsne(), None, &rsne(), None, 2).is_ok() {
        return Err("SAE constructor accepted WPA2-PSK");
    }
    let bad_ap = |ap: Vec<u8>| {
        Security::new_sae(OWN, AP, &PMK, &sae_rsne(8, MFP, true), None, &ap, None, 2).is_err()
    };
    if !bad_ap(sae_rsne(8, 0, false)) || !bad_ap(sae_rsne(24, MFP, false)) {
        return Err("AP without MFPC or the station AKM admitted");
    }
    if Security::new_sae(
        OWN,
        AP,
        &PMK,
        &sae_rsne(8, 0x80, true),
        None,
        &sae_rsne(8, MFP, false),
        None,
        2,
    )
    .is_ok()
    {
        return Err("station RSNE without MFPR admitted");
    }
    if Security::new_sae(
        OWN,
        AP,
        &PMK,
        &sae_rsne(24, MFP, true),
        Some(&RSNXE),
        &sae_rsne(24, MFP, false),
        Some(&RSNXE),
        2,
    )
    .map_or(true, |s| s.supplicant.key_mgmt() != KeyMgmt::SaeExtKey)
    {
        return Err("AKM 24 owner");
    }
    // M3 without the IGTK KDE under PMF is a protocol failure.
    let mut s = sae_owner().map_err(|_| "owner")?;
    let p = sae_ptk();
    s.receive(&mpdu(native(&sae_key_frame(M1, 1, &[], None), false)), SN)
        .map_err(|_| "M1")?;
    deliver(&mut s);
    if s.receive(
        &mpdu(native(
            &sae_key_frame(M3, 2, &m3_key_data(false), Some(&p)),
            false,
        )),
        SN,
    ) != Err(Error::Protocol)
        || s.port_open()
    {
        return Err("PMF M3 without IGTK admitted");
    }
    Ok(())
}
fn smoke_station_sae_owner_profile_and_igtk_requirement() -> TestResult {
    match sae_profile() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_sae_owner_profile_and_igtk_requirement
);

fn robust_management() -> Result<(), &'static str> {
    let mut s = sae_established()?;
    let tk = sae_ptk().tk;
    let deauth = mgmt(0xc0, OWN, &[7, 0]);
    // Unprotected unicast robust frames are dropped under PMF.
    if s.receive_management(&mpdu(deauth.clone())) != Ok(MgmtRx::Ignored) {
        return Err("unprotected deauthentication admitted");
    }
    let protected = protect_from_ap(&deauth, &tk, 1);
    if s.receive_management(&mpdu(protected.clone())) != Ok(MgmtRx::Frame(deauth.clone())) {
        return Err("protected deauthentication not decrypted");
    }
    if s.receive_management(&mpdu(protected)) != Ok(MgmtRx::Ignored) {
        return Err("replayed protected deauthentication admitted");
    }
    let mut tampered = protect_from_ap(&deauth, &tk, 2);
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    if s.receive_management(&mpdu(tampered)) != Ok(MgmtRx::Ignored) {
        return Err("tampered protected frame admitted");
    }
    // Non-robust (Public Action) frames pass unchanged.
    let public = mgmt(0xd0, OWN, &[4, 0]);
    if s.receive_management(&mpdu(public.clone())) != Ok(MgmtRx::Frame(public)) {
        return Err("public action dropped");
    }
    // Group robust frame: BIP-CMAC-128 under the M3 IGTK (IPN > 7).
    let bcast = mgmt(0xc0, [255; 6], &[3, 0]);
    let mut igtk = narf_crypto::bip_cmac::Igtk::install(IGTK, 4).unwrap();
    igtk.tx_pn = 7;
    let mut body = bcast[24..].to_vec();
    crate::mfp::protect_outbound(&mut igtk, &bcast[..24], &mut body).unwrap();
    let mut signed = bcast[..24].to_vec();
    signed.extend_from_slice(&body);
    if s.receive_management(&mpdu(signed.clone())) != Ok(MgmtRx::Frame(bcast.clone())) {
        return Err("BIP group deauthentication refused");
    }
    if s.receive_management(&mpdu(signed)) != Ok(MgmtRx::Ignored) {
        return Err("BIP replay admitted");
    }
    if s.receive_management(&mpdu(bcast)) != Ok(MgmtRx::Ignored) {
        return Err("group robust frame without MMIE admitted");
    }
    // Station-originated protected Disassociation.
    let mut disassoc = vec![0xa0, 0, 0, 0];
    disassoc.extend_from_slice(&AP);
    disassoc.extend_from_slice(&OWN);
    disassoc.extend_from_slice(&AP);
    disassoc.extend_from_slice(&[0x20, 0, 8, 0]);
    let out = s
        .protect_management(&disassoc)
        .map_err(|_| "protect_management refused")?;
    let mut window = crate::ccmp::ReplayWindow { last_seen_pn: 0 };
    let mut wire = out[24..].to_vec();
    let plain = crate::ccmp::unprotect(
        &Ccm,
        &out[..24],
        tk.as_slice().try_into().unwrap(),
        0,
        true,
        &mut window,
        &mut wire,
    )
    .map_err(|_| "AP could not decrypt station disassociation")?;
    if plain != disassoc[24..] || out[1] & 0x40 == 0 {
        return Err("protected disassociation body");
    }
    let public = {
        let mut f = disassoc.clone();
        f[0] = 0xd0;
        f[24] = 4;
        f
    };
    if s.protect_management(&public) != Err(Error::Profile) {
        return Err("non-robust frame protected");
    }
    // A WPA2 owner has no PMF management path.
    let mut wpa2 = established();
    if wpa2.protect_management(&disassoc) != Err(Error::State)
        || wpa2.receive_management(&mpdu(mgmt(0xc0, OWN, &[7, 0])))
            != Ok(MgmtRx::Frame(mgmt(0xc0, OWN, &[7, 0])))
    {
        return Err("WPA2 owner applied PMF");
    }
    Ok(())
}
fn smoke_station_sae_pmf_robust_management_ccmp_and_bip() -> TestResult {
    match robust_management() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_sae_pmf_robust_management_ccmp_and_bip
);

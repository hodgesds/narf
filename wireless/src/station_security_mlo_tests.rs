//! Real MLO handshakes, original physical admission and class-specific crypto.
use super::*;
use crate::association::mlo::{BasicMultiLink, Context, Local};
use alloc::boxed::Box;
const OWN_MLD: [u8; 6] = [2, 0, 0, 0, 0, 0x11];
const AP_MLD: [u8; 6] = [2, 0, 0, 0, 0, 0x12];
const IGTK: [u8; 16] = [0x9e; 16];
fn context(id: u8) -> Context {
    let mut bytes = vec![0x10, 1, 10];
    bytes.extend_from_slice(&AP_MLD);
    bytes.extend_from_slice(&[id, 0, 0]);
    Local::single_link(OWN_MLD)
        .unwrap()
        .context(OWN, AP, &BasicMultiLink::parse(&bytes).unwrap())
        .unwrap()
}
fn pmf_rsne() -> Vec<u8> {
    let mut value = crate::rsn::RsnIe::wpa2_psk_ccmp();
    value.rsn_capabilities = crate::rsn::RSN_CAP_MFP_CAPABLE | crate::rsn::RSN_CAP_MFP_REQUIRED;
    value.encode_body()
}
fn owner(context: Context) -> Box<Security> {
    Box::new(
        Security::new(OWN, AP, &PMK, &pmf_rsne(), &pmf_rsne(), None, 2)
            .unwrap()
            .with_mld(context)
            .unwrap(),
    )
}
fn field(selector: u8, data: &[u8]) -> Vec<u8> {
    let mut value = vec![221, (4 + data.len()) as u8, 0, 0x0f, 0xac, selector];
    value.extend_from_slice(data);
    value
}
fn mac() -> Vec<u8> {
    field(3, &AP_MLD)
}
fn keys(c: Context, gtk: [u8; 16], igtk: [u8; 16], with_link: bool) -> Vec<u8> {
    let mut value = if with_link { mac() } else { Vec::new() };
    if with_link {
        let mut link = vec![c.link_id() | 0x10];
        link.extend_from_slice(&AP);
        link.extend_from_slice(&ie(48, &pmf_rsne()).unwrap());
        value.extend_from_slice(&field(19, &link));
    }
    let mut g = vec![c.link_id() << 4 | 2, 9, 0, 0, 0, 0, 0];
    g.extend_from_slice(&gtk);
    value.extend_from_slice(&field(16, &g));
    let mut i = vec![4, 0, 7, 0, 0, 0, 0, 0, c.link_id() << 4];
    i.extend_from_slice(&igtk);
    value.extend_from_slice(&field(17, &i));
    value
}
struct MldFrame {
    bytes: Vec<u8>,
    context: Option<Context>,
}
impl RawFrame for MldFrame {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn unmodified(&self) -> bool {
        true
    }
    fn mld_context(&self) -> Option<Context> {
        self.context
    }
}
fn frame(body: &[u8], c: Context) -> MldFrame {
    let mut bytes = native(body, false);
    bytes[16..22].copy_from_slice(&AP_MLD);
    MldFrame {
        bytes,
        context: Some(c),
    }
}
fn deliver_mld(owner: &mut Security, c: &Context) -> Result<(), Error> {
    let len = owner.pending_frame().ok_or(Error::State)?.len();
    owner.reply_delivered_mld(c, len)
}
struct Fixture {
    owner: Box<Security>,
    context: Context,
    ptk: Ptk,
}
fn staged() -> Result<Fixture, &'static str> {
    let c = context(3);
    let mut s = owner(c);
    if s.receive(&frame(&key_frame(0x8a, 1, AN, &mac(), None), c), SN) != Ok(Rx::ReplyReady) {
        return Err("MLD genuine M1/M2");
    }
    let p = eapol::wpa_pmk_to_ptk(KeyMgmt::Psk, &PMK, &AP_MLD, &OWN_MLD, &AN, &SN, 16);
    let pending = s.pending_frame().ok_or("MLD M2 missing")?;
    let m2 = KeyFrame::decode(&pending[36..], 16).ok_or("MLD M2 decode")?;
    if m2.key_data != eapol::mlo::message2(c, &ie(48, &pmf_rsne()).unwrap()).unwrap()
        || pending[4..10] != AP
        || pending[10..16] != OWN
        || pending[16..22] != AP_MLD
        || s.supplicant.tptk.as_ref().map(|p| &p.kck) != Some(&p.kck)
        || p.kck == ptk(AN, SN).kck
    {
        return Err("MLD M2/PTK conflated logical addresses with physical packet identity");
    }
    if s.reply_delivered(pending.len()) != Err(Error::Profile) {
        return Err("MLD terminal link proof bypass");
    }
    deliver_mld(&mut s, &c).map_err(|_| "MLD exact M2 terminal")?;
    if s.receive(
        &frame(
            &key_frame(0x13ca, 2, AN, &keys(c, GTK, IGTK, true), Some(&p)),
            c,
        ),
        SN,
    ) != Ok(Rx::ReplyReady)
    {
        return Err("MLD authenticated encrypted M3");
    }
    Ok(Fixture {
        owner: s,
        context: c,
        ptk: p,
    })
}
fn establish() -> Result<Fixture, &'static str> {
    let mut f = staged()?;
    deliver_mld(&mut f.owner, &f.context).map_err(|_| "MLD exact M4 terminal")?;
    Ok(f)
}
fn payload(multicast: bool) -> Vec<u8> {
    let mut value = native(&[], multicast);
    value[30..32].copy_from_slice(&[8, 0]);
    value.extend_from_slice(&[0x45, 0, 0, 4]);
    value
}
// Independent fixture construction: crypto is over logical DATA A1/A2;
// the emitted radio header remains physical. Group/management are untouched.
fn crypto_header(physical: &[u8]) -> Vec<u8> {
    let mut header = physical.to_vec();
    if header[0] & 0x0c == 8 && header[4] & 1 == 0 {
        let (a1, a2) = if header[1] & 3 == 1 {
            (AP_MLD, OWN_MLD)
        } else {
            (OWN_MLD, AP_MLD)
        };
        header[4..10].copy_from_slice(&a1);
        header[10..16].copy_from_slice(&a2);
        if header.len() == 26 && header[24] & 0x80 != 0 {
            header[16..22].copy_from_slice(&AP_MLD);
        }
    }
    header
}
fn encrypt(frame: &[u8], tk: &[u8], pn: u64, id: u8) -> Vec<u8> {
    let mut header = frame[..24].to_vec();
    header[1] |= 0x40;
    let mut body = frame[24..].to_vec();
    let wire = crate::ccmp::protect(
        &Ccm,
        &crypto_header(&header),
        tk.try_into().unwrap(),
        pn,
        id,
        0,
        false,
        &mut body,
    )
    .unwrap();
    header.extend_from_slice(&wire);
    header
}
fn decrypt(frame: &[u8], tk: &[u8]) -> Vec<u8> {
    let mut wire = frame[24..].to_vec();
    let mut replay = crate::ccmp::ReplayWindow { last_seen_pn: 0 };
    crate::ccmp::unprotect(
        &Ccm,
        &crypto_header(&frame[..24]),
        tk.try_into().unwrap(),
        0,
        false,
        &mut replay,
        &mut wire,
    )
    .unwrap()
}
fn aggregate(tk: &[u8], destination: [u8; 6], tid: u8) -> (Vec<u8>, Vec<Vec<u8>>) {
    aggregate_wire(tk, destination, tid, true)
}
fn aggregate_wire(
    tk: &[u8],
    destination: [u8; 6],
    tid: u8,
    logical: bool,
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let bridge = [2, 0, 0, 0, 0, 0x77];
    let frames: Vec<_> = (1..=2)
        .map(|value| {
            let mut ethernet = destination.to_vec();
            ethernet.extend_from_slice(&bridge);
            ethernet.extend_from_slice(&[8, 0, 0x45, 0, 0, value]);
            ethernet
        })
        .collect();
    let refs: Vec<_> = frames.iter().map(Vec::as_slice).collect();
    let mut body = crate::amsdu::encode(&refs, bridge, crate::amsdu::Limit::Ht3839).unwrap();
    let mut header = vec![0x88, 0x42, 0, 0];
    header.extend_from_slice(&OWN);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&[0, 0, 0x80 | tid, 0]);
    let crypto = if logical {
        crypto_header(&header)
    } else {
        header.clone()
    };
    let encrypted = crate::ccmp::protect(
        &Ccm,
        &crypto,
        tk.try_into().unwrap(),
        1,
        0,
        tid,
        false,
        &mut body,
    )
    .unwrap();
    header.extend_from_slice(&encrypted);
    (header, frames)
}
fn crypto_vectors() -> Result<(), &'static str> {
    // Independently generated with Python cryptography/OpenSSL AESCCM, not
    // narf's CCM/AAD/projection code. Full parameters are retained under
    // shared-single-link-mld-r2-independent-ccmp-vector.json.
    let header = [
        8, 0x42, 0, 0, 2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0x77, 0x30, 0,
    ];
    let body = [0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 0x45, 0, 0, 4];
    let logical = [
        1, 0, 0, 0x20, 0, 0, 0, 0, 0x02, 0x7a, 0x13, 0x77, 0x64, 0x77, 0x3d, 0xd0, 0x40, 0xdc,
        0xea, 0x72, 0xc4, 0x69, 0xc1, 0xcd, 0x1b, 0x5b, 0x4c, 0xb5,
    ];
    let physical = [
        1, 0, 0, 0x20, 0, 0, 0, 0, 0xfa, 0x8c, 0x39, 0x6b, 0x53, 0x41, 0x59, 0xc6, 0xd2, 0xe1,
        0x4c, 0xdd, 0xce, 0xb1, 0x5e, 0xae, 0x90, 0x1c, 0xdb, 0xd3,
    ];
    let make = |role, id| {
        Key::new(&[0x71; 16], id, role, OWN, AP, 0)
            .unwrap()
            .with_mld_context(Some(&context(3)))
            .unwrap()
    };
    let mut key = make(Role::Pairwise, 0);
    let mut wrong = physical.to_vec();
    if key.unprotect(&header, &mut wrong).is_ok() || wrong != physical {
        return Err("MLD unicast physical-AAD known vector admitted or mutated on rejection");
    }
    let mut right = logical.to_vec();
    if key.unprotect(&header, &mut right) != Ok(body.to_vec()) {
        return Err(
            "independent logical-AAD MLD vector failed after physical-AAD same-PN rejection",
        );
    }
    let mut ordinary = Key::new(&[0x71; 16], 0, Role::Pairwise, OWN, AP, 0).unwrap();
    if ordinary.unprotect(&header, &mut physical.to_vec()) != Ok(body.to_vec()) {
        return Err("ordinary non-MLD physical-AAD vector changed");
    }
    let mut management = vec![0xc0, 0x40, 0, 0];
    management.extend_from_slice(&OWN);
    management.extend_from_slice(&AP);
    management.extend_from_slice(&AP);
    management.extend_from_slice(&[0, 0]);
    let mut management_body = vec![3, 0];
    let mut wire = crate::ccmp::protect(
        &Ccm,
        &management,
        &[0x71; 16],
        1,
        0,
        0,
        true,
        &mut management_body,
    )
    .unwrap();
    if key.unprotect_management(&management, &mut wire) != Ok(vec![3, 0]) {
        return Err(
            "MLD management did not retain original physical-AAD/nonce and independent replay slot",
        );
    }
    let mut group = header;
    group[4..10].fill(0xff);
    let mut group_body = body.to_vec();
    let mut wire =
        crate::ccmp::protect(&Ccm, &group, &[0x71; 16], 1, 2, 0, false, &mut group_body).unwrap();
    if make(Role::Group, 2).unprotect(&group, &mut wire) != Ok(body.to_vec()) {
        return Err("MLD group DATA did not retain physical link AAD/nonce");
    }
    Ok(())
}
fn handshake() -> Result<(), &'static str> {
    crypto_vectors()?;
    let mut f = staged()?;
    if f.owner.port_open()
        || f.owner.pair.is_some()
        || f.owner.group.iter().any(Option::is_some)
        || f.owner.igtk.active.is_some()
    {
        return Err("MLD keys/port installed before native M4 terminal");
    }
    let len = f.owner.pending_frame().unwrap().len();
    if f.owner.reply_delivered_mld(&context(4), len) != Err(Error::Profile)
        || f.owner.pending_frame().is_none()
    {
        return Err("foreign MLD link consumed exact pending reply");
    }
    deliver_mld(&mut f.owner, &f.context).map_err(|_| "MLD M4 terminal")?;
    if !f.owner.port_open()
        || f.owner.group[2].as_ref().map(|g| *g.material) != Some(GTK)
        || f.owner.igtk.active.as_ref().map(|k| k.key) != Some(IGTK)
    {
        return Err("MLD selected-link native keys absent after exact terminal");
    }
    let bytes = encrypt(&payload(false), &f.ptk.tk, 1, 0);
    let wrong = MldFrame {
        bytes: bytes.clone(),
        context: Some(context(4)),
    };
    if f.owner.receive(&wrong, SN) != Ok(Rx::Ignored) {
        return Err("foreign native link entered MLD packet key/replay owner");
    }
    let right = MldFrame {
        bytes: bytes.clone(),
        context: Some(f.context),
    };
    let data = match f.owner.receive(&right, SN) {
        Ok(Rx::Data(data)) => data,
        _ => return Err("original physical frame with logical MLD unicast crypto failed"),
    };
    if f.owner.ethernet(&data).as_ref().map(|v| &v[..6]) != Some(OWN_MLD.as_slice())
        || f.owner.receive(&right, SN) != Ok(Rx::Ignored)
    {
        return Err("MLD Ethernet identity/replay state mismatch");
    }
    // Native MLO GTK PN is9; descriptor RSC in key_frame is5. PN6 must fail.
    for (pn, accepted) in [(6, false), (10, true)] {
        let raw = MldFrame {
            bytes: encrypt(&payload(true), &GTK, pn, 2),
            context: Some(f.context),
        };
        if matches!(f.owner.receive(&raw, SN), Ok(Rx::Data(_))) != accepted {
            return Err("MLD GTK used descriptor-wide RSC instead of selected link PN");
        }
    }
    let mut ethernet = vec![2, 0, 0, 0, 0, 9];
    ethernet.extend_from_slice(&OWN_MLD);
    ethernet.extend_from_slice(&[8, 0, 0x45, 0, 0, 4]);
    let tx = f
        .owner
        .transmit_ethernet(&ethernet)
        .map_err(|_| "MLD logical Ethernet TX")?;
    if tx[4..10] != AP
        || tx[10..16] != OWN
        || decrypt(&tx, &f.ptk.tk)[..8] != [0xaa, 0xaa, 3, 0, 0, 0, 8, 0]
    {
        return Err("MLD TX rewrote its original physical radio header or logical crypto failed");
    }
    let (wire, expected) = aggregate(&f.ptk.tk, OWN_MLD, 3);
    let (wrong_aad, _) = aggregate_wire(&f.ptk.tk, OWN_MLD, 3, false);
    if f.owner.receive_amsdu(&MldFrame {
        bytes: wrong_aad,
        context: Some(f.context),
    }) != Ok(None)
    {
        return Err("MLD A-MSDU accepted valid physical-AAD MIC instead of logical MLD AAD");
    }
    let mut foreign_bssid = wire.clone();
    foreign_bssid[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 0x77]);
    if f.owner.receive_amsdu(&MldFrame {
        bytes: foreign_bssid,
        context: Some(f.context),
    }) != Ok(None)
    {
        return Err("MLD A-MSDU projected a foreign raw BSSID to selected AP MLD");
    }
    let mut ordinary = Key::new(
        f.ptk.tk.as_slice().try_into().unwrap(),
        0,
        Role::Pairwise,
        OWN,
        AP,
        0,
    )
    .unwrap();
    if ordinary.unprotect_amsdu(&wire[..26], &wire[26..]).is_ok() {
        return Err("ordinary packet key admitted MLD logical aggregate DA");
    }
    let wrong = MldFrame {
        bytes: wire.clone(),
        context: Some(context(4)),
    };
    if f.owner.receive_amsdu(&wrong) != Ok(None) {
        return Err("foreign link consumed aggregate ciphertext or PN");
    }
    let current = MldFrame {
        bytes: wire.clone(),
        context: Some(f.context),
    };
    if f.owner.receive_amsdu(&current) != Ok(Some(expected))
        || f.owner.receive_amsdu(&current) != Ok(None)
    {
        return Err(
            "MLD aggregate lost logical DA/external bridged SA or reset physical-link replay",
        );
    }
    let (physical, _) = aggregate(&f.ptk.tk, OWN, 4);
    let physical = MldFrame {
        bytes: physical,
        context: Some(f.context),
    };
    if f.owner.receive_amsdu(&physical) != Ok(None) {
        return Err("MLD aggregate aliased physical DA to logical MSDU destination");
    }
    let (logical, expected) = aggregate(&f.ptk.tk, OWN_MLD, 4);
    if f.owner.receive_amsdu(&MldFrame {
        bytes: logical,
        context: Some(f.context),
    }) != Ok(Some(expected))
    {
        return Err("rejected physical aggregate DA committed PN before logical-DA validation");
    }
    Ok(())
}
fn smoke_mld_ptk_link_keys_native_ccmp_and_exact_m4_terminal() -> TestResult {
    handshake().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/station_security/mlo",
    smoke_mld_ptk_link_keys_native_ccmp_and_exact_m4_terminal
);

fn negative_and_rekey() -> Result<(), &'static str> {
    let c = context(3);
    let mut s = owner(c);
    let mut badmac = mac();
    *badmac.last_mut().unwrap() ^= 1;
    let mut nonces = 0;
    if s.receive_with_nonce(&frame(&key_frame(0x8a, 1, AN, &badmac, None), c), || {
        nonces += 1;
        Some(SN)
    }) != Ok(Rx::Ignored)
        || nonces != 0
        || s.supplicant.tptk.is_some()
    {
        return Err("bad MLD M1 consumed nonce or PTK state");
    }
    let good = keys(c, GTK, IGTK, true);
    for mutation in 0..10 {
        let mut s = owner(c);
        if s.receive(&frame(&key_frame(0x8a, 1, AN, &mac(), None), c), SN) != Ok(Rx::ReplyReady) {
            return Err("negative MLD fixture M1");
        }
        deliver_mld(&mut s, &c).map_err(|_| "negative M2 terminal")?;
        let p = eapol::wpa_pmk_to_ptk(KeyMgmt::Psk, &PMK, &AP_MLD, &OWN_MLD, &AN, &SN, 16);
        let mut data = good.clone();
        let mut flags = 0x13ca;
        let gtk = data
            .windows(4)
            .position(|w| w == [0, 0x0f, 0xac, 16])
            .unwrap()
            + 4;
        let link = data
            .windows(4)
            .position(|w| w == [0, 0x0f, 0xac, 19])
            .unwrap()
            + 4;
        match mutation {
            0 => data[6] ^= 1,
            1 => data[link] ^= 1,
            2 => data[link + 1] ^= 2,
            3 => data[link + 9] ^= 1,
            4 => data[gtk] |= 8,
            5 => data[gtk] = 0x42,
            6 => {
                let copy = data[gtk - 6..gtk + 23].to_vec();
                data.extend_from_slice(&copy);
            }
            7 => {
                flags &= !0x40;
            }
            8 => {
                flags &= !0x200;
            }
            _ => {
                // Inflate the final IGTK element's claimed extent beyond
                // the actual authenticated plaintext, including AES padding.
                let igtk = data
                    .windows(4)
                    .position(|w| w == [0, 0x0f, 0xac, 17])
                    .unwrap();
                data[igtk - 1] = 255;
            }
        }
        if s.receive(&frame(&key_frame(flags, 2, AN, &data, Some(&p)), c), SN)
            .is_ok()
            || s.port_open()
            || s.pair.is_some()
            || s.pending_frame().is_some()
        {
            return Err("invalid authenticated MLD MAC/link/RSN/key/flags published native keys");
        }
    }
    let mut f = establish()?;
    let newer = [0x88; 16];
    let next_igtk = [0x99; 16];
    let group = key_frame(
        0x1382,
        3,
        [0; 32],
        &keys(c, newer, next_igtk, false),
        Some(&f.ptk),
    );
    let group = frame(&group, c);
    let group = MldFrame {
        bytes: encrypt(&group.bytes, &f.ptk.tk, 1, 0),
        context: Some(c),
    };
    if f.owner.receive(&group, SN) != Ok(Rx::ReplyReady)
        || f.owner.group[2].as_ref().map(|g| *g.material) != Some(GTK)
    {
        return Err("MLD group rekey installed before reply terminal");
    }
    deliver_mld(&mut f.owner, &c).map_err(|_| "MLD group reply terminal")?;
    if f.owner.group[2].as_ref().map(|g| *g.material) != Some(newer) {
        return Err("MLD group GTK not installed on exact link");
    }
    let multicast = MldFrame {
        bytes: encrypt(&payload(true), &newer, 10, 2),
        context: Some(c),
    };
    if !matches!(f.owner.receive(&multicast, SN), Ok(Rx::Data(_))) {
        return Err("new MLO GTK actual CCMP receive");
    }
    let again = frame(
        &key_frame(
            0x1382,
            4,
            [0; 32],
            &keys(c, newer, next_igtk, false),
            Some(&f.ptk),
        ),
        c,
    );
    let again = MldFrame {
        bytes: encrypt(&again.bytes, &f.ptk.tk, 2, 0),
        context: Some(c),
    };
    if f.owner.receive(&again, SN) != Ok(Rx::ReplyReady) {
        return Err("MLD duplicate material with fresh EAPOL counter");
    }
    deliver_mld(&mut f.owner, &c).map_err(|_| "MLD same-key reply terminal")?;
    if f.owner.receive(&multicast, SN) != Ok(Rx::Ignored) {
        return Err("MLO GTK reinstallation reset per-link replay counter");
    }
    let retired = frame(
        &key_frame(0x1382, 5, [0; 32], &keys(c, GTK, IGTK, false), Some(&f.ptk)),
        c,
    );
    let retired = MldFrame {
        bytes: encrypt(&retired.bytes, &f.ptk.tk, 3, 0),
        context: Some(c),
    };
    if f.owner.receive(&retired, SN) != Err(Error::KeyReuse) || f.owner.port_open() {
        return Err("retired MLO key material resurrected old per-link PN state");
    }
    pairwise_rekey()?;
    Ok(())
}
fn pairwise_rekey() -> Result<(), &'static str> {
    let mut f = establish()?;
    let c = f.context;
    let an = [0x61; 32];
    let sn = [0x62; 32];
    let next = eapol::wpa_pmk_to_ptk(KeyMgmt::Psk, &PMK, &AP_MLD, &OWN_MLD, &an, &sn, 16);
    let m1 = frame(&key_frame(0x8a, 3, an, &mac(), None), c);
    let m1 = MldFrame {
        bytes: encrypt(&m1.bytes, &f.ptk.tk, 1, 0),
        context: Some(c),
    };
    if f.owner.receive(&m1, sn) != Ok(Rx::ReplyReady) {
        return Err("MLD protected rekey M1 not admitted under installed physical link key");
    }
    let m2 = f.owner.pending_frame().ok_or("MLD rekey M2 missing")?;
    let m2_plain = decrypt(m2, &f.ptk.tk);
    let m2 = KeyFrame::decode(&m2_plain[12..], 16).ok_or("MLD old-key rekey M2 decode")?;
    if m2.key_nonce != sn
        || f.owner.pair.as_ref().map(|p| p.material.as_slice()) != Some(f.ptk.tk.as_slice())
        || f.owner.port_open()
    {
        return Err("MLD rekey M2 replaced old key or opened port before terminal delivery");
    }
    deliver_mld(&mut f.owner, &c).map_err(|_| "MLD rekey M2 terminal")?;
    let m3 = frame(
        &key_frame(
            0x13ca,
            4,
            an,
            &keys(c, [0x74; 16], [0x75; 16], true),
            Some(&next),
        ),
        c,
    );
    let m3 = MldFrame {
        bytes: encrypt(&m3.bytes, &f.ptk.tk, 2, 0),
        context: Some(c),
    };
    if f.owner.receive(&m3, sn) != Ok(Rx::ReplyReady) {
        return Err("MLD authenticated new-PTK M3 under old packet key failed");
    }
    let pending = f.owner.pending_frame().ok_or("MLD rekey M4 missing")?;
    let m4_plain = decrypt(pending, &f.ptk.tk);
    let m4 = KeyFrame::decode(&m4_plain[12..], 16).ok_or("MLD old-key rekey M4 decode")?;
    let mut signed = m4_plain[8..].to_vec();
    signed[81..97].fill(0);
    let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(&next.kck, &signed);
    if m4.key_mic != mic[..16]
        || f.owner.pair.as_ref().map(|p| p.material.as_slice()) != Some(f.ptk.tk.as_slice())
        || f.owner.port_open()
        || f.owner.reply_delivered_mld(&context(4), pending.len()) != Err(Error::Profile)
    {
        return Err("MLD M4 lost old packet/new KCK separation or exact native link terminal");
    }
    deliver_mld(&mut f.owner, &c).map_err(|_| "MLD rekey M4 terminal")?;
    let retired = MldFrame {
        bytes: encrypt(&payload(false), &f.ptk.tk, 3, 0),
        context: Some(c),
    };
    let current = MldFrame {
        bytes: encrypt(&payload(false), &next.tk, 1, 0),
        context: Some(c),
    };
    if !f.owner.port_open()
        || f.owner.receive(&retired, sn) != Ok(Rx::Ignored)
        || !matches!(f.owner.receive(&current, sn), Ok(Rx::Data(_)))
        || f.owner.receive(&current, sn) != Ok(Rx::Ignored)
    {
        return Err("MLD new physical key epoch/replay accepted retired material or lost fresh PN");
    }
    Ok(())
}
fn smoke_mld_m1_nonce_boundaries_authenticated_kdes_group_rekey_and_replay() -> TestResult {
    negative_and_rekey().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/station_security/mlo",
    smoke_mld_m1_nonce_boundaries_authenticated_kdes_group_rekey_and_replay
);

const OWN_LINK2: [u8; 6] = [2, 0, 0, 0, 0, 0x21];
const AP_LINK2: [u8; 6] = [2, 0, 0, 0, 0, 0x22];
fn further_context(id: u8) -> Context {
    let mut bytes = vec![0x10, 1, 10];
    bytes.extend_from_slice(&AP_MLD);
    bytes.extend_from_slice(&[id, 0, 0]);
    Local::single_link(OWN_MLD)
        .unwrap()
        .context(OWN_LINK2, AP_LINK2, &BasicMultiLink::parse(&bytes).unwrap())
        .unwrap()
}
fn further_kdes(id: u8, with_link: bool, gtk: [u8; 16]) -> Vec<u8> {
    let mut value = Vec::new();
    if with_link {
        let mut link = vec![id | 0x10];
        link.extend_from_slice(&AP_LINK2);
        link.extend_from_slice(&ie(48, &pmf_rsne()).unwrap());
        value.extend_from_slice(&field(19, &link));
    }
    let mut g = vec![id << 4 | 1, 3, 0, 0, 0, 0, 0];
    g.extend_from_slice(&gtk);
    value.extend_from_slice(&field(16, &g));
    let mut i = vec![5, 0, 1, 0, 0, 0, 0, 0, id << 4];
    i.extend_from_slice(&[0x5a; 16]);
    value.extend_from_slice(&field(17, &i));
    value
}
fn multi_link_kdes() -> Result<(), &'static str> {
    use crate::eapol::mlo::{self, Error as E, Kind, Profile};
    let (assoc, link) = (context(1), further_context(2));
    let rsne = ie(48, &pmf_rsne()).unwrap();
    let profile = Profile {
        rsne: &rsne,
        rsnxe: None,
        gtk_len: 16,
        igtk_len: Some(16),
    };
    // M2: MLD MAC KDE, then one MLO Link KDE (no RSNE) per further link.
    let m2 = mlo::message2_links(assoc, &[link], &[]).map_err(|_| "multi-link M2")?;
    let mut expected = field(3, &OWN_MLD);
    let mut info = vec![2];
    info.extend_from_slice(&OWN_LINK2);
    expected.extend_from_slice(&field(19, &info));
    if m2 != expected || mlo::message2_links(assoc, &[assoc], &[]) != Err(E::Profile) {
        return Err("multi-link M2 Link KDE layout or assoc-link exclusion");
    }
    let flags =
        crate::eapol::KI_ENCRYPTED_KEY_DATA | crate::eapol::KI_INSTALL | crate::eapol::KI_SECURE;
    let mut m3 = keys(assoc, [1; 16], IGTK, true);
    m3.extend_from_slice(&further_kdes(2, true, [7; 16]));
    let got = mlo::authenticated_link_keys(
        assoc,
        &[(link, profile)],
        Kind::Pairwise3,
        flags,
        &m3,
        profile,
    )
    .map_err(|_| "multi-link M3 rejected")?;
    if got.len() != 2
        || got[0].link_id != 1
        || got[0].gtk.key != [1; 16]
        || got[1].link_id != 2
        || got[1].gtk.key != [7; 16]
        || got[1].gtk.key_id != 1
        || got[1].gtk.rsc[..2] != [3, 0]
        || got[1].igtk.as_ref().map(|igtk| igtk.key_id) != Some(5)
    {
        return Err("multi-link M3 per-link GTK/IGTK/PN");
    }
    // M3 needs every accepted link's Link KDE; group rekeys need each GTK.
    let mut unlinked = keys(assoc, [1; 16], IGTK, true);
    unlinked.extend_from_slice(&further_kdes(2, false, [7; 16]));
    let group = further_kdes(2, false, [8; 16]);
    if mlo::authenticated_link_keys(
        assoc,
        &[(link, profile)],
        Kind::Pairwise3,
        flags,
        &unlinked,
        profile,
    ) != Err(E::Link)
        || mlo::authenticated_link_keys(
            assoc,
            &[(link, profile)],
            Kind::Group1,
            crate::eapol::KI_ENCRYPTED_KEY_DATA,
            &group,
            profile,
        ) != Err(E::Key)
    {
        return Err("multi-link M3/group accepted a missing per-link KDE");
    }
    // A KDE for a link outside the association is refused, and the
    // single-link profile still refuses any affiliated link's KDE.
    let mut stranger = m3.clone();
    stranger.extend_from_slice(&further_kdes(3, false, [9; 16]));
    if mlo::authenticated_link_keys(
        assoc,
        &[(link, profile)],
        Kind::Pairwise3,
        flags,
        &stranger,
        profile,
    ) != Err(E::Link)
        || mlo::authenticated_keys(assoc, Kind::Pairwise3, flags, &m3, profile) != Err(E::Link)
    {
        return Err("per-link KDE outside the association accepted");
    }
    Ok(())
}
fn smoke_mld_multi_link_m2_link_kdes_and_per_link_group_keys() -> TestResult {
    multi_link_kdes().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/station_security/mlo",
    smoke_mld_multi_link_m2_link_kdes_and_per_link_group_keys
);

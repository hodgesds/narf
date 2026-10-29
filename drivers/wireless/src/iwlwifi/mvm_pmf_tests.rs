//! Gen2 WPA3-SAE/PMF conversations with an independently authored AP and
//! firmware model: SAE (hunting-and-pecking and H2E) from the AP's own
//! `SaeSession`, a SHA-256-KDF/AES-CMAC authenticator delivering GTK and
//! IGTK, native key/IGTK/epoch receipts and PMF management receive.
use super::super::super::{firmware_api::FirmwareApi, firmware_parser_tests, runtime};
use super::super::{
    auth::tests::fixture as link_fixture,
    data::tests::{associated, policy, prepare},
    queue::tests::Fixture,
    rsna,
};
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::{pin, Pin},
    task::{Context as TaskContext, Poll, Waker},
};
use narf_crypto::bip_cmac::Igtk;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::eapol::KeyFrame;

const OWN: [u8; 6] = [2; 6];
const AP: [u8; 6] = [2, 4, 6, 8, 10, 12];
const PASSWORD: &[u8] = b"correct horse";
const SNONCE: [u8; 32] = [0x11; 32];
const ANONCE: [u8; 32] = [0x22; 32];
const GTK: [u8; 16] = [0x77; 16];
const IGTK: [u8; 16] = [0x99; 16];
const IPN: u64 = 0x0102_0304;

fn check(test: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    test().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn poll<T>(future: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let result = future.poll(&mut TaskContext::from_waker(Waker::noop()));
    if result.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}
/// RSNE body: CCMP-128 group/pairwise, AKM `akm`, MFPC|MFPR.
fn rsne(akm: u8) -> Vec<u8> {
    vec![
        1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, akm, 0xc0, 0,
    ]
}
fn header(fc: u8, to: [u8; 6], from: [u8; 6], third: [u8; 6]) -> Vec<u8> {
    let mut b = vec![fc, 0, 0, 0];
    b.extend_from_slice(&to);
    b.extend_from_slice(&from);
    b.extend_from_slice(&third);
    b.extend_from_slice(&[0, 0]);
    b
}
/// Authored API4 RX descriptor (48 bytes) followed by the MPDU.
fn envelope(frame: &[u8], status: u32) -> Vec<u8> {
    let mut b = vec![0; 48];
    b[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    b[12..16].copy_from_slice(&status.to_le_bytes());
    b[16..20].copy_from_slice(&0x7f00_0000u32.to_le_bytes());
    b[32] = 40;
    b[34] = 1;
    b.extend_from_slice(frame);
    b
}
fn eapol_frame(pdu: &[u8]) -> Vec<u8> {
    let mut f = header(8, OWN, AP, AP);
    f[1] = 2;
    f.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    f.extend_from_slice(pdu);
    f
}
fn cmac_mic(kck: &[u8], pdu: &[u8]) -> [u8; 16] {
    let mut clear = pdu.to_vec();
    clear[81..97].fill(0);
    let mic = narf_crypto::cmac_aes128::cmac_aes128_truncated(kck.try_into().unwrap(), &clear, 16);
    mic.try_into().unwrap()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Enable,
    Disable,
    Commit,
    Confirm,
    Associate,
    Link,
    Mac,
    Message2,
    Message4,
    PairKey,
    GroupKey,
    Igtk,
    Fence,
    RemovePair,
    RemoveGroup,
    RemoveIgtk,
    RemoveQueue,
    Deauth { protected: bool },
    Data,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Fault {
    None,
    /// The AP rejects the Commit with status 1 (unspecified failure).
    RejectCommit,
    /// The AP runs SAE with another password; its Confirm cannot verify.
    WrongPassword,
    /// Message 3 omits the IGTK KDE.
    NoIgtk,
}
/// Independent AP + firmware receipt model.
struct Ap {
    sae: SaeSession,
    h2e: bool,
    fault: Fault,
    ptk: Option<(Vec<u8>, Vec<u8>, [u8; 16])>,
    events: Vec<Kind>,
    keys: [Option<[u8; 16]>; 5],
    igtk: Option<u16>,
    enabled: bool,
    m4: bool,
    sync: u32,
    assoc_rsne: Vec<u8>,
    data: Vec<Vec<u8>>,
}
impl Ap {
    fn new(h2e: bool, fault: Fault) -> Self {
        let password = if fault == Fault::WrongPassword {
            &b"wrong battery"[..]
        } else {
            PASSWORD
        };
        let sae = if h2e {
            SaeSession::new_h2e_bytes(b"net", password, AP, OWN)
        } else {
            SaeSession::new_hunt_and_peck(password, AP, OWN)
        }
        .with_test_seed([0x42; 64]);
        Self {
            sae,
            h2e,
            fault,
            ptk: None,
            events: Vec::new(),
            keys: [None; 5],
            igtk: None,
            enabled: false,
            m4: false,
            sync: 0,
            assoc_rsne: Vec::new(),
            data: Vec::new(),
        }
    }
    fn auth(&self, seq: u16, status: u16, body: &[u8]) -> Vec<u8> {
        let mut f = header(0xb0, OWN, AP, AP);
        f.extend_from_slice(&3u16.to_le_bytes());
        f.extend_from_slice(&seq.to_le_bytes());
        f.extend_from_slice(&status.to_le_bytes());
        f.extend_from_slice(body);
        envelope(&f, 3)
    }
    fn m1(&self) -> Vec<u8> {
        let mut m1 = KeyFrame::empty(16);
        m1.key_information = 0x88;
        m1.key_length = 16;
        m1.replay_counter = 1;
        m1.key_nonce = ANONCE;
        envelope(&eapol_frame(&m1.into_eapol()), 3)
    }
    fn derive(&mut self, snonce: &[u8; 32]) -> Result<(), &'static str> {
        let pmk = *self.sae.pmk().ok_or("AP SAE PMK absent")?;
        let mut context = Vec::new();
        context.extend_from_slice(&AP.min(OWN));
        context.extend_from_slice(&AP.max(OWN));
        context.extend_from_slice(&ANONCE.min(*snonce));
        context.extend_from_slice(&ANONCE.max(*snonce));
        let ptk =
            narf_wireless::sae::session::kdf_sha256(&pmk, b"Pairwise key expansion", &context, 48);
        self.ptk = Some((
            ptk[..16].to_vec(),
            ptk[16..32].to_vec(),
            ptk[32..48].try_into().unwrap(),
        ));
        Ok(())
    }
    fn m3(&self) -> Result<Vec<u8>, &'static str> {
        let (kck, kek, _) = self.ptk.as_ref().ok_or("AP M3 before PTK")?;
        let mut clear = vec![48, 20];
        clear.extend_from_slice(&rsne(8));
        clear.extend_from_slice(&[221, 22, 0, 15, 172, 1, 1, 0]);
        clear.extend_from_slice(&GTK);
        if self.fault != Fault::NoIgtk {
            clear.extend_from_slice(&[221, 28, 0, 15, 172, 9, 4, 0]);
            clear.extend_from_slice(&IPN.to_le_bytes()[..6]);
            clear.extend_from_slice(&IGTK);
        }
        if clear.len() % 8 != 0 {
            clear.push(221);
        }
        while clear.len() % 8 != 0 {
            clear.push(0);
        }
        let mut m3 = KeyFrame::empty(16);
        m3.key_information = 0x13c8;
        m3.key_length = 16;
        m3.replay_counter = 2;
        m3.key_nonce = ANONCE;
        m3.key_data = narf_crypto::aes_kw::aes_wrap(kek.as_slice().try_into().unwrap(), &clear)
            .ok_or("AP key wrap")?;
        let mut pdu = m3.into_eapol();
        let mic = cmac_mic(kck, &pdu);
        pdu[81..97].copy_from_slice(&mic);
        Ok(envelope(&eapol_frame(&pdu), 3))
    }
    /// A firmware-decrypted protected unicast Deauthentication.
    fn protected_deauth(&self, pn: u64, decrypted: bool) -> Vec<u8> {
        let mut f = header(0xc0, OWN, AP, AP);
        f[1] = 0x40;
        let p = pn.to_le_bytes();
        f.extend_from_slice(&[p[0], p[1], 0, 0x20, p[2], p[3], p[4], p[5]]);
        f.extend_from_slice(&7u16.to_le_bytes());
        envelope(&f, if decrypted { 0xa4f } else { 3 })
    }
    fn unprotected_deauth(&self) -> Vec<u8> {
        let mut f = header(0xc0, OWN, AP, AP);
        f.extend_from_slice(&7u16.to_le_bytes());
        envelope(&f, 3)
    }
    /// A group-addressed Deauthentication with a BIP-CMAC-128 MMIE.
    fn bip_deauth(&self, key: [u8; 16], ipn: u64) -> Vec<u8> {
        let f = header(0xc0, [0xff; 6], AP, AP);
        let mut igtk = Igtk::install(key, 4).unwrap();
        igtk.tx_pn = ipn - 1;
        let mut body = 7u16.to_le_bytes().to_vec();
        narf_wireless::mfp::protect_outbound(&mut igtk, &f, &mut body).unwrap();
        let mut frame = f;
        frame.extend_from_slice(&body);
        envelope(&frame, 3)
    }
    fn react(
        &mut self,
        p: runtime::model::Published,
        fw: &mut runtime::model::Firmware,
    ) -> Result<(), &'static str> {
        if p.queue == 0 {
            let (op, group) = (p.bytes[0], p.bytes[1]);
            let sequence = u16::from_le_bytes([p.bytes[2], p.bytes[3]]);
            let b = &p.bytes[8..];
            let ok = vec![1, 0, 0, 0];
            let (kind, reply_group, reply) = match (group, op) {
                (1, 0x18) => {
                    self.enabled = b.get(20) != Some(&16);
                    let kind = if self.enabled {
                        Kind::Enable
                    } else {
                        Kind::Disable
                    };
                    (kind, 0, ok)
                }
                (3, 9) => (Kind::Link, 3, vec![]),
                (3, 8) => (Kind::Mac, 3, vec![]),
                (1, 0x17) => {
                    let flags = u16::from_le_bytes([b[2], b[3]]);
                    let group_key = flags & 0x4000 != 0;
                    let slot = usize::from(b[1]);
                    if b.len() != 76 || flags & 0x8000 == 0 || self.enabled {
                        return Err("PMF key lacks STA_KEY_MFP or precedes peer disable");
                    }
                    if flags & 0x800 != 0 {
                        self.keys[slot].take().ok_or("removed absent key")?;
                        let kind = if group_key {
                            Kind::RemoveGroup
                        } else {
                            Kind::RemovePair
                        };
                        (kind, 0, ok)
                    } else {
                        let expected = if group_key {
                            (GTK, 10 | 0x8000 | 0x4000 | 0x100, 2)
                        } else {
                            (self.ptk.as_ref().ok_or("PTK before M2")?.2, 10 | 0x8000, 0)
                        };
                        if !self.m4
                            || flags != expected.1
                            || slot != expected.2
                            || b[4..20] != expected.0
                            || b[20..] != [0; 56]
                        {
                            return Err("PMF native key bytes/flags/order");
                        }
                        self.keys[slot] = Some(expected.0);
                        let kind = if group_key {
                            Kind::GroupKey
                        } else {
                            Kind::PairKey
                        };
                        (kind, 0, ok)
                    }
                }
                (0, 0x1f) => {
                    // Literal SEC_MGMT_MULTICAST_KEY_CMD_API_S_VER_2 layout.
                    let mut expected = [0u8; 52];
                    let kind = if b.get(..4) == Some(&[2, 0, 0, 0]) {
                        expected[0] = 2;
                        expected[4..20].copy_from_slice(&IGTK);
                        expected[44..48].copy_from_slice(&(IPN as u32).to_le_bytes());
                        self.igtk = Some(4);
                        Kind::Igtk
                    } else {
                        expected[1] = 8;
                        self.igtk.take().ok_or("removed absent IGTK")?;
                        Kind::RemoveIgtk
                    };
                    expected[36] = 4;
                    if b != expected || self.enabled {
                        return Err("MGMT_MCAST_KEY wire layout/order");
                    }
                    (kind, 0, vec![])
                }
                (5, 2) => {
                    self.sync += 1;
                    let mut marker = vec![8, 0, 0, 0, 0, 0, 1, 0];
                    marker.extend_from_slice(&self.sync.to_le_bytes());
                    fw.inject(op, group, sequence, &[]);
                    fw.inject(0xff, 5, 0x8000, &marker);
                    self.events.push(Kind::Fence);
                    return Ok(());
                }
                (5, 0x17) => {
                    if self.keys.iter().any(Option::is_some) || self.igtk.is_some() {
                        return Err("queue removed before key/IGTK retirement");
                    }
                    (Kind::RemoveQueue, 5, vec![24, 0, 0, 0, 0x91, 0, 0, 0])
                }
                _ => return Err("unexpected native SAE/PMF control"),
            };
            self.events.push(kind);
            fw.inject(op, reply_group, sequence, &reply);
            return Ok(());
        }
        if !self.enabled && p.queue == 23 {
            return Err("management frame without enabled peer");
        }
        let flags = u32::from_le_bytes(p.bytes[8..12].try_into().unwrap());
        let frame = p.bytes[24..].to_vec();
        let mut complete = vec![0; 48];
        complete[0] = 1;
        complete[36..38].copy_from_slice(&p.queue.to_le_bytes());
        complete[40] = 1;
        complete[44..48].copy_from_slice(&u32::from(p.pointer).to_le_bytes());
        fw.inject(0x1c, 0, 0x8000, &complete);
        if frame[4..10] != AP || frame[10..16] != OWN {
            return Err("frame not addressed to the AP");
        }
        match frame[0] {
            0xb0 => {
                let field = |at: usize| u16::from_le_bytes([frame[at], frame[at + 1]]);
                let (alg, seq) = (field(24), field(26));
                if alg != 3 {
                    return Err("SAE owner sent another algorithm");
                }
                if seq == 1 {
                    self.events.push(Kind::Commit);
                    if field(28) != if self.h2e { 126 } else { 0 } {
                        return Err("commit status disagrees with PWE");
                    }
                    if self.fault == Fault::RejectCommit {
                        fw.inject(0xc1, 0, 0x8000, &self.auth(1, 1, &[]));
                        return Ok(());
                    }
                    let commit = self.sae.build_commit();
                    self.sae
                        .on_commit(&frame[30..])
                        .map_err(|_| "AP rejected station commit")?;
                    let status = if self.h2e { 126 } else { 0 };
                    fw.inject(0xc1, 0, 0x8000, &self.auth(1, status, &commit));
                } else {
                    self.events.push(Kind::Confirm);
                    let confirm = self.sae.build_confirm();
                    if self.fault != Fault::WrongPassword {
                        self.sae
                            .on_confirm(&frame[30..])
                            .map_err(|_| "AP rejected station confirm")?;
                    }
                    fw.inject(0xc1, 0, 0x8000, &self.auth(2, 0, &confirm));
                }
            }
            0 => {
                self.events.push(Kind::Associate);
                let mut at = 28;
                while at + 2 <= frame.len() {
                    let len = usize::from(frame[at + 1]);
                    if frame[at] == 48 {
                        self.assoc_rsne = frame[at + 2..at + 2 + len].to_vec();
                    }
                    at += 2 + len;
                }
                let mut expected = rsne(8);
                expected.truncate(18);
                expected.extend_from_slice(&[0xc0, 0, 1, 0]);
                expected.extend_from_slice(self.sae.pmkid().ok_or("AP PMKID absent")?);
                if self.assoc_rsne != expected || frame[24] & 0x10 == 0 {
                    return Err("association RSNE lacks exact SAE PMKID/MFPR");
                }
                let mut r = header(0x10, OWN, AP, AP);
                r.extend_from_slice(&[0x11, 0, 0, 0, 7, 0xc0, 1, 1, 0x82]);
                fw.inject(0xc1, 0, 0x8000, &envelope(&r, 3));
            }
            8 if p.queue == 23 => {
                if flags & 2 == 0
                    || frame.get(24..32) != Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e])
                {
                    return Err("initial EAPOL not plaintext/LLC");
                }
                let pdu = &frame[32..];
                let key = KeyFrame::decode(&pdu[4..], 16).ok_or("AP EAPOL decode")?;
                if key.key_information == 0x108 {
                    self.events.push(Kind::Message2);
                    let mut station = vec![48, self.assoc_rsne.len() as u8];
                    station.extend_from_slice(&self.assoc_rsne);
                    self.derive(&key.key_nonce)?;
                    let kck = self.ptk.as_ref().unwrap().0.clone();
                    if key.replay_counter != 1
                        || key.key_data != station
                        || pdu[81..97] != cmac_mic(&kck, pdu)
                    {
                        return Err("M2 RSNE/replay/AES-CMAC MIC");
                    }
                    let m3 = self.m3()?;
                    fw.inject(0xc1, 0, 0x8000, &m3);
                } else {
                    self.events.push(Kind::Message4);
                    let kck = &self.ptk.as_ref().ok_or("M4 before M2")?.0;
                    if key.key_information != 0x308 || pdu[81..97] != cmac_mic(kck, pdu) {
                        return Err("M4 flags/AES-CMAC MIC");
                    }
                    self.m4 = true;
                }
            }
            0xc0 => {
                let protected = frame[1] & 0x40 != 0;
                if protected == (flags & 2 != 0) || frame[24..] != [3, 0] {
                    return Err("deauthentication crypto flags/reason");
                }
                self.events.push(Kind::Deauth { protected });
            }
            _ => {
                if frame[1] & 0x40 == 0 || flags & 2 != 0 || self.keys[0].is_none() {
                    return Err("PMF data without native PTK");
                }
                self.events.push(Kind::Data);
                self.data.push(frame);
            }
        }
        Ok(())
    }
}
fn drive<T>(
    mut op: Pin<&mut impl Future<Output = Result<T, &'static str>>>,
    trace: &runtime::model::TxTrace,
    firmware: &mut runtime::model::Firmware,
    ap: &mut Ap,
) -> Result<Result<T, &'static str>, &'static str> {
    for _ in 0..256 {
        let result = poll(op.as_mut());
        while let Some(p) = trace.take() {
            ap.react(p, firmware)?;
        }
        if let Poll::Ready(result) = result {
            return Ok(result);
        }
    }
    Err("SAE/PMF fixture progress budget")
}
/// Configured link owner whose observed AP offers WPA3-SAE (`akm`), with
/// the Gen2 TX/rate/data/key/RX-sync command versions.
fn sae_fixture(h2e: bool, akm: u8) -> Result<Fixture, &'static str> {
    let mut f = link_fixture()?;
    let owner = f.owner.as_mut().unwrap();
    let beacon = &mut owner.beacons[0];
    beacon.capabilities |= 16;
    beacon.privacy = true;
    beacon.information_elements.extend_from_slice(&[48, 20]);
    beacon.information_elements.extend_from_slice(&rsne(akm));
    if h2e {
        beacon
            .information_elements
            .extend_from_slice(&[244, 1, 0x20]);
    }
    let image = firmware_parser_tests::mvm_image();
    let parsed = super::super::super::parse_ucode(&image).unwrap();
    let mut versions = parsed.api.commands.to_vec();
    versions.extend_from_slice(&[
        0x1c, 0, 9, 0, 0x1c, 1, 0, 6, 0xc1, 0, 0, 4, 0xf7, 5, 0, 3, 15, 5, 3, 0, 0x17, 1, 3, 0, 2,
        5, 1, 0, 0xff, 5, 0, 1,
    ]);
    runtime::model::versions(&mut owner.hardware, &versions);
    let mut caps = FirmwareApi::default();
    caps.api_changes[0] = 1 << 29;
    owner.security = rsna::Context::new(&caps);
    Ok(f)
}
fn seeded(join: &SaeJoin, own: [u8; 6], peer: [u8; 6]) -> Result<SaeSession, &'static str> {
    let mut session = if join.h2e() {
        SaeSession::new_h2e_bytes(b"net", PASSWORD, own, peer)
    } else {
        SaeSession::new_hunt_and_peck(PASSWORD, own, peer)
    }
    .with_test_seed([0x31; 64]);
    session.build_commit();
    Ok(session)
}
fn authenticate(
    f: &mut Fixture,
    ap: &mut Ap,
) -> Result<Result<AuthenticationStatus, &'static str>, &'static str> {
    let owner = f.owner.as_mut().unwrap();
    let mut op =
        pin!(owner.authenticate_sae_using(b"net", &[], SaePwe::Both, seeded, || Ok(policy())));
    drive(op.as_mut(), &f.trace, &mut f.firmware, ap)
}
/// SAE authentication, PMF association and data preparation.
fn sae_prepared(h2e: bool, fault: Fault) -> Result<(Fixture, Ap), &'static str> {
    let mut f = sae_fixture(h2e, 8)?;
    let mut ap = Ap::new(h2e, fault);
    if authenticate(&mut f, &mut ap)?.map(|s| s.status) != Ok(0) {
        return Err("SAE authentication did not complete");
    }
    {
        let owner = f.owner.as_mut().unwrap();
        let mut op = pin!(owner.associate_legacy_using(
            b"net",
            SecurityMode::Wpa3Sae { pwe: SaePwe::Both },
            || Ok(policy())
        ));
        let status = drive(op.as_mut(), &f.trace, &mut f.firmware, &mut ap)??;
        if !status.pmf || !status.protected || status.aid != 7 {
            return Err("SAE association did not negotiate PMF");
        }
    }
    prepare(&mut f, true)?;
    while f.trace.take().is_some() {}
    Ok((f, ap))
}
fn secure(f: &mut Fixture, ap: &mut Ap) -> Result<Result<(), &'static str>, &'static str> {
    f.firmware.inject(0xc1, 0, 0x8000, &ap.m1());
    let owner = f.owner.as_mut().unwrap();
    let mut op = pin!(owner.secure_sae_using(|| Ok(SNONCE), || Ok(policy())));
    drive(op.as_mut(), &f.trace, &mut f.firmware, ap)
}
fn secured(h2e: bool) -> Result<(Fixture, Ap), &'static str> {
    let (mut f, mut ap) = sae_prepared(h2e, Fault::None)?;
    secure(&mut f, &mut ap)??;
    Ok((f, ap))
}

fn smoke_gen2_sae_pmf_native_conversation_and_protected_management() -> TestResult {
    check(|| {
        for h2e in [false, true] {
            let (mut f, ap) = secured(h2e)?;
            let expected = [
                Kind::Enable,
                Kind::Commit,
                Kind::Confirm,
                Kind::Disable,
                Kind::Enable,
                Kind::Associate,
                Kind::Disable,
                Kind::Disable,
                Kind::Link,
                Kind::Mac,
                Kind::Enable,
                Kind::Message2,
                Kind::Message4,
                Kind::Disable,
                Kind::PairKey,
                Kind::GroupKey,
                Kind::Igtk,
                Kind::Fence,
                Kind::Enable,
            ];
            if ap.events != expected {
                return Err("SAE/association/M4/key/IGTK/epoch order");
            }
            let owner = f.owner.as_mut().unwrap();
            if owner.phase() != Phase::DataPrepared || !owner.data_port_using(|| Ok(policy())) {
                return Err("PMF controlled port not open");
            }
            // An unprotected unicast or a forged/replayed robust frame is
            // dropped without state change (ieee80211_drop_unencrypted_mgmt).
            for packet in [
                ap.unprotected_deauth(),
                ap.protected_deauth(5, false),
                ap.bip_deauth([0x55; 16], IPN + 1),
                ap.bip_deauth(IGTK, IPN),
            ] {
                f.firmware.inject(0xc1, 0, 0x8000, &packet);
                if owner.receive_data_using(|| Ok(policy())).is_err()
                    || owner.phase() != Phase::DataPrepared
                {
                    return Err("unprotected/forged/replayed robust frame ended association");
                }
            }
            let packet = if h2e {
                ap.protected_deauth(5, true)
            } else {
                ap.bip_deauth(IGTK, IPN + 1)
            };
            f.firmware.inject(0xc1, 0, 0x8000, &packet);
            if owner.receive_data_using(|| Ok(policy())).is_ok() {
                return Err("valid protected/BIP deauthentication ignored");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/pmf",
    smoke_gen2_sae_pmf_native_conversation_and_protected_management
);

fn smoke_gen2_pmf_close_protects_deauth_and_retires_igtk() -> TestResult {
    check(|| {
        let (mut f, mut ap) = secured(false)?;
        let mark = ap.events.len();
        {
            let owner = f.owner.as_mut().unwrap();
            let mut current = || Ok(policy());
            let mut op = pin!(owner.deauthenticate_using(3, &mut current));
            if drive(op.as_mut(), &f.trace, &mut f.firmware, &mut ap)? != Ok(true) {
                return Err("PMF leaving deauthentication not acknowledged");
            }
        }
        {
            let owner = f.owner.as_mut().unwrap();
            let mut op = pin!(owner.release_legacy_data());
            drive(op.as_mut(), &f.trace, &mut f.firmware, &mut ap)??;
        }
        if ap.events[mark..]
            != [
                Kind::Deauth { protected: true },
                Kind::Disable,
                Kind::RemovePair,
                Kind::RemoveGroup,
                Kind::RemoveIgtk,
                Kind::Fence,
                Kind::RemoveQueue,
            ]
            || f.owner.as_ref().unwrap().phase() != Phase::Associated
        {
            return Err("PMF close order: protected deauth, keys, IGTK, epoch, queue");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/pmf",
    smoke_gen2_pmf_close_protects_deauth_and_retires_igtk
);

fn smoke_gen2_sae_pmf_failures_are_terminal_or_unpublished() -> TestResult {
    check(|| {
        // AP rejection: the peer is disabled again, no SAE is retained and
        // association has nothing to consume.
        let mut f = sae_fixture(false, 8)?;
        let mut ap = Ap::new(false, Fault::RejectCommit);
        if authenticate(&mut f, &mut ap)?.map(|s| s.status) != Ok(1)
            || ap.events != [Kind::Enable, Kind::Commit, Kind::Disable]
        {
            return Err("SAE rejection not published after peer disable");
        }
        {
            let owner = f.owner.as_mut().unwrap();
            let mut op = pin!(owner.associate_legacy_using(
                b"net",
                SecurityMode::Wpa3Sae { pwe: SaePwe::Both },
                || Ok(policy())
            ));
            if drive(op.as_mut(), &f.trace, &mut f.firmware, &mut ap)?.is_ok() {
                return Err("association consumed a rejected SAE exchange");
            }
        }
        // A Confirm under another password fails the owner.
        let mut f = sae_fixture(false, 8)?;
        let mut ap = Ap::new(false, Fault::WrongPassword);
        if authenticate(&mut f, &mut ap)?.is_ok()
            || f.owner.as_ref().unwrap().phase() != Phase::Failed
        {
            return Err("unverifiable SAE Confirm accepted");
        }
        // Message 3 without the IGTK installs no key.
        let (mut f, mut ap) = sae_prepared(false, Fault::NoIgtk)?;
        if secure(&mut f, &mut ap)?.is_ok()
            || ap.events.contains(&Kind::PairKey)
            || ap.events.contains(&Kind::Igtk)
        {
            return Err("M3 without IGTK installed keys");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/pmf",
    smoke_gen2_sae_pmf_failures_are_terminal_or_unpublished
);

fn smoke_gen2_pmf_not_granted_paths_refuse_and_wire_layouts() -> TestResult {
    check(|| {
        // SAE-EXT-KEY (AKM 24) under H2E is not offered by this key owner.
        let mut f = sae_fixture(true, 24)?;
        let mut ap = Ap::new(true, Fault::None);
        if authenticate(&mut f, &mut ap)?.is_ok() || !ap.events.is_empty() {
            return Err("AKM 24 SAE reached the air");
        }
        // Without the native key API there is no PMF owner.
        let mut f = link_fixture()?;
        if f.owner.as_ref().unwrap().station_sae_supported() {
            return Err("SAE advertised without native key API");
        }
        let mut ap = Ap::new(false, Fault::None);
        if authenticate(&mut f, &mut ap)?.is_ok() || !ap.events.is_empty() {
            return Err("SAE without key API reached the air");
        }
        // A WPA2 association cannot run the SAE owner, nor SAE the WPA2 one.
        let mut f = associated(true, 3, false)?;
        prepare(&mut f, true)?;
        {
            let owner = f.owner.as_mut().unwrap();
            let mut op = pin!(owner.secure_sae_using(|| Ok(SNONCE), || Ok(policy())));
            if !matches!(poll(op.as_mut()), Poll::Ready(Err(_))) {
                return Err("SAE owner accepted a WPA2 association");
            }
        }
        let (mut f, _) = sae_prepared(false, Fault::None)?;
        {
            let owner = f.owner.as_mut().unwrap();
            let mut op = pin!(owner.secure_using([0x55; 32], || Ok(SNONCE), || Ok(policy())));
            if !matches!(poll(op.as_mut()), Poll::Ready(Err(_))) {
                return Err("WPA2 owner accepted a PMF association");
            }
        }
        // Linux iwl_mvm_send_sta_igtk v2 bytes, install and remove.
        let install = igtk_command(Some(&IGTK), 5, 0x0a0b_0c0d_0e0f);
        let mut expected = [0u8; 52];
        expected[0] = 2;
        expected[4..20].copy_from_slice(&IGTK);
        expected[36] = 5;
        expected[44..50].copy_from_slice(&[0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a]);
        let mut removed = [0u8; 52];
        removed[1] = 8;
        removed[36] = 5;
        if *install != expected || *igtk_command(None, 5, 9) != removed {
            return Err("MGMT_MCAST_KEY v2 layout");
        }
        // Without PMF the legacy check stays: unprotected unicast only.
        let mut legacy = header(0xc0, OWN, AP, AP);
        legacy.extend_from_slice(&[7, 0]);
        let packet = envelope(&legacy, 3);
        let mpdu = scan_api::mpdu_gen2(&packet).ok_or("legacy deauth envelope")?;
        let mut rx = PmfRx::default();
        if !ap_disconnected(&mpdu, OWN, AP, 1, None)
            || ap_disconnected(&mpdu, OWN, AP, 1, Some(&mut rx))
        {
            return Err("PMF did not drop unprotected unicast deauthentication");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/pmf",
    smoke_gen2_pmf_not_granted_paths_refuse_and_wire_layouts
);

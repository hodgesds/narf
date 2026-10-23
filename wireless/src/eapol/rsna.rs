//! The RSN supplicant's pairwise side for the AKMs NARF drives (PSK,
//! PSK-SHA256, SAE): wpa_supplicant `wpa_sm_rx_eapol` →
//! `wpa_supplicant_process_1_of_4` / `_3_of_4` (hostap
//! `src/rsn_supp/wpa.c`) with the AKM rules of `src/common/wpa_common.c`
//! (`wpa_pmk_to_ptk`, `wpa_eapol_key_mic`) and the Key Data parse of
//! `wpa_parse_kde_ies`.
//!
//! A 4-way handshake may run at any time after the first one: an M1
//! while associated is a PTK rekey (`sm->tptk` derived, M2 with the
//! Secure bit, the new PTK takes over when M3's MIC verifies with it,
//! `wpa_sm_tptk_to_ptk`). The `installed` flag makes a retransmitted M3
//! answer without reinstalling the key (KRACK, `wpa_supplicant_install_ptk`
//! "Do not re-install same PTK to the driver").
//!
//! Not modelled (no NARF caller): WPA1, TKIP / GCMP, FT, FILS, OWE,
//! DPP, OCV, MLO, Extended Key ID, PMKSA caching (the PMK is given).

use alloc::vec::Vec;

use super::{
    eapol_key_mic, EapolHeader, EapolType, FourWayState, GroupKeyDrop, GroupKeyFail, GroupKeyM1,
    Gtk, Igtk, KeyFrame, Ptk, Supplicant, KEY_DESCRIPTOR_RSN, KI_ENCRYPTED_KEY_DATA, KI_INSTALL,
    KI_KEY_INDEX_MASK, KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE, KI_SECURE, KI_VERSION_AES_128_CMAC,
    KI_VERSION_HMAC_MD5_RC4, KI_VERSION_HMAC_SHA1_AES, WPAS_EAPOL_VERSION, WPA_GTK_MAX_LEN,
    WPA_IGTK_KDE_PREFIX_LEN,
};

/// `WPA_KEY_INFO_TYPE_AKM_DEFINED`.
pub const KI_VERSION_AKM_DEFINED: u16 = 0;
/// `WLAN_REASON_IE_IN_4WAY_DIFFERS`.
pub const WLAN_REASON_IE_IN_4WAY_DIFFERS: u16 = 17;
/// `WLAN_REASON_UNSPECIFIED`.
pub const WLAN_REASON_UNSPECIFIED: u16 = 1;
/// `WLAN_EID_RSN` / `WLAN_EID_RSNX`.
const EID_RSN: u8 = 48;
const EID_RSNX: u8 = 244;
/// `RSN_KEY_DATA_GROUPKEY` / `_IGTK` / `_PMKID` selectors.
const KDE_GROUPKEY: [u8; 4] = [0x00, 0x0F, 0xAC, 1];
const KDE_IGTK: [u8; 4] = [0x00, 0x0F, 0xAC, 9];
const KDE_PMKID: [u8; 4] = [0x00, 0x0F, 0xAC, 4];

/// `WPA_KEY_MGMT_*` of the negotiated AKM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyMgmt {
    /// AKM 00-0F-AC:2 (`WPA_KEY_MGMT_PSK`).
    Psk,
    /// AKM 00-0F-AC:6 (`WPA_KEY_MGMT_PSK_SHA256`).
    PskSha256,
    /// AKM 00-0F-AC:8 (`WPA_KEY_MGMT_SAE`).
    Sae,
}

impl KeyMgmt {
    /// The AKM suite type (00-0F-AC:`n`).
    pub const fn suite_type(self) -> u8 {
        match self {
            KeyMgmt::Psk => 2,
            KeyMgmt::PskSha256 => 6,
            KeyMgmt::Sae => 8,
        }
    }

    /// From an AKM suite type.
    pub const fn from_suite_type(t: u8) -> Option<Self> {
        match t {
            2 => Some(KeyMgmt::Psk),
            6 => Some(KeyMgmt::PskSha256),
            8 => Some(KeyMgmt::Sae),
            _ => None,
        }
    }

    /// `wpa_key_mgmt_sha256`: PRF / KDF over SHA-256.
    pub const fn sha256(self) -> bool {
        !matches!(self, KeyMgmt::Psk)
    }

    /// `wpa_use_akm_defined`: Key Descriptor Version 0.
    pub const fn akm_defined(self) -> bool {
        matches!(self, KeyMgmt::Sae)
    }

    /// `wpa_mic_len` (16 for all three; IEEE 802.11-2020 Table 12-11).
    pub const fn mic_len(self) -> usize {
        16
    }

    /// `wpa_kck_len` / `wpa_kek_len` (16 / 16).
    pub const fn kck_len(self) -> usize {
        16
    }
    pub const fn kek_len(self) -> usize {
        16
    }

    /// The Key Descriptor Version an authenticator uses with a CCMP
    /// pairwise cipher (hostapd `wpa_auth` `version` choice): 0 for an
    /// AKM-defined suite, 3 for the SHA-256 AKMs, 2 for PSK.
    pub const fn key_info_version(self) -> u16 {
        match self {
            KeyMgmt::Sae => KI_VERSION_AKM_DEFINED,
            KeyMgmt::PskSha256 => KI_VERSION_AES_128_CMAC,
            KeyMgmt::Psk => KI_VERSION_HMAC_SHA1_AES,
        }
    }
}

/// `wpa_sm_rx_eapol`'s Key Descriptor Version checks for a CCMP
/// pairwise cipher: PSK accepts 2 and, by the interoperability
/// workaround, 3; the SHA-256 AKMs need 3; SAE needs 0 (AKM-defined).
pub fn key_ver_allowed(km: KeyMgmt, ver: u16) -> bool {
    if ver != KI_VERSION_HMAC_MD5_RC4
        && ver != KI_VERSION_AES_128_CMAC
        && ver != KI_VERSION_HMAC_SHA1_AES
        && !km.akm_defined()
    {
        return false;
    }
    // RC4 needs TKIP pairwise (not supported).
    if ver == KI_VERSION_HMAC_MD5_RC4 {
        return false;
    }
    if ver == KI_VERSION_HMAC_SHA1_AES && km != KeyMgmt::Psk {
        return false;
    }
    if km.akm_defined() && ver != KI_VERSION_AKM_DEFINED {
        return false;
    }
    if km.sha256() {
        return ver == KI_VERSION_AES_128_CMAC || km.akm_defined();
    }
    // CCMP, not AKM-defined: 2, or 3 ("allow incorrect … but stronger").
    ver == KI_VERSION_HMAC_SHA1_AES || ver == KI_VERSION_AES_128_CMAC
}

/// `wpa_eapol_key_mic` for `km`: version 2 = HMAC-SHA1-128, 3 =
/// AES-128-CMAC, 0 (AKM-defined) with SAE = AES-128-CMAC.
pub fn wpa_eapol_key_mic(km: KeyMgmt, ver: u16, kck: &[u8], pdu: &[u8]) -> Option<Vec<u8>> {
    match ver {
        KI_VERSION_AKM_DEFINED if km == KeyMgmt::Sae => {
            eapol_key_mic(KI_VERSION_AES_128_CMAC, kck, pdu, km.mic_len())
        }
        KI_VERSION_HMAC_SHA1_AES | KI_VERSION_AES_128_CMAC => {
            eapol_key_mic(ver, kck, pdu, km.mic_len())
        }
        _ => None,
    }
}

/// `wpa_pmk_to_ptk(pmk, "Pairwise key expansion", own, aa, snonce,
/// anonce, …)`: `min(AA,SA) || max(AA,SA) || min(nonces) || max(nonces)`
/// through PRF-SHA1 (PSK) or `sha256_prf` (PSK-SHA256, SAE), split KCK
/// (16) || KEK (16) || TK (`tk_len`).
pub fn wpa_pmk_to_ptk(
    km: KeyMgmt,
    pmk: &[u8],
    aa: &[u8; 6],
    sa: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    tk_len: usize,
) -> Ptk {
    if !km.sha256() {
        return super::derive_ptk(&HmacSha1, pmk, aa, sa, anonce, snonce, tk_len);
    }
    let mut data = Vec::with_capacity(76);
    let (a1, a2) = if aa < sa { (aa, sa) } else { (sa, aa) };
    data.extend_from_slice(a1);
    data.extend_from_slice(a2);
    let (n1, n2) = if anonce < snonce {
        (anonce, snonce)
    } else {
        (snonce, anonce)
    };
    data.extend_from_slice(n1);
    data.extend_from_slice(n2);
    let (kck, kek) = (km.kck_len(), km.kek_len());
    let b =
        crate::sae::session::kdf_sha256(pmk, b"Pairwise key expansion", &data, kck + kek + tk_len);
    Ptk {
        kck: b[..kck].to_vec(),
        kek: b[kck..kck + kek].to_vec(),
        tk: b[kck + kek..].to_vec(),
    }
}

struct HmacSha1;
impl super::HmacPrimitive for HmacSha1 {
    fn out_len(&self) -> usize {
        20
    }
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
    }
}

/// What the supplicant was configured with for this association
/// (`wpa_sm_set_param` / `wpa_sm_set_assoc_wpa_ie` /
/// `wpa_sm_set_ap_rsn_ie` / `wpa_sm_set_pmk`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsnaParams {
    pub key_mgmt: KeyMgmt,
    /// The PMK (PSK / SAE).
    pub pmk: Vec<u8>,
    /// Our RSNE, then our RSNXE when sent (`sm->assoc_wpa_ie`,
    /// `sm->assoc_rsnxe`): the Key Data of message 2/4.
    pub assoc_ie: Vec<u8>,
    /// The AP's RSNE / RSNXE elements from its Beacon / Probe Response
    /// (`sm->ap_rsn_ie`, `sm->ap_rsnxe`), checked against message 3/4.
    pub ap_rsn_ie: Vec<u8>,
    pub ap_rsnxe: Option<Vec<u8>>,
    /// `wpa_cipher_key_len(pairwise / group)`.
    pub pairwise_key_len: usize,
    pub group_key_len: usize,
    /// `wpa_cipher_key_len(mgmt_group_cipher)` when PMF is negotiated
    /// (`sm->mgmt_group_cipher` valid), else `None`.
    pub mgmt_group_key_len: Option<usize>,
    /// `wpa_sm_pmf_enabled`.
    pub pmf: bool,
}

/// Message 1/4 processed: send `reply` (2/4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairwiseM1 {
    pub reply: Vec<u8>,
    /// An M1 after a PTK was already in place (`sm->ptk_set`): a rekey.
    pub rekey: bool,
}

/// Message 3/4 processed: send `reply` (4/4), then install `tk`
/// (`Some` when Install is set and this PTK is not installed yet; then
/// call [`Supplicant::pairwise_key_installed`]), the GTK, the IGTK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairwiseM3 {
    pub reply: Vec<u8>,
    pub tk: Option<Vec<u8>>,
    /// `None` = the GTK in use ("Not reinstalling already in-use GTK").
    pub gtk: Option<Gtk>,
    /// `None` = no IGTK sent / PMF off / already in use.
    pub igtk: Option<Igtk>,
    /// The Secure bit (`wpa_supplicant_key_neg_complete(.., secure)`).
    pub secure: bool,
}

/// A processed EAPOL-Key frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EapolRx {
    Pairwise1(PairwiseM1),
    Pairwise3(PairwiseM3),
    Group1(GroupKeyM1),
}

/// Why message 3/4 failed (`goto failed` → `wpa_sm_deauthenticate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairwiseFail {
    /// `wpa_supplicant_parse_ies` failed.
    KeyData,
    /// "GTK IE in unencrypted key data" / "IGTK KDE in unencrypted key data".
    UnencryptedKde,
    /// "Invalid GTK KDE length".
    GtkKdeLength,
    /// "Invalid IGTK KDE length".
    IgtkKdeLength,
    /// "IE in 3/4 msg does not match with IE in Beacon/ProbeResp".
    RsnIeMismatch,
    /// "RSNXE mismatch between Beacon/ProbeResp and EAPOL-Key msg 3/4".
    RsnxeMismatch,
    /// "Non-zero Extended Key ID Key ID in PTK0 handshake".
    KeyId,
    /// "ANonce from message 1 … differs from 3".
    ANonce,
    /// "Invalid CCMP key length".
    KeyLength,
    /// "No GTK KDE included in EAPOL-Key msg 3/4".
    NoGtk,
    /// `wpa_supplicant_check_group_cipher`.
    GtkCipherLength,
    /// `ieee80211w_set_keys` / `wpa_supplicant_install_igtk` failed.
    Igtk,
}

/// Why an EAPOL-Key frame was not processed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EapolRxError {
    /// A new SNonce was required, but the trusted nonce provider failed.
    /// No new nonce or message1 key state was committed; abort the operation.
    NonceUnavailable,
    /// Dropped (`goto out` / the discard returns); the association stays.
    Drop(GroupKeyDrop),
    /// A 4-way handshake failure: deauthenticate with `reason`.
    Pairwise { reason: u16, why: PairwiseFail },
    /// A Group Key message 1/2 failure (deauthenticate, reason 1).
    Group(GroupKeyFail),
}

/// `struct wpa_eapol_ie_parse` (the parts used here).
#[derive(Default)]
struct KdeIes<'a> {
    rsn_ie: Option<&'a [u8]>,
    rsnxe: Option<&'a [u8]>,
    gtk: Option<&'a [u8]>,
    igtk: Option<&'a [u8]>,
    key_id: Option<&'a [u8]>,
}

/// `wpa_parse_kde_ies` + `wpa_parse_generic`: elements (later ones win)
/// and the KDEs; `Err` on a Key Data underflow.
fn parse_kde_ies(buf: &[u8]) -> Result<KdeIes<'_>, ()> {
    let mut ie = KdeIes::default();
    let mut pos = 0usize;
    while buf.len() - pos > 1 {
        if buf[pos] == 0xdd && (pos == buf.len() - 1 || buf[pos + 1] == 0) {
            break;
        }
        let dlen = 2 + buf[pos + 1] as usize;
        if dlen > buf.len() - pos {
            return Err(());
        }
        let e = &buf[pos..pos + dlen];
        match e[0] {
            EID_RSN => ie.rsn_ie = Some(e),
            EID_RSNX => ie.rsnxe = Some(e),
            0xdd if e[1] as usize > 4 => {
                let sel = &e[2..6];
                let data = &e[6..];
                if e[1] as usize > 4 + 2 && sel == KDE_GROUPKEY {
                    ie.gtk = Some(data);
                } else if e[1] as usize > 4 + 2 && sel == KDE_IGTK {
                    ie.igtk = Some(data);
                } else if sel == [0x00, 0x0F, 0xAC, 13] && !data.is_empty() {
                    // RSN_KEY_DATA_KEYID
                    ie.key_id = Some(data);
                } else if sel == KDE_PMKID {
                    // PMKID: the SAE / PSK PMK is used regardless
                    // (wpa_supplicant_get_pmk keeps sm->pmk).
                }
            }
            _ => {}
        }
        pos += dlen;
    }
    Ok(ie)
}

/// The front half of `wpa_sm_rx_eapol` shared by every EAPOL-Key frame:
/// length / type / descriptor / replay / flag / version checks, the
/// MIC (with the TPTK first, then the PTK: `wpa_supplicant_verify_eapol_key_mic`)
/// and the Key Data decryption.
pub(super) struct Front {
    pub tmp: Vec<u8>,
    pub key_info: u16,
    pub ver: u16,
    pub replay_counter: u64,
    pub key_data: Vec<u8>,
}

impl Supplicant {
    /// Configure the association (`wpa_sm_set_param` … before the first
    /// EAPOL-Key frame); the SNonce is renewed on the first M1
    /// (`wpa_sm_notify_assoc` sets `renew_snonce`).
    pub fn with_rsna(mut self, p: RsnaParams) -> Self {
        self.key_mgmt = p.key_mgmt;
        self.rsna = Some(p);
        self.renew_snonce = true;
        self
    }

    /// The negotiated AKM.
    pub fn key_mgmt(&self) -> KeyMgmt {
        self.key_mgmt
    }

    /// The driver accepted the TK of the last message 3/4 (`sm->ptk.installed`).
    pub fn pairwise_key_installed(&mut self) {
        self.ptk_installed = true;
    }

    pub(super) fn front(&mut self, pdu: &[u8]) -> Result<Front, GroupKeyDrop> {
        use GroupKeyDrop as D;
        let mic_len = self.key_mgmt.mic_len();
        let keyhdrlen = 77 + mic_len + 2;
        if pdu.len() < 4 + keyhdrlen {
            return Err(D::TooShort);
        }
        let plen = u16::from_be_bytes([pdu[2], pdu[3]]) as usize;
        if pdu[1] != EapolType::EapolKey as u8 {
            return Err(D::NotKey);
        }
        if plen > pdu.len() - 4 || plen < keyhdrlen {
            return Err(D::BadLength);
        }
        let mut tmp = pdu[..4 + plen].to_vec();
        let body = 4;
        if tmp[body] != KEY_DESCRIPTOR_RSN && tmp[body] != super::KEY_DESCRIPTOR_WPA_LEGACY {
            return Err(D::BadDescriptor);
        }
        let mic_off = body + 77;
        let kdl_off = mic_off + mic_len;
        let mut key_data_len = u16::from_be_bytes([tmp[kdl_off], tmp[kdl_off + 1]]) as usize;
        if key_data_len > plen - keyhdrlen {
            return Err(D::KeyDataOverflow);
        }
        let mut rc = [0u8; 8];
        rc.copy_from_slice(&tmp[body + 5..body + 13]);
        let replay_counter = u64::from_be_bytes(rc);
        if self.rx_replay_counter_set && replay_counter <= self.last_replay_counter {
            return Err(D::Replay);
        }
        let key_info = u16::from_be_bytes([tmp[body + 1], tmp[body + 2]]);
        if key_info & super::KI_SMK_MESSAGE != 0 {
            return Err(D::Smk);
        }
        if key_info & super::KI_KEY_ACK == 0 {
            return Err(D::NoAck);
        }
        if key_info & super::KI_REQUEST != 0 {
            return Err(D::Request);
        }
        if tmp[body] != KEY_DESCRIPTOR_RSN {
            return Err(D::BadDescriptor);
        }
        let ver = key_info & super::KI_VERSION_MASK;
        if !key_ver_allowed(self.key_mgmt, ver) {
            return Err(D::BadVersion);
        }
        if key_info & KI_KEY_MIC != 0 {
            let got = tmp[mic_off..mic_off + mic_len].to_vec();
            tmp[mic_off..mic_off + mic_len].fill(0);
            let km = self.key_mgmt;
            let ok_with =
                |p: &Ptk| wpa_eapol_key_mic(km, ver, &p.kck, &tmp).is_some_and(|m| m == got);
            let mut ok = false;
            if self.tptk.as_ref().is_some_and(ok_with) {
                // wpa_sm_tptk_to_ptk
                self.ptk = self.tptk.take();
                self.ptk_installed = false;
                self.renew_snonce = true;
                ok = true;
            }
            if !ok && self.ptk.as_ref().is_some_and(ok_with) {
                ok = true;
            }
            if !ok {
                return Err(D::BadMic);
            }
            tmp[mic_off..mic_off + mic_len].copy_from_slice(&got);
            self.last_replay_counter = replay_counter;
            self.rx_replay_counter_set = true;
        }
        let kd_off = kdl_off + 2;
        let mut key_data = tmp[kd_off..kd_off + key_data_len].to_vec();
        if key_info & KI_ENCRYPTED_KEY_DATA != 0 {
            if key_info & KI_KEY_MIC == 0 {
                return Err(D::EncryptedUnauthenticated);
            }
            let Some(ptk) = self.ptk.as_ref() else {
                return Err(D::Decrypt);
            };
            if key_data_len < 8 || key_data_len % 8 != 0 {
                return Err(D::Decrypt);
            }
            key_data_len -= 8;
            let kek: Option<&[u8; 16]> = ptk.kek.as_slice().try_into().ok();
            match kek.and_then(|k| narf_crypto::aes_kw::aes_unwrap(k, &key_data)) {
                Some(k) if k.len() == key_data_len => key_data = k,
                _ => return Err(D::Decrypt),
            }
        }
        Ok(Front {
            tmp,
            key_info,
            ver,
            replay_counter,
            key_data,
        })
    }

    /// wpa_supplicant `wpa_sm_rx_eapol` for any EAPOL-Key frame (`pdu` =
    /// 802.1X header + body) of a [`Self::with_rsna`] association:
    /// message 1/4 (also a PTK rekey while associated), 3/4, or Group
    /// Key message 1/2. `encrypted` says the frame arrived protected
    /// (`enum frame_encryption`); `fresh_snonce` is used when the SNonce
    /// must be renewed (`sm->renew_snonce`: the first M1, and the first
    /// M1 after a completed 4-way handshake).
    pub fn rx_eapol(
        &mut self,
        pdu: &[u8],
        encrypted: bool,
        fresh_snonce: [u8; 32],
    ) -> Result<EapolRx, EapolRxError> {
        self.rx_eapol_with_nonce(pdu, encrypted, || Some(fresh_snonce))
    }

    /// As rx_eapol, obtaining entropy only at an actual new-SNonce
    /// consumption point. The provider runs after the existing native EAPOL
    /// validation and message1 KDE/PMF checks, only while renew_snonce is set.
    /// Message1 retries, message3, group rekeys and discarded traffic never
    /// request fresh material. None fails before nonce/key-state mutation.
    pub fn rx_eapol_with_nonce(
        &mut self,
        pdu: &[u8],
        encrypted: bool,
        fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<EapolRx, EapolRxError> {
        if self.rsna.is_none() {
            // "No SSID info found"
            return Err(EapolRxError::Drop(GroupKeyDrop::NotKey));
        }
        let f = self.front(pdu).map_err(EapolRxError::Drop)?;
        if f.key_info & KI_KEY_TYPE_PAIRWISE != 0 {
            if f.key_info & KI_KEY_INDEX_MASK != 0 {
                // "Ignored EAPOL-Key (Pairwise) with non-zero key index"
                return Err(EapolRxError::Drop(GroupKeyDrop::Pairwise));
            }
            if f.key_info & (KI_KEY_MIC | KI_ENCRYPTED_KEY_DATA) != 0 {
                self.process_3_of_4(&f).map(EapolRx::Pairwise3)
            } else {
                self.process_1_of_4(&f, encrypted, fresh_snonce)
                    .map(EapolRx::Pairwise1)
            }
        } else if f.key_info & KI_KEY_MIC != 0 {
            let r = self.rsna.as_ref().unwrap();
            let (gl, ml) = (r.group_key_len, r.mgmt_group_key_len);
            self.process_1_of_2(&f, gl, ml)
                .map(EapolRx::Group1)
                .map_err(|e| match e {
                    super::GroupKeyError::Drop(d) => EapolRxError::Drop(d),
                    super::GroupKeyError::Fail(g) => EapolRxError::Group(g),
                })
        } else {
            // "EAPOL-Key (Group) without Mic/Encr bit - dropped"
            Err(EapolRxError::Drop(GroupKeyDrop::NoMic))
        }
    }

    /// The 802.1X header + an EAPOL-Key body with its MIC.
    fn build_reply(&self, k: KeyFrame, ver: u16, kck: &[u8]) -> Vec<u8> {
        let body = k.encode();
        let mut out = Vec::with_capacity(4 + body.len());
        EapolHeader {
            version: WPAS_EAPOL_VERSION,
            packet_type: EapolType::EapolKey as u8,
            body_length: body.len() as u16,
        }
        .encode(&mut out);
        out.extend_from_slice(&body);
        let mic_len = self.key_mgmt.mic_len();
        if let Some(m) = wpa_eapol_key_mic(self.key_mgmt, ver, kck, &out) {
            out[4 + 77..4 + 77 + mic_len].copy_from_slice(&m);
        }
        out
    }

    /// `wpa_supplicant_process_1_of_4` + `wpa_supplicant_send_2_of_4`.
    fn process_1_of_4(
        &mut self,
        f: &Front,
        encrypted: bool,
        mut fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<PairwiseM1, EapolRxError> {
        let r = self.rsna.clone().unwrap();
        if !encrypted && self.ptk_installed && r.pmf {
            // "Discard unencrypted EAPOL-Key msg 1/4 when TK is set and
            // PMF is enabled"
            return Err(EapolRxError::Drop(GroupKeyDrop::Unencrypted));
        }
        if parse_kde_ies(&f.key_data).is_err() {
            // "Discard EAPOL-Key msg 1/4 with invalid IEs/KDEs"
            return Err(EapolRxError::Drop(GroupKeyDrop::KeyData));
        }
        if self.renew_snonce {
            self.snonce = fresh_snonce().ok_or(EapolRxError::NonceUnavailable)?;
            self.renew_snonce = false;
        }
        let mut anonce = [0u8; 32];
        anonce.copy_from_slice(&f.tmp[4 + 13..4 + 45]);
        let tptk = wpa_pmk_to_ptk(
            r.key_mgmt,
            &r.pmk,
            &self.aa,
            &self.sa,
            &anonce,
            &self.snonce,
            r.pairwise_key_len,
        );
        let rekey = self.ptk.is_some();
        let mut m2 = KeyFrame::empty(r.key_mgmt.mic_len());
        m2.descriptor_type = KEY_DESCRIPTOR_RSN;
        m2.key_information =
            f.ver | KI_KEY_TYPE_PAIRWISE | if rekey { KI_SECURE } else { 0 } | KI_KEY_MIC;
        m2.key_length = 0;
        m2.replay_counter = f.replay_counter;
        m2.key_nonce = self.snonce;
        m2.key_data = r.assoc_ie.clone();
        let reply = self.build_reply(m2, f.ver, &tptk.kck);
        self.tptk = Some(tptk);
        self.anonce = anonce;
        self.state = FourWayState::WaitM3;
        Ok(PairwiseM1 { reply, rekey })
    }

    /// `wpa_supplicant_process_3_of_4` (+ `wpa_supplicant_validate_ie`,
    /// `wpa_supplicant_send_4_of_4`, `wpa_supplicant_pairwise_gtk`,
    /// `ieee80211w_set_keys`).
    fn process_3_of_4(&mut self, f: &Front) -> Result<PairwiseM3, EapolRxError> {
        let r = self.rsna.clone().unwrap();
        let fail = |why| EapolRxError::Pairwise {
            reason: WLAN_REASON_UNSPECIFIED,
            why,
        };
        let ie = parse_kde_ies(&f.key_data).map_err(|_| fail(PairwiseFail::KeyData))?;
        let encr = f.key_info & KI_ENCRYPTED_KEY_DATA != 0;
        if ie.gtk.is_some() && !encr {
            return Err(fail(PairwiseFail::UnencryptedKde));
        }
        if let Some(g) = ie.gtk {
            if g.len() < 2 || g.len() - 2 > WPA_GTK_MAX_LEN {
                return Err(fail(PairwiseFail::GtkKdeLength));
            }
        }
        if ie.igtk.is_some() && !encr {
            return Err(fail(PairwiseFail::UnencryptedKde));
        }
        if let (Some(i), Some(ml)) = (ie.igtk, r.mgmt_group_key_len) {
            if i.len() != WPA_IGTK_KDE_PREFIX_LEN + ml {
                return Err(fail(PairwiseFail::IgtkKdeLength));
            }
        }
        // wpa_supplicant_validate_ie (wpa_compare_rsn_ie without FT is an
        // exact compare).
        let ie_differs = |why| EapolRxError::Pairwise {
            reason: WLAN_REASON_IE_IN_4WAY_DIFFERS,
            why,
        };
        match ie.rsn_ie {
            None => return Err(ie_differs(PairwiseFail::RsnIeMismatch)),
            Some(m3) if m3 != &r.ap_rsn_ie[..] => {
                return Err(ie_differs(PairwiseFail::RsnIeMismatch))
            }
            _ => {}
        }
        if ie.rsnxe != r.ap_rsnxe.as_deref() {
            return Err(ie_differs(PairwiseFail::RsnxeMismatch));
        }
        // wpa_handle_ext_key_id (Extended Key ID not enabled).
        if ie.key_id.is_some_and(|k| k[0] & 0x03 != 0) {
            return Err(fail(PairwiseFail::KeyId));
        }
        if f.tmp[4 + 13..4 + 45] != self.anonce {
            return Err(fail(PairwiseFail::ANonce));
        }
        let keylen = u16::from_be_bytes([f.tmp[4 + 3], f.tmp[4 + 4]]) as usize;
        if keylen != r.pairwise_key_len {
            return Err(fail(PairwiseFail::KeyLength));
        }
        // MIC verified with this PTK in `front` (a fresh TPTK became the
        // PTK); without one there is nothing to answer with.
        let Some(ptk) = self.ptk.clone() else {
            return Err(EapolRxError::Drop(GroupKeyDrop::BadMic));
        };
        let mut m4 = KeyFrame::empty(r.key_mgmt.mic_len());
        m4.descriptor_type = KEY_DESCRIPTOR_RSN;
        m4.key_information = (f.key_info & KI_SECURE) | f.ver | KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC;
        m4.key_length = 0;
        m4.replay_counter = f.replay_counter;
        let reply = self.build_reply(m4, f.ver, &ptk.kck);
        self.renew_snonce = true;
        let tk = (f.key_info & KI_INSTALL != 0 && !self.ptk_installed).then(|| ptk.tk.clone());
        self.state = FourWayState::PtkDone;
        // wpa_supplicant_pairwise_gtk
        let Some(g) = ie.gtk else {
            return Err(fail(PairwiseFail::NoGtk));
        };
        if g.len() - 2 != r.group_key_len {
            return Err(fail(PairwiseFail::GtkCipherLength));
        }
        let mut rsc = [0u8; 8];
        rsc.copy_from_slice(&f.tmp[4 + 61..4 + 69]);
        let new_gtk = Gtk {
            key_id: g[0] & 0x3,
            // wpa_supplicant_gtk_tx_bit_workaround: pairwise key in use.
            tx: false,
            key: g[2..].to_vec(),
            rsc,
        };
        let gtk = (self.gtk.as_deref() != Some(&new_gtk.key[..])).then_some(new_gtk);
        // ieee80211w_set_keys → wpa_supplicant_install_igtk
        let mut igtk = None;
        if let (Some(i), Some(_)) = (ie.igtk, r.mgmt_group_key_len) {
            let key_id = u16::from_le_bytes([i[0], i[1]]);
            let key = i[8..].to_vec();
            if self.igtk.as_deref() != Some(&key[..]) {
                if key_id > 4095 {
                    return Err(fail(PairwiseFail::Igtk));
                }
                let mut ipn = [0u8; 6];
                ipn.copy_from_slice(&i[2..8]);
                igtk = Some(Igtk { key_id, ipn, key });
            }
        }
        Ok(PairwiseM3 {
            reply,
            tk,
            gtk,
            igtk,
            secure: f.key_info & KI_SECURE != 0,
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod rsna_tests {
    use super::super::*;
    use super::*;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const AA: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    const SA: [u8; 6] = [0x00, 0x03, 0x7F, 0x12, 0x34, 0x56];
    const ANONCE: [u8; 32] = [0x11; 32];
    const SNONCE: [u8; 32] = [0x22; 32];
    /// The IEEE 802.11-2020 Annex J.10 SAE PMK.
    const SAE_PMK: [u8; 32] = [
        0x4e, 0x4d, 0xfa, 0xb1, 0xa2, 0xdd, 0x8a, 0xc1, 0xa9, 0x17, 0x90, 0xf9, 0x53, 0xfa, 0xaa,
        0x45, 0x2a, 0xe5, 0xc6, 0x87, 0x3a, 0xb7, 0x5b, 0x63, 0x60, 0x5b, 0xa6, 0x63, 0xf8, 0xa7,
        0xfe, 0x59,
    ];
    /// AP RSNE: group CCMP, CCMP, AKM SAE, MFPC | MFPR (0x00cc).
    const AP_RSNE: [u8; 22] = [
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01,
        0x00, 0x00, 0x0F, 0xAC, 0x08, 0xCC, 0x00,
    ];
    /// RSNXE: field length 0 | SAE H2E (bit 5).
    const RSNXE: [u8; 3] = [0xF4, 0x01, 0x20];
    const GTK: [u8; 16] = [0x7C; 16];
    const IGTK: [u8; 16] = [0x9E; 16];

    fn params() -> RsnaParams {
        let mut assoc = AP_RSNE.to_vec();
        assoc.extend_from_slice(&RSNXE);
        RsnaParams {
            key_mgmt: KeyMgmt::Sae,
            pmk: SAE_PMK.to_vec(),
            assoc_ie: assoc,
            ap_rsn_ie: AP_RSNE.to_vec(),
            ap_rsnxe: Some(RSNXE.to_vec()),
            pairwise_key_len: 16,
            group_key_len: 16,
            mgmt_group_key_len: Some(16),
            pmf: true,
        }
    }

    fn sup() -> Supplicant {
        Supplicant::new(AA, SA, [0; 32]).with_rsna(params())
    }

    /// hostapd-side EAPOL-Key frame: Key Info `ki`, replay counter,
    /// ANonce, Key Data wrapped with `kek` when Encrypted Key Data (padded
    /// `dd 00…` to 8 / at least 16), MIC with `kck` when Key MIC.
    fn ap_frame(ki: u16, rc: u64, nonce: [u8; 32], kd: &[u8], ptk: Option<&Ptk>) -> Vec<u8> {
        let mut k = KeyFrame::empty(16);
        k.key_information = ki;
        k.key_length = 16;
        k.replay_counter = rc;
        k.key_nonce = nonce;
        k.key_data = if ki & KI_ENCRYPTED_KEY_DATA != 0 {
            let mut d = kd.to_vec();
            if d.len() % 8 != 0 || d.len() < 16 {
                d.push(0xDD);
                while d.len() % 8 != 0 || d.len() < 16 {
                    d.push(0);
                }
            }
            let kek: [u8; 16] = ptk.unwrap().kek.as_slice().try_into().unwrap();
            narf_crypto::aes_kw::aes_wrap(&kek, &d).unwrap()
        } else {
            kd.to_vec()
        };
        let mut b = k.into_eapol();
        b[0] = 2; // hostapd eapol_version 2
        if ki & KI_KEY_MIC != 0 {
            let p = ptk.unwrap();
            let m = narf_crypto::cmac_aes128::cmac_aes128(p.kck.as_slice().try_into().unwrap(), &b);
            b[81..97].copy_from_slice(&m);
        }
        b
    }

    fn m3_kd(rsne: &[u8], rsnxe: Option<&[u8]>, igtk_kde: bool) -> Vec<u8> {
        let mut kd = rsne.to_vec();
        if let Some(x) = rsnxe {
            kd.extend_from_slice(x);
        }
        kd.extend_from_slice(&[0xDD, 22, 0x00, 0x0F, 0xAC, 0x01, 0x01, 0x00]);
        kd.extend_from_slice(&GTK);
        if igtk_kde {
            kd.extend_from_slice(&[0xDD, 28, 0x00, 0x0F, 0xAC, 0x09, 0x04, 0x00]);
            kd.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
            kd.extend_from_slice(&IGTK);
        }
        kd
    }

    /// M1 (SAE, ver 0): Pairwise | Ack.
    const M1_KI: u16 = 0x0088;
    /// M3 (SAE, ver 0): Pairwise | Install | Ack | MIC | Secure | Encr.
    const M3_KI: u16 = 0x13C8;

    fn ptk_of(anonce: [u8; 32], snonce: [u8; 32]) -> Ptk {
        wpa_pmk_to_ptk(KeyMgmt::Sae, &SAE_PMK, &AA, &SA, &anonce, &snonce, 16)
    }

    /// `wpa_sm_rx_eapol`'s descriptor-version table for CCMP, and the
    /// AKM-8 PTK through `sha256_prf` against an outside computation
    /// (`openssl mac -digest SHA256 … HMAC` over
    /// `01 00 || "Pairwise key expansion" || SA || AA || ANonce || SNonce
    /// || 80 01`, then `02 00 …`).
    fn smoke_eapol_akm_rules_and_sha256_ptk() -> TestResult {
        let table = [
            (KeyMgmt::Psk, [false, false, true, true]),
            (KeyMgmt::PskSha256, [false, false, false, true]),
            (KeyMgmt::Sae, [true, false, false, false]),
        ];
        for (km, want) in table {
            for (ver, &w) in want.iter().enumerate() {
                if key_ver_allowed(km, ver as u16) != w {
                    return TestResult::Fail("descriptor version table");
                }
            }
        }
        let p = ptk_of(ANONCE, SNONCE);
        let want: [u8; 48] = [
            0xFF, 0x66, 0x77, 0x2B, 0xC6, 0xFE, 0x53, 0x94, 0x89, 0xAE, 0xEB, 0x8D, 0x3D, 0x08,
            0x9D, 0x79, 0xE3, 0x0B, 0x7A, 0xC0, 0xB2, 0x9F, 0x02, 0x0F, 0x0E, 0x10, 0xAC, 0x26,
            0x2D, 0xD3, 0xD9, 0xB5, 0xB8, 0x3F, 0xAD, 0xD8, 0x1D, 0x76, 0xD1, 0x08, 0x44, 0xFF,
            0x34, 0x21, 0x79, 0x9E, 0x60, 0x26,
        ];
        if p.kck[..] != want[..16] || p.kek[..] != want[16..32] || p.tk[..] != want[32..] {
            return TestResult::Fail("AKM 8 PTK (KDF-SHA256)");
        }
        // PSK keeps PRF-SHA1.
        let psk = wpa_pmk_to_ptk(KeyMgmt::Psk, &SAE_PMK, &AA, &SA, &ANONCE, &SNONCE, 16);
        if psk.kck == p.kck {
            return TestResult::Fail("PSK must use PRF-SHA1");
        }
        // ver 0 MIC is AES-128-CMAC for SAE only.
        if wpa_eapol_key_mic(KeyMgmt::Sae, 0, &p.kck, b"x")
            != Some(
                narf_crypto::cmac_aes128::cmac_aes128(p.kck[..].try_into().unwrap(), b"x").to_vec(),
            )
            || wpa_eapol_key_mic(KeyMgmt::Psk, 0, &p.kck, b"x").is_some()
        {
            return TestResult::Fail("AKM-defined MIC");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_akm_rules_and_sha256_ptk);

    /// A full AKM-8 4-way handshake (descriptor version 0, AES-CMAC
    /// MICs): the M2 / M4 bytes wpa_supplicant `wpa_supplicant_send_2_of_4`
    /// / `_4_of_4` emit, the TK / GTK / IGTK from M3, then a PTK rekey
    /// (M1 while associated → M2 with Secure, new PTK only after M3's MIC
    /// verifies with it) and a retransmitted M3 that answers without a
    /// reinstall.
    fn smoke_eapol_sae_4way_and_ptk_rekey() -> TestResult {
        let mut s = sup();
        let m1 = ap_frame(M1_KI, 1, ANONCE, &[], None);
        let r = match s.rx_eapol(&m1, false, SNONCE) {
            Ok(EapolRx::Pairwise1(r)) => r,
            _ => return TestResult::Fail("M1"),
        };
        let p = ptk_of(ANONCE, SNONCE);
        // M2: 802.1X v1, type 3, len 95 + 25; RSN; Key Info = ver 0 |
        // Pairwise | MIC = 0x0108; Key Length 0; RC 1; SNonce; Key Data =
        // RSNE || RSNXE; AES-CMAC MIC.
        let mut g = vec![0x01, 0x03, 0x00, 95 + 25, 0x02, 0x01, 0x08, 0x00, 0x00];
        g.extend_from_slice(&1u64.to_be_bytes());
        g.extend_from_slice(&SNONCE);
        g.extend_from_slice(&[0u8; 16 + 8 + 8 + 16]);
        g.extend_from_slice(&[0x00, 25]);
        g.extend_from_slice(&params().assoc_ie);
        let mic = narf_crypto::cmac_aes128::cmac_aes128(p.kck[..].try_into().unwrap(), &g);
        g[81..97].copy_from_slice(&mic);
        if r.reply != g || r.rekey {
            return TestResult::Fail("M2 golden");
        }
        let m3 = ap_frame(
            M3_KI,
            2,
            ANONCE,
            &m3_kd(&AP_RSNE, Some(&RSNXE), true),
            Some(&p),
        );
        let r = match s.rx_eapol(&m3, false, [0x33; 32]) {
            Ok(EapolRx::Pairwise3(r)) => r,
            _ => return TestResult::Fail("M3"),
        };
        let mut g = vec![0x01, 0x03, 0x00, 95, 0x02, 0x03, 0x08, 0x00, 0x00];
        g.extend_from_slice(&2u64.to_be_bytes());
        g.extend_from_slice(&[0u8; 32 + 16 + 8 + 8 + 16 + 2]);
        let mic = narf_crypto::cmac_aes128::cmac_aes128(p.kck[..].try_into().unwrap(), &g);
        g[81..97].copy_from_slice(&mic);
        if r.reply != g || r.tk.as_deref() != Some(&p.tk[..]) || !r.secure {
            return TestResult::Fail("M4 golden / TK");
        }
        if r.gtk.as_ref().map(|g| (g.key_id, &g.key[..])) != Some((1, &GTK[..]))
            || r.igtk
                != Some(Igtk {
                    key_id: 4,
                    ipn: [1, 0, 0, 0, 0, 0],
                    key: IGTK.to_vec(),
                })
        {
            return TestResult::Fail("GTK / IGTK from M3");
        }
        s.pairwise_key_installed();
        s.group_keys_installed(Some(&GTK), Some(&IGTK));

        // Retransmitted M3 (RC 3): answered, no reinstall of TK / GTK / IGTK.
        let m3b = ap_frame(
            M3_KI,
            3,
            ANONCE,
            &m3_kd(&AP_RSNE, Some(&RSNXE), true),
            Some(&p),
        );
        match s.rx_eapol(&m3b, true, [0x33; 32]) {
            Ok(EapolRx::Pairwise3(r)) if r.tk.is_none() && r.gtk.is_none() && r.igtk.is_none() => {}
            _ => return TestResult::Fail("M3 retransmission reinstalled"),
        }
        // Unencrypted M1 after the TK with PMF: dropped.
        let anonce2 = [0x44; 32];
        let rk1 = ap_frame(M1_KI, 4, anonce2, &[], None);
        if s.rx_eapol(&rk1, false, [0x55; 32]) != Err(EapolRxError::Drop(GroupKeyDrop::Unencrypted))
        {
            return TestResult::Fail("unencrypted rekey M1 accepted");
        }
        // PTK rekey: M1 (encrypted) → M2 with Secure and the renewed SNonce.
        let r = match s.rx_eapol(&rk1, true, [0x55; 32]) {
            Ok(EapolRx::Pairwise1(r)) => r,
            _ => return TestResult::Fail("rekey M1"),
        };
        if !r.rekey
            || u16::from_be_bytes([r.reply[5], r.reply[6]]) != 0x0308
            || r.reply[17..49] != [0x55; 32]
        {
            return TestResult::Fail("rekey M2 (Secure, new SNonce)");
        }
        let p2 = ptk_of(anonce2, [0x55; 32]);
        // The old PTK stays in use until the rekey M3 verifies with the new one.
        if s.ptk.as_ref().map(|x| &x.tk) != Some(&p.tk) {
            return TestResult::Fail("PTK replaced before M3");
        }
        let m3 = ap_frame(
            M3_KI,
            5,
            anonce2,
            &m3_kd(&AP_RSNE, Some(&RSNXE), true),
            Some(&p2),
        );
        match s.rx_eapol(&m3, true, [0x66; 32]) {
            Ok(EapolRx::Pairwise3(r)) if r.tk.as_deref() == Some(&p2.tk[..]) && r.gtk.is_none() => {
            }
            _ => return TestResult::Fail("rekey M3 → new TK, same GTK kept"),
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_sae_4way_and_ptk_rekey);

    /// Negatives of `wpa_sm_rx_eapol` / `_process_3_of_4`: version 2
    /// under SAE dropped; M3 RSNE / RSNXE differing from the Beacon →
    /// reason 17; a changed ANonce, a bad IGTK KDE length → reason 1; a
    /// bad MIC dropped without advancing the replay counter.
    fn smoke_eapol_sae_4way_negatives() -> TestResult {
        let p = ptk_of(ANONCE, SNONCE);
        let after_m1 = || {
            let mut s = sup();
            let _ = s.rx_eapol(&ap_frame(M1_KI, 1, ANONCE, &[], None), false, SNONCE);
            s
        };
        if sup().rx_eapol(&ap_frame(0x008A, 1, ANONCE, &[], None), false, SNONCE)
            != Err(EapolRxError::Drop(GroupKeyDrop::BadVersion))
        {
            return TestResult::Fail("ver 2 under SAE accepted");
        }
        let check = |kd: Vec<u8>, nonce: [u8; 32], reason: u16, why: PairwiseFail| {
            let m3 = ap_frame(M3_KI, 2, nonce, &kd, Some(&p));
            after_m1().rx_eapol(&m3, false, SNONCE) == Err(EapolRxError::Pairwise { reason, why })
        };
        let mut rsne = AP_RSNE;
        rsne[20] = 0x80; // MFPC only
        if !check(
            m3_kd(&rsne, Some(&RSNXE), true),
            ANONCE,
            17,
            PairwiseFail::RsnIeMismatch,
        ) {
            return TestResult::Fail("RSNE mismatch");
        }
        if !check(
            m3_kd(&AP_RSNE, None, true),
            ANONCE,
            17,
            PairwiseFail::RsnxeMismatch,
        ) {
            return TestResult::Fail("RSNXE missing in M3");
        }
        if !check(
            m3_kd(&AP_RSNE, Some(&RSNXE), true),
            [0x12; 32],
            1,
            PairwiseFail::ANonce,
        ) {
            return TestResult::Fail("ANonce changed");
        }
        let mut kd = m3_kd(&AP_RSNE, Some(&RSNXE), false);
        kd.extend_from_slice(&[
            0xDD, 20, 0x00, 0x0F, 0xAC, 0x09, 0x04, 0x00, 1, 0, 0, 0, 0, 0,
        ]);
        kd.extend_from_slice(&[0x9E; 8]);
        if !check(kd, ANONCE, 1, PairwiseFail::IgtkKdeLength) {
            return TestResult::Fail("IGTK KDE length");
        }
        let mut s = after_m1();
        let mut bad = ap_frame(
            M3_KI,
            2,
            ANONCE,
            &m3_kd(&AP_RSNE, Some(&RSNXE), true),
            Some(&p),
        );
        bad[90] ^= 1;
        if s.rx_eapol(&bad, false, SNONCE) != Err(EapolRxError::Drop(GroupKeyDrop::BadMic))
            || s.rx_replay_counter_set
        {
            return TestResult::Fail("bad MIC");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_sae_4way_negatives);
    fn smoke_eapol_nonce_provider_is_lazy_at_actual_m1_renewal() -> TestResult {
        let mut s = sup();
        let mut calls = 0;
        let m1 = ap_frame(M1_KI, 1, ANONCE, &[], None);
        if !matches!(
            s.rx_eapol_with_nonce(&m1, false, || {
                calls += 1;
                Some(SNONCE)
            }),
            Ok(EapolRx::Pairwise1(_))
        ) || calls != 1
        {
            return TestResult::Fail("initial M1 did not consume exactly one SNonce");
        }
        if !matches!(
            s.rx_eapol_with_nonce(&m1, false, || panic!("retry requested nonce")),
            Ok(EapolRx::Pairwise1(_))
        ) {
            return TestResult::Fail("M1 retry failed without a new nonce");
        }
        let p = ptk_of(ANONCE, SNONCE);
        let m3 = ap_frame(
            M3_KI,
            2,
            ANONCE,
            &m3_kd(&AP_RSNE, Some(&RSNXE), true),
            Some(&p),
        );
        if !matches!(
            s.rx_eapol_with_nonce(&m3, false, || panic!("M3 requested nonce")),
            Ok(EapolRx::Pairwise3(_))
        ) {
            return TestResult::Fail("M3 failed without a nonce request");
        }
        s.pairwise_key_installed();
        s.group_keys_installed(Some(&GTK), Some(&IGTK));
        let group = ap_frame(
            0x1380,
            3,
            [0; 32],
            &m3_kd(&AP_RSNE, Some(&RSNXE), true),
            Some(&p),
        );
        if !matches!(
            s.rx_eapol_with_nonce(&group, true, || panic!("group requested SNonce")),
            Ok(EapolRx::Group1(_))
        ) {
            return TestResult::Fail("group rekey requested or needed a fresh SNonce");
        }
        let rekey = ap_frame(M1_KI, 4, [0x44; 32], &[], None);
        if s.rx_eapol_with_nonce(&rekey, false, || panic!("PMF drop requested nonce"))
            != Err(EapolRxError::Drop(GroupKeyDrop::Unencrypted))
        {
            return TestResult::Fail("PMF reject bypassed nonce boundary");
        }
        let bad = ap_frame(M1_KI, 4, [0x44; 32], &[0xdd, 20, 0], None);
        if s.rx_eapol_with_nonce(&bad, true, || panic!("bad KDE requested nonce"))
            != Err(EapolRxError::Drop(GroupKeyDrop::KeyData))
        {
            return TestResult::Fail("malformed M1 crossed the nonce boundary");
        }
        let replay = ap_frame(M1_KI, 3, ANONCE, &[], None);
        if s.rx_eapol_with_nonce(&replay, true, || panic!("replay requested nonce"))
            != Err(EapolRxError::Drop(GroupKeyDrop::Replay))
        {
            return TestResult::Fail("replayed M1 crossed the nonce boundary");
        }
        if !matches!(
            s.rx_eapol_with_nonce(&rekey, true, || {
                calls += 1;
                Some([0x55; 32])
            }),
            Ok(EapolRx::Pairwise1(_))
        ) || calls != 2
            || s.snonce != [0x55; 32]
        {
            return TestResult::Fail("new PTK rekey did not renew exactly once");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/eapol",
        smoke_eapol_nonce_provider_is_lazy_at_actual_m1_renewal
    );
    fn smoke_eapol_nonce_failure_does_not_commit_m1_state() -> TestResult {
        let mut s = sup();
        let mut calls = 0;
        let m1 = ap_frame(M1_KI, 1, ANONCE, &[], None);
        if s.rx_eapol_with_nonce(&m1, false, || {
            calls += 1;
            None
        }) != Err(EapolRxError::NonceUnavailable)
            || calls != 1
            || s.snonce != [0; 32]
            || s.anonce != [0; 32]
            || !s.renew_snonce
            || s.tptk.is_some()
            || s.ptk.is_some()
            || s.state != FourWayState::WaitM1
            || s.rx_replay_counter_set
        {
            return TestResult::Fail("failed nonce source changed initial M1/key state");
        }
        if !matches!(
            s.rx_eapol_with_nonce(&m1, false, || Some(SNONCE)),
            Ok(EapolRx::Pairwise1(_))
        ) {
            return TestResult::Fail("nonce failure consumed the M1 attempt");
        }
        let p = ptk_of(ANONCE, SNONCE);
        let m3 = ap_frame(
            M3_KI,
            2,
            ANONCE,
            &m3_kd(&AP_RSNE, Some(&RSNXE), true),
            Some(&p),
        );
        s.rx_eapol_with_nonce(&m3, false, || panic!("M3 entropy"))
            .unwrap();
        s.pairwise_key_installed();
        let rekey = ap_frame(M1_KI, 3, [0x44; 32], &[], None);
        if s.rx_eapol_with_nonce(&rekey, true, || None) != Err(EapolRxError::NonceUnavailable)
            || s.snonce != SNONCE
            || s.anonce != ANONCE
            || !s.renew_snonce
            || s.tptk.is_some()
            || s.ptk.as_ref().map(|k| &k.tk) != Some(&p.tk)
            || !s.ptk_installed
            || s.state != FourWayState::PtkDone
        {
            return TestResult::Fail("failed rekey entropy replaced the installed key/nonce");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/eapol",
        smoke_eapol_nonce_failure_does_not_commit_m1_state
    );
}

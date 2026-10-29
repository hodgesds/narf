//! ath11k station security: what wpa_supplicant (SME, RSN supplicant)
//! and mac80211 (802.11w frame handling, software BIP) do around
//! `ath11k_mac_op_set_key` for a WCN6855 station.
//!
//! | NARF | Linux / hostap |
//! |---|---|
//! | [`select_rsn`] | wpa_supplicant `wpa_supplicant_set_suites` (AKM order, `wpas_get_ssid_pmf`, `wpas_set_mgmt_group_cipher`) |
//! | [`sta_rsn_ie`] | `wpa_gen_wpa_ie_rsn` + `rsn_supp_capab` |
//! | `Mac::rsna_4way` | `wpa_sm_rx_eapol` → `wpa_supplicant_process_{1,3}_of_4` (shared `narf_wireless::eapol`), `wpa_supplicant_install_ptk` / `_gtk` / `_igtk` → `ath11k_mac_op_set_key` |
//! | `Mac::mfp_rx` | mac80211 `ieee80211_rx_h_decrypt` (CCMP mgmt PN, `ieee80211_crypto_aes_cmac_decrypt`) + `ieee80211_drop_unencrypted_mgmt` |
//! | `Mac::mfp_tx` | `ieee80211_tx_h_select_key` + `ccmp_encrypt_skb` with `IEEE80211_KEY_FLAG_GENERATE_IV_MGMT` + `ath11k_mac_mgmt_tx_wmi` MIC tailroom |
//! | `Mac::sa_query_*` | mac80211 `ieee80211_process_sa_query_req`; wpa_supplicant `sme_event_unprot_disconnect` / `sme_sa_query_timer` / `sme_process_sa_query_response` |
//!
//! ath11k hands every BIP suite to mac80211 (`ath11k_mac_op_set_key` returns
//! 1 — "BIP needs to be done in software", WCN6855 included): the IGTK
//! never reaches the firmware; group-addressed
//! robust management frames are verified here. The firmware decrypts
//! unicast protected management frames and delivers them with the
//! Protected bit, the CCMP header and the MIC still in place
//! (`ath11k_mgmt_rx_event` sets `RX_FLAG_DECRYPTED` only), so the
//! management replay counter (`rx_pn[IEEE80211_NUM_TIDS]`) is the host's.

extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroizing;

use narf_crypto::bip::{self, Cipher as BipCipher};
use narf_wireless::eapol::KeyMgmt;
use narf_wireless::rsn::{self, RsnIe, Suite};
use narf_wireless::{
    SecurityConfig, CIPHER_SUITE_AES_CMAC, CIPHER_SUITE_BIP_CMAC_256, CIPHER_SUITE_BIP_GMAC_128,
    CIPHER_SUITE_BIP_GMAC_256, CIPHER_SUITE_CCMP, CIPHER_SUITE_CCMP_256, CIPHER_SUITE_GCMP,
    CIPHER_SUITE_GCMP_256,
};

use super::super::mac_frame::{self as frame, capab, eid, ParsedIes};

/// `WLAN_EID_RSNX`.
pub const EID_RSNX: u8 = 244;
/// `WLAN_RSNX_CAPAB_SAE_H2E` (bit 5 of the Extended RSN Capabilities).
pub const RSNX_CAPAB_SAE_H2E: u8 = 5;
/// `WLAN_REASON_PREV_AUTH_NOT_VALID`.
pub const WLAN_REASON_PREV_AUTH_NOT_VALID: u16 = 2;
/// `WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA` / `_CLASS3_…_NONASSOC_STA`.
pub const WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA: u16 = 6;
pub const WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA: u16 = 7;
/// `WLAN_CATEGORY_SA_QUERY`, `WLAN_ACTION_SA_QUERY_REQUEST` / `_RESPONSE`.
pub const WLAN_CATEGORY_SA_QUERY: u8 = 8;
pub const WLAN_ACTION_SA_QUERY_REQUEST: u8 = 0;
pub const WLAN_ACTION_SA_QUERY_RESPONSE: u8 = 1;
/// `WLAN_SA_QUERY_TR_ID_LEN`.
pub const WLAN_SA_QUERY_TR_ID_LEN: usize = 2;
/// wpa_supplicant `sa_query_retry_timeout` / `sa_query_max_timeout` (TU).
pub const SA_QUERY_RETRY_TU: u64 = 201;
pub const SA_QUERY_MAX_TU: u64 = 1000;
/// `IEEE80211_CCMP_HDR_LEN` / `IEEE80211_CCMP_MIC_LEN`.
pub const CCMP_HDR_LEN: usize = 8;
pub const CCMP_MIC_LEN: usize = 8;
/// `IEEE80211_CCMP_256_MIC_LEN` and `IEEE80211_GCMP_MIC_LEN`.
pub const EXTENDED_MGMT_MIC_LEN: usize = 16;

/// Translate cfg80211's management-group selector into its host BIP engine.
/// ath11k returns `1` from `set_key` for all of these, so none may be handed
/// to WMI as a data cipher.
pub const fn bip_cipher(suite: u32) -> Option<BipCipher> {
    match suite {
        CIPHER_SUITE_AES_CMAC => Some(BipCipher::Cmac128),
        CIPHER_SUITE_BIP_CMAC_256 => Some(BipCipher::Cmac256),
        CIPHER_SUITE_BIP_GMAC_128 => Some(BipCipher::Gmac128),
        CIPHER_SUITE_BIP_GMAC_256 => Some(BipCipher::Gmac256),
        _ => None,
    }
}

/// The hardware MIC tailroom for a protected robust management frame under
/// an installed pairwise data cipher. TKIP cannot protect an MFP frame.
pub const fn protected_mgmt_mic_len(suite: u32) -> Option<usize> {
    match suite {
        CIPHER_SUITE_CCMP => Some(CCMP_MIC_LEN),
        CIPHER_SUITE_CCMP_256 | CIPHER_SUITE_GCMP | CIPHER_SUITE_GCMP_256 => {
            Some(EXTENDED_MGMT_MIC_LEN)
        }
        _ => None,
    }
}

/// What the SME negotiated for an RSN association.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsnPlan {
    pub key_mgmt: KeyMgmt,
    /// `wpas_get_ssid_pmf(...) == MGMT_FRAME_PROTECTION_REQUIRED` (our
    /// MFPR): SAE (WPA3-Personal); PSK is optional (MFPC only).
    pub pmf_required: bool,
    /// MFP in use (`assoc_data->use_mfp` → `sta->mfp`): the AP is MFP
    /// capable and has a usable BIP group-management cipher.
    pub mfp: bool,
    /// The AP's group cipher (ours = the AP's, `wpa_gen_wpa_ie_rsn`).
    pub group_cipher: Suite,
    /// The AP's RSNE / RSNXE elements (`sm->ap_rsn_ie`, `sm->ap_rsnxe`).
    pub ap_rsn_ie: Vec<u8>,
    pub ap_rsnxe: Option<Vec<u8>>,
    /// SAE: the AP's RSNXE advertises SAE H2E (`use_pt`).
    pub sae_h2e: bool,
}

/// The credential that goes with an [`RsnPlan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    /// The PMK (PSK / PBKDF2 passphrase).
    Pmk([u8; 32]),
    /// The SAE password.
    Sae(Vec<u8>),
}

/// Why [`select_rsn`] refused the BSS (`step::CONNECT_UNSUPPORTED` detail).
pub mod refuse {
    /// Open requested for a protected BSS.
    pub const OPEN_TO_PROTECTED: u32 = 1;
    /// No usable RSN element: not CCMP-128 pairwise + group, or no AKM
    /// we can do with this credential.
    pub const RSN: u32 = 2;
    /// SAE requested of a BSS without AKM 8.
    pub const NO_SAE: u32 = 3;
    /// PMF required (by the AP or by SAE) but not possible: the AP is
    /// not MFP capable, or its group management cipher is unsupported
    /// ("Management frame protection required but the selected AP does
    /// not enable it").
    pub const PMF: u32 = 4;
}

/// The RSN Extended Capabilities field of an RSNXE element (the first
/// octet; `rsnxe[2]`).
fn rsnxe_capa(rsnxe: Option<&[u8]>) -> u8 {
    rsnxe.filter(|r| r.len() >= 3).map_or(0, |r| r[2])
}

/// wpa_supplicant `wpa_supplicant_set_suites` for a station that does
/// CCMP-128 and the AKMs PSK (2), PSK-SHA256 (6) and SAE (8), with the
/// PMF policy of a WPA2/WPA3-Personal profile: PMF optional for PSK
/// (MFPC, NetworkManager's / iwd's default — standalone wpa_supplicant's
/// `pmf=0` would leave it off), required for SAE (WPA3). The AKM
/// preference is wpa_supplicant's (SAE before PSK-SHA256 before PSK):
/// [`SecurityConfig::Wpa3`] (a password) picks SAE when the AP offers it
/// — transition mode included — and [`SecurityConfig::Wpa2`] (a PMK)
/// picks PSK-SHA256 / PSK. `Ok(None)` = Open.
pub fn select_rsn(
    ies: &ParsedIes,
    capability: u16,
    sec: &SecurityConfig,
) -> Result<Option<(RsnPlan, Credential)>, u32> {
    let (want, cred) = match sec {
        SecurityConfig::Open => {
            if ies.rsn.is_some() || ies.wpa.is_some() || capability & capab::PRIVACY != 0 {
                return Err(refuse::OPEN_TO_PROTECTED);
            }
            return Ok(None);
        }
        SecurityConfig::Wpa2 { psk } => (
            &[KeyMgmt::PskSha256, KeyMgmt::Psk][..],
            Credential::Pmk(*psk),
        ),
        SecurityConfig::Wpa3 { password } => {
            (&[KeyMgmt::Sae][..], Credential::Sae(password.clone()))
        }
        // The supplicant in userspace chose the suites (its RSNE rides in
        // the association's elements).
        SecurityConfig::External(_) => return Ok(None),
    };
    let body = ies.rsn.as_deref().ok_or(refuse::RSN)?;
    let r = RsnIe::decode_body(body).ok_or(refuse::RSN)?;
    let ccmp = Suite::standard(rsn::CIPHER_CCMP_128);
    if r.group_cipher != ccmp || !r.pairwise_ciphers.contains(&ccmp) {
        return Err(refuse::RSN);
    }
    let Some(&key_mgmt) = want
        .iter()
        .find(|k| r.akms.contains(&Suite::standard(k.suite_type())))
    else {
        return Err(if matches!(cred, Credential::Sae(_)) {
            refuse::NO_SAE
        } else {
            refuse::RSN
        });
    };
    let pmf_required = key_mgmt == KeyMgmt::Sae;
    let ap_mfpc = r.rsn_capabilities & rsn::RSN_CAP_MFP_CAPABLE != 0;
    let ap_mfpr = r.rsn_capabilities & rsn::RSN_CAP_MFP_REQUIRED != 0;
    // wpas_set_mgmt_group_cipher: the AP's (default AES-128-CMAC when
    // the RSNE leaves it out) masked with what we do (AES-128-CMAC only;
    // mac80211 also has the GMAC / CMAC-256 BIPs, ath11k hands them all
    // to software, NARF has only CMAC-128).
    let bip_ok = r
        .group_management_cipher
        .is_none_or(|c| c == Suite::standard(rsn::CIPHER_BIP_CMAC_128));
    let mfp = ap_mfpc && bip_ok;
    if (pmf_required || ap_mfpr) && !mfp {
        return Err(refuse::PMF);
    }
    let mut ap_rsn_ie = alloc::vec![eid::RSN, body.len() as u8];
    ap_rsn_ie.extend_from_slice(body);
    let ap_rsnxe = ies.rsnxe.as_ref().map(|b| {
        let mut v = alloc::vec![EID_RSNX, b.len() as u8];
        v.extend_from_slice(b);
        v
    });
    let sae_h2e = key_mgmt == KeyMgmt::Sae
        && rsnxe_capa(ap_rsnxe.as_deref()) & (1 << RSNX_CAPAB_SAE_H2E) != 0;
    Ok(Some((
        RsnPlan {
            key_mgmt,
            pmf_required,
            mfp,
            group_cipher: r.group_cipher,
            ap_rsn_ie,
            ap_rsnxe,
            sae_h2e,
        },
        cred,
    )))
}

/// Our RSN element (`wpa_gen_wpa_ie_rsn`): version 1, the AP's group
/// cipher, CCMP pairwise, the AKM, `rsn_supp_capab` (16 PTKSA replay
/// counters with WMM — wpa_supplicant claims WMM for any HT/VHT/HE
/// association or a WMM AP —, MFPC for PMF optional or required, MFPR
/// for required) and, when PMF is in use, PMKID count 0 + BIP-CMAC-128.
pub fn sta_rsn_ie(plan: &RsnPlan, wmm: bool) -> Vec<u8> {
    let mut caps = rsn::RSN_CAP_MFP_CAPABLE;
    if wmm {
        caps |= 3 << 2; // RSN_NUM_REPLAY_COUNTERS_16 << 2
    }
    if plan.pmf_required {
        caps |= rsn::RSN_CAP_MFP_REQUIRED;
    }
    let body = RsnIe {
        version: 1,
        group_cipher: plan.group_cipher,
        pairwise_ciphers: alloc::vec![Suite::standard(rsn::CIPHER_CCMP_128)],
        akms: alloc::vec![Suite::standard(plan.key_mgmt.suite_type())],
        rsn_capabilities: caps,
        pmkids: Vec::new(),
        group_management_cipher: plan
            .mfp
            .then_some(Suite::standard(rsn::CIPHER_BIP_CMAC_128)),
    }
    .encode_body();
    let mut v = alloc::vec![eid::RSN, body.len() as u8];
    v.extend_from_slice(&body);
    v
}

/// Our RSNXE (`wpa_gen_rsnxe`): SAE with H2E possible (`sae_pwe` both)
/// sets `WLAN_RSNX_CAPAB_SAE_H2E`; nothing else applies, so no element
/// for PSK.
pub fn sta_rsnxe(plan: &RsnPlan) -> Option<Vec<u8>> {
    // Field length (n - 1) = 0 in bits 0-3.
    (plan.key_mgmt == KeyMgmt::Sae).then(|| alloc::vec![EID_RSNX, 1, 1 << RSNX_CAPAB_SAE_H2E])
}

/// `_ieee80211_is_robust_mgmt_frame`.
pub fn is_robust_mgmt(f: &[u8]) -> bool {
    if f.len() < frame::MGMT_HDR_LEN {
        return false;
    }
    let fc = u16::from_le_bytes([f[0], f[1]]);
    match fc & frame::FCTL_TYPE_STYPE {
        frame::stype::DEAUTH | frame::stype::DISASSOC => true,
        frame::stype::ACTION => {
            if fc & frame::FCTL_PROTECTED != 0 {
                return true;
            }
            let Some(&cat) = f.get(frame::MGMT_HDR_LEN) else {
                return false;
            };
            // PUBLIC, HT, WNM_UNPROTECTED, SELF_PROTECTED, UNPROT_DMG,
            // VHT, S1G, VENDOR_SPECIFIC are not robust.
            !matches!(cat, 4 | 7 | 11 | 15 | 20 | 21 | 22 | 127)
        }
        _ => false,
    }
}

/// `ieee80211_get_mmie_keyidx`: the Key ID of any valid-length BIP MMIE
/// ending a group-addressed robust frame.
pub fn mmie_keyidx(f: &[u8]) -> Option<u16> {
    if f.len() < frame::MGMT_HDR_LEN || f[4] & 1 == 0 || !is_robust_mgmt(f) {
        return None;
    }
    bip::parse_mmie(&f[frame::MGMT_HDR_LEN..])
        .ok()
        .map(|mmie| mmie.key_id)
}

/// The 48-bit PN of a CCMP header (`ccmp_hdr2pn`).
pub fn ccmp_pn(h: &[u8]) -> u64 {
    u64::from_be_bytes([0, 0, h[7], h[6], h[5], h[4], h[1], h[0]])
}

/// `ccmp_pn2hdr`: PN0 PN1 rsvd (ExtIV | key id << 6) PN2..PN5.
pub fn ccmp_hdr(pn: u64, key_id: u8) -> [u8; CCMP_HDR_LEN] {
    let b = pn.to_le_bytes();
    [b[0], b[1], 0, 0x20 | (key_id << 6), b[2], b[3], b[4], b[5]]
}

/// mac80211's view of a host-protected management frame as ath11k hands
/// it to `WMI_MGMT_TX_SEND_CMDID`: the Protected bit, the CCMP header
/// `ccmp_encrypt_skb` writes (PN = `++key->conf.tx_pn`, key 0) and the
/// `IEEE80211_CCMP_MIC_LEN` tail `ath11k_mac_mgmt_tx_wmi` reserves — the
/// firmware encrypts in place.
pub fn protect_mgmt(f: &[u8], pn: u64) -> Vec<u8> {
    protect_mgmt_with_mic_len(f, pn, CCMP_MIC_LEN)
}

/// The same management-IV construction for CCMP-256 and GCMP. Those ciphers
/// share the eight-octet ExtIV but carry a 128-bit MIC rather than CCMP-128's
/// 64-bit MIC.
pub fn protect_mgmt_with_mic_len(f: &[u8], pn: u64, mic_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(f.len() + CCMP_HDR_LEN + mic_len);
    out.extend_from_slice(&f[..frame::MGMT_HDR_LEN]);
    out[1] |= (frame::FCTL_PROTECTED >> 8) as u8;
    out.extend_from_slice(&ccmp_hdr(pn, 0));
    out.extend_from_slice(&f[frame::MGMT_HDR_LEN..]);
    out.extend(core::iter::repeat_n(0u8, mic_len));
    out
}

/// mac80211 `ieee80211_process_sa_query_req`'s response: Action, DA =
/// the AP, SA = us, BSSID = the AP, SA Query Response with the request's
/// transaction identifier (protection added on transmit).
pub fn build_sa_query(own: &[u8; 6], ap: &[u8; 6], action: u8, trans_id: [u8; 2]) -> Vec<u8> {
    let mut f = frame::mgmt_hdr(frame::stype::ACTION, ap, own, ap);
    f.extend_from_slice(&[WLAN_CATEGORY_SA_QUERY, action, trans_id[0], trans_id[1]]);
    f
}

/// Host-side 802.11w state of an association (mac80211 key structures +
/// wpa_supplicant SA Query state).
#[derive(Clone, PartialEq, Eq)]
pub struct MfpIgtk {
    cipher: BipCipher,
    key: Vec<u8>,
    rx_pn: u64,
}

impl core::fmt::Debug for MfpIgtk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MfpIgtk")
            .field("cipher", &self.cipher)
            .field("rx_pn", &self.rx_pn)
            .finish()
    }
}

/// Host-side 802.11w state of an association (mac80211 key structures +
/// wpa_supplicant SA Query state).
#[derive(Clone, Debug)]
pub struct MfpState {
    /// The IGTKs by key index 4 / 5 (`link->gtk[4..6]`), including their
    /// BIP suite and receive replay number.
    pub igtk: [Option<MfpIgtk>; 2],
    /// The PTK's management receive PN (`u.ccmp.rx_pn[IEEE80211_NUM_TIDS]`).
    pub mgmt_rx_pn: u64,
    /// The PTK's transmit PN for host-built CCMP headers (`conf.tx_pn`).
    pub mgmt_tx_pn: u64,
    /// MIC tailroom for the active pairwise management protection cipher.
    /// CCMP-128 is the in-kernel-supplicant default; external supplicants set
    /// this on each successful pairwise key install.
    pub mgmt_mic_len: usize,
    /// SA Query in progress: start (ms), transaction ids sent, next timer (µs).
    pub sa_query: Option<SaQuery>,
    /// `sme.last_unprot_disconnect` (ms).
    pub last_unprot_ms: Option<u64>,
    /// An unprotected Deauthentication / Disassociation was dropped with a
    /// reason that warrants an SA Query (`sme_event_unprot_disconnect`).
    pub unprot_pending: bool,
    /// SA Query Requests from the AP to answer (transaction ids).
    pub sa_query_req: Vec<[u8; 2]>,
}

impl Default for MfpState {
    fn default() -> Self {
        Self {
            igtk: [None, None],
            mgmt_rx_pn: 0,
            mgmt_tx_pn: 0,
            mgmt_mic_len: CCMP_MIC_LEN,
            sa_query: None,
            last_unprot_ms: None,
            unprot_pending: false,
            sa_query_req: Vec::new(),
        }
    }
}

/// wpa_supplicant `sme.sa_query_*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaQuery {
    pub start_ms: u64,
    pub trans_ids: Vec<[u8; 2]>,
    /// When the next `sme_sa_query_timer` fires, in µs since `start_ms`.
    pub next_us: u64,
}

/// What [`MfpState::rx`] made of a frame from the AP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MfpRx {
    /// Deliver (with the protection removed when there was some).
    Pass(Option<Vec<u8>>),
    /// Drop (`RX_DROP_U_*`); `unprot` = an unprotected Deauthentication /
    /// Disassociation (`cfg80211_rx_unprot_mlme_mgmt`).
    Drop { unprot: bool },
}

impl MfpState {
    /// Install an IGTK (`ieee80211_key_alloc` copies the IPN into either the
    /// CMAC or GMAC replay state). `false` for an invalid key shape or index.
    pub fn install_igtk(
        &mut self,
        cipher: BipCipher,
        key_id: u16,
        key: &[u8],
        ipn: [u8; 6],
    ) -> bool {
        let Some(slot) = key_id.checked_sub(4).filter(|&s| s < 2) else {
            return false;
        };
        if key.len() != cipher.key_len() {
            return false;
        }
        self.igtk[slot as usize] = Some(MfpIgtk {
            cipher,
            key: key.to_vec(),
            rx_pn: narf_crypto::bip_cmac::decode_ipn(&ipn),
        });
        true
    }

    /// mac80211's MFP receive rules for a robust management frame `f` from
    /// our AP's station entry (`sta->mfp` set): see the module docs.
    /// `ptk` / `gtk` = a pairwise / group key is installed.
    pub fn rx(&mut self, f: &[u8], ptk: bool, gtk: bool) -> MfpRx {
        if !is_robust_mgmt(f) {
            return MfpRx::Pass(None);
        }
        let fc = u16::from_le_bytes([f[0], f[1]]);
        let st = fc & frame::FCTL_TYPE_STYPE;
        let deauth = st == frame::stype::DEAUTH || st == frame::stype::DISASSOC;
        if f[4] & 1 != 0 {
            // Group addressed: BIP (ieee80211_crypto_aes_cmac_decrypt).
            let Ok(mmie) = bip::parse_mmie(&f[frame::MGMT_HDR_LEN..]) else {
                return MfpRx::Drop { unprot: deauth };
            };
            let Some(key) = mmie
                .key_id
                .checked_sub(4)
                .filter(|&s| s < 2)
                .and_then(|s| self.igtk[s as usize].as_ref())
                .cloned()
            else {
                return MfpRx::Drop { unprot: false };
            };
            if mmie.ipn <= key.rx_pn {
                return MfpRx::Drop { unprot: false }; // RX_DROP_U_REPLAY
            }
            if bip::verify_mmie(
                key.cipher,
                &key.key,
                &f[..frame::MGMT_HDR_LEN],
                &f[frame::MGMT_HDR_LEN..],
            )
            .is_err()
            {
                return MfpRx::Drop { unprot: false }; // RX_DROP_U_MIC_FAIL
            }
            self.igtk[(mmie.key_id - 4) as usize]
                .as_mut()
                .unwrap()
                .rx_pn = mmie.ipn;
            // skb_trim(skb, skb->len - sizeof(*mmie))
            return MfpRx::Pass(Some(f[..f.len() - key.cipher.mmie_len()].to_vec()));
        }
        if fc & frame::FCTL_PROTECTED != 0 {
            // Decrypted by the firmware; CCMP header + MIC still there.
            if !ptk || f.len() < frame::MGMT_HDR_LEN + CCMP_HDR_LEN + self.mgmt_mic_len {
                return MfpRx::Drop { unprot: false };
            }
            let h = &f[frame::MGMT_HDR_LEN..frame::MGMT_HDR_LEN + CCMP_HDR_LEN];
            if h[3] & 0x20 == 0 || h[3] >> 6 != 0 {
                return MfpRx::Drop { unprot: false }; // no ExtIV / not the PTK id
            }
            let pn = ccmp_pn(h);
            if pn <= self.mgmt_rx_pn {
                return MfpRx::Drop { unprot: false }; // RX_DROP_U_REPLAY
            }
            self.mgmt_rx_pn = pn;
            let mut out = f[..frame::MGMT_HDR_LEN].to_vec();
            out[1] &= !((frame::FCTL_PROTECTED >> 8) as u8);
            out.extend_from_slice(
                &f[frame::MGMT_HDR_LEN + CCMP_HDR_LEN..f.len() - self.mgmt_mic_len],
            );
            return MfpRx::Pass(Some(out));
        }
        // Unprotected unicast robust frame.
        if deauth {
            // "Permit unprotected deauth/disassoc frames during 4-way-HS
            // (key is installed after HS)": rx->key is any GTK.
            if !gtk {
                return MfpRx::Pass(None);
            }
            return MfpRx::Drop { unprot: true };
        }
        MfpRx::Drop { unprot: false }
    }
}

/// wpa_supplicant `WPA_PARAM_WMM_ENABLED` when the RSNE is generated (before
/// the association): the BSS carries a WMM vendor element
/// (`wpa_bss_get_vendor_ie(bss, WMM_IE_VENDOR_TYPE)`).
pub fn wpa_wmm(bss_ies: &[u8]) -> bool {
    frame::find_vendor_elem(bss_ies, frame::OUI_MICROSOFT, frame::OUI_TYPE_MICROSOFT_WMM).is_some()
}

/// Our RSNE (+ RSNXE) as sent in the Association Request and in M2
/// (`sm->assoc_wpa_ie` || `sm->assoc_rsnxe`).
pub fn assoc_ies(plan: &RsnPlan, bss_ies: &[u8]) -> Vec<u8> {
    let mut v = sta_rsn_ie(plan, wpa_wmm(bss_ies));
    if let Some(x) = sta_rsnxe(plan) {
        v.extend_from_slice(&x);
    }
    v
}

// ── The mac layer's security operations ─────────────────────────────

use narf_wireless::eapol::{
    EapolRx, EapolRxError, GroupKeyDrop, GroupKeyFail, PairwiseFail, RsnaParams, Supplicant,
};

use super::{errno, fail, step, timeout, DataPort, LinkLoss, Mac, MacError, ScanBss, WmiPort};

/// Failed partial samples never escape this temporary buffer. The shared
/// supplicant invokes this only when an accepted M1 must renew SNonce.
fn random_snonce(wmi: &impl WmiPort) -> Result<[u8; 32], i32> {
    let mut bytes = Zeroizing::new([0; 32]);
    wmi.random_bytes(bytes.as_mut_slice())?;
    Ok(*bytes)
}

/// `step::EAPOL_PROTO` / `step::EAPOL_GTK` details of a 4-way failure.
fn pairwise_fail_step(w: PairwiseFail) -> (u32, u32) {
    match w {
        PairwiseFail::UnencryptedKde => (step::EAPOL_PROTO, 3),
        PairwiseFail::RsnIeMismatch => (step::EAPOL_PROTO, 4),
        PairwiseFail::RsnxeMismatch => (step::EAPOL_PROTO, 7),
        PairwiseFail::ANonce => (step::EAPOL_PROTO, 8),
        PairwiseFail::KeyLength => (step::EAPOL_PROTO, 9),
        PairwiseFail::KeyId => (step::EAPOL_PROTO, 10),
        PairwiseFail::KeyData => (step::EAPOL_PROTO, 11),
        PairwiseFail::NoGtk => (step::EAPOL_GTK, 2),
        PairwiseFail::GtkKdeLength | PairwiseFail::GtkCipherLength => (step::EAPOL_GTK, 3),
        PairwiseFail::Igtk => (step::EAPOL_GTK, 4),
        PairwiseFail::IgtkKdeLength => (step::EAPOL_GTK, 5),
    }
}

impl<P: WmiPort, D: DataPort> Mac<P, D> {
    /// The 4-way handshake over the shared supplicant (wpa_supplicant
    /// `wpa_sm_rx_eapol`; 10 s `wpa_supplicant_req_auth_timeout`), then
    /// the installs `wpa_supplicant_process_3_of_4` does after message
    /// 4/4: PTK (`ath11k_mac_op_set_key` pairwise), GTK (group), IGTK
    /// (software BIP: ath11k returns 1 for every BIP suite, no WMI command).
    pub(super) async fn rsna_4way(
        &mut self,
        bss: &ScanBss,
        plan: &RsnPlan,
        pmk: &[u8],
    ) -> Result<(), MacError> {
        let own = self.caps.mac_addr;
        let aa = bss.bssid;
        let params = RsnaParams {
            key_mgmt: plan.key_mgmt,
            pmk: pmk.to_vec(),
            assoc_ie: assoc_ies(plan, &bss.ies),
            ap_rsn_ie: plan.ap_rsn_ie.clone(),
            ap_rsnxe: plan.ap_rsnxe.clone(),
            pairwise_key_len: 16,
            group_key_len: 16,
            mgmt_group_key_len: plan.mfp.then_some(16),
            pmf: plan.mfp,
        };
        let mut sup = Supplicant::new(aa, own, [0; 32]).with_rsna(params);
        let deadline = self.wmi.now_ms() + timeout::EAPOL as u64;
        let mut mic_failures = 0u32;
        loop {
            // WMI events (kickout, deauth) can end the attempt.
            while let Some(ev) = self.wmi.next_event(0).await {
                self.handle_event(&ev);
            }
            if let Some(loss) = self.link.as_ref().and_then(|l| l.loss) {
                let d = match loss {
                    LinkLoss::Deauth { reason, .. } => reason as u32,
                    _ => 0xFFFF,
                };
                return fail(
                    step::EAPOL_PROTO,
                    0x1_0000 | d,
                    errno::ENOLINK,
                    "4-way (link lost)",
                );
            }
            let now = self.wmi.now_ms();
            if now >= deadline {
                let (s, what) = if mic_failures > 0 {
                    (step::EAPOL_MIC, "4-way (MIC failure)")
                } else {
                    (step::EAPOL_TIMEOUT, "4-way (timeout)")
                };
                return fail(s, sup.state as u32, errno::ETIMEDOUT, what);
            }
            let slice = ((deadline - now) as u32).min(50);
            let Some((eth, encrypted)) = self.dp.recv_eapol(slice).await else {
                continue;
            };
            let Some((src, pdu)) = frame::parse_eapol_eth(&eth) else {
                continue;
            };
            if src != aa {
                continue;
            }
            let mut entropy_error = None;
            let result =
                sup.rx_eapol_with_nonce(pdu, encrypted, || match random_snonce(&self.wmi) {
                    Ok(bytes) => Some(bytes),
                    Err(error) => {
                        entropy_error = Some(error);
                        None
                    }
                });
            match result {
                Ok(EapolRx::Pairwise1(m2)) => {
                    let f = frame::eapol_eth(&aa, &own, &m2.reply);
                    if let Err(e) = self.dp.send_eth(&f).await {
                        return fail(step::EAPOL_PROTO, 2, e, "4-way (M2 TX)");
                    }
                }
                Ok(EapolRx::Pairwise3(m3)) => {
                    let f = frame::eapol_eth(&aa, &own, &m3.reply);
                    if let Err(e) = self.dp.send_eth(&f).await {
                        return fail(step::EAPOL_PROTO, 6, e, "4-way (M4 TX)");
                    }
                    if let Some(tk) = m3.tk.as_ref() {
                        self.install_key(aa, 0, tk, true).await?;
                        self.link.as_mut().unwrap().ptk_installed = true;
                        sup.pairwise_key_installed();
                        self.mfp.mgmt_rx_pn = 0;
                        self.mfp.mgmt_tx_pn = 0;
                    }
                    if let Some(g) = m3.gtk.as_ref() {
                        self.install_key(aa, g.key_id, &g.key, false).await?;
                        self.seed_group_rsc(aa, g.key_id, &g.rsc).await;
                        self.link.as_mut().unwrap().gtk_idx = Some(g.key_id);
                        sup.group_keys_installed(Some(&g.key), None);
                    }
                    if let Some(i) = m3.igtk.as_ref() {
                        if !self
                            .mfp
                            .install_igtk(BipCipher::Cmac128, i.key_id, &i.key, i.ipn)
                        {
                            // "Failed to configure IGTK": cfg80211 allows
                            // only key index 4 / 5 for AES-CMAC.
                            self.link.as_mut().unwrap().deauth_reason =
                                frame::WLAN_REASON_UNSPECIFIED;
                            return fail(step::EAPOL_GTK, 4, errno::EINVAL, "4-way (IGTK)");
                        }
                        sup.group_keys_installed(None, Some(&i.key));
                    }
                    self.sup = Some(sup);
                    return Ok(());
                }
                Ok(EapolRx::Group1(_)) => {}
                Err(EapolRxError::NonceUnavailable) => {
                    return fail(
                        step::ENTROPY,
                        1,
                        entropy_error.unwrap_or(errno::EIO),
                        "4-way entropy",
                    );
                }
                Err(EapolRxError::Drop(GroupKeyDrop::BadMic)) => mic_failures += 1,
                Err(EapolRxError::Drop(_)) => {}
                Err(EapolRxError::Pairwise { reason, why }) => {
                    self.link.as_mut().unwrap().deauth_reason = reason;
                    let (s, d) = pairwise_fail_step(why);
                    return fail(s, d, errno::EPROTO, "4-way handshake");
                }
                Err(EapolRxError::Group(_)) => {
                    self.link.as_mut().unwrap().deauth_reason = frame::WLAN_REASON_UNSPECIFIED;
                    return fail(step::EAPOL_GTK, 0x100, errno::EPROTO, "4-way (group)");
                }
            }
        }
    }

    /// EAPOL received after the association completed: wpa_supplicant's
    /// `wpa_supplicant_rx_eapol` → `wpa_sm_rx_eapol` for the Group Key
    /// Handshake (`wpa_supplicant_process_1_of_2`): the new GTK
    /// installed with its key index (`ath11k_mac_op_set_key(SET_KEY,
    /// group)` → `ath11k_install_key(WMI_KEY_GROUP)` + the PN config), the
    /// IGTK in software when PMF is in use (`ieee80211w_set_keys`; an
    /// invalid one is only logged), message 2/2 sent. Frames whose source
    /// is not the AP are not processed (`last_eapol_matches_bssid`);
    /// without RSN EAPOL is ignored. A failed handshake deauthenticates
    /// with `WLAN_REASON_UNSPECIFIED` ([`LinkLoss::Supplicant`]).
    ///
    /// A pairwise message 1/4 is a PTK rekey (`wpa_supplicant_process_1_of_4`
    /// while completed): message 2/4 goes back, message 3/4 is answered and
    /// the new TK installed as mac80211 replaces a PTK0 ([`Self::ptk_rekey`]).
    pub(super) async fn rx_eapol(&mut self) {
        while let Some((eth, encrypted)) = self.dp.recv_eapol(0).await {
            let Some(l) = self.link.as_ref() else {
                continue;
            };
            if let Some(e) = l.external {
                // ieee80211_deliver_skb_to_local_stack for the control
                // port protocol: userspace's supplicant gets it.
                if l.assoc && l.loss.is_none() {
                    self.queue_control_port_rx(eth, encrypted, e.control_port);
                }
                continue;
            }
            if !l.authorized || l.loss.is_some() || self.sup.is_none() {
                continue;
            }
            let aa = l.bss.bssid;
            let Some((src, pdu)) = frame::parse_eapol_eth(&eth) else {
                continue;
            };
            if src != aa {
                continue;
            }
            let wmi = &self.wmi;
            let r = self
                .sup
                .as_mut()
                .unwrap()
                .rx_eapol_with_nonce(pdu, encrypted, || random_snonce(wmi).ok());
            let own = self.caps.mac_addr;
            let m1 = match r {
                Ok(EapolRx::Group1(m)) => m,
                Ok(EapolRx::Pairwise1(m2)) => {
                    // wpa_supplicant_send_2_of_4 ("goto failed" on a TX error).
                    let f = frame::eapol_eth(&aa, &own, &m2.reply);
                    if self.dp.send_eth(&f).await.is_err() {
                        self.supplicant_deauth(step::PTK_REKEY, 1);
                        return;
                    }
                    continue;
                }
                Ok(EapolRx::Pairwise3(m3)) => {
                    if let Err(d) = self.ptk_rekey(aa, &m3).await {
                        self.supplicant_deauth(step::PTK_REKEY, d);
                        return;
                    }
                    continue;
                }
                Err(EapolRxError::Pairwise { reason, why }) => {
                    let (s, d) = pairwise_fail_step(why);
                    if let Some(l) = self.link.as_mut() {
                        if l.loss.is_none() {
                            l.loss = Some(LinkLoss::Supplicant {
                                reason,
                                step: s,
                                detail: d,
                            });
                        }
                    }
                    return;
                }
                Err(EapolRxError::NonceUnavailable) => {
                    self.supplicant_deauth(step::ENTROPY, 2);
                    return;
                }
                Err(EapolRxError::Drop(_)) => continue,
                Err(EapolRxError::Group(f)) => {
                    let n = match f {
                        GroupKeyFail::Before4Way => 1,
                        GroupKeyFail::KeyData => 2,
                        GroupKeyFail::GtkUnencrypted => 3,
                        GroupKeyFail::NoGtk => 4,
                        GroupKeyFail::GtkKdeLength => 5,
                        GroupKeyFail::GtkCipherLength => 6,
                    };
                    self.supplicant_deauth(step::EAPOL_GTK, 0x100 | n);
                    return;
                }
            };
            if let Some(g) = m1.gtk.as_ref() {
                // wpa_supplicant_install_gtk → wpa_sm_set_key(GROUP_RX).
                if self.install_key(aa, g.key_id, &g.key, false).await.is_err() {
                    self.supplicant_deauth(step::EAPOL_GTK, 0x200);
                    return;
                }
                self.seed_group_rsc(aa, g.key_id, &g.rsc).await;
                if let Some(s) = self.sup.as_mut() {
                    s.group_keys_installed(Some(&g.key), None);
                }
                if let Some(l) = self.link.as_mut() {
                    l.gtk_idx = Some(g.key_id);
                }
            }
            if let Some(Ok(Some(i))) = m1.igtk.as_ref() {
                // ieee80211w_set_keys: a failure is "Failed to configure
                // IGTK", not fatal.
                if self
                    .mfp
                    .install_igtk(BipCipher::Cmac128, i.key_id, &i.key, i.ipn)
                {
                    if let Some(s) = self.sup.as_mut() {
                        s.group_keys_installed(None, Some(&i.key));
                    }
                }
            }
            if self
                .dp
                .send_eth(&frame::eapol_eth(&aa, &own, &m1.reply))
                .await
                .is_err()
            {
                self.supplicant_deauth(step::EAPOL_GTK, 0x300);
                return;
            }
        }
    }

    /// Message 3/4 of a PTK rekey: message 4/4 first (wpa_supplicant
    /// sends it under the old key), then `wpa_supplicant_install_ptk` →
    /// `ieee80211_add_key` → `ieee80211_key_replace` for PTK0 without
    /// Extended Key ID on ath11k (hardware crypto, `AMPDU_AGGREGATION`, no
    /// `NL80211_EXT_FEATURE_CAN_REPLACE_PTK0`): `ieee80211_pairwise_rekey`
    /// tears the RX BA sessions down with a DELBA each
    /// (`ieee80211_sta_tear_down_BA_sessions(AGG_STOP_LOCAL_REQUEST)`,
    /// `WLAN_REASON_QSTA_LEAVE_QBSS`) and flushes the queues
    /// (`ieee80211_flush_queues(.., false)`); the old key is disabled
    /// (`ath11k_mac_op_set_key(DISABLE_KEY)`: cipher NONE + PN config off),
    /// the new one installed (`SET_KEY`: fragment flush, install, PN config
    /// = the REO PN reset) and made the TX key (`_ieee80211_set_tx_key`;
    /// the management PNs restart with it). A retransmitted 3/4 only gets
    /// its 4/4 (no TK: "Do not re-install same PTK"). Then a new GTK /
    /// IGTK from the message, as after the first 4-way. `Err` = detail.
    async fn ptk_rekey(
        &mut self,
        aa: [u8; 6],
        m3: &narf_wireless::eapol::PairwiseM3,
    ) -> Result<(), u32> {
        let own = self.caps.mac_addr;
        if self
            .dp
            .send_eth(&frame::eapol_eth(&aa, &own, &m3.reply))
            .await
            .is_err()
        {
            return Err(2);
        }
        if let Some(tk) = m3.tk.as_ref() {
            for tid in 0..16 {
                self.stop_rx_ba_session(
                    tid,
                    frame::WLAN_BACK_RECIPIENT,
                    frame::WLAN_REASON_QSTA_LEAVE_QBSS,
                    true,
                )
                .await;
            }
            self.dp.flush_tx().await;
            let vdev_id = self.vif.as_ref().map_or(0, |v| v.vdev_id);
            let old = super::VdevInstallKeyArg {
                vdev_id,
                macaddr: aa,
                key_idx: 0,
                key_flags: super::WMI_KEY_PAIRWISE,
                key_cipher: super::cipher::NONE,
                ..Default::default()
            };
            if self.install_key_cmd(&old).await.is_err() {
                return Err(3);
            }
            let _ = self
                .dp
                .rx_pn_replay_config(vdev_id, aa, super::cipher::AES_CCM, 16, 0, true, false)
                .await;
            if self.install_key(aa, 0, tk, true).await.is_err() {
                return Err(4);
            }
            if let Some(s) = self.sup.as_mut() {
                s.pairwise_key_installed();
            }
            self.mfp.mgmt_rx_pn = 0;
            self.mfp.mgmt_tx_pn = 0;
        }
        if let Some(g) = m3.gtk.as_ref() {
            if self.install_key(aa, g.key_id, &g.key, false).await.is_err() {
                return Err(5);
            }
            self.seed_group_rsc(aa, g.key_id, &g.rsc).await;
            if let Some(l) = self.link.as_mut() {
                l.gtk_idx = Some(g.key_id);
            }
            if let Some(s) = self.sup.as_mut() {
                s.group_keys_installed(Some(&g.key), None);
            }
        }
        if let Some(i) = m3.igtk.as_ref() {
            if !self
                .mfp
                .install_igtk(BipCipher::Cmac128, i.key_id, &i.key, i.ipn)
            {
                return Err(6);
            }
            if let Some(s) = self.sup.as_mut() {
                s.group_keys_installed(None, Some(&i.key));
            }
        }
        Ok(())
    }

    /// mac80211's MFP receive path for a robust frame from our AP while
    /// `sta->mfp` (see [`MfpState::rx`]), or from one of our MFP AP clients.
    /// `None` = the rules do not apply (no matching peer or no MFP).
    /// `wpa_supplicant_install_gtk` passes the EAPOL-Key RSC
    /// (`key_rsc_len` 6, little-endian) as the group key's receive sequence;
    /// mac80211 seeds every TID's replay counter with it.
    pub(super) async fn seed_group_rsc(&mut self, addr: [u8; 6], key_idx: u8, rsc: &[u8]) {
        let seq = rsc
            .iter()
            .take(6)
            .enumerate()
            .fold(0u64, |seq, (i, b)| seq | (*b as u64) << (8 * i));
        if let Some(vdev_id) = self.vif.as_ref().map(|vif| vif.vdev_id) {
            self.dp.group_rx_seq(vdev_id, addr, key_idx, seq).await;
        }
    }

    pub(super) fn mfp_rx_filter(&mut self, f: &[u8]) -> Option<MfpRx> {
        if let Some(l) = self.link.as_ref() {
            if l.assoc && l.sta.mfp && f.len() >= frame::MGMT_HDR_LEN && f[10..16] == l.bss.bssid {
                let (ptk, gtk) = (l.ptk_installed, l.gtk_idx.is_some());
                let r = self.mfp.rx(f, ptk, gtk);
                if r == (MfpRx::Drop { unprot: true }) {
                    self.unprot_disconnect(f);
                }
                return Some(r);
            }
        }
        self.ap_mfp_rx_filter(f)
    }

    /// The AP arm of mac80211's MFP receive filter. Robust management frames
    /// from a PMF client are unicast and firmware-decrypted; ath11k leaves
    /// the CCMP header and MIC in place, so retain the host replay window and
    /// pass hostapd the stripped frame. Clients never originate a protected
    /// group robust frame, so such a frame is rejected rather than treating
    /// the AP's transmit IGTK as a receive key.
    fn ap_mfp_rx_filter(&mut self, f: &[u8]) -> Option<MfpRx> {
        if f.len() < frame::MGMT_HDR_LEN {
            return None;
        }
        let source: [u8; 6] = f[10..16].try_into().unwrap();
        let ap = self.ap.as_mut()?;
        let have_gtk = !ap.group_keys.is_empty();
        let station = ap
            .stations
            .iter_mut()
            .find(|station| station.mac == source)?;
        if !station.mfp || !is_robust_mgmt(f) {
            return None;
        }
        let fc = u16::from_le_bytes([f[0], f[1]]);
        let st = fc & frame::FCTL_TYPE_STYPE;
        let deauth = st == frame::stype::DEAUTH || st == frame::stype::DISASSOC;
        if f[4] & 1 != 0 {
            return Some(MfpRx::Drop { unprot: false });
        }
        if fc & frame::FCTL_PROTECTED != 0 {
            let Some(mic_len) = station
                .pairwise_key
                .as_ref()
                .and_then(|(_, cipher, _)| protected_mgmt_mic_len(*cipher))
            else {
                return Some(MfpRx::Drop { unprot: false });
            };
            if f.len() < frame::MGMT_HDR_LEN + CCMP_HDR_LEN + mic_len {
                return Some(MfpRx::Drop { unprot: false });
            }
            let h = &f[frame::MGMT_HDR_LEN..frame::MGMT_HDR_LEN + CCMP_HDR_LEN];
            if h[3] & 0x20 == 0 || h[3] >> 6 != 0 {
                return Some(MfpRx::Drop { unprot: false });
            }
            let pn = ccmp_pn(h);
            if pn <= station.mgmt_rx_pn {
                return Some(MfpRx::Drop { unprot: false });
            }
            station.mgmt_rx_pn = pn;
            let mut out = f[..frame::MGMT_HDR_LEN].to_vec();
            out[1] &= !((frame::FCTL_PROTECTED >> 8) as u8);
            out.extend_from_slice(&f[frame::MGMT_HDR_LEN + CCMP_HDR_LEN..f.len() - mic_len]);
            return Some(MfpRx::Pass(Some(out)));
        }
        if deauth && !have_gtk {
            // During the 4-way handshake the peer has not received the GTK
            // yet, so an otherwise-valid unprotected teardown remains legal.
            return Some(MfpRx::Pass(None));
        }
        Some(MfpRx::Drop { unprot: deauth })
    }

    /// wpa_supplicant `sme_event_unprot_disconnect`: an unprotected
    /// Deauthentication / Disassociation from the AP with reason 6 / 7
    /// while completed starts an SA Query (at most every 10 s).
    fn unprot_disconnect(&mut self, f: &[u8]) {
        let Some(l) = self.link.as_ref() else {
            return;
        };
        if !l.authorized || f.len() < frame::MGMT_HDR_LEN + 2 {
            return;
        }
        let reason = u16::from_le_bytes([f[24], f[25]]);
        if reason != WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA
            && reason != WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA
        {
            return;
        }
        if self.mfp.sa_query.is_some() || self.mfp.unprot_pending {
            return;
        }
        let now = self.wmi.now_ms();
        if self.mfp.last_unprot_ms.is_some_and(|t| now < t + 10_000) {
            return;
        }
        self.mfp.last_unprot_ms = Some(now);
        self.mfp.unprot_pending = true;
    }

    /// An SA Query Action frame from the AP (after the MFP rules):
    /// a Request → mac80211 `ieee80211_process_sa_query_req` (to us, from
    /// the AP we are associated with) queues the Response; a Response →
    /// wpa_supplicant `sme_sa_query_rx` / `sme_process_sa_query_response`
    /// (unicast, a transaction id we sent) ends the SA Query.
    pub(super) fn sa_query_rx(&mut self, f: &[u8]) {
        let own = self.caps.mac_addr;
        let Some(l) = self.link.as_ref() else {
            return;
        };
        if !l.assoc || f.len() < frame::MGMT_HDR_LEN + 1 + 1 + WLAN_SA_QUERY_TR_ID_LEN {
            return;
        }
        let ap = l.bss.bssid;
        let (da, sa, bssid) = (&f[4..10], &f[10..16], &f[16..22]);
        let tid = [f[26], f[27]];
        match f[25] {
            WLAN_ACTION_SA_QUERY_REQUEST => {
                if da != own || sa != ap || bssid != ap {
                    return;
                }
                self.mfp.sa_query_req.push(tid);
            }
            WLAN_ACTION_SA_QUERY_RESPONSE => {
                if da[0] & 1 != 0 || sa != ap {
                    return;
                }
                if self
                    .mfp
                    .sa_query
                    .as_ref()
                    .is_some_and(|q| q.trans_ids.contains(&tid))
                {
                    // sme_stop_sa_query
                    self.mfp.sa_query = None;
                }
            }
            _ => {}
        }
    }

    /// The deferred 802.11w work: SA Query Responses, the start of an SA
    /// Query, and `sme_sa_query_timer` (a new Request every 201 TU; past
    /// 1000 TU without a matching Response:
    /// `wpa_supplicant_deauthenticate(WLAN_REASON_PREV_AUTH_NOT_VALID)`,
    /// detail = Requests sent).
    pub(super) async fn mfp_deferred(&mut self) {
        let own = self.caps.mac_addr;
        let Some(ap) = self.link.as_ref().map(|l| l.bss.bssid) else {
            self.mfp.sa_query_req.clear();
            return;
        };
        for tid in core::mem::take(&mut self.mfp.sa_query_req) {
            let f = build_sa_query(&own, &ap, WLAN_ACTION_SA_QUERY_RESPONSE, tid);
            self.tx_mgmt_nowait(&f).await;
        }
        let now = self.wmi.now_ms();
        if core::mem::take(&mut self.mfp.unprot_pending) {
            self.mfp.sa_query = Some(SaQuery {
                start_ms: now,
                trans_ids: Vec::new(),
                next_us: 0,
            });
        }
        let Some(q) = self.mfp.sa_query.as_ref() else {
            return;
        };
        let passed_us = (now - q.start_ms) * 1000;
        if passed_us < q.next_us {
            return;
        }
        // sme_check_sa_query_timeout
        if !q.trans_ids.is_empty() && passed_us / 1024 > SA_QUERY_MAX_TU {
            let sent = q.trans_ids.len() as u32;
            self.mfp.sa_query = None;
            if let Some(l) = self.link.as_mut() {
                if l.loss.is_none() {
                    l.loss = Some(LinkLoss::Supplicant {
                        reason: WLAN_REASON_PREV_AUTH_NOT_VALID,
                        step: step::SA_QUERY_TIMEOUT,
                        detail: sent,
                    });
                }
            }
            return;
        }
        let mut tid = [0u8; 2];
        if self.wmi.random_bytes(&mut tid).is_err() {
            self.mfp.sa_query = None;
            self.supplicant_deauth(step::ENTROPY, 3);
            return;
        }
        if let Some(q) = self.mfp.sa_query.as_mut() {
            q.trans_ids.push(tid);
            q.next_us += SA_QUERY_RETRY_TU * 1024;
        }
        let f = build_sa_query(&own, &ap, WLAN_ACTION_SA_QUERY_REQUEST, tid);
        self.tx_mgmt_nowait(&f).await;
    }

    /// mac80211 `ieee80211_tx_h_select_key` for a management frame: a
    /// unicast robust frame to an MFP station/client with a PTK is
    /// CCMP-family-protected (host header, firmware encryption); robust group
    /// frames from an AP receive a host-generated MMIE for the installed BIP
    /// suite.
    pub(super) fn mfp_tx(&mut self, f: &[u8]) -> Vec<u8> {
        let use_mfp = self
            .link
            .as_ref()
            .is_some_and(|l| l.sta.mfp && l.ptk_installed);
        if use_mfp && f.len() >= frame::MGMT_HDR_LEN && f[4] & 1 == 0 && is_robust_mgmt(f) {
            self.mfp.mgmt_tx_pn += 1;
            return protect_mgmt_with_mic_len(f, self.mfp.mgmt_tx_pn, self.mfp.mgmt_mic_len);
        }
        if f.len() < frame::MGMT_HDR_LEN || !is_robust_mgmt(f) {
            return f.to_vec();
        }
        if f[4] & 1 == 0 {
            let dest: [u8; 6] = f[4..10].try_into().unwrap();
            if let Some(station) =
                self.ap
                    .as_mut()
                    .and_then(|ap| ap.stations.iter_mut().find(|station| station.mac == dest))
                    .filter(|station| {
                        station.mfp
                            && station.pairwise_key.as_ref().is_some_and(|(_, cipher, _)| {
                                protected_mgmt_mic_len(*cipher).is_some()
                            })
                    })
            {
                station.mgmt_tx_pn += 1;
                let mic_len =
                    protected_mgmt_mic_len(station.pairwise_key.as_ref().unwrap().1).unwrap();
                return protect_mgmt_with_mic_len(f, station.mgmt_tx_pn, mic_len);
            }
            return f.to_vec();
        }
        let Some(igtk) = self.ap.as_mut().and_then(|ap| {
            let selected = ap.default_igtk;
            let position = selected
                .and_then(|idx| ap.igtks.iter().position(|key| key.idx == idx))
                .or_else(|| ap.igtks.len().checked_sub(1));
            position.and_then(|position| ap.igtks.get_mut(position))
        }) else {
            return f.to_vec();
        };
        let mut body = f[frame::MGMT_HDR_LEN..].to_vec();
        let Some(cipher) = bip_cipher(igtk.cipher) else {
            return f.to_vec();
        };
        let Ok(ipn) = bip::protect_mmie(
            cipher,
            &igtk.key,
            igtk.idx as u16,
            &mut igtk.tx_ipn,
            &f[..frame::MGMT_HDR_LEN],
            &mut body,
        ) else {
            return f.to_vec();
        };
        debug_assert_eq!(igtk.tx_ipn, ipn);
        let mut out = f[..frame::MGMT_HDR_LEN].to_vec();
        out.extend_from_slice(&body);
        out
    }
}

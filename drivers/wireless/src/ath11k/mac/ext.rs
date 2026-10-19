//! The station with its supplicant (and, for SAE, its SME) in userspace:
//! what mac80211 does for wpa_supplicant without handshake offload.
//!
//! | NARF | Linux |
//! |---|---|
//! | [`Mac::ext_add_key`] | `ieee80211_add_key` → `ieee80211_key_link` (KRACK `-EALREADY` → 0, `ieee80211_key_replace` for PTK0) → `ath11k_mac_op_set_key(SET_KEY)`; AES-CMAC stays in software (`return 1`) |
//! | [`Mac::ext_del_key`] | `ieee80211_del_key` → `ath11k_mac_op_set_key(DISABLE_KEY)` (pairwise only on a STA vif) |
//! | [`Mac::ext_set_authorized`] | `sta_apply_auth_flags` → `ath11k_mac_op_sta_state(ASSOC ↔ AUTHORIZED)` + `ieee80211_recalc_ps_vif` |
//! | [`Mac::take_control_port_rx`] | `ieee80211_deliver_skb_to_local_stack`: the control port protocol to `cfg80211_rx_control_port`, or to the netdev with DA = own address |
//! | [`Mac::sme_authenticate`] | `ieee80211_mgd_auth` (+ `ieee80211_prep_connection`) → `ieee80211_auth` / `ieee80211_rx_mgmt_auth` |
//! | [`Mac::sme_associate`] | `ieee80211_mgd_assoc` → `ieee80211_send_assoc` / `ieee80211_rx_mgmt_assoc_resp` → `ieee80211_assoc_success` |
//! | [`Mac::sme_deauthenticate`] | `ieee80211_mgd_deauth` |
//! | [`Mac::set_power_save`] | `ieee80211_set_power_mgmt` → `ieee80211_recalc_ps_vif` → `ath11k_mac_vif_setup_ps` |

extern crate alloc;

use alloc::vec::Vec;

use narf_wireless::{
    ControlPort, KeyParams, MlmeAssocRequest, MlmeAuthRequest, CIPHER_SUITE_AES_CMAC,
    CIPHER_SUITE_BIP_CMAC_256, CIPHER_SUITE_BIP_GMAC_128, CIPHER_SUITE_BIP_GMAC_256,
    CIPHER_SUITE_CCMP, CIPHER_SUITE_CCMP_256, CIPHER_SUITE_GCMP, CIPHER_SUITE_GCMP_256,
    CIPHER_SUITE_TKIP,
};

use super::super::mac_frame::{self as frame, eid, ParsedIes};
use super::sae::{
    build_auth_sae, AUTH_TIMEOUT_SAE, WLAN_AUTH_SAE, WLAN_STATUS_ANTI_CLOGGING_TOKEN_REQ,
    WLAN_STATUS_SAE_HASH_TO_ELEMENT, WLAN_STATUS_SAE_PK,
};
use super::sec::EID_RSNX;
use super::sec::{bip_cipher, protected_mgmt_mic_len};
use super::{
    channel_number_freq, errno, fail, firmware_key_cipher, step, timeout, DataPort, Mac, MacError,
    ScanState, VdevInstallKeyArg, WmiPort, WMI_KEY_PAIRWISE,
};

/// The keys an external supplicant installed (mac80211's key table for
/// the AP station). Not `Debug`-printed: key material.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ExtKeys {
    pub ptk: Option<ExtKey>,
    /// GTKs by index 0..=3, IGTKs 4..=5.
    pub group: [Option<ExtKey>; 6],
}

/// One installed external-supplicant key.  Retaining its suite alongside the
/// secret bytes prevents an otherwise identical replacement from silently
/// preserving an obsolete descriptor encryption type.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtKey {
    pub cipher: u32,
    pub key: Vec<u8>,
}

impl core::fmt::Debug for ExtKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtKeys")
            .field("ptk", &self.ptk.is_some())
            .field(
                "group",
                &self.group.iter().map(Option::is_some).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// A received control-port frame for userspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPortRx {
    /// The 802.3 frame (destination rewritten to our address).
    pub eth: Vec<u8>,
    /// The MPDU was decrypted (`RX_FLAG_DECRYPTED`).
    pub decrypted: bool,
    /// `sdata->control_port_over_nl80211`.
    pub over_nl80211: bool,
}

/// The elements an offloading SME puts in its Association Request: ours
/// (`ours` = RSNE [+ RSNXE]) where userspace had its RSNE (or first), the
/// rest of userspace's `NL80211_ATTR_IE` in its order, its own RSNE /
/// RSNXE dropped (the driver negotiates the suite). Malformed input is
/// passed through unchanged (nl80211 validated it).
pub fn merge_sme_ies(ours: Option<Vec<u8>>, user: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut placed = false;
    let mut rest = user;
    let mut elements = Vec::new();
    while rest.len() >= 2 && rest.len() >= 2 + rest[1] as usize {
        let n = 2 + rest[1] as usize;
        elements.push(&rest[..n]);
        rest = &rest[n..];
    }
    let ours = ours.unwrap_or_default();
    for e in elements {
        match e[0] {
            eid::RSN => {
                if !placed {
                    out.extend_from_slice(&ours);
                    placed = true;
                }
            }
            EID_RSNX => {}
            _ => out.extend_from_slice(e),
        }
    }
    if !placed {
        let mut v = ours;
        v.extend_from_slice(&out);
        out = v;
    }
    out
}

/// Set `bit` in octet `octet` of the Extended Capabilities element in
/// `ies`, when the element is that long.
pub fn set_ext_capa_bit(ies: &mut [u8], octet: usize, bit: u8) {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            return;
        }
        if ies[i] == eid::EXT_CAPABILITY && len > octet {
            ies[i + 2 + octet] |= bit;
            return;
        }
        i += 2 + len;
    }
}

impl<P: WmiPort, D: DataPort> Mac<P, D> {
    /// Queue a received EAPOL frame for userspace (DA = our address, as
    /// `ieee80211_deliver_skb_to_local_stack` rewrites a PAE group DA).
    pub(super) fn queue_control_port_rx(
        &mut self,
        mut eth: Vec<u8>,
        decrypted: bool,
        port: ControlPort,
    ) {
        if eth.len() < 14 {
            return;
        }
        let own = self.caps.mac_addr;
        if !port.over_nl80211 {
            eth[..6].copy_from_slice(&own);
        }
        if self.ctrl_rx.len() >= 32 {
            self.ctrl_rx.remove(0);
        }
        self.ctrl_rx.push(ControlPortRx {
            eth,
            decrypted,
            over_nl80211: port.over_nl80211,
        });
    }

    /// Received control-port frames since the last call.
    pub fn take_control_port_rx(&mut self) -> Vec<ControlPortRx> {
        core::mem::take(&mut self.ctrl_rx)
    }

    /// The keys an external supplicant installed.
    pub fn ext_keys(&self) -> &ExtKeys {
        &self.ext_keys
    }

    /// `ieee80211_add_key` for the AP station of an external-supplicant
    /// association.
    pub async fn ext_add_key(&mut self, k: &KeyParams) -> Result<(), MacError> {
        let Some(l) = self.link.as_ref() else {
            return fail(step::KEY_INSTALL, 0x400, errno::ENOLINK, "key (no link)");
        };
        if !l.assoc {
            // "The ASSOC test makes sure the driver is ready".
            return fail(
                step::KEY_INSTALL,
                0x401,
                errno::ENOENT,
                "key (not associated)",
            );
        }
        let aa = l.bss.bssid;
        let had_ptk = l.ptk_installed;
        if k.pairwise && l.sta.mfp && protected_mgmt_mic_len(k.cipher).is_none() {
            // MFP's unicast protection follows the installed PTK. TKIP has
            // no robust-management construction, so mac80211 cannot accept
            // it for an MFP peer either.
            return fail(
                step::KEY_INSTALL,
                k.cipher,
                errno::EOPNOTSUPP,
                "MFP pairwise cipher",
            );
        }
        match k.cipher {
            // BIP: ath11k_mac_op_set_key returns 1, mac80211 does it in
            // software from the IPN (`aes_cmac` / `aes_gmac.rx_pn`).
            suite @ (CIPHER_SUITE_AES_CMAC
            | CIPHER_SUITE_BIP_CMAC_256
            | CIPHER_SUITE_BIP_GMAC_128
            | CIPHER_SUITE_BIP_GMAC_256) => {
                if k.pairwise || k.peer.is_some() || !(4..=5).contains(&k.idx) {
                    return fail(step::KEY_INSTALL, 0x402, errno::EINVAL, "IGTK shape");
                }
                let slot = k.idx as usize;
                if self
                    .ext_keys
                    .group
                    .get(slot)
                    .and_then(Option::as_ref)
                    .is_some_and(|known| {
                        known.cipher == suite && known.key.as_slice() == k.key.as_slice()
                    })
                {
                    return Ok(());
                }
                let mut ipn = [0u8; 6];
                if k.seq.len() == 6 {
                    ipn.copy_from_slice(&k.seq);
                }
                if !self
                    .mfp
                    .install_igtk(bip_cipher(suite).unwrap(), k.idx as u16, &k.key, ipn)
                {
                    return fail(step::KEY_INSTALL, 0x402, errno::EINVAL, "IGTK");
                }
                self.ext_keys.group[slot] = Some(ExtKey {
                    cipher: suite,
                    key: k.key.clone(),
                });
                Ok(())
            }
            suite @ (CIPHER_SUITE_TKIP
            | CIPHER_SUITE_CCMP
            | CIPHER_SUITE_CCMP_256
            | CIPHER_SUITE_GCMP
            | CIPHER_SUITE_GCMP_256)
                if k.pairwise =>
            {
                // KRACK protection: the same key again is not re-installed.
                if self.ext_keys.ptk.as_ref().is_some_and(|known| {
                    known.cipher == suite && known.key.as_slice() == k.key.as_slice()
                }) {
                    return Ok(());
                }
                if had_ptk {
                    // ieee80211_key_replace of PTK0 without
                    // CAN_REPLACE_PTK0, as in the in-kernel PTK rekey.
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
                    let previous_suite = self
                        .ext_keys
                        .ptk
                        .as_ref()
                        .map_or(CIPHER_SUITE_CCMP, |known| known.cipher);
                    self.disable_ptk(aa, previous_suite).await?;
                }
                self.install_key_with_cipher(aa, 0, &k.key, true, suite)
                    .await?;
                if let Some(l) = self.link.as_mut() {
                    l.ptk_installed = true;
                }
                self.mfp.mgmt_rx_pn = 0;
                self.mfp.mgmt_tx_pn = 0;
                if let Some(mic_len) = protected_mgmt_mic_len(suite) {
                    self.mfp.mgmt_mic_len = mic_len;
                }
                self.ext_keys.ptk = Some(ExtKey {
                    cipher: suite,
                    key: k.key.clone(),
                });
                Ok(())
            }
            suite @ (CIPHER_SUITE_TKIP
            | CIPHER_SUITE_CCMP
            | CIPHER_SUITE_CCMP_256
            | CIPHER_SUITE_GCMP
            | CIPHER_SUITE_GCMP_256) => {
                let slot = k.idx as usize;
                if self
                    .ext_keys
                    .group
                    .get(slot)
                    .and_then(Option::as_ref)
                    .is_some_and(|known| {
                        known.cipher == suite && known.key.as_slice() == k.key.as_slice()
                    })
                {
                    return Ok(());
                }
                self.install_key_with_cipher(aa, k.idx, &k.key, false, suite)
                    .await?;
                if let Some(l) = self.link.as_mut() {
                    l.gtk_idx = Some(k.idx);
                }
                self.ext_keys.group[slot] = Some(ExtKey {
                    cipher: suite,
                    key: k.key.clone(),
                });
                Ok(())
            }
            // "cipher %d is not supported".
            c => fail(step::KEY_INSTALL, c, errno::EOPNOTSUPP, "key (cipher)"),
        }
    }

    /// `ath11k_mac_op_set_key(DISABLE_KEY)` of the pairwise key: cipher NONE
    /// + the PN configuration off.
    async fn disable_ptk(&mut self, aa: [u8; 6], suite: u32) -> Result<(), MacError> {
        let vdev_id = self.vif.as_ref().map_or(0, |v| v.vdev_id);
        let old = VdevInstallKeyArg {
            vdev_id,
            macaddr: aa,
            key_idx: 0,
            key_flags: WMI_KEY_PAIRWISE,
            key_cipher: super::cipher::NONE,
            ..Default::default()
        };
        self.install_key_cmd(&old).await?;
        let (cipher, _, _) = firmware_key_cipher(suite).unwrap_or((super::cipher::AES_CCM, 0, 0));
        let _ = self
            .dp
            .rx_pn_replay_config(vdev_id, aa, cipher, 16, 0, true, false)
            .await;
        let _ = self.dp.tkip_rx_mic_config(vdev_id, aa, None).await;
        if let Some(l) = self.link.as_mut() {
            l.ptk_installed = false;
        }
        self.mfp.mgmt_mic_len = super::sec::CCMP_MIC_LEN;
        Ok(())
    }

    /// `ieee80211_del_key`: a pairwise key is disabled in the firmware; a
    /// group key on a STA vif only leaves mac80211's table (ath11k skips
    /// its DISABLE_KEY), an IGTK the software BIP.
    pub async fn ext_del_key(&mut self, idx: u8, pairwise: bool) -> Result<(), MacError> {
        let Some(aa) = self.link.as_ref().map(|l| l.bss.bssid) else {
            return fail(step::KEY_INSTALL, 0x410, errno::ENOENT, "del key (no link)");
        };
        if pairwise {
            let Some(key) = self.ext_keys.ptk.take() else {
                return fail(step::KEY_INSTALL, 0x411, errno::ENOENT, "del key (no PTK)");
            };
            return self.disable_ptk(aa, key.cipher).await;
        }
        let slot = idx as usize;
        if self
            .ext_keys
            .group
            .get_mut(slot)
            .and_then(Option::take)
            .is_none()
        {
            return fail(
                step::KEY_INSTALL,
                0x412,
                errno::ENOENT,
                "del key (no group key)",
            );
        }
        if slot >= 4 {
            self.mfp.igtk[slot - 4] = None;
        } else if let Some(l) = self.link.as_mut() {
            if l.gtk_idx == Some(idx) {
                l.gtk_idx = None;
            }
        }
        Ok(())
    }

    /// `sta_apply_auth_flags(AUTHORIZED)`: ASSOC → AUTHORIZED
    /// (`ath11k_mac_op_sta_state` → `WMI_PEER_AUTHORIZE`, then
    /// `ieee80211_recalc_ps_vif`), or back to ASSOC (`is_authorized =
    /// false`, no command).
    pub async fn ext_set_authorized(&mut self, on: bool) -> Result<(), MacError> {
        let Some(l) = self.link.as_ref() else {
            return fail(
                step::PEER_AUTHORIZE,
                0x10,
                errno::ENOENT,
                "authorize (no link)",
            );
        };
        if !l.assoc {
            return fail(
                step::PEER_AUTHORIZE,
                0x11,
                errno::EINVAL,
                "authorize (not associated)",
            );
        }
        let addr = l.bss.bssid;
        if on {
            self.authorize().await?;
            self.setup_ps().await;
        } else if l.authorized {
            self.link.as_mut().unwrap().authorized = false;
            self.dp.set_authorized(addr, false);
        }
        Ok(())
    }

    /// `ieee80211_set_power_mgmt(enabled)` → `ieee80211_recalc_ps_vif`:
    /// enabled once the AP is authorized and a beacon was seen
    /// (`ieee80211_powersave_allowed`), disabled at once.
    pub async fn set_power_save(&mut self, enabled: bool) {
        self.powersave = enabled;
        let Some(v) = self.vif.clone() else {
            return;
        };
        if enabled && !v.ps {
            self.setup_ps().await;
        } else if !enabled && v.ps {
            let c = super::sta_powersave_mode_cmd(v.vdev_id, super::sta_ps_mode::DISABLED);
            if self
                .cmd(c, step::STA_PS, 0x100, "sta ps mode")
                .await
                .is_ok()
            {
                if let Some(v) = self.vif.as_mut() {
                    v.ps = false;
                }
            }
        }
    }

    /// `wdev->ps` as the mac layer applies it.
    pub fn power_save(&self) -> bool {
        self.powersave
    }

    /// `ieee80211_mgd_auth`: prepare the connection to the BSS (once per
    /// authentication; a continuing SAE exchange keeps it), send the
    /// Authentication frame userspace's SME built — Open System, or SAE
    /// with `auth_data` = transaction | status | body — and return the
    /// peer's answer (`cfg80211_rx_mlme_mgmt`). A denial tears the
    /// connection down (`ieee80211_destroy_auth_data`) except the SAE
    /// statuses that wait for userspace (anti-clogging, H2E / PK commit);
    /// `Err` with ETIMEDOUT is `cfg80211_auth_timeout`.
    pub async fn sme_authenticate(&mut self, req: &MlmeAuthRequest) -> Result<Vec<u8>, MacError> {
        if self.vif.is_none() {
            return fail(step::CONNECT_STATE, 1, errno::ENOTCONN, "auth (no vdev)");
        }
        let Some(freq) = channel_number_freq(req.channel) else {
            return fail(
                step::CONNECT_NO_BSS,
                req.channel,
                errno::EINVAL,
                "auth (channel)",
            );
        };
        let alg = match req.auth_type {
            0 => frame::WLAN_AUTH_OPEN,
            4 => WLAN_AUTH_SAE,
            t => {
                return fail(
                    step::CONNECT_UNSUPPORTED,
                    t,
                    errno::EOPNOTSUPP,
                    "auth (type)",
                )
            }
        };
        let Some(bss) = self
            .bss
            .iter()
            .find(|b| b.bssid == req.peer && b.freq == freq)
            .cloned()
        else {
            return fail(
                step::CONNECT_NO_BSS,
                freq,
                errno::ENOENT,
                "auth (BSS not in scan table)",
            );
        };
        let cont = self
            .link
            .as_ref()
            .is_some_and(|l| l.bss.bssid == req.peer && !l.assoc);
        if !cont {
            let previous = self
                .link
                .as_ref()
                .and_then(|l| l.assoc.then_some(l.bss.bssid));
            if let Some(l) = self.link.as_ref() {
                // "disconnect from AP %pM for new auth to %pM".
                let (assoc, bssid) = (l.assoc, l.bss.bssid);
                self.teardown(assoc, frame::WLAN_REASON_UNSPECIFIED).await;
                if assoc {
                    self.disconnect = Some(super::Disconnect {
                        reason: frame::WLAN_REASON_UNSPECIFIED,
                        from_ap: false,
                        deauth: true,
                        bssid,
                    });
                }
            }
            self.mlme_prev_bssid = previous;
            if self.scan.state != ScanState::Idle {
                self.scan_abort().await;
            }
            let ies = bss.parsed();
            let external = Some(narf_wireless::ExternalSecurity::default());
            if let Err(e) = self.prep_connection(&bss, &ies, None, external).await {
                self.mlme_prev_bssid = None;
                self.teardown(false, 0).await;
                return Err(e);
            }
        }
        let own = self.caps.mac_addr;
        let mut f = if alg == WLAN_AUTH_SAE {
            if req.auth_data.len() < 4 {
                return fail(step::SAE_COMMIT, 0x10, errno::EINVAL, "auth (SAE data)");
            }
            let trans = u16::from_le_bytes([req.auth_data[0], req.auth_data[1]]);
            let status = u16::from_le_bytes([req.auth_data[2], req.auth_data[3]]);
            build_auth_sae(&own, &req.peer, trans, status, &req.auth_data[4..])
        } else {
            frame::build_auth_open(&own, &req.peer)
        };
        f.extend_from_slice(&req.ie);
        let sae_trans = if alg == WLAN_AUTH_SAE {
            u16::from_le_bytes([req.auth_data[0], req.auth_data[1]])
        } else {
            1
        };
        let (wait, matches): (u32, fn(&[u8]) -> bool) = if alg == WLAN_AUTH_SAE {
            if sae_trans == 1 {
                (AUTH_TIMEOUT_SAE, |r| {
                    frame::parse_auth(r)
                        .is_some_and(|a| a.alg == WLAN_AUTH_SAE && (1..=2).contains(&a.transaction))
                })
            } else {
                (AUTH_TIMEOUT_SAE, |r| {
                    frame::parse_auth(r)
                        .is_some_and(|a| a.alg == WLAN_AUTH_SAE && a.transaction == 2)
                })
            }
        } else {
            (timeout::MLME_RESPONSE, |r| {
                frame::parse_auth(r)
                    .is_some_and(|a| a.alg == frame::WLAN_AUTH_OPEN && a.transaction == 2)
            })
        };
        let resp = match self
            .mlme_exchange(
                &f,
                step::AUTH_TX,
                step::AUTH_TIMEOUT,
                "authenticate",
                wait,
                matches,
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.mlme_prev_bssid = None;
                self.teardown(false, 0).await;
                return Err(e);
            }
        };
        let a = frame::parse_auth(&resp).unwrap();
        if a.status != frame::WLAN_STATUS_SUCCESS {
            let waits = alg == WLAN_AUTH_SAE
                && (a.status == WLAN_STATUS_ANTI_CLOGGING_TOKEN_REQ
                    || a.transaction == 1
                        && (a.status == WLAN_STATUS_SAE_HASH_TO_ELEMENT
                            || a.status == WLAN_STATUS_SAE_PK));
            if !waits {
                self.mlme_prev_bssid = None;
                self.teardown(false, 0).await;
            }
            return Ok(resp);
        }
        // ieee80211_mark_sta_auth: Open at once, SAE on the peer's
        // Confirm answering ours.
        if alg != WLAN_AUTH_SAE || a.transaction == 2 && sae_trans == 2 {
            if let Some(l) = self.link.as_mut() {
                l.authenticated = true;
            }
        }
        Ok(resp)
    }

    /// `ieee80211_mgd_assoc` after a completed authentication: the
    /// (Re)Association Request with userspace's elements, the response
    /// (whatever its status; a rejection tears the connection down), and
    /// on success `ieee80211_assoc_success` with the port closed until
    /// SET_STATION when userspace asked for a control port.
    pub async fn sme_associate(&mut self, req: &MlmeAssocRequest) -> Result<Vec<u8>, MacError> {
        let ok = self
            .link
            .as_ref()
            .is_some_and(|l| l.bss.bssid == req.peer && l.authenticated && !l.assoc);
        if !ok {
            return fail(
                step::CONNECT_STATE,
                3,
                errno::ENOLINK,
                "assoc (not authenticated)",
            );
        }
        if req
            .prev_bssid
            .is_some_and(|prev| Some(prev) != self.mlme_prev_bssid)
        {
            return fail(
                step::CONNECT_STATE,
                7,
                errno::EINVAL,
                "reassoc (previous BSS)",
            );
        }
        let bss = self.link.as_ref().unwrap().bss.clone();
        let ies: ParsedIes = bss.parsed();
        let ext = narf_wireless::ExternalSecurity {
            use_mfp: req.use_mfp,
            privacy: req.privacy,
            control_port: req.control_port,
        };
        self.link.as_mut().unwrap().external = Some(ext);
        let resp = match self
            .associate_exchange_with_fallback(&bss, &ies, &req.ssid, None, &req.ie, req.prev_bssid)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.mlme_prev_bssid = None;
                self.teardown(false, 0).await;
                return Err(e);
            }
        };
        self.mlme_prev_bssid = None;
        let a = frame::parse_assoc_resp(&resp).unwrap();
        if a.status != frame::WLAN_STATUS_SUCCESS {
            self.teardown(false, 0).await;
            return Ok(resp);
        }
        if !req.control_port.enabled {
            self.link.as_mut().unwrap().authorized = true;
        }
        let r = self.assoc_success(&bss, &ies, &resp).await;
        if let Err(e) = r {
            let reason = self.link.as_ref().map_or(0, |l| l.deauth_reason);
            self.teardown(true, reason).await;
            return Err(e);
        }
        if self.link.as_ref().is_some_and(|l| l.authorized) {
            self.authorize().await?;
            self.setup_ps().await;
        }
        narf_memory::diag::set_wifi_stage(narf_memory::diag::WifiStage::Connected);
        Ok(resp)
    }

    /// `ieee80211_mgd_deauth` / `_disassoc`: tear down the authentication
    /// or association with `peer`; returns the frame for
    /// `cfg80211_tx_mlme_mgmt` (a Deauthentication, or the Disassociation
    /// that was asked for — NARF's teardown always transmits a
    /// Deauthentication). ENOTCONN for another peer.
    pub async fn sme_deauthenticate(
        &mut self,
        peer: [u8; 6],
        reason: u16,
        deauth: bool,
    ) -> Result<Vec<u8>, MacError> {
        let Some(l) = self.link.as_ref() else {
            return fail(step::CONNECT_STATE, 4, errno::ENOTCONN, "deauth (no link)");
        };
        if l.bss.bssid != peer {
            return fail(
                step::CONNECT_STATE,
                5,
                errno::ENOTCONN,
                "deauth (other BSS)",
            );
        }
        let assoc = l.assoc;
        let own = self.caps.mac_addr;
        if !assoc {
            // An authentication in progress: mac80211 still sends the
            // Deauthentication ("tx = !auth_data->done" — always for an
            // authenticated station).
            let vdev = self.vif.as_ref().map(|v| v.vdev_id);
            if vdev.is_some() {
                let _ = self.send_deauth_frame(peer, reason).await;
            }
        }
        self.teardown(assoc, reason).await;
        self.mlme_prev_bssid = None;
        let d = super::Disconnect {
            reason,
            from_ap: false,
            deauth,
            bssid: peer,
        };
        if assoc {
            self.disconnect = Some(d);
        }
        Ok(d.frame(&own))
    }
}

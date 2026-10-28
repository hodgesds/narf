// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Gen2 WPA3-SAE authentication and management-frame protection (PMF).
//! Host SAE follows mac80211 `ieee80211_auth` with wpa_supplicant's SME
//! (`sme_send_authentication`/`sme_sae_auth`) through the shared JoinPlan
//! SAE state machine. PMF follows mac80211 `ieee80211_drop_unencrypted_mgmt`
//! and `ieee80211_crypto_aes_cmac_decrypt`, and the iwlmvm key paths
//! `iwl_mvm_send_sta_key` (`STA_KEY_MFP`) and `iwl_mvm_send_sta_igtk`
//! (MGMT_MCAST_KEY, `fw/api/sta.h`).
use super::super::{boot_context::put32, scan_api};
use super::{assoc::AssociationStatus, auth::AuthenticationStatus, Owner, Phase};
use alloc::{boxed::Box, vec::Vec};
use narf_wireless::{
    association::{Bss, JoinPlan, SaeJoin, SaePwe, SaeStep, SecurityMode},
    eapol::KeyMgmt,
    mfp::MfpKeyStore,
    reg::RegulatoryDomain,
    sae::SaeSession,
};
use zeroize::Zeroizing;

/// `MGMT_MCAST_KEY` (group 0), `fw/api/commands.h`.
pub(super) const MGMT_MCAST_KEY: u8 = 0x1f;
/// `STA_KEY_FLG_CCM`: Linux uses it for an AES-CMAC (BIP-CMAC-128) IGTK.
const STA_KEY_FLG_CCM: u32 = 2;
/// `STA_KEY_NOT_VALID`.
const STA_KEY_NOT_VALID: u32 = 1 << 11;
/// `STA_KEY_MFP`: set on every pairwise/group key of an MFP station.
pub(super) const STA_KEY_MFP: u16 = 1 << 15;
/// Commit, up to three anti-clogging Commits (`MAX_ANTI_CLOGGING`) and
/// Confirm bound the frames one SAE attempt may emit.
const MAX_SAE_FRAMES: usize = 5;

/// A completed SAE exchange retained for the following association.
pub(super) struct SaeAuthenticated {
    pub status: AuthenticationStatus,
    pub ssid: Vec<u8>,
    pub plan: JoinPlan,
    pub request: Vec<u8>,
    pub pmk: Zeroizing<[u8; 32]>,
    /// Next management sequence number after the SAE frames.
    pub sequence: u16,
}

/// Host PMF receive state of one data owner: the BIP IGTKs and the
/// pairwise management replay counter (mac80211 keeps robust management
/// frames on their own CCMP RX PN, `IEEE80211_NUM_TIDS`).
#[derive(Default)]
pub(super) struct PmfRx {
    pub mfp: MfpKeyStore,
    pub mgmt_pn: u64,
}

/// MGMT_MCAST_KEY v2 (`SEC_MGMT_MULTICAST_KEY_CMD_API_S_VER_2`, 52 bytes):
/// ctrl_flags, igtk[32], key_id, sta_id (station 0), receive_seq_cnt.
/// Pre-AX210 22000 devices use the new RX API, hence v2 (Linux
/// `iwl_mvm_has_new_rx_api`). `None` removes the key (`STA_KEY_NOT_VALID`).
pub(super) fn igtk_command(key: Option<&[u8; 16]>, key_id: u16, ipn: u64) -> Zeroizing<[u8; 52]> {
    let mut bytes = Zeroizing::new([0; 52]);
    match key {
        Some(material) => {
            put32(&mut bytes[..], 0, STA_KEY_FLG_CCM);
            bytes[4..20].copy_from_slice(material);
            bytes[44..52].copy_from_slice(&ipn.to_le_bytes());
        }
        None => put32(&mut bytes[..], 0, STA_KEY_NOT_VALID),
    }
    put32(&mut bytes[..], 36, u32::from(key_id));
    bytes
}

/// Whether a received Deauthentication/Disassociation from the bound AP
/// ends the association. Without PMF this is the legacy unprotected check.
/// With PMF (mac80211 `ieee80211_drop_unencrypted_mgmt`, WLAN_STA_MFP set
/// at association): an unprotected unicast frame is dropped; a protected
/// one counts only when firmware reports station0 CCM decryption with a
/// valid MIC and its PN advances the management replay counter; a
/// group-addressed one needs a valid BIP-CMAC-128 MMIE under an installed
/// IGTK with an advancing IPN. Dropped frames change no state.
pub(super) fn ap_disconnected(
    mpdu: &scan_api::Mpdu<'_>,
    local: [u8; 6],
    bssid: [u8; 6],
    channel: u8,
    pmf: Option<&mut PmfRx>,
) -> bool {
    let f = mpdu.frame;
    if mpdu.channel != channel
        || f.len() < 24
        || !matches!(f[0], 0xa0 | 0xc0)
        || f[1] & 0x87 != 0
        || f[10..16] != bssid
        || f[16..22] != bssid
        || f[22] & 15 != 0
        || mpdu.amsdu
    {
        return false;
    }
    let protected = f[1] & 0x40 != 0;
    let Some(pmf) = pmf else {
        return !protected && f[4..10] == local && mpdu.body(24, 0).is_some_and(|b| b.len() == 2);
    };
    if f[4..10] == local {
        if !protected || mpdu.status & (0x1f000000 | 0xf4c) != 0xa4c {
            return false;
        }
        // CCMP header: PN0 PN1 rsvd (ExtIV|KeyID0) PN2..PN5.
        let Some(iv) = f.get(24..32).filter(|iv| iv[3] == 0x20) else {
            return false;
        };
        let pn = u64::from_le_bytes([iv[0], iv[1], iv[4], iv[5], iv[6], iv[7], 0, 0]);
        if pn <= pmf.mgmt_pn || mpdu.body(24, 8).is_none_or(|b| b.len() != 2) {
            return false;
        }
        pmf.mgmt_pn = pn;
        return true;
    }
    if f[4..10] != [0xff; 6] || protected || mpdu.status & 0xf40 != 0 {
        return false;
    }
    mpdu.body(24, 0)
        .filter(|b| b.len() == 20)
        .is_some_and(|body| {
            narf_wireless::mfp::verify_inbound(&mut pmf.mfp, &f[..24], body)
                .is_ok_and(|reason| reason.len() == 2)
        })
}

/// The SAE session of a JoinPlan, built from the driver's own entropy
/// (wpa_supplicant `sae_pwe` method chosen by the plan).
pub(super) fn fresh_session(
    join: &SaeJoin,
    ssid: &[u8],
    password: &[u8],
    own: [u8; 6],
    peer: [u8; 6],
) -> Result<SaeSession, &'static str> {
    let session = if join.h2e() {
        SaeSession::new_h2e_bytes(ssid, password, own, peer)
    } else {
        SaeSession::new_hunt_and_peck(password, own, peer)
    };
    let mut session = match join.akm_suite_selector() {
        Some(selector) => session
            .with_akm_suite_selector(selector)
            .map_err(|_| "MVM SAE AKM selector refused")?,
        None => session,
    };
    session
        .try_build_commit()
        .map_err(|_| "MVM SAE commit entropy unavailable")?;
    Ok(session)
}

impl Owner {
    /// The PMF association contract this Gen2 owner implements: the native
    /// key API (CCMP station keys) plus the MGMT_MCAST_KEY IGTK command.
    pub(in crate::iwlwifi) fn station_sae_supported(&self) -> bool {
        self.security_api().is_ok()
    }

    /// Host WPA3-SAE authentication with the observed AP. Like
    /// [`Self::authenticate_open`], the peer is disabled again before any
    /// result is published; nothing here grants association or keys.
    pub async fn authenticate_sae(
        &mut self,
        ssid: &[u8],
        password: &[u8],
    ) -> Result<AuthenticationStatus, &'static str> {
        let password = Zeroizing::new(password.to_vec());
        let ssid_owned = ssid.to_vec();
        self.authenticate_sae_using(
            ssid,
            &[],
            SaePwe::Both,
            |join, own, peer| fresh_session(join, &ssid_owned, &password, own, peer),
            || {
                narf_wireless::reg::db::get_domain()
                    .ok_or("MVM current authentication policy unavailable")
            },
        )
        .await
    }

    pub(super) async fn authenticate_sae_using(
        &mut self,
        ssid: &[u8],
        elements: &[u8],
        pwe: SaePwe,
        session: impl FnOnce(&SaeJoin, [u8; 6], [u8; 6]) -> Result<SaeSession, &'static str>,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<AuthenticationStatus, &'static str> {
        let link = self
            .prepared_active_link()
            .ok_or("MVM SAE requires active link")?;
        let queue = self
            .prepared_management_queue()
            .ok_or("missing SAE authentication queue")?;
        let local = self.mac.ok_or("missing SAE authentication MAC")?;
        if !self.hardware.idle_tx_binding(queue, 0, 15)
            || self.hardware.version(1, 0x18) != Some((12, 2))
            || !self.station_sae_supported()
        {
            return Err("MVM SAE peer/queue/key contract no longer matches");
        }
        let beacon = self
            .beacons
            .iter()
            .find(|b| b.bssid == link.bssid && b.channel == link.channel)
            .ok_or("missing original SAE BSS")?;
        let bss = Bss {
            bssid: beacon.bssid,
            ssid: beacon.ssid.clone(),
            channel: beacon.channel,
            band: None,
            signal_dbm: None,
            capability: beacon.capabilities,
            beacon_interval: beacon.interval,
            information_elements: beacon.information_elements.clone(),
        };
        let rate = self.authentication_rate(&bss.information_elements, link.channel)?;
        let mut plan = self.station_plan(
            &bss,
            ssid,
            SecurityMode::Wpa3Sae { pwe },
            elements,
            self.power.phy.offered.is_some(),
        )?;
        let join = plan.sae().ok_or("MVM SAE plan absent")?;
        // The native 4-way owner implements AKM 8 (SHA-256 KDF, AES-CMAC
        // MIC). SAE-EXT-KEY (AKM 24) needs its variable-length KDF.
        if join.akm() != KeyMgmt::Sae {
            return Err("MVM SAE-EXT-KEY (AKM 24) is not implemented");
        }
        let mut sae = session(join, local, link.bssid)?;
        let commit = plan
            .start_sae_authentication(&sae)
            .map_err(|_| "MVM SAE commit refused by plan")?
            .to_vec();
        self.check_link_power(&policy()?)?;
        self.phase = Phase::Authenticating;
        let result = self
            .authenticate_sae_inner(
                local,
                link.bssid,
                link.channel,
                queue,
                rate,
                commit,
                &mut plan,
                &mut sae,
                &mut policy,
            )
            .await;
        match result {
            Ok((status, retained)) => {
                if let Some((request, sequence)) = retained {
                    let pmk = Zeroizing::new(*sae.pmk().ok_or("MVM SAE produced no PMK")?);
                    self.power.prepared.as_mut().unwrap().mlme.sae =
                        Some(Box::new(SaeAuthenticated {
                            status,
                            ssid: ssid.to_vec(),
                            plan,
                            request,
                            pmk,
                            sequence,
                        }));
                }
                self.phase = Phase::LinkActive;
                Ok(status)
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn authenticate_sae_inner(
        &mut self,
        local: [u8; 6],
        bssid: [u8; 6],
        channel: u8,
        queue: u16,
        rate: u32,
        commit: Vec<u8>,
        plan: &mut JoinPlan,
        sae: &mut SaeSession,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(AuthenticationStatus, Option<(Vec<u8>, u16)>), &'static str> {
        if let Some((version, request)) = self.mcc_request()? {
            let reply = self
                .qualified_link_command(1, 0xc8, &request, policy)
                .await?;
            self.accept_mcc(version, &reply)?;
        }
        self.check_link_power(&policy()?)?;
        self.hardware.discard_key_transition_rx()?;
        let reply = self
            .qualified_link_command(1, 0x18, &super::auth::disable_tx(false), policy)
            .await?;
        if reply.len() != 4 || u32::from_le_bytes(reply[..4].try_into().unwrap()) & 0xff != 1 {
            return Err("MVM SAE peer-enable status failed");
        }
        let mut frame = commit;
        let mut sequence = 0u16;
        let mut outcome = Err(0);
        'exchange: for _ in 0..MAX_SAE_FRAMES {
            frame[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
            sequence += 1;
            self.check_link_power(&policy()?)?;
            self.qualified_management_transmit(queue, &frame, rate, policy)
                .await?;
            loop {
                let (_, response) = self
                    .authentication_response(local, bssid, channel, 3, policy)
                    .await?;
                match plan.sae_authentication_response(&response, sae) {
                    Ok(SaeStep::Ignored) => continue,
                    Ok(SaeStep::Transmit(next)) => {
                        frame = next.to_vec();
                        continue 'exchange;
                    }
                    Ok(SaeStep::Associate(request)) => {
                        outcome = Ok(request.to_vec());
                        break 'exchange;
                    }
                    Err(narf_wireless::association::Error::Rejected(code)) => {
                        outcome = Err(code);
                        break 'exchange;
                    }
                    Err(_) => return Err("MVM SAE protocol failure"),
                }
            }
        }
        if outcome == Err(0) {
            return Err("MVM SAE frame budget exhausted");
        }
        let reply = self
            .hardware
            .command_with_header_version(1, 0x18, &super::auth::disable_tx(true), 0)
            .await?;
        if reply.payload.len() != 4
            || u32::from_le_bytes(reply.payload[..4].try_into().unwrap()) & 0xff != 1
            || !self.hardware.idle_tx_binding(queue, 0, 15)
        {
            return Err("MVM SAE peer-disable/queue receipt failed");
        }
        self.check_link_power(&policy()?)?;
        let status = AuthenticationStatus {
            bssid,
            channel,
            status: *outcome.as_ref().err().unwrap_or(&0),
        };
        Ok((status, outcome.ok().map(|request| (request, sequence))))
    }

    /// Association after a retained SAE exchange: the plan's own request
    /// (RSNE with the SAE PMKID) is sent; the response is checked by the
    /// same plan. PMF and the PMK are retained for the native 4-way owner.
    pub(super) async fn associate_sae_using(
        &mut self,
        local: [u8; 6],
        queue: u16,
        timing: (u16, u8),
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<AssociationStatus, &'static str> {
        let active = self
            .prepared_active_link()
            .ok_or("association requires active link")?;
        let retained = self
            .power
            .prepared
            .as_mut()
            .and_then(|p| p.mlme.sae.take())
            .ok_or("missing actual retained SAE authentication")?;
        if retained.status.bssid != active.bssid
            || retained.status.channel != active.channel
            || retained.status.status != 0
        {
            return Err("SAE authentication differs from association context");
        }
        let SaeAuthenticated {
            plan,
            request,
            pmk,
            sequence,
            ..
        } = *retained;
        let mut frame = request;
        if self.power.phy.offered.is_some() {
            if frame.len() + narf_wireless::wmm::INFORMATION.len() > 4096 {
                return Err("MVM WMM request extent exceeded");
            }
            frame.extend_from_slice(&narf_wireless::wmm::INFORMATION);
        }
        frame[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
        let beacon = self
            .beacons
            .iter()
            .find(|b| b.bssid == active.bssid && b.channel == active.channel)
            .ok_or("association BSS missing")?;
        let rate = self.authentication_rate(&beacon.information_elements, active.channel)?;
        self.check_link_power(&policy()?)?;
        let mlme = &mut self.power.prepared.as_mut().unwrap().mlme;
        mlme.authenticated = None;
        mlme.plan = Some(plan);
        mlme.prepared = None;
        mlme.sae_pmk = Some(pmk);
        self.phase = Phase::Associating;
        self.finish_association(local, queue, &frame, rate, timing.0, timing.1, policy)
            .await
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_pmf_tests.rs"]
pub(super) mod tests;

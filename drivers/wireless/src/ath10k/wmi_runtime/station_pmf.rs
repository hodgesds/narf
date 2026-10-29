// SPDX-License-Identifier: GPL-2.0-or-later
//! WPA2-PMF and WPA3-SAE association material. SAE runs on the host over
//! the initial management transport through the shared `JoinPlan` state
//! machine (wpa_supplicant `sme_sae_auth` over mac80211 `ieee80211_auth`);
//! robust management protection is the software CCMP/BIP owner's
//! (`station_security::Security`), since this RAW image disables firmware
//! crypto (Linux v7.2 core.c `ATH10K_CRYPT_MODE_SW`).
use super::*;
use alloc::boxed::Box;
use narf_wireless::association::{AkmSet, JoinOptions, JoinPlan, Pmf, SaeStep, SecurityMode};
use zeroize::Zeroizing;

/// The negotiated station RSNE/RSNXE (repeated in EAPOL message 2/4) and
/// the SAE PMK, retained from association until the data owner starts.
pub(in crate::ath10k) struct Rsn {
    pub(in crate::ath10k) rsne: Vec<u8>,
    pub(in crate::ath10k) rsnxe: Option<Vec<u8>>,
    pub(in crate::ath10k) sae_pmk: Option<Zeroizing<[u8; 32]>>,
    /// Both RSNEs set MFPC (`JoinPlan::pmf`): robust frames are protected.
    pub(in crate::ath10k) pmf: bool,
}
impl core::fmt::Debug for Rsn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rsn")
            .field("pmf", &self.pmf)
            .field("sae", &self.sae_pmk.is_some())
            .finish_non_exhaustive()
    }
}
impl Rsn {
    pub(super) fn bind(
        plan: &JoinPlan,
        sae_pmk: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<Option<Box<Self>>, Error> {
        let Some(rsne) = plan.rsn_body() else {
            return if sae_pmk.is_some() {
                Err(Error::Malformed)
            } else {
                Ok(None)
            };
        };
        Ok(Some(Box::new(Self {
            rsne,
            rsnxe: plan.sae().and_then(|s| s.station_rsnxe()),
            sae_pmk,
            pmf: plan.pmf(),
        })))
    }
}

/// RSN Capabilities of the AP's scanned RSNE, if it has one.
fn ap_rsn_capabilities(mut ies: &[u8]) -> Result<Option<u16>, Error> {
    while !ies.is_empty() {
        let h = ies.get(..2).ok_or(Error::Malformed)?;
        let body = ies.get(2..2 + usize::from(h[1])).ok_or(Error::Malformed)?;
        if h[0] == 48 {
            return Ok(narf_wireless::rsn::RsnIe::decode_body(body).map(|r| r.rsn_capabilities));
        }
        ies = &ies[2 + body.len()..];
    }
    Ok(None)
}

/// Join options for the key path this owner implements. WPA3 offers every
/// SAE AKM (the plan selects 8, or 24 under H2E). WPA2 advertises MFPC
/// (wpa_supplicant `ieee80211w=1`) only toward an AP that sets MFPC, where
/// PMF then comes into force; toward any other AP the request is unchanged.
pub(super) fn options(security: SecurityMode, ies: &[u8]) -> Result<JoinOptions, Error> {
    Ok(match security {
        SecurityMode::Open => JoinOptions::default(),
        SecurityMode::Wpa3Sae { .. } => JoinOptions::default().with_akms(AkmSet::ALL),
        SecurityMode::Wpa2Psk => match ap_rsn_capabilities(ies)? {
            Some(caps) if caps & narf_wireless::rsn::RSN_CAP_MFP_CAPABLE != 0 => {
                JoinOptions::default()
                    .with_akms(AkmSet::ALL)
                    .with_pmf(Pmf::Optional)
            }
            _ => JoinOptions::default(),
        },
    })
}

/// Commit, up to three anti-clogging Commits and Confirm, plus silently
/// discarded peer frames, bound one SAE attempt.
const SAE_STEPS: usize = 16;

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    /// Host SAE: a Commit from the kernel CSPRNG, bounded anti-clogging
    /// retries and Confirm through the shared plan, returning the SAE
    /// association request and PMK. The boxed session (password element,
    /// scalars) is dropped here.
    pub(super) async fn authenticate_sae(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        plan: &mut JoinPlan,
        ssid: &[u8],
        password: &[u8],
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), Error> {
        use narf_wireless::sae::SaeSession;
        let join = plan.sae().ok_or(Error::Unsupported)?;
        let own = self.ready.ok_or(Error::Failed)?.mac;
        let bssid = self.peer.as_ref().ok_or(Error::Failed)?.bssid;
        let session = if join.h2e() {
            SaeSession::new_h2e_bytes(ssid, password, own, bssid)
        } else {
            SaeSession::new_hunt_and_peck(password, own, bssid)
        };
        let session = match join.akm_suite_selector() {
            Some(selector) => session
                .with_akm_suite_selector(selector)
                .map_err(|_| Error::Unsupported)?,
            None => session,
        };
        let mut session = Box::new(session);
        session.try_build_commit().map_err(|_| Error::Failed)?;
        let mut frame = Some(wire::owned(
            plan.start_sae_authentication(&session)
                .map_err(plan_error)?,
        )?);
        for _ in 0..SAE_STEPS {
            let response = checked_policy(
                self.exchange_management(domain, frame.as_deref(), true),
                validate,
            )
            .await?;
            // Any plan error is terminal for this owner.
            self.failed = true;
            match plan
                .sae_authentication_response(&response, &mut session)
                .map_err(plan_error)?
            {
                SaeStep::Ignored => frame = None,
                SaeStep::Transmit(next) => frame = Some(wire::owned(next)?),
                SaeStep::Associate(request) => {
                    let request = wire::owned(request)?;
                    let pmk = Zeroizing::new(*session.pmk().ok_or(Error::Malformed)?);
                    self.peer.as_mut().ok_or(Error::Failed)?.exchange_stage = 1;
                    self.failed = false;
                    return Ok((request, pmk));
                }
            }
            self.failed = false;
        }
        self.failed = true;
        Err(Error::Exhausted)
    }
}

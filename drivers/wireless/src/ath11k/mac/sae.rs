//! WPA3-SAE authentication for the station: wpa_supplicant's SME
//! (`sme_send_authentication` → `sme_auth_build_sae_commit` /
//! `sme_auth_build_sae_confirm`, `sme_sae_auth`) over mac80211's
//! `ieee80211_auth` / `ieee80211_rx_mgmt_auth` (Authentication frames
//! with algorithm 3, `IEEE80211_AUTH_MAX_TRIES` tries per frame, the TX
//! status wait `IEEE80211_AUTH_TIMEOUT_LONG` and, once acked,
//! `IEEE80211_AUTH_TIMEOUT_SAE` for the answer), on the shared
//! `narf_wireless::sae::SaeSession` (pinned to IEEE 802.11-2020 Annex
//! J.10).
//!
//! PWE: Hash-to-Element when the AP's RSNXE has `SAE_H2E` (Commit status
//! 126), hunting and pecking otherwise (status 0) — wpa_supplicant with
//! `sae_pwe=2` (both). Group 19 only (wpa_supplicant's default list is
//! 19, 20, 21; NARF has P-256 only, so a status 77 ends the attempt).
//! No SAE-PK (status 127), no password identifiers, no FT-SAE (AKM 9
//! needs FT authentication with MDE / FTE and the R0KH / R1KH key
//! hierarchy, which NARF does not have).

extern crate alloc;

use alloc::vec::Vec;

use narf_wireless::sae::{SaeError, SaeSession, SaeState};

use super::super::mac_frame::{self as frame, stype};
use super::sec::RsnPlan;
use super::{errno, fail, step, DataPort, Mac, MacError, ScanBss, WmiPort};

/// `WLAN_AUTH_SAE`.
pub const WLAN_AUTH_SAE: u16 = 3;
/// `WLAN_STATUS_ANTI_CLOGGING_TOKEN_REQ`, `_FINITE_CYCLIC_GROUP_NOT_SUPPORTED`,
/// `_SAE_HASH_TO_ELEMENT`, `_SAE_PK`.
pub const WLAN_STATUS_ANTI_CLOGGING_TOKEN_REQ: u16 = 76;
pub const WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED: u16 = 77;
pub const WLAN_STATUS_SAE_HASH_TO_ELEMENT: u16 = 126;
pub const WLAN_STATUS_SAE_PK: u16 = 127;
/// `IEEE80211_AUTH_TIMEOUT_SAE` (ms).
pub const AUTH_TIMEOUT_SAE: u32 = 2000;
/// NARF-only bound on anti-clogging rounds (wpa_supplicant resends the
/// Commit for every token request).
pub const MAX_ANTI_CLOGGING: u32 = 3;

/// `ieee80211_send_auth(sdata, trans, WLAN_AUTH_SAE, status, data, …)`.
pub fn build_auth_sae(
    own: &[u8; 6],
    bssid: &[u8; 6],
    trans: u16,
    status: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut f = frame::mgmt_hdr(stype::AUTH, bssid, own, bssid);
    f.extend_from_slice(&WLAN_AUTH_SAE.to_le_bytes());
    f.extend_from_slice(&trans.to_le_bytes());
    f.extend_from_slice(&status.to_le_bytes());
    f.extend_from_slice(data);
    f
}

/// The token of an anti-clogging request (`sme_sae_auth`): after the
/// group, an Anti-Clogging Token Container for H2E, the rest otherwise.
pub fn anti_clogging_token(data: &[u8], h2e: bool) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }
    let t = &data[2..];
    if !h2e {
        return Some(t.to_vec());
    }
    // id 255, len, ext 93: "Invalid SAE anti-clogging token container header"
    if t.len() < 3 || t[0] != 0xFF || t[1] == 0 || t[1] as usize > t.len() - 2 || t[2] != 93 {
        return None;
    }
    Some(t[3..2 + t[1] as usize].to_vec())
}

/// [`build_auth_sae`]'s Commit status for the PWE mode.
fn commit_status(h2e: bool) -> u16 {
    if h2e {
        WLAN_STATUS_SAE_HASH_TO_ELEMENT
    } else {
        frame::WLAN_STATUS_SUCCESS
    }
}

/// An SAE Authentication frame (algorithm, transaction, status, body).
fn parse_sae(f: &[u8]) -> Option<(u16, u16, &[u8])> {
    let a = frame::parse_auth(f)?;
    (a.alg == WLAN_AUTH_SAE).then(|| (a.transaction, a.status, &f[frame::MGMT_HDR_LEN + 6..]))
}

impl<P: WmiPort, D: DataPort> Mac<P, D> {
    /// SAE authentication; returns the PMK.
    pub(super) async fn sae_authenticate(
        &mut self,
        bss: &ScanBss,
        plan: &RsnPlan,
        password: &[u8],
    ) -> Result<[u8; 32], MacError> {
        let own = self.caps.mac_addr;
        let bssid = bss.bssid;
        let h2e = plan.sae_h2e;
        let ssid = bss.ssid();
        let mut sae = if h2e {
            SaeSession::new_h2e_bytes(&ssid, password, own, bssid)
        } else {
            SaeSession::new_hunt_and_peck(password, own, bssid)
        };
        // dragonfly_generate_scalar's randomness from get_random_bytes.
        let mut seed = [0u8; 64];
        self.wmi.random_bytes(&mut seed);
        sae = sae.with_test_seed(seed);
        let commit = sae.build_commit();
        if commit.is_empty() {
            // "SAE: Could not pick PWE"
            return fail(step::SAE_PWE, 0, errno::EINVAL, "SAE (PWE)");
        }
        let mut token: Option<Vec<u8>> = None;
        let mut rounds = 0;
        // ── Commit ──
        loop {
            let body = sae.commit_body(token.as_deref());
            let f = build_auth_sae(&own, &bssid, 1, commit_status(h2e), &body);
            let r = self
                .mlme_exchange(
                    &f,
                    step::AUTH_TX,
                    step::SAE_TIMEOUT,
                    "SAE commit",
                    AUTH_TIMEOUT_SAE,
                    |r| parse_sae(r).is_some_and(|(t, _, _)| t == 1 || t == 2),
                )
                .await?;
            let (trans, status, data) = parse_sae(&r).unwrap();
            if trans == 1 && status == WLAN_STATUS_ANTI_CLOGGING_TOKEN_REQ {
                rounds += 1;
                if rounds > MAX_ANTI_CLOGGING {
                    return fail(
                        step::SAE_REJECTED,
                        status as u32,
                        errno::ECONNREFUSED,
                        "SAE (anti-clogging)",
                    );
                }
                // sae_group_allowed on the requested group.
                if data.len() < 2 || u16::from_le_bytes([data[0], data[1]]) != 19 {
                    return fail(
                        step::SAE_COMMIT,
                        1,
                        errno::EPROTO,
                        "SAE (anti-clogging group)",
                    );
                }
                let Some(t) = anti_clogging_token(data, h2e) else {
                    return fail(step::SAE_COMMIT, 2, errno::EPROTO, "SAE (token container)");
                };
                token = Some(t);
                continue;
            }
            if status != frame::WLAN_STATUS_SUCCESS
                && status != WLAN_STATUS_SAE_HASH_TO_ELEMENT
                && status != WLAN_STATUS_SAE_PK
            {
                // Group not supported (no other group enabled) or a reject.
                return fail(
                    step::SAE_REJECTED,
                    status as u32,
                    errno::ECONNREFUSED,
                    "SAE (rejected)",
                );
            }
            if trans != 1 {
                // ieee80211_rx_mgmt_auth passes a Confirm through; the SME
                // is not in CONFIRMED and fails it.
                return fail(
                    step::SAE_COMMIT,
                    3,
                    errno::EPROTO,
                    "SAE (confirm before commit)",
                );
            }
            // "Unexpected use of status code …"
            if (h2e && status == frame::WLAN_STATUS_SUCCESS)
                || (!h2e && status == WLAN_STATUS_SAE_HASH_TO_ELEMENT)
                || status == WLAN_STATUS_SAE_PK
            {
                return fail(step::SAE_COMMIT, 4, errno::EPROTO, "SAE (commit status)");
            }
            match sae.on_commit(data) {
                Ok(()) => break,
                // SAE_SILENTLY_DISCARD: wait for the retransmission.
                Err(SaeError::Reflection) => continue,
                Err(_) => return fail(step::SAE_COMMIT, 5, errno::EPROTO, "SAE (peer commit)"),
            }
        }
        // ── Confirm ──
        let confirm = sae.build_confirm();
        let f = build_auth_sae(&own, &bssid, 2, frame::WLAN_STATUS_SUCCESS, &confirm);
        let r = self
            .mlme_exchange(
                &f,
                step::AUTH_TX,
                step::SAE_TIMEOUT,
                "SAE confirm",
                AUTH_TIMEOUT_SAE,
                |r| parse_sae(r).is_some_and(|(t, _, _)| t == 2),
            )
            .await?;
        let (_, status, data) = parse_sae(&r).unwrap();
        if status != frame::WLAN_STATUS_SUCCESS {
            return fail(
                step::SAE_REJECTED,
                status as u32,
                errno::ECONNREFUSED,
                "SAE (confirm rejected)",
            );
        }
        if sae.on_confirm(data).is_err() || sae.state() != SaeState::Accepted {
            return fail(step::SAE_CONFIRM, 0, errno::EPROTO, "SAE (confirm)");
        }
        Ok(*sae.pmk().unwrap())
    }
}

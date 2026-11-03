//! Connection profiles retained across a driver's automatic recovery.
//!
//! Linux keeps the `net_device` across `ieee80211_restart_hw`; mac80211's
//! `ieee80211_reconfig` reprograms the restarted firmware from host state,
//! and a driver that cannot keep the association asks for
//! `IEEE80211_SDATA_DISCONNECT_HW_RESTART`, so `ieee80211_sta_restart`
//! reports `ieee80211_sta_connection_lost` and wpa_supplicant reconnects
//! from the network block it still holds (SSID, PSK/SAE password, the BSS
//! it last used): scan, then authenticate/associate and a fresh RSNA.
//!
//! In NARF a recovered generation is a new driver object behind the same
//! rebound `wlan%d` name, so the in-kernel connection owner keeps that
//! network block here, keyed by the netdev name: a driver [`retain`]s the
//! profile of an association that completed, [`forget`]s it when the
//! operator disconnects or the link was already down when the generation
//! retired, and the successor generation [`take`]s it once to reconnect.
//! Secrets live in zeroizing storage and are copied out only into the
//! [`AssociateRequest`] handed back to the driver's own associate path.
//! External-supplicant associations are never retained: that supplicant
//! owns its own reconnection, as wpa_supplicant does on Linux.
//!
//! A name alone is not an identity: another device or driver may later
//! register the same `wlan%d`. Each profile is therefore bound to the
//! [`Owner`] that retained it (driver family + permanent MAC, the identity
//! mac80211 keeps in `wiphy->perm_addr` across `ieee80211_restart_hw`), and
//! [`take`] by any other owner destroys (zeroizes) it instead of handing the
//! credential over.
use crate::{AssociateRequest, SecurityConfig};
use alloc::{string::String, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;
use zeroize::Zeroizing;

/// The retained credential of an in-kernel RSNA.
enum Credential {
    Open,
    Psk(Zeroizing<[u8; 32]>),
    Sae(Zeroizing<Vec<u8>>),
}

/// One retained network block: the BSS, SSID, credential and SME elements
/// of an association that completed.
pub struct Profile {
    bssid: [u8; 6],
    ssid: Vec<u8>,
    frequency_mhz: u32,
    channel: u32,
    credential: Credential,
    ie: Vec<u8>,
}

impl Profile {
    /// The profile of `request`; `None` for an external supplicant or an
    /// empty SAE password, neither of which the in-kernel owner can replay.
    pub fn capture(request: &AssociateRequest) -> Option<Self> {
        let credential = match &request.security {
            SecurityConfig::Open => Credential::Open,
            SecurityConfig::Wpa2 { psk } => Credential::Psk(Zeroizing::new(*psk)),
            SecurityConfig::Wpa3 { password } if !password.is_empty() => {
                Credential::Sae(Zeroizing::new(password.clone()))
            }
            _ => return None,
        };
        Some(Self {
            bssid: request.bssid,
            ssid: request.ssid.clone(),
            frequency_mhz: request.frequency_mhz,
            channel: request.channel,
            credential,
            ie: request.ie.clone(),
        })
    }
    pub fn bssid(&self) -> [u8; 6] {
        self.bssid
    }
    pub fn ssid(&self) -> &[u8] {
        &self.ssid
    }
    pub fn frequency_mhz(&self) -> u32 {
        self.frequency_mhz
    }
    pub fn channel(&self) -> u32 {
        self.channel
    }
    /// A fresh association request for the retained BSS and credential.
    pub fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: self.bssid,
            ssid: self.ssid.clone(),
            frequency_mhz: self.frequency_mhz,
            channel: self.channel,
            security: match &self.credential {
                Credential::Open => SecurityConfig::Open,
                Credential::Psk(psk) => SecurityConfig::Wpa2 { psk: **psk },
                Credential::Sae(password) => SecurityConfig::Wpa3 {
                    password: password.to_vec(),
                },
            },
            ie: self.ie.clone(),
        }
    }
}

/// The device a profile belongs to: the retaining driver family and the
/// radio's permanent MAC address. A rebinding generation of the same radio
/// presents the same identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub family: &'static str,
    pub permanent_mac: [u8; 6],
}

type Entry = (String, Owner, Profile);
static PROFILES: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

/// Keep `profile` for `name` on behalf of `owner`, replacing an older one.
pub fn retain(name: &str, owner: Owner, profile: Profile) {
    let old = {
        let mut profiles = PROFILES.lock();
        let old = profiles
            .iter()
            .position(|(n, _, _)| n == name)
            .map(|at| profiles.swap_remove(at));
        profiles.push((String::from(name), owner, profile));
        old
    };
    drop(old);
}

/// Drop any profile for `name` (operator disconnect, or no link to restore).
pub fn forget(name: &str) {
    let old = {
        let mut profiles = PROFILES.lock();
        profiles
            .iter()
            .position(|(n, _, _)| n == name)
            .map(|at| profiles.swap_remove(at))
    };
    drop(old);
}

/// Take the profile `owner` retained for `name`; each profile is replayed
/// once. A profile retained by a different owner is removed and zeroized,
/// never returned.
pub fn take(name: &str, owner: Owner) -> Option<Profile> {
    let (_, retained_by, profile) = {
        let mut profiles = PROFILES.lock();
        let at = profiles.iter().position(|(n, _, _)| n == name)?;
        profiles.swap_remove(at)
    };
    if retained_by != owner {
        drop(profile);
        return None;
    }
    Some(profile)
}

/// Whether `owner` has a profile retained for `name`.
pub fn retained(name: &str, owner: Owner) -> bool {
    PROFILES
        .lock()
        .iter()
        .any(|(n, o, _)| n == name && *o == owner)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "reconnect_tests.rs"]
mod tests;

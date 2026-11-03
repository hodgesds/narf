// SPDX-License-Identifier: GPL-2.0-or-later
//! Secondary-bsscfg station construction and runtime rebinding.
//!
//! A secondary station is the same `Station` state machine as the primary,
//! addressed through `brcmfmac::vif_bsscfg::Bsscfg` (`struct brcmf_if` of
//! its own ifidx/bsscfgidx). Device-wide state the primary established at
//! `brcmf_config_dongle` time (CLM, country, regulatory policy, bus
//! aggregation, `roam_off`, firmware capabilities) is shared, never
//! re-issued; per-interface state starts empty, as a freshly created
//! firmware bsscfg is. Its events join the composed `event_msgs` union
//! (`brcmfmac::event_mask`).
use super::*;
use crate::brcmfmac::vif_bsscfg::Parked;

/// `BRCMF_C_SET_INFRA` / `BRCMF_C_SET_AUTH` (`fwil_types.h`).
const SET_INFRA: u32 = 20;
const SET_AUTH: u32 = 22;

impl<R: Fullmac> Station<R> {
    /// Move the role state onto another runtime, returning the old one.
    /// The state machine, cache and grants are unchanged.
    pub(crate) fn rebind<S: Fullmac>(self, runtime: S) -> (Station<S>, R) {
        let Station {
            runtime: old,
            mac,
            channels,
            domain,
            policy,
            connection,
            bssid,
            cache,
            scan_id,
            supplicant,
            mfp_supported,
            sae_offload,
            firmware_roaming,
            roam,
            external,
            protection,
            pmkid_v3,
            pmksa,
            mfp_verified,
            phy,
            ht_verified,
            vht_verified,
            power_save,
            operation,
            probe_ies,
            ac_priority,
        } = self;
        (
            Station {
                runtime,
                mac,
                channels,
                domain,
                policy,
                connection,
                bssid,
                cache,
                scan_id,
                supplicant,
                mfp_supported,
                sae_offload,
                firmware_roaming,
                roam,
                external,
                protection,
                pmkid_v3,
                pmksa,
                mfp_verified,
                phy,
                ht_verified,
                vht_verified,
                power_save,
                operation,
                probe_ies,
                ac_priority,
            },
            old,
        )
    }

    /// Idle parked station for the secondary bsscfg whose IF ADD address is
    /// `mac`, sharing this primary's device-wide capabilities and policy.
    /// No connection, cache, PMKSA, key or PHY verification is inherited.
    pub(crate) fn secondary(&self, mac: [u8; 6]) -> Station<Parked<R>> {
        Station {
            runtime: Parked::new(),
            mac,
            channels: self.channels.clone(),
            domain: self.domain.clone(),
            policy: self.policy.clone(),
            connection: None,
            bssid: None,
            cache: Vec::new(),
            scan_id: 0,
            supplicant: self.supplicant,
            mfp_supported: self.mfp_supported,
            sae_offload: self.sae_offload,
            // roam_off is device-wide (brcmf_dongle_roam on the primary).
            firmware_roaming: self.firmware_roaming,
            roam: None,
            external: None,
            protection: None,
            pmkid_v3: self.pmkid_v3,
            // A new firmware bsscfg starts with an empty pmkid_info list.
            pmksa: Some(pmksa::Cache::default()),
            mfp_verified: false,
            phy: self.phy.clone(),
            ht_verified: false,
            vht_verified: false,
            power_save: false,
            operation: false,
            probe_ies: Vec::new(),
            ac_priority: wmm::DEFAULT_AC_PRIORITY,
        }
    }

    /// Per-interface dcmds the primary issues at initialization, addressed
    /// to this bsscfg's ifidx (`brcmf_cfg80211_change_iface` SET_INFRA,
    /// `brcmf_cfg80211_set_power_mgmt` PM off, open-system SET_AUTH).
    pub(crate) async fn configure_secondary(&mut self) -> Result<(), Error> {
        set_int(&mut self.runtime, ioctl::WLC_SET_PM, 0).await?;
        set_int(&mut self.runtime, SET_INFRA, 1).await?;
        set_int(&mut self.runtime, SET_AUTH, 0).await?;
        // This bsscfg's STA events join the device-wide union; written
        // only when they add bits (beside a primary AP, which consumes
        // only AP events). Removal clears the need (`vif_owner::remove`).
        write_events(
            &mut self.runtime,
            roam::event_mask(self.firmware_roaming),
            false,
        )
        .await?;
        self.power_save = false;
        Ok(())
    }

    /// The station has neither a link nor an operation in progress.
    pub(crate) fn idle(&self) -> bool {
        !self.operation
            && self.bssid.is_none()
            && self.roam.is_none()
            && self.connection.is_none()
            && self.external.is_none()
    }
}

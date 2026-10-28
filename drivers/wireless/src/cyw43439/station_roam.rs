// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware-internal roaming for the common FullMAC station.
//!
//! Linux brcmfmac `cfg80211.c::brcmf_dongle_roam` configures the firmware
//! roaming engine (`bcn_timeout` 2 with roaming, 4 without; `roam_off`;
//! `BRCMF_C_SET_ROAM_TRIGGER` {-75 dBm, BRCM_BAND_ALL};
//! `BRCMF_C_SET_ROAM_DELTA` {20, BRCM_BAND_ALL}). `brcmf_notify_roaming_status`
//! handles `BRCMF_E_ROAM`/`SUCCESS` while connected with
//! `brcmf_bss_roaming_done`: the new BSSID is the event address, the
//! association IEs are re-read and `BRCMF_C_GET_BSS_INFO` yields the new
//! chanspec before `cfg80211_roamed`. A firmware supplicant re-keys the new
//! AP and reports `BRCMF_E_PSK_SUP`/`FWSUP_COMPLETED` (`brcmf_is_linkup`).
//!
//! NARF keeps its stricter port contract: the roam event closes the host
//! port at once; it reopens only after the new peer is confirmed by
//! `WLC_GET_BSSID`, its firmware chanspec is admitted by current
//! regulatory policy under a fresh TX grant (with `qtxpower` re-applied to
//! that grant), the firmware supplicant confirmed keys, PMF is re-verified
//! from the new association elements and WMM is re-ranked. Late events from
//! the old peer are ignored as Linux ignores link-down for another BSSID.
use super::{
    channel, events, ioctl, occupied_power, policy::TxGrant, set_var, Error, Fullmac, Station,
};
use alloc::vec::Vec;

/// `cfg80211.h` `BRCMF_DEFAULT_BCN_TIMEOUT_ROAM_{ON,OFF}`.
pub const BCN_TIMEOUT_ROAM_ON: u32 = 2;
pub const BCN_TIMEOUT_ROAM_OFF: u32 = 4;
/// `cfg80211.h` `WL_ROAM_TRIGGER_LEVEL` / `WL_ROAM_DELTA`; `defs.h`
/// `BRCM_BAND_ALL`.
pub const ROAM_TRIGGER_LEVEL: i32 = -75;
pub const ROAM_DELTA: u32 = 20;
pub const BAND_ALL: u32 = 3;
/// `fwil.h` `BRCMF_C_SET_ROAM_TRIGGER` / `BRCMF_C_SET_ROAM_DELTA`.
pub const SET_ROAM_TRIGGER: u32 = 55;
pub const SET_ROAM_DELTA: u32 = 57;
/// `BRCMF_E_ROAM`.
pub const WLC_E_ROAM: u32 = 19;
/// Firmware roam plus re-keying budget (the association budget).
const ROAM_BUDGET_MS: u64 = 15_000;

#[derive(Debug)]
pub(super) struct Pending {
    pub(super) peer: [u8; 6],
    pub(super) keys: bool,
    deadline: narf_time::Deadline,
}

/// Completed roam for host publication (`cfg80211_roam_info`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Roamed {
    pub bssid: [u8; 6],
    pub frequency_mhz: u32,
    pub request_ies: Vec<u8>,
    pub response_ies: Vec<u8>,
}

/// Decode a firmware current chanspec into an occupied channel.
pub(super) fn occupied(chanspec: u16) -> Option<channel::Operating> {
    match chanspec & 0x3800 {
        0x1000 => channel::Operating::twenty(channel::primary(chanspec, 0)?)
            .filter(|op| op.chanspec() == chanspec),
        0x1800 => channel::Operating::decode40(chanspec),
        _ => channel::Operating::decode80(chanspec),
    }
}

impl<R: Fullmac> Station<R> {
    /// Enable or disable the firmware roaming engine (Linux `roamoff`
    /// module parameter, applied by `brcmf_dongle_roam`). Only while
    /// disconnected; the event mask gains or loses `BRCMF_E_ROAM`.
    pub async fn set_firmware_roaming(&mut self, enabled: bool) -> Result<(), Error> {
        if self.bssid.is_some() || self.roam.is_some() || self.operation {
            return Err(Error::Busy);
        }
        self.operation = true;
        let result = async {
            let timeout = if enabled {
                BCN_TIMEOUT_ROAM_ON
            } else {
                BCN_TIMEOUT_ROAM_OFF
            };
            set_var(&mut self.runtime, "bcn_timeout", &timeout.to_le_bytes()).await?;
            set_var(
                &mut self.runtime,
                "roam_off",
                &u32::from(!enabled).to_le_bytes(),
            )
            .await?;
            if enabled {
                let mut trigger = ROAM_TRIGGER_LEVEL.to_le_bytes().to_vec();
                trigger.extend_from_slice(&BAND_ALL.to_le_bytes());
                self.runtime
                    .command(ioctl::Direction::Set, SET_ROAM_TRIGGER, &trigger, 4)
                    .await?;
                let mut delta = ROAM_DELTA.to_le_bytes().to_vec();
                delta.extend_from_slice(&BAND_ALL.to_le_bytes());
                self.runtime
                    .command(ioctl::Direction::Set, SET_ROAM_DELTA, &delta, 4)
                    .await?;
            }
            set_var(&mut self.runtime, "event_msgs", &event_mask(enabled)).await
        }
        .await;
        self.operation = false;
        match result {
            Ok(()) => self.firmware_roaming = enabled,
            Err(_) => {
                // Partial roaming configuration is not a known policy.
                self.runtime.fail();
                self.runtime.set_link(None);
            }
        }
        result
    }

    pub fn firmware_roaming(&self) -> bool {
        self.firmware_roaming
    }

    /// A firmware roam is in progress: the host port is closed.
    pub fn roam_pending(&self) -> Option<[u8; 6]> {
        self.roam.as_ref().map(|r| r.peer)
    }

    /// Consume one event while connected or roaming. Returns `true` when the
    /// event was a roam transition (handled here).
    pub(super) fn roam_event(&mut self, event: &super::super::runtime::Event) -> bool {
        let header = &event.header;
        if let Some(pending) = self.roam.as_mut() {
            if header.source_mac != pending.peer {
                // Late old-peer link loss after the roam is ignored, exactly
                // as brcmf_notify_connect_status skips another BSSID.
                return true;
            }
            match header.event_type {
                events::WLC_E_PSK_SUP if header.status == 6 => pending.keys = true,
                events::WLC_E_PSK_SUP => {
                    self.roam = None;
                    self.close_roam_failure();
                }
                events::WLC_E_DEAUTH
                | events::WLC_E_DEAUTH_IND
                | events::WLC_E_DISASSOC
                | events::WLC_E_DISASSOC_IND => {
                    self.roam = None;
                    self.close_link();
                }
                events::WLC_E_LINK if header.flags & 1 == 0 => {
                    self.roam = None;
                    self.close_link();
                }
                _ => {}
            }
            return true;
        }
        if !self.firmware_roaming || header.event_type != WLC_E_ROAM || header.status != 0 {
            return false;
        }
        let Some(old) = self.bssid else {
            return false;
        };
        let peer = header.source_mac;
        if peer == [0; 6] || peer[0] & 1 != 0 || peer == old {
            return false;
        }
        self.bssid = None;
        self.connection = None;
        self.ht_verified = false;
        self.vht_verified = false;
        self.mfp_verified = false;
        self.runtime.set_link(None);
        let secure = self.protection.is_some_and(|p| p.akm() != 0);
        self.roam = Some(Pending {
            peer,
            keys: !secure,
            deadline: narf_time::Deadline::after_ms(ROAM_BUDGET_MS),
        });
        true
    }

    fn close_link(&mut self) {
        self.bssid = None;
        self.connection = None;
        self.protection = None;
        self.reset_wmm();
        self.runtime.set_link(None);
    }

    /// Roaming re-key failure: like a failed join, the firmware's
    /// authorization state is unknown, so the runtime is poisoned.
    fn close_roam_failure(&mut self) {
        self.close_link();
        self.runtime.fail();
    }

    /// Drive a pending firmware roam to publication. `Ok(None)` while it
    /// still waits for keys; `Ok(Some(_))` once the new peer is authorized.
    pub async fn complete_roam(&mut self) -> Result<Option<Roamed>, Error> {
        self.poll()?;
        let Some(pending) = self.roam.as_ref() else {
            return Ok(None);
        };
        if !pending.keys {
            if pending.deadline.expired() {
                self.roam = None;
                self.close_roam_failure();
                return Err(Error::Timeout);
            }
            return Ok(None);
        }
        let peer = pending.peer;
        self.operation = true;
        let result = self.confirm_roam(peer).await;
        self.operation = false;
        match result {
            Ok(roamed) => Ok(Some(roamed)),
            Err(error) => {
                self.roam = None;
                self.close_roam_failure();
                Err(error)
            }
        }
    }

    async fn confirm_roam(&mut self, peer: [u8; 6]) -> Result<Roamed, Error> {
        let reply = self
            .runtime
            .command(ioctl::Direction::Get, ioctl::WLC_GET_BSSID, &[], 6)
            .await?;
        if reply.as_slice() != peer {
            return Err(Error::Malformed);
        }
        let mut query = b"chanspec\0".to_vec();
        query.extend_from_slice(&[0; 4]);
        let reply = self
            .runtime
            .command(ioctl::Direction::Get, ioctl::WLC_GET_VAR, &query, 4)
            .await?;
        let chanspec = super::le32(&reply, 0)?;
        let occupied = u16::try_from(chanspec)
            .ok()
            .and_then(occupied)
            .ok_or(Error::Malformed)?;
        if !self.channels.contains(&occupied.primary) {
            return Err(Error::Unsupported);
        }
        let power = occupied_power(&self.domain, occupied).ok_or(Error::Unsupported)?;
        let grant: TxGrant = self.grant_occupied(occupied, power)?;
        self.tx_var(grant, "qtxpower", &(u32::from(power) * 4).to_le_bytes())
            .await?;
        let protection = self.protection.ok_or(Error::Failed)?;
        if protection.verify() {
            self.mfp_verified = self
                .verify_management_protection(grant, peer, protection)
                .await?;
        }
        self.ac_priority = match self
            .tx_query(grant, "wme_ac_sta", super::wmm::ACPARAM_LEN)
            .await
        {
            Ok(rows) => super::wmm::prioritize(&rows)?,
            Err(Error::Firmware(_)) => super::wmm::DEFAULT_AC_PRIORITY,
            Err(error) => return Err(error),
        };
        let (request_ies, response_ies) = self.association_ies(grant).await?;
        // Fresh idle fence: no queued loss of the new peer may be skipped.
        loop {
            self.check_grants(core::slice::from_ref(&grant))?;
            let consumed = self.runtime.poll()?;
            while let Some(event) = self.runtime.pop_event() {
                self.roam_event(&event);
            }
            if self.roam.as_ref().is_none_or(|r| r.peer != peer) {
                return Err(Error::Failed);
            }
            if consumed == 0 {
                break;
            }
        }
        self.roam = None;
        self.connection = Some(grant);
        self.bssid = Some(peer);
        self.runtime.set_ac_priority(self.ac_priority);
        self.runtime.set_link(Some(peer));
        Ok(Roamed {
            bssid: peer,
            frequency_mhz: channel::frequency(occupied.primary).ok_or(Error::Malformed)?,
            request_ies,
            response_ies,
        })
    }

    /// `brcmf_get_assoc_ies`: `assoc_info` lengths then both element lists.
    async fn association_ies(&mut self, grant: TxGrant) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let info = self.tx_query(grant, "assoc_info", 8).await?;
        if info.len() != 8 {
            return Err(Error::Malformed);
        }
        let request = super::le32(&info, 0)? as usize;
        let response = super::le32(&info, 4)? as usize;
        if request > super::MAX_REPLY || response > super::MAX_REPLY {
            return Err(Error::Malformed);
        }
        let mut out = (Vec::new(), Vec::new());
        if request != 0 {
            out.0 = self.tx_query(grant, "assoc_req_ies", request).await?;
        }
        if response != 0 {
            out.1 = self.tx_query(grant, "assoc_resp_ies", response).await?;
        }
        if out.0.len() != request || out.1.len() != response {
            return Err(Error::Malformed);
        }
        Ok(out)
    }
}

/// Station event mask; firmware roaming adds `BRCMF_E_ROAM`.
pub fn event_mask(roaming: bool) -> [u8; 16] {
    let mut mask = [0; 16];
    for event in super::EVENTS {
        mask[event / 8] |= 1 << (event % 8);
    }
    if roaming {
        mask[WLC_E_ROAM as usize / 8] |= 1 << (WLC_E_ROAM % 8);
    }
    mask
}

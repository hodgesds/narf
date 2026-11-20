// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware PMKSA/PMKID cache (`pmkid_info`).
//!
//! Linux brcmfmac `cfg80211.c` keeps a host `brcmf_pmk_list_le` of at most
//! `BRCMF_MAXPMKID`=16 `{bssid, pmkid}` rows. `set_pmksa` replaces the row
//! for the same BSSID or appends one (-EINVAL when full); `del_pmksa`
//! compacts the list (-EINVAL when absent); `flush_pmksa` clears it. Each
//! change rewrites the whole list with the `pmkid_info` iovar. Firmware with
//! `wlc_ver` major >= 13 (`BRCMF_FEAT_PMKID_V3`, `feature.c`) instead takes
//! one `brcmf_pmk_op_v3_le` operation per call (`brcmf_pmksa_v3_op`); a
//! flush is `count = 0`. Linux leaves `BRCMF_FEAT_PMKID_V2` as a TODO and
//! uses the v1 list there, as here. Firmware inserts a cached PMKID into its
//! (re)association RSNE for the SAE/802.1X AKMs; PSK has no PMKSA.
use super::{set_var, Error, Fullmac};
use alloc::vec::Vec;

/// `fwil_types.h` `BRCMF_MAXPMKID`.
pub const MAX_ENTRIES: usize = 16;
/// `sizeof(struct brcmf_pmk_list_le)`.
pub const LIST_LEN: usize = 4 + MAX_ENTRIES * 22;
/// `sizeof(struct brcmf_pmksa_v3)`.
pub const V3_ENTRY_LEN: usize = 112;
/// `sizeof(struct brcmf_pmk_op_v3_le)`.
pub const V3_OP_LEN: usize = 8 + MAX_ENTRIES * V3_ENTRY_LEN;
/// `BRCMF_PMKSA_VER_3` / `BRCMF_PMKSA_NO_EXPIRY`.
pub const VER_3: u16 = 3;
pub const NO_EXPIRY: u32 = u32::MAX;
/// `sizeof(struct brcmf_wlc_version_le)`; major at offset 12.
pub const WLC_VERSION_LEN: usize = 16;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Entry {
    pub bssid: [u8; 6],
    pub pmkid: [u8; 16],
    pub ssid: Vec<u8>,
}

/// Host mirror of the firmware list in Linux order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Cache {
    entries: Vec<Entry>,
}
impl Cache {
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    /// Linux `brcmf_cfg80211_set_pmksa` list semantics.
    pub fn set(&mut self, entry: Entry) -> Result<(), Error> {
        if entry.ssid.len() > 32 {
            return Err(Error::Malformed);
        }
        if let Some(row) = self.entries.iter_mut().find(|r| r.bssid == entry.bssid) {
            *row = entry;
        } else if self.entries.len() < MAX_ENTRIES {
            self.entries.push(entry);
        } else {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    /// Linux `brcmf_cfg80211_del_pmksa`: remove by BSSID and compact.
    pub fn delete(&mut self, bssid: [u8; 6]) -> Result<(), Error> {
        let index = self
            .entries
            .iter()
            .position(|r| r.bssid == bssid)
            .ok_or(Error::Malformed)?;
        self.entries.remove(index);
        Ok(())
    }
    pub fn flush(&mut self) {
        self.entries.clear();
    }
    /// `struct brcmf_pmk_list_le` (zero-filled tail, fixed size).
    pub fn encode_list(&self) -> Vec<u8> {
        let mut out = alloc::vec![0; LIST_LEN];
        out[..4].copy_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for (i, entry) in self.entries.iter().enumerate() {
            let row = &mut out[4 + i * 22..4 + (i + 1) * 22];
            row[..6].copy_from_slice(&entry.bssid);
            row[6..].copy_from_slice(&entry.pmkid);
        }
        out
    }
}

/// `brcmf_pmksa_v3_op`: `None` is a flush (count 0), otherwise one entry
/// with `time_left` NO_EXPIRY (`alive`) or 0 (delete).
pub fn encode_v3(entry: Option<&Entry>, alive: bool) -> Vec<u8> {
    let mut out = alloc::vec![0; V3_OP_LEN];
    out[..2].copy_from_slice(&VER_3.to_le_bytes());
    let mut length = 8u16;
    if let Some(entry) = entry {
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        length += V3_ENTRY_LEN as u16;
        let row = &mut out[8..8 + V3_ENTRY_LEN];
        row[..6].copy_from_slice(&entry.bssid);
        row[6..22].copy_from_slice(&entry.pmkid);
        row[22] = 16; // pmkid_len = WLAN_PMKID_LEN
        if !entry.ssid.is_empty() {
            row[75] = entry.ssid.len() as u8;
            row[76..76 + entry.ssid.len()].copy_from_slice(&entry.ssid);
        }
        row[108..112].copy_from_slice(&if alive { NO_EXPIRY } else { 0 }.to_le_bytes());
    }
    out[2..4].copy_from_slice(&length.to_le_bytes());
    out
}

/// Linux `brcmf_feat_wlc_version_overrides`: major >= 13 selects v3.
pub fn v3_from_wlc_version(reply: &[u8]) -> Result<bool, Error> {
    let major = reply.get(12..14).ok_or(Error::Malformed)?;
    Ok(u16::from_le_bytes([major[0], major[1]]) >= 13)
}

/// Reconcile firmware with `desired`. v1 rewrites the whole list exactly as
/// Linux does after each change; v3 flushes and re-adds each row, which is
/// the same sequence of `brcmf_pmksa_v3_op` calls a fresh cache replays.
pub async fn program<R: Fullmac>(runtime: &mut R, v3: bool, desired: &Cache) -> Result<(), Error> {
    if !v3 {
        return set_var(runtime, "pmkid_info", &desired.encode_list()).await;
    }
    set_var(runtime, "pmkid_info", &encode_v3(None, false)).await?;
    for entry in desired.entries() {
        set_var(runtime, "pmkid_info", &encode_v3(Some(entry), true)).await?;
    }
    Ok(())
}

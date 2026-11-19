// SPDX-License-Identifier: GPL-2.0-or-later
//! WMI network-list-offload (WoWLAN NET_DETECT) types shared by the ath
//! drivers.
//!
//! The firmware-facing `NloConfig`/`NloNetwork` types lived in the ath11k
//! driver's `wmi` module; promoted here so ath10k can build the same WoW
//! NET_DETECT configuration. The WMI serialization that consumes them stays in
//! each driver.

use alloc::vec::Vec;

/// A network match encoded in one `nlo_configured_parameters` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NloNetwork {
    pub ssid: Vec<u8>,
    pub rssi_threshold_dbm: Option<i32>,
    /// The network is probed as hidden because it is also in the directed
    /// scan SSID list; ordinary matches use firmware's value zero.
    pub hidden: bool,
}

/// The firmware-facing portion of cfg80211 WoWLAN NET_DETECT.  All periods
/// are seconds at this interface; the WMI layout carries milliseconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NloConfig {
    pub probe_ssids: Vec<Vec<u8>>,
    pub channels_mhz: Vec<u32>,
    /// Retained cfg80211 probe IEs. Linux advertises 512 bytes for NLO even
    /// though `wmi_wow_nlo_config_cmd` has no variable IE-byte array, so the
    /// target command intentionally leaves its IE bitmap zero as Linux does.
    pub probe_ies: Vec<u8>,
    pub networks: Vec<NloNetwork>,
    pub plans: Vec<(u32, Option<u32>)>,
    pub delay_secs: u32,
    pub random_mac: Option<narf_wireless::ScanRandomMac>,
}

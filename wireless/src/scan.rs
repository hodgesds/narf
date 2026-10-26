use alloc::vec::Vec;

/// Randomized source address parameters for one scan.
///
/// This is cfg80211's `mac_addr` / `mac_addr_mask` pair.  `addr` contains
/// the bits selected by `mask`; the remaining bits are randomized by the
/// firmware for probe requests.  The generic nl80211 parser guarantees a
/// locally-administered unicast address and mask before constructing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanRandomMac {
    pub addr: [u8; 6],
    pub mask: [u8; 6],
}

pub struct ScanRequest {
    pub ssids: Vec<Vec<u8>>,
    /// Authoritative centre frequencies in MHz. This keeps 6 GHz channels
    /// distinct from identically numbered 2.4/5 GHz channels.
    pub frequencies_mhz: Vec<u32>,
    /// Legacy channel-number selector for callers that cannot yet provide a
    /// frequency. It is unambiguous only for the 2.4/5 GHz profiles that
    /// predate 6 GHz support.
    pub channels: Vec<u32>,
    pub active: bool,
    /// `NL80211_SCAN_FLAG_RANDOM_ADDR`, if requested and supported by the
    /// physical wiphy.  Passive scans carry this too: firmware uses it for
    /// any probe requests caused by a later directed scan phase.
    pub random_mac: Option<ScanRandomMac>,
    /// `NL80211_SCAN_FLAG_COLOCATED_6GHZ`. On firmware with per-channel scan
    /// configuration, non-PSC 6 GHz channels are scanned only after an RNR
    /// in the concurrent 2.4/5 GHz scan identifies them.
    pub colocated_6ghz: bool,
    /// `NL80211_ATTR_MEASUREMENT_DURATION`, in TUs. When nonzero, ath11k
    /// uses it as the active and passive scan dwell time on every band.
    pub duration_tu: Option<u16>,
    /// `NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY`. ath11k accepts the
    /// flag as cfg80211 does; firmware has one dwell-time setting, so the
    /// requested duration is applied identically for mandatory and maximum
    /// requests.
    pub duration_mandatory: bool,
    /// Caller-supplied `NL80211_ATTR_IE` bytes for the Probe Request. The
    /// generic control layer enforces the driver's `max_scan_ie_len()` budget
    /// (512 bytes by default, 256 for ath10k). Each driver validates and adds
    /// accepted elements to its Probe Request representation.
    pub extra_ies: Vec<u8>,
}

pub struct ScanResult {
    pub bss_list: Vec<BssInfo>,
}

#[derive(Debug, Clone)]
pub struct BssInfo {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    /// Centre frequency in MHz; this is the canonical BSS channel identity.
    pub frequency_mhz: u32,
    /// IEEE channel number, retained for presentation and legacy callers.
    pub channel: u32,
    pub rssi: i8,
    pub security: BssSecurity,
}

#[derive(Debug, Clone, Copy)]
pub enum BssSecurity {
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
}

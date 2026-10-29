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

/// `NL80211_ATTR_SCAN_FLAGS` bits that travel beside a `ScanRequest`
/// (`WirelessNetIface::scan_with_flags`). They are separate from `ScanRequest`
/// so existing request literals stay valid; the default is "no flag".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanFlags {
    /// `NL80211_SCAN_FLAG_RANDOM_SN`: randomize the 802.11 sequence number
    /// of every Probe Request in this scan (accepted only when the wiphy
    /// advertises `NL80211_EXT_FEATURE_SCAN_RANDOM_SN`).
    pub random_sn: bool,
}

pub struct ScanResult {
    pub bss_list: Vec<BssInfo>,
    /// Colocated 6 GHz APs found in the 2.4/5 GHz results' Reduced Neighbor
    /// Reports (`parse_colocated_aps`), for `plan_6ghz_scan`. Empty unless
    /// the driver honours `ScanRequest::colocated_6ghz`.
    pub colocated_6ghz: Vec<ColocatedAp>,
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

/// Element ID of the Reduced Neighbor Report (IEEE802.11-2020 9.4.2.170).
pub const EID_REDUCED_NEIGHBOR_REPORT: u8 = 201;
/// `IEEE80211_RNR_TBTT_PARAMS_PSD_RESERVED`: no 20 MHz PSD reported.
pub const PSD_RESERVED: i8 = -128;
/// `IEEE80211_RNR_TBTT_PARAMS_PSD_NO_LIMIT`.
pub const PSD_NO_LIMIT: i8 = 127;

const TBTT_PARAMS_OCT_RECOMMENDED: u8 = 0x01;
const TBTT_PARAMS_SAME_SSID: u8 = 0x02;
const TBTT_PARAMS_MULTI_BSSID: u8 = 0x04;
const TBTT_PARAMS_TRANSMITTED_BSSID: u8 = 0x08;
const TBTT_PARAMS_COLOC_ESS: u8 = 0x10;
const TBTT_PARAMS_PROBE_ACTIVE: u8 = 0x20;
const TBTT_PARAMS_COLOC_AP: u8 = 0x40;
const RNR_MLD_PARAMS_DISABLED_LINK: u16 = 0x2000;

/// One colocated 6 GHz AP reported by a 2.4/5 GHz BSS's Reduced Neighbor
/// Report (cfg80211 `struct cfg80211_colocated_ap`). Scan facts only: it
/// grants no channel, probe or association authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColocatedAp {
    pub bssid: [u8; 6],
    /// 6 GHz channel number and centre frequency.
    pub channel: u8,
    pub frequency_mhz: u32,
    /// Short SSID (`~crc32_le(~0, ssid)`), when reported or implied by
    /// `same_ssid`.
    pub short_ssid: Option<u32>,
    /// The reporting BSS's SSID when `same_ssid`, else empty.
    pub ssid: Vec<u8>,
    pub oct_recommended: bool,
    pub same_ssid: bool,
    pub multi_bss: bool,
    pub transmitted_bssid: bool,
    pub unsolicited_probe: bool,
    pub colocated_ess: bool,
    /// 20 MHz PSD limit (`PSD_RESERVED` when absent).
    pub psd_20: i8,
}

/// IEEE802.11 Short SSID: the CRC-32 of the SSID (cfg80211
/// `~crc32_le(~0, ssid, len)`).
pub fn short_ssid(ssid: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in ssid {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// 6 GHz Preferred Scanning Channel (cfg80211 `cfg80211_channel_is_psc`).
pub fn is_psc_6ghz(channel: u8) -> bool {
    channel % 16 == 5
}

/// `ieee80211_operating_class_to_band` == `NL80211_BAND_6GHZ`.
fn op_class_6ghz(op_class: u8) -> bool {
    matches!(op_class, 131..=135 | 137)
}

/// cfg80211 `cfg80211_parse_ap_info`: `None` for an entry that is skipped.
fn parse_ap_info(
    info: &[u8],
    channel: u8,
    frequency_mhz: u32,
    ssid: &[u8],
    reporter_short_ssid: u32,
) -> Option<ColocatedAp> {
    let mut bssid = [0; 6];
    bssid.copy_from_slice(&info[1..7]);
    let (short_ssid, params, psd_20) = if info.len() > 9 {
        // `ieee80211_tbtt_info_ge_11`; ignore disabled MLD links.
        if info.len() >= 16
            && u16::from_le_bytes([info[14], info[15]]) & RNR_MLD_PARAMS_DISABLED_LINK != 0
        {
            return None;
        }
        let short = u32::from_le_bytes([info[7], info[8], info[9], info[10]]);
        let psd = if info.len() >= 13 {
            info[12] as i8
        } else {
            PSD_RESERVED
        };
        (Some(short), info[11], psd)
    } else {
        // `ieee80211_tbtt_info_7_8_9`.
        let psd = if info.len() == 9 {
            info[8] as i8
        } else {
            PSD_RESERVED
        };
        (None, info[7], psd)
    };
    // `is_valid_ether_addr`, and only colocated APs.
    if bssid[0] & 1 != 0 || bssid == [0; 6] || params & TBTT_PARAMS_COLOC_AP == 0 {
        return None;
    }
    let same_ssid = params & TBTT_PARAMS_SAME_SSID != 0;
    Some(ColocatedAp {
        bssid,
        channel,
        frequency_mhz,
        short_ssid: if same_ssid {
            Some(reporter_short_ssid)
        } else {
            short_ssid
        },
        ssid: if same_ssid { ssid.to_vec() } else { Vec::new() },
        oct_recommended: params & TBTT_PARAMS_OCT_RECOMMENDED != 0,
        same_ssid,
        multi_bss: params & TBTT_PARAMS_MULTI_BSSID != 0,
        transmitted_bssid: params & TBTT_PARAMS_TRANSMITTED_BSSID != 0,
        unsolicited_probe: params & TBTT_PARAMS_PROBE_ACTIVE != 0,
        colocated_ess: params & TBTT_PARAMS_COLOC_ESS != 0,
        psd_20,
    })
}

/// cfg80211 `cfg80211_parse_colocated_ap` (Linux v7.2 net/wireless/scan.c)
/// over the information elements of one 2.4/5 GHz beacon or probe response:
/// the colocated 6 GHz APs of its Reduced Neighbor Reports. TBTT entries of
/// another type, band or length are skipped; a BSS without a valid SSID
/// element, or any malformed RNR (`cfg80211_iter_rnr` failure), yields no
/// AP. Entries whose 6 GHz channel number has no frequency are skipped
/// (cfg80211 drops them later when `ieee80211_get_channel` fails), and a
/// BSSID already reported on the same channel is not repeated.
pub fn parse_colocated_aps(ies: &[u8]) -> Vec<ColocatedAp> {
    let mut out = Vec::new();
    let mut ssid = None;
    let mut rnrs = Vec::new();
    let mut rest = ies;
    while rest.len() >= 2 {
        let len = usize::from(rest[1]);
        let Some(body) = rest.get(2..2 + len) else {
            break;
        };
        match rest[0] {
            0 if ssid.is_none() => ssid = Some(body),
            EID_REDUCED_NEIGHBOR_REPORT => rnrs.push(body),
            _ => {}
        }
        rest = &rest[2 + len..];
    }
    let Some(ssid) = ssid.filter(|s| s.len() <= 32) else {
        return out;
    };
    let reporter = short_ssid(ssid);
    for rnr in rnrs {
        let mut pos = rnr;
        while pos.len() >= 4 {
            let (hdr, len, op_class, channel) = (pos[0], usize::from(pos[1]), pos[2], pos[3]);
            let count = usize::from(hdr >> 4) + 1;
            pos = &pos[4..];
            if count * len > pos.len() {
                return Vec::new();
            }
            let usable =
                hdr & 0x03 == 0 && op_class_6ghz(op_class) && (len == 8 || len == 9 || len >= 12);
            let frequency = crate::association::channel::frequency_in(
                crate::association::channel::Band::Ghz6,
                channel,
            );
            for info in pos[..count * len].chunks_exact(len.max(1)) {
                let (true, Some(mhz)) = (usable, frequency) else {
                    continue;
                };
                if let Some(ap) = parse_ap_info(info, channel, mhz, ssid, reporter) {
                    if !out
                        .iter()
                        .any(|o: &ColocatedAp| o.bssid == ap.bssid && o.frequency_mhz == mhz)
                    {
                        out.push(ap);
                    }
                }
            }
            pos = &pos[count * len..];
        }
        if !pos.is_empty() {
            return Vec::new();
        }
    }
    out
}

/// One per-AP 6 GHz probe target (cfg80211 `struct
/// cfg80211_scan_6ghz_params`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scan6GhzTarget {
    pub frequency_mhz: u32,
    pub channel: u8,
    pub bssid: [u8; 6],
    pub short_ssid: Option<u32>,
    pub unsolicited_probe: bool,
    pub psd_20: i8,
    /// A PSC channel whose wanted APs are all colocated: no initial listen.
    pub psc_no_listen: bool,
}

/// The second, 6 GHz part of a scan (cfg80211 `cfg80211_scan_6ghz`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan6GhzPlan {
    /// 6 GHz channels to scan, in MHz, in request order then target order.
    pub frequencies_mhz: Vec<u32>,
    pub targets: Vec<Scan6GhzTarget>,
}

/// cfg80211 `cfg80211_find_ssid_match`.
fn ssid_match(ap: &ColocatedAp, ssids: &[Vec<u8>]) -> bool {
    ssids.iter().any(|ssid| {
        if ssid.is_empty() {
            return !ap.multi_bss || ap.transmitted_bssid;
        }
        if !ap.ssid.is_empty() && ap.ssid.len() == ssid.len() {
            ap.ssid == *ssid
        } else {
            ap.short_ssid == Some(short_ssid(ssid))
        }
    })
}

/// cfg80211 `cfg80211_scan_6ghz` (Linux v7.2 net/wireless/scan.c) for a
/// request and the colocated APs collected from its 2.4/5 GHz results
/// (`parse_colocated_aps`). Without `colocated_6ghz` every requested 6 GHz
/// channel is scanned and no target is produced. With it, only PSC channels
/// are scanned blind, unless a directed one-SSID scan found a colocated
/// ESS AP with that SSID, and each colocated AP on a requested channel that
/// matches the SSIDs (and `bssid`, when the request names one) becomes a
/// target. Channel usability (`IEEE80211_CHAN_DISABLED`, interface
/// restrictions) stays with the driver.
pub fn plan_6ghz_scan(
    request: &ScanRequest,
    colocated: &[ColocatedAp],
    bssid: Option<[u8; 6]>,
) -> Scan6GhzPlan {
    use crate::association::channel::{from_frequency_band, Band};
    let six = |mhz: u32| match from_frequency_band(mhz) {
        Some((Band::Ghz6, channel)) => Some(channel),
        _ => None,
    };
    let need_scan_psc = !(request.colocated_6ghz
        && !colocated.is_empty()
        && request.ssids.len() == 1
        && !request.ssids[0].is_empty()
        && colocated
            .iter()
            .any(|ap| ap.colocated_ess && ssid_match(ap, &request.ssids)));
    let mut plan = Scan6GhzPlan::default();
    for mhz in &request.frequencies_mhz {
        if let Some(channel) = six(*mhz) {
            if ((need_scan_psc && is_psc_6ghz(channel)) || !request.colocated_6ghz)
                && !plan.frequencies_mhz.contains(mhz)
            {
                plan.frequencies_mhz.push(*mhz);
            }
        }
    }
    if !request.colocated_6ghz {
        return plan;
    }
    for ap in colocated {
        if !request.frequencies_mhz.contains(&ap.frequency_mhz)
            || six(ap.frequency_mhz).is_none()
            || (!request.ssids.is_empty() && !ssid_match(ap, &request.ssids))
            || bssid.is_some_and(|b| b != ap.bssid)
            || (request.ssids.is_empty() && ap.multi_bss && !ap.transmitted_bssid)
        {
            continue;
        }
        if !plan.frequencies_mhz.contains(&ap.frequency_mhz) {
            plan.frequencies_mhz.push(ap.frequency_mhz);
        }
        plan.targets.push(Scan6GhzTarget {
            frequency_mhz: ap.frequency_mhz,
            channel: ap.channel,
            bssid: ap.bssid,
            short_ssid: ap.short_ssid,
            unsolicited_probe: ap.unsolicited_probe,
            psd_20: ap.psd_20,
            psc_no_listen: is_psc_6ghz(ap.channel) && !need_scan_psc,
        });
    }
    plan
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "scan_colocated_tests.rs"]
mod colocated_tests;

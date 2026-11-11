//! CONNAC2 network-list offload wire requests consumed by native suspend.
//! Linux mt76_connac_mcu.{c,h}, mt76_connac.h and cfg80211 core's default
//! one-plan profile. Channel permission and host RNG belong to the retained
//! caller; this encoder cannot grant either of them.
use alloc::{vec, vec::Vec};
use narf_wireless::{NetDetectConfig, SchedScanSupport};

use super::{channel, firmware_transport::Error};

pub(super) const REQUEST: u8 = 0x62;
pub(super) const ENABLE: u8 = 0x61;
const REQUEST_LEN: usize = 1224;

/// WoWLAN net-detect (mt7921 `max_nd_match_sets` = 10).
pub(crate) const LIMITS: SchedScanSupport = SchedScanSupport {
    max_match_sets: 10,
    max_ssids: 10,
    max_ie_len: 512,
    max_scan_plans: 1,
    max_plan_interval_secs: u16::MAX as u32,
    max_plan_iterations: 0,
    max_frequencies: 64,
    random_mac: true,
};

/// `struct mt76_connac_sched_scan_req` holds MT76_CONNAC_MAX_SCAN_MATCH
/// (16) match records (offsets 368..1008).
const WIRE_MATCHES: usize = 16;

/// Host scheduled scan: mt7921 `wiphy->max_match_sets` =
/// MT76_CONNAC_MAX_SCAN_MATCH, the whole wire array.
pub(crate) const SCHED_LIMITS: SchedScanSupport = SchedScanSupport {
    max_match_sets: WIRE_MATCHES as u8,
    ..LIMITS
};

#[path = "wowlan_nlo_tests.rs"]
mod tests;

/// The WoWLAN net-detect bounds.
pub(super) fn validate(config: &NetDetectConfig) -> Result<(), Error> {
    validate_with(config, LIMITS)
}

pub(super) fn validate_with(
    config: &NetDetectConfig,
    limits: SchedScanSupport,
) -> Result<(), Error> {
    if config.probe_ssids.len() > 10
        || config.probe_ssids.iter().any(|ssid| ssid.len() > 32)
        || config.matches.is_empty()
        || config.matches.len() > usize::from(limits.max_match_sets).min(WIRE_MATCHES)
        || config
            .matches
            .iter()
            .any(|one| one.ssid.is_empty() || one.ssid.len() > 32)
        || config.probe_ies.len() > 512
        || config.frequencies_mhz.len() > 64
        || config.plans.len() != 1
        || config.plans[0].iterations.is_some()
        || !(1..=u32::from(u16::MAX)).contains(&config.plans[0].interval_secs)
    {
        return Err(Error::Bounds);
    }
    super::firmware_transport::validate_scan_options(super::firmware_transport::ScanOptions {
        extra_ies: &config.probe_ies,
        random_mac: config.random_mac,
    })
}

pub(super) fn request(
    config: &NetDetectConfig,
    sequence: u8,
    channels: &[(channel::Band, u8)],
    random_address: Option<[u8; 6]>,
) -> Result<Vec<u8>, Error> {
    // The caller's plan applied its own limits; this is the wire bound.
    validate_with(config, SCHED_LIMITS)?;
    if sequence == 0
        || sequence > 127
        || channels.is_empty()
        || channels.len() > 64
        || channels
            .iter()
            .any(|&(band, number)| channel::frequency_in(band, number).is_none())
        || random_address.is_some() != config.random_mac.is_some()
    {
        return Err(Error::Bounds);
    }
    let mut body = vec![0u8; REQUEST_LEN + config.probe_ies.len()];
    body[0] = 1;
    body[1] = sequence; // native radio owns band_idx0/BSS0
    body[3] = config.probe_ssids.len() as u8;
    body[4] = config.matches.len() as u8;
    body[6..8].copy_from_slice(&(config.probe_ies.len() as u16).to_le_bytes());
    for (index, ssid) in config.probe_ssids.iter().enumerate() {
        let at = 8 + 36 * index;
        body[at..at + 4].copy_from_slice(&(ssid.len() as u32).to_le_bytes());
        body[at + 4..at + 4 + ssid.len()].copy_from_slice(ssid);
    }
    for (index, one) in config.matches.iter().enumerate() {
        let at = 368 + 40 * index;
        body[at..at + 4].copy_from_slice(
            &one.rssi_threshold_dbm
                .unwrap_or(-300) // NL80211_SCAN_RSSI_THOLD_OFF
                .to_le_bytes(),
        );
        body[at + 4..at + 4 + one.ssid.len()].copy_from_slice(&one.ssid);
        body[at + 36] = one.ssid.len() as u8;
    }
    // Never let firmware choose channels outside the caller's actual
    // hardware/regulatory allow-list, even for an unspecified nl80211 list.
    body[1008] = 4;
    body[1009] = channels.len() as u8;
    body[1010] = 1;
    for (index, &(band, number)) in channels.iter().enumerate() {
        body[1012 + 2 * index] = band.scan_tag();
        body[1013 + 2 * index] = number;
    }
    body[1140..1142].copy_from_slice(&(config.plans[0].interval_secs as u16).to_le_bytes());
    // mt7921 union: bss_idx0, padding, delay32, padding12, random_mac6.
    body[1164..1168].copy_from_slice(&config.delay_secs.to_le_bytes());
    if let (Some(random), Some(address)) = (config.random_mac, random_address) {
        if address[0] & 1 != 0
            || address
                .iter()
                .zip(random.addr)
                .zip(random.mask)
                .any(|((&actual, supplied), mask)| actual & mask != supplied & mask)
        {
            return Err(Error::Bounds);
        }
        body[1011] = 1;
        body[1180..1186].copy_from_slice(&address);
    }
    body[REQUEST_LEN..].copy_from_slice(&config.probe_ies);
    Ok(body)
}

pub(super) fn enable(enabled: bool) -> [u8; 4] {
    [u8::from(!enabled), 0, 0, 0]
}

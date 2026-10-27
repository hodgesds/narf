// SPDX-License-Identifier: GPL-2.0-or-later
//! Channel1 software-scan plan for the retained RTL8821CE/RTL8822CE station.
//!
//! This profile's firmware does not take Linux's `FW_FEATURE_SCAN_OFFLOAD`
//! branch, so `rtw_ops_hw_scan` returns 1 and mac80211 runs its software scan:
//! one broadcast-DA/wildcard-BSSID Probe Request per requested SSID (at most
//! `RTW_SCAN_MAX_SSIDS` = 4), transmitted through the ordinary management
//! queue at the lowest basic CCK rate with no ACK report, followed by the
//! channel dwell. `rtw_get_max_scan_ie_len` reports `IEEE80211_MAX_DATA_LEN`
//! for this path and mac80211 subtracts its own preq IEs from that budget.
//! Random source addresses are not part of this plan.
use super::packet_format::MAX_MPDU;
use alloc::vec::Vec;
use narf_wireless::{ScanRequest, WirelessError};

/// Linux `main.h::RTW_SCAN_MAX_SSIDS`.
pub(super) const MAX_SSIDS: u8 = 4;
/// Every legacy 2.4GHz bitrate the station also offers at association,
/// without basic flags (mac80211 `ieee80211_put_srates_elem` for a preq).
const RATES: [u8; 8] = [0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24];
const EXTENDED_RATES: [u8; 4] = [0x30, 0x48, 0x60, 0x6c];
/// Header, longest SSID, rates, extended rates and DS Parameter Set.
const OWN_LENGTH: usize = 24 + (2 + 32) + (2 + RATES.len()) + (2 + EXTENDED_RATES.len()) + 3;
/// `IEEE80211_MAX_DATA_LEN` less the driver-built preq elements; the result
/// always fits the retained2304-byte native TX MPDU allocation.
pub(super) const MAX_EXTRA_IES: u16 = (MAX_MPDU - OWN_LENGTH) as u16;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Plan {
    pub dwell_ms: u64,
    /// Complete unsequenced Probe Request MPDUs, without FCS.
    pub probes: Vec<Vec<u8>>,
}

/// Caller probe elements: well formed, bounded, never duplicating an element
/// this plan already emits (SSID, rates, extended rates, DS Parameter Set).
fn validate_ies(mut bytes: &[u8]) -> Result<(), WirelessError> {
    if bytes.len() > usize::from(MAX_EXTRA_IES) {
        return Err(WirelessError::InvalidArgs);
    }
    while !bytes.is_empty() {
        let head = bytes.get(..2).ok_or(WirelessError::InvalidArgs)?;
        let end = 2 + usize::from(head[1]);
        let body = bytes.get(2..end).ok_or(WirelessError::InvalidArgs)?;
        match head[0] {
            0 | 1 | 3 | 50 => return Err(WirelessError::InvalidArgs),
            221 if body.len() < 3 => return Err(WirelessError::InvalidArgs),
            255 if body.is_empty() => return Err(WirelessError::InvalidArgs),
            _ => {}
        }
        bytes = &bytes[end..];
    }
    Ok(())
}

fn probe(own: [u8; 6], ssid: &[u8], extra: &[u8]) -> Result<Vec<u8>, WirelessError> {
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(OWN_LENGTH + extra.len())
        .map_err(|_| WirelessError::HardwareError)?;
    frame.extend_from_slice(&[0x40, 0, 0, 0]);
    frame.extend_from_slice(&[255; 6]);
    frame.extend_from_slice(&own);
    frame.extend_from_slice(&[255; 6]);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0, ssid.len() as u8]);
    frame.extend_from_slice(ssid);
    frame.extend_from_slice(&[1, RATES.len() as u8]);
    frame.extend_from_slice(&RATES);
    frame.extend_from_slice(&[50, EXTENDED_RATES.len() as u8]);
    frame.extend_from_slice(&EXTENDED_RATES);
    frame.extend_from_slice(&[3, 1, 1]);
    frame.extend_from_slice(extra);
    Ok(frame)
}

/// Admit one channel1 scan request. Passive requests keep the original
/// receive-only behaviour; active requests add the software-scan probes.
pub(super) fn plan(request: &ScanRequest, own: [u8; 6]) -> Result<Plan, WirelessError> {
    if request.random_mac.is_some()
        || request.colocated_6ghz
        || !request.active && !request.extra_ies.is_empty()
        || request.frequencies_mhz.iter().any(|f| *f != 2412)
        || request.channels.iter().any(|ch| *ch != 1)
        || request.active && request.ssids.len() > usize::from(MAX_SSIDS)
        || request.ssids.len() > 32
        || request.ssids.iter().any(|s| s.len() > 32)
    {
        return Err(WirelessError::NotSupported);
    }
    let dwell_ms = match request.duration_tu {
        Some(n @ 1..=1000) => (u64::from(n) * 1024).div_ceil(1000),
        Some(_) => return Err(WirelessError::InvalidArgs),
        None if request.duration_mandatory => return Err(WirelessError::InvalidArgs),
        None => 200,
    };
    if !request.active {
        return Ok(Plan {
            dwell_ms,
            probes: Vec::new(),
        });
    }
    if own == [0; 6] || own[0] & 1 != 0 {
        return Err(WirelessError::InvalidArgs);
    }
    validate_ies(&request.extra_ies)?;
    let mut probes = Vec::new();
    probes
        .try_reserve_exact(request.ssids.len().max(1))
        .map_err(|_| WirelessError::HardwareError)?;
    if request.ssids.is_empty() {
        probes.push(probe(own, &[], &request.extra_ies)?);
    }
    for ssid in &request.ssids {
        probes.push(probe(own, ssid, &request.extra_ies)?);
    }
    Ok(Plan { dwell_ms, probes })
}

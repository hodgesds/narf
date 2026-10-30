// SPDX-License-Identifier: GPL-2.0-or-later
//! mac80211 software-scan Probe Requests on the retained qualified channel.
//! Uses the same source-backed legacy management rate and native TX receipts
//! as authentication; broadcast destinations require no peer ACK.
use super::prepare::station::Error;
use alloc::vec::Vec;

/// mac80211's ordinary software-scan SSID limit, not a firmware offload claim.
pub(super) const MAX_SSIDS: usize = 4;
pub(super) fn request(
    own: [u8; 6],
    channel: u8,
    ssid: &[u8],
    ht: Option<[u8; 26]>,
) -> Result<Vec<u8>, Error> {
    if own == [0; 6] || own[0] & 1 != 0 || ssid.len() > 32 || !(1..=11).contains(&channel) {
        return Err(Error::Profile);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(100 + ssid.len())
        .map_err(|_| Error::Allocation)?;
    bytes.extend_from_slice(&[0x40, 0, 0, 0]);
    bytes.extend_from_slice(&[255; 6]);
    bytes.extend_from_slice(&own);
    bytes.extend_from_slice(&[255; 6]);
    bytes.extend_from_slice(&[0, 0]); // The retained station assigns its SSN.
    bytes.extend_from_slice(&[0, ssid.len() as u8]);
    bytes.extend_from_slice(ssid);
    bytes.extend_from_slice(&[1, 8, 2, 4, 11, 22, 12, 18, 24, 36]);
    bytes.extend_from_slice(&[50, 4, 48, 72, 96, 108]);
    bytes.extend_from_slice(&[3, 1, channel]);
    if let Some(ht) = ht {
        bytes.extend_from_slice(&[45, 26]);
        bytes.extend_from_slice(&ht);
    }
    Ok(bytes)
}

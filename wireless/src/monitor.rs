//! Raw monitor capture helpers. This module formats observed metadata; it
//! grants neither monitor mode nor device/receive authority.
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Frame,
    Frequency,
    Length,
    Allocation,
}

/// Receive-only channel definition using nl80211 width values (0 = 20NOHT,
/// 1 = 20, 2 = 40, 3 = 80, 5 = 160). Drivers validate hardware, geometry
/// and current receive policy before enabling capture. Zero center2 means a
/// contiguous channel; unsupported widths are refused, never narrowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    pub frequency_mhz: u32,
    pub width: u32,
    pub center1_mhz: u32,
    pub center2_mhz: u32,
}

/// Original receive facts. Absent PHY fields remain absent from radiotap;
/// callers must not substitute a configured channel or a guessed signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub frequency_mhz: u32,
    pub signal_dbm: Option<i8>,
}

/// Minimum IEEE802.11 MAC-header bounds (ieee80211_hdrlen). In particular
/// ACK/CTS are ten-octet control frames; optional DATA fields remain raw.
pub fn header_len(frame: &[u8]) -> Option<usize> {
    let fc = u16::from_le_bytes(frame.get(..2)?.try_into().ok()?);
    if fc & 3 != 0 {
        return None;
    }
    let length = match fc & 0x0c {
        0 => 24,
        4 => {
            if fc & 0xe0 == 0xc0 {
                10
            } else {
                16
            }
        }
        8 => {
            24 + usize::from(fc & 0x0300 == 0x0300) * 6
                + usize::from(fc & 0x0080 != 0) * (2 + usize::from(fc & 0x8000 != 0) * 4)
        }
        _ => return None,
    };
    (frame.len() >= length).then_some(length)
}

/// A version-0 radiotap header plus the exact original MPDU. Only FLAGS,
/// CHANNEL and an actually observed dBm signal are present. No timestamp,
/// rate, GI, FCS or decryption validity is synthesized. The native capture
/// adapter must supply an MPDU with no trailing FCS.
pub fn encode(frame: &[u8], metadata: Metadata) -> Result<Vec<u8>, Error> {
    header_len(frame).ok_or(Error::Frame)?;
    let (band, channel) = crate::association::channel::from_frequency_band(metadata.frequency_mhz)
        .ok_or(Error::Frequency)?;
    if band == crate::association::channel::Band::Ghz6 && channel != 2 && channel % 4 != 1 {
        return Err(Error::Frequency);
    }
    let frequency = u16::try_from(metadata.frequency_mhz).map_err(|_| Error::Frequency)?;
    let length = 14 + usize::from(metadata.signal_dbm.is_some());
    let total = frame
        .len()
        .checked_add(length)
        .filter(|n| *n <= u16::MAX as usize)
        .ok_or(Error::Length)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| Error::Allocation)?;
    bytes.resize(length, 0);
    bytes[2..4].copy_from_slice(&(length as u16).to_le_bytes());
    let present = (1u32 << 1)
        | (1 << 3)
        | if metadata.signal_dbm.is_some() {
            1 << 5
        } else {
            0
        };
    bytes[4..8].copy_from_slice(&present.to_le_bytes());
    bytes[8] = if frame[1] & 0x40 != 0 { 4 } else { 0 }
        | if frame[1] & 4 != 0
            || matches!(frame[0] & 0x0c, 0 | 8) && frame.get(22).is_some_and(|sc| sc & 15 != 0)
        {
            8
        } else {
            0
        };
    // CHANNEL is naturally aligned at offset10. Six-GHz has no legacy
    // radiotap 2GHz/5GHz flag: its exact frequency carries that identity.
    bytes[10..12].copy_from_slice(&frequency.to_le_bytes());
    let flags: u16 = match band {
        crate::association::channel::Band::Ghz2 => 0x0080,
        crate::association::channel::Band::Ghz5 => 0x0100,
        crate::association::channel::Band::Ghz6 => 0,
    };
    bytes[12..14].copy_from_slice(&flags.to_le_bytes());
    if let Some(signal) = metadata.signal_dbm {
        bytes[14] = signal as u8;
    }
    bytes.extend_from_slice(frame);
    Ok(bytes)
}

#[cfg(feature = "kernel-test")]
#[path = "monitor_tests.rs"]
mod tests;

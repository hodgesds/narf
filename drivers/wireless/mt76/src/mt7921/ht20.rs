//! Narrow non-BA HT20 station profile, IEEE HT elements and CONNAC2 peer facts.
//! Firmware layouts: mt76_connac_mcu.{c,h}; local HT MCS shape: mt76/mac80211.c.
use super::firmware_transport::{Error, RadioInfo, ScanBss};
use alloc::{vec, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile {
    capability: [u8; 26],
    operation: [u8; 22],
}

/// One RX/TX stream, HT20, long GI, no LDPC/STBC/greenfield, 3839-byte
/// A-MSDU. No BA session is offered/created by a capability element.
pub(crate) fn capability() -> [u8; 26] {
    let mut bytes = [0; 26];
    bytes[2] = 7 << 2; // Smallest A-MPDU factor; maximum 16-us MPDU density.
    bytes[3] = 0xff; // RX MCS0..7, actual HT-capable CONNAC2 first stream.
    bytes[15] = 1; // TX MCS set defined, equal to RX; one stream.
    bytes
}

impl Profile {
    pub(crate) fn prepare(info: RadioInfo, bss: &ScanBss) -> Result<Self, Error> {
        if !info.capabilities.phy.ht
            || info.capabilities.phy.spatial_streams == 0
            || super::channel::band(bss.channel)
                .is_none_or(|band| info.capabilities.phy.bands & band.capability() == 0)
        {
            return Err(Error::UnsupportedFirmware);
        }
        Self::parse(&bss.information_elements, bss.channel)
    }
    pub(crate) fn parse(mut ies: &[u8], channel: u8) -> Result<Self, Error> {
        if ies.len() > 2048 {
            return Err(Error::Bounds);
        }
        let (mut capability, mut operation) = (None, None);
        while !ies.is_empty() {
            let header = ies.get(..2).ok_or(Error::Bounds)?;
            let end = 2 + usize::from(header[1]);
            let body = ies.get(2..end).ok_or(Error::Bounds)?;
            match header[0] {
                45 => {
                    if capability.is_some() || body.len() != 26 {
                        return Err(Error::Bounds);
                    }
                    capability = Some(<[u8; 26]>::try_from(body).unwrap());
                }
                61 => {
                    if operation.is_some() || body.len() != 22 {
                        return Err(Error::Bounds);
                    }
                    operation = Some(<[u8; 22]>::try_from(body).unwrap());
                }
                _ => {}
            }
            ies = &ies[end..];
        }
        let capability = capability.ok_or(Error::UnsupportedFirmware)?;
        let operation = operation.ok_or(Error::UnsupportedFirmware)?;
        let cap = u16::from_le_bytes(capability[..2].try_into().unwrap());
        if operation[0] != channel
            || capability[3] == 0
            || operation[6] & !capability[3] != 0
            || capability[2] & 0xe0 != 0
            || (cap >> 2) & 3 == 2
            || operation[7..].iter().any(|&byte| byte != 0)
        {
            return Err(Error::UnsupportedFirmware);
        }
        Ok(Self {
            capability,
            operation,
        })
    }
    pub(crate) fn transmit_mcs(self) -> u8 {
        self.capability[3]
    }
    pub(crate) fn ampdu(self) -> u8 {
        self.capability[2] & 31
    }
    pub(crate) fn peer_capability(self) -> u16 {
        // Only the peer's SMPS constraint survives the local capability
        // intersection. Unsupported width/GI/LDPC/STBC/TX-AMSDU stay disabled.
        u16::from_le_bytes(self.capability[..2].try_into().unwrap()) & 12
    }
    pub(crate) fn dynamic_smps(self) -> bool {
        self.peer_capability() >> 2 == 1
    }
    pub(crate) fn request_ie() -> Vec<u8> {
        let mut bytes = vec![45, 26];
        bytes.extend_from_slice(&capability());
        bytes
    }
    pub(crate) fn received_ies(self) -> Vec<u8> {
        let mut bytes = vec![45, 26];
        bytes.extend_from_slice(&self.capability);
        bytes.extend_from_slice(&[61, 22]);
        bytes.extend_from_slice(&self.operation);
        bytes
    }
    pub(crate) fn rlm(channel: u8, receive_chains: u8) -> Vec<u8> {
        let mut bytes = vec![0; 20];
        bytes[4..8].copy_from_slice(&[2, 0, 16, 0]); // UNI_BSS_INFO_RLM.
        bytes[8] = channel;
        bytes[9] = channel;
        bytes[12] = 1; // One calibrated transmit chain, BW20 enum zero.
        bytes[13] = receive_chains;
        bytes[14] = 1; // Source RLM.short_st, not an HT short-GI capability.
        bytes[17] = u8::from(channel > 14);
        bytes
    }
}

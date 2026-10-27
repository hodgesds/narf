//! Narrow non-BA HT20 station profile, IEEE HT elements and CONNAC2 peer facts.
//! Firmware layouts: mt76_connac_mcu.{c,h}; local HT MCS shape: mt76/mac80211.c.
use super::firmware_transport::{Error, RadioInfo, ScanBss};
use alloc::{vec, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile {
    capability: [u8; 26],
    operation: [u8; 22],
    secondary: Option<u8>,
    rx_streams: u8,
    tx_streams: u8,
    rx_ldpc: bool,
    rx_stbc: bool,
    tx_ldpc: bool,
}

/// One RX/TX stream, HT20 with optional short GI, no LDPC/STBC/greenfield, 3839-byte
/// A-MSDU. No BA session is offered/created by a capability element.
pub(crate) fn capability() -> [u8; 26] {
    let mut bytes = [0; 26];
    bytes[0] = 1 << 5; // IEEE80211_HT_CAP_SGI_20, actual CONNAC2 HT radio.
    bytes[2] = 7 << 2; // Smallest A-MPDU factor; maximum 16-us MPDU density.
    bytes[3] = 0xff; // RX MCS0..7, actual HT-capable CONNAC2 first stream.
    bytes[15] = 1; // TX MCS set defined, equal to RX; one stream.
    bytes
}
pub(crate) fn capability40() -> [u8; 26] {
    let mut bytes = capability();
    bytes[0] |= 2 | 64;
    bytes
}

impl Profile {
    pub(crate) fn from_shared(
        n: &narf_wireless::association::phy::HtNegotiation,
        width: u8,
    ) -> Self {
        let mut capability = [0; 26];
        let cap = (n.peer_capability() & 12)
            | u16::from(n.tx_ldpc())
            | (u16::from(n.tx_sgi20()) << 5)
            | if width != 0 {
                2 | (u16::from(n.tx_sgi40()) << 6)
            } else {
                0
            };
        capability[..2].copy_from_slice(&cap.to_le_bytes());
        capability[2] = n.peer_ampdu_factor() | (n.peer_mpdu_density() << 2);
        capability[3..13].copy_from_slice(&n.tx_mcs());
        // Static SMPS permits one transmit data stream. Dynamic SMPS is
        // represented separately in the native WTBL and handled by firmware.
        let tx_streams = if matches!(n.peer_capability() & 12, 4 | 12) && capability[4] != 0 {
            2
        } else {
            capability[4..13].fill(0);
            1
        };
        capability[15] = n.peer_tx_params();
        Self {
            capability,
            operation: n.operation().body(),
            secondary: if width != 0 {
                n.operation().secondary()
            } else {
                None
            },
            rx_streams: if n.local_capability()[4] != 0 { 2 } else { 1 },
            tx_streams,
            rx_ldpc: n.rx_ldpc(),
            rx_stbc: n.rx_stbc(),
            tx_ldpc: n.tx_ldpc(),
        }
    }
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
            secondary: None,
            rx_streams: 1,
            tx_streams: 1,
            rx_ldpc: false,
            rx_stbc: false,
            tx_ldpc: false,
        })
    }
    pub(crate) fn transmit_mcs_mask(self) -> [u8; 10] {
        let mut mask = [0; 10];
        mask[..usize::from(self.tx_streams)]
            .copy_from_slice(&self.capability[3..3 + usize::from(self.tx_streams)]);
        mask
    }
    pub(crate) fn transmit_streams(self) -> u8 {
        self.tx_streams
    }
    pub(crate) fn receive_streams(self) -> u8 {
        self.rx_streams
    }
    pub(crate) fn receive_ldpc(self) -> bool {
        self.rx_ldpc
    }
    pub(crate) fn receive_stbc(self) -> bool {
        self.rx_stbc
    }
    pub(crate) fn transmit_ldpc(self) -> bool {
        self.tx_ldpc
    }
    pub(crate) fn ampdu(self) -> u8 {
        self.capability[2] & 31
    }
    pub(crate) fn peer_capability(self) -> u16 {
        // CONNAC2 consumes SGI20 in STA_REC_HT; the WTBL_RAW short-GI
        // programming in Linux is explicitly CONNAC1-only. No SGI40 or
        // wider-width bit survives this local HT20 capability intersection.
        let cap = u16::from_le_bytes(self.capability[..2].try_into().unwrap());
        (cap & (12 | 32))
            | u16::from(self.tx_ldpc)
            | if self.secondary.is_some() {
                2 | (u16::from(self.short_gi()) << 6)
            } else {
                0
            }
    }
    pub(crate) fn dynamic_smps(self) -> bool {
        self.peer_capability() & 12 == 4
    }
    pub(crate) fn short_gi(self) -> bool {
        self.capability[0] & if self.secondary.is_some() { 64 } else { 32 } != 0
    }
    pub(crate) fn secondary(self, channel: u8) -> Option<u8> {
        if self.capability[0] & 2 == 0 || self.capability[1] & 64 != 0 || self.operation[1] & 4 == 0
        {
            return None;
        }
        match self.operation[1] & 3 {
            1 => channel.checked_add(4),
            3 => channel.checked_sub(4),
            _ => None,
        }
    }
    pub(crate) fn with_secondary(mut self, secondary: Option<u8>) -> Result<Self, Error> {
        if secondary.is_some() && self.secondary(self.operation[0]) != secondary {
            return Err(Error::UnsupportedFirmware);
        }
        self.secondary = secondary;
        Ok(self)
    }
    pub(crate) fn negotiated_secondary(self) -> Option<u8> {
        self.secondary
    }
    pub(crate) fn request_ie(self) -> Vec<u8> {
        let mut bytes = vec![45, 26];
        bytes.extend_from_slice(&if self.secondary.is_some() {
            capability40()
        } else {
            capability()
        });
        bytes
    }
    pub(crate) fn received_ies(self) -> Vec<u8> {
        let mut bytes = vec![45, 26];
        bytes.extend_from_slice(&self.capability);
        bytes.extend_from_slice(&[61, 22]);
        bytes.extend_from_slice(&self.operation);
        bytes
    }
    pub(crate) fn rlm(self, channel: u8, receive_chains: u8) -> Vec<u8> {
        let mut bytes = vec![0; 20];
        bytes[4..8].copy_from_slice(&[2, 0, 16, 0]); // UNI_BSS_INFO_RLM.
        bytes[8] = channel;
        bytes[9] = channel;
        bytes[12] = self.tx_streams; // Actual selected transmit-chain count.
        bytes[13] = receive_chains;
        bytes[14] = 1; // Source RLM.short_st, not an HT short-GI capability.
        bytes[17] = u8::from(channel > 14);
        if let Some(secondary) = self.secondary {
            bytes[9] = ((u16::from(channel) + u16::from(secondary)) / 2) as u8;
            bytes[11] = 1; // CMD_CBW_40MHZ.
            bytes[15] = 4; // Source HT40 allowed.
            bytes[16] = if secondary > channel { 1 } else { 3 }; // SCA/SCB.
        }
        bytes
    }
}

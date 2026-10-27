// SPDX-License-Identifier: BSD-3-Clause-Clear
//! Profile-dispatched live receive view. Hardware bytes retain their own
//! layout; no WCN6855 offsets are applied to an IPQ8074 descriptor.
use super::{
    dp::{HalRxDescWcn6855, RxAttention},
    hw::HwRev,
    ipq8074::HalRxDescIpq8074,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorFormatMismatch;

#[derive(Clone, Copy, Debug)]
pub enum RxDescriptor {
    Wcn6855(HalRxDescWcn6855),
    Ipq8074(HalRxDescIpq8074),
}
macro_rules! delegate {
    ($($name:ident -> $ty:ty),* $(,)?) => {$(
        pub fn $name(&self) -> $ty {
            match self { Self::Wcn6855(d) => d.$name(), Self::Ipq8074(d) => d.$name() }
        }
    )*};
}
impl RxDescriptor {
    pub fn decode(rev: HwRev, bytes: &[u8]) -> Option<Self> {
        match rev {
            HwRev::Qca6390Hw20 => HalRxDescIpq8074::from_bytes(bytes).map(Self::Ipq8074),
            HwRev::Wcn6855Hw20 | HwRev::Wcn6855Hw21 | HwRev::Qca2066Hw21 | HwRev::Qca6698aqHw21 => {
                HalRxDescWcn6855::from_bytes(bytes).map(Self::Wcn6855)
            }
            _ => None,
        }
    }
    pub fn msdu_len_offset(rev: HwRev) -> Option<usize> {
        match rev {
            HwRev::Qca6390Hw20 => Some(core::mem::offset_of!(HalRxDescIpq8074, msdu_start) + 4),
            HwRev::Wcn6855Hw20 | HwRev::Wcn6855Hw21 | HwRev::Qca2066Hw21 | HwRev::Qca6698aqHw21 => {
                Some(core::mem::offset_of!(HalRxDescWcn6855, msdu_start) + 4)
            }
            _ => None,
        }
    }
    delegate!(first_msdu -> bool, last_msdu -> bool, l3_pad_bytes -> u8, msdu_len -> u16, decap_type -> u8,
              encrypt_valid -> bool, encrypt_type -> u32, mpdu_tid -> u8, mpdu_start_seq_no -> u16,
              mpdu_peer_id -> u16, mpdu_start_tag -> u32, msdu_done -> bool, msdu_freq -> u32);
    pub fn attention(&self) -> RxAttention {
        match self {
            Self::Wcn6855(d) => d.attention,
            Self::Ipq8074(d) => d.attention,
        }
    }
    pub fn mpdu_info1(&self) -> u32 {
        match self {
            Self::Wcn6855(d) => d.mpdu_start.info1,
            Self::Ipq8074(d) => d.mpdu_start.info1,
        }
    }
    pub fn addr2(&self) -> [u8; 6] {
        match self {
            Self::Wcn6855(d) => d.mpdu_start.addr2,
            Self::Ipq8074(d) => d.mpdu_start.addr2,
        }
    }
    /// `ath11k_dp_rx_h_80211_hdr`: the received 802.11 header (and, for a
    /// protected frame, its IV/Key ID) the RXDMA copied into `hdr_status`.
    pub fn hdr_status(&self) -> &[u8] {
        match self {
            Self::Wcn6855(d) => &d.hdr_status,
            Self::Ipq8074(d) => &d.hdr_status,
        }
    }
    pub fn rate_info(&self) -> u32 {
        match self {
            Self::Wcn6855(d) => d.msdu_start.info3,
            Self::Ipq8074(d) => d.msdu_start.info3,
        }
    }
    pub fn copy_attention_end(&mut self, last: &Self) -> Result<(), DescriptorFormatMismatch> {
        match (self, last) {
            (Self::Wcn6855(first), Self::Wcn6855(last)) => {
                first.msdu_end = last.msdu_end;
                first.attention = last.attention;
                first.mpdu_end = last.mpdu_end;
            }
            (Self::Ipq8074(first), Self::Ipq8074(last)) => {
                first.msdu_end = last.msdu_end;
                first.attention = last.attention;
                first.mpdu_end = last.mpdu_end;
            }
            _ => return Err(DescriptorFormatMismatch),
        }
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause-Clear
// Qualcomm Copyright (c) 2018-2021. Layouts from Linux ath11k/rx_desc.h.
//! `struct hal_rx_desc_qcn9074` — the RX descriptor of QCN9074, IPQ5018
//! and WCN6750 (`hw_params.hal_desc_sz`, `ath11k_hw_qcn9074_rx_desc_*`
//! in `hw.c`). 384 bytes: the IPQ8074 size, with a different MSDU-end
//! and MPDU-start layout (first/last/L3-pad move to `msdu_end.info4`,
//! sequence/encrypt-valid to `mpdu_start.info11`, TID/enc-type to
//! `mpdu_start.info9`).
use super::dp::*;
use super::hal::{field_get, genmask};
use core::mem::{offset_of, size_of};

/// `RX_MSDU_END_INFO4_*` (QCN9074 `msdu_end.info4`, a `__le16`).
pub const RX_MSDU_END_INFO4_L3_HDR_PADDING: u32 = genmask(11, 10);
pub const RX_MSDU_END_INFO4_FIRST_MSDU: u32 = 1 << 12;
pub const RX_MSDU_END_INFO4_LAST_MSDU: u32 = 1 << 13;
/// `RX_MPDU_START_INFO9_*`.
pub const RX_MPDU_START_INFO9_ENC_TYPE: u32 = genmask(5, 2);
pub const RX_MPDU_START_INFO9_TID: u32 = genmask(18, 15);
/// `RX_MPDU_START_INFO11_*` (same bits as the WCN6855 `info1` word).
pub const RX_MPDU_START_INFO11_ENCRYPT_INFO_VALID: u32 = 1 << 9;
pub const RX_MPDU_START_INFO11_MPDU_SEQ_NUM: u32 = genmask(31, 20);

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct RxMsduEndQcn9074 {
    pub info0: u16,
    pub phy_ppdu_id: u16,
    pub ip_hdr_cksum: u16,
    pub mpdu_length_info: u16,
    pub info1: u32,
    pub rule_indication: [u32; 2],
    pub info2: u32,
    pub ipv6_options_crc: u32,
    pub tcp_seq_num: u32,
    pub tcp_ack_num: u32,
    pub info3: u16,
    pub window_size: u16,
    pub tcp_udp_cksum: u16,
    pub info4: u16,
    pub sa_idx: u16,
    pub da_idx: u16,
    pub info5: u32,
    pub fse_metadata: u32,
    pub cce_metadata: u16,
    pub sa_sw_peer_id: u16,
    pub info6: u32,
    pub cum_l4_cksum: u16,
    pub cum_ip_length: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct RxMsduStartQcn9074 {
    pub info0: u16,
    pub phy_ppdu_id: u16,
    pub info1: u32,
    pub info2: u32,
    pub toeplitz_hash: u32,
    pub flow_id_toeplitz: u32,
    pub info3: u32,
    pub ppdu_start_timestamp: u32,
    pub phy_meta_data: u32,
    pub vlan_ctag_c1: u16,
    pub vlan_stag_c1: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct RxMpduStartQcn9074 {
    pub info7: u32,
    pub reo_queue_desc_lo: u32,
    pub info8: u32,
    pub pn: [u32; 4],
    pub info9: u32,
    pub peer_meta_data: u32,
    pub info10: u16,
    pub phy_ppdu_id: u16,
    pub ast_index: u16,
    pub sw_peer_id: u16,
    pub info11: u32,
    pub info12: u32,
    pub info13: u32,
    pub frame_ctrl: u16,
    pub duration: u16,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub seq_ctrl: u16,
    pub addr4: [u8; 6],
    pub qos_ctrl: u16,
    pub ht_ctrl: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct HalRxDescQcn9074 {
    pub msdu_end_tag: u32,
    pub msdu_end: RxMsduEndQcn9074,
    pub rx_attn_tag: u32,
    pub attention: RxAttention,
    pub msdu_start_tag: u32,
    pub msdu_start: RxMsduStartQcn9074,
    pub rx_padding0: [u8; HAL_RX_DESC_PADDING0_BYTES],
    pub mpdu_start_tag: u32,
    pub mpdu_start: RxMpduStartQcn9074,
    pub mpdu_end_tag: u32,
    pub mpdu_end: RxMpduEnd,
    pub rx_padding1: [u8; HAL_RX_DESC_PADDING1_BYTES],
    pub hdr_status_tag: u32,
    pub phy_ppdu_id: u32,
    pub hdr_status: [u8; HAL_RX_DESC_HDR_STATUS_LEN],
}

impl HalRxDescQcn9074 {
    /// `sizeof(struct hal_rx_desc_qcn9074)` = `hw_params.hal_desc_sz`.
    pub const SIZE: usize = size_of::<HalRxDescQcn9074>();

    /// Decode from the first [`Self::SIZE`] bytes of an RX buffer.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::SIZE {
            return None;
        }
        // SAFETY: `HalRxDescQcn9074` is `repr(C, packed)` plain old data
        // (integers and byte arrays; every bit pattern valid) and `b`
        // holds at least `SIZE` bytes; `read_unaligned` copes with any
        // alignment.
        Some(unsafe { core::ptr::read_unaligned(b.as_ptr() as *const Self) })
    }

    /// `ath11k_hw_qcn9074_rx_desc_get_first_msdu`.
    pub fn first_msdu(&self) -> bool {
        let v = self.msdu_end.info4 as u32;
        v & RX_MSDU_END_INFO4_FIRST_MSDU != 0
    }
    /// `ath11k_hw_qcn9074_rx_desc_get_last_msdu`.
    pub fn last_msdu(&self) -> bool {
        let v = self.msdu_end.info4 as u32;
        v & RX_MSDU_END_INFO4_LAST_MSDU != 0
    }
    /// `ath11k_hw_qcn9074_rx_desc_get_l3_pad_bytes`.
    pub fn l3_pad_bytes(&self) -> u8 {
        field_get(RX_MSDU_END_INFO4_L3_HDR_PADDING, self.msdu_end.info4 as u32) as u8
    }
    /// `ath11k_hw_qcn9074_rx_desc_get_msdu_len`.
    pub fn msdu_len(&self) -> u16 {
        field_get(RX_MSDU_START_INFO1_MSDU_LENGTH, self.msdu_start.info1) as u16
    }
    /// `ath11k_hw_qcn9074_rx_desc_get_decap_type`.
    pub fn decap_type(&self) -> u8 {
        field_get(RX_MSDU_START_INFO2_DECAP_FORMAT, self.msdu_start.info2) as u8
    }
    /// `ath11k_hw_qcn9074_rx_desc_encrypt_valid`.
    pub fn encrypt_valid(&self) -> bool {
        let v = self.mpdu_start.info11;
        v & RX_MPDU_START_INFO11_ENCRYPT_INFO_VALID != 0
    }
    /// `ath11k_hw_qcn9074_rx_desc_get_encrypt_type`.
    pub fn encrypt_type(&self) -> u32 {
        field_get(RX_MPDU_START_INFO9_ENC_TYPE, self.mpdu_start.info9)
    }
    /// `ath11k_hw_qcn9074_rx_desc_get_mpdu_tid`.
    pub fn mpdu_tid(&self) -> u8 {
        field_get(RX_MPDU_START_INFO9_TID, self.mpdu_start.info9) as u8
    }
    /// `ath11k_hw_qcn9074_rx_desc_get_mpdu_start_seq_no`.
    pub fn mpdu_start_seq_no(&self) -> u16 {
        field_get(RX_MPDU_START_INFO11_MPDU_SEQ_NUM, self.mpdu_start.info11) as u16
    }
    /// `ath11k_hw_qcn9074_rx_desc_get_mpdu_peer_id`.
    pub fn mpdu_peer_id(&self) -> u16 {
        self.mpdu_start.sw_peer_id
    }
    /// `ath11k_hw_qcn9074_rx_desc_get_mpdu_start_tag`.
    pub fn mpdu_start_tag(&self) -> u32 {
        field_get(HAL_TLV_HDR_TAG, self.mpdu_start_tag)
    }
    /// `ath11k_dp_rx_h_attn_msdu_done` on the common attention TLV.
    pub fn msdu_done(&self) -> bool {
        let v = self.attention.info2;
        v & RX_ATTENTION_INFO2_MSDU_DONE != 0
    }
    /// `ath11k_hw_qcn9074_rx_desc_get_msdu_freq` (`phy_meta_data`).
    pub fn msdu_freq(&self) -> u32 {
        self.msdu_start.phy_meta_data
    }
}

// Offsets computed from Linux `rx_desc.h` (`__packed` layout).
const _: () = assert!(size_of::<RxMsduEndQcn9074>() == 68);
const _: () = assert!(size_of::<RxMsduStartQcn9074>() == 36);
const _: () = assert!(size_of::<RxMpduStartQcn9074>() == 92);
const _: () = assert!(size_of::<HalRxDescQcn9074>() == 384);
const _: () = assert!(offset_of!(HalRxDescQcn9074, attention) == 76);
const _: () = assert!(offset_of!(HalRxDescQcn9074, msdu_start) == 92);
const _: () = assert!(offset_of!(HalRxDescQcn9074, mpdu_start) == 136);
const _: () = assert!(offset_of!(HalRxDescQcn9074, mpdu_end) == 232);
const _: () = assert!(offset_of!(HalRxDescQcn9074, hdr_status) == 264);

#[cfg(any(test, feature = "kernel-test"))]
#[path = "qcn9074_tests.rs"]
mod tests;

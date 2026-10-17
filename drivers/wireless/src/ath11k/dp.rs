//! Data-path descriptor layouts (TCL / REO / WBM / RXDMA) and the
//! WCN6855 RX descriptor.
//!
//! Layouts only — the DP rings' runtime is a later phase. Every struct
//! is `#[repr(C, packed)]` like the Linux `__packed` original and has a
//! `size_of` assertion against the value `sizeof()` gives for the Linux
//! definition (checked by compiling `hal_desc.h` / `rx_desc.h`). Field
//! masks keep the Linux names so cross-references stay mechanical.
//! The HAL ring types and per-type ring configuration these
//! descriptors live in are in [`super::hal`]
//! ([`super::hal::HalRingType`], [`super::hal::SRNG_CONFIG_TEMPLATE`]).
//!
//! Linux references (BSD-3-Clause-Clear):
//! - `drivers/net/wireless/ath/ath11k/dp.h` — ring sizes.
//! - `drivers/net/wireless/ath/ath11k/hal_desc.h` — TCL / REO / WBM
//!   descriptors, buffer address info, TLV header.
//! - `drivers/net/wireless/ath/ath11k/rx_desc.h` — `hal_rx_desc_wcn6855`.
//! - `drivers/net/wireless/ath/ath11k/hw.c` —
//!   `ath11k_hw_wcn6855_rx_desc_*` accessors.

#![allow(dead_code)]

use core::mem::{offset_of, size_of};

use super::hal::{field_get, field_prep, genmask};

// ── Ring-size constants (dp.h) ─────────────────────────────────────

pub const DP_TCL_NUM_RING_MAX: usize = 3;
pub const DP_TCL_DATA_RING_SIZE: u32 = 512;
pub const DP_TCL_DATA_RING_SIZE_WCN6750: u32 = 2048;
pub const DP_TX_COMP_RING_SIZE: u32 = 32768;
pub const DP_TCL_CMD_RING_SIZE: u32 = 32;
pub const DP_TCL_STATUS_RING_SIZE: u32 = 32;
pub const DP_REO_DST_RING_MAX: usize = 4;
pub const DP_REO_DST_RING_SIZE: u32 = 2048;
pub const DP_REO_REINJECT_RING_SIZE: u32 = 32;
pub const DP_RX_RELEASE_RING_SIZE: u32 = 1024;
pub const DP_REO_EXCEPTION_RING_SIZE: u32 = 128;
pub const DP_REO_CMD_RING_SIZE: u32 = 256;
pub const DP_REO_STATUS_RING_SIZE: u32 = 2048;
pub const DP_WBM_RELEASE_RING_SIZE: u32 = 64;
pub const DP_RXDMA_BUF_RING_SIZE: u32 = 4096;
pub const DP_RXDMA_REFILL_RING_SIZE: u32 = 2048;
pub const DP_RXDMA_ERR_DST_RING_SIZE: u32 = 1024;
pub const DP_RXDMA_MON_STATUS_RING_SIZE: u32 = 1024;
pub const DP_RXDMA_MONITOR_BUF_RING_SIZE: u32 = 4096;
pub const DP_RXDMA_MONITOR_DST_RING_SIZE: u32 = 2048;
pub const DP_RXDMA_MONITOR_DESC_RING_SIZE: u32 = 4096;
pub const DP_RX_BUFFER_SIZE: u32 = 2048;
pub const DP_RX_BUFFER_ALIGN_SIZE: u32 = 128;

// ── struct ath11k_buffer_addr ─────────────────────────────────────

pub const BUFFER_ADDR_INFO0_ADDR: u32 = genmask(31, 0);
pub const BUFFER_ADDR_INFO1_ADDR: u32 = genmask(7, 0);
pub const BUFFER_ADDR_INFO1_RET_BUF_MGR: u32 = genmask(10, 8);
pub const BUFFER_ADDR_INFO1_SW_COOKIE: u32 = genmask(31, 11);

/// `struct ath11k_buffer_addr` (8 bytes): a 40-bit buffer address, the
/// return buffer manager and a 21-bit software cookie.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BufferAddr {
    pub info0: u32,
    pub info1: u32,
}

impl BufferAddr {
    /// `ath11k_hal_rx_buf_addr_info_set`.
    pub const fn new(paddr: u64, cookie: u32, manager: u8) -> Self {
        BufferAddr {
            info0: field_prep(BUFFER_ADDR_INFO0_ADDR, paddr as u32),
            info1: field_prep(BUFFER_ADDR_INFO1_ADDR, (paddr >> 32) as u32)
                | field_prep(BUFFER_ADDR_INFO1_RET_BUF_MGR, manager as u32)
                | field_prep(BUFFER_ADDR_INFO1_SW_COOKIE, cookie),
        }
    }

    /// `ath11k_hal_rx_buf_addr_info_get`: (paddr, cookie, rbm).
    pub const fn get(&self) -> (u64, u32, u8) {
        let i0 = self.info0;
        let i1 = self.info1;
        (
            field_get(BUFFER_ADDR_INFO0_ADDR, i0) as u64
                | ((field_get(BUFFER_ADDR_INFO1_ADDR, i1) as u64) << 32),
            field_get(BUFFER_ADDR_INFO1_SW_COOKIE, i1),
            field_get(BUFFER_ADDR_INFO1_RET_BUF_MGR, i1) as u8,
        )
    }
}

// ── TLV header ────────────────────────────────────────────────────

pub const HAL_TLV_HDR_TAG: u32 = genmask(9, 1);
pub const HAL_TLV_HDR_LEN: u32 = genmask(25, 10);
pub const HAL_TLV_USR_ID: u32 = genmask(31, 26);
pub const HAL_TLV_ALIGN: usize = 4;
/// `HAL_SRNG_TLV_HDR_TAG` / `_LEN` (hal.h; same fields).
pub const HAL_SRNG_TLV_HDR_TAG: u32 = genmask(9, 1);
pub const HAL_SRNG_TLV_HDR_LEN: u32 = genmask(25, 10);

/// `struct hal_tlv_hdr` without the flexible `value[]` (4 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalTlvHdr {
    pub tl: u32,
}

impl HalTlvHdr {
    pub const fn new(tag: u32, len: u32) -> Self {
        HalTlvHdr {
            tl: field_prep(HAL_TLV_HDR_TAG, tag) | field_prep(HAL_TLV_HDR_LEN, len),
        }
    }
}

/// `enum hal_tlv_tag` values the TCL / REO rings carry.
pub mod tlv_tag {
    pub const HAL_REO_GET_QUEUE_STATS: u32 = 0x0132;
    pub const HAL_REO_GET_QUEUE_STATS_STATUS: u32 = 0x0137;
    pub const HAL_TCL_DATA_CMD: u32 = 0x0144;
    pub const HAL_TCL_GSE_CMD: u32 = 0x0145;
    pub const HAL_CE_SRC_DESC: u32 = 0x0196;
    pub const HAL_CE_DST_DESC: u32 = 0x01a4;
}

// ── rx_mpdu_desc / rx_msdu_desc ───────────────────────────────────

pub const RX_MPDU_DESC_INFO0_MSDU_COUNT: u32 = genmask(7, 0);
pub const RX_MPDU_DESC_INFO0_SEQ_NUM: u32 = genmask(19, 8);
pub const RX_MPDU_DESC_INFO0_FRAG_FLAG: u32 = 1 << 20;
pub const RX_MPDU_DESC_INFO0_MPDU_RETRY: u32 = 1 << 21;
pub const RX_MPDU_DESC_INFO0_AMPDU_FLAG: u32 = 1 << 22;
pub const RX_MPDU_DESC_INFO0_BAR_FRAME: u32 = 1 << 23;
pub const RX_MPDU_DESC_INFO0_VALID_PN: u32 = 1 << 24;
pub const RX_MPDU_DESC_INFO0_VALID_SA: u32 = 1 << 25;
pub const RX_MPDU_DESC_INFO0_SA_IDX_TIMEOUT: u32 = 1 << 26;
pub const RX_MPDU_DESC_INFO0_VALID_DA: u32 = 1 << 27;
pub const RX_MPDU_DESC_INFO0_DA_MCBC: u32 = 1 << 28;
pub const RX_MPDU_DESC_INFO0_DA_IDX_TIMEOUT: u32 = 1 << 29;
pub const RX_MPDU_DESC_INFO0_RAW_MPDU: u32 = 1 << 30;
pub const RX_MPDU_DESC_META_DATA_PEER_ID: u32 = genmask(15, 0);

/// `struct rx_mpdu_desc` (8 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxMpduDesc {
    pub info0: u32,
    pub meta_data: u32,
}

pub const RX_MSDU_DESC_INFO0_FIRST_MSDU_IN_MPDU: u32 = 1 << 0;
pub const RX_MSDU_DESC_INFO0_LAST_MSDU_IN_MPDU: u32 = 1 << 1;
pub const RX_MSDU_DESC_INFO0_MSDU_CONTINUATION: u32 = 1 << 2;
pub const RX_MSDU_DESC_INFO0_MSDU_LENGTH: u32 = genmask(16, 3);
pub const RX_MSDU_DESC_INFO0_REO_DEST_IND: u32 = genmask(21, 17);
pub const RX_MSDU_DESC_INFO0_MSDU_DROP: u32 = 1 << 22;
pub const RX_MSDU_DESC_INFO0_VALID_SA: u32 = 1 << 23;
pub const RX_MSDU_DESC_INFO0_SA_IDX_TIMEOUT: u32 = 1 << 24;
pub const RX_MSDU_DESC_INFO0_VALID_DA: u32 = 1 << 25;
pub const RX_MSDU_DESC_INFO0_DA_MCBC: u32 = 1 << 26;
pub const RX_MSDU_DESC_INFO0_DA_IDX_TIMEOUT: u32 = 1 << 27;

/// `struct rx_msdu_desc` (8 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxMsduDesc {
    pub info0: u32,
    pub rsvd0: u32,
}

// ── REO destination / entrance rings ──────────────────────────────

pub const HAL_REO_DEST_RING_INFO0_QUEUE_ADDR_HI: u32 = genmask(7, 0);
pub const HAL_REO_DEST_RING_INFO0_BUFFER_TYPE: u32 = 1 << 8;
pub const HAL_REO_DEST_RING_INFO0_PUSH_REASON: u32 = genmask(10, 9);
pub const HAL_REO_DEST_RING_INFO0_ERROR_CODE: u32 = genmask(15, 11);
pub const HAL_REO_DEST_RING_INFO0_RX_QUEUE_NUM: u32 = genmask(31, 16);
pub const HAL_REO_DEST_RING_INFO1_REORDER_INFO_VALID: u32 = 1 << 0;
pub const HAL_REO_DEST_RING_INFO1_REORDER_OPCODE: u32 = genmask(4, 1);
pub const HAL_REO_DEST_RING_INFO1_REORDER_SLOT_IDX: u32 = genmask(12, 5);
pub const HAL_REO_DEST_RING_INFO2_RING_ID: u32 = genmask(27, 20);
pub const HAL_REO_DEST_RING_INFO2_LOOPING_COUNT: u32 = genmask(31, 28);

/// `struct hal_reo_dest_ring` (64 bytes) — REO2SW entry, one MSDU.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalReoDestRing {
    pub buf_addr_info: BufferAddr,
    pub rx_mpdu_info: RxMpduDesc,
    pub rx_msdu_info: RxMsduDesc,
    pub queue_addr_lo: u32,
    pub info0: u32,
    pub info1: u32,
    pub rsvd0: u32,
    pub rsvd1: u32,
    pub rsvd2: u32,
    pub rsvd3: u32,
    pub rsvd4: u32,
    pub rsvd5: u32,
    pub info2: u32,
}

pub const HAL_REO_ENTR_RING_INFO0_QUEUE_ADDR_HI: u32 = genmask(7, 0);
pub const HAL_REO_ENTR_RING_INFO0_MPDU_BYTE_COUNT: u32 = genmask(21, 8);
pub const HAL_REO_ENTR_RING_INFO0_DEST_IND: u32 = genmask(26, 22);
pub const HAL_REO_ENTR_RING_INFO0_FRAMELESS_BAR: u32 = 1 << 27;
pub const HAL_REO_ENTR_RING_INFO1_RXDMA_PUSH_REASON: u32 = genmask(1, 0);
pub const HAL_REO_ENTR_RING_INFO1_RXDMA_ERROR_CODE: u32 = genmask(6, 2);

/// `struct hal_reo_entrance_ring` (32 bytes) — SW2REO / RXDMA2SW entry.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalReoEntranceRing {
    pub buf_addr_info: BufferAddr,
    pub rx_mpdu_info: RxMpduDesc,
    pub queue_addr_lo: u32,
    pub info0: u32,
    pub info1: u32,
    pub info2: u32,
}

/// `sizeof(struct hal_reo_get_queue_stats)` (REO_CMD ring entry body).
pub const HAL_REO_GET_QUEUE_STATS_SIZE: usize = 36;
/// `sizeof(struct hal_reo_get_queue_stats_status)` (REO_STATUS body).
pub const HAL_REO_GET_QUEUE_STATS_STATUS_SIZE: usize = 100;

// ── TCL data / status ─────────────────────────────────────────────

pub const HAL_TCL_DATA_CMD_INFO0_DESC_TYPE: u32 = 1 << 0;
pub const HAL_TCL_DATA_CMD_INFO0_EPD: u32 = 1 << 1;
pub const HAL_TCL_DATA_CMD_INFO0_ENCAP_TYPE: u32 = genmask(3, 2);
pub const HAL_TCL_DATA_CMD_INFO0_ENCRYPT_TYPE: u32 = genmask(7, 4);
pub const HAL_TCL_DATA_CMD_INFO0_SRC_BUF_SWAP: u32 = 1 << 8;
pub const HAL_TCL_DATA_CMD_INFO0_LNK_META_SWAP: u32 = 1 << 9;
pub const HAL_TCL_DATA_CMD_INFO0_SEARCH_TYPE: u32 = genmask(13, 12);
pub const HAL_TCL_DATA_CMD_INFO0_ADDR_EN: u32 = genmask(15, 14);
pub const HAL_TCL_DATA_CMD_INFO0_CMD_NUM: u32 = genmask(31, 16);
pub const HAL_TCL_DATA_CMD_INFO1_DATA_LEN: u32 = genmask(15, 0);
pub const HAL_TCL_DATA_CMD_INFO1_IP4_CKSUM_EN: u32 = 1 << 16;
pub const HAL_TCL_DATA_CMD_INFO1_UDP4_CKSUM_EN: u32 = 1 << 17;
pub const HAL_TCL_DATA_CMD_INFO1_UDP6_CKSUM_EN: u32 = 1 << 18;
pub const HAL_TCL_DATA_CMD_INFO1_TCP4_CKSUM_EN: u32 = 1 << 19;
pub const HAL_TCL_DATA_CMD_INFO1_TCP6_CKSUM_EN: u32 = 1 << 20;
pub const HAL_TCL_DATA_CMD_INFO1_TO_FW: u32 = 1 << 21;
pub const HAL_TCL_DATA_CMD_INFO1_PKT_OFFSET: u32 = genmask(31, 23);
pub const HAL_TCL_DATA_CMD_INFO2_BUF_TIMESTAMP: u32 = genmask(18, 0);
pub const HAL_TCL_DATA_CMD_INFO2_BUF_T_VALID: u32 = 1 << 19;
pub const HAL_TCL_DATA_CMD_INFO2_TID_OVERWRITE: u32 = 1 << 21;
pub const HAL_TCL_DATA_CMD_INFO2_TID: u32 = genmask(25, 22);
pub const HAL_TCL_DATA_CMD_INFO2_LMAC_ID: u32 = genmask(27, 26);
pub const HAL_TCL_DATA_CMD_INFO3_DSCP_TID_TABLE_IDX: u32 = genmask(5, 0);
pub const HAL_TCL_DATA_CMD_INFO3_SEARCH_INDEX: u32 = genmask(25, 6);
pub const HAL_TCL_DATA_CMD_INFO3_CACHE_SET_NUM: u32 = genmask(29, 26);
pub const HAL_TCL_DATA_CMD_INFO4_RING_ID: u32 = genmask(27, 20);
pub const HAL_TCL_DATA_CMD_INFO4_LOOPING_COUNT: u32 = genmask(31, 28);

/// `struct hal_tcl_data_cmd` (28 bytes). On the TCL_DATA ring each
/// entry is a [`HalTlvHdr`] followed by this (32 bytes,
/// `HAL_TCL_DESC_LEN` = 28).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalTclDataCmd {
    pub buf_addr_info: BufferAddr,
    pub info0: u32,
    pub info1: u32,
    pub info2: u32,
    pub info3: u32,
    pub info4: u32,
}

/// `HAL_TCL_DESC_LEN`.
pub const HAL_TCL_DESC_LEN: usize = size_of::<HalTclDataCmd>();
/// `sizeof(struct hal_tcl_gse_cmd)`.
pub const HAL_TCL_GSE_CMD_SIZE: usize = 28;

pub const HAL_TCL_STATUS_RING_INFO0_GSE_CTRL: u32 = genmask(3, 0);
pub const HAL_TCL_STATUS_RING_INFO0_GSE_SEL: u32 = 1 << 4;
pub const HAL_TCL_STATUS_RING_INFO0_CACHE_OP_RES: u32 = genmask(6, 5);
pub const HAL_TCL_STATUS_RING_INFO0_MSDU_CNT: u32 = genmask(31, 8);
pub const HAL_TCL_STATUS_RING_INFO1_HASH_IDX: u32 = genmask(19, 0);
pub const HAL_TCL_STATUS_RING_INFO2_RING_ID: u32 = genmask(27, 20);
pub const HAL_TCL_STATUS_RING_INFO2_LOOPING_COUNT: u32 = genmask(31, 28);

/// `struct hal_tcl_status_ring` (32 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalTclStatusRing {
    pub info0: u32,
    pub msdu_byte_count: u32,
    pub msdu_timestamp: u32,
    pub meta_data: [u32; 2],
    pub info1: u32,
    pub rsvd0: u32,
    pub info2: u32,
}

// ── WBM ───────────────────────────────────────────────────────────

/// `struct hal_wbm_link_desc` (8 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalWbmLinkDesc {
    pub buf_addr_info: BufferAddr,
}

/// `struct hal_wbm_buffer_ring` (8 bytes) — RXDMA buffer ring entry.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalWbmBufferRing {
    pub buf_addr_info: BufferAddr,
}

/// `struct hal_tx_rate_stats` (8 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalTxRateStats {
    pub info0: u32,
    pub tsf: u32,
}

pub const HAL_WBM_RELEASE_INFO0_REL_SRC_MODULE: u32 = genmask(2, 0);
pub const HAL_WBM_RELEASE_INFO0_BM_ACTION: u32 = genmask(5, 3);
pub const HAL_WBM_RELEASE_INFO0_DESC_TYPE: u32 = genmask(8, 6);
pub const HAL_WBM_RELEASE_INFO0_FIRST_MSDU_IDX: u32 = genmask(12, 9);
pub const HAL_WBM_RELEASE_INFO0_TQM_RELEASE_REASON: u32 = genmask(16, 13);
pub const HAL_WBM_RELEASE_INFO0_RXDMA_PUSH_REASON: u32 = genmask(18, 17);
pub const HAL_WBM_RELEASE_INFO0_RXDMA_ERROR_CODE: u32 = genmask(23, 19);
pub const HAL_WBM_RELEASE_INFO0_REO_PUSH_REASON: u32 = genmask(25, 24);
pub const HAL_WBM_RELEASE_INFO0_REO_ERROR_CODE: u32 = genmask(30, 26);
pub const HAL_WBM_RELEASE_INFO0_WBM_INTERNAL_ERROR: u32 = 1 << 31;
pub const HAL_WBM_RELEASE_INFO1_TQM_STATUS_NUMBER: u32 = genmask(23, 0);
pub const HAL_WBM_RELEASE_INFO1_TRANSMIT_COUNT: u32 = genmask(30, 24);
pub const HAL_WBM_RELEASE_INFO2_ACK_FRAME_RSSI: u32 = genmask(7, 0);
pub const HAL_WBM_RELEASE_INFO2_SW_REL_DETAILS_VALID: u32 = 1 << 8;
pub const HAL_WBM_RELEASE_INFO2_FIRST_MSDU: u32 = 1 << 9;
pub const HAL_WBM_RELEASE_INFO2_LAST_MSDU: u32 = 1 << 10;
pub const HAL_WBM_RELEASE_INFO2_MSDU_IN_AMSDU: u32 = 1 << 11;
pub const HAL_WBM_RELEASE_INFO2_FW_TX_NOTIF_FRAME: u32 = 1 << 12;
pub const HAL_WBM_RELEASE_INFO2_BUFFER_TIMESTAMP: u32 = genmask(31, 13);
pub const HAL_WBM_RELEASE_INFO3_PEER_ID: u32 = genmask(15, 0);
pub const HAL_WBM_RELEASE_INFO3_TID: u32 = genmask(19, 16);
pub const HAL_WBM_RELEASE_INFO3_RING_ID: u32 = genmask(27, 20);
pub const HAL_WBM_RELEASE_INFO3_LOOPING_COUNT: u32 = genmask(31, 28);
pub const HAL_WBM_REL_HTT_TX_COMP_INFO0_STATUS: u32 = genmask(12, 9);
pub const HAL_WBM_REL_HTT_TX_COMP_INFO0_REINJ_REASON: u32 = genmask(16, 13);
pub const HAL_WBM_REL_HTT_TX_COMP_INFO0_EXP_FRAME: u32 = 1 << 17;

/// `struct hal_wbm_release_ring` (32 bytes) — TX completion / RX error
/// release entry.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalWbmReleaseRing {
    pub buf_addr_info: BufferAddr,
    pub info0: u32,
    pub info1: u32,
    pub info2: u32,
    pub rate_stats: HalTxRateStats,
    pub info3: u32,
}

// ── hal_rx_desc_wcn6855 (rx_desc.h) ───────────────────────────────

pub const RX_ATTENTION_INFO1_FIRST_MPDU: u32 = 1 << 0;
pub const RX_ATTENTION_INFO1_MCAST_BCAST: u32 = 1 << 2;
pub const RX_ATTENTION_INFO1_MSDU_LEN_ERR: u32 = 1 << 17;
pub const RX_ATTENTION_INFO1_TCP_UDP_CKSUM_FAIL: u32 = 1 << 18;
pub const RX_ATTENTION_INFO1_IP_CKSUM_FAIL: u32 = 1 << 19;
pub const RX_ATTENTION_INFO1_MPDU_LEN_ERR: u32 = 1 << 27;
pub const RX_ATTENTION_INFO1_TKIP_MIC_ERR: u32 = 1 << 28;
pub const RX_ATTENTION_INFO1_DECRYPT_ERR: u32 = 1 << 29;
pub const RX_ATTENTION_INFO1_UNDECRYPT_FRAME_ERR: u32 = 1 << 30;
pub const RX_ATTENTION_INFO1_FCS_ERR: u32 = 1 << 31;
pub const RX_ATTENTION_INFO2_DCRYPT_STATUS_CODE: u32 = genmask(12, 10);
pub const RX_ATTENTION_INFO2_MSDU_DONE: u32 = 1 << 31;

/// `struct rx_attention` (12 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxAttention {
    pub info0: u16,
    pub phy_ppdu_id: u16,
    pub info1: u32,
    pub info2: u32,
}

pub const RX_MPDU_START_INFO1_MPDU_FCTRL_VALID: u32 = 1 << 0;
pub const RX_MPDU_START_INFO1_MAC_ADDR2_VALID: u32 = 1 << 3;
pub const RX_MPDU_START_INFO1_MPDU_SEQ_CTRL_VALID: u32 = 1 << 6;
pub const RX_MPDU_START_INFO1_ENCRYPT_INFO_VALID: u32 = 1 << 9;
pub const RX_MPDU_START_INFO1_MPDU_SEQ_NUM: u32 = genmask(31, 20);
pub const RX_MPDU_START_INFO2_ENC_TYPE: u32 = genmask(5, 2);
pub const RX_MPDU_START_INFO2_TID_WCN6855: u32 = genmask(18, 15);

/// `struct rx_mpdu_start_wcn6855` (92 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxMpduStartWcn6855 {
    pub info3: u32,
    pub reo_queue_desc_lo: u32,
    pub info4: u32,
    pub pn: [u32; 4],
    pub info2: u32,
    pub peer_meta_data: u32,
    pub info0: u16,
    pub phy_ppdu_id: u16,
    pub ast_index: u16,
    pub sw_peer_id: u16,
    pub info1: u32,
    pub info5: u32,
    pub info6: u32,
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

pub const RX_MSDU_START_INFO1_MSDU_LENGTH: u32 = genmask(13, 0);
pub const RX_MSDU_START_INFO2_DECAP_FORMAT: u32 = genmask(9, 8);
pub const RX_MSDU_START_INFO2_MESH_CTRL_PRESENT: u32 = 1 << 22;
pub const RX_MSDU_START_INFO2_LDPC: u32 = 1 << 23;
pub const RX_MSDU_START_INFO3_PKT_TYPE: u32 = genmask(11, 8);
pub const RX_MSDU_START_INFO3_SGI: u32 = genmask(14, 13);
pub const RX_MSDU_START_INFO3_RATE_MCS: u32 = genmask(18, 15);
pub const RX_MSDU_START_INFO3_RECV_BW: u32 = genmask(20, 19);
pub const RX_MSDU_START_INFO3_MIMO_SS_BITMAP: u32 = genmask(31, 24);

/// `struct rx_msdu_start_wcn6855` (36 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxMsduStartWcn6855 {
    pub info0: u16,
    pub phy_ppdu_id: u16,
    pub info1: u32,
    pub info2: u32,
    pub toeplitz_hash: u32,
    pub flow_id_toeplitz: u32,
    pub info3: u32,
    pub ppdu_start_timestamp: u32,
    pub phy_meta_data: u32,
    pub vlan_ctag_ci: u16,
    pub vlan_stag_ci: u16,
}

pub const RX_MSDU_END_INFO2_FIRST_MSDU_WCN6855: u32 = 1 << 28;
pub const RX_MSDU_END_INFO2_LAST_MSDU_WCN6855: u32 = 1 << 29;
pub const RX_MSDU_END_INFO2_L3_HDR_PADDING: u32 = genmask(27, 26);

/// `struct rx_msdu_end_wcn6855` (76 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxMsduEndWcn6855 {
    pub info0: u16,
    pub phy_ppdu_id: u16,
    pub ip_hdr_cksum: u16,
    pub reported_mpdu_len: u16,
    pub info1: u32,
    pub ext_wapi_pn: [u32; 2],
    pub info4: u32,
    pub ipv6_options_crc: u32,
    pub tcp_seq_num: u32,
    pub tcp_ack_num: u32,
    pub info3: u16,
    pub window_size: u16,
    pub info2: u32,
    pub sa_idx: u16,
    pub da_idx: u16,
    pub info5: u32,
    pub fse_metadata: u32,
    pub cce_metadata: u16,
    pub sa_sw_peer_id: u16,
    pub rule_indication: [u32; 2],
    pub info6: u32,
    pub info7: u32,
}

/// `struct rx_mpdu_end` (8 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxMpduEnd {
    pub info0: u16,
    pub phy_ppdu_id: u16,
    pub info1: u32,
}

pub const HAL_RX_DESC_PADDING0_BYTES: usize = 4;
pub const HAL_RX_DESC_PADDING1_BYTES: usize = 16;
pub const HAL_RX_DESC_HDR_STATUS_LEN: usize = 120;

/// `struct hal_rx_desc_wcn6855` (392 bytes; `hw_params.hal_desc_sz`
/// for WCN6855). The MSDU payload follows at offset 392.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HalRxDescWcn6855 {
    pub msdu_end_tag: u32,
    pub msdu_end: RxMsduEndWcn6855,
    pub rx_attn_tag: u32,
    pub attention: RxAttention,
    pub msdu_start_tag: u32,
    pub msdu_start: RxMsduStartWcn6855,
    pub rx_padding0: [u8; HAL_RX_DESC_PADDING0_BYTES],
    pub mpdu_start_tag: u32,
    pub mpdu_start: RxMpduStartWcn6855,
    pub mpdu_end_tag: u32,
    pub mpdu_end: RxMpduEnd,
    pub rx_padding1: [u8; HAL_RX_DESC_PADDING1_BYTES],
    pub hdr_status_tag: u32,
    pub phy_ppdu_id: u32,
    pub hdr_status: [u8; HAL_RX_DESC_HDR_STATUS_LEN],
}

impl HalRxDescWcn6855 {
    /// Size of the descriptor in front of every RX buffer.
    pub const SIZE: usize = size_of::<HalRxDescWcn6855>();

    /// Decode from the first [`Self::SIZE`] bytes of an RX buffer.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::SIZE {
            return None;
        }
        // SAFETY: `HalRxDescWcn6855` is `repr(C, packed)` plain old data
        // (integers and byte arrays; every bit pattern valid) and `b`
        // holds at least `SIZE` bytes; `read_unaligned` copes with any
        // alignment.
        Some(unsafe { core::ptr::read_unaligned(b.as_ptr() as *const Self) })
    }

    /// `ath11k_hw_wcn6855_rx_desc_get_first_msdu`.
    pub fn first_msdu(&self) -> bool {
        let v = self.msdu_end.info2;
        v & RX_MSDU_END_INFO2_FIRST_MSDU_WCN6855 != 0
    }
    /// `ath11k_hw_wcn6855_rx_desc_get_last_msdu`.
    pub fn last_msdu(&self) -> bool {
        let v = self.msdu_end.info2;
        v & RX_MSDU_END_INFO2_LAST_MSDU_WCN6855 != 0
    }
    /// `ath11k_hw_wcn6855_rx_desc_get_l3_pad_bytes`.
    pub fn l3_pad_bytes(&self) -> u8 {
        field_get(RX_MSDU_END_INFO2_L3_HDR_PADDING, self.msdu_end.info2) as u8
    }
    /// `ath11k_hw_wcn6855_rx_desc_get_msdu_len`.
    pub fn msdu_len(&self) -> u16 {
        field_get(RX_MSDU_START_INFO1_MSDU_LENGTH, self.msdu_start.info1) as u16
    }
    /// `ath11k_hw_wcn6855_rx_desc_get_decap_type`.
    pub fn decap_type(&self) -> u8 {
        field_get(RX_MSDU_START_INFO2_DECAP_FORMAT, self.msdu_start.info2) as u8
    }
    /// `ath11k_hw_wcn6855_rx_desc_encrypt_valid`.
    pub fn encrypt_valid(&self) -> bool {
        let v = self.mpdu_start.info1;
        v & RX_MPDU_START_INFO1_ENCRYPT_INFO_VALID != 0
    }
    /// `ath11k_hw_wcn6855_rx_desc_get_encrypt_type`.
    pub fn encrypt_type(&self) -> u32 {
        field_get(RX_MPDU_START_INFO2_ENC_TYPE, self.mpdu_start.info2)
    }
    /// `ath11k_hw_wcn6855_rx_desc_get_mpdu_tid`.
    pub fn mpdu_tid(&self) -> u8 {
        field_get(RX_MPDU_START_INFO2_TID_WCN6855, self.mpdu_start.info2) as u8
    }
    /// `ath11k_hw_wcn6855_rx_desc_get_mpdu_start_seq_no`.
    pub fn mpdu_start_seq_no(&self) -> u16 {
        field_get(RX_MPDU_START_INFO1_MPDU_SEQ_NUM, self.mpdu_start.info1) as u16
    }
    /// `ath11k_hw_wcn6855_rx_desc_get_mpdu_peer_id`.
    pub fn mpdu_peer_id(&self) -> u16 {
        self.mpdu_start.sw_peer_id
    }
    /// `ath11k_hw_wcn6855_rx_desc_get_mpdu_start_tag`.
    pub fn mpdu_start_tag(&self) -> u32 {
        field_get(HAL_TLV_HDR_TAG, self.mpdu_start_tag)
    }
    /// `ath11k_dp_rx_h_attn_msdu_done` on the WCN6855 attention TLV.
    pub fn msdu_done(&self) -> bool {
        let v = self.attention.info2;
        v & RX_ATTENTION_INFO2_MSDU_DONE != 0
    }
    /// `ath11k_hw_wcn6855_rx_desc_get_msdu_freq` (`phy_meta_data`).
    pub fn msdu_freq(&self) -> u32 {
        self.msdu_start.phy_meta_data
    }
}

// ── layout assertions (sizes / offsets from the Linux structs) ────

const _: () = assert!(size_of::<BufferAddr>() == 8);
const _: () = assert!(size_of::<HalTlvHdr>() == 4);
const _: () = assert!(size_of::<RxMpduDesc>() == 8);
const _: () = assert!(size_of::<RxMsduDesc>() == 8);
const _: () = assert!(size_of::<HalReoDestRing>() == 64);
const _: () = assert!(offset_of!(HalReoDestRing, queue_addr_lo) == 24);
const _: () = assert!(offset_of!(HalReoDestRing, info0) == 28);
const _: () = assert!(offset_of!(HalReoDestRing, info2) == 60);
const _: () = assert!(size_of::<HalReoEntranceRing>() == 32);
const _: () = assert!(size_of::<HalTclDataCmd>() == 28);
const _: () = assert!(size_of::<HalTclStatusRing>() == 32);
const _: () = assert!(offset_of!(HalTclStatusRing, info2) == 28);
const _: () = assert!(size_of::<HalWbmLinkDesc>() == 8);
const _: () = assert!(size_of::<HalWbmBufferRing>() == 8);
const _: () = assert!(size_of::<HalWbmReleaseRing>() == 32);
const _: () = assert!(offset_of!(HalWbmReleaseRing, info0) == 8);
const _: () = assert!(offset_of!(HalWbmReleaseRing, rate_stats) == 20);
const _: () = assert!(offset_of!(HalWbmReleaseRing, info3) == 28);
const _: () = assert!(size_of::<RxAttention>() == 12);
const _: () = assert!(size_of::<RxMsduStartWcn6855>() == 36);
const _: () = assert!(size_of::<RxMsduEndWcn6855>() == 76);
const _: () = assert!(size_of::<RxMpduStartWcn6855>() == 92);
const _: () = assert!(size_of::<RxMpduEnd>() == 8);
const _: () = assert!(size_of::<HalRxDescWcn6855>() == 392);
const _: () = assert!(offset_of!(HalRxDescWcn6855, msdu_end) == 4);
const _: () = assert!(offset_of!(HalRxDescWcn6855, rx_attn_tag) == 80);
const _: () = assert!(offset_of!(HalRxDescWcn6855, attention) == 84);
const _: () = assert!(offset_of!(HalRxDescWcn6855, msdu_start_tag) == 96);
const _: () = assert!(offset_of!(HalRxDescWcn6855, msdu_start) == 100);
const _: () = assert!(offset_of!(HalRxDescWcn6855, rx_padding0) == 136);
const _: () = assert!(offset_of!(HalRxDescWcn6855, mpdu_start_tag) == 140);
const _: () = assert!(offset_of!(HalRxDescWcn6855, mpdu_start) == 144);
const _: () = assert!(offset_of!(HalRxDescWcn6855, mpdu_end_tag) == 236);
const _: () = assert!(offset_of!(HalRxDescWcn6855, mpdu_end) == 240);
const _: () = assert!(offset_of!(HalRxDescWcn6855, rx_padding1) == 248);
const _: () = assert!(offset_of!(HalRxDescWcn6855, hdr_status_tag) == 264);
const _: () = assert!(offset_of!(HalRxDescWcn6855, phy_ppdu_id) == 268);
const _: () = assert!(offset_of!(HalRxDescWcn6855, hdr_status) == 272);

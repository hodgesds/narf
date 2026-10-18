//! Data-path ring runtime — the TCL / WBM / REO / RXDMA rings on top of
//! the HAL SRNG core, plus TX submit / completion and RX reap / decap.
//!
//! A port of Linux `drivers/net/wireless/ath/ath11k/dp.c`, the ring and
//! data parts of `dp_tx.c` / `dp_rx.c`, and the helpers of `hal_tx.c` /
//! `hal_rx.c` they use, for the WCN6855 family (single pdev,
//! `num_rxdma_per_pdev = 2`, `rx_mac_buf_ring = true`,
//! `rxdma1_enable = false`, `supports_monitor = false`, one TCL ring):
//!
//! | NARF | Linux |
//! |---|---|
//! | [`Dp::alloc`] | `ath11k_dp_alloc` (+ `ath11k_wbm_idle_ring_setup`, `ath11k_dp_link_desc_setup`, `ath11k_dp_srng_common_setup`, `ath11k_hal_tx_set_dscp_tid_map` ×48) |
//! | [`Dp::pdev_reo_setup`] | `ath11k_dp_pdev_reo_setup` |
//! | [`Dp::pdev_alloc`] | `ath11k_dp_pdev_pre_alloc` + `ath11k_dp_pdev_alloc` → `ath11k_dp_rx_pdev_alloc` (`rx_pdev_srng_alloc`, `rxdma_pdev_buf_setup`, HTT SRING_SETUP per ring) |
//! | [`Dp::mon_status_default_msgs`] | `ath11k_mac_config_mon_status_default` |
//! | [`Dp::htt_t2h_msg_handler`] | `ath11k_dp_htt_htc_t2h_msg_handler` (+ `ath11k_peer_map_event` / `unmap_event`) |
//! | [`VifTx::attach`] | `ath11k_dp_vdev_tx_attach` + `ath11k_dp_update_vdev_search` |
//! | [`Dp::tx`] | `ath11k_dp_tx` (+ `ath11k_hal_tx_cmd_desc_setup`) |
//! | [`Dp::tx_completion_handler`] | `ath11k_dp_tx_completion_handler` |
//! | [`Dp::process_rx`] | `ath11k_dp_process_rx` (+ `process_msdu`, `msdu_coalesce`, `h_mpdu`) |
//! | [`Dp::process_rx_err`] | `ath11k_dp_process_rx_err` (fragments to [`super::dp_frag`]) |
//! | [`Dp::rx_process_wbm_err`] | `ath11k_dp_rx_process_wbm_err` (+ `h_null_q_desc`) |
//! | [`Dp::process_rxdma_err`] | `ath11k_dp_process_rxdma_err` |
//! | [`Dp::process_reo_status`] | `ath11k_dp_process_reo_status` |
//! | [`Dp::reap_mon_status`] | `ath11k_dp_rx_reap_mon_status_ring` (status buffers recycled, not parsed) |
//! | [`Dp::service_srng`] | `ath11k_dp_service_srng` |
//! | [`Dp::service_shadow_timers`] | `ath11k_dp_shadow_timer_handler` |
//!
//! All register and ring I/O goes through [`Hal`] and [`ChipIo`]; ring
//! and buffer memory is DMA32 coherent ([`DmaMem`]). Every RX buffer is
//! its own [`DmaMem`] (Linux: an skb mapped for DMA), every TX frame is
//! copied into a [`DmaMem`] bounce buffer held until its completion.
//!
//! The RX side delivers **Ethernet II frames** ([`RxMsdu::frame`]):
//! native-wifi decap is converted 802.11 → 802.3 (DA / SA from the
//! 802.11 header, ethertype from the RFC 1042 / bridge-tunnel SNAP);
//! Ethernet-II decap is passed through. Linux instead rebuilds 802.11
//! for mac80211 (`ath11k_dp_rx_h_undecap_*`); NARF has no mac80211.
//!
//! Per-peer REO TID queues and REO commands live in
//! [`super::dp_peer`] (state in [`Dp::peer_rx`]); until a peer's queues
//! are set up, its unicast frames arrive through the WBM error path as
//! `REO_DEST_RING_ERROR_CODE_DESC_ADDR_ZERO`, which Linux and NARF both
//! deliver.
//!
//! Not ported: the WBM idle-list scatter setup (needs > 2 MiB of idle
//! entries; WCN6855 needs 256 KiB), monitor rings, PPDU / peer stats, TX
//! rate statistics, ring teardown (`ath11k_dp_free`).

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use super::ce::{CeMsi, HpUpdateTimer};
use super::dp::*;
use super::hal::{
    errno, field_get, field_prep, flags, genmask, ring_id, DmaMem, Hal, HalRingType, SrngParams,
    TransportError, HAL_ADDR_LSB_REG_MASK, HAL_ADDR_MSB_REG_SHIFT, HAL_RING_BASE_ALIGN,
    HAL_SEQ_WCSS_UMAC_REO_REG, HAL_SEQ_WCSS_UMAC_TCL_REG, HAL_SRNG_INT_BATCH_THRESHOLD_OTHER,
    HAL_SRNG_INT_BATCH_THRESHOLD_RX, HAL_SRNG_INT_BATCH_THRESHOLD_TX,
    HAL_SRNG_INT_TIMER_THRESHOLD_OTHER, HAL_SRNG_INT_TIMER_THRESHOLD_RX,
    HAL_SRNG_INT_TIMER_THRESHOLD_TX,
};
use super::htt::{self, HttT2h, HttTarget, RxRingTlvFilter};
use super::hw::{rbm, HwHalParams, HwParams, HwRev, RingMask, HW_HAL_PARAMS_QCA6390};
use super::power::ChipIo;

// ── diag steps (DP 200–216; HTT 220–225 in `htt::step`) ──

pub mod step {
    /// `ath11k_hal_srng_setup` failed under `ath11k_dp_srng_setup`
    /// (detail = ring type << 24 | ring_num << 16 | HAL step).
    pub const SRNG_SETUP: u32 = 200;
    /// Ring memory allocation failed (detail = ring type << 24 | bytes
    /// >> 8, truncated).
    pub const RING_ALLOC: u32 = 201;
    /// More link-descriptor banks than `DP_LINK_DESC_BANKS_MAX` (detail =
    /// banks).
    pub const LINK_DESC_BANKS: u32 = 202;
    /// Link-descriptor bank allocation failed (detail = bank).
    pub const LINK_DESC_ALLOC: u32 = 203;
    /// The idle list needs the scatter-buffer path (not ported; detail =
    /// idle-list bytes).
    pub const SCATTER_UNSUPPORTED: u32 = 204;
    /// "Not a valid ring type in dp" (detail = ring type).
    pub const BAD_RING_TYPE: u32 = 205;
    /// `pdev_alloc` / `pdev_reo_setup` called twice (detail = which).
    pub const ALREADY_SET_UP: u32 = 206;
    /// A data-path call on a ring that is not set up (detail = which).
    pub const NOT_SET_UP: u32 = 207;
    /// `ath11k_dp_tx`: no free TX descriptor id (`-ENOSPC`; detail =
    /// ring).
    pub const TX_IDR_FULL: u32 = 208;
    /// `ath11k_dp_tx`: TCL ring full (`-ENOMEM`, `desc_na`; detail =
    /// ring).
    pub const TX_RING_FULL: u32 = 209;
    /// `ath11k_dp_tx`: not a data frame without HW 802.11 encap
    /// (`-EOPNOTSUPP`; detail = frame control).
    pub const TX_NOT_DATA: u32 = 210;
    /// `ath11k_dp_tx`: raw / 802.3 encap (`-EINVAL`; detail = encap).
    pub const TX_BAD_ENCAP: u32 = 211;
    /// `ath11k_dp_tx` after a crash flush (`-ESHUTDOWN`).
    pub const TX_SHUTDOWN: u32 = 212;
    /// TX bounce buffer allocation failed (`-ENOMEM`; detail = len).
    pub const TX_DMA: u32 = 213;
    /// NARF-stricter: frame shorter than its 802.11 header, or longer
    /// than `HAL_TCL_DATA_CMD_INFO1_DATA_LEN` (detail = len).
    pub const TX_FRAME_LEN: u32 = 214;
    /// Link descriptor address outside every bank (NARF-stricter;
    /// detail = bank).
    pub const LINK_DESC_LOOKUP: u32 = 215;
    /// `ath11k_dp_rx_link_desc_return`: SW2WBM release ring full
    /// (`-ENOBUFS`).
    pub const LINK_DESC_RETURN: u32 = 216;
}

/// Linux `-EOPNOTSUPP`.
pub const EOPNOTSUPP: i32 = 95;

// ── constants (hal.h / dp.h / hal_desc.h / hal_tx.h / dp_rx.h) ────

pub const HAL_LINK_DESC_SIZE: u32 = 32 << 2;
pub const HAL_LINK_DESC_ALIGN: u32 = 128;
pub const HAL_NUM_MPDUS_PER_LINK_DESC: u32 = 6;
pub const HAL_NUM_TX_MSDUS_PER_LINK_DESC: u32 = 7;
pub const HAL_NUM_RX_MSDUS_PER_LINK_DESC: u32 = 6;
pub const HAL_NUM_MPDU_LINKS_PER_QUEUE_DESC: u32 = 12;
pub const HAL_WBM_IDLE_SCATTER_BUF_SIZE_MAX: u32 = 32704;
pub const HAL_WBM_IDLE_SCATTER_NEXT_PTR_SIZE: u32 = 8;
pub const HAL_WBM_IDLE_SCATTER_BUF_SIZE: u32 =
    HAL_WBM_IDLE_SCATTER_BUF_SIZE_MAX - HAL_WBM_IDLE_SCATTER_NEXT_PTR_SIZE;

pub const DP_LINK_DESC_ALLOC_SIZE_THRESH: u32 = 0x20_0000;
pub const DP_LINK_DESC_BANKS_MAX: u32 = 8;
pub const DP_NUM_CLIENTS_MAX: u32 = 64;
pub const DP_AVG_TIDS_PER_CLIENT: u32 = 2;
pub const DP_NUM_TIDS_MAX: u32 = DP_NUM_CLIENTS_MAX * DP_AVG_TIDS_PER_CLIENT;
pub const DP_AVG_MSDUS_PER_FLOW: u32 = 128;
pub const DP_AVG_FLOWS_PER_TID: u32 = 2;
pub const DP_AVG_MPDUS_PER_TID_MAX: u32 = 128;
pub const DP_AVG_MSDUS_PER_MPDU: u32 = 4;
pub const DP_IDLE_SCATTER_BUFS_MAX: u32 = 16;
pub const DP_RX_RELEASE_RING_NUM: u32 = 3;
pub const DP_RX_HASH_ENABLE: u32 = 1;
pub const DP_TX_IDR_SIZE: u32 = DP_TX_COMP_RING_SIZE;

pub const DP_RXDMA_BUF_COOKIE_BUF_ID: u32 = genmask(17, 0);
pub const DP_RXDMA_BUF_COOKIE_PDEV_ID: u32 = genmask(20, 18);
pub const DP_TX_DESC_ID_MAC_ID: u32 = genmask(1, 0);
pub const DP_TX_DESC_ID_MSDU_ID: u32 = genmask(18, 2);
pub const DP_TX_DESC_ID_POOL_ID: u32 = genmask(20, 19);

/// `ATH11K_SHADOW_DP_TIMER_INTERVAL` / `_CTRL_` (ms).
pub const ATH11K_SHADOW_DP_TIMER_INTERVAL: u64 = 20;
pub const ATH11K_SHADOW_CTRL_TIMER_INTERVAL: u64 = 10;
/// `ATH11K_HW_MAX_QUEUES`.
pub const ATH11K_HW_MAX_QUEUES: u32 = 4;

pub const HAL_DSCP_TID_MAP_TBL_NUM_ENTRIES_MAX: u32 = 48;
pub const HAL_DSCP_TID_TBL_SIZE: u32 = 24;
pub const HAL_TCL1_RING_CMN_CTRL_REG: u32 = 0x14;
pub const HAL_TCL1_RING_DSCP_TID_MAP: u32 = 0x2c;
pub const HAL_TCL1_RING_CMN_CTRL_DSCP_TID_MAP_PROG_EN: u32 = 1 << 17;

pub const HAL_REO1_GEN_ENABLE: u32 = 0x0;
pub const HAL_REO1_DEST_RING_CTRL_IX_0: u32 = 0x4;
pub const HAL_REO1_DEST_RING_CTRL_IX_1: u32 = 0x8;
pub const HAL_REO1_DEST_RING_CTRL_IX_2: u32 = 0xc;
pub const HAL_REO1_DEST_RING_CTRL_IX_3: u32 = 0x10;
pub const HAL_REO1_GEN_ENABLE_AGING_LIST_ENABLE: u32 = 1 << 2;
pub const HAL_REO1_GEN_ENABLE_AGING_FLUSH_ENABLE: u32 = 1 << 3;
pub const HAL_REO1_MISC_CTL_FRAGMENT_DST_RING: u32 = genmask(20, 17);
pub const HAL_DEFAULT_REO_TIMEOUT_USEC: u32 = 40 * 1000;
pub const HAL_HASH_ROUTING_RING_SW1: u32 = 1;
pub const HAL_HASH_ROUTING_RING_SW2: u32 = 2;
pub const HAL_HASH_ROUTING_RING_SW3: u32 = 3;
pub const HAL_HASH_ROUTING_RING_SW4: u32 = 4;

pub const HAL_REO_CMD_HDR_INFO0_CMD_NUMBER: u32 = genmask(15, 0);
pub const HAL_REO_STATUS_HDR_INFO0_STATUS_NUM: u32 = genmask(15, 0);
pub const HAL_REO_STATUS_HDR_INFO0_EXEC_STATUS: u32 = genmask(27, 26);

pub const HTT_TCL_META_DATA_TYPE: u32 = 1 << 0;
pub const HTT_TCL_META_DATA_VALID_HTT: u32 = 1 << 1;
pub const HTT_TCL_META_DATA_VDEV_ID: u32 = genmask(9, 2);
pub const HTT_TCL_META_DATA_PDEV_ID: u32 = genmask(11, 10);
pub const HTT_TX_WBM_COMP_INFO0_STATUS: u32 = genmask(12, 9);
pub const HTT_TX_WBM_COMP_INFO1_ACK_RSSI: u32 = genmask(31, 24);
pub const HTT_TX_WBM_COMP_INFO2_SW_PEER_ID: u32 = genmask(15, 0);
pub const HTT_TX_WBM_COMP_INFO2_VALID: u32 = 1 << 21;
pub const HTT_INVALID_PEER_ID: u16 = 0xffff;

pub const HAL_TX_ADDRX_EN: u16 = 1;
pub const HAL_TX_ADDRY_EN: u16 = 2;
pub const HAL_TX_ADDR_SEARCH_DEFAULT: u8 = 0;
pub const HAL_TX_ADDR_SEARCH_INDEX: u8 = 1;
pub const HAL_TX_STATUS_FLAGS_FIRST_MSDU: u32 = 1 << 0;
pub const HAL_TX_RATE_STATS_INFO0_VALID: u32 = 1 << 0;
pub const HAL_DESC_REO_NON_QOS_TID: u8 = 16;

pub const RX_ATTENTION_INFO1_A_MSDU_ERROR: u32 = 1 << 12;
pub const RX_ATTENTION_INFO1_OVERFLOW_ERR: u32 = 1 << 16;
pub const RX_DESC_DECRYPT_STATUS_CODE_OK: u32 = 0;
pub const DP_RX_MPDU_ERR_FCS: u32 = 1 << 0;
pub const DP_RX_MPDU_ERR_DECRYPT: u32 = 1 << 1;
pub const DP_RX_MPDU_ERR_TKIP_MIC: u32 = 1 << 2;
pub const DP_RX_MPDU_ERR_AMSDU_ERR: u32 = 1 << 3;
pub const DP_RX_MPDU_ERR_OVERFLOW: u32 = 1 << 4;
pub const DP_RX_MPDU_ERR_MSDU_LEN: u32 = 1 << 5;
pub const DP_RX_MPDU_ERR_MPDU_LEN: u32 = 1 << 6;

/// `enum dp_rx_decap_type`.
pub mod decap {
    pub const RAW: u8 = 0;
    pub const NATIVE_WIFI: u8 = 1;
    pub const ETHERNET2_DIX: u8 = 2;
    pub const IEEE8023: u8 = 3;
}

/// `enum hal_encrypt_type`.
pub mod enc {
    pub const WEP_40: u32 = 0;
    pub const WEP_104: u32 = 1;
    pub const TKIP_NO_MIC: u32 = 2;
    pub const WEP_128: u32 = 3;
    pub const TKIP_MIC: u32 = 4;
    pub const WAPI: u32 = 5;
    pub const CCMP_128: u32 = 6;
    pub const OPEN: u32 = 7;
    pub const CCMP_256: u32 = 8;
    pub const GCMP_128: u32 = 9;
    pub const AES_GCMP_256: u32 = 10;
    pub const WAPI_GCM_SM4: u32 = 11;
}

/// `enum hal_tcl_encap_type`.
pub mod encap {
    pub const RAW: u32 = 0;
    pub const NATIVE_WIFI: u32 = 1;
    pub const ETHERNET: u32 = 2;
    pub const IEEE8023: u32 = 3;
}

/// `enum hal_wbm_rel_src_module`.
pub mod rel_src {
    pub const TQM: u32 = 0;
    pub const RXDMA: u32 = 1;
    pub const REO: u32 = 2;
    pub const FW: u32 = 3;
    pub const SW: u32 = 4;
}

/// `enum hal_wbm_tqm_rel_reason`.
pub mod tqm {
    pub const FRAME_ACKED: u32 = 0;
    pub const CMD_REMOVE_MPDU: u32 = 1;
    pub const CMD_REMOVE_TX: u32 = 2;
    pub const CMD_REMOVE_NOTX: u32 = 3;
    pub const CMD_REMOVE_AGED_FRAMES: u32 = 4;
}

/// `enum hal_wbm_htt_tx_comp_status`.
pub mod htt_comp {
    pub const OK: u32 = 0;
    pub const DROP: u32 = 1;
    pub const TTL: u32 = 2;
    pub const REINJ: u32 = 3;
    pub const INSPECT: u32 = 4;
    pub const MEC_NOTIFY: u32 = 5;
}

/// `enum hal_reo_dest_ring_push_reason` / `_buffer_type` /
/// `_error_code` (the ones the DP tests).
pub mod reo {
    pub const PUSH_REASON_ERR_DETECTED: u32 = 0;
    pub const PUSH_REASON_ROUTING_INSTRUCTION: u32 = 1;
    pub const BUFFER_TYPE_MSDU: u32 = 0;
    pub const BUFFER_TYPE_LINK_DESC: u32 = 1;
    pub const ERROR_CODE_DESC_ADDR_ZERO: u32 = 0;
    pub const ERROR_CODE_PN_CHECK_FAILED: u32 = 11;
    pub const ERROR_CODE_MAX: usize = 15;
}

/// `enum hal_reo_entr_rxdma_ecode`.
pub mod rxdma_ecode {
    pub const OVERFLOW_ERR: u32 = 0;
    pub const FCS_ERR: u32 = 2;
    pub const TKIP_MIC_ERR: u32 = 4;
    pub const MAX: usize = 14;
}

/// `enum hal_wbm_rel_bm_act` / `hal_wbm_rel_desc_type`.
pub const HAL_WBM_REL_BM_ACT_PUT_IN_IDLE: u32 = 0;
pub const HAL_WBM_REL_BM_ACT_REL_MSDU: u32 = 1;
pub const HAL_WBM_REL_DESC_TYPE_REL_MSDU: u32 = 0;
pub const HAL_WBM_REL_DESC_TYPE_MSDU_LINK: u32 = 1;

/// `enum hal_tlv_tag` values of the REO status ring and the monitor
/// status buffer.
pub mod status_tag {
    pub const REO_UPDATE_RX_REO_QUEUE_STATUS: u32 = 0x99;
    pub const REO_GET_QUEUE_STATS_STATUS: u32 = 0x137;
    pub const REO_FLUSH_QUEUE_STATUS: u32 = 0x138;
    pub const REO_FLUSH_CACHE_STATUS: u32 = 0x139;
    pub const REO_UNBLOCK_CACHE_STATUS: u32 = 0x13a;
    pub const REO_FLUSH_TIMEOUT_LIST_STATUS: u32 = 0x156;
    pub const REO_DESCRIPTOR_THRESHOLD_REACHED_STATUS: u32 = 0x159;
    pub const RX_STATUS_BUFFER_DONE: u32 = 0x140;
}

/// 802.11 bits the DP inspects.
pub const IEEE80211_FCTL_FTYPE: u16 = 0x000c;
pub const IEEE80211_FTYPE_DATA: u16 = 0x0008;
pub const IEEE80211_STYPE_QOS_DATA: u16 = 0x0080;
pub const IEEE80211_FCTL_TODS: u16 = 0x0100;
pub const IEEE80211_FCTL_FROMDS: u16 = 0x0200;
pub const IEEE80211_FCTL_ORDER: u16 = 0x8000;
pub const IEEE80211_QOS_CTL_LEN: usize = 2;
pub const IEEE80211_QOS_CTL_TID_MASK: u32 = 0x000f;
pub const ETH_P_PAE: u16 = 0x888e;
pub const ETH_HLEN: usize = 14;
/// RFC 1042 / 802.1H bridge-tunnel SNAP headers (without the type).
pub const RFC1042_HEADER: [u8; 6] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00];
pub const BRIDGE_TUNNEL_HEADER: [u8; 6] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8];

// ── per-chip DP parameters (core.c `ath11k_hw_params`) ─────────────

/// The `struct ath11k_hw_params` fields the data path reads.
#[derive(Copy, Clone, Debug)]
pub struct DpHwParams {
    pub hw: HwParams,
    pub hal_params: &'static HwHalParams,
    pub num_rxdma_per_pdev: u32,
    pub rx_mac_buf_ring: bool,
    pub rxdma1_enable: bool,
    pub supports_monitor: bool,
    pub full_monitor_mode: bool,
    pub htt_peer_map_v2: bool,
    pub tcl_ring_retry: bool,
    pub tx_ring_size: u32,
    pub hal_desc_sz: usize,
    pub alloc_cacheable_memory: bool,
    pub single_pdev_only: bool,
}

impl DpHwParams {
    /// The WCN6855 family entries (WCN6855 HW2.0 / HW2.1, QCA2066,
    /// QCA6698AQ share every DP field). `None` for parts whose DP is
    /// not ported.
    pub fn for_rev(rev: HwRev) -> Option<DpHwParams> {
        match rev {
            HwRev::Wcn6855Hw20 | HwRev::Wcn6855Hw21 | HwRev::Qca2066Hw21 | HwRev::Qca6698aqHw21 => {
                Some(DpHwParams {
                    hw: rev.params()?,
                    hal_params: &HW_HAL_PARAMS_QCA6390,
                    num_rxdma_per_pdev: 2,
                    rx_mac_buf_ring: true,
                    rxdma1_enable: false,
                    supports_monitor: false,
                    full_monitor_mode: false,
                    htt_peer_map_v2: false,
                    tcl_ring_retry: true,
                    tx_ring_size: DP_TCL_DATA_RING_SIZE,
                    hal_desc_sz: HalRxDescWcn6855::SIZE,
                    alloc_cacheable_memory: false,
                    single_pdev_only: true,
                })
            }
            _ => None,
        }
    }

    /// `hal_params->num_tx_rings`.
    pub fn num_tx_rings(&self) -> usize {
        self.hal_params.tcl2wbm_rbm_map.len()
    }
}

/// Ring sizes (entries). [`DpRingSizes::LINUX`] is what Linux uses and
/// what bring-up must use; tests shrink rings to exercise wrap-around and
/// full rings cheaply.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpRingSizes {
    pub wbm_release: u32,
    pub tcl_cmd: u32,
    pub tcl_status: u32,
    /// `hw_params.tx_ring_size` when `None`.
    pub tcl_data: Option<u32>,
    pub tx_comp: u32,
    pub reo_reinject: u32,
    pub rx_release: u32,
    pub reo_exception: u32,
    pub reo_cmd: u32,
    pub reo_status: u32,
    pub reo_dst: u32,
    pub rxdma_buf: u32,
    pub rx_mac_buf: u32,
    pub rxdma_err_dst: u32,
    pub rxdma_mon_status: u32,
    /// `tx_ring[i].tx_status` FIFO length (`DP_TX_COMP_RING_SIZE`).
    pub tx_status_fifo: u32,
    /// `ath11k_wbm_idle_ring_setup`'s computed total when `None`.
    pub n_link_desc: Option<u32>,
}

impl DpRingSizes {
    pub const LINUX: DpRingSizes = DpRingSizes {
        wbm_release: DP_WBM_RELEASE_RING_SIZE,
        tcl_cmd: DP_TCL_CMD_RING_SIZE,
        tcl_status: DP_TCL_STATUS_RING_SIZE,
        tcl_data: None,
        tx_comp: DP_TX_COMP_RING_SIZE,
        reo_reinject: DP_REO_REINJECT_RING_SIZE,
        rx_release: DP_RX_RELEASE_RING_SIZE,
        reo_exception: DP_REO_EXCEPTION_RING_SIZE,
        reo_cmd: DP_REO_CMD_RING_SIZE,
        reo_status: DP_REO_STATUS_RING_SIZE,
        reo_dst: DP_REO_DST_RING_SIZE,
        rxdma_buf: DP_RXDMA_BUF_RING_SIZE,
        rx_mac_buf: 1024,
        rxdma_err_dst: DP_RXDMA_ERR_DST_RING_SIZE,
        rxdma_mon_status: DP_RXDMA_MON_STATUS_RING_SIZE,
        tx_status_fifo: DP_TX_COMP_RING_SIZE,
        n_link_desc: None,
    };
}

/// Linux `ath11k_wbm_idle_ring_setup`'s `n_link_desc` (rounded up to a
/// power of two with `1 << fls(n)`). 32768 for every ath11k part.
pub const fn wbm_idle_n_link_desc() -> u32 {
    let n_mpdu_link_desc =
        (DP_NUM_TIDS_MAX * DP_AVG_MPDUS_PER_TID_MAX) / HAL_NUM_MPDUS_PER_LINK_DESC;
    let n_mpdu_queue_desc = n_mpdu_link_desc / HAL_NUM_MPDU_LINKS_PER_QUEUE_DESC;
    let n_tx_msdu_link_desc = (DP_NUM_TIDS_MAX * DP_AVG_FLOWS_PER_TID * DP_AVG_MSDUS_PER_FLOW)
        / HAL_NUM_TX_MSDUS_PER_LINK_DESC;
    let n_rx_msdu_link_desc = (DP_NUM_TIDS_MAX * DP_AVG_MPDUS_PER_TID_MAX * DP_AVG_MSDUS_PER_MPDU)
        / HAL_NUM_RX_MSDUS_PER_LINK_DESC;
    let n = n_mpdu_link_desc + n_mpdu_queue_desc + n_tx_msdu_link_desc + n_rx_msdu_link_desc;
    if n & (n - 1) != 0 {
        // fls(n) = 32 - leading_zeros
        1 << (32 - n.leading_zeros())
    } else {
        n
    }
}

/// Linux `ath11k_dp_link_desc_setup` bank split: `(n_link_desc_bank,
/// last_bank_sz)` for `n_link_desc` 128-byte descriptors.
pub const fn link_desc_banks(n_link_desc: u32) -> (u32, u32) {
    let tot = n_link_desc * HAL_LINK_DESC_SIZE + HAL_LINK_DESC_ALIGN;
    if tot <= DP_LINK_DESC_ALLOC_SIZE_THRESH {
        (1, tot)
    } else {
        let per = DP_LINK_DESC_ALLOC_SIZE_THRESH - HAL_LINK_DESC_ALIGN;
        let mut n = tot / per;
        let last = tot % per;
        if last != 0 {
            n += 1;
        }
        (n, last)
    }
}

// ── MSI (dp.c) ─────────────────────────────────────────────────────

/// Linux `ath11k_dp_srng_calculate_msi_group` (with
/// `ath11k_dp_srng_find_ring_in_mask`): the ext-IRQ group of a ring, or
/// `None` (`-ENOENT`). `ring_num` is `ring_num + mac_id`, as Linux
/// passes it.
pub fn calculate_msi_group(mask: &RingMask, ty: HalRingType, ring_num: u32) -> Option<usize> {
    let (grp, ring_num): (&[u8], u32) = match ty {
        HalRingType::Wbm2SwRelease => {
            if ring_num == DP_RX_RELEASE_RING_NUM {
                (&mask.rx_wbm_rel, 0)
            } else {
                (&mask.tx, ring_num)
            }
        }
        HalRingType::ReoException => (&mask.rx_err, ring_num),
        HalRingType::ReoDst => (&mask.rx, ring_num),
        HalRingType::ReoStatus => (&mask.reo_status, ring_num),
        HalRingType::RxdmaMonitorStatus | HalRingType::RxdmaMonitorDst => {
            (&mask.rx_mon_status, ring_num)
        }
        HalRingType::RxdmaDst => (&mask.rxdma2host, ring_num),
        HalRingType::RxdmaBuf => (&mask.host2rxdma, ring_num),
        _ => return None,
    };
    if ring_num >= 8 {
        return None;
    }
    let bit = 1u8 << ring_num;
    grp.iter().position(|&g| g & bit != 0)
}

/// Linux `ath11k_dp_srng_msi_setup`: `(msi_addr, msi_data)` for the ring
/// (and `HAL_SRNG_FLAGS_MSI_INTR`), `None` when the ring has no group or
/// there is no "DP" MSI user.
pub fn srng_msi(
    mask: &RingMask,
    msi: Option<&CeMsi>,
    ty: HalRingType,
    ring_num: u32,
) -> Option<(u64, u32)> {
    let msi = msi?;
    let (count, start, _base) = msi.config.user_assignment("DP", msi.ep_base_data)?;
    let group = calculate_msi_group(mask, ty, ring_num)? as u32;
    if count == 0 {
        return None;
    }
    Some((msi.addr, (group % count) + start))
}

// ── IDR (lowest-free id allocator, like `idr_alloc`) ──────────────

/// `struct idr` as ath11k uses it: `alloc(start, end)` returns the
/// lowest free id in `[start, end)`.
#[derive(Debug)]
pub struct Idr<T> {
    slots: Vec<Option<T>>,
    /// Every id below this is in use.
    hint: u32,
    count: usize,
}

impl<T> Default for Idr<T> {
    fn default() -> Self {
        Idr {
            slots: Vec::new(),
            hint: 0,
            count: 0,
        }
    }
}

impl<T> Idr<T> {
    /// `idr_alloc(idr, v, start, end)`; `Err(v)` = `-ENOSPC`.
    pub fn alloc(&mut self, v: T, start: u32, end: u32) -> Result<u32, T> {
        let from = start.max(self.hint);
        let mut id = from;
        while id < end {
            match self.slots.get(id as usize) {
                Some(Some(_)) => id += 1,
                _ => break,
            }
        }
        if id >= end {
            return Err(v);
        }
        if self.slots.len() <= id as usize {
            self.slots.resize_with(id as usize + 1, || None);
        }
        self.slots[id as usize] = Some(v);
        self.count += 1;
        if start <= self.hint && id == from {
            self.hint = id + 1;
        }
        Ok(id)
    }

    pub fn find(&self, id: u32) -> Option<&T> {
        self.slots.get(id as usize).and_then(|s| s.as_ref())
    }

    pub fn find_mut(&mut self, id: u32) -> Option<&mut T> {
        self.slots.get_mut(id as usize).and_then(|s| s.as_mut())
    }

    pub fn remove(&mut self, id: u32) -> Option<T> {
        let v = self.slots.get_mut(id as usize)?.take()?;
        self.count -= 1;
        self.hint = self.hint.min(id);
        Some(v)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// In-use ids, ascending.
    pub fn ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_some())
            .map(|(i, _)| i as u32)
    }
}

// ── rings and buffers ─────────────────────────────────────────────

/// `struct dp_srng` (memory is owned by the HAL ring).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpSrng {
    pub ring_id: u32,
    /// Linux `ring->size` (bytes, `num_entries * entry_sz + 7`).
    pub size: u32,
    pub num_entries: u32,
}

/// One posted RX buffer (`skb` + `ATH11K_SKB_RXCB(skb)->paddr`).
#[derive(Debug)]
pub struct RxBuf {
    pub mem: DmaMem,
    pub paddr: u64,
    /// A reassembled MPDU reinjected through the REO (`rxcb->is_frag`):
    /// its length (descriptor + MPDU).
    pub frag_len: Option<u32>,
}

/// `struct dp_rxdma_ring`.
#[derive(Debug)]
pub struct RxdmaRing {
    pub refill_buf_ring: DpSrng,
    pub bufs: Idr<RxBuf>,
    pub bufs_max: u32,
}

/// One in-flight TX frame (`skb` + `ATH11K_SKB_CB(skb)->paddr`).
#[derive(Debug)]
pub struct TxBuf {
    pub mem: DmaMem,
    pub paddr: u64,
    pub len: u32,
    pub mac_id: u8,
}

/// `struct dp_tx_ring`.
#[derive(Debug)]
pub struct DpTxRing {
    pub tcl_data_ring_id: u8,
    pub tcl_data_ring: DpSrng,
    pub tcl_comp_ring: DpSrng,
    pub txbuf: Idr<TxBuf>,
    tx_status: Vec<[u32; 8]>,
    tx_status_head: u32,
    tx_status_tail: u32,
}

impl DpTxRing {
    fn compl_next(&self, x: u32) -> u32 {
        (x + 1) % self.tx_status.len() as u32
    }
}

/// `struct dp_link_desc_bank`.
#[derive(Debug)]
pub struct LinkDescBank {
    mem: DmaMem,
    /// `vaddr - vaddr_unaligned`.
    pub align_bytes: u32,
    /// Aligned device address.
    pub paddr: u64,
    /// Bytes allocated (Linux `size`).
    pub size: u32,
}

impl LinkDescBank {
    /// Word `i` of the 128-byte link descriptor at device address `pa`,
    /// if it lies in this bank.
    pub(super) fn rd(&self, pa: u64, i: u32) -> Option<u32> {
        let off = pa.checked_sub(self.paddr)?;
        let byte = off + self.align_bytes as u64 + i as u64 * 4;
        if byte + 4 > self.mem.len() as u64 || off % 4 != 0 {
            return None;
        }
        Some(self.mem.rd32((byte / 4) as usize))
    }

    /// Write word `i` of the link descriptor at `pa` (the defrag
    /// reinjection rewrites its first MSDU entry).
    pub(super) fn wr(&self, pa: u64, i: u32, v: u32) -> Option<()> {
        let off = pa.checked_sub(self.paddr)?;
        let byte = off + self.align_bytes as u64 + i as u64 * 4;
        if byte + 4 > self.mem.len() as u64 || off % 4 != 0 {
            return None;
        }
        self.mem.wr32((byte / 4) as usize, v);
        Some(())
    }
}

/// `struct ath11k_pdev_dp` (the ring part).
#[derive(Debug)]
pub struct PdevDp {
    pub mac_id: u32,
    pub rx_refill_buf_ring: RxdmaRing,
    pub rx_mac_buf_ring: Vec<DpSrng>,
    pub rxdma_err_dst_ring: Vec<DpSrng>,
    pub rx_mon_status_refill_ring: Vec<RxdmaRing>,
    /// `num_tx_pending`.
    pub num_tx_pending: u32,
}

/// The peer fields the data path uses (`struct ath11k_peer`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpPeer {
    pub vdev_id: u8,
    pub peer_id: u16,
    pub addr: [u8; 6],
    pub ast_hash: u16,
    pub hw_peer_id: u16,
    /// `sec_type` / `sec_type_grp` (`enum hal_encrypt_type`; set by the
    /// key-install path, `OPEN` until then).
    pub sec_type: u32,
    pub sec_type_grp: u32,
}

/// Counters Linux keeps in `soc_stats` (plus NARF's drop reasons).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DpStats {
    pub tx_misc_fail: u32,
    pub tx_desc_na: [u32; DP_TCL_NUM_RING_MAX],
    pub tx_completed: u32,
    pub tx_unknown_msdu: u32,
    pub tx_htt_unknown_status: u32,
    pub tx_status_fifo_full: u32,
    pub hal_reo_error: [u32; DP_REO_DST_RING_MAX],
    pub reo_error: [u32; reo::ERROR_CODE_MAX + 1],
    pub rxdma_error: [u32; rxdma_ecode::MAX + 1],
    pub err_ring_pkts: u32,
    pub invalid_rbm: u32,
    pub rx_invalid_cookie: u32,
    pub rx_msdu_len_err: u32,
    pub rx_msdu_not_done: u32,
    pub rx_no_last_buf: u32,
    pub rx_invalid_len: u32,
    pub rx_coalesce_err: u32,
    pub rx_decap_unsupported: u32,
    pub rx_fcs_err: u32,
    pub rx_mic_err: u32,
    pub rx_decrypt_err: u32,
    pub rx_delivered: u32,
    pub rx_buf_alloc_fail: u32,
    /// Fragments refused by `ath11k_dp_rx_frag_h_mpdu` (freed, link
    /// descriptor returned).
    pub rx_err_frags_dropped: u32,
    /// Reassembled MPDUs reinjected into the REO.
    pub rx_defrag_reinjected: u32,
    /// Complete fragment sets dropped (PN gap, reassembly / reinjection
    /// failure).
    pub rx_defrag_dropped: u32,
    /// Incomplete sets dropped by the fragment timer.
    pub rx_defrag_timeout: u32,
    pub wbm_err_parse: u32,
    pub reo_err_parse: u32,
    pub link_desc_lookup_fail: u32,
    pub link_desc_return_fail: u32,
    pub reo_status_unknown: u32,
    pub mon_status_reaped: u32,
    pub mon_status_not_done: u32,
    pub htt_unhandled: u32,
    pub htt_peer_unmap_unknown: u32,
}

// ── TX / RX results ───────────────────────────────────────────────

/// The vif fields `ath11k_dp_tx` reads (`struct ath11k_vif`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VifTx {
    pub vdev_id: u8,
    pub tcl_metadata: u16,
    pub hal_addr_search_flags: u16,
    pub search_type: u8,
    /// `arvif->ast_hash` / `ast_idx` (from the BSS peer's map event).
    pub ast_hash: u16,
    pub ast_idx: u16,
}

impl VifTx {
    /// Linux `ath11k_dp_vdev_tx_attach` + `ath11k_dp_update_vdev_search`
    /// for a station vdev.
    pub fn attach(vdev_id: u8, pdev_id: u8, htt_peer_map_v2: bool) -> VifTx {
        let mut tcl_metadata = field_prep(HTT_TCL_META_DATA_TYPE, 1)
            | field_prep(HTT_TCL_META_DATA_VDEV_ID, vdev_id as u32)
            | field_prep(HTT_TCL_META_DATA_PDEV_ID, pdev_id as u32);
        tcl_metadata &= !HTT_TCL_META_DATA_VALID_HTT;
        let (flags, search) = if htt_peer_map_v2 {
            (HAL_TX_ADDRX_EN, HAL_TX_ADDR_SEARCH_INDEX)
        } else {
            (HAL_TX_ADDRY_EN, HAL_TX_ADDR_SEARCH_DEFAULT)
        };
        VifTx {
            vdev_id,
            tcl_metadata: tcl_metadata as u16,
            hal_addr_search_flags: flags,
            search_type: search,
            ast_hash: 0,
            ast_idx: 0,
        }
    }
}

/// How the frame handed to [`Dp::tx`] is encapsulated
/// (`ath11k_dp_tx_get_encap_type`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TxEncap {
    /// `IEEE80211_TX_CTL_HW_80211_ENCAP`: an Ethernet II frame; the
    /// firmware builds the 802.11 header (vdev `TX_ENCAP_TYPE` must be
    /// ETHERNET).
    Ethernet,
    /// An 802.11 data frame; QoS control is stripped
    /// (`ath11k_dp_tx_encap_nwifi`).
    NativeWifi,
}

/// The per-frame `skb` state `ath11k_dp_tx` reads.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxMeta {
    pub encap: TxEncap,
    /// `skb->priority`.
    pub priority: u32,
    /// `skb_get_queue_mapping(skb)`.
    pub queue: u16,
    /// `hw_ops->get_ring_selector` (Linux: `smp_processor_id()`).
    pub ring_selector: u32,
    /// `skb->ip_summed == CHECKSUM_PARTIAL`.
    pub csum_partial: bool,
    /// `ar->pdev_idx` / `ar->lmac_id`.
    pub pdev_idx: u8,
    pub lmac_id: u8,
}

/// `struct hal_tx_info` (the fields `ath11k_hal_tx_cmd_desc_setup`
/// writes).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalTxInfo {
    pub meta_data_flags: u16,
    pub ring_id: u8,
    pub desc_id: u32,
    pub desc_type: u32,
    pub encap_type: u32,
    pub paddr: u64,
    pub data_len: u32,
    pub pkt_offset: u32,
    pub encrypt_type: u32,
    pub flags0: u32,
    pub flags1: u32,
    pub addr_search_flags: u16,
    pub bss_ast_hash: u16,
    pub bss_ast_idx: u16,
    pub tid: u8,
    pub search_type: u8,
    pub lmac_id: u8,
    pub dscp_tid_tbl_idx: u8,
    pub enable_mesh: bool,
    pub rbm_id: u8,
}

/// Linux `ath11k_hal_tx_cmd_desc_setup`: the seven words of
/// `struct hal_tcl_data_cmd` (after the TLV header). Mesh is not used
/// by a station (`ti->enable_mesh` false).
pub fn hal_tx_cmd_desc(ti: &HalTxInfo) -> [u32; 7] {
    let mut info3 = field_prep(
        HAL_TCL_DATA_CMD_INFO3_DSCP_TID_TABLE_IDX,
        ti.dscp_tid_tbl_idx as u32,
    ) | field_prep(HAL_TCL_DATA_CMD_INFO3_SEARCH_INDEX, ti.bss_ast_idx as u32)
        | field_prep(HAL_TCL_DATA_CMD_INFO3_CACHE_SET_NUM, ti.bss_ast_hash as u32);
    if ti.enable_mesh {
        // ath11k_hw_wcn6855_tx_mesh_enable: HAL_QCN9074_TCL_DATA_CMD_INFO3_MESH_ENABLE
        info3 |= 1 << 30;
    }
    [
        field_prep(BUFFER_ADDR_INFO0_ADDR, ti.paddr as u32),
        field_prep(
            BUFFER_ADDR_INFO1_ADDR,
            (ti.paddr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
        ) | field_prep(BUFFER_ADDR_INFO1_RET_BUF_MGR, ti.rbm_id as u32)
            | field_prep(BUFFER_ADDR_INFO1_SW_COOKIE, ti.desc_id),
        field_prep(HAL_TCL_DATA_CMD_INFO0_DESC_TYPE, ti.desc_type)
            | field_prep(HAL_TCL_DATA_CMD_INFO0_ENCAP_TYPE, ti.encap_type)
            | field_prep(HAL_TCL_DATA_CMD_INFO0_ENCRYPT_TYPE, ti.encrypt_type)
            | field_prep(HAL_TCL_DATA_CMD_INFO0_SEARCH_TYPE, ti.search_type as u32)
            | field_prep(HAL_TCL_DATA_CMD_INFO0_ADDR_EN, ti.addr_search_flags as u32)
            | field_prep(HAL_TCL_DATA_CMD_INFO0_CMD_NUM, ti.meta_data_flags as u32),
        ti.flags0
            | field_prep(HAL_TCL_DATA_CMD_INFO1_DATA_LEN, ti.data_len)
            | field_prep(HAL_TCL_DATA_CMD_INFO1_PKT_OFFSET, ti.pkt_offset),
        ti.flags1
            | field_prep(HAL_TCL_DATA_CMD_INFO2_TID, ti.tid as u32)
            | field_prep(HAL_TCL_DATA_CMD_INFO2_LMAC_ID, ti.lmac_id as u32),
        info3,
        0,
    ]
}

/// `ath11k_hal_tx_init_data_ring`'s TLV header of every TCL entry.
pub const TCL_DATA_TLV_HDR: u32 =
    (tlv_tag::HAL_TCL_DATA_CMD << 1) | ((HAL_TCL_DESC_LEN as u32) << 10);

/// A transmitted frame's completion (`struct hal_tx_status` / the HTT
/// variant `struct ath11k_dp_htt_wbm_tx_status`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxCompletion {
    pub ring: u8,
    pub msdu_id: u32,
    pub mac_id: u8,
    /// `HAL_WBM_REL_SRC_MODULE_*`.
    pub buf_rel_source: u32,
    /// TQM: `HAL_WBM_TQM_REL_REASON_*`; FW: `HAL_WBM_REL_HTT_TX_COMP_STATUS_*`.
    pub status: u32,
    pub acked: bool,
    pub ack_rssi: u8,
    pub ppdu_id: u32,
    pub try_cnt: u8,
    pub tid: u8,
    pub peer_id: u16,
    pub flags: u32,
    pub rate_stats: u32,
    pub len: u32,
}

/// A delivered MSDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RxMsdu {
    /// Ethernet II frame (DA, SA, ethertype, payload).
    pub frame: Vec<u8>,
    pub mac_id: u8,
    pub peer_id: u16,
    pub tid: u8,
    pub seq_no: u16,
    pub is_first_msdu: bool,
    pub is_last_msdu: bool,
    pub is_mcbc: bool,
    pub is_eapol: bool,
    pub decrypted: bool,
    /// `DP_RX_MPDU_ERR_*` of the MPDU (FCS / MIC / decrypt errors are
    /// dropped before delivery).
    pub err_bitmap: u32,
    /// `RX_MSDU_START` decap format (`decap::*`).
    pub decap: u8,
    /// Checksums verified by hardware (`CHECKSUM_UNNECESSARY`).
    pub csum_ok: bool,
    /// `rx_desc_get_msdu_freq` (phy meta data).
    pub freq: u32,
    /// Delivered from the WBM error ring (`DESC_ADDR_ZERO`).
    pub from_err_path: bool,
}

/// A REO status ring entry's uniform header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReoStatus {
    pub tag: u32,
    pub cmd_num: u16,
    pub cmd_status: u8,
}

/// What one [`Dp::service_srng`] pass produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DpServiceOutput {
    pub work_done: u32,
    pub rx: Vec<RxMsdu>,
    pub tx_done: Vec<TxCompletion>,
    pub reo_status: Vec<ReoStatus>,
}

// ── the DP context ────────────────────────────────────────────────

/// `struct ath11k_dp` + the single pdev's `struct ath11k_pdev_dp`.
#[derive(Debug)]
pub struct Dp {
    pub cfg: DpHwParams,
    pub sizes: DpRingSizes,
    msi: Option<CeMsi>,
    pub wbm_idle_ring: DpSrng,
    pub n_link_desc: u32,
    /// Idle-list entries written (`src_get_next_entry` stops one short
    /// of the ring).
    pub link_desc_posted: u32,
    pub link_desc_banks: Vec<LinkDescBank>,
    pub wbm_desc_rel_ring: DpSrng,
    pub tcl_cmd_ring: DpSrng,
    pub tcl_status_ring: DpSrng,
    pub tx_ring: Vec<DpTxRing>,
    pub tx_ring_timer: Vec<HpUpdateTimer>,
    pub reo_reinject_ring: DpSrng,
    pub rx_rel_ring: DpSrng,
    pub reo_except_ring: DpSrng,
    pub reo_cmd_ring: DpSrng,
    pub reo_cmd_timer: HpUpdateTimer,
    pub reo_status_ring: DpSrng,
    pub reo_dst_ring: Vec<DpSrng>,
    pub pdev: Option<PdevDp>,
    pub htt: HttTarget,
    pub peers: Vec<DpPeer>,
    /// `ATH11K_FLAG_CRASH_FLUSH`.
    pub crash_flush: bool,
    pub stats: DpStats,
    /// Per-peer REO queues + pending REO commands (`dp_peer`).
    pub peer_rx: super::dp_peer::DpPeerRx,
    /// The service pass's clock (ms; `jiffies` for the fragment timer).
    pub now_ms: u64,
}

fn dp_err(step: u32, detail: u32, errno: i32) -> TransportError {
    TransportError::new(step, detail, errno)
}

/// Read `N` descriptor words of the entry at word offset `off`.
fn rd_desc<const N: usize>(hal: &Hal, id: u32, off: u32) -> [u32; N] {
    let mut w = [0u32; N];
    for (i, v) in w.iter_mut().enumerate() {
        *v = hal.desc_rd(id, off, i as u32);
    }
    w
}

/// Linux `ath11k_dp_srng_setup`: ring memory + MSI + interrupt
/// thresholds, then `ath11k_hal_srng_setup`.
#[allow(clippy::too_many_arguments)] // Linux's signature + the MSI inputs
fn dp_srng_setup(
    hal: &mut Hal,
    io: &impl ChipIo,
    mask: &RingMask,
    msi: Option<&CeMsi>,
    ty: HalRingType,
    ring_num: u32,
    mac_id: u32,
    num_entries: u32,
) -> Result<DpSrng, TransportError> {
    let entry_sz = hal.entry_size_bytes(ty);
    let max_entries = hal.max_entries(ty);
    let num_entries = num_entries.min(max_entries);
    let size = num_entries * entry_sz + HAL_RING_BASE_ALIGN as u32 - 1;

    // Linux allocates `size` and aligns the start to 8. The NARF
    // allocator is page aligned, so `num_entries * entry_sz` with no
    // slack keeps a power-of-two ring in one power-of-two allocation.
    let bytes = (num_entries * entry_sz) as usize;
    let ring = DmaMem::alloc(bytes, 1)
        .and_then(|m| {
            if m.paddr() % HAL_RING_BASE_ALIGN as u64 == 0 {
                Ok(m)
            } else {
                DmaMem::alloc(bytes, HAL_RING_BASE_ALIGN)
            }
        })
        .map_err(|e| {
            dp_err(
                step::RING_ALLOC,
                ((ty as u32) << 24) | ((bytes as u32 >> 8) & 0x00ff_ffff),
                e.errno,
            )
        })?;

    let mut params = SrngParams::new(ring, num_entries);
    if let Some((addr, data)) = srng_msi(mask, msi, ty, ring_num + mac_id) {
        params.msi_addr = addr;
        params.msi_data = data;
        params.flags |= flags::MSI_INTR;
    }

    use HalRingType as T;
    match ty {
        T::ReoDst => {
            params.intr_batch_cntr_thres_entries = HAL_SRNG_INT_BATCH_THRESHOLD_RX;
            params.intr_timer_thres_us = HAL_SRNG_INT_TIMER_THRESHOLD_RX;
        }
        T::RxdmaBuf | T::RxdmaMonitorBuf | T::RxdmaMonitorStatus => {
            params.low_threshold = num_entries >> 3;
            params.flags |= flags::LOW_THRESH_INTR_EN;
            params.intr_batch_cntr_thres_entries = 0;
            params.intr_timer_thres_us = HAL_SRNG_INT_TIMER_THRESHOLD_RX;
        }
        T::Wbm2SwRelease if ring_num < 3 => {
            params.intr_batch_cntr_thres_entries = HAL_SRNG_INT_BATCH_THRESHOLD_TX;
            params.intr_timer_thres_us = HAL_SRNG_INT_TIMER_THRESHOLD_TX;
        }
        T::Wbm2SwRelease
        | T::ReoException
        | T::ReoReinject
        | T::ReoCmd
        | T::ReoStatus
        | T::TclData
        | T::TclCmd
        | T::TclStatus
        | T::WbmIdleLink
        | T::Sw2WbmRelease
        | T::RxdmaDst
        | T::RxdmaMonitorDst
        | T::RxdmaMonitorDesc => {
            params.intr_batch_cntr_thres_entries = HAL_SRNG_INT_BATCH_THRESHOLD_OTHER;
            params.intr_timer_thres_us = HAL_SRNG_INT_TIMER_THRESHOLD_OTHER;
        }
        T::RxdmaDirBuf => {}
        T::CeSrc | T::CeDst | T::CeDstStatus => {
            return Err(dp_err(step::BAD_RING_TYPE, ty as u32, errno::EINVAL));
        }
    }

    let id = hal
        .srng_setup(io, ty, ring_num, mac_id, params)
        .map_err(|e| {
            dp_err(
                step::SRNG_SETUP,
                ((ty as u32) << 24) | ((ring_num & 0xff) << 16) | (e.step & 0xffff),
                e.errno,
            )
        })?;
    Ok(DpSrng {
        ring_id: id,
        size,
        num_entries,
    })
}

/// Free every HAL ring set up since `before` was taken (a failed
/// allocation's unwind).
fn release_new_rings(hal: &mut Hal, before: &[u32]) {
    for id in hal.srng_ids() {
        if !before.contains(&id) {
            hal.srng_free(id);
        }
    }
}

/// `DSCP_TID_MAP_TBL_ENTRY_SIZE` table of hal_tx.c (DSCP >> 3).
const fn dscp_tid(i: usize) -> u32 {
    (i / 8) as u32
}

/// Linux `ath11k_hal_tx_set_dscp_tid_map`.
pub fn hal_tx_set_dscp_tid_map(io: &impl ChipIo, id: u32) {
    let ctrl = HAL_SEQ_WCSS_UMAC_TCL_REG + HAL_TCL1_RING_CMN_CTRL_REG;
    let v = io.read32(ctrl) | HAL_TCL1_RING_CMN_CTRL_DSCP_TID_MAP_PROG_EN;
    io.write32(ctrl, v);

    let mut addr = HAL_SEQ_WCSS_UMAC_TCL_REG
        + HAL_TCL1_RING_DSCP_TID_MAP
        + (4 * id * (HAL_DSCP_TID_TBL_SIZE / 4));
    let mut hw_map_val = [0u8; HAL_DSCP_TID_TBL_SIZE as usize];
    let mut cnt = 0;
    let mut i = 0;
    while i < 64 {
        let mut value = 0u32;
        for k in 0..8 {
            // HAL_TCL1_RING_FIELD_DSCP_TID_MAPk = GENMASK(3k + 2, 3k)
            value |= field_prep(genmask(3 * k + 2, 3 * k), dscp_tid(i + k as usize));
        }
        hw_map_val[cnt..cnt + 3].copy_from_slice(&value.to_le_bytes()[..3]);
        cnt += 3;
        i += 8;
    }
    for c in hw_map_val.chunks_exact(4) {
        io.write32(addr, u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
        addr += 4;
    }

    let v = io.read32(ctrl) & !HAL_TCL1_RING_CMN_CTRL_DSCP_TID_MAP_PROG_EN;
    io.write32(ctrl, v);
}

/// Linux `ath11k_hw_wcn6855_reo_setup` (`hw_ops->reo_setup`), called at
/// the end of `ath11k_dp_srng_common_setup`: aging, the fragment
/// destination ring (REO2SW1) and the hash → REO2SW1..4 destination map
/// (`DEST_RING_CTRL_IX_2` / `_3`).
pub fn wcn6855_reo_setup(io: &impl ChipIo, misc_ctl: u32, aging_thresh: [u32; 4]) {
    let reo_base = HAL_SEQ_WCSS_UMAC_REO_REG;
    let ring_hash_map = HAL_HASH_ROUTING_RING_SW1
        | (HAL_HASH_ROUTING_RING_SW2 << 4)
        | (HAL_HASH_ROUTING_RING_SW3 << 8)
        | (HAL_HASH_ROUTING_RING_SW4 << 12)
        | (HAL_HASH_ROUTING_RING_SW1 << 16)
        | (HAL_HASH_ROUTING_RING_SW2 << 20)
        | (HAL_HASH_ROUTING_RING_SW3 << 24)
        | (HAL_HASH_ROUTING_RING_SW4 << 28);

    let mut val = io.read32(reo_base + HAL_REO1_GEN_ENABLE);
    val |= field_prep(HAL_REO1_GEN_ENABLE_AGING_LIST_ENABLE, 1)
        | field_prep(HAL_REO1_GEN_ENABLE_AGING_FLUSH_ENABLE, 1);
    io.write32(reo_base + HAL_REO1_GEN_ENABLE, val);

    let mut val = io.read32(reo_base + misc_ctl);
    val &= !HAL_REO1_MISC_CTL_FRAGMENT_DST_RING;
    val |= field_prep(HAL_REO1_MISC_CTL_FRAGMENT_DST_RING, ring_id::REO2SW1);
    io.write32(reo_base + misc_ctl, val);

    for a in aging_thresh {
        io.write32(reo_base + a, HAL_DEFAULT_REO_TIMEOUT_USEC);
    }

    io.write32(reo_base + HAL_REO1_DEST_RING_CTRL_IX_2, ring_hash_map);
    io.write32(reo_base + HAL_REO1_DEST_RING_CTRL_IX_3, ring_hash_map);
}

/// `ath11k_hal_set_link_desc_addr`: the two words of a
/// `struct hal_wbm_link_desc` (rbm `WBM_IDLE_DESC_LIST`, cookie = bank).
pub const fn link_desc_words(cookie: u32, paddr: u64) -> [u32; 2] {
    [
        field_prep(
            BUFFER_ADDR_INFO0_ADDR,
            (paddr & HAL_ADDR_LSB_REG_MASK) as u32,
        ),
        field_prep(
            BUFFER_ADDR_INFO1_ADDR,
            (paddr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
        ) | field_prep(BUFFER_ADDR_INFO1_RET_BUF_MGR, 1)
            | field_prep(BUFFER_ADDR_INFO1_SW_COOKIE, cookie),
    ]
}

/// `ath11k_hal_rx_buf_addr_info_set` words.
pub const fn buf_addr_words(paddr: u64, cookie: u32, manager: u8) -> [u32; 2] {
    let b = BufferAddr::new(paddr, cookie, manager);
    [b.info0, b.info1]
}

/// `ath11k_hal_rx_buf_addr_info_get`: (paddr, cookie, rbm).
pub const fn buf_addr_get(w0: u32, w1: u32) -> (u64, u32, u8) {
    BufferAddr {
        info0: w0,
        info1: w1,
    }
    .get()
}

/// `ieee80211_hdrlen` for the frame types the data path sees.
pub fn ieee80211_hdrlen(fc: u16) -> usize {
    let mut hdrlen = 24;
    if fc & IEEE80211_FCTL_FTYPE == IEEE80211_FTYPE_DATA {
        if fc & (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS)
            == (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS)
        {
            hdrlen = 30;
        }
        if fc & IEEE80211_STYPE_QOS_DATA != 0 {
            hdrlen += IEEE80211_QOS_CTL_LEN;
            if fc & IEEE80211_FCTL_ORDER != 0 {
                hdrlen += 4;
            }
        }
    }
    hdrlen
}

fn is_data(fc: u16) -> bool {
    fc & IEEE80211_FCTL_FTYPE == IEEE80211_FTYPE_DATA
}

/// `ieee80211_get_DA` / `ieee80211_get_SA` of an 802.11 header.
pub fn ieee80211_da_sa(hdr: &[u8]) -> Option<([u8; 6], [u8; 6])> {
    if hdr.len() < 24 {
        return None;
    }
    let fc = u16::from_le_bytes([hdr[0], hdr[1]]);
    let a = |o: usize| -> [u8; 6] {
        let mut m = [0u8; 6];
        m.copy_from_slice(&hdr[o..o + 6]);
        m
    };
    let to_ds = fc & IEEE80211_FCTL_TODS != 0;
    let from_ds = fc & IEEE80211_FCTL_FROMDS != 0;
    let da = if to_ds { a(16) } else { a(4) };
    let sa = if from_ds {
        if to_ds {
            if hdr.len() < 30 {
                return None;
            }
            a(24)
        } else {
            a(16)
        }
    } else {
        a(10)
    };
    Some((da, sa))
}

/// 802.11 (native-wifi decap) → Ethernet II: DA / SA from the header,
/// ethertype from an RFC 1042 / bridge-tunnel SNAP header; without SNAP
/// an 802.3 length frame.
pub fn nwifi_to_eth(msdu: &[u8]) -> Option<Vec<u8>> {
    if msdu.len() < 2 {
        return None;
    }
    let fc = u16::from_le_bytes([msdu[0], msdu[1]]);
    let hdrlen = ieee80211_hdrlen(fc);
    if msdu.len() < hdrlen {
        return None;
    }
    let (da, sa) = ieee80211_da_sa(msdu)?;
    let payload = &msdu[hdrlen..];
    let mut out = Vec::with_capacity(ETH_HLEN + payload.len());
    out.extend_from_slice(&da);
    out.extend_from_slice(&sa);
    if payload.len() >= 8
        && (payload[..6] == RFC1042_HEADER || payload[..6] == BRIDGE_TUNNEL_HEADER)
    {
        out.extend_from_slice(&payload[6..8]);
        out.extend_from_slice(&payload[8..]);
    } else {
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
    }
    Some(out)
}

/// 802.3 (length + LLC/SNAP) → Ethernet II when the SNAP is RFC 1042 /
/// bridge-tunnel; anything else is returned unchanged.
pub fn ieee8023_to_eth(msdu: &[u8]) -> Option<Vec<u8>> {
    if msdu.len() < ETH_HLEN {
        return None;
    }
    let len_or_type = u16::from_be_bytes([msdu[12], msdu[13]]);
    if len_or_type < 0x600 && msdu.len() >= ETH_HLEN + 8 {
        let snap = &msdu[ETH_HLEN..ETH_HLEN + 6];
        if snap == RFC1042_HEADER || snap == BRIDGE_TUNNEL_HEADER {
            let mut out = Vec::with_capacity(msdu.len() - 8);
            out.extend_from_slice(&msdu[..12]);
            out.extend_from_slice(&msdu[ETH_HLEN + 6..]);
            return Some(out);
        }
    }
    Some(msdu.to_vec())
}

/// One reaped RX buffer (`skb` + `struct ath11k_skb_rxcb`).
#[derive(Clone, Debug)]
struct RxSkb {
    data: Vec<u8>,
    is_first_msdu: bool,
    is_last_msdu: bool,
    is_continuation: bool,
    peer_id: u16,
    seq_no: u16,
    tid: u8,
    mac_id: u8,
    err_rel_src: u32,
    err_code: u32,
    /// `rxcb->is_frag`: a reassembled MPDU back from the REO.
    is_frag: bool,
}

impl RxSkb {
    fn new(data: Vec<u8>, mac_id: u8) -> RxSkb {
        RxSkb {
            data,
            is_first_msdu: false,
            is_last_msdu: false,
            is_continuation: false,
            peer_id: 0,
            seq_no: 0,
            tid: 0,
            mac_id,
            err_rel_src: 0,
            err_code: 0,
            is_frag: false,
        }
    }
}

/// Why an MSDU was not delivered (counted in [`DpStats`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxDrop {
    NoLastBuf,
    MsduLenErr,
    MsduNotDone,
    InvalidLen,
    Coalesce,
    DecapUnsupported,
    Fcs,
    Mic,
    Decrypt,
}

/// `ath11k_dp_rx_h_attn_mpdu_err`.
pub fn attn_mpdu_err(d: &HalRxDescWcn6855) -> u32 {
    let info = d.attention.info1;
    let mut e = 0;
    if info & RX_ATTENTION_INFO1_FCS_ERR != 0 {
        e |= DP_RX_MPDU_ERR_FCS;
    }
    if info & RX_ATTENTION_INFO1_DECRYPT_ERR != 0 {
        e |= DP_RX_MPDU_ERR_DECRYPT;
    }
    if info & RX_ATTENTION_INFO1_TKIP_MIC_ERR != 0 {
        e |= DP_RX_MPDU_ERR_TKIP_MIC;
    }
    if info & RX_ATTENTION_INFO1_A_MSDU_ERROR != 0 {
        e |= DP_RX_MPDU_ERR_AMSDU_ERR;
    }
    if info & RX_ATTENTION_INFO1_OVERFLOW_ERR != 0 {
        e |= DP_RX_MPDU_ERR_OVERFLOW;
    }
    if info & RX_ATTENTION_INFO1_MSDU_LEN_ERR != 0 {
        e |= DP_RX_MPDU_ERR_MSDU_LEN;
    }
    if info & RX_ATTENTION_INFO1_MPDU_LEN_ERR != 0 {
        e |= DP_RX_MPDU_ERR_MPDU_LEN;
    }
    e
}

fn rx_desc(b: &[u8]) -> HalRxDescWcn6855 {
    HalRxDescWcn6855::from_bytes(b).expect("RX buffer holds a descriptor")
}

impl Dp {
    /// Linux `ath11k_dp_alloc` (called from
    /// `ath11k_core_qmi_firmware_ready` after `ath11k_ce_init_pipes`).
    /// `hal` is the device's HAL (`Ce::hal`); `msi` the probe's MSI (DP
    /// user). Failures are latched and printed.
    pub fn alloc(
        hal: &mut Hal,
        io: &impl ChipIo,
        cfg: &DpHwParams,
        sizes: DpRingSizes,
        msi: Option<CeMsi>,
    ) -> Result<Dp, TransportError> {
        let before = hal.srng_ids();
        let r = Self::alloc_inner(hal, io, cfg, sizes, msi);
        if let Err(e) = &r {
            e.report("ath11k DP alloc");
            // fail_cmn_srng_cleanup / fail_link_desc_cleanup: every ring
            // this attempt set up leaves the HAL (the link descriptor
            // banks went with the error), so the HAL takes a new attempt.
            release_new_rings(hal, &before);
        }
        r
    }

    /// The probe's DP MSI (`ath11k_dp_srng_msi_setup` input).
    pub fn msi(&self) -> Option<CeMsi> {
        self.msi
    }

    /// Linux `ath11k_dp_pdev_reo_cleanup`: the REO2SW destination rings
    /// (`ath11k_core_stop`, `ath11k_core_reconfigure_on_crash`).
    pub fn pdev_reo_cleanup(&mut self, hal: &mut Hal) {
        for r in self.reo_dst_ring.drain(..) {
            hal.srng_free(r.ring_id);
        }
    }

    /// Linux `ath11k_dp_pdev_free` for the single pdev
    /// (`ath11k_dp_rx_pdev_free`: `ath11k_dp_rx_pdev_srng_free` + the RX
    /// buffers of `ath11k_dp_rxdma_pdev_buf_free`; the monitor reap timer
    /// is the runtime's). Only once the hardware no longer uses the rings.
    pub fn pdev_free(&mut self, hal: &mut Hal) {
        let Some(p) = self.pdev.take() else { return };
        hal.srng_free(p.rx_refill_buf_ring.refill_buf_ring.ring_id);
        for r in p.rx_mac_buf_ring.iter().chain(p.rxdma_err_dst_ring.iter()) {
            hal.srng_free(r.ring_id);
        }
        for r in &p.rx_mon_status_refill_ring {
            hal.srng_free(r.refill_buf_ring.ring_id);
        }
        // The RX buffers in the IDRs go with `p`.
        drop(p);
    }

    /// Linux `ath11k_dp_free` (`ath11k_core_reconfigure_on_crash`, after
    /// the device reset): the WBM idle ring + link descriptor banks
    /// (`ath11k_dp_link_desc_cleanup`), the shadow timers and the common
    /// rings (`ath11k_dp_srng_common_cleanup`), the REO command lists with
    /// their queue descriptors (`ath11k_dp_reo_cmd_list_cleanup`; NARF's
    /// stranded descriptors go too: the device that might have used them
    /// was reset; the per-TID fragment buffers and frag timers go with
    /// the peer state) and the pending TX buffers
    /// (`ath11k_dp_tx_pending_cleanup`). A pdev or REO destination ring
    /// still set up is released first. Afterwards the HAL holds none of
    /// this DP's rings.
    pub fn free(mut self, hal: &mut Hal) {
        self.pdev_free(hal);
        self.pdev_reo_cleanup(hal);
        hal.srng_free(self.wbm_idle_ring.ring_id);
        self.link_desc_banks.clear();
        // ath11k_dp_stop_shadow_timers
        for t in self.tx_ring_timer.iter_mut() {
            t.started = false;
        }
        self.reo_cmd_timer.started = false;
        let common = [
            self.wbm_desc_rel_ring,
            self.tcl_cmd_ring,
            self.tcl_status_ring,
            self.reo_reinject_ring,
            self.rx_rel_ring,
            self.reo_except_ring,
            self.reo_cmd_ring,
            self.reo_status_ring,
        ];
        for r in self.tx_ring.iter() {
            hal.srng_free(r.tcl_data_ring.ring_id);
            hal.srng_free(r.tcl_comp_ring.ring_id);
        }
        for r in common {
            hal.srng_free(r.ring_id);
        }
        // The queue descriptors and TX buffers drop with `self`.
        self.peer_rx = super::dp_peer::DpPeerRx::default();
        for r in self.tx_ring.iter_mut() {
            r.txbuf = Idr::default();
        }
    }

    fn alloc_inner(
        hal: &mut Hal,
        io: &impl ChipIo,
        cfg: &DpHwParams,
        sizes: DpRingSizes,
        msi: Option<CeMsi>,
    ) -> Result<Dp, TransportError> {
        let mask = *cfg.hw.ring_mask;
        let m = msi.as_ref();

        // ath11k_wbm_idle_ring_setup
        let n_link_desc = sizes.n_link_desc.unwrap_or_else(wbm_idle_n_link_desc);
        let wbm_idle_ring = dp_srng_setup(
            hal,
            io,
            &mask,
            m,
            HalRingType::WbmIdleLink,
            0,
            0,
            n_link_desc,
        )?;

        // ath11k_dp_link_desc_setup
        let (banks, posted) = Self::link_desc_setup(hal, io, wbm_idle_ring.ring_id, n_link_desc)?;

        // ath11k_dp_srng_common_setup
        let wbm_desc_rel_ring = dp_srng_setup(
            hal,
            io,
            &mask,
            m,
            HalRingType::Sw2WbmRelease,
            0,
            0,
            sizes.wbm_release,
        )?;
        let tcl_cmd_ring =
            dp_srng_setup(hal, io, &mask, m, HalRingType::TclCmd, 0, 0, sizes.tcl_cmd)?;
        let tcl_status_ring = dp_srng_setup(
            hal,
            io,
            &mask,
            m,
            HalRingType::TclStatus,
            0,
            0,
            sizes.tcl_status,
        )?;

        let mut tx_ring = Vec::new();
        let mut tx_ring_timer = Vec::new();
        for (i, map) in cfg.hal_params.tcl2wbm_rbm_map.iter().enumerate() {
            let tcl_data_ring = dp_srng_setup(
                hal,
                io,
                &mask,
                m,
                HalRingType::TclData,
                map.tcl_ring_num as u32,
                0,
                sizes.tcl_data.unwrap_or(cfg.tx_ring_size),
            )?;
            let tcl_comp_ring = dp_srng_setup(
                hal,
                io,
                &mask,
                m,
                HalRingType::Wbm2SwRelease,
                map.wbm_ring_num as u32,
                0,
                sizes.tx_comp,
            )?;
            Self::hal_tx_init_data_ring(hal, tcl_data_ring.ring_id);
            tx_ring_timer.push(Self::shadow_timer(
                cfg,
                ATH11K_SHADOW_DP_TIMER_INTERVAL,
                tcl_data_ring.ring_id,
            ));
            tx_ring.push(DpTxRing {
                tcl_data_ring_id: i as u8,
                tcl_data_ring,
                tcl_comp_ring,
                txbuf: Idr::default(),
                tx_status: vec![[0u32; 8]; sizes.tx_status_fifo.max(2) as usize],
                tx_status_head: 0,
                tx_status_tail: sizes.tx_status_fifo.max(2) - 1,
            });
        }

        let reo_reinject_ring = dp_srng_setup(
            hal,
            io,
            &mask,
            m,
            HalRingType::ReoReinject,
            0,
            0,
            sizes.reo_reinject,
        )?;
        let rx_rel_ring = dp_srng_setup(
            hal,
            io,
            &mask,
            m,
            HalRingType::Wbm2SwRelease,
            DP_RX_RELEASE_RING_NUM,
            0,
            sizes.rx_release,
        )?;
        let reo_except_ring = dp_srng_setup(
            hal,
            io,
            &mask,
            m,
            HalRingType::ReoException,
            0,
            0,
            sizes.reo_exception,
        )?;
        let reo_cmd_ring =
            dp_srng_setup(hal, io, &mask, m, HalRingType::ReoCmd, 0, 0, sizes.reo_cmd)?;
        Self::hal_reo_init_cmd_ring(hal, reo_cmd_ring.ring_id);
        let reo_cmd_timer =
            Self::shadow_timer(cfg, ATH11K_SHADOW_CTRL_TIMER_INTERVAL, reo_cmd_ring.ring_id);
        let reo_status_ring = dp_srng_setup(
            hal,
            io,
            &mask,
            m,
            HalRingType::ReoStatus,
            0,
            0,
            sizes.reo_status,
        )?;

        // hw_ops->reo_setup (wcn6855)
        let r = hal.regs;
        wcn6855_reo_setup(
            io,
            r.hal_reo1_misc_ctl,
            [
                r.hal_reo1_aging_thresh_ix_0,
                r.hal_reo1_aging_thresh_ix_1,
                r.hal_reo1_aging_thresh_ix_2,
                r.hal_reo1_aging_thresh_ix_3,
            ],
        );

        for i in 0..HAL_DSCP_TID_MAP_TBL_NUM_ENTRIES_MAX {
            hal_tx_set_dscp_tid_map(io, i);
        }

        Ok(Dp {
            cfg: *cfg,
            sizes,
            msi,
            wbm_idle_ring,
            n_link_desc,
            link_desc_posted: posted,
            link_desc_banks: banks,
            wbm_desc_rel_ring,
            tcl_cmd_ring,
            tcl_status_ring,
            tx_ring,
            tx_ring_timer,
            reo_reinject_ring,
            rx_rel_ring,
            reo_except_ring,
            reo_cmd_ring,
            reo_cmd_timer,
            reo_status_ring,
            reo_dst_ring: Vec::new(),
            pdev: None,
            htt: HttTarget::default(),
            peers: Vec::new(),
            crash_flush: false,
            stats: DpStats::default(),
            peer_rx: super::dp_peer::DpPeerRx::default(),
            now_ms: 0,
        })
    }

    /// `ath11k_dp_shadow_init_timer`.
    fn shadow_timer(cfg: &DpHwParams, interval_ms: u64, ring_id: u32) -> HpUpdateTimer {
        HpUpdateTimer {
            init: cfg.hw.supports_shadow_regs,
            ring_id,
            interval_ms,
            ..HpUpdateTimer::default()
        }
    }

    /// Linux `ath11k_dp_link_desc_setup` for the WBM idle list: allocate
    /// the banks and post every descriptor the ring takes. Returns the
    /// banks and how many entries were posted.
    fn link_desc_setup(
        hal: &mut Hal,
        io: &impl ChipIo,
        ring: u32,
        n_link_desc: u32,
    ) -> Result<(Vec<LinkDescBank>, u32), TransportError> {
        let (n_bank, last_bank_sz) = link_desc_banks(n_link_desc);
        if n_bank > DP_LINK_DESC_BANKS_MAX {
            return Err(dp_err(step::LINK_DESC_BANKS, n_bank, errno::EINVAL));
        }
        // ath11k_dp_link_desc_bank_alloc
        let mut banks = Vec::with_capacity(n_bank as usize);
        for i in 0..n_bank {
            let mut desc_sz = DP_LINK_DESC_ALLOC_SIZE_THRESH;
            if i == n_bank - 1 && last_bank_sz != 0 {
                desc_sz = last_bank_sz;
            }
            let mem = DmaMem::alloc(desc_sz as usize, 1)
                .map_err(|e| dp_err(step::LINK_DESC_ALLOC, i, e.errno))?;
            let raw = mem.paddr();
            let a = HAL_LINK_DESC_ALIGN as u64;
            let aligned = (raw + a - 1) & !(a - 1);
            banks.push(LinkDescBank {
                mem,
                align_bytes: (aligned - raw) as u32,
                paddr: aligned,
                size: desc_sz,
            });
        }

        let entry_sz = hal.entry_size_bytes(HalRingType::WbmIdleLink);
        let tot_mem_sz = entry_sz * n_link_desc;
        if tot_mem_sz > DP_LINK_DESC_ALLOC_SIZE_THRESH {
            // ath11k_dp_scatter_idle_link_desc_setup — not ported.
            return Err(dp_err(step::SCATTER_UNSUPPORTED, tot_mem_sz, EOPNOTSUPP));
        }

        hal.access_begin(ring);
        let mut posted = 0;
        for (i, b) in banks.iter().enumerate() {
            let mut n_entries = (b.size - b.align_bytes) / HAL_LINK_DESC_SIZE;
            let mut paddr = b.paddr;
            while n_entries > 0 {
                let Some(off) = hal.src_get_next_entry(ring) else {
                    break;
                };
                hal.desc_wr(ring, off, &link_desc_words(i as u32, paddr));
                posted += 1;
                n_entries -= 1;
                paddr += HAL_LINK_DESC_SIZE as u64;
            }
        }
        hal.access_end(io, ring);
        Ok((banks, posted))
    }

    /// Linux `ath11k_hal_tx_init_data_ring`.
    fn hal_tx_init_data_ring(hal: &Hal, ring: u32) {
        let Some(s) = hal.srng(ring) else { return };
        let (n, esz) = (s.num_entries, s.entry_size);
        for i in 0..n {
            hal.desc_wr(ring, i * esz, &[TCL_DATA_TLV_HDR]);
        }
    }

    /// Linux `ath11k_hal_reo_init_cmd_ring`: command numbers from 1.
    fn hal_reo_init_cmd_ring(hal: &Hal, ring: u32) {
        let Some(s) = hal.srng(ring) else { return };
        let (n, esz) = (s.num_entries, s.entry_size);
        for i in 0..n {
            // tlv (word 0), hal_reo_get_queue_stats.cmd.info0 (word 1)
            hal.desc_wr(
                ring,
                i * esz + 1,
                &[field_prep(HAL_REO_CMD_HDR_INFO0_CMD_NUMBER, i + 1)],
            );
        }
    }

    /// Linux `ath11k_dp_pdev_reo_setup` (from `ath11k_core_start`, after
    /// `ath11k_mac_allocate`): the four REO2SW destination rings.
    pub fn pdev_reo_setup(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
    ) -> Result<(), TransportError> {
        if !self.reo_dst_ring.is_empty() {
            return Err(dp_err(step::ALREADY_SET_UP, 1, errno::EINVAL));
        }
        let mask = *self.cfg.hw.ring_mask;
        for i in 0..DP_REO_DST_RING_MAX as u32 {
            match dp_srng_setup(
                hal,
                io,
                &mask,
                self.msi.as_ref(),
                HalRingType::ReoDst,
                i,
                0,
                self.sizes.reo_dst,
            ) {
                Ok(r) => self.reo_dst_ring.push(r),
                Err(e) => {
                    e.report("ath11k DP reo_dst ring");
                    // err_reo_cleanup
                    self.pdev_reo_cleanup(hal);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// `ath11k_dp_rxdma_ring_buf_setup`.
    fn rxdma_ring_buf_setup(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        mac_id: u32,
        ring: &mut RxdmaRing,
        ty: HalRingType,
    ) {
        let num_entries = ring.refill_buf_ring.size / hal.entry_size_bytes(ty);
        ring.bufs_max = num_entries;
        let mgr = self.cfg.hal_params.rx_buf_rbm;
        self.rxbufs_replenish(hal, io, mac_id, ring, num_entries, mgr);
    }

    /// Linux `ath11k_dp_pdev_alloc` for the single pdev (`mac_id` 0):
    /// `ath11k_dp_pdev_pre_alloc` + `ath11k_dp_rx_pdev_alloc` (+ the
    /// no-op `ath11k_dp_rx_pdev_mon_attach`). Returns the HTT
    /// SRING_SETUP messages in Linux's order; the caller sends each on
    /// the HTT endpoint and stops at the first send failure, as Linux
    /// does.
    pub fn pdev_alloc(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        mac_id: u32,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let before = hal.srng_ids();
        let r = self.pdev_alloc_inner(hal, io, mac_id);
        if let Err(e) = &r {
            e.report("ath11k DP pdev alloc");
            // ath11k_dp_pdev_alloc's err: ath11k_dp_pdev_free (the rings
            // this attempt set up; nothing was sent to the firmware yet).
            if self.pdev.is_none() {
                release_new_rings(hal, &before);
            }
        }
        r
    }

    fn pdev_alloc_inner(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        mac_id: u32,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        if self.pdev.is_some() {
            return Err(dp_err(step::ALREADY_SET_UP, 2, errno::EINVAL));
        }
        let mask = *self.cfg.hw.ring_mask;
        let m = self.msi;
        let cfg = self.cfg;
        let sz = self.sizes;

        // ath11k_dp_rx_pdev_srng_alloc
        let refill = dp_srng_setup(
            hal,
            io,
            &mask,
            m.as_ref(),
            HalRingType::RxdmaBuf,
            0,
            mac_id,
            sz.rxdma_buf,
        )?;
        let mut rx_mac_buf_ring = Vec::new();
        if cfg.rx_mac_buf_ring {
            for i in 0..cfg.num_rxdma_per_pdev {
                rx_mac_buf_ring.push(dp_srng_setup(
                    hal,
                    io,
                    &mask,
                    m.as_ref(),
                    HalRingType::RxdmaBuf,
                    1,
                    mac_id + i,
                    sz.rx_mac_buf,
                )?);
            }
        }
        let mut rxdma_err_dst_ring = Vec::new();
        for i in 0..cfg.num_rxdma_per_pdev {
            rxdma_err_dst_ring.push(dp_srng_setup(
                hal,
                io,
                &mask,
                m.as_ref(),
                HalRingType::RxdmaDst,
                0,
                mac_id + i,
                sz.rxdma_err_dst,
            )?);
        }
        let mut mon_status = Vec::new();
        for i in 0..cfg.num_rxdma_per_pdev {
            mon_status.push(RxdmaRing {
                refill_buf_ring: dp_srng_setup(
                    hal,
                    io,
                    &mask,
                    m.as_ref(),
                    HalRingType::RxdmaMonitorStatus,
                    0,
                    mac_id + i,
                    sz.rxdma_mon_status,
                )?,
                bufs: Idr::default(),
                bufs_max: 0,
            });
        }
        // rxdma1_enable = false: no monitor buf / dst / desc rings (the
        // mon reap timer is the caller's: `reap_mon_status`).

        // ath11k_dp_rxdma_pdev_buf_setup
        let mut refill_ring = RxdmaRing {
            refill_buf_ring: refill,
            bufs: Idr::default(),
            bufs_max: 0,
        };
        self.rxdma_ring_buf_setup(hal, io, mac_id, &mut refill_ring, HalRingType::RxdmaBuf);
        for ring in mon_status.iter_mut() {
            self.rxdma_ring_buf_setup(hal, io, mac_id, ring, HalRingType::RxdmaMonitorStatus);
        }

        // HTT SRING_SETUP, in ath11k_dp_rx_pdev_alloc order.
        let rmb = cfg.rx_mac_buf_ring;
        let mut msgs = Vec::new();
        msgs.push(
            htt::srng_setup_msg(
                hal,
                rmb,
                refill_ring.refill_buf_ring.ring_id,
                mac_id,
                HalRingType::RxdmaBuf,
            )?
            .to_vec(),
        );
        for (i, r) in rx_mac_buf_ring.iter().enumerate() {
            msgs.push(
                htt::srng_setup_msg(
                    hal,
                    rmb,
                    r.ring_id,
                    mac_id + i as u32,
                    HalRingType::RxdmaBuf,
                )?
                .to_vec(),
            );
        }
        for (i, r) in rxdma_err_dst_ring.iter().enumerate() {
            msgs.push(
                htt::srng_setup_msg(
                    hal,
                    rmb,
                    r.ring_id,
                    mac_id + i as u32,
                    HalRingType::RxdmaDst,
                )?
                .to_vec(),
            );
        }
        for (i, r) in mon_status.iter().enumerate() {
            msgs.push(
                htt::srng_setup_msg(
                    hal,
                    rmb,
                    r.refill_buf_ring.ring_id,
                    mac_id + i as u32,
                    HalRingType::RxdmaMonitorStatus,
                )?
                .to_vec(),
            );
        }

        self.pdev = Some(PdevDp {
            mac_id,
            rx_refill_buf_ring: refill_ring,
            rx_mac_buf_ring,
            rxdma_err_dst_ring,
            rx_mon_status_refill_ring: mon_status,
            num_tx_pending: 0,
        });
        Ok(msgs)
    }

    /// `ath11k_mac_config_mon_status_default(ar, enable)` (from
    /// `ath11k_mac_op_start` / `_stop`): one RX_RING_SELECTION_CFG per
    /// monitor-status ring, the default status filter when enabling, an
    /// all-zero filter when disabling.
    pub fn mon_status_default_msgs(
        &self,
        hal: &Hal,
        enable: bool,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let pdev = self
            .pdev
            .as_ref()
            .ok_or(dp_err(step::NOT_SET_UP, 2, errno::EINVAL))?;
        let filter = if enable {
            htt::MON_STATUS_FILTER_DEFAULT
        } else {
            RxRingTlvFilter::default()
        };
        let mut out = Vec::new();
        for (i, r) in pdev.rx_mon_status_refill_ring.iter().enumerate() {
            out.push(
                htt::rx_filter_setup_msg(
                    hal,
                    self.cfg.rx_mac_buf_ring,
                    r.refill_buf_ring.ring_id,
                    pdev.mac_id + i as u32,
                    HalRingType::RxdmaMonitorStatus,
                    DP_RX_BUFFER_SIZE,
                    &filter,
                )?
                .to_vec(),
            );
        }
        Ok(out)
    }

    // ── HTT T2H ───────────────────────────────────────────────────

    /// Linux `ath11k_dp_htt_htc_t2h_msg_handler`: decode, record the
    /// target version (`htt_tgt_version_received`), maintain the peer
    /// table (`ath11k_peer_map_event` / `ath11k_peer_unmap_event`).
    pub fn htt_t2h_msg_handler(&mut self, msg: &[u8]) -> Result<HttT2h, TransportError> {
        let ev = htt::decode_t2h(msg)?;
        match ev {
            HttT2h::VersionConf { major, minor } => {
                self.htt.ver_major = major;
                self.htt.ver_minor = minor;
                self.htt.version_received = true;
            }
            HttT2h::PeerMap {
                vdev_id,
                peer_id,
                mac,
                ast_hash,
                hw_peer_id,
                ..
            } => {
                if !self
                    .peers
                    .iter()
                    .any(|p| p.vdev_id == vdev_id && p.addr == mac)
                {
                    self.peers.push(DpPeer {
                        vdev_id,
                        peer_id,
                        addr: mac,
                        ast_hash,
                        hw_peer_id,
                        sec_type: enc::OPEN,
                        sec_type_grp: enc::OPEN,
                    });
                }
            }
            HttT2h::PeerUnmap { peer_id, .. } => {
                match self.peers.iter().position(|p| p.peer_id == peer_id) {
                    Some(i) => {
                        self.peers.remove(i);
                        self.peer_rx.peer_unmapped(peer_id);
                    }
                    None => self.stats.htt_peer_unmap_unknown += 1,
                }
            }
            HttT2h::Skipped(_) => {}
            HttT2h::Unhandled(_) => self.stats.htt_unhandled += 1,
        }
        Ok(ev)
    }

    /// `ath11k_peer_find_by_id`.
    pub fn peer_by_id(&self, peer_id: u16) -> Option<&DpPeer> {
        self.peers.iter().find(|p| p.peer_id == peer_id)
    }

    /// Set a peer's cipher (the key-install path's `peer->sec_type` /
    /// `sec_type_grp`).
    pub fn set_peer_sec_type(&mut self, peer_id: u16, ucast: u32, mcast: u32) -> bool {
        match self.peers.iter_mut().find(|p| p.peer_id == peer_id) {
            Some(p) => {
                p.sec_type = ucast;
                p.sec_type_grp = mcast;
                true
            }
            None => false,
        }
    }

    // ── RX buffers ───────────────────────────────────────────────

    /// Linux `ath11k_dp_rxbufs_replenish`: post up to `req_entries`
    /// (0 = "top up when more than 3/4 is free") fresh buffers; returns
    /// how many were posted.
    pub fn rxbufs_replenish(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        mac_id: u32,
        rx_ring: &mut RxdmaRing,
        req_entries: u32,
        mgr: u8,
    ) -> u32 {
        let mut req = req_entries.min(rx_ring.bufs_max);
        let id = rx_ring.refill_buf_ring.ring_id;
        hal.access_begin(id);
        let num_free = hal.src_num_free(id, true);
        if req == 0 && num_free > (rx_ring.bufs_max * 3) / 4 {
            req = num_free;
        }
        req = req.min(num_free);
        let mut num_remain = req;
        while num_remain > 0 {
            let mem =
                match DmaMem::alloc(DP_RX_BUFFER_SIZE as usize, DP_RX_BUFFER_ALIGN_SIZE as usize) {
                    Ok(m) => m,
                    Err(_) => {
                        self.stats.rx_buf_alloc_fail += 1;
                        break;
                    }
                };
            let paddr = mem.paddr();
            let buf_id = match rx_ring.bufs.alloc(
                RxBuf {
                    mem,
                    paddr,
                    frag_len: None,
                },
                1,
                rx_ring.bufs_max * 3 + 1,
            ) {
                Ok(b) => b,
                Err(_) => break,
            };
            let Some(off) = hal.src_get_next_entry(id) else {
                rx_ring.bufs.remove(buf_id);
                break;
            };
            let cookie = field_prep(DP_RXDMA_BUF_COOKIE_PDEV_ID, mac_id)
                | field_prep(DP_RXDMA_BUF_COOKIE_BUF_ID, buf_id);
            num_remain -= 1;
            hal.desc_wr(id, off, &buf_addr_words(paddr, cookie, mgr));
        }
        hal.access_end(io, id);
        req - num_remain
    }

    /// Post `n` buffers to the pdev's refill ring with the RX buffer
    /// manager (the `ath11k_dp_rxbufs_replenish(.., rx_refill_buf_ring,
    /// n, rx_buf_rbm)` every reap path ends with).
    pub fn replenish_refill(&mut self, hal: &mut Hal, io: &impl ChipIo, n: u32) {
        let Some(mut pdev) = self.pdev.take() else {
            return;
        };
        let mgr = self.cfg.hal_params.rx_buf_rbm;
        let mac_id = pdev.mac_id;
        self.rxbufs_replenish(hal, io, mac_id, &mut pdev.rx_refill_buf_ring, n, mgr);
        self.pdev = Some(pdev);
    }

    /// Take the refill-ring buffer `buf_id` (`idr_find` + `idr_remove` +
    /// `dma_unmap_single`), returning its full contents.
    pub(super) fn take_rx_buf(&mut self, buf_id: u32) -> Option<Vec<u8>> {
        self.take_rx_buf_frag(buf_id).map(|(d, _)| d)
    }

    /// [`Self::take_rx_buf`] + whether it is a reinjected reassembled
    /// MPDU (`rxcb->is_frag`; its exact length is returned).
    fn take_rx_buf_frag(&mut self, buf_id: u32) -> Option<(Vec<u8>, bool)> {
        let pdev = self.pdev.as_mut()?;
        let b = pdev.rx_refill_buf_ring.bufs.remove(buf_id)?;
        let len = b
            .frag_len
            .map_or(DP_RX_BUFFER_SIZE as usize, |l| l as usize);
        let mut data = vec![0u8; len];
        b.mem.read_bytes(0, &mut data);
        Some((data, b.frag_len.is_some()))
    }

    /// Posted RX buffer `buf_id` of the refill ring (tests / device
    /// models).
    pub fn rx_buf(&self, buf_id: u32) -> Option<&RxBuf> {
        self.pdev.as_ref()?.rx_refill_buf_ring.bufs.find(buf_id)
    }

    // ── TX ───────────────────────────────────────────────────────

    /// Linux `ath11k_dp_tx`: copy `frame` into a DMA bounce buffer, fill
    /// the next TCL data descriptor and publish it. Returns the TX
    /// descriptor id (`desc_id`) the completion carries.
    pub fn tx(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        vif: &VifTx,
        meta: &TxMeta,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<u32, TransportError> {
        if self.crash_flush {
            return Err(dp_err(step::TX_SHUTDOWN, 0, errno::ESHUTDOWN));
        }
        let mut data: Vec<u8> = frame.to_vec();
        let fc = if data.len() >= 2 {
            u16::from_le_bytes([data[0], data[1]])
        } else {
            0
        };
        if meta.encap == TxEncap::NativeWifi {
            if data.len() < 2 {
                return Err(dp_err(step::TX_FRAME_LEN, data.len() as u32, errno::EINVAL));
            }
            if !is_data(fc) {
                return Err(dp_err(step::TX_NOT_DATA, fc as u32, EOPNOTSUPP));
            }
            if data.len() < ieee80211_hdrlen(fc) {
                return Err(dp_err(step::TX_FRAME_LEN, data.len() as u32, errno::EINVAL));
            }
        } else if data.len() < ETH_HLEN {
            return Err(dp_err(step::TX_FRAME_LEN, data.len() as u32, errno::EINVAL));
        }

        let num_tx_rings = self.cfg.num_tx_rings() as u32;
        let pool_id = meta.queue as u32 & (ATH11K_HW_MAX_QUEUES - 1);
        let mut ring_selector = meta.ring_selector;
        let mut ring_map = 0u32;
        loop {
            // A retry sees the frame as the previous attempt left it
            // (Linux re-reads `skb->data`).
            let fc = if meta.encap == TxEncap::NativeWifi {
                u16::from_le_bytes([data[0], data[1]])
            } else {
                fc
            };
            let ring = (ring_selector % num_tx_rings) as usize;
            let rbm_id = self.cfg.hal_params.tcl2wbm_rbm_map[ring].rbm_id;
            ring_map |= 1 << ring;

            // idr_alloc(.., 0, DP_TX_IDR_SIZE - 1) — the buffer is the
            // bounce copy made below; reserve the id with a placeholder
            // first so a full IDR fails before any allocation, like
            // Linux.
            if self.tx_ring[ring].txbuf.len() >= (DP_TX_IDR_SIZE - 1) as usize {
                if ring_map == (1 << num_tx_rings) - 1 || !self.cfg.tcl_ring_retry {
                    self.stats.tx_misc_fail += 1;
                    return Err(dp_err(step::TX_IDR_FULL, ring as u32, errno::ENOSPC));
                }
                ring_selector = ring_selector.wrapping_add(1);
                continue;
            }

            let mut ti = HalTxInfo {
                ring_id: ring as u8,
                rbm_id,
                encap_type: match meta.encap {
                    TxEncap::Ethernet => encap::ETHERNET,
                    TxEncap::NativeWifi => encap::NATIVE_WIFI,
                },
                meta_data_flags: vif.tcl_metadata,
                addr_search_flags: vif.hal_addr_search_flags,
                search_type: vif.search_type,
                desc_type: 0, // HAL_TCL_DESC_TYPE_BUFFER
                pkt_offset: 0,
                lmac_id: meta.lmac_id,
                bss_ast_hash: vif.ast_hash,
                bss_ast_idx: vif.ast_idx,
                dscp_tid_tbl_idx: 0,
                ..HalTxInfo::default()
            };
            if meta.csum_partial {
                ti.flags0 |= HAL_TCL_DATA_CMD_INFO1_IP4_CKSUM_EN
                    | HAL_TCL_DATA_CMD_INFO1_UDP4_CKSUM_EN
                    | HAL_TCL_DATA_CMD_INFO1_UDP6_CKSUM_EN
                    | HAL_TCL_DATA_CMD_INFO1_TCP4_CKSUM_EN
                    | HAL_TCL_DATA_CMD_INFO1_TCP6_CKSUM_EN;
            }
            ti.flags1 |= field_prep(HAL_TCL_DATA_CMD_INFO2_TID_OVERWRITE, 1);
            // ath11k_dp_tx_get_tid
            ti.tid = match meta.encap {
                TxEncap::Ethernet => (meta.priority & IEEE80211_QOS_CTL_TID_MASK) as u8,
                TxEncap::NativeWifi if fc & IEEE80211_STYPE_QOS_DATA == 0 => {
                    HAL_DESC_REO_NON_QOS_TID
                }
                TxEncap::NativeWifi => (meta.priority & IEEE80211_QOS_CTL_TID_MASK) as u8,
            };
            if meta.encap == TxEncap::NativeWifi && fc & IEEE80211_STYPE_QOS_DATA != 0 {
                // ath11k_dp_tx_encap_nwifi: drop QoS control, clear the
                // QoS subtype bit.
                let qos = ieee80211_hdrlen(fc)
                    - IEEE80211_QOS_CTL_LEN
                    - if fc & IEEE80211_FCTL_ORDER != 0 { 4 } else { 0 };
                data.drain(qos..qos + IEEE80211_QOS_CTL_LEN);
                let nfc = fc & !IEEE80211_STYPE_QOS_DATA;
                data[..2].copy_from_slice(&nfc.to_le_bytes());
            }
            if data.len() as u32 > HAL_TCL_DATA_CMD_INFO1_DATA_LEN {
                return Err(dp_err(step::TX_FRAME_LEN, data.len() as u32, errno::EINVAL));
            }

            // dma_map_single → a DMA32 bounce copy.
            let mut mem = match DmaMem::alloc(data.len().max(4), 4) {
                Ok(m) => m,
                Err(_) => {
                    self.stats.tx_misc_fail += 1;
                    return Err(dp_err(step::TX_DMA, data.len() as u32, errno::ENOMEM));
                }
            };
            mem.write_bytes(0, &data);
            let paddr = mem.paddr();
            let msdu_id = match self.tx_ring[ring].txbuf.alloc(
                TxBuf {
                    mem,
                    paddr,
                    len: data.len() as u32,
                    mac_id: meta.pdev_idx,
                },
                0,
                DP_TX_IDR_SIZE - 1,
            ) {
                Ok(id) => id,
                Err(_) => {
                    self.stats.tx_misc_fail += 1;
                    return Err(dp_err(step::TX_IDR_FULL, ring as u32, errno::ENOSPC));
                }
            };
            ti.desc_id = field_prep(DP_TX_DESC_ID_MAC_ID, meta.pdev_idx as u32)
                | field_prep(DP_TX_DESC_ID_MSDU_ID, msdu_id)
                | field_prep(DP_TX_DESC_ID_POOL_ID, pool_id);
            ti.paddr = paddr;
            ti.data_len = data.len() as u32;

            let tcl = self.tx_ring[ring].tcl_data_ring.ring_id;
            hal.access_begin(tcl);
            let Some(off) = hal.src_get_next_entry(tcl) else {
                hal.access_end(io, tcl);
                self.stats.tx_desc_na[ring] += 1;
                self.tx_ring[ring].txbuf.remove(msdu_id);
                if ring_map != (1 << num_tx_rings) - 1
                    && self.cfg.tcl_ring_retry
                    && num_tx_rings > 1
                {
                    ring_selector = ring_selector.wrapping_add(1);
                    continue;
                }
                return Err(dp_err(step::TX_RING_FULL, ring as u32, errno::ENOMEM));
            };
            hal.desc_wr(tcl, off + 1, &hal_tx_cmd_desc(&ti));
            hal.access_end(io, tcl);
            // ath11k_dp_shadow_start_timer
            self.tx_ring_timer[ring].start(now_ms);
            if let Some(p) = self.pdev.as_mut() {
                p.num_tx_pending += 1;
            }
            return Ok(ti.desc_id);
        }
    }

    /// Linux `ath11k_dp_tx_completion_handler` for TX ring `ring`.
    pub fn tx_completion_handler(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        ring: usize,
    ) -> Vec<TxCompletion> {
        let mut out = Vec::new();
        let Some(tx) = self.tx_ring.get_mut(ring) else {
            return out;
        };
        let id = tx.tcl_comp_ring.ring_id;
        hal.access_begin(id);
        while tx.compl_next(tx.tx_status_head) != tx.tx_status_tail {
            let Some(off) = hal.dst_get_next_entry(id) else {
                break;
            };
            let head = tx.tx_status_head as usize;
            tx.tx_status[head] = rd_desc::<8>(hal, id, off);
            tx.tx_status_head = tx.compl_next(tx.tx_status_head);
        }
        if hal.dst_peek(id).is_some() && tx.compl_next(tx.tx_status_head) == tx.tx_status_tail {
            self.stats.tx_status_fifo_full += 1;
        }
        hal.access_end(io, id);

        let tx = &mut self.tx_ring[ring];
        while tx.compl_next(tx.tx_status_tail) != tx.tx_status_head {
            tx.tx_status_tail = tx.compl_next(tx.tx_status_tail);
            let d = tx.tx_status[tx.tx_status_tail as usize];
            let desc_id = field_get(BUFFER_ADDR_INFO1_SW_COOKIE, d[1]);
            let mac_id = field_get(DP_TX_DESC_ID_MAC_ID, desc_id) as u8;
            let msdu_id = field_get(DP_TX_DESC_ID_MSDU_ID, desc_id);
            let info0 = d[2];
            let src = field_get(HAL_WBM_RELEASE_INFO0_REL_SRC_MODULE, info0);

            if src == rel_src::FW {
                // ath11k_dp_tx_process_htt_tx_complete: htt_tx_wbm_completion
                // starts at byte 8 (info0 / info1 / info2 of the release ring).
                let st = field_get(HTT_TX_WBM_COMP_INFO0_STATUS, info0);
                match st {
                    htt_comp::OK | htt_comp::DROP | htt_comp::TTL => {
                        let peer_id = if d[4] & HTT_TX_WBM_COMP_INFO2_VALID != 0 {
                            field_get(HTT_TX_WBM_COMP_INFO2_SW_PEER_ID, d[4]) as u16
                        } else {
                            HTT_INVALID_PEER_ID
                        };
                        match tx.txbuf.remove(msdu_id) {
                            Some(b) => {
                                out.push(TxCompletion {
                                    ring: ring as u8,
                                    msdu_id,
                                    mac_id,
                                    buf_rel_source: src,
                                    status: st,
                                    acked: st == htt_comp::OK,
                                    ack_rssi: field_get(HTT_TX_WBM_COMP_INFO1_ACK_RSSI, d[3]) as u8,
                                    ppdu_id: 0,
                                    try_cnt: 0,
                                    tid: 0,
                                    peer_id,
                                    flags: 0,
                                    rate_stats: 0,
                                    len: b.len,
                                });
                                self.stats.tx_completed += 1;
                                if let Some(p) = self.pdev.as_mut() {
                                    p.num_tx_pending = p.num_tx_pending.saturating_sub(1);
                                }
                            }
                            None => self.stats.tx_unknown_msdu += 1,
                        }
                    }
                    htt_comp::REINJ | htt_comp::INSPECT => {
                        // ath11k_dp_tx_free_txbuf
                        match tx.txbuf.remove(msdu_id) {
                            Some(_) => {
                                if let Some(p) = self.pdev.as_mut() {
                                    p.num_tx_pending = p.num_tx_pending.saturating_sub(1);
                                }
                            }
                            None => self.stats.tx_unknown_msdu += 1,
                        }
                    }
                    htt_comp::MEC_NOTIFY => {}
                    _ => self.stats.tx_htt_unknown_status += 1,
                }
                continue;
            }

            let Some(b) = tx.txbuf.remove(msdu_id) else {
                self.stats.tx_unknown_msdu += 1;
                continue;
            };
            if let Some(p) = self.pdev.as_mut() {
                p.num_tx_pending = p.num_tx_pending.saturating_sub(1);
            }
            // ath11k_dp_tx_status_parse (TQM / other)
            let mut c = TxCompletion {
                ring: ring as u8,
                msdu_id,
                mac_id,
                buf_rel_source: src,
                status: 0,
                acked: false,
                ack_rssi: 0,
                ppdu_id: 0,
                try_cnt: 0,
                tid: 0,
                peer_id: 0,
                flags: 0,
                rate_stats: 0,
                len: b.len,
            };
            if src == rel_src::TQM {
                c.status = field_get(HAL_WBM_RELEASE_INFO0_TQM_RELEASE_REASON, info0);
                c.ppdu_id = field_get(HAL_WBM_RELEASE_INFO1_TQM_STATUS_NUMBER, d[3]);
                c.try_cnt = field_get(HAL_WBM_RELEASE_INFO1_TRANSMIT_COUNT, d[3]) as u8;
                c.ack_rssi = field_get(HAL_WBM_RELEASE_INFO2_ACK_FRAME_RSSI, d[4]) as u8;
                if d[4] & HAL_WBM_RELEASE_INFO2_FIRST_MSDU != 0 {
                    c.flags |= HAL_TX_STATUS_FLAGS_FIRST_MSDU;
                }
                c.peer_id = field_get(HAL_WBM_RELEASE_INFO3_PEER_ID, d[7]) as u16;
                c.tid = field_get(HAL_WBM_RELEASE_INFO3_TID, d[7]) as u8;
                c.rate_stats = if d[5] & HAL_TX_RATE_STATS_INFO0_VALID != 0 {
                    d[5]
                } else {
                    0
                };
                // ath11k_dp_tx_complete_msdu: ACK iff FRAME_ACKED
                // (frames are not sent IEEE80211_TX_CTL_NO_ACK here).
                c.acked = c.status == tqm::FRAME_ACKED;
            }
            // Linux WARNs on (and does not report) a non-TQM source here.
            self.stats.tx_completed += 1;
            out.push(c);
        }
        out
    }

    // ── RX ───────────────────────────────────────────────────────

    /// Linux `ath11k_dp_process_rx` on REO destination ring `ring`
    /// (0..3): reap up to `budget` MSDUs, decode and decap them,
    /// replenish the refill ring.
    pub fn process_rx(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        ring: usize,
        budget: u32,
    ) -> (u32, Vec<RxMsdu>) {
        let mut out = Vec::new();
        let Some(r) = self.reo_dst_ring.get(ring).copied() else {
            return (0, out);
        };
        let id = r.ring_id;
        let mut list: VecDeque<RxSkb> = VecDeque::new();
        let mut num_buffs_reaped = 0u32;
        let mut total_msdu_reaped = 0u32;
        let mut done = false;

        loop {
            hal.access_begin(id);
            while let Some(off) = hal.dst_get_next_entry(id) {
                let d: [u32; 16] = rd_desc(hal, id, off);
                let cookie = field_get(BUFFER_ADDR_INFO1_SW_COOKIE, d[1]);
                let buf_id = field_get(DP_RXDMA_BUF_COOKIE_BUF_ID, cookie);
                let mac_id = field_get(DP_RXDMA_BUF_COOKIE_PDEV_ID, cookie) as u8;
                if buf_id == 0 {
                    continue;
                }
                let Some((data, is_frag)) = self.take_rx_buf_frag(buf_id) else {
                    self.stats.rx_invalid_cookie += 1;
                    continue;
                };
                num_buffs_reaped += 1;
                let push = field_get(HAL_REO_DEST_RING_INFO0_PUSH_REASON, d[7]);
                if push != reo::PUSH_REASON_ROUTING_INSTRUCTION {
                    self.stats.hal_reo_error[ring] += 1;
                    continue;
                }
                let mut skb = RxSkb::new(data, mac_id);
                skb.is_frag = is_frag;
                let msdu_info = d[4];
                skb.is_first_msdu = msdu_info & RX_MSDU_DESC_INFO0_FIRST_MSDU_IN_MPDU != 0;
                skb.is_last_msdu = msdu_info & RX_MSDU_DESC_INFO0_LAST_MSDU_IN_MPDU != 0;
                skb.is_continuation = msdu_info & RX_MSDU_DESC_INFO0_MSDU_CONTINUATION != 0;
                skb.peer_id = field_get(RX_MPDU_DESC_META_DATA_PEER_ID, d[3]) as u16;
                skb.seq_no = field_get(RX_MPDU_DESC_INFO0_SEQ_NUM, d[2]) as u16;
                skb.tid = field_get(HAL_REO_DEST_RING_INFO0_RX_QUEUE_NUM, d[7]) as u8;
                let cont = skb.is_continuation;
                list.push_back(skb);
                if cont {
                    done = false;
                } else {
                    total_msdu_reaped += 1;
                    done = true;
                }
                if total_msdu_reaped >= budget {
                    break;
                }
            }
            // The hardware may have moved HP after we cached it: retry so
            // a partially reaped MPDU completes in this pass.
            if !done && hal.dst_num_free(id, true) != 0 {
                hal.access_end(io, id);
                continue;
            }
            hal.access_end(io, id);
            break;
        }

        if total_msdu_reaped == 0 {
            return (0, out);
        }
        if num_buffs_reaped != 0 {
            // ath11k_dp_rx_process_received_packets
            while let Some(msdu) = list.pop_front() {
                match self.process_msdu(msdu, &mut list) {
                    Ok(Some(m)) => {
                        self.stats.rx_delivered += 1;
                        out.push(m);
                    }
                    Ok(None) => {}
                    Err(e) => self.count_drop(e),
                }
            }
            self.replenish_refill(hal, io, num_buffs_reaped);
        }
        (total_msdu_reaped, out)
    }

    fn count_drop(&mut self, e: RxDrop) {
        let s = &mut self.stats;
        match e {
            RxDrop::NoLastBuf => s.rx_no_last_buf += 1,
            RxDrop::MsduLenErr => s.rx_msdu_len_err += 1,
            RxDrop::MsduNotDone => s.rx_msdu_not_done += 1,
            RxDrop::InvalidLen => s.rx_invalid_len += 1,
            RxDrop::Coalesce => s.rx_coalesce_err += 1,
            RxDrop::DecapUnsupported => s.rx_decap_unsupported += 1,
            RxDrop::Fcs => s.rx_fcs_err += 1,
            RxDrop::Mic => s.rx_mic_err += 1,
            RxDrop::Decrypt => s.rx_decrypt_err += 1,
        }
    }

    /// Linux `ath11k_dp_rx_process_msdu` (+ `ath11k_dp_rx_msdu_coalesce`,
    /// `ath11k_dp_rx_h_ppdu`, `ath11k_dp_rx_h_mpdu`).
    fn process_msdu(
        &mut self,
        mut first: RxSkb,
        list: &mut VecDeque<RxSkb>,
    ) -> Result<Option<RxMsdu>, RxDrop> {
        let desc_sz = self.cfg.hal_desc_sz;
        let bufsz = DP_RX_BUFFER_SIZE as usize;

        // ath11k_dp_rx_get_msdu_last_buf
        let last_idx: Option<usize> = if !first.is_continuation {
            None
        } else {
            match list.iter().position(|s| !s.is_continuation) {
                Some(i) => Some(i),
                None => return Err(RxDrop::NoLastBuf),
            }
        };

        let mut rxd = rx_desc(&first.data);
        if attn_mpdu_err(&rxd) & DP_RX_MPDU_ERR_MSDU_LEN != 0 {
            return Err(RxDrop::MsduLenErr);
        }
        let lrxd = match last_idx {
            None => rxd,
            Some(i) => rx_desc(&list[i].data),
        };
        if !lrxd.msdu_done() {
            return Err(RxDrop::MsduNotDone);
        }
        let msdu_len = rxd.msdu_len() as usize;
        let l3pad = lrxd.l3_pad_bytes() as usize;

        let payload: Vec<u8> = if first.is_frag {
            // skb_pull(msdu, hal_rx_desc_sz): the whole reassembled MPDU.
            first.data[desc_sz..].to_vec()
        } else if !first.is_continuation {
            if msdu_len + desc_sz > bufsz {
                return Err(RxDrop::InvalidLen);
            }
            // NARF-stricter: the pad must fit the buffer too (Linux reads
            // into the skb tailroom).
            if desc_sz + l3pad + msdu_len > bufsz {
                return Err(RxDrop::InvalidLen);
            }
            first.data[desc_sz + l3pad..desc_sz + l3pad + msdu_len].to_vec()
        } else {
            // ath11k_dp_rx_msdu_coalesce
            let hdr_len = desc_sz + l3pad;
            let first_len = bufsz - hdr_len;
            if msdu_len <= first_len {
                // WARN_ON_ONCE: the "continuation" fits in one buffer.
                first.data[hdr_len..hdr_len + msdu_len].to_vec()
            } else {
                first.is_first_msdu = lrxd.first_msdu();
                first.is_last_msdu = lrxd.last_msdu();
                // ath11k_dp_rx_desc_end_tlv_copy (wcn6855: msdu_end,
                // attention, mpdu_end from the last buffer)
                rxd.msdu_end = lrxd.msdu_end;
                rxd.attention = lrxd.attention;
                rxd.mpdu_end = lrxd.mpdu_end;
                let mut v = first.data[hdr_len..bufsz].to_vec();
                let mut rem = (msdu_len - first_len) as isize;
                while let Some(skb) = list.pop_front() {
                    if rem <= 0 {
                        break;
                    }
                    let buf_len = if skb.is_continuation {
                        bufsz - desc_sz
                    } else {
                        rem as usize
                    };
                    if buf_len > bufsz - desc_sz {
                        return Err(RxDrop::Coalesce);
                    }
                    v.extend_from_slice(&skb.data[desc_sz..desc_sz + buf_len]);
                    rem -= buf_len as isize;
                    if !skb.is_continuation {
                        break;
                    }
                }
                v
            }
        };

        self.h_mpdu(first, &rxd, payload, false)
    }

    /// Linux `ath11k_dp_rx_h_mpdu` + `ath11k_dp_rx_h_undecap` (to
    /// Ethernet II) + the drops mac80211 applies (FCS, MIC, decrypt
    /// failure).
    fn h_mpdu(
        &mut self,
        skb: RxSkb,
        rxd: &HalRxDescWcn6855,
        payload: Vec<u8>,
        from_err_path: bool,
    ) -> Result<Option<RxMsdu>, RxDrop> {
        let mut peer_id = skb.peer_id;
        let mut seq_no = skb.seq_no;
        let is_mcbc =
            rxd.first_msdu() && (rxd.attention.info1 & RX_ATTENTION_INFO1_MCAST_BCAST != 0);
        if is_mcbc {
            peer_id = rxd.mpdu_peer_id();
            seq_no = rxd.mpdu_start_seq_no();
        }

        // ath11k_dp_rx_h_find_peer
        let mut peer = if peer_id != 0 {
            self.peer_by_id(peer_id).copied()
        } else {
            None
        };
        if peer.is_none() {
            let v = rxd.mpdu_start.info1;
            if v & RX_MPDU_START_INFO1_MAC_ADDR2_VALID != 0 {
                let a2 = rxd.mpdu_start.addr2;
                peer = self.peers.iter().find(|p| p.addr == a2).copied();
            }
        }
        let enctype = match peer {
            Some(p) => {
                if is_mcbc {
                    p.sec_type_grp
                } else {
                    p.sec_type
                }
            }
            None => {
                if rxd.encrypt_valid() {
                    rxd.encrypt_type()
                } else {
                    enc::OPEN
                }
            }
        };
        let err_bitmap = attn_mpdu_err(rxd);
        let decrypted = enctype != enc::OPEN
            && err_bitmap == 0
            && field_get(RX_ATTENTION_INFO2_DCRYPT_STATUS_CODE, rxd.attention.info2)
                == RX_DESC_DECRYPT_STATUS_CODE_OK;

        // mac80211 drops these (RX_FLAG_FAILED_FCS_CRC / MMIC_ERROR) or
        // never decrypts them.
        if err_bitmap & DP_RX_MPDU_ERR_FCS != 0 {
            return Err(RxDrop::Fcs);
        }
        if err_bitmap & DP_RX_MPDU_ERR_TKIP_MIC != 0 {
            return Err(RxDrop::Mic);
        }
        if err_bitmap & DP_RX_MPDU_ERR_DECRYPT != 0 {
            return Err(RxDrop::Decrypt);
        }

        // ath11k_dp_rx_h_csum_offload
        let csum_ok = rxd.attention.info1
            & (RX_ATTENTION_INFO1_IP_CKSUM_FAIL | RX_ATTENTION_INFO1_TCP_UDP_CKSUM_FAIL)
            == 0;

        let decap_ty = rxd.decap_type();
        let frame = match decap_ty {
            // ath11k_dp_rx_h_undecap_raw (a single-MSDU MPDU only), then
            // mac80211's 802.11 → 802.3.
            decap::RAW if skb.is_first_msdu && skb.is_last_msdu => {
                super::dp_frag::undecap_raw(&payload, enctype, decrypted, is_mcbc)
                    .and_then(|f| nwifi_to_eth(&f))
            }
            decap::NATIVE_WIFI => nwifi_to_eth(&payload),
            decap::ETHERNET2_DIX => (payload.len() >= ETH_HLEN).then(|| payload.clone()),
            decap::IEEE8023 => ieee8023_to_eth(&payload),
            _ => None,
        };
        let Some(frame) = frame else {
            return Err(RxDrop::DecapUnsupported);
        };
        let is_eapol =
            frame.len() >= ETH_HLEN && u16::from_be_bytes([frame[12], frame[13]]) == ETH_P_PAE;
        Ok(Some(RxMsdu {
            frame,
            mac_id: skb.mac_id,
            peer_id,
            tid: skb.tid,
            seq_no,
            is_first_msdu: skb.is_first_msdu,
            is_last_msdu: skb.is_last_msdu,
            is_mcbc,
            is_eapol,
            decrypted,
            err_bitmap,
            decap: decap_ty,
            csum_ok,
            freq: rxd.msdu_freq(),
            from_err_path,
        }))
    }

    // ── RX error paths ───────────────────────────────────────────

    /// The 128-byte `hal_rx_msdu_link` at `paddr` in bank `bank`:
    /// `ath11k_hal_rx_msdu_link_info_get` → (cookies, rbm).
    fn msdu_link_info(&self, bank: u32, paddr: u64) -> Option<(Vec<u32>, u8)> {
        let b = self.link_desc_banks.get(bank as usize)?;
        if paddr < b.paddr
            || paddr + HAL_LINK_DESC_SIZE as u64 > b.paddr + (b.size - b.align_bytes) as u64
        {
            return None;
        }
        // desc_hdr (1) + buf_addr_info (2) + info0 (1) + pn (4) = 8 words,
        // then six hal_rx_msdu_details of 4 words.
        let rbm = field_get(BUFFER_ADDR_INFO1_RET_BUF_MGR, b.rd(paddr, 9)?) as u8;
        let mut cookies = Vec::new();
        for i in 0..HAL_NUM_RX_MSDUS_PER_LINK_DESC {
            let w0 = b.rd(paddr, 8 + 4 * i)?;
            if field_get(BUFFER_ADDR_INFO0_ADDR, w0) == 0 {
                break;
            }
            cookies.push(field_get(
                BUFFER_ADDR_INFO1_SW_COOKIE,
                b.rd(paddr, 9 + 4 * i)?,
            ));
        }
        Some((cookies, rbm))
    }

    /// Linux `ath11k_dp_rx_link_desc_return`: hand the link descriptor
    /// named by the ring entry's `buf_addr_info` back to WBM
    /// (`ath11k_hal_rx_msdu_link_desc_set` — Linux ORs into the recycled
    /// entry's `info0`, reproduced here).
    pub fn link_desc_return(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        buf_addr_info: [u32; 2],
        action: u32,
    ) -> Result<(), TransportError> {
        let id = self.wbm_desc_rel_ring.ring_id;
        hal.access_begin(id);
        let r = match hal.src_get_next_entry(id) {
            Some(off) => {
                let info0 = hal.desc_rd(id, off, 2)
                    | field_prep(HAL_WBM_RELEASE_INFO0_REL_SRC_MODULE, rel_src::SW)
                    | field_prep(HAL_WBM_RELEASE_INFO0_BM_ACTION, action)
                    | field_prep(
                        HAL_WBM_RELEASE_INFO0_DESC_TYPE,
                        HAL_WBM_REL_DESC_TYPE_MSDU_LINK,
                    );
                hal.desc_wr(id, off, &[buf_addr_info[0], buf_addr_info[1], info0]);
                Ok(())
            }
            None => {
                self.stats.link_desc_return_fail += 1;
                Err(dp_err(step::LINK_DESC_RETURN, 0, errno::ENOBUFS))
            }
        };
        hal.access_end(io, id);
        r
    }

    /// Linux `ath11k_dp_process_rx_err` (REO exception ring): a
    /// single-MSDU fragment goes to the reassembly
    /// ([`Dp::rx_err_buf`] → [`Dp::frag_h_mpdu`]); everything else is
    /// dropped and its link descriptor returned. Linux quirk kept: `drop`
    /// is not reset per entry, so once a pass dropped an entry, the
    /// fragments after it are freed too (their link descriptors not
    /// returned).
    pub fn process_rx_err(&mut self, hal: &mut Hal, io: &impl ChipIo, budget: u32) -> u32 {
        let id = self.reo_except_ring.ring_id;
        let quota = budget;
        let mut budget = budget;
        let mut tot_n_bufs_reaped = 0u32;
        let mut drop = false;

        hal.access_begin(id);
        while budget > 0 {
            let Some(off) = hal.dst_get_next_entry(id) else {
                break;
            };
            self.stats.err_ring_pkts += 1;
            let d: [u32; 16] = rd_desc(hal, id, off);
            // ath11k_hal_desc_reo_parse_err
            let push = field_get(HAL_REO_DEST_RING_INFO0_PUSH_REASON, d[7]);
            let err_code = field_get(HAL_REO_DEST_RING_INFO0_ERROR_CODE, d[7]) as usize;
            if let Some(c) = self.stats.reo_error.get_mut(err_code) {
                *c += 1;
            }
            if (push != reo::PUSH_REASON_ERR_DETECTED
                && push != reo::PUSH_REASON_ROUTING_INSTRUCTION)
                || field_get(HAL_REO_DEST_RING_INFO0_BUFFER_TYPE, d[7])
                    != reo::BUFFER_TYPE_LINK_DESC
            {
                self.stats.reo_err_parse += 1;
                continue;
            }
            let (paddr, desc_bank, _) = buf_addr_get(d[0], d[1]);
            let Some((cookies, rbm_v)) = self.msdu_link_info(desc_bank, paddr) else {
                self.stats.link_desc_lookup_fail += 1;
                continue;
            };
            if rbm_v != rbm::WBM_IDLE_DESC_LIST && rbm_v != rbm::SW1_BM && rbm_v != rbm::SW3_BM {
                self.stats.invalid_rbm += 1;
                let _ = self.link_desc_return(hal, io, [d[0], d[1]], HAL_WBM_REL_BM_ACT_REL_MSDU);
                continue;
            }
            let is_frag = d[2] & RX_MPDU_DESC_INFO0_FRAG_FLAG != 0;
            // "Process only rx fragments with one msdu per link desc
            // below, and drop msdu's indicated due to error reasons."
            if !is_frag || cookies.len() > 1 {
                drop = true;
                let _ =
                    self.link_desc_return(hal, io, [d[0], d[1]], HAL_WBM_REL_BM_ACT_PUT_IN_IDLE);
            }
            for c in cookies {
                let buf_id = field_get(DP_RXDMA_BUF_COOKIE_BUF_ID, c);
                if self.rx_err_buf(hal, io, &d, buf_id, drop) {
                    tot_n_bufs_reaped += 1;
                }
            }
            if tot_n_bufs_reaped >= quota {
                tot_n_bufs_reaped = quota;
                break;
            }
            budget = quota - tot_n_bufs_reaped;
        }
        hal.access_end(io, id);

        if tot_n_bufs_reaped != 0 {
            self.replenish_refill(hal, io, tot_n_bufs_reaped);
        }
        tot_n_bufs_reaped
    }

    /// Linux `ath11k_dp_rx_process_wbm_err` (+ `ath11k_dp_rx_wbm_err`,
    /// `h_reo_err` / `h_null_q_desc`, `h_rxdma_err`). `DESC_ADDR_ZERO`
    /// (no REO queue for the TID) MSDUs are delivered; everything else
    /// is counted and dropped. TKIP MIC failures are dropped (Linux hands
    /// them to mac80211's countermeasures; NARF has none).
    pub fn rx_process_wbm_err(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        budget: u32,
    ) -> (u32, Vec<RxMsdu>) {
        let id = self.rx_rel_ring.ring_id;
        let mut budget = budget;
        let mut total = 0u32;
        let mut list: VecDeque<RxSkb> = VecDeque::new();
        hal.access_begin(id);
        while budget > 0 {
            let Some(off) = hal.dst_get_next_entry(id) else {
                break;
            };
            let d: [u32; 8] = rd_desc(hal, id, off);
            // ath11k_hal_wbm_desc_parse_err
            let info0 = d[2];
            let ty = field_get(HAL_WBM_RELEASE_INFO0_DESC_TYPE, info0);
            let src = field_get(HAL_WBM_RELEASE_INFO0_REL_SRC_MODULE, info0);
            let mgr = field_get(BUFFER_ADDR_INFO1_RET_BUF_MGR, d[1]) as u8;
            if ty != HAL_WBM_REL_DESC_TYPE_REL_MSDU
                || (src != rel_src::RXDMA && src != rel_src::REO)
            {
                self.stats.wbm_err_parse += 1;
                continue;
            }
            if mgr != rbm::SW1_BM && mgr != rbm::SW3_BM {
                self.stats.invalid_rbm += 1;
                self.stats.wbm_err_parse += 1;
                continue;
            }
            let cookie = field_get(BUFFER_ADDR_INFO1_SW_COOKIE, d[1]);
            let (push, code) = if src == rel_src::REO {
                (
                    field_get(HAL_WBM_RELEASE_INFO0_REO_PUSH_REASON, info0),
                    field_get(HAL_WBM_RELEASE_INFO0_REO_ERROR_CODE, info0),
                )
            } else {
                (
                    field_get(HAL_WBM_RELEASE_INFO0_RXDMA_PUSH_REASON, info0),
                    field_get(HAL_WBM_RELEASE_INFO0_RXDMA_ERROR_CODE, info0),
                )
            };
            let buf_id = field_get(DP_RXDMA_BUF_COOKIE_BUF_ID, cookie);
            let mac_id = field_get(DP_RXDMA_BUF_COOKIE_PDEV_ID, cookie) as u8;
            let Some(data) = self.take_rx_buf(buf_id) else {
                self.stats.rx_invalid_cookie += 1;
                continue;
            };
            total += 1;
            budget -= 1;
            if push != reo::PUSH_REASON_ERR_DETECTED {
                continue;
            }
            let mut skb = RxSkb::new(data, mac_id);
            skb.err_rel_src = src;
            skb.err_code = code;
            list.push_back(skb);
        }
        hal.access_end(io, id);

        let mut out = Vec::new();
        if total == 0 {
            return (0, out);
        }
        self.replenish_refill(hal, io, total);

        while let Some(skb) = list.pop_front() {
            let r = match skb.err_rel_src {
                rel_src::REO => {
                    if let Some(c) = self.stats.reo_error.get_mut(skb.err_code as usize) {
                        *c += 1;
                    }
                    if skb.err_code == reo::ERROR_CODE_DESC_ADDR_ZERO {
                        self.h_null_q_desc(skb, &mut list)
                    } else {
                        Ok(None)
                    }
                }
                rel_src::RXDMA => {
                    if let Some(c) = self.stats.rxdma_error.get_mut(skb.err_code as usize) {
                        *c += 1;
                    }
                    if skb.err_code == rxdma_ecode::TKIP_MIC_ERR {
                        Err(RxDrop::Mic)
                    } else {
                        Ok(None)
                    }
                }
                _ => Ok(None),
            };
            match r {
                Ok(Some(m)) => {
                    self.stats.rx_delivered += 1;
                    out.push(m);
                }
                Ok(None) => {}
                Err(e) => self.count_drop(e),
            }
        }
        (total, out)
    }

    /// Linux `ath11k_dp_rx_h_null_q_desc` (+ `null_q_desc_sg_drop`).
    fn h_null_q_desc(
        &mut self,
        mut skb: RxSkb,
        list: &mut VecDeque<RxSkb>,
    ) -> Result<Option<RxMsdu>, RxDrop> {
        let desc_sz = self.cfg.hal_desc_sz;
        let bufsz = DP_RX_BUFFER_SIZE as usize;
        let rxd = rx_desc(&skb.data);
        let msdu_len = rxd.msdu_len() as usize;
        if msdu_len + desc_sz > bufsz {
            // First buffer is dropped by the caller; drop the rest of the
            // scatter list.
            let rest = msdu_len - (bufsz - desc_sz);
            let mut n_buffs = rest.div_ceil(bufsz - desc_sz);
            list.retain(|s| {
                if n_buffs > 0
                    && s.err_rel_src == rel_src::REO
                    && s.err_code == reo::ERROR_CODE_DESC_ADDR_ZERO
                {
                    n_buffs -= 1;
                    false
                } else {
                    true
                }
            });
            return Err(RxDrop::InvalidLen);
        }
        if !rxd.msdu_done() {
            list.clear();
            return Err(RxDrop::MsduNotDone);
        }
        skb.is_first_msdu = rxd.first_msdu();
        skb.is_last_msdu = rxd.last_msdu();
        let l3pad = rxd.l3_pad_bytes() as usize;
        if desc_sz + l3pad + msdu_len > bufsz {
            return Err(RxDrop::InvalidLen);
        }
        let payload = skb.data[desc_sz + l3pad..desc_sz + l3pad + msdu_len].to_vec();
        skb.tid = rxd.mpdu_tid();
        skb.peer_id = 0;
        let r = self.h_mpdu(skb, &rxd, payload, true)?;
        Ok(r.map(|mut m| {
            m.tid = rxd.mpdu_tid();
            m
        }))
    }

    /// Linux `ath11k_dp_process_rxdma_err` for `mac_id`: count the error
    /// code, free the MSDUs of each link descriptor, return the link
    /// descriptor. Returns `budget - quota` as Linux does.
    pub fn process_rxdma_err(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        mac_id: u32,
        budget: u32,
    ) -> u32 {
        // ath11k_hw_mac_id_to_srng_id_qca6390 = mac_id
        let Some(ring) = self
            .pdev
            .as_ref()
            .and_then(|p| p.rxdma_err_dst_ring.get(mac_id as usize))
            .copied()
        else {
            return 0;
        };
        let id = ring.ring_id;
        let mut quota = budget as i64;
        let mut num_buf_freed = 0u32;
        let mut returns: Vec<[u32; 2]> = Vec::new();
        hal.access_begin(id);
        loop {
            let q = quota;
            quota -= 1;
            if q == 0 {
                break;
            }
            let Some(off) = hal.dst_get_next_entry(id) else {
                break;
            };
            let d: [u32; 8] = rd_desc(hal, id, off);
            let (paddr, desc_bank, _) = buf_addr_get(d[0], d[1]);
            let code = field_get(HAL_REO_ENTR_RING_INFO1_RXDMA_ERROR_CODE, d[6]) as usize;
            if let Some(c) = self.stats.rxdma_error.get_mut(code) {
                *c += 1;
            }
            match self.msdu_link_info(desc_bank, paddr) {
                Some((cookies, _rbm)) => {
                    for c in cookies {
                        let buf_id = field_get(DP_RXDMA_BUF_COOKIE_BUF_ID, c);
                        if self.take_rx_buf(buf_id).is_some() {
                            num_buf_freed += 1;
                        } else {
                            self.stats.rx_invalid_cookie += 1;
                        }
                    }
                }
                None => self.stats.link_desc_lookup_fail += 1,
            }
            returns.push([d[0], d[1]]);
        }
        hal.access_end(io, id);
        for b in returns {
            let _ = self.link_desc_return(hal, io, b, HAL_WBM_REL_BM_ACT_PUT_IN_IDLE);
        }
        if num_buf_freed != 0 {
            self.replenish_refill(hal, io, num_buf_freed);
        }
        (budget as i64 - quota) as u32
    }

    /// Linux `ath11k_dp_process_reo_status`: the uniform header of every
    /// status entry. Matching against the pending command list is
    /// `Dp::reo_status_handler` (`dp_peer`).
    pub fn process_reo_status(&mut self, hal: &mut Hal, io: &impl ChipIo) -> Vec<ReoStatus> {
        let id = self.reo_status_ring.ring_id;
        let mut out = Vec::new();
        hal.access_begin(id);
        while let Some(off) = hal.dst_get_next_entry(id) {
            let w0 = hal.desc_rd(id, off, 0);
            let tag = field_get(HAL_SRNG_TLV_HDR_TAG, w0);
            use status_tag as t;
            match tag {
                t::REO_GET_QUEUE_STATS_STATUS
                | t::REO_FLUSH_QUEUE_STATUS
                | t::REO_FLUSH_CACHE_STATUS
                | t::REO_UNBLOCK_CACHE_STATUS
                | t::REO_FLUSH_TIMEOUT_LIST_STATUS
                | t::REO_DESCRIPTOR_THRESHOLD_REACHED_STATUS
                | t::REO_UPDATE_RX_REO_QUEUE_STATUS => {
                    let info0 = hal.desc_rd(id, off, 1);
                    out.push(ReoStatus {
                        tag,
                        cmd_num: field_get(HAL_REO_STATUS_HDR_INFO0_STATUS_NUM, info0) as u16,
                        cmd_status: field_get(HAL_REO_STATUS_HDR_INFO0_EXEC_STATUS, info0) as u8,
                    });
                }
                _ => self.stats.reo_status_unknown += 1,
            }
        }
        hal.access_end(io, id);
        out
    }

    /// Linux `ath11k_dp_rx_reap_mon_status_ring` for RXDMA `mac_id`
    /// (non-full-monitor): recycle every status buffer the hardware has
    /// finished. NARF does not parse the PPDU status TLVs (Linux uses them
    /// for RSSI / rate statistics only). Returns buffers reaped.
    pub fn reap_mon_status(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        mac_id: u32,
        budget: &mut u32,
    ) -> u32 {
        let Some(mut pdev) = self.pdev.take() else {
            return 0;
        };
        let mgr = self.cfg.hal_params.rx_buf_rbm;
        let mut reaped = 0;
        if let Some(ring) = pdev.rx_mon_status_refill_ring.get_mut(mac_id as usize) {
            let id = ring.refill_buf_ring.ring_id;
            hal.access_begin(id);
            while *budget > 0 {
                *budget -= 1;
                let Some(off) = hal.src_peek(id) else {
                    break;
                };
                let (paddr, cookie, _) =
                    buf_addr_get(hal.desc_rd(id, off, 0), hal.desc_rd(id, off, 1));
                if paddr != 0 {
                    let buf_id = field_get(DP_RXDMA_BUF_COOKIE_BUF_ID, cookie);
                    match ring.bufs.find(buf_id) {
                        None => {
                            self.stats.rx_invalid_cookie += 1;
                        }
                        Some(b) => {
                            let tag = field_get(HAL_TLV_HDR_TAG, b.mem.rd32(0));
                            if tag != status_tag::RX_STATUS_BUFFER_DONE {
                                self.stats.mon_status_not_done += 1;
                                // ath11k_dp_rx_mon_buf_done on HP + 1
                                if !Self::mon_buf_done(hal, ring, id) {
                                    continue;
                                }
                            } else {
                                self.stats.mon_status_reaped += 1;
                            }
                            ring.bufs.remove(buf_id);
                        }
                    }
                }
                // move_next: a fresh buffer in the same slot.
                let mem =
                    DmaMem::alloc(DP_RX_BUFFER_SIZE as usize, DP_RX_BUFFER_ALIGN_SIZE as usize);
                let new = mem.ok().and_then(|mem| {
                    let p = mem.paddr();
                    ring.bufs
                        .alloc(
                            RxBuf {
                                mem,
                                paddr: p,
                                frag_len: None,
                            },
                            0,
                            ring.bufs_max,
                        )
                        .ok()
                        .map(|i| (i, p))
                });
                match new {
                    None => {
                        self.stats.rx_buf_alloc_fail += 1;
                        hal.desc_wr(id, off, &buf_addr_words(0, 0, mgr));
                        reaped += 1;
                        break;
                    }
                    Some((buf_id, p)) => {
                        let cookie = field_prep(DP_RXDMA_BUF_COOKIE_PDEV_ID, mac_id)
                            | field_prep(DP_RXDMA_BUF_COOKIE_BUF_ID, buf_id);
                        hal.desc_wr(id, off, &buf_addr_words(p, cookie, mgr));
                        hal.src_get_next_entry(id);
                        reaped += 1;
                    }
                }
            }
            hal.access_end(io, id);
        }
        self.pdev = Some(pdev);
        reaped
    }

    /// `ath11k_dp_rx_mon_buf_done`: the HP + 1 entry's buffer is DONE.
    fn mon_buf_done(hal: &Hal, ring: &RxdmaRing, id: u32) -> bool {
        let Some(off) = hal.src_next_peek(id) else {
            return false;
        };
        let (_, cookie, _) = buf_addr_get(hal.desc_rd(id, off, 0), hal.desc_rd(id, off, 1));
        let buf_id = field_get(DP_RXDMA_BUF_COOKIE_BUF_ID, cookie);
        match ring.bufs.find(buf_id) {
            Some(b) => {
                field_get(HAL_TLV_HDR_TAG, b.mem.rd32(0)) == status_tag::RX_STATUS_BUFFER_DONE
            }
            None => false,
        }
    }

    /// Linux `ath11k_dp_service_srng` for ext-IRQ group `grp_id`.
    pub fn service_srng(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        grp_id: usize,
        budget: u32,
    ) -> DpServiceOutput {
        let mut o = DpServiceOutput::default();
        let mask = *self.cfg.hw.ring_mask;
        if grp_id >= mask.tx.len() {
            return o;
        }
        let mut budget = budget as i64;
        for i in 0..self.cfg.num_tx_rings() {
            let wbm = self.cfg.hal_params.tcl2wbm_rbm_map[i].wbm_ring_num;
            if (1u8 << wbm) & mask.tx[grp_id] != 0 {
                let c = self.tx_completion_handler(hal, io, i);
                o.tx_done.extend(c);
            }
        }
        macro_rules! account {
            ($n:expr) => {{
                let n = $n;
                budget -= n as i64;
                o.work_done += n;
                if budget <= 0 {
                    return o;
                }
            }};
        }
        if mask.rx_err[grp_id] != 0 {
            account!(self.process_rx_err(hal, io, budget as u32));
        }
        if mask.rx_wbm_rel[grp_id] != 0 {
            let (n, rx) = self.rx_process_wbm_err(hal, io, budget as u32);
            o.rx.extend(rx);
            account!(n);
        }
        if mask.rx[grp_id] != 0 {
            let ring = 7 - mask.rx[grp_id].leading_zeros() as usize; // fls - 1
            let (n, rx) = self.process_rx(hal, io, ring, budget as u32);
            o.rx.extend(rx);
            account!(n);
        }
        if mask.rx_mon_status[grp_id] != 0 {
            for j in 0..self.cfg.num_rxdma_per_pdev {
                if mask.rx_mon_status[grp_id] & (1 << j) != 0 {
                    let mut b = budget as u32;
                    let n = self.reap_mon_status(hal, io, j, &mut b);
                    account!(n);
                }
            }
        }
        if mask.reo_status[grp_id] != 0 {
            o.reo_status = self.process_reo_status(hal, io);
        }
        for j in 0..self.cfg.num_rxdma_per_pdev {
            if mask.rxdma2host[grp_id] & (1 << j) != 0 {
                let n = self.process_rxdma_err(hal, io, j, budget as u32);
                budget -= n as i64;
                o.work_done += n;
            }
            if budget <= 0 {
                return o;
            }
            if mask.host2rxdma[grp_id] & (1 << j) != 0 {
                self.replenish_refill(hal, io, 0);
            }
        }
        o
    }

    /// `ath11k_dp_shadow_timer_handler` for every DP shadow timer that is
    /// due: re-publish the ring HP when no TX happened in the interval.
    pub fn service_shadow_timers(&mut self, hal: &mut Hal, io: &impl ChipIo, now_ms: u64) {
        for t in self.tx_ring_timer.iter_mut() {
            if t.expire(now_ms) {
                hal.shadow_update_hp_tp(io, t.ring_id);
            }
        }
        if self.reo_cmd_timer.expire(now_ms) {
            hal.shadow_update_hp_tp(io, self.reo_cmd_timer.ring_id);
        }
    }
}

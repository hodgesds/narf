//! Per-peer RX reorder (REO) queues and the REO command ring.
//!
//! A port of the peer data-path parts of Linux
//! `drivers/net/wireless/ath/ath11k/`:
//!
//! | NARF | Linux |
//! |---|---|
//! | [`Dp::peer_setup_begin`] / [`Dp::peer_setup_next`] / [`Dp::peer_setup_wmi_failed`] | `ath11k_dp_peer_setup` (dp.c) |
//! | [`Dp::peer_cleanup`] | `ath11k_dp_peer_cleanup` (dp.c) → `ath11k_peer_rx_tid_cleanup` |
//! | [`Dp::peer_cleanup_all`] | the DP part of `ath11k_mac_peer_cleanup_all` |
//! | [`Dp::rx_tid_setup`] / [`Dp::rx_tid_wmi_failed`] | `ath11k_peer_rx_tid_setup` / `ath11k_dp_rx_tid_mem_free` |
//! | `Dp::rx_tid_delete` (private; via cleanup) | `ath11k_peer_rx_tid_delete` |
//! | [`Dp::ampdu_start`] / [`Dp::ampdu_stop`] | `ath11k_dp_rx_ampdu_start` / `_stop` |
//! | [`Dp::send_reo_cmd`] | `ath11k_dp_tx_send_reo_cmd` + `ath11k_hal_reo_cmd_send` |
//! | [`Dp::reo_status_handler`] | the command-list half of `ath11k_dp_process_reo_status` |
//! | [`Dp::reo_cmd_list_cleanup`] | `ath11k_dp_reo_cmd_list_cleanup` |
//! | [`hal_reo_qdesc_size`] / [`hal_reo_qdesc_setup`] | `ath11k_hal_reo_qdesc_size` / `_setup` (hal_rx.c) |
//! | [`hal_reo_cmd_desc`] | `ath11k_hal_reo_cmd_{queue_stats,flush_cache,update_rx_queue}` |
//!
//! WMI commands are *returned*, never sent: the WMI endpoint belongs to
//! the core, and the HAL the REO ring lives in is owned by the CE, so
//! the mac layer interleaves `Dp` steps with `wmi_cmd_send` exactly in
//! Linux's order (see [`Dp::peer_setup_begin`]).
//!
//! Queue descriptors are DMA32 coherent [`DmaMem`]s (Linux:
//! `dma_alloc_noncoherent` + `dma_sync_single_for_device`).
//!
//! Deliberate deviations (all invisible to the device):
//! - Where Linux frees a queue descriptor after a REO command failed to
//!   *reach* the ring (ring full / shutdown) while the hardware may still
//!   reference it, NARF keeps the memory ([`DpPeerRx::stranded`]) instead.
//! - An unsupported / unknown REO command type, and FLUSH_CACHE with
//!   BLOCK_LATER and no free blocking slot, are rejected *before* a ring
//!   entry is taken; Linux takes the entry first and publishes a stale
//!   descriptor (no ath11k caller reaches either path).
//! - The FLUSH_CACHE / UNBLOCK_CACHE status side of the blocking-slot
//!   bookkeeping (`avail_blk_resource`) is not ported: no ath11k caller
//!   sets `HAL_REO_CMD_FLG_FLUSH_BLOCK_LATER`.
//! - NARF-stricter: a TID above `HAL_DESC_REO_NON_QOS_TID` is refused
//!   (Linux indexes `peer->rx_tid[]` out of bounds).
//!
//! Fragment reassembly lives in [`super::dp_frag`]; its per-TID state is
//! in [`RxTid`]. `ath11k_peer_rx_frag_setup` is its peer lookup and
//! `dp_setup_done`; [`TkipRxMicKey`] is the host-only receive direction
//! needed to verify a reassembled TKIP Michael MIC.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::dp::{HAL_TLV_HDR_LEN, HAL_TLV_HDR_TAG};
use super::dp_ring::{
    Dp, ReoStatus, EOPNOTSUPP, HAL_DESC_REO_NON_QOS_TID, HAL_LINK_DESC_ALIGN,
    HAL_REO_CMD_HDR_INFO0_CMD_NUMBER,
};
use super::hal::{dma_wmb, errno, field_get, field_prep, genmask, DmaMem, Hal, TransportError};
use super::power::ChipIo;
use super::wmi::{self, WmiCmd};

// ── diag steps (230–249) ──────────────────────────────────────────

pub mod step {
    /// `ath11k_peer_find` failed (`-ENOENT`); detail = vdev id.
    pub const PEER_NOT_FOUND: u32 = 230;
    /// REO queue descriptor allocation (`-ENOMEM`); detail = tid.
    pub const QDESC_ALLOC: u32 = 231;
    /// REO command ring full (`-ENOBUFS`); detail = command type.
    pub const REO_CMD_RING_FULL: u32 = 232;
    /// `ATH11K_FLAG_CRASH_FLUSH` (`-ESHUTDOWN`).
    pub const REO_CMD_SHUTDOWN: u32 = 233;
    /// FLUSH_QUEUE / UNBLOCK_CACHE / FLUSH_TIMEOUT_LIST (`-EOPNOTSUPP`).
    pub const REO_CMD_UNSUPPORTED: u32 = 234;
    /// Not a `hal_reo_cmd_type` (`-EINVAL`).
    pub const REO_CMD_UNKNOWN: u32 = 235;
    /// The ring entry carried command number 0 (`-EINVAL`).
    pub const REO_CMD_NUM_ZERO: u32 = 236;
    /// FLUSH_CACHE BLOCK_LATER with no free blocking slot (`-ENOSPC`).
    pub const REO_CMD_NO_BLOCK_RES: u32 = 237;
    /// NARF-stricter: tid > `HAL_DESC_REO_NON_QOS_TID` (`-EINVAL`).
    pub const BAD_TID: u32 = 238;
    /// A WMI command of the peer setup failed (reported by the caller
    /// through [`super::Dp::peer_setup_wmi_failed`]); detail = tid, or
    /// `0xff` for `WMI_PEER_SET_DEFAULT_ROUTING`.
    pub const WMI_SEND: u32 = 239;
}

/// `-ENOENT`.
pub const ENOENT: i32 = 2;

// ── constants (hal.h, hal_desc.h, hal_rx.h, dp.h) ─────────────────

/// `IEEE80211_NUM_TIDS`; `rx_tid[]` has `IEEE80211_NUM_TIDS + 1` entries
/// (the last is the non-QoS TID 16).
pub const IEEE80211_NUM_TIDS: usize = 16;
pub const NUM_RX_TIDS: usize = IEEE80211_NUM_TIDS + 1;
pub const DP_BA_WIN_SZ_MAX: u32 = 256;
pub const DP_REO_DESC_FREE_THRESHOLD: u32 = 64;
pub const DP_REO_DESC_FREE_TIMEOUT_MS: u64 = 1000;
/// `DP_RX_HASH_ENABLE` (dp.h).
pub const DP_RX_HASH_ENABLE: u32 = 1;
/// `HAL_MAX_AVAIL_BLK_RES`.
pub const HAL_MAX_AVAIL_BLK_RES: u8 = 3;

/// `sizeof(struct hal_rx_reo_queue)`.
pub const HAL_RX_REO_QUEUE_SIZE: u32 = 128;
/// `sizeof(struct hal_rx_reo_queue_ext)`.
pub const HAL_RX_REO_QUEUE_EXT_SIZE: u32 = 128;
/// Body of every REO command used here (`hal_reo_get_queue_stats`,
/// `hal_reo_flush_cache`, `hal_reo_update_rx_queue`: 9 words).
pub const HAL_REO_CMD_BODY_SIZE: u32 = 36;
/// TLV header + body.
pub const HAL_REO_CMD_WORDS: usize = 10;

/// `enum hal_reo_cmd_type`.
pub mod reo_cmd_type {
    pub const GET_QUEUE_STATS: u32 = 0;
    pub const FLUSH_QUEUE: u32 = 1;
    pub const FLUSH_CACHE: u32 = 2;
    pub const UNBLOCK_CACHE: u32 = 3;
    pub const FLUSH_TIMEOUT_LIST: u32 = 4;
    pub const UPDATE_RX_QUEUE: u32 = 5;
}

/// `enum hal_reo_cmd_status`.
pub mod reo_cmd_status {
    pub const SUCCESS: u8 = 0;
    pub const BLOCKED: u8 = 1;
    pub const FAILED: u8 = 2;
    pub const RESOURCE_BLOCKED: u8 = 3;
    pub const DRAIN: u8 = 0xff;
}

/// `enum hal_pn_type`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HalPnType {
    None = 0,
    Wpa = 1,
    WapiEven = 2,
    WapiUneven = 3,
}

/// TLV tags of the REO commands (`enum hal_tlv_tag`).
pub mod reo_tlv {
    pub const HAL_REO_GET_QUEUE_STATS: u32 = 0x132;
    pub const HAL_REO_FLUSH_CACHE: u32 = 0x134;
    pub const HAL_REO_UPDATE_RX_REO_QUEUE: u32 = 0x1a3;
}

pub const HAL_REO_CMD_HDR_INFO0_STATUS_REQUIRED: u32 = 1 << 16;

pub const HAL_REO_CMD_FLG_NEED_STATUS: u32 = 1 << 0;
pub const HAL_REO_CMD_FLG_STATS_CLEAR: u32 = 1 << 1;
pub const HAL_REO_CMD_FLG_FLUSH_BLOCK_LATER: u32 = 1 << 2;
pub const HAL_REO_CMD_FLG_FLUSH_RELEASE_BLOCKING: u32 = 1 << 3;
pub const HAL_REO_CMD_FLG_FLUSH_NO_INVAL: u32 = 1 << 4;
pub const HAL_REO_CMD_FLG_FLUSH_FWD_ALL_MPDUS: u32 = 1 << 5;
pub const HAL_REO_CMD_FLG_FLUSH_ALL: u32 = 1 << 6;

pub const HAL_REO_CMD_UPD0_RX_QUEUE_NUM: u32 = 1 << 8;
pub const HAL_REO_CMD_UPD0_VLD: u32 = 1 << 9;
pub const HAL_REO_CMD_UPD0_ALDC: u32 = 1 << 10;
pub const HAL_REO_CMD_UPD0_DIS_DUP_DETECTION: u32 = 1 << 11;
pub const HAL_REO_CMD_UPD0_SOFT_REORDER_EN: u32 = 1 << 12;
pub const HAL_REO_CMD_UPD0_AC: u32 = 1 << 13;
pub const HAL_REO_CMD_UPD0_BAR: u32 = 1 << 14;
pub const HAL_REO_CMD_UPD0_RETRY: u32 = 1 << 15;
pub const HAL_REO_CMD_UPD0_CHECK_2K_MODE: u32 = 1 << 16;
pub const HAL_REO_CMD_UPD0_OOR_MODE: u32 = 1 << 17;
pub const HAL_REO_CMD_UPD0_BA_WINDOW_SIZE: u32 = 1 << 18;
pub const HAL_REO_CMD_UPD0_PN_CHECK: u32 = 1 << 19;
pub const HAL_REO_CMD_UPD0_EVEN_PN: u32 = 1 << 20;
pub const HAL_REO_CMD_UPD0_UNEVEN_PN: u32 = 1 << 21;
pub const HAL_REO_CMD_UPD0_PN_HANDLE_ENABLE: u32 = 1 << 22;
pub const HAL_REO_CMD_UPD0_PN_SIZE: u32 = 1 << 23;
pub const HAL_REO_CMD_UPD0_IGNORE_AMPDU_FLG: u32 = 1 << 24;
pub const HAL_REO_CMD_UPD0_SVLD: u32 = 1 << 25;
pub const HAL_REO_CMD_UPD0_SSN: u32 = 1 << 26;
pub const HAL_REO_CMD_UPD0_SEQ_2K_ERR: u32 = 1 << 27;
pub const HAL_REO_CMD_UPD0_PN_ERR: u32 = 1 << 28;
pub const HAL_REO_CMD_UPD0_PN_VALID: u32 = 1 << 29;
pub const HAL_REO_CMD_UPD0_PN: u32 = 1 << 30;

pub const HAL_REO_CMD_UPD1_VLD: u32 = 1 << 16;
pub const HAL_REO_CMD_UPD1_ALDC: u32 = genmask(18, 17);
pub const HAL_REO_CMD_UPD1_DIS_DUP_DETECTION: u32 = 1 << 19;
pub const HAL_REO_CMD_UPD1_SOFT_REORDER_EN: u32 = 1 << 20;
pub const HAL_REO_CMD_UPD1_AC: u32 = genmask(22, 21);
pub const HAL_REO_CMD_UPD1_BAR: u32 = 1 << 23;
pub const HAL_REO_CMD_UPD1_RETRY: u32 = 1 << 24;
pub const HAL_REO_CMD_UPD1_CHECK_2K_MODE: u32 = 1 << 25;
pub const HAL_REO_CMD_UPD1_OOR_MODE: u32 = 1 << 26;
pub const HAL_REO_CMD_UPD1_PN_CHECK: u32 = 1 << 27;
pub const HAL_REO_CMD_UPD1_EVEN_PN: u32 = 1 << 28;
pub const HAL_REO_CMD_UPD1_UNEVEN_PN: u32 = 1 << 29;
pub const HAL_REO_CMD_UPD1_PN_HANDLE_ENABLE: u32 = 1 << 30;
pub const HAL_REO_CMD_UPD1_IGNORE_AMPDU_FLG: u32 = 1 << 31;

pub const HAL_REO_CMD_UPD2_SVLD: u32 = 1 << 10;
pub const HAL_REO_CMD_UPD2_SSN: u32 = genmask(22, 11);
pub const HAL_REO_CMD_UPD2_SEQ_2K_ERR: u32 = 1 << 23;
pub const HAL_REO_CMD_UPD2_PN_ERR: u32 = 1 << 24;

pub const HAL_REO_GET_QUEUE_STATS_INFO0_QUEUE_ADDR_HI: u32 = genmask(7, 0);
pub const HAL_REO_GET_QUEUE_STATS_INFO0_CLEAR_STATS: u32 = 1 << 8;

pub const HAL_REO_FLUSH_CACHE_INFO0_CACHE_ADDR_HI: u32 = genmask(7, 0);
pub const HAL_REO_FLUSH_CACHE_INFO0_FWD_ALL_MPDUS: u32 = 1 << 8;
pub const HAL_REO_FLUSH_CACHE_INFO0_RELEASE_BLOCK_IDX: u32 = 1 << 9;
pub const HAL_REO_FLUSH_CACHE_INFO0_BLOCK_RESRC_IDX: u32 = genmask(11, 10);
pub const HAL_REO_FLUSH_CACHE_INFO0_FLUSH_WO_INVALIDATE: u32 = 1 << 12;
pub const HAL_REO_FLUSH_CACHE_INFO0_BLOCK_CACHE_USAGE: u32 = 1 << 13;
pub const HAL_REO_FLUSH_CACHE_INFO0_FLUSH_ALL: u32 = 1 << 14;

pub const HAL_REO_UPD_RX_QUEUE_INFO0_QUEUE_ADDR_HI: u32 = genmask(7, 0);
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_RX_QUEUE_NUM: u32 = 1 << 8;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_VLD: u32 = 1 << 9;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_ASSOC_LNK_DESC_CNT: u32 = 1 << 10;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_DIS_DUP_DETECTION: u32 = 1 << 11;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_SOFT_REORDER_EN: u32 = 1 << 12;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_AC: u32 = 1 << 13;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_BAR: u32 = 1 << 14;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_RETRY: u32 = 1 << 15;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_CHECK_2K_MODE: u32 = 1 << 16;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_OOR_MODE: u32 = 1 << 17;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_BA_WINDOW_SIZE: u32 = 1 << 18;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_PN_CHECK: u32 = 1 << 19;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_EVEN_PN: u32 = 1 << 20;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_UNEVEN_PN: u32 = 1 << 21;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_PN_HANDLE_ENABLE: u32 = 1 << 22;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_PN_SIZE: u32 = 1 << 23;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_IGNORE_AMPDU_FLG: u32 = 1 << 24;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_SVLD: u32 = 1 << 25;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_SSN: u32 = 1 << 26;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_SEQ_2K_ERR: u32 = 1 << 27;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_PN_ERR: u32 = 1 << 28;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_PN_VALID: u32 = 1 << 29;
pub const HAL_REO_UPD_RX_QUEUE_INFO0_UPD_PN: u32 = 1 << 30;

pub const HAL_REO_UPD_RX_QUEUE_INFO1_RX_QUEUE_NUMBER: u32 = genmask(15, 0);
pub const HAL_REO_UPD_RX_QUEUE_INFO1_VLD: u32 = 1 << 16;
pub const HAL_REO_UPD_RX_QUEUE_INFO1_ASSOC_LNK_DESC_COUNTER: u32 = genmask(18, 17);
pub const HAL_REO_UPD_RX_QUEUE_INFO1_DIS_DUP_DETECTION: u32 = 1 << 19;
pub const HAL_REO_UPD_RX_QUEUE_INFO1_SOFT_REORDER_EN: u32 = 1 << 20;
pub const HAL_REO_UPD_RX_QUEUE_INFO1_AC: u32 = genmask(22, 21);
pub const HAL_REO_UPD_RX_QUEUE_INFO1_BAR: u32 = 1 << 23;
pub const HAL_REO_UPD_RX_QUEUE_INFO1_RETRY: u32 = 1 << 24;
pub const HAL_REO_UPD_RX_QUEUE_INFO1_CHECK_2K_MODE: u32 = 1 << 25;
pub const HAL_REO_UPD_RX_QUEUE_INFO1_OOR_MODE: u32 = 1 << 26;
pub const HAL_REO_UPD_RX_QUEUE_INFO1_PN_CHECK: u32 = 1 << 27;
pub const HAL_REO_UPD_RX_QUEUE_INFO1_EVEN_PN: u32 = 1 << 28;
pub const HAL_REO_UPD_RX_QUEUE_INFO1_UNEVEN_PN: u32 = 1 << 29;
pub const HAL_REO_UPD_RX_QUEUE_INFO1_PN_HANDLE_ENABLE: u32 = 1 << 30;
pub const HAL_REO_UPD_RX_QUEUE_INFO1_IGNORE_AMPDU_FLG: u32 = 1 << 31;

pub const HAL_REO_UPD_RX_QUEUE_INFO2_BA_WINDOW_SIZE: u32 = genmask(7, 0);
pub const HAL_REO_UPD_RX_QUEUE_INFO2_PN_SIZE: u32 = genmask(9, 8);
pub const HAL_REO_UPD_RX_QUEUE_INFO2_SVLD: u32 = 1 << 10;
pub const HAL_REO_UPD_RX_QUEUE_INFO2_SSN: u32 = genmask(22, 11);
pub const HAL_REO_UPD_RX_QUEUE_INFO2_SEQ_2K_ERR: u32 = 1 << 23;
pub const HAL_REO_UPD_RX_QUEUE_INFO2_PN_ERR: u32 = 1 << 24;

/// `enum hal_rx_reo_queue_pn_size`.
pub const HAL_RX_REO_QUEUE_PN_SIZE_24: u8 = 0;
pub const HAL_RX_REO_QUEUE_PN_SIZE_48: u8 = 1;
pub const HAL_RX_REO_QUEUE_PN_SIZE_128: u8 = 2;

pub const HAL_DESC_REO_OWNED: u32 = 4;
pub const HAL_DESC_REO_QUEUE_DESC: u32 = 8;
pub const HAL_DESC_REO_QUEUE_EXT_DESC: u32 = 9;
pub const HAL_DESC_HDR_INFO0_OWNER: u32 = genmask(3, 0);
pub const HAL_DESC_HDR_INFO0_BUF_TYPE: u32 = genmask(7, 4);
pub const HAL_DESC_HDR_INFO0_DBG_RESERVED: u32 = genmask(31, 8);
pub const REO_QUEUE_DESC_MAGIC_DEBUG_PATTERN_0: u32 = 0xDD_BEEF;
pub const REO_QUEUE_DESC_MAGIC_DEBUG_PATTERN_1: u32 = 0xAD_BEEF;
pub const REO_QUEUE_DESC_MAGIC_DEBUG_PATTERN_2: u32 = 0xBD_BEEF;
pub const REO_QUEUE_DESC_MAGIC_DEBUG_PATTERN_3: u32 = 0xCD_BEEF;

pub const HAL_RX_REO_QUEUE_RX_QUEUE_NUMBER: u32 = genmask(15, 0);
pub const HAL_RX_REO_QUEUE_INFO0_VLD: u32 = 1 << 0;
pub const HAL_RX_REO_QUEUE_INFO0_ASSOC_LNK_DESC_COUNTER: u32 = genmask(2, 1);
pub const HAL_RX_REO_QUEUE_INFO0_AC: u32 = genmask(6, 5);
pub const HAL_RX_REO_QUEUE_INFO0_RETRY: u32 = 1 << 8;
pub const HAL_RX_REO_QUEUE_INFO0_BA_WINDOW_SIZE: u32 = genmask(18, 11);
pub const HAL_RX_REO_QUEUE_INFO0_PN_CHECK: u32 = 1 << 19;
pub const HAL_RX_REO_QUEUE_INFO0_PN_SIZE: u32 = genmask(24, 23);
pub const HAL_RX_REO_QUEUE_INFO0_IGNORE_AMPDU_FLG: u32 = 1 << 25;
pub const HAL_RX_REO_QUEUE_INFO1_SVLD: u32 = 1 << 0;
pub const HAL_RX_REO_QUEUE_INFO1_SSN: u32 = genmask(12, 1);

// ── queue descriptors (hal_rx.c) ──────────────────────────────────

/// `ath11k_tid_to_ac` (`enum wme_ac`: BE 0, BK 1, VI 2, VO 3).
pub const fn tid_to_ac(tid: u32) -> u32 {
    match tid {
        0 | 3 => 0,
        1 | 2 => 1,
        4 | 5 => 2,
        _ => 3,
    }
}

/// Linux `ath11k_hal_reo_qdesc_size` (bytes).
pub const fn hal_reo_qdesc_size(ba_window_size: u32, tid: u8) -> u32 {
    let num_ext_desc = if ba_window_size <= 1 {
        if tid != HAL_DESC_REO_NON_QOS_TID {
            1
        } else {
            0
        }
    } else if ba_window_size <= 105 {
        1
    } else if ba_window_size <= 210 {
        2
    } else {
        3
    };
    HAL_RX_REO_QUEUE_SIZE + num_ext_desc * HAL_RX_REO_QUEUE_EXT_SIZE
}

/// `ath11k_hal_reo_set_desc_hdr`.
const fn desc_hdr(owner: u32, buffer_type: u32, magic: u32) -> u32 {
    field_prep(HAL_DESC_HDR_INFO0_OWNER, owner)
        | field_prep(HAL_DESC_HDR_INFO0_BUF_TYPE, buffer_type)
        | field_prep(HAL_DESC_HDR_INFO0_DBG_RESERVED, magic)
}

/// Linux `ath11k_hal_reo_qdesc_setup` into the words of the descriptor
/// (`w.len()` ≥ 32, and ≥ 128 for a QoS TID: the three
/// `hal_rx_reo_queue_ext` written unconditionally). Words Linux does not
/// write are left as they are.
pub fn hal_reo_qdesc_setup(
    w: &mut [u32],
    tid: u8,
    ba_window_size: u32,
    start_seq: u32,
    ty: HalPnType,
) {
    // memset(qdesc, 0, sizeof(*qdesc))
    for v in w.iter_mut().take((HAL_RX_REO_QUEUE_SIZE / 4) as usize) {
        *v = 0;
    }
    w[0] = desc_hdr(
        HAL_DESC_REO_OWNED,
        HAL_DESC_REO_QUEUE_DESC,
        REO_QUEUE_DESC_MAGIC_DEBUG_PATTERN_0,
    );
    w[1] = field_prep(HAL_RX_REO_QUEUE_RX_QUEUE_NUMBER, tid as u32);
    let mut info0 = field_prep(HAL_RX_REO_QUEUE_INFO0_VLD, 1)
        | field_prep(HAL_RX_REO_QUEUE_INFO0_ASSOC_LNK_DESC_COUNTER, 1)
        | field_prep(HAL_RX_REO_QUEUE_INFO0_AC, tid_to_ac(tid as u32));

    let mut ba = ba_window_size.max(1);
    if ba == 1 && tid != HAL_DESC_REO_NON_QOS_TID {
        ba += 1;
    }
    if ba == 1 {
        info0 |= field_prep(HAL_RX_REO_QUEUE_INFO0_RETRY, 1);
    }
    info0 |= field_prep(HAL_RX_REO_QUEUE_INFO0_BA_WINDOW_SIZE, ba - 1);
    match ty {
        HalPnType::None | HalPnType::WapiEven | HalPnType::WapiUneven => {}
        HalPnType::Wpa => {
            info0 |= field_prep(HAL_RX_REO_QUEUE_INFO0_PN_CHECK, 1)
                | field_prep(
                    HAL_RX_REO_QUEUE_INFO0_PN_SIZE,
                    HAL_RX_REO_QUEUE_PN_SIZE_48 as u32,
                );
        }
    }
    info0 |= field_prep(HAL_RX_REO_QUEUE_INFO0_IGNORE_AMPDU_FLG, 1);
    w[2] = info0;

    let mut info1 = field_prep(HAL_RX_REO_QUEUE_INFO1_SVLD, 0);
    if start_seq <= 0xfff {
        info1 = field_prep(HAL_RX_REO_QUEUE_INFO1_SSN, start_seq);
    }
    w[3] = info1;

    if tid == HAL_DESC_REO_NON_QOS_TID {
        return;
    }
    let magic = [
        REO_QUEUE_DESC_MAGIC_DEBUG_PATTERN_1,
        REO_QUEUE_DESC_MAGIC_DEBUG_PATTERN_2,
        REO_QUEUE_DESC_MAGIC_DEBUG_PATTERN_3,
    ];
    let q = (HAL_RX_REO_QUEUE_SIZE / 4) as usize;
    let e = (HAL_RX_REO_QUEUE_EXT_SIZE / 4) as usize;
    for (i, m) in magic.iter().enumerate() {
        let base = q + i * e;
        for v in w[base..base + e].iter_mut() {
            *v = 0;
        }
        w[base] = desc_hdr(HAL_DESC_REO_OWNED, HAL_DESC_REO_QUEUE_EXT_DESC, *m);
    }
}

// ── REO commands (hal_rx.c) ───────────────────────────────────────

/// `struct ath11k_hal_reo_cmd`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalReoCmd {
    pub addr_lo: u32,
    pub flag: u32,
    pub upd0: u32,
    pub upd1: u32,
    pub upd2: u32,
    pub pn: [u32; 4],
    pub rx_queue_num: u16,
    pub min_rel: u16,
    pub min_fwd: u16,
    pub addr_hi: u8,
    pub ac_list: u8,
    pub blocking_idx: u8,
    pub ba_window_size: u16,
    pub pn_size: u8,
}

/// `hal->avail_blk_resource` / `current_blk_index` (zero from
/// `ath11k_hal_srng_init`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BlkRes {
    pub avail_blk_resource: u8,
    pub current_blk_index: u8,
}

/// `ffz` on the u8 promoted to `unsigned long`.
const fn ffz(x: u8) -> u8 {
    (!(x as u64)).trailing_zeros() as u8
}

/// `cmd->info0`: keep the pre-written command number (and every other
/// bit), clear then set STATUS_REQUIRED.
const fn cmd_hdr(prev_info0: u32, flag: u32) -> u32 {
    let mut v = prev_info0 & !HAL_REO_CMD_HDR_INFO0_STATUS_REQUIRED;
    if flag & HAL_REO_CMD_FLG_NEED_STATUS != 0 {
        v |= HAL_REO_CMD_HDR_INFO0_STATUS_REQUIRED;
    }
    v
}

const fn tlv(tag: u32) -> u32 {
    field_prep(HAL_TLV_HDR_TAG, tag) | field_prep(HAL_TLV_HDR_LEN, HAL_REO_CMD_BODY_SIZE)
}

const fn bit(cond: bool) -> u32 {
    cond as u32
}

/// Check the command can be encoded (NARF: before a ring entry is
/// taken). Returns the errno Linux returns.
pub fn hal_reo_cmd_check(ty: u32, cmd: &HalReoCmd, blk: &BlkRes) -> Result<(), (u32, i32)> {
    use reo_cmd_type as t;
    match ty {
        t::GET_QUEUE_STATS | t::UPDATE_RX_QUEUE => Ok(()),
        t::FLUSH_CACHE => {
            if cmd.flag & HAL_REO_CMD_FLG_FLUSH_BLOCK_LATER != 0
                && ffz(blk.avail_blk_resource) >= HAL_MAX_AVAIL_BLK_RES
            {
                Err((step::REO_CMD_NO_BLOCK_RES, errno::ENOSPC))
            } else {
                Ok(())
            }
        }
        t::FLUSH_QUEUE | t::UNBLOCK_CACHE | t::FLUSH_TIMEOUT_LIST => {
            Err((step::REO_CMD_UNSUPPORTED, EOPNOTSUPP))
        }
        _ => Err((step::REO_CMD_UNKNOWN, errno::EINVAL)),
    }
}

/// The ten words (TLV header + body) Linux leaves in the REO command
/// ring entry whose command header was `prev_info0`
/// (`ath11k_hal_reo_cmd_queue_stats` / `_flush_cache` /
/// `_update_rx_queue`). `cmd` is updated as Linux updates it (PN size,
/// BA window size); `blk` as `_flush_cache` updates it.
pub fn hal_reo_cmd_desc(
    ty: u32,
    cmd: &mut HalReoCmd,
    prev_info0: u32,
    blk: &mut BlkRes,
) -> Result<[u32; HAL_REO_CMD_WORDS], (u32, i32)> {
    hal_reo_cmd_check(ty, cmd, blk)?;
    let mut w = [0u32; HAL_REO_CMD_WORDS];
    w[1] = cmd_hdr(prev_info0, cmd.flag);
    w[2] = cmd.addr_lo;
    use reo_cmd_type as t;
    match ty {
        t::GET_QUEUE_STATS => {
            w[0] = tlv(reo_tlv::HAL_REO_GET_QUEUE_STATS);
            w[3] = field_prep(
                HAL_REO_GET_QUEUE_STATS_INFO0_QUEUE_ADDR_HI,
                cmd.addr_hi as u32,
            );
            if cmd.flag & HAL_REO_CMD_FLG_STATS_CLEAR != 0 {
                w[3] |= HAL_REO_GET_QUEUE_STATS_INFO0_CLEAR_STATS;
            }
        }
        t::FLUSH_CACHE => {
            let avail_slot = ffz(blk.avail_blk_resource);
            let block_later = cmd.flag & HAL_REO_CMD_FLG_FLUSH_BLOCK_LATER != 0;
            if block_later {
                blk.current_blk_index = avail_slot;
            }
            w[0] = tlv(reo_tlv::HAL_REO_FLUSH_CACHE);
            let mut info0 = field_prep(HAL_REO_FLUSH_CACHE_INFO0_CACHE_ADDR_HI, cmd.addr_hi as u32);
            if cmd.flag & HAL_REO_CMD_FLG_FLUSH_FWD_ALL_MPDUS != 0 {
                info0 |= HAL_REO_FLUSH_CACHE_INFO0_FWD_ALL_MPDUS;
            }
            if block_later {
                info0 |= HAL_REO_FLUSH_CACHE_INFO0_BLOCK_CACHE_USAGE;
                info0 |= field_prep(HAL_REO_FLUSH_CACHE_INFO0_BLOCK_RESRC_IDX, avail_slot as u32);
            }
            if cmd.flag & HAL_REO_CMD_FLG_FLUSH_NO_INVAL != 0 {
                info0 |= HAL_REO_FLUSH_CACHE_INFO0_FLUSH_WO_INVALIDATE;
            }
            if cmd.flag & HAL_REO_CMD_FLG_FLUSH_ALL != 0 {
                info0 |= HAL_REO_FLUSH_CACHE_INFO0_FLUSH_ALL;
            }
            w[3] = info0;
        }
        _ => {
            // t::UPDATE_RX_QUEUE (hal_reo_cmd_check passed)
            w[0] = tlv(reo_tlv::HAL_REO_UPDATE_RX_REO_QUEUE);
            let u0 = cmd.upd0;
            let f = |m: u32| bit(u0 & m != 0);
            w[3] = field_prep(HAL_REO_UPD_RX_QUEUE_INFO0_QUEUE_ADDR_HI, cmd.addr_hi as u32)
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_RX_QUEUE_NUM,
                    f(HAL_REO_CMD_UPD0_RX_QUEUE_NUM),
                )
                | field_prep(HAL_REO_UPD_RX_QUEUE_INFO0_UPD_VLD, f(HAL_REO_CMD_UPD0_VLD))
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_ASSOC_LNK_DESC_CNT,
                    f(HAL_REO_CMD_UPD0_ALDC),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_DIS_DUP_DETECTION,
                    f(HAL_REO_CMD_UPD0_DIS_DUP_DETECTION),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_SOFT_REORDER_EN,
                    f(HAL_REO_CMD_UPD0_SOFT_REORDER_EN),
                )
                | field_prep(HAL_REO_UPD_RX_QUEUE_INFO0_UPD_AC, f(HAL_REO_CMD_UPD0_AC))
                | field_prep(HAL_REO_UPD_RX_QUEUE_INFO0_UPD_BAR, f(HAL_REO_CMD_UPD0_BAR))
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_RETRY,
                    f(HAL_REO_CMD_UPD0_RETRY),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_CHECK_2K_MODE,
                    f(HAL_REO_CMD_UPD0_CHECK_2K_MODE),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_OOR_MODE,
                    f(HAL_REO_CMD_UPD0_OOR_MODE),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_BA_WINDOW_SIZE,
                    f(HAL_REO_CMD_UPD0_BA_WINDOW_SIZE),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_PN_CHECK,
                    f(HAL_REO_CMD_UPD0_PN_CHECK),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_EVEN_PN,
                    f(HAL_REO_CMD_UPD0_EVEN_PN),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_UNEVEN_PN,
                    f(HAL_REO_CMD_UPD0_UNEVEN_PN),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_PN_HANDLE_ENABLE,
                    f(HAL_REO_CMD_UPD0_PN_HANDLE_ENABLE),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_PN_SIZE,
                    f(HAL_REO_CMD_UPD0_PN_SIZE),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_IGNORE_AMPDU_FLG,
                    f(HAL_REO_CMD_UPD0_IGNORE_AMPDU_FLG),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_SVLD,
                    f(HAL_REO_CMD_UPD0_SVLD),
                )
                | field_prep(HAL_REO_UPD_RX_QUEUE_INFO0_UPD_SSN, f(HAL_REO_CMD_UPD0_SSN))
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_SEQ_2K_ERR,
                    f(HAL_REO_CMD_UPD0_SEQ_2K_ERR),
                )
                // UPD_PN_ERR (28) stays clear: Linux does not map
                // HAL_REO_CMD_UPD0_PN_ERR.
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO0_UPD_PN_VALID,
                    f(HAL_REO_CMD_UPD0_PN_VALID),
                )
                | field_prep(HAL_REO_UPD_RX_QUEUE_INFO0_UPD_PN, f(HAL_REO_CMD_UPD0_PN));

            let u1 = cmd.upd1;
            let g = |m: u32| bit(u1 & m != 0);
            w[4] = field_prep(
                HAL_REO_UPD_RX_QUEUE_INFO1_RX_QUEUE_NUMBER,
                cmd.rx_queue_num as u32,
            ) | field_prep(HAL_REO_UPD_RX_QUEUE_INFO1_VLD, g(HAL_REO_CMD_UPD1_VLD))
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO1_ASSOC_LNK_DESC_COUNTER,
                    field_get(HAL_REO_CMD_UPD1_ALDC, u1),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO1_DIS_DUP_DETECTION,
                    g(HAL_REO_CMD_UPD1_DIS_DUP_DETECTION),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO1_SOFT_REORDER_EN,
                    g(HAL_REO_CMD_UPD1_SOFT_REORDER_EN),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO1_AC,
                    field_get(HAL_REO_CMD_UPD1_AC, u1),
                )
                | field_prep(HAL_REO_UPD_RX_QUEUE_INFO1_BAR, g(HAL_REO_CMD_UPD1_BAR))
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO1_CHECK_2K_MODE,
                    g(HAL_REO_CMD_UPD1_CHECK_2K_MODE),
                )
                | field_prep(HAL_REO_UPD_RX_QUEUE_INFO1_RETRY, g(HAL_REO_CMD_UPD1_RETRY))
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO1_OOR_MODE,
                    g(HAL_REO_CMD_UPD1_OOR_MODE),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO1_PN_CHECK,
                    g(HAL_REO_CMD_UPD1_PN_CHECK),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO1_EVEN_PN,
                    g(HAL_REO_CMD_UPD1_EVEN_PN),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO1_UNEVEN_PN,
                    g(HAL_REO_CMD_UPD1_UNEVEN_PN),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO1_PN_HANDLE_ENABLE,
                    g(HAL_REO_CMD_UPD1_PN_HANDLE_ENABLE),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO1_IGNORE_AMPDU_FLG,
                    g(HAL_REO_CMD_UPD1_IGNORE_AMPDU_FLG),
                );

            cmd.pn_size = match cmd.pn_size {
                24 => HAL_RX_REO_QUEUE_PN_SIZE_24,
                48 => HAL_RX_REO_QUEUE_PN_SIZE_48,
                128 => HAL_RX_REO_QUEUE_PN_SIZE_128,
                v => v,
            };
            if cmd.ba_window_size < 1 {
                cmd.ba_window_size = 1;
            }
            if cmd.ba_window_size == 1 {
                cmd.ba_window_size += 1;
            }
            let u2 = cmd.upd2;
            w[5] = field_prep(
                HAL_REO_UPD_RX_QUEUE_INFO2_BA_WINDOW_SIZE,
                cmd.ba_window_size as u32 - 1,
            ) | field_prep(HAL_REO_UPD_RX_QUEUE_INFO2_PN_SIZE, cmd.pn_size as u32)
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO2_SVLD,
                    bit(u2 & HAL_REO_CMD_UPD2_SVLD != 0),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO2_SSN,
                    field_get(HAL_REO_CMD_UPD2_SSN, u2),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO2_SEQ_2K_ERR,
                    bit(u2 & HAL_REO_CMD_UPD2_SEQ_2K_ERR != 0),
                )
                | field_prep(
                    HAL_REO_UPD_RX_QUEUE_INFO2_PN_ERR,
                    bit(u2 & HAL_REO_CMD_UPD2_PN_ERR != 0),
                );
            // pn[4] stay zero (memset_startat; Linux never copies cmd->pn).
        }
    }
    Ok(w)
}

// ── per-peer state ────────────────────────────────────────────────

/// The queue memory and the fields of `struct dp_rx_tid` Linux copies
/// into a pending command (`memcpy(&dp_cmd->data, rx_tid, …)`).
#[derive(Debug)]
pub struct RxTidData {
    pub tid: u8,
    pub paddr: u64,
    pub size: u32,
    pub ba_win_sz: u32,
    /// `vaddr_unaligned` (the allocation).
    pub mem: Option<DmaMem>,
}

/// `struct dp_rx_tid`.
#[derive(Debug, Default)]
pub struct RxTid {
    pub tid: u8,
    pub paddr: u64,
    pub size: u32,
    pub ba_win_sz: u32,
    pub active: bool,
    mem: Option<DmaMem>,
    /// `rx_frags`: the fragments held (RX descriptor + raw MPDU), in
    /// fragment-number order.
    pub rx_frags: Vec<Vec<u8>>,
    /// `cur_sn` / `last_frag_no` / `rx_frag_bitmap`.
    pub cur_sn: u16,
    pub last_frag_no: u8,
    pub rx_frag_bitmap: u16,
    /// `dst_ring_desc`: fragment 0's REO exception ring entry.
    pub dst_ring_desc: Option<[u32; 16]>,
    /// `frag_timer` expiry (ms), when armed.
    pub frag_timer: Option<u64>,
}

impl RxTid {
    /// The queue descriptor memory, while this TID owns it.
    pub fn mem(&self) -> Option<&DmaMem> {
        self.mem.as_ref()
    }
}

/// The host-held RX Michael direction for an encrypted TKIP peer.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TkipRxMicKey([u8; 8]);

impl TkipRxMicKey {
    pub const fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    pub const fn bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl core::fmt::Debug for TkipRxMicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TkipRxMicKey(<redacted>)")
    }
}

/// The RX part of `struct ath11k_peer` for one HTT-mapped peer.
#[derive(Debug)]
pub struct PeerRx {
    pub vdev_id: u8,
    pub addr: [u8; 6],
    pub peer_id: u16,
    pub rx_tid: [RxTid; NUM_RX_TIDS],
    /// `key[NL80211_TKIP_DATA_OFFSET_RX_MIC_KEY..][..8]`, retained only
    /// while a pairwise TKIP key is installed. The firmware owns the
    /// temporal key and transmit Michael direction.
    pub tkip_rx_mic: Option<TkipRxMicKey>,
    pub dp_setup_done: bool,
}

/// The handler a pending REO command runs on its status.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReoCmdHandler {
    /// `ath11k_dp_rx_tid_del_func`.
    TidDel,
    /// `ath11k_dp_reo_cmd_free`.
    CmdFree,
}

/// `struct dp_reo_cmd`.
#[derive(Debug)]
pub struct DpReoCmd {
    pub cmd_num: u16,
    pub handler: ReoCmdHandler,
    pub data: RxTidData,
}

/// `struct dp_reo_cache_flush_elem`.
#[derive(Debug)]
pub struct CacheFlushElem {
    pub ts_ms: u64,
    pub data: RxTidData,
}

/// Counters (Linux warnings).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerRxStats {
    pub reo_cmds_sent: u32,
    /// Statuses whose command number is not pending (Linux: no handler).
    pub status_unmatched: u32,
    /// `failed to delete rx tid %d hw descriptor` (memory stays held).
    pub tid_del_failed: u32,
    /// `failed to flush rx tid hw desc`.
    pub flush_failed: u32,
    /// FLUSH_CACHE chunks that could not be queued.
    pub flush_send_failed: u32,
    /// Queue descriptors kept because the device may still use them.
    pub stranded: u32,
    /// Queue descriptors freed.
    pub freed: u32,
}

/// `ab->peers` RX state + `dp->reo_cmd_list` +
/// `dp->reo_cmd_cache_flush_list` + the HAL blocking-slot state.
#[derive(Debug, Default)]
pub struct DpPeerRx {
    pub peers: Vec<PeerRx>,
    pub reo_cmd_list: Vec<DpReoCmd>,
    pub cache_flush_list: Vec<CacheFlushElem>,
    pub cache_flush_count: u32,
    pub blk: BlkRes,
    /// Descriptors NARF keeps instead of freeing (see the module doc).
    pub stranded: Vec<DmaMem>,
    pub stats: PeerRxStats,
}

impl DpPeerRx {
    fn strand(&mut self, mem: Option<DmaMem>) {
        if let Some(m) = mem {
            self.stranded.push(m);
            self.stats.stranded += 1;
        }
    }

    fn free(&mut self, mem: Option<DmaMem>) {
        if mem.is_some() {
            self.stats.freed += 1;
        }
        drop(mem);
    }

    /// `ath11k_peer_unmap_event` frees the peer with whatever queues it
    /// still owns (Linux leaks their DMA memory); NARF keeps them.
    pub fn peer_unmapped(&mut self, peer_id: u16) {
        while let Some(i) = self.peers.iter().position(|p| p.peer_id == peer_id) {
            let mut p = self.peers.remove(i);
            for t in p.rx_tid.iter_mut() {
                let m = t.mem.take();
                self.strand(m);
            }
        }
    }

    /// The RX state of an HTT-mapped peer.
    pub fn peer(&self, vdev_id: u8, addr: &[u8; 6]) -> Option<&PeerRx> {
        self.peers
            .iter()
            .find(|p| p.vdev_id == vdev_id && p.addr == *addr)
    }
}

/// One `ath11k_peer_rx_tid_setup` result: the
/// `WMI_PEER_REORDER_QUEUE_SETUP_CMDID` to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RxTidSetup {
    pub tid: u8,
    pub cmd: WmiCmd,
    /// The queue already existed (REO UPDATE_RX_QUEUE path).
    pub updated: bool,
}

/// `ath11k_dp_peer_setup` in progress (see [`Dp::peer_setup_begin`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerSetup {
    pub vdev_id: u8,
    pub addr: [u8; 6],
    /// Next TID to set up; `NUM_RX_TIDS` = fragment setup next; beyond = done.
    next_tid: u8,
    /// The TID whose WMI command was returned last.
    last: Option<(u8, bool)>,
}

fn perr(step: u32, detail: u32, errno: i32) -> TransportError {
    TransportError::new(step, detail, errno)
}

impl Dp {
    /// `ath11k_peer_find(ab, vdev_id, addr)` → index into
    /// `peer_rx.peers` (created on first use for an HTT-mapped peer).
    fn peer_rx_idx(&mut self, vdev_id: u8, addr: &[u8; 6]) -> Option<usize> {
        let peer_id = self
            .peers
            .iter()
            .find(|p| p.vdev_id == vdev_id && p.addr == *addr)?
            .peer_id;
        let rx = &mut self.peer_rx;
        if let Some(i) = rx
            .peers
            .iter()
            .position(|p| p.vdev_id == vdev_id && p.addr == *addr && p.peer_id == peer_id)
        {
            return Some(i);
        }
        rx.peers.push(PeerRx {
            vdev_id,
            addr: *addr,
            peer_id,
            rx_tid: Default::default(),
            tkip_rx_mic: None,
            dp_setup_done: false,
        });
        Some(rx.peers.len() - 1)
    }

    /// Install or clear the host-only receive Michael direction for a
    /// pairwise TKIP key. Linux keeps a Michael shash per peer and receives
    /// this key from mac80211; the WCN6855 firmware owns the remaining TKIP
    /// material, so DP deliberately retains only these eight octets.
    pub fn tkip_rx_mic_config(
        &mut self,
        vdev_id: u8,
        addr: &[u8; 6],
        key: Option<[u8; 8]>,
    ) -> Result<(), i32> {
        let pi = self
            .peer_rx_idx(vdev_id, addr)
            .ok_or(perr(step::PEER_NOT_FOUND, vdev_id as u32, ENOENT).errno)?;
        self.peer_rx.peers[pi].tkip_rx_mic = key.map(TkipRxMicKey::new);
        Ok(())
    }

    /// The stored host-only receive Michael direction for one HTT peer.
    pub(super) fn tkip_rx_mic_key(&self, peer_id: u16) -> Option<&[u8; 8]> {
        self.peer_rx
            .peers
            .iter()
            .find(|peer| peer.peer_id == peer_id)
            .and_then(|peer| peer.tkip_rx_mic.as_ref())
            .map(TkipRxMicKey::bytes)
    }

    // ── REO command ring ────────────────────────────────────────

    /// Linux `ath11k_dp_tx_send_reo_cmd` + `ath11k_hal_reo_cmd_send`:
    /// queue one command on the REO command ring; with a handler the
    /// queue memory moves into `dp->reo_cmd_list` until its status.
    /// Returns the command number. On failure the memory is handed back.
    pub fn send_reo_cmd(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        ty: u32,
        cmd: &mut HalReoCmd,
        cb: Option<(ReoCmdHandler, RxTidData)>,
        now_ms: u64,
    ) -> Result<u16, (TransportError, Option<RxTidData>)> {
        let back = |e: TransportError, cb: Option<(ReoCmdHandler, RxTidData)>| {
            Err((e, cb.map(|(_, d)| d)))
        };
        if self.crash_flush {
            return back(perr(step::REO_CMD_SHUTDOWN, ty, errno::ESHUTDOWN), cb);
        }
        if let Err((s, e)) = hal_reo_cmd_check(ty, cmd, &self.peer_rx.blk) {
            return back(perr(s, ty, e), cb);
        }
        let id = self.reo_cmd_ring.ring_id;
        hal.access_begin(id);
        let Some(off) = hal.src_get_next_entry(id) else {
            hal.access_end(io, id);
            return back(perr(step::REO_CMD_RING_FULL, ty, errno::ENOBUFS), cb);
        };
        let prev = hal.desc_rd(id, off, 1);
        let w = match hal_reo_cmd_desc(ty, cmd, prev, &mut self.peer_rx.blk) {
            Ok(w) => w,
            Err(_) => unreachable!("hal_reo_cmd_check passed"),
        };
        hal.desc_wr(id, off, &w);
        // ath11k_dp_shadow_start_timer before access_end, as Linux.
        self.reo_cmd_timer.start(now_ms);
        hal.access_end(io, id);
        self.peer_rx.stats.reo_cmds_sent += 1;

        let cmd_num = field_get(HAL_REO_CMD_HDR_INFO0_CMD_NUMBER, w[1]) as u16;
        if cmd_num == 0 {
            return back(perr(step::REO_CMD_NUM_ZERO, ty, errno::EINVAL), cb);
        }
        if let Some((handler, data)) = cb {
            self.peer_rx.reo_cmd_list.push(DpReoCmd {
                cmd_num,
                handler,
                data,
            });
        }
        Ok(cmd_num)
    }

    /// The command-list half of Linux `ath11k_dp_process_reo_status`:
    /// run the handler of each status's pending command (matched by
    /// command number only, as Linux). Feed it
    /// `DpServiceOutput::reo_status` (or [`Dp::process_reo_status`]).
    pub fn reo_status_handler(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        statuses: &[ReoStatus],
        now_ms: u64,
    ) {
        for st in statuses {
            let Some(i) = self
                .peer_rx
                .reo_cmd_list
                .iter()
                .position(|c| c.cmd_num == st.cmd_num)
            else {
                self.peer_rx.stats.status_unmatched += 1;
                continue;
            };
            let c = self.peer_rx.reo_cmd_list.remove(i);
            match c.handler {
                ReoCmdHandler::TidDel => {
                    self.rx_tid_del_func(hal, io, c.data, st.cmd_status, now_ms)
                }
                ReoCmdHandler::CmdFree => self.reo_cmd_free(c.data, st.cmd_status),
            }
        }
    }

    /// [`Dp::process_reo_status`] + [`Dp::reo_status_handler`].
    pub fn process_reo_status_and_dispatch(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        now_ms: u64,
    ) -> Vec<ReoStatus> {
        let st = self.process_reo_status(hal, io);
        self.reo_status_handler(hal, io, &st, now_ms);
        st
    }

    /// Linux `ath11k_dp_reo_cmd_free`.
    fn reo_cmd_free(&mut self, data: RxTidData, status: u8) {
        if status != reo_cmd_status::SUCCESS {
            self.peer_rx.stats.flush_failed += 1;
        }
        self.peer_rx.free(data.mem);
    }

    /// Linux `ath11k_dp_reo_cache_flush`: flush every 128-byte block of
    /// the descriptor beyond the first, then the first with status; the
    /// memory is freed on that status.
    fn reo_cache_flush(&mut self, hal: &mut Hal, io: &impl ChipIo, data: RxTidData, now_ms: u64) {
        let desc_sz = hal_reo_qdesc_size(0, HAL_DESC_REO_NON_QOS_TID);
        let mut tot = data.size;
        while tot > desc_sz {
            tot -= desc_sz;
            let mut cmd = HalReoCmd {
                addr_lo: (data.paddr + tot as u64) as u32,
                addr_hi: (data.paddr >> 32) as u8,
                ..HalReoCmd::default()
            };
            if self
                .send_reo_cmd(hal, io, reo_cmd_type::FLUSH_CACHE, &mut cmd, None, now_ms)
                .is_err()
            {
                self.peer_rx.stats.flush_send_failed += 1;
            }
        }
        let mut cmd = HalReoCmd {
            addr_lo: data.paddr as u32,
            addr_hi: (data.paddr >> 32) as u8,
            flag: HAL_REO_CMD_FLG_NEED_STATUS,
            ..HalReoCmd::default()
        };
        if let Err((_, d)) = self.send_reo_cmd(
            hal,
            io,
            reo_cmd_type::FLUSH_CACHE,
            &mut cmd,
            Some((ReoCmdHandler::CmdFree, data)),
            now_ms,
        ) {
            // Linux frees here; the REO cache may still hold the
            // descriptor, so NARF keeps it.
            self.peer_rx.stats.flush_send_failed += 1;
            self.peer_rx.strand(d.and_then(|d| d.mem));
        }
    }

    /// Linux `ath11k_dp_rx_tid_del_func`.
    fn rx_tid_del_func(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        data: RxTidData,
        status: u8,
        now_ms: u64,
    ) {
        if status == reo_cmd_status::DRAIN {
            self.peer_rx.free(data.mem);
            return;
        } else if status != reo_cmd_status::SUCCESS {
            // "Shouldn't happen!" — Linux returns without freeing.
            self.peer_rx.stats.tid_del_failed += 1;
            self.peer_rx.strand(data.mem);
            return;
        }
        self.peer_rx.cache_flush_list.push(CacheFlushElem {
            ts_ms: now_ms,
            data,
        });
        self.peer_rx.cache_flush_count += 1;

        // Flush and invalidate aged REO desc from HW cache.
        let mut i = 0;
        while i < self.peer_rx.cache_flush_list.len() {
            let e = &self.peer_rx.cache_flush_list[i];
            if self.peer_rx.cache_flush_count > DP_REO_DESC_FREE_THRESHOLD
                || now_ms > e.ts_ms + DP_REO_DESC_FREE_TIMEOUT_MS
            {
                let e = self.peer_rx.cache_flush_list.remove(i);
                self.peer_rx.cache_flush_count -= 1;
                self.reo_cache_flush(hal, io, e.data, now_ms);
            } else {
                i += 1;
            }
        }
    }

    /// Linux `ath11k_dp_reo_cmd_list_cleanup` (from `ath11k_dp_free`):
    /// free every pending and cache-flush-pending descriptor.
    pub fn reo_cmd_list_cleanup(&mut self) {
        let cmds = core::mem::take(&mut self.peer_rx.reo_cmd_list);
        for c in cmds {
            self.peer_rx.free(c.data.mem);
        }
        let elems = core::mem::take(&mut self.peer_rx.cache_flush_list);
        for e in elems {
            self.peer_rx.cache_flush_count -= 1;
            self.peer_rx.free(e.data.mem);
        }
    }

    // ── RX TID queues ───────────────────────────────────────────

    /// Linux `ath11k_peer_rx_tid_reo_update` on `peer_rx.peers[pi]
    /// .rx_tid[t]`.
    #[allow(clippy::too_many_arguments)] // Linux's signature + HAL/IO/time
    fn rx_tid_reo_update(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        pi: usize,
        t: usize,
        ba_win_sz: u32,
        ssn: u16,
        update_ssn: bool,
        now_ms: u64,
    ) -> Result<(), TransportError> {
        let paddr = self.peer_rx.peers[pi].rx_tid[t].paddr;
        let mut cmd = HalReoCmd {
            addr_lo: paddr as u32,
            addr_hi: (paddr >> 32) as u8,
            flag: HAL_REO_CMD_FLG_NEED_STATUS,
            upd0: HAL_REO_CMD_UPD0_BA_WINDOW_SIZE,
            ba_window_size: ba_win_sz as u16,
            ..HalReoCmd::default()
        };
        if update_ssn {
            cmd.upd0 |= HAL_REO_CMD_UPD0_SSN;
            cmd.upd2 = field_prep(HAL_REO_CMD_UPD2_SSN, ssn as u32);
        }
        self.send_reo_cmd(
            hal,
            io,
            reo_cmd_type::UPDATE_RX_QUEUE,
            &mut cmd,
            None,
            now_ms,
        )
        .map_err(|(e, _)| e)?;
        self.peer_rx.peers[pi].rx_tid[t].ba_win_sz = ba_win_sz;
        Ok(())
    }

    /// Linux `ath11k_peer_rx_tid_setup`: allocate and write the TID's
    /// REO queue descriptor (or, when it exists, REO UPDATE_RX_QUEUE the
    /// new window / SSN), and return the
    /// `WMI_PEER_REORDER_QUEUE_SETUP_CMDID` to send. If that WMI command
    /// fails, call [`Dp::rx_tid_wmi_failed`].
    #[allow(clippy::too_many_arguments)] // Linux's signature + HAL/IO/time
    pub fn rx_tid_setup(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        vdev_id: u8,
        addr: &[u8; 6],
        tid: u8,
        ba_win_sz: u32,
        ssn: u16,
        pn_type: HalPnType,
        now_ms: u64,
    ) -> Result<RxTidSetup, TransportError> {
        if tid as usize > IEEE80211_NUM_TIDS {
            return Err(perr(step::BAD_TID, tid as u32, errno::EINVAL));
        }
        let pi = self.peer_rx_idx(vdev_id, addr).ok_or(perr(
            step::PEER_NOT_FOUND,
            vdev_id as u32,
            ENOENT,
        ))?;
        let t = tid as usize;

        if self.peer_rx.peers[pi].rx_tid[t].active {
            let paddr = self.peer_rx.peers[pi].rx_tid[t].paddr;
            self.rx_tid_reo_update(hal, io, pi, t, ba_win_sz, ssn, true, now_ms)?;
            return Ok(RxTidSetup {
                tid,
                cmd: wmi::peer_rx_reorder_queue_setup_cmd(
                    vdev_id as u32,
                    addr,
                    paddr,
                    tid,
                    1,
                    ba_win_sz,
                ),
                updated: true,
            });
        }

        let rx_tid = &mut self.peer_rx.peers[pi].rx_tid[t];
        rx_tid.tid = tid;
        rx_tid.ba_win_sz = ba_win_sz;
        let hw_desc_sz = if tid == HAL_DESC_REO_NON_QOS_TID {
            hal_reo_qdesc_size(ba_win_sz, tid)
        } else {
            hal_reo_qdesc_size(DP_BA_WIN_SZ_MAX, tid)
        };
        let mem = DmaMem::alloc(hw_desc_sz as usize, HAL_LINK_DESC_ALIGN as usize)
            .map_err(|e| perr(step::QDESC_ALLOC, tid as u32, e.errno))?;
        let mut w = alloc::vec![0u32; (hw_desc_sz / 4) as usize];
        hal_reo_qdesc_setup(&mut w, tid, ba_win_sz, ssn as u32, pn_type);
        for (i, v) in w.iter().enumerate() {
            mem.wr32(i, *v);
        }
        // dma_sync_single_for_device
        dma_wmb();
        let paddr = mem.paddr();
        rx_tid.paddr = paddr;
        rx_tid.size = hw_desc_sz;
        rx_tid.mem = Some(mem);
        rx_tid.active = true;
        Ok(RxTidSetup {
            tid,
            cmd: wmi::peer_rx_reorder_queue_setup_cmd(
                vdev_id as u32,
                addr,
                paddr,
                tid,
                1,
                ba_win_sz,
            ),
            updated: false,
        })
    }

    /// The failure path after [`Dp::rx_tid_setup`]'s WMI command failed:
    /// a freshly allocated queue is freed (`ath11k_dp_rx_tid_mem_free`);
    /// an updated one stays.
    pub fn rx_tid_wmi_failed(&mut self, vdev_id: u8, addr: &[u8; 6], setup: &RxTidSetup) {
        if !setup.updated {
            self.rx_tid_mem_free(vdev_id, addr, setup.tid);
        }
    }

    /// Linux `ath11k_dp_rx_tid_mem_free`.
    fn rx_tid_mem_free(&mut self, vdev_id: u8, addr: &[u8; 6], tid: u8) {
        let Some(pi) = self.peer_rx_idx(vdev_id, addr) else {
            return;
        };
        let rx_tid = &mut self.peer_rx.peers[pi].rx_tid[tid as usize];
        if !rx_tid.active {
            return;
        }
        let m = rx_tid.mem.take();
        rx_tid.active = false;
        self.peer_rx.free(m);
    }

    /// Linux `ath11k_peer_rx_tid_delete`: REO UPDATE_RX_QUEUE with VLD
    /// cleared; the descriptor is released by
    /// `ath11k_dp_rx_tid_del_func` on the command's status.
    fn rx_tid_delete(&mut self, hal: &mut Hal, io: &impl ChipIo, pi: usize, tid: u8, now_ms: u64) {
        let t = tid as usize;
        let Some(rx_tid) = self
            .peer_rx
            .peers
            .get_mut(pi)
            .and_then(|p| p.rx_tid.get_mut(t))
        else {
            return;
        };
        if !rx_tid.active {
            return;
        }
        rx_tid.active = false;
        let data = RxTidData {
            tid: rx_tid.tid,
            paddr: rx_tid.paddr,
            size: rx_tid.size,
            ba_win_sz: rx_tid.ba_win_sz,
            mem: rx_tid.mem.take(),
        };
        let mut cmd = HalReoCmd {
            flag: HAL_REO_CMD_FLG_NEED_STATUS,
            addr_lo: data.paddr as u32,
            addr_hi: (data.paddr >> 32) as u8,
            upd0: HAL_REO_CMD_UPD0_VLD,
            ..HalReoCmd::default()
        };
        if let Err((_, d)) = self.send_reo_cmd(
            hal,
            io,
            reo_cmd_type::UPDATE_RX_QUEUE,
            &mut cmd,
            Some((ReoCmdHandler::TidDel, data)),
            now_ms,
        ) {
            // Linux frees here although the queue is still valid in the
            // hardware; NARF keeps it.
            self.peer_rx.strand(d.and_then(|d| d.mem));
        }
        let rx_tid = &mut self.peer_rx.peers[pi].rx_tid[t];
        rx_tid.paddr = 0;
        rx_tid.size = 0;
    }

    /// Linux `ath11k_peer_rx_tid_cleanup` on `peer_rx.peers[pi]`.
    fn rx_tid_cleanup(&mut self, hal: &mut Hal, io: &impl ChipIo, pi: usize, now_ms: u64) {
        for tid in 0..NUM_RX_TIDS as u8 {
            self.rx_tid_delete(hal, io, pi, tid, now_ms);
            self.frags_cleanup(hal, io, pi, tid as usize, true);
            self.peer_rx.peers[pi].rx_tid[tid as usize].frag_timer = None;
        }
    }

    // ── peer setup / cleanup ────────────────────────────────────

    /// Linux `ath11k_dp_peer_setup` (from `ath11k_mac_station_add`, i.e.
    /// `ath11k_mac_op_sta_state` NOTEXIST → NONE, right after
    /// `ath11k_peer_create` returned — the peer is HTT-mapped by then).
    /// Step 1: the `WMI_PEER_SET_DEFAULT_ROUTING` command (`reo_dest =
    /// mac_id + 1`). The integrator then does:
    ///
    /// ```text
    /// let (mut op, cmd) = dp.peer_setup_begin(vdev_id, addr, mac_id);
    /// wmi_cmd_send(cmd)?;                        // failure: return it
    /// while let Some(cmd) = dp.peer_setup_next(hal, io, &mut op, now)? {
    ///     if let Err(e) = wmi_cmd_send(cmd) {
    ///         return Err(dp.peer_setup_wmi_failed(hal, io, &op, e, now));
    ///     }
    /// }
    /// ```
    ///
    /// which is Linux's exact order: default routing, then per TID
    /// 0..=16 queue setup + `WMI_PEER_REORDER_QUEUE_SETUP_CMDID`, then the
    /// fragment context.
    pub fn peer_setup_begin(&self, vdev_id: u8, addr: [u8; 6], mac_id: u32) -> (PeerSetup, WmiCmd) {
        let reo_dest = mac_id + 1;
        let cmd = wmi::peer_set_param_cmd(
            &addr,
            vdev_id as u32,
            wmi::peer_param::SET_DEFAULT_ROUTING,
            DP_RX_HASH_ENABLE | (reo_dest << 1),
        );
        (
            PeerSetup {
                vdev_id,
                addr,
                next_tid: 0,
                last: None,
            },
            cmd,
        )
    }

    /// Next step of `ath11k_dp_peer_setup`: set up the next TID and return
    /// its WMI command; after TID 16, the fragment setup and `Ok(None)`.
    /// A failure has already unwound (`peer_clean`) when it returns.
    pub fn peer_setup_next(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        op: &mut PeerSetup,
        now_ms: u64,
    ) -> Result<Option<WmiCmd>, TransportError> {
        let (vdev_id, addr) = (op.vdev_id, op.addr);
        if (op.next_tid as usize) < NUM_RX_TIDS {
            let tid = op.next_tid;
            match self.rx_tid_setup(hal, io, vdev_id, &addr, tid, 1, 0, HalPnType::None, now_ms) {
                Ok(s) => {
                    op.last = Some((tid, s.updated));
                    op.next_tid += 1;
                    Ok(Some(s.cmd))
                }
                Err(e) => {
                    op.next_tid = u8::MAX;
                    self.peer_clean(hal, io, vdev_id, &addr, tid as i32, now_ms);
                    Err(e)
                }
            }
        } else if op.next_tid as usize == NUM_RX_TIDS {
            op.next_tid += 1;
            // ath11k_peer_rx_frag_setup
            match self.peer_rx_idx(vdev_id, &addr) {
                Some(pi) => {
                    self.peer_rx.peers[pi].dp_setup_done = true;
                    Ok(None)
                }
                None => {
                    // "failed to setup rx defrag context"; tid-- → 16.
                    self.peer_clean(hal, io, vdev_id, &addr, IEEE80211_NUM_TIDS as i32, now_ms);
                    Err(perr(step::PEER_NOT_FOUND, vdev_id as u32, ENOENT))
                }
            }
        } else {
            Ok(None)
        }
    }

    /// The last command returned by [`Dp::peer_setup_begin`] /
    /// [`Dp::peer_setup_next`] failed with `errno`: unwind as
    /// `ath11k_dp_peer_setup` does and return the error to report.
    pub fn peer_setup_wmi_failed(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        op: &PeerSetup,
        errno: i32,
        now_ms: u64,
    ) -> TransportError {
        let Some((tid, updated)) = op.last else {
            // WMI_PEER_SET_DEFAULT_ROUTING: Linux returns at once.
            return perr(step::WMI_SEND, 0xff, errno);
        };
        let setup = RxTidSetup {
            tid,
            cmd: WmiCmd {
                cmd_id: 0,
                buf: Vec::new(),
            },
            updated,
        };
        self.rx_tid_wmi_failed(op.vdev_id, &op.addr, &setup);
        self.peer_clean(hal, io, op.vdev_id, &op.addr, tid as i32, now_ms);
        perr(step::WMI_SEND, tid as u32, errno)
    }

    /// `peer_clean:` of `ath11k_dp_peer_setup`: delete TIDs `tid..=0`.
    fn peer_clean(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        vdev_id: u8,
        addr: &[u8; 6],
        mut tid: i32,
        now_ms: u64,
    ) {
        let Some(pi) = self.peer_rx_idx(vdev_id, addr) else {
            return;
        };
        while tid >= 0 {
            self.rx_tid_delete(hal, io, pi, tid as u8, now_ms);
            tid -= 1;
        }
    }

    /// Linux `ath11k_dp_peer_cleanup` (from `ath11k_mac_station_remove`,
    /// sta_state NONE → NOTEXIST, *before* `ath11k_peer_delete`): delete
    /// every TID queue. No WMI command (Linux never sends
    /// `WMI_PEER_REORDER_QUEUE_REMOVE_CMDID`; `PEER_DELETE` drops the
    /// firmware's queue pointers).
    pub fn peer_cleanup(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        vdev_id: u8,
        addr: &[u8; 6],
        now_ms: u64,
    ) -> Result<(), TransportError> {
        let pi = self.peer_rx_idx(vdev_id, addr).ok_or(perr(
            step::PEER_NOT_FOUND,
            vdev_id as u32,
            ENOENT,
        ))?;
        self.rx_tid_cleanup(hal, io, pi, now_ms);
        self.peer_rx.peers[pi].dp_setup_done = false;
        Ok(())
    }

    /// The DP part of `ath11k_mac_peer_cleanup_all`: delete every
    /// peer's TID queues and forget the peers.
    pub fn peer_cleanup_all(&mut self, hal: &mut Hal, io: &impl ChipIo, now_ms: u64) {
        for pi in 0..self.peer_rx.peers.len() {
            self.rx_tid_cleanup(hal, io, pi, now_ms);
        }
        self.peer_rx.peers.clear();
        self.peers.clear();
    }

    // ── key install ─────────────────────────────────────────────

    /// Linux `ath11k_dp_peer_rx_pn_replay_config` (from
    /// `ath11k_mac_op_set_key`, after `ath11k_install_key`): REO
    /// UPDATE_RX_QUEUE with PN / PN_SIZE / PN_VALID / PN_CHECK / SVLD on
    /// every active TID of the peer. Only pairwise keys (`pairwise`;
    /// group PN checks stay with mac80211 in Linux, nowhere in NARF);
    /// `rsn_cipher` = TKIP / CCMP / GCMP, where a `SET_KEY` (`install`)
    /// also turns the PN check on with a 48-bit PN. Stops at the first
    /// command that cannot be queued and returns its error, as Linux.
    #[allow(clippy::too_many_arguments)] // the set_key arguments + HAL/IO/time
    pub fn pn_replay_config(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        vdev_id: u8,
        addr: &[u8; 6],
        rsn_cipher: bool,
        pairwise: bool,
        install: bool,
        now_ms: u64,
    ) -> Result<(), TransportError> {
        if !pairwise {
            return Ok(());
        }
        let mut cmd = HalReoCmd {
            flag: HAL_REO_CMD_FLG_NEED_STATUS,
            upd0: HAL_REO_CMD_UPD0_PN
                | HAL_REO_CMD_UPD0_PN_SIZE
                | HAL_REO_CMD_UPD0_PN_VALID
                | HAL_REO_CMD_UPD0_PN_CHECK
                | HAL_REO_CMD_UPD0_SVLD,
            ..HalReoCmd::default()
        };
        if rsn_cipher && install {
            cmd.upd1 |= HAL_REO_CMD_UPD1_PN_CHECK;
            cmd.pn_size = 48;
        }
        let pi = self.peer_rx_idx(vdev_id, addr).ok_or(perr(
            step::PEER_NOT_FOUND,
            vdev_id as u32,
            ENOENT,
        ))?;
        for tid in 0..NUM_RX_TIDS {
            let t = &self.peer_rx.peers[pi].rx_tid[tid];
            if !t.active {
                continue;
            }
            // One `cmd` across the TIDs, as Linux:
            // `ath11k_hal_reo_cmd_update_rx_queue` rewrites `pn_size` (48 →
            // its enum) and `ba_window_size` (0 → 2) in place, so later
            // TIDs see the converted values (which encode the same).
            cmd.addr_lo = t.paddr as u32;
            cmd.addr_hi = (t.paddr >> 32) as u8;
            if let Err((e, _)) = self.send_reo_cmd(
                hal,
                io,
                reo_cmd_type::UPDATE_RX_QUEUE,
                &mut cmd,
                None,
                now_ms,
            ) {
                return Err(e);
            }
        }
        Ok(())
    }

    // ── ADDBA ───────────────────────────────────────────────────

    /// Linux `ath11k_dp_rx_ampdu_start` (`IEEE80211_AMPDU_RX_START`):
    /// [`Dp::rx_tid_setup`] with the negotiated window and SSN.
    #[allow(clippy::too_many_arguments)] // ieee80211_ampdu_params + HAL/IO/time
    pub fn ampdu_start(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        vdev_id: u8,
        addr: &[u8; 6],
        tid: u8,
        buf_size: u16,
        ssn: u16,
        pn_type: HalPnType,
        now_ms: u64,
    ) -> Result<RxTidSetup, TransportError> {
        self.rx_tid_setup(
            hal,
            io,
            vdev_id,
            addr,
            tid,
            buf_size as u32,
            ssn,
            pn_type,
            now_ms,
        )
    }

    /// Linux `ath11k_dp_rx_ampdu_stop` (`IEEE80211_AMPDU_RX_STOP`):
    /// `None` when the TID has no queue; else the
    /// `WMI_PEER_REORDER_QUEUE_SETUP_CMDID` (window 1) to send.
    ///
    /// Linux quirk kept: the REO update goes to `peer->rx_tid` — TID 0's
    /// queue — not to `tid`'s.
    pub fn ampdu_stop(
        &mut self,
        hal: &mut Hal,
        io: &impl ChipIo,
        vdev_id: u8,
        addr: &[u8; 6],
        tid: u8,
        now_ms: u64,
    ) -> Result<Option<WmiCmd>, TransportError> {
        if tid as usize > IEEE80211_NUM_TIDS {
            return Err(perr(step::BAD_TID, tid as u32, errno::EINVAL));
        }
        let pi = self.peer_rx_idx(vdev_id, addr).ok_or(perr(
            step::PEER_NOT_FOUND,
            vdev_id as u32,
            ENOENT,
        ))?;
        let paddr = self.peer_rx.peers[pi].rx_tid[tid as usize].paddr;
        let active = self.peer_rx.peers[pi].rx_tid[tid as usize].active;
        if !active {
            return Ok(None);
        }
        self.rx_tid_reo_update(hal, io, pi, 0, 1, 0, false, now_ms)?;
        Ok(Some(wmi::peer_rx_reorder_queue_setup_cmd(
            vdev_id as u32,
            addr,
            paddr,
            tid,
            1,
            1,
        )))
    }
}

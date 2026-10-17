//! HTT (Host ↔ Target data-path messages) — the `HTT_DATA_MSG` HTC
//! service the data path is configured through.
//!
//! A port of the HTT parts of Linux
//! `drivers/net/wireless/ath/ath11k/dp_tx.c` (H2T encoders) and
//! `dp_rx.c::ath11k_dp_htt_htc_t2h_msg_handler` (T2H decode), with the
//! wire layouts of `dp.h`:
//!
//! - [`ver_req_msg`] = `ath11k_dp_tx_htt_h2t_ver_req_msg` (the message;
//!   the 3 s wait for VERSION_CONF is the caller's — [`HttTarget`]).
//! - [`get_ring_id_type`] = `ath11k_dp_tx_get_ring_id_type`.
//! - [`srng_setup_msg`] = `ath11k_dp_tx_htt_srng_setup`
//!   (`HTT_H2T_MSG_TYPE_SRING_SETUP`, 52 bytes).
//! - [`rx_filter_setup_msg`] = `ath11k_dp_tx_htt_rx_filter_setup`
//!   (`HTT_H2T_MSG_TYPE_RX_RING_SELECTION_CFG`, 28 bytes), with
//!   [`MON_STATUS_FILTER_DEFAULT`] = `ath11k_mac_mon_status_filter_default`
//!   (what `ath11k_mac_config_mon_status_default` programs at
//!   `ath11k_mac_op_start`).
//! - [`ppdu_stats_cfg_msgs`] = `ath11k_dp_tx_htt_h2t_ppdu_stats_req`.
//! - [`decode_t2h`] = the decode half of
//!   `ath11k_dp_htt_htc_t2h_msg_handler`: VERSION_CONF, PEER_MAP,
//!   PEER_MAP2, PEER_UNMAP / PEER_UNMAP2; PPDU_STATS_IND, EXT_STATS_CONF,
//!   PKTLOG and BKPRESSURE_EVENT_IND are recognised and skipped (Linux
//!   feeds them to stats / debugfs / pktlog only); anything else is
//!   [`HttT2h::Unhandled`] (Linux: "htt event %d not handled").
//!
//! Every message is the little-endian `__packed` struct Linux builds in
//! `skb->data`; the caller sends it on the HTT endpoint
//! (`ab->dp.eid`, from `ath11k_dp_htt_connect`) through HTC.
//!
//! Not ported (unreached on WCN6855 station): `ath11k_dp_tx_htt_monitor_mode_ring_config`
//! (monitor vdevs; `supports_monitor = false`),
//! `ath11k_dp_tx_htt_rx_full_mon_setup` (`full_monitor_mode = false`),
//! `ath11k_dp_tx_htt_h2t_ext_stats_req` (debugfs).

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::hal::{
    errno, field_get, field_prep, flags, genmask, ring_id, Hal, HalRingType, TransportError,
    HAL_ADDR_LSB_REG_MASK, HAL_ADDR_MSB_REG_SHIFT, HAL_SRNG_RINGS_PER_LMAC,
};

// ── diag steps (HTT 135–141; DP rings use 110–134, 142–149) ───────

pub mod step {
    /// `ath11k_dp_tx_get_ring_id_type`: ring type the DP never
    /// configures over HTT (detail = ring type).
    pub const RING_TYPE: u32 = 135;
    /// RXDMA_BUF ring id outside the pdev's two buffer rings (only
    /// without `rx_mac_buf_ring`; detail = ring id).
    pub const RING_ID: u32 = 136;
    /// The ring id names no set-up HAL ring (detail = ring id).
    pub const NO_RING: u32 = 137;
    /// T2H message shorter than its type needs (detail = type << 16 |
    /// len).
    pub const T2H_TRUNCATED: u32 = 138;
    /// VERSION_CONF major is not `HTT_TARGET_VERSION_MAJOR` (detail =
    /// major << 8 | minor).
    pub const VERSION: u32 = 140;
    /// No VERSION_CONF within `HTT_TARGET_VERSION_TIMEOUT_MS`.
    pub const VERSION_TIMEOUT: u32 = 141;
}

/// Linux `-ETIMEDOUT`, `-EOPNOTSUPP`.
pub const ETIMEDOUT: i32 = 110;
pub const EOPNOTSUPP: i32 = 95;

// ── message types / fields (dp.h) ─────────────────────────────────

/// `enum htt_h2t_msg_type`.
pub mod h2t {
    pub const VERSION_REQ: u32 = 0;
    pub const SRING_SETUP: u32 = 0xb;
    pub const RX_RING_SELECTION_CFG: u32 = 0xc;
    pub const EXT_STATS_CFG: u32 = 0x10;
    pub const PPDU_STATS_CFG: u32 = 0x11;
    pub const RX_FULL_MONITOR_MODE: u32 = 0x17;
}

/// `enum htt_t2h_msg_type`.
pub mod t2h {
    pub const VERSION_CONF: u8 = 0x0;
    pub const PEER_MAP: u8 = 0x3;
    pub const PEER_UNMAP: u8 = 0x4;
    pub const RX_ADDBA: u8 = 0x5;
    pub const PKTLOG: u8 = 0x8;
    pub const SEC_IND: u8 = 0xb;
    pub const EXT_STATS_CONF: u8 = 0x1c;
    pub const PPDU_STATS_IND: u8 = 0x1d;
    pub const PEER_MAP2: u8 = 0x1e;
    pub const PEER_UNMAP2: u8 = 0x1f;
    pub const BKPRESSURE_EVENT_IND: u8 = 0x24;
}

/// `HTT_TARGET_VERSION_MAJOR`.
pub const HTT_TARGET_VERSION_MAJOR: u8 = 3;
/// `HTT_TARGET_VERSION_TIMEOUT_HZ` (3 * HZ).
pub const HTT_TARGET_VERSION_TIMEOUT_MS: u64 = 3000;

pub const HTT_VER_REQ_INFO_MSG_ID: u32 = genmask(7, 0);

/// `enum htt_srng_ring_type`.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HttRingType {
    HwToSw = 0,
    SwToHw = 1,
    SwToSw = 2,
}

/// `enum htt_srng_ring_id`.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HttRingId {
    RxdmaHostBuf = 0,
    RxdmaMonitorStatus = 1,
    RxdmaMonitorBuf = 2,
    RxdmaMonitorDesc = 3,
    RxdmaMonitorDest = 4,
    Host1ToFwRxbuf = 5,
    Host2ToFwRxbuf = 6,
    RxdmaNonMonitorDest = 7,
}

pub const HTT_SRNG_SETUP_CMD_INFO0_MSG_TYPE: u32 = genmask(7, 0);
pub const HTT_SRNG_SETUP_CMD_INFO0_PDEV_ID: u32 = genmask(15, 8);
pub const HTT_SRNG_SETUP_CMD_INFO0_RING_ID: u32 = genmask(23, 16);
pub const HTT_SRNG_SETUP_CMD_INFO0_RING_TYPE: u32 = genmask(31, 24);
pub const HTT_SRNG_SETUP_CMD_INFO1_RING_SIZE: u32 = genmask(15, 0);
pub const HTT_SRNG_SETUP_CMD_INFO1_RING_ENTRY_SIZE: u32 = genmask(23, 16);
pub const HTT_SRNG_SETUP_CMD_INFO1_RING_LOOP_CNT_DIS: u32 = 1 << 25;
pub const HTT_SRNG_SETUP_CMD_INFO1_RING_FLAGS_MSI_SWAP: u32 = 1 << 27;
pub const HTT_SRNG_SETUP_CMD_INFO1_RING_FLAGS_HOST_FW_SWAP: u32 = 1 << 28;
pub const HTT_SRNG_SETUP_CMD_INFO1_RING_FLAGS_TLV_SWAP: u32 = 1 << 29;
pub const HTT_SRNG_SETUP_CMD_INTR_INFO_BATCH_COUNTER_THRESH: u32 = genmask(14, 0);
pub const HTT_SRNG_SETUP_CMD_INTR_INFO_SW_INTR_MODE: u32 = 1 << 15;
pub const HTT_SRNG_SETUP_CMD_INTR_INFO_INTR_TIMER_THRESH: u32 = genmask(31, 16);
pub const HTT_SRNG_SETUP_CMD_INFO2_INTR_LOW_THRESH: u32 = genmask(15, 0);
pub const HTT_SRNG_SETUP_CMD_INFO2_PRE_FETCH_TIMER_CFG: u32 = 1 << 16;
pub const HTT_SRNG_SETUP_CMD_INFO2_RESPONSE_REQUIRED: u32 = 1 << 19;

/// `sizeof(struct htt_srng_setup_cmd)` (13 words).
pub const HTT_SRNG_SETUP_CMD_LEN: usize = 52;

pub const HTT_PPDU_STATS_CFG_MSG_TYPE: u32 = genmask(7, 0);
pub const HTT_PPDU_STATS_CFG_SOC_STATS: u32 = 1 << 8;
pub const HTT_PPDU_STATS_CFG_PDEV_ID: u32 = genmask(15, 9);
pub const HTT_PPDU_STATS_CFG_TLV_TYPE_BITMASK: u32 = genmask(31, 16);

/// `enum htt_ppdu_stats_tag_type` bits of `HTT_PPDU_STATS_TAG_DEFAULT`.
pub const HTT_PPDU_STATS_TAG_DEFAULT: u32 = (1 << 0) // COMMON
    | (1 << 1) // USR_COMMON
    | (1 << 2) // USR_RATE
    | (1 << 5) // SCH_CMD_STATUS
    | (1 << 6) // USR_COMPLTN_COMMON
    | (1 << 9) // USR_COMPLTN_ACK_BA_STATUS
    | (1 << 10) // USR_COMPLTN_FLUSH
    | (1 << 11); // USR_COMMON_ARRAY

pub const HTT_RX_RING_SELECTION_CFG_CMD_INFO0_MSG_TYPE: u32 = genmask(7, 0);
pub const HTT_RX_RING_SELECTION_CFG_CMD_INFO0_PDEV_ID: u32 = genmask(15, 8);
pub const HTT_RX_RING_SELECTION_CFG_CMD_INFO0_RING_ID: u32 = genmask(23, 16);
pub const HTT_RX_RING_SELECTION_CFG_CMD_INFO0_SS: u32 = 1 << 24;
pub const HTT_RX_RING_SELECTION_CFG_CMD_INFO0_PS: u32 = 1 << 25;
pub const HTT_RX_RING_SELECTION_CFG_CMD_INFO1_BUF_SIZE: u32 = genmask(15, 0);

/// `sizeof(struct htt_rx_ring_selection_cfg_cmd)` (7 words).
pub const HTT_RX_RING_SELECTION_CFG_CMD_LEN: usize = 28;

/// `enum htt_rx_filter_tlv_flags`.
pub mod rx_tlv {
    pub const MPDU_START: u32 = 1 << 0;
    pub const MSDU_START: u32 = 1 << 1;
    pub const RX_PACKET: u32 = 1 << 2;
    pub const MSDU_END: u32 = 1 << 3;
    pub const MPDU_END: u32 = 1 << 4;
    pub const PACKET_HEADER: u32 = 1 << 5;
    pub const PER_MSDU_HEADER: u32 = 1 << 6;
    pub const ATTENTION: u32 = 1 << 7;
    pub const PPDU_START: u32 = 1 << 8;
    pub const PPDU_END: u32 = 1 << 9;
    pub const PPDU_END_USER_STATS: u32 = 1 << 10;
    pub const PPDU_END_USER_STATS_EXT: u32 = 1 << 11;
    pub const PPDU_END_STATUS_DONE: u32 = 1 << 12;
}

/// The FP ("filter pass") bits of the `htt_rx_*_pkt_filter_tlv_flags*`
/// enums the default filter uses (FP = bit 3k, MD = 3k + 1, MO = 3k + 2).
pub mod fp {
    // flags0 (mgmt)
    pub const ASSOC_REQ: u32 = 1 << 0;
    pub const ASSOC_RESP: u32 = 1 << 3;
    pub const REASSOC_REQ: u32 = 1 << 6;
    pub const REASSOC_RESP: u32 = 1 << 9;
    pub const PROBE_REQ: u32 = 1 << 12;
    pub const PROBE_RESP: u32 = 1 << 15;
    pub const PROBE_TIMING_ADV: u32 = 1 << 18;
    pub const BEACON: u32 = 1 << 24;
    pub const ATIM: u32 = 1 << 27;
    // flags1 (mgmt)
    pub const DISASSOC: u32 = 1 << 0;
    pub const AUTH: u32 = 1 << 3;
    pub const DEAUTH: u32 = 1 << 6;
    pub const ACTION: u32 = 1 << 9;
    pub const ACTION_NOACK: u32 = 1 << 12;
    // flags2 (ctrl)
    pub const CTRL_WRAPPER: u32 = 1 << 21;
    pub const BAR: u32 = 1 << 24;
    pub const BA: u32 = 1 << 27;
    // flags3 (ctrl)
    pub const PSPOLL: u32 = 1 << 0;
    pub const RTS: u32 = 1 << 3;
    pub const CTS: u32 = 1 << 6;
    pub const ACK: u32 = 1 << 9;
    pub const CFEND: u32 = 1 << 12;
    pub const CFEND_ACK: u32 = 1 << 15;
    // flags3 (data)
    pub const DATA_MCAST: u32 = 1 << 18;
    pub const DATA_UCAST: u32 = 1 << 21;
    pub const DATA_NULL: u32 = 1 << 24;
}

/// `HTT_RX_FP_MGMT_FILTER_FLAGS0`.
pub const HTT_RX_FP_MGMT_FILTER_FLAGS0: u32 = fp::ASSOC_REQ
    | fp::ASSOC_RESP
    | fp::REASSOC_REQ
    | fp::REASSOC_RESP
    | fp::PROBE_REQ
    | fp::PROBE_RESP
    | fp::PROBE_TIMING_ADV
    | fp::BEACON
    | fp::ATIM;
/// `HTT_RX_FP_MGMT_FILTER_FLAGS1`.
pub const HTT_RX_FP_MGMT_FILTER_FLAGS1: u32 =
    fp::DISASSOC | fp::AUTH | fp::DEAUTH | fp::ACTION | fp::ACTION_NOACK;
/// `HTT_RX_FP_CTRL_FILTER_FLASG2`.
pub const HTT_RX_FP_CTRL_FILTER_FLASG2: u32 = fp::CTRL_WRAPPER | fp::BAR | fp::BA;
/// `HTT_RX_FP_CTRL_FILTER_FLASG3`.
pub const HTT_RX_FP_CTRL_FILTER_FLASG3: u32 =
    fp::PSPOLL | fp::RTS | fp::CTS | fp::ACK | fp::CFEND | fp::CFEND_ACK;
/// `HTT_RX_FP_DATA_FILTER_FLASG3`.
pub const HTT_RX_FP_DATA_FILTER_FLASG3: u32 = fp::DATA_MCAST | fp::DATA_UCAST | fp::DATA_NULL;

/// `struct htt_rx_ring_tlv_filter`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxRingTlvFilter {
    pub rx_filter: u32,
    pub pkt_filter_flags0: u32,
    pub pkt_filter_flags1: u32,
    pub pkt_filter_flags2: u32,
    pub pkt_filter_flags3: u32,
}

/// `ath11k_mac_mon_status_filter_default` (mac.c).
pub const MON_STATUS_FILTER_DEFAULT: RxRingTlvFilter = RxRingTlvFilter {
    rx_filter: rx_tlv::MPDU_START | rx_tlv::PPDU_END | rx_tlv::PPDU_END_STATUS_DONE,
    pkt_filter_flags0: HTT_RX_FP_MGMT_FILTER_FLAGS0,
    pkt_filter_flags1: HTT_RX_FP_MGMT_FILTER_FLAGS1,
    pkt_filter_flags2: HTT_RX_FP_CTRL_FILTER_FLASG2,
    pkt_filter_flags3: HTT_RX_FP_DATA_FILTER_FLASG3 | HTT_RX_FP_CTRL_FILTER_FLASG3,
};

pub const HTT_T2H_MSG_TYPE: u32 = genmask(7, 0);
pub const HTT_T2H_VERSION_CONF_MINOR: u32 = genmask(15, 8);
pub const HTT_T2H_VERSION_CONF_MAJOR: u32 = genmask(23, 16);
pub const HTT_T2H_PEER_MAP_INFO_VDEV_ID: u32 = genmask(15, 8);
pub const HTT_T2H_PEER_MAP_INFO_PEER_ID: u32 = genmask(31, 16);
pub const HTT_T2H_PEER_MAP_INFO1_MAC_ADDR_H16: u32 = genmask(15, 0);
pub const HTT_T2H_PEER_MAP_INFO1_HW_PEER_ID: u32 = genmask(31, 16);
pub const HTT_T2H_PEER_MAP_INFO2_AST_HASH_VAL: u32 = genmask(15, 0);
pub const HTT_T2H_PEER_UNMAP_INFO_PEER_ID: u32 = HTT_T2H_PEER_MAP_INFO_PEER_ID;

/// `DP_SW2HW_MACID`.
pub const fn dp_sw2hw_macid(mac_id: u32) -> u32 {
    mac_id + 1
}

fn le_words<const N: usize>(w: &[u32]) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, v) in w.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

// ── H2T ───────────────────────────────────────────────────────────

/// `ath11k_dp_tx_htt_h2t_ver_req_msg`: `struct htt_ver_req_cmd`.
pub fn ver_req_msg() -> [u8; 4] {
    field_prep(HTT_VER_REQ_INFO_MSG_ID, h2t::VERSION_REQ).to_le_bytes()
}

/// Linux `ath11k_dp_tx_get_ring_id_type`. `rx_mac_buf_ring` is
/// `hw_params.rx_mac_buf_ring` (true on WCN6855).
pub fn get_ring_id_type(
    rx_mac_buf_ring: bool,
    mac_id: u32,
    ring_id: u32,
    ty: HalRingType,
) -> Result<(HttRingType, HttRingId), TransportError> {
    match ty {
        HalRingType::RxdmaBuf => {
            let off = mac_id * HAL_SRNG_RINGS_PER_LMAC;
            if !rx_mac_buf_ring {
                // Linux sets the ids and still returns -EINVAL.
                if !(ring_id == ring_id::WMAC1_SW2RXDMA0_BUF + off
                    || ring_id == ring_id::WMAC1_SW2RXDMA1_BUF + off)
                {
                    return Err(TransportError::new(step::RING_ID, ring_id, errno::EINVAL));
                }
                Ok((HttRingType::SwToHw, HttRingId::RxdmaHostBuf))
            } else if ring_id == ring_id::WMAC1_SW2RXDMA0_BUF {
                Ok((HttRingType::SwToSw, HttRingId::Host1ToFwRxbuf))
            } else {
                Ok((HttRingType::SwToHw, HttRingId::RxdmaHostBuf))
            }
        }
        HalRingType::RxdmaDst => Ok((HttRingType::HwToSw, HttRingId::RxdmaNonMonitorDest)),
        HalRingType::RxdmaMonitorBuf => Ok((HttRingType::SwToHw, HttRingId::RxdmaMonitorBuf)),
        HalRingType::RxdmaMonitorStatus => Ok((HttRingType::SwToHw, HttRingId::RxdmaMonitorStatus)),
        HalRingType::RxdmaMonitorDst => Ok((HttRingType::HwToSw, HttRingId::RxdmaMonitorDest)),
        HalRingType::RxdmaMonitorDesc => Ok((HttRingType::SwToHw, HttRingId::RxdmaMonitorDesc)),
        _ => Err(TransportError::new(
            step::RING_TYPE,
            ty as u32,
            errno::EINVAL,
        )),
    }
}

fn pdev_field(ring_type: HttRingType, mac_id: u32) -> u32 {
    if matches!(ring_type, HttRingType::SwToHw | HttRingType::HwToSw) {
        dp_sw2hw_macid(mac_id)
    } else {
        mac_id
    }
}

/// Linux `ath11k_dp_tx_htt_srng_setup`: `struct htt_srng_setup_cmd` for
/// HAL ring `ring_id` (an LMAC ring the firmware owns the registers of),
/// from the ring's parameters as the HAL holds them
/// (`ath11k_hal_srng_get_params` + `get_hp_addr` / `get_tp_addr`).
pub fn srng_setup_msg(
    hal: &Hal,
    rx_mac_buf_ring: bool,
    ring_id: u32,
    mac_id: u32,
    ty: HalRingType,
) -> Result<[u8; HTT_SRNG_SETUP_CMD_LEN], TransportError> {
    let s = hal
        .srng(ring_id)
        .ok_or(TransportError::new(step::NO_RING, ring_id, errno::EINVAL))?;
    let hp_addr = hal.get_hp_addr(ring_id);
    let tp_addr = hal.get_tp_addr(ring_id);
    let (htt_ring_type, htt_ring_id) = get_ring_id_type(rx_mac_buf_ring, mac_id, ring_id, ty)?;

    let info0 = field_prep(HTT_SRNG_SETUP_CMD_INFO0_MSG_TYPE, h2t::SRING_SETUP)
        | field_prep(
            HTT_SRNG_SETUP_CMD_INFO0_PDEV_ID,
            pdev_field(htt_ring_type, mac_id),
        )
        | field_prep(HTT_SRNG_SETUP_CMD_INFO0_RING_TYPE, htt_ring_type as u32)
        | field_prep(HTT_SRNG_SETUP_CMD_INFO0_RING_ID, htt_ring_id as u32);

    // ath11k_hal_srng_get_entrysize(ab, ring_type) >> 2
    let ring_entry_sz = hal.entry_size_bytes(ty) >> 2;
    let f = s.flags;
    let mut info1 = field_prep(HTT_SRNG_SETUP_CMD_INFO1_RING_ENTRY_SIZE, ring_entry_sz)
        | field_prep(
            HTT_SRNG_SETUP_CMD_INFO1_RING_SIZE,
            s.num_entries * ring_entry_sz,
        )
        | field_prep(
            HTT_SRNG_SETUP_CMD_INFO1_RING_FLAGS_MSI_SWAP,
            (f & flags::MSI_SWAP != 0) as u32,
        )
        | field_prep(
            HTT_SRNG_SETUP_CMD_INFO1_RING_FLAGS_TLV_SWAP,
            (f & flags::DATA_TLV_SWAP != 0) as u32,
        )
        | field_prep(
            HTT_SRNG_SETUP_CMD_INFO1_RING_FLAGS_HOST_FW_SWAP,
            (f & flags::RING_PTR_SWAP != 0) as u32,
        );
    if htt_ring_type == HttRingType::SwToHw {
        info1 |= HTT_SRNG_SETUP_CMD_INFO1_RING_LOOP_CNT_DIS;
    }

    let intr_info = field_prep(
        HTT_SRNG_SETUP_CMD_INTR_INFO_BATCH_COUNTER_THRESH,
        s.intr_batch_cntr_thres_entries * ring_entry_sz,
    ) | field_prep(
        HTT_SRNG_SETUP_CMD_INTR_INFO_INTR_TIMER_THRESH,
        s.intr_timer_thres_us >> 3,
    );

    // `params.low_threshold` is `srng->u.src_ring.low_threshold` (words).
    let info2 = if f & flags::LOW_THRESH_INTR_EN != 0 {
        field_prep(HTT_SRNG_SETUP_CMD_INFO2_INTR_LOW_THRESH, s.low_threshold)
    } else {
        0
    };

    let w = [
        info0,
        (s.ring_base_paddr & HAL_ADDR_LSB_REG_MASK) as u32,
        (s.ring_base_paddr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
        info1,
        (hp_addr & HAL_ADDR_LSB_REG_MASK) as u32,
        (hp_addr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
        (tp_addr & HAL_ADDR_LSB_REG_MASK) as u32,
        (tp_addr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
        s.msi_addr as u32,
        (s.msi_addr >> 32) as u32,
        s.msi_data,
        intr_info,
        info2,
    ];
    Ok(le_words(&w))
}

/// Linux `ath11k_dp_tx_htt_rx_filter_setup`:
/// `struct htt_rx_ring_selection_cfg_cmd`.
pub fn rx_filter_setup_msg(
    hal: &Hal,
    rx_mac_buf_ring: bool,
    ring_id: u32,
    mac_id: u32,
    ty: HalRingType,
    rx_buf_size: u32,
    tlv_filter: &RxRingTlvFilter,
) -> Result<[u8; HTT_RX_RING_SELECTION_CFG_CMD_LEN], TransportError> {
    let s = hal
        .srng(ring_id)
        .ok_or(TransportError::new(step::NO_RING, ring_id, errno::EINVAL))?;
    let (htt_ring_type, htt_ring_id) = get_ring_id_type(rx_mac_buf_ring, mac_id, ring_id, ty)?;
    let info0 = field_prep(
        HTT_RX_RING_SELECTION_CFG_CMD_INFO0_MSG_TYPE,
        h2t::RX_RING_SELECTION_CFG,
    ) | field_prep(
        HTT_RX_RING_SELECTION_CFG_CMD_INFO0_PDEV_ID,
        pdev_field(htt_ring_type, mac_id),
    ) | field_prep(
        HTT_RX_RING_SELECTION_CFG_CMD_INFO0_RING_ID,
        htt_ring_id as u32,
    ) | field_prep(
        HTT_RX_RING_SELECTION_CFG_CMD_INFO0_SS,
        (s.flags & flags::MSI_SWAP != 0) as u32,
    ) | field_prep(
        HTT_RX_RING_SELECTION_CFG_CMD_INFO0_PS,
        (s.flags & flags::DATA_TLV_SWAP != 0) as u32,
    );
    let w = [
        info0,
        field_prep(HTT_RX_RING_SELECTION_CFG_CMD_INFO1_BUF_SIZE, rx_buf_size),
        tlv_filter.pkt_filter_flags0,
        tlv_filter.pkt_filter_flags1,
        tlv_filter.pkt_filter_flags2,
        tlv_filter.pkt_filter_flags3,
        tlv_filter.rx_filter,
    ];
    Ok(le_words(&w))
}

/// Linux `ath11k_dp_tx_htt_h2t_ppdu_stats_req`: one
/// `struct htt_ppdu_stats_cfg_cmd` per RXDMA of the pdev (pdev mask
/// `1 << (pdev_idx + i)`).
pub fn ppdu_stats_cfg_msgs(pdev_idx: u32, num_rxdma_per_pdev: u32, mask: u32) -> Vec<[u8; 4]> {
    (0..num_rxdma_per_pdev)
        .map(|i| {
            let pdev_mask = 1u32 << (pdev_idx + i);
            (field_prep(HTT_PPDU_STATS_CFG_MSG_TYPE, h2t::PPDU_STATS_CFG)
                | field_prep(HTT_PPDU_STATS_CFG_PDEV_ID, pdev_mask)
                | field_prep(HTT_PPDU_STATS_CFG_TLV_TYPE_BITMASK, mask))
            .to_le_bytes()
        })
        .collect()
}

// ── T2H ───────────────────────────────────────────────────────────

/// A decoded target → host message.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HttT2h {
    VersionConf {
        major: u8,
        minor: u8,
    },
    /// PEER_MAP (v1: `ast_hash` / `hw_peer_id` are 0, as Linux passes)
    /// or PEER_MAP2.
    PeerMap {
        v2: bool,
        vdev_id: u8,
        peer_id: u16,
        mac: [u8; 6],
        ast_hash: u16,
        hw_peer_id: u16,
    },
    PeerUnmap {
        v2: bool,
        peer_id: u16,
    },
    /// PPDU_STATS_IND / EXT_STATS_CONF / PKTLOG / BKPRESSURE_EVENT_IND:
    /// statistics only, skipped.
    Skipped(u8),
    /// Any other type (Linux: "htt event %d not handled").
    Unhandled(u8),
}

fn rd_word(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]])
}

/// `ath11k_dp_get_mac_addr` (little-endian host).
pub fn dp_get_mac_addr(addr_l32: u32, addr_h16: u16) -> [u8; 6] {
    let l = addr_l32.to_le_bytes();
    let h = addr_h16.to_le_bytes();
    [l[0], l[1], l[2], l[3], h[0], h[1]]
}

/// Decode half of Linux `ath11k_dp_htt_htc_t2h_msg_handler` (the
/// message is the HTC payload of the HTT endpoint).
///
/// NARF-stricter: Linux reads the struct fields without a length check;
/// a message shorter than its type's struct (or empty) is rejected.
pub fn decode_t2h(msg: &[u8]) -> Result<HttT2h, TransportError> {
    let short = |ty: u8| {
        TransportError::new(
            step::T2H_TRUNCATED,
            ((ty as u32) << 16) | (msg.len() as u32 & 0xffff),
            errno::EINVAL,
        )
    };
    if msg.len() < 4 {
        return Err(short(msg.first().copied().unwrap_or(0)));
    }
    let w0 = rd_word(msg, 0);
    let ty = field_get(HTT_T2H_MSG_TYPE, w0) as u8;
    let need = |words: usize| {
        if msg.len() < words * 4 {
            Err(short(ty))
        } else {
            Ok(())
        }
    };
    Ok(match ty {
        t2h::VERSION_CONF => HttT2h::VersionConf {
            major: field_get(HTT_T2H_VERSION_CONF_MAJOR, w0) as u8,
            minor: field_get(HTT_T2H_VERSION_CONF_MINOR, w0) as u8,
        },
        t2h::PEER_MAP | t2h::PEER_MAP2 => {
            let v2 = ty == t2h::PEER_MAP2;
            // htt_t2h_peer_map_event: info, mac_addr_l32, info1, info2
            need(if v2 { 4 } else { 3 })?;
            let info1 = rd_word(msg, 2);
            let mac = dp_get_mac_addr(
                rd_word(msg, 1),
                field_get(HTT_T2H_PEER_MAP_INFO1_MAC_ADDR_H16, info1) as u16,
            );
            let (ast_hash, hw_peer_id) = if v2 {
                (
                    field_get(HTT_T2H_PEER_MAP_INFO2_AST_HASH_VAL, rd_word(msg, 3)) as u16,
                    field_get(HTT_T2H_PEER_MAP_INFO1_HW_PEER_ID, info1) as u16,
                )
            } else {
                (0, 0)
            };
            HttT2h::PeerMap {
                v2,
                vdev_id: field_get(HTT_T2H_PEER_MAP_INFO_VDEV_ID, w0) as u8,
                peer_id: field_get(HTT_T2H_PEER_MAP_INFO_PEER_ID, w0) as u16,
                mac,
                ast_hash,
                hw_peer_id,
            }
        }
        t2h::PEER_UNMAP | t2h::PEER_UNMAP2 => HttT2h::PeerUnmap {
            v2: ty == t2h::PEER_UNMAP2,
            peer_id: field_get(HTT_T2H_PEER_UNMAP_INFO_PEER_ID, w0) as u16,
        },
        t2h::PPDU_STATS_IND | t2h::EXT_STATS_CONF | t2h::PKTLOG | t2h::BKPRESSURE_EVENT_IND => {
            HttT2h::Skipped(ty)
        }
        other => HttT2h::Unhandled(other),
    })
}

/// `ath11k_dp` HTT target state: the endpoint and the VERSION_CONF
/// `ath11k_dp_tx_htt_h2t_ver_req_msg` waits for.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HttTarget {
    /// `dp->eid` (HTC endpoint of `ATH11K_HTC_SVC_ID_HTT_DATA_MSG`).
    pub eid: Option<u8>,
    pub ver_major: u8,
    pub ver_minor: u8,
    /// `htt_tgt_version_received` completed.
    pub version_received: bool,
}

impl HttTarget {
    /// Linux's check after the completion: major must be
    /// `HTT_TARGET_VERSION_MAJOR` (else `-EOPNOTSUPP`). `Ok(false)` while
    /// no VERSION_CONF has arrived.
    pub fn version_ok(&self) -> Result<bool, TransportError> {
        if !self.version_received {
            return Ok(false);
        }
        if self.ver_major != HTT_TARGET_VERSION_MAJOR {
            return Err(TransportError::new(
                step::VERSION,
                ((self.ver_major as u32) << 8) | self.ver_minor as u32,
                EOPNOTSUPP,
            ));
        }
        Ok(true)
    }

    /// The caller's wait expired (`wait_for_completion_timeout` == 0).
    pub fn timeout_error() -> TransportError {
        TransportError::new(step::VERSION_TIMEOUT, 0, ETIMEDOUT)
    }
}

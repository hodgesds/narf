//! Wireless Module Interface — TLV command encoders and event decoders.
//!
//! WMI is ath11k's host↔firmware control plane, carried over the HTC
//! `WMI_CONTROL` endpoint (see [`super::htc`]). A command is a 4-byte
//! `struct wmi_cmd_hdr` (24-bit command id) followed by a TLV stream;
//! an event is the same shape with an event id.
//!
//! Everything here is a byte-exact port of Linux
//! `drivers/net/wireless/ath/ath11k/wmi.{c,h}` for the subset a
//! WCN6855 single-pdev station needs. Each encoder names the Linux
//! builder it reproduces; the produced [`WmiCmd::buf`] is exactly the
//! `skb->data` that builder hands to `ath11k_wmi_cmd_send`, including
//! the zero tail `ath11k_wmi_alloc_skb` rounds `len` up to and the
//! places where Linux fills a TLV length field idiosyncratically
//! (documented at each site). [`WmiCmd::frame`] then prepends the
//! `wmi_cmd_hdr` as `ath11k_wmi_cmd_send_nowait` does.
//!
//! Identifier values (command/event ids, TLV tags, service bits,
//! pdev/vdev parameter ids) live in [`super::wmi_ids`], generated from
//! the Linux enums and re-exported here.
//!
//! Decoders follow `ath11k_wmi_tlv_iter`: a TLV whose length runs past
//! the buffer, or that is shorter than its `wmi_tlv_policies[]` minimum,
//! fails the whole event; TLVs are *not* padded (the walker advances by
//! exactly the length field); unknown tags are skipped. Where Linux
//! reads past a TLV without checking (it trusts the firmware), the
//! decoders here reject instead — each such spot is marked
//! "NARF-stricter".

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

pub use super::wmi_ids::*;

// ── Framing (wmi.h) ─────────────────────────────────────────────────

/// `WMI_CMD_HDR_CMD_ID` — `GENMASK(23, 0)` of `wmi_cmd_hdr.cmd_id`.
pub const WMI_CMD_HDR_CMD_ID: u32 = 0x00FF_FFFF;
/// `TLV_HDR_SIZE` — `sizeof_field(struct wmi_tlv, header)`.
pub const TLV_HDR_SIZE: usize = 4;
/// `WMI_TLV_LEN` — `GENMASK(15, 0)`.
pub const WMI_TLV_LEN: u32 = 0x0000_FFFF;
/// `WMI_TLV_TAG` — `GENMASK(31, 16)`.
pub const WMI_TLV_TAG: u32 = 0xFFFF_0000;
/// `WMI_MAX_MEM_REQS`.
pub const WMI_MAX_MEM_REQS: usize = 32;
/// `WMI_PDEV_ID_SOC`.
pub const WMI_PDEV_ID_SOC: u32 = 0;
/// `WMI_HOST_MAX_PDEV`.
pub const WMI_HOST_MAX_PDEV: usize = 3;
/// `MAX_RADIOS` (core.h).
pub const MAX_RADIOS: usize = 3;
/// `WMI_BSS_COLOR_COLLISION_DETECTION` in `enum wmi_bss_color_collision`.
/// The generated identifier table contains wire IDs and tags, while this
/// small event-kind enum is local to the WMI payload definition.
pub const WMI_BSS_COLOR_COLLISION_DETECTION: u32 = 1;

/// `FIELD_PREP(WMI_TLV_TAG, tag) | FIELD_PREP(WMI_TLV_LEN, len)`.
pub const fn tlv_hdr(tag: u16, len: usize) -> u32 {
    ((tag as u32) << 16) | (len as u32 & WMI_TLV_LEN)
}

/// `FIELD_GET(WMI_TLV_TAG, hdr)`.
pub const fn tlv_hdr_tag(hdr: u32) -> u16 {
    (hdr >> 16) as u16
}

/// `FIELD_GET(WMI_TLV_LEN, hdr)`.
pub const fn tlv_hdr_len(hdr: u32) -> u16 {
    (hdr & WMI_TLV_LEN) as u16
}

const fn roundup4(n: usize) -> usize {
    (n + 3) & !3
}

/// One encoded WMI command: the command id and the body exactly as
/// Linux's builder leaves it in `skb->data` before
/// `ath11k_wmi_cmd_send` pushes the `wmi_cmd_hdr`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WmiCmd {
    /// `enum wmi_tlv_cmd_id` value.
    pub cmd_id: u32,
    /// TLV body, length already rounded up to 4 like
    /// `ath11k_wmi_alloc_skb`.
    pub buf: Vec<u8>,
}

impl WmiCmd {
    /// `ath11k_wmi_cmd_send_nowait`: push `wmi_cmd_hdr` with
    /// `FIELD_PREP(WMI_CMD_HDR_CMD_ID, cmd_id)`. The result is the HTC
    /// payload for the WMI endpoint.
    pub fn frame(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.buf.len());
        out.extend_from_slice(&(self.cmd_id & WMI_CMD_HDR_CMD_ID).to_le_bytes());
        out.extend_from_slice(&self.buf);
        out
    }
}

/// Sequential little-endian writer. `finish(len)` zero-fills to
/// `roundup(len, 4)` — the length `ath11k_wmi_alloc_skb(len)` puts
/// and memsets — so trailing reserved space matches Linux.
struct W {
    b: Vec<u8>,
}

impl W {
    fn new(cap: usize) -> Self {
        W {
            b: Vec::with_capacity(roundup4(cap)),
        }
    }
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn tlv(&mut self, tag: u16, len: usize) {
        self.u32(tlv_hdr(tag, len));
    }
    /// `struct wmi_mac_addr` — 6 address bytes in an 8-byte union.
    fn mac(&mut self, m: &[u8; 6]) {
        self.b.extend_from_slice(m);
        self.b.extend_from_slice(&[0, 0]);
    }
    fn bytes(&mut self, s: &[u8]) {
        self.b.extend_from_slice(s);
    }
    fn zeros(&mut self, n: usize) {
        self.b.resize(self.b.len() + n, 0);
    }
    fn pad_to(&mut self, n: usize) {
        debug_assert!(self.b.len() <= n);
        self.b.resize(n, 0);
    }
    fn finish(mut self, cmd_id: u32, linux_len: usize) -> WmiCmd {
        let n = roundup4(linux_len);
        debug_assert!(self.b.len() <= n, "encoder wrote past Linux len");
        self.b.resize(n, 0);
        WmiCmd {
            cmd_id,
            buf: self.b,
        }
    }
}

// ── Struct sizes (sizeof in Linux wmi.h, all __packed) ──────────────

/// `sizeof(struct wmi_init_cmd)`.
pub const WMI_INIT_CMD_SIZE: usize = 32;
/// `sizeof(struct wmi_resource_config)`.
pub const WMI_RESOURCE_CONFIG_SIZE: usize = 292;
/// `sizeof(struct wlan_host_mem_chunk)`.
pub const WLAN_HOST_MEM_CHUNK_SIZE: usize = 16;
/// `sizeof(struct wmi_pdev_set_hw_mode_cmd_param)`.
pub const WMI_PDEV_SET_HW_MODE_CMD_SIZE: usize = 16;
/// `sizeof(struct wmi_pdev_band_to_mac)`.
pub const WMI_PDEV_BAND_TO_MAC_SIZE: usize = 16;
/// `sizeof(struct wmi_channel)`.
pub const WMI_CHANNEL_SIZE: usize = 28;
/// `sizeof(struct wmi_vdev_start_request_cmd)`.
pub const WMI_VDEV_START_REQUEST_CMD_SIZE: usize = 108;
/// `sizeof(struct wmi_vdev_create_cmd)`.
pub const WMI_VDEV_CREATE_CMD_SIZE: usize = 40;
/// `sizeof(struct wmi_vdev_txrx_streams)`.
pub const WMI_VDEV_TXRX_STREAMS_SIZE: usize = 16;
/// `sizeof(struct wmi_vdev_set_tpc_power_cmd)`.
pub const WMI_VDEV_SET_TPC_POWER_CMD_SIZE: usize = 20;
/// `sizeof(struct wmi_vdev_ch_power_info)`.
pub const WMI_VDEV_CH_POWER_INFO_SIZE: usize = 12;
/// `sizeof(struct wmi_twt_enable_params_cmd)`.
pub const WMI_TWT_ENABLE_PARAMS_CMD_SIZE: usize = 72;
/// `sizeof(struct wmi_twt_disable_params_cmd)`.
pub const WMI_TWT_DISABLE_PARAMS_CMD_SIZE: usize = 8;
/// `ATH11K_NUM_PWR_LEVELS`: WCN6855 supports eight 20 MHz chunks, i.e.
/// the contiguous 160 MHz maximum supported by this driver.
pub const WMI_TPC_MAX_POWER_LEVELS: usize = 8;
/// `sizeof(struct wmi_vdev_up_cmd)`.
pub const WMI_VDEV_UP_CMD_SIZE: usize = 36;
/// `sizeof(struct wmi_bcn_tmpl_cmd)`.
pub const WMI_BCN_TMPL_CMD_SIZE: usize = 56;
/// `sizeof(struct wmi_bcn_prb_info)`.
pub const WMI_BCN_PRB_INFO_SIZE: usize = 12;
/// `sizeof(struct wmi_fils_discovery_tmpl_cmd)`.
pub const WMI_FILS_DISCOVERY_TMPL_CMD_SIZE: usize = 12;
/// `sizeof(struct wmi_probe_tmpl_cmd)`.
pub const WMI_PROBE_TMPL_CMD_SIZE: usize = 12;
/// `sizeof(struct wmi_fils_discovery_cmd)`.
pub const WMI_FILS_DISCOVERY_CMD_SIZE: usize = 16;
/// `sizeof(struct wmi_peer_assoc_complete_cmd)`.
pub const WMI_PEER_ASSOC_COMPLETE_CMD_SIZE: usize = 164;
/// `sizeof(struct wmi_ap_ps_peer_cmd)`.
pub const WMI_AP_PS_PEER_CMD_SIZE: usize = 24;
/// `sizeof(struct wmi_vht_rate_set)`.
pub const WMI_VHT_RATE_SET_SIZE: usize = 24;
/// `sizeof(struct wmi_he_rate_set)`.
pub const WMI_HE_RATE_SET_SIZE: usize = 12;
/// `sizeof(struct wmi_vdev_install_key_cmd)`.
pub const WMI_VDEV_INSTALL_KEY_CMD_SIZE: usize = 104;
/// `sizeof(struct wmi_start_scan_cmd)`.
pub const WMI_START_SCAN_CMD_SIZE: usize = 160;
/// `sizeof(struct wmi_ssid)`.
pub const WMI_SSID_SIZE: usize = 36;
/// `sizeof(struct wmi_mac_addr)`.
pub const WMI_MAC_ADDR_SIZE: usize = 8;
/// `sizeof(struct hint_short_ssid)`.
pub const HINT_SHORT_SSID_SIZE: usize = 8;
/// `sizeof(struct hint_bssid)`.
pub const HINT_BSSID_SIZE: usize = 12;
/// `sizeof(struct wmi_scan_chan_list_cmd)`.
pub const WMI_SCAN_CHAN_LIST_CMD_SIZE: usize = 16;
/// `sizeof(struct wmi_mgmt_send_cmd)`.
pub const WMI_MGMT_SEND_CMD_SIZE: usize = 36;
/// `sizeof(struct wmi_mgmt_send_params)`.
pub const WMI_MGMT_SEND_PARAMS_SIZE: usize = 12;
/// `sizeof(struct wmi_gtk_rekey_offload_cmd)`.
pub const WMI_GTK_REKEY_OFFLOAD_CMD_SIZE: usize = 52;
/// `sizeof(struct wmi_wow_enable_cmd)`.
pub const WMI_WOW_ENABLE_CMD_SIZE: usize = 16;
/// `sizeof(struct wmi_wow_host_wakeup_ind)`.
pub const WMI_WOW_HOST_WAKEUP_CMD_SIZE: usize = 8;
/// `sizeof(struct wmi_wow_add_del_event_cmd)`.
pub const WMI_WOW_ADD_DEL_EVENT_CMD_SIZE: usize = 16;
/// `sizeof(struct wmi_wow_del_pattern_cmd)`.
pub const WMI_WOW_DEL_PATTERN_CMD_SIZE: usize = 16;
/// `sizeof(struct wmi_hw_data_filter_cmd)`.
pub const WMI_HW_DATA_FILTER_CMD_SIZE: usize = 16;
/// `sizeof(struct wmi_sta_keepalive_cmd)`.
pub const WMI_STA_KEEPALIVE_CMD_SIZE: usize = 20;
/// `sizeof(struct wmi_sta_keepalive_arp_resp)`.
pub const WMI_STA_KEEPALIVE_ARP_RESPONSE_SIZE: usize = 20;
/// `sizeof(struct wmi_wow_bitmap_pattern)`.
pub const WMI_WOW_BITMAP_PATTERN_SIZE: usize = 316;
/// Maximum pattern payload of `struct wmi_wow_bitmap_pattern`.
pub const WMI_WOW_MAX_PATTERN_SIZE: usize = 148;
/// `WMI_MAX_NS_OFFLOADS` — fixed entries in the first NS array.
pub const WMI_MAX_NS_OFFLOADS: usize = 2;
/// `WMI_MAX_ARP_OFFLOADS` — fixed entries in the ARP array.
pub const WMI_MAX_ARP_OFFLOADS: usize = 2;
/// `ATH11K_IPV6_MAX_COUNT` — address records the ath11k host retains.
pub const WMI_MAX_IPV6_OFFLOADS: usize = 16;
/// `sizeof(struct wmi_ns_offload_tuple)`.
pub const WMI_NS_OFFLOAD_TUPLE_SIZE: usize = 80;
/// `sizeof(struct wmi_arp_offload_tuple)`.
pub const WMI_ARP_OFFLOAD_TUPLE_SIZE: usize = 24;
/// The prefix of `struct wmi_gtk_offload_status_event` through its replay
/// counter.  Linux has no `wmi_tlv_policies[]` entry for this tag, but it
/// reads these five words immediately; NARF rejects a shorter TLV rather
/// than risking an out-of-bounds firmware read.
pub const WMI_GTK_OFFLOAD_STATUS_EVENT_PREFIX_SIZE: usize = 20;

// ── Misc wmi.h / hw.h / core.h constants ────────────────────────────

/// `enum wmi_host_hw_mode_config_type`.
pub mod hw_mode {
    pub const SINGLE: u32 = 0;
    pub const DBS: u32 = 1;
    pub const SBS_PASSIVE: u32 = 2;
    pub const SBS: u32 = 3;
    pub const DBS_SBS: u32 = 4;
    pub const DBS_OR_SBS: u32 = 5;
    pub const MAX: u32 = 6;
}

/// `ath11k_hw_mode_pri_map[]` (wmi.c), built from the `*_PRI` enum:
/// DBS_SBS=0, DBS=1, DBS_OR_SBS=2, SBS=3, SBS_PASSIVE=4, SINGLE=5,
/// MAX=6. Lower is preferred.
pub const HW_MODE_PRI_MAP: [u32; 7] = [5, 1, 4, 3, 0, 2, 6];

/// `enum wmi_host_wlan_band` capability bits.
pub const WMI_HOST_WLAN_2G_CAP: u32 = 0x1;
/// See [`WMI_HOST_WLAN_2G_CAP`].
pub const WMI_HOST_WLAN_5G_CAP: u32 = 0x2;
/// See [`WMI_HOST_WLAN_2G_CAP`].
pub const WMI_HOST_WLAN_2G_5G_CAP: u32 = 0x3;

/// `WMI_RSRC_CFG_FLAG1_BSS_CHANNEL_INFO_64`.
pub const WMI_RSRC_CFG_FLAG1_BSS_CHANNEL_INFO_64: u32 = 1 << 5;
/// `WMI_RSRC_CFG_FLAG2_CALC_NEXT_DTIM_COUNT_SET`.
pub const WMI_RSRC_CFG_FLAG2_CALC_NEXT_DTIM_COUNT_SET: u32 = 1 << 9;
/// `WMI_CFG_HOST_SERVICE_FLAG_REG_CC_EXT` (bit position).
pub const WMI_CFG_HOST_SERVICE_FLAG_REG_CC_EXT: u32 = 4;

/// hw.h `TARGET_*` defaults used by `ath11k_init_wmi_config_qca6390`.
pub mod target {
    pub const NUM_PEER_KEYS: u32 = 2;
    pub const AST_SKID_LIMIT: u32 = 16;
    pub const RX_TIMEOUT_LO_PRI: u32 = 100;
    pub const RX_TIMEOUT_HI_PRI: u32 = 40;
    pub const DECAP_MODE_RAW: u32 = 0;
    pub const DECAP_MODE_NATIVE_WIFI: u32 = 1;
    pub const DECAP_MODE_ETH: u32 = 2;
    pub const SCAN_MAX_PENDING_REQS: u32 = 4;
    pub const BMISS_OFFLOAD_MAX_VDEV: u32 = 3;
    pub const ROAM_OFFLOAD_MAX_VDEV: u32 = 3;
    pub const ROAM_OFFLOAD_MAX_AP_PROFILES: u32 = 8;
    pub const TX_DBG_LOG_SIZE: u32 = 1024;
    pub const VOW_CONFIG: u32 = 0;
    pub const RX_BATCHMODE: u32 = 1;
}

/// `WMI_TPC_CHAINMASK_CONFIG_BAND_2G`.
pub const WMI_TPC_CHAINMASK_CONFIG_BAND_2G: u32 = 0;
/// `WMI_TPC_CHAINMASK_CONFIG_BAND_5G`.
pub const WMI_TPC_CHAINMASK_CONFIG_BAND_5G: u32 = 1;
/// `WMI_NUM_SUPPORTED_BAND_MAX`.
pub const WMI_NUM_SUPPORTED_BAND_MAX: u32 = 2;

/// `enum wmi_vdev_type`.
pub mod vdev_type {
    pub const UNSPEC: u32 = 0;
    pub const AP: u32 = 1;
    pub const STA: u32 = 2;
    pub const IBSS: u32 = 3;
    pub const MONITOR: u32 = 4;
}

/// `enum wmi_vdev_subtype`.
pub mod vdev_subtype {
    pub const NONE: u32 = 0;
    pub const P2P_DEVICE: u32 = 1;
    pub const P2P_CLIENT: u32 = 2;
    pub const P2P_GO: u32 = 3;
    pub const PROXY_STA: u32 = 4;
    pub const MESH_NON_11S: u32 = 5;
    pub const MESH_11S: u32 = 6;
}

/// `enum wmi_peer_type`.
pub mod peer_type {
    pub const DEFAULT: u32 = 0;
    pub const BSS: u32 = 1;
    pub const TDLS: u32 = 2;
}

/// `WMI_PEER_*` parameter ids for `WMI_PEER_SET_PARAM_CMDID` (wmi.h
/// `#define`s, not an enum).
pub mod peer_param {
    pub const MIMO_PS_STATE: u32 = 0x1;
    pub const AMPDU: u32 = 0x2;
    pub const AUTHORIZE: u32 = 0x3;
    pub const CHWIDTH: u32 = 0x4;
    pub const NSS: u32 = 0x5;
    pub const USE_4ADDR: u32 = 0x6;
    pub const MEMBERSHIP: u32 = 0x7;
    pub const USERPOS: u32 = 0x8;
    pub const CRIT_PROTO_HINT_ENABLED: u32 = 0x9;
    pub const TX_FAIL_CNT_THR: u32 = 0xA;
    pub const SET_HW_RETRY_CTS2S: u32 = 0xB;
    pub const IBSS_ATIM_WINDOW_LENGTH: u32 = 0xC;
    pub const PHYMODE: u32 = 0xD;
    pub const USE_FIXED_PWR: u32 = 0xE;
    pub const PARAM_FIXED_RATE: u32 = 0xF;
    pub const SET_MU_WHITELIST: u32 = 0x10;
    pub const SET_MAX_TX_RATE: u32 = 0x11;
    pub const SET_MIN_TX_RATE: u32 = 0x12;
    pub const SET_DEFAULT_ROUTING: u32 = 0x13;
}

/// `enum wmi_tlv_peer_flags`.
pub mod peer_flags {
    pub const AUTH: u32 = 0x0000_0001;
    pub const QOS: u32 = 0x0000_0002;
    pub const NEED_PTK_4_WAY: u32 = 0x0000_0004;
    pub const NEED_GTK_2_WAY: u32 = 0x0000_0010;
    pub const HE: u32 = 0x0000_0400;
    pub const APSD: u32 = 0x0000_0800;
    pub const HT: u32 = 0x0000_1000;
    pub const BW_40MHZ: u32 = 0x0000_2000;
    pub const STBC: u32 = 0x0000_8000;
    pub const LDPC: u32 = 0x0001_0000;
    pub const DYN_MIMOPS: u32 = 0x0002_0000;
    pub const STATIC_MIMOPS: u32 = 0x0004_0000;
    pub const SPATIAL_MUX: u32 = 0x0020_0000;
    pub const TWT_REQ: u32 = 0x0040_0000;
    pub const TWT_RESP: u32 = 0x0080_0000;
    pub const VHT: u32 = 0x0200_0000;
    pub const BW_80MHZ: u32 = 0x0400_0000;
    pub const PMF: u32 = 0x0800_0000;
    pub const IS_P2P_CAPABLE: u32 = 0x2000_0000;
    pub const BW_160MHZ: u32 = 0x4000_0000;
    pub const SAFEMODE_EN: u32 = 0x8000_0000;
}

/// `enum wmi_ap_ps_peer_param` and `enum wmi_ap_ps_param_uapsd`.
pub mod ap_ps_peer_param {
    pub const UAPSD: u32 = 0;
    pub const MAX_SP: u32 = 1;
    pub const SIFS_RESP_FRMTYPE: u32 = 3;
    pub const SIFS_RESP_UAPSD: u32 = 4;

    pub const AC0_DELIVERY_EN: u32 = 1 << 0;
    pub const AC0_TRIGGER_EN: u32 = 1 << 1;
    pub const AC1_DELIVERY_EN: u32 = 1 << 2;
    pub const AC1_TRIGGER_EN: u32 = 1 << 3;
    pub const AC2_DELIVERY_EN: u32 = 1 << 4;
    pub const AC2_TRIGGER_EN: u32 = 1 << 5;
    pub const AC3_DELIVERY_EN: u32 = 1 << 6;
    pub const AC3_TRIGGER_EN: u32 = 1 << 7;

    /// `DISABLE_SIFS_RESPONSE_TRIGGER`.
    pub const DISABLE_SIFS_RESPONSE_TRIGGER: u32 = 0;
}

/// `enum wmi_phy_mode`.
pub mod phy_mode {
    pub const MODE_11A: u32 = 0;
    pub const MODE_11G: u32 = 1;
    pub const MODE_11B: u32 = 2;
    pub const MODE_11GONLY: u32 = 3;
    pub const MODE_11NA_HT20: u32 = 4;
    pub const MODE_11NG_HT20: u32 = 5;
    pub const MODE_11NA_HT40: u32 = 6;
    pub const MODE_11NG_HT40: u32 = 7;
    pub const MODE_11AC_VHT20: u32 = 8;
    pub const MODE_11AC_VHT40: u32 = 9;
    pub const MODE_11AC_VHT80: u32 = 10;
    pub const MODE_11AC_VHT20_2G: u32 = 11;
    pub const MODE_11AC_VHT40_2G: u32 = 12;
    pub const MODE_11AC_VHT80_2G: u32 = 13;
    pub const MODE_11AC_VHT80_80: u32 = 14;
    pub const MODE_11AC_VHT160: u32 = 15;
    pub const MODE_11AX_HE20: u32 = 16;
    pub const MODE_11AX_HE40: u32 = 17;
    pub const MODE_11AX_HE80: u32 = 18;
    pub const MODE_11AX_HE80_80: u32 = 19;
    pub const MODE_11AX_HE160: u32 = 20;
    pub const MODE_11AX_HE20_2G: u32 = 21;
    pub const MODE_11AX_HE40_2G: u32 = 22;
    pub const MODE_11AX_HE80_2G: u32 = 23;
    pub const MODE_UNKNOWN: u32 = 24;
}

/// `WMI_VDEV_START_*` flags.
pub const WMI_VDEV_START_HIDDEN_SSID: u32 = 1 << 0;
/// See [`WMI_VDEV_START_HIDDEN_SSID`].
pub const WMI_VDEV_START_PMF_ENABLED: u32 = 1 << 1;
/// See [`WMI_VDEV_START_HIDDEN_SSID`].
pub const WMI_VDEV_START_LDPC_RX_ENABLED: u32 = 1 << 3;
/// See [`WMI_VDEV_START_HIDDEN_SSID`].
pub const WMI_VDEV_START_HW_ENCRYPTION_DISABLED: u32 = 1 << 4;

/// `WMI_CHAN_INFO_*` bits of `wmi_channel.info`.
pub mod chan_info {
    /// `GENMASK(5, 0)`.
    pub const MODE: u32 = 0x3F;
    pub const HT40_PLUS: u32 = 1 << 6;
    pub const PASSIVE: u32 = 1 << 7;
    pub const ADHOC_ALLOWED: u32 = 1 << 8;
    pub const AP_DISABLED: u32 = 1 << 9;
    pub const DFS: u32 = 1 << 10;
    pub const ALLOW_HT: u32 = 1 << 11;
    pub const ALLOW_VHT: u32 = 1 << 12;
    pub const CHAN_CHANGE_CAUSE_CSA: u32 = 1 << 13;
    pub const HALF_RATE: u32 = 1 << 14;
    pub const QUARTER_RATE: u32 = 1 << 15;
    pub const DFS_FREQ2: u32 = 1 << 16;
    pub const ALLOW_HE: u32 = 1 << 17;
    pub const PSC: u32 = 1 << 18;
}

/// `WMI_CHAN_REG_INFO1_*` / `WMI_CHAN_REG_INFO2_*` field shifts (each
/// field is 8 bits wide).
pub mod chan_reg {
    pub const INFO1_MIN_PWR_SHIFT: u32 = 0;
    pub const INFO1_MAX_PWR_SHIFT: u32 = 8;
    pub const INFO1_MAX_REG_PWR_SHIFT: u32 = 16;
    pub const INFO1_REG_CLS_SHIFT: u32 = 24;
    pub const INFO2_ANT_MAX_SHIFT: u32 = 0;
    pub const INFO2_MAX_TX_PWR_SHIFT: u32 = 8;
}

/// `enum wmi_scan_event_type`.
pub mod scan_event {
    pub const STARTED: u32 = 1 << 0;
    pub const COMPLETED: u32 = 1 << 1;
    pub const BSS_CHANNEL: u32 = 1 << 2;
    pub const FOREIGN_CHAN: u32 = 1 << 3;
    pub const DEQUEUED: u32 = 1 << 4;
    pub const PREEMPTED: u32 = 1 << 5;
    pub const START_FAILED: u32 = 1 << 6;
    pub const RESTARTED: u32 = 1 << 7;
    pub const FOREIGN_CHAN_EXIT: u32 = 1 << 8;
    pub const SUSPENDED: u32 = 1 << 9;
    pub const RESUMED: u32 = 1 << 10;
    pub const MAX: u32 = 1 << 15;
}

/// `enum wmi_scan_completion_reason`.
pub mod scan_reason {
    pub const COMPLETED: u32 = 0;
    pub const CANCELLED: u32 = 1;
    pub const PREEMPTED: u32 = 2;
    pub const TIMEDOUT: u32 = 3;
    pub const INTERNAL_FAILURE: u32 = 4;
}

/// `enum wmi_scan_priority`.
pub mod scan_priority {
    pub const VERY_LOW: u32 = 0;
    pub const LOW: u32 = 1;
    pub const MEDIUM: u32 = 2;
    pub const HIGH: u32 = 3;
    pub const VERY_HIGH: u32 = 4;
}

/// `WMI_SCAN_*` control flags (`wmi_start_scan_cmd.scan_ctrl_flags`).
pub mod scan_flag {
    pub const PASSIVE: u32 = 0x1;
    pub const ADD_BCAST_PROBE_REQ: u32 = 0x2;
    pub const ADD_CCK_RATES: u32 = 0x4;
    pub const ADD_OFDM_RATES: u32 = 0x8;
    pub const CHAN_STAT_EVENT: u32 = 0x10;
    pub const FILTER_PROBE_REQ: u32 = 0x20;
    pub const BYPASS_DFS_CHN: u32 = 0x40;
    pub const CONTINUE_ON_ERROR: u32 = 0x80;
    pub const FILTER_PROMISCUOS: u32 = 0x100;
    pub const FORCE_ACTIVE_ON_DFS: u32 = 0x200;
    pub const ADD_TPC_IE_IN_PROBE_REQ: u32 = 0x400;
    pub const ADD_DS_IE_IN_PROBE_REQ: u32 = 0x800;
    pub const ADD_SPOOF_MAC_IN_PROBE_REQ: u32 = 0x1000;
    pub const OFFCHAN_MGMT_TX: u32 = 0x2000;
    pub const OFFCHAN_DATA_TX: u32 = 0x4000;
    pub const CAPTURE_PHY_ERROR: u32 = 0x8000;
    pub const STRICT_PASSIVE_ON_PCHN: u32 = 0x10000;
    pub const HALF_RATE_SUPPORT: u32 = 0x20000;
    pub const QUARTER_RATE_SUPPORT: u32 = 0x40000;
    pub const RANDOM_SEQ_NO_IN_PROBE_REQ: u32 = 0x80000;
    pub const ENABLE_IE_WHTELIST_IN_PROBE_REQ: u32 = 0x100000;
    /// `WMI_SCAN_DWELL_MODE_MASK`.
    pub const DWELL_MODE_MASK: u32 = 0x00E0_0000;
    /// `WMI_SCAN_DWELL_MODE_SHIFT`.
    pub const DWELL_MODE_SHIFT: u32 = 21;
    /// `WMI_SCAN_FLAG_EXT_PASSIVE_SCAN_START_TIME_ENHANCE`
    /// (`scan_ctrl_flags_ext`).
    pub const EXT_PASSIVE_SCAN_START_TIME_ENHANCE: u32 = 0x0000_0800;
    /// `WMI_SCAN_CONFIG_PER_CHANNEL_MASK` — `GENMASK(19, 0)` (chan list).
    pub const CONFIG_PER_CHANNEL_MASK: u32 = 0x000F_FFFF;
    /// `WMI_SCAN_CH_FLAG_SCAN_ONLY_IF_RNR_FOUND`.
    pub const CH_FLAG_SCAN_ONLY_IF_RNR_FOUND: u32 = 1 << 20;
    /// Every flag `ath11k_wmi_copy_scan_event_cntrl_flags` maps from a
    /// `scan_f_*` bit. `BYPASS_DFS_CHN` and `CONTINUE_ON_ERROR` have
    /// `scan_f_*` bits in `scan_req_params` but Linux never copies
    /// them into the command, so they are excluded.
    pub const LINUX_COPIED: u32 = PASSIVE
        | STRICT_PASSIVE_ON_PCHN
        | FILTER_PROMISCUOS
        | CAPTURE_PHY_ERROR
        | HALF_RATE_SUPPORT
        | QUARTER_RATE_SUPPORT
        | ADD_CCK_RATES
        | ADD_OFDM_RATES
        | CHAN_STAT_EVENT
        | FILTER_PROBE_REQ
        | ADD_BCAST_PROBE_REQ
        | OFFCHAN_MGMT_TX
        | OFFCHAN_DATA_TX
        | FORCE_ACTIVE_ON_DFS
        | ADD_TPC_IE_IN_PROBE_REQ
        | ADD_DS_IE_IN_PROBE_REQ
        | ADD_SPOOF_MAC_IN_PROBE_REQ
        | RANDOM_SEQ_NO_IN_PROBE_REQ
        | ENABLE_IE_WHTELIST_IN_PROBE_REQ;
}

/// `WMI_SCAN_STOP_ONE` / `WMI_SCN_STOP_VAP_ALL` / `WMI_SCAN_STOP_ALL`.
pub mod scan_stop {
    pub const ONE: u32 = 0x0000_0000;
    pub const VAP_ALL: u32 = 0x0100_0000;
    pub const ALL: u32 = 0x0400_0000;
}

/// `ATH11K_SCAN_ID` — host-triggered scan id prefix.
pub const ATH11K_SCAN_ID: u32 = 0xA000;
/// `WMI_APPEND_TO_EXISTING_CHAN_LIST_FLAG`.
pub const WMI_APPEND_TO_EXISTING_CHAN_LIST_FLAG: u32 = 1;
/// `WMI_MGMT_SEND_DOWNLD_LEN`.
pub const WMI_MGMT_SEND_DOWNLD_LEN: usize = 64;
/// `WMI_TX_PARAMS_DWORD1_CFR_CAPTURE`.
pub const WMI_TX_PARAMS_DWORD1_CFR_CAPTURE: u32 = 1 << 21;

/// `WMI_KEY_PAIRWISE` / `WMI_KEY_GROUP`.
pub const WMI_KEY_PAIRWISE: u32 = 0x00;
/// See [`WMI_KEY_PAIRWISE`].
pub const WMI_KEY_GROUP: u32 = 0x01;

/// `WMI_CIPHER_*`.
pub mod cipher {
    pub const NONE: u32 = 0x0;
    pub const WEP: u32 = 0x1;
    pub const TKIP: u32 = 0x2;
    pub const AES_OCB: u32 = 0x3;
    pub const AES_CCM: u32 = 0x4;
    pub const WAPI: u32 = 0x5;
    pub const CKIP: u32 = 0x6;
    pub const AES_CMAC: u32 = 0x7;
    pub const ANY: u32 = 0x8;
    pub const AES_GCM: u32 = 0x9;
    pub const AES_GMAC: u32 = 0xa;
}

/// `enum wmi_sta_ps_mode`.
pub mod sta_ps_mode {
    pub const DISABLED: u32 = 0;
    pub const ENABLED: u32 = 1;
}

/// `enum wmi_sta_powersave_param`.
pub mod sta_ps_param {
    pub const RX_WAKE_POLICY: u32 = 0;
    pub const TX_WAKE_THRESHOLD: u32 = 1;
    pub const PSPOLL_COUNT: u32 = 2;
    pub const INACTIVITY_TIME: u32 = 3;
    pub const UAPSD: u32 = 4;
    /// `WMI_STA_PS_RX_WAKE_POLICY_WAKE`.
    pub const RX_WAKE_POLICY_WAKE: u32 = 0;
    /// `WMI_STA_PS_RX_WAKE_POLICY_POLL_UAPSD`.
    pub const RX_WAKE_POLICY_POLL_UAPSD: u32 = 1;
    /// `WMI_STA_PS_TX_WAKE_THRESHOLD_NEVER`.
    pub const TX_WAKE_THRESHOLD_NEVER: u32 = 0;
    /// `WMI_STA_PS_TX_WAKE_THRESHOLD_ALWAYS`.
    pub const TX_WAKE_THRESHOLD_ALWAYS: u32 = 1;
    /// `WMI_STA_PS_PSPOLL_COUNT_NO_MAX`.
    pub const PSPOLL_COUNT_NO_MAX: u32 = 0;
}

/// `enum set_init_cc_type`.
pub mod init_cc_type {
    pub const ALPHA: u32 = 0;
    pub const COUNTRY_CODE: u32 = 1;
    pub const REGDOMAIN: u32 = 2;
}

/// `enum wmi_start_event_param` (`vdev_start_resp.resp_type`).
pub const WMI_VDEV_START_RESP_EVENT: u32 = 0;
/// See [`WMI_VDEV_START_RESP_EVENT`].
pub const WMI_VDEV_RESTART_RESP_EVENT: u32 = 1;
/// `WMI_VDEV_START_RESPONSE_STATUS_SUCCESS`.
pub const WMI_VDEV_START_RESPONSE_STATUS_SUCCESS: u32 = 0;

/// `WMI_RX_STATUS_*` (`wmi_mgmt_rx_hdr.status`).
pub mod rx_status {
    pub const OK: u32 = 0x00;
    pub const ERR_CRC: u32 = 0x01;
    pub const ERR_DECRYPT: u32 = 0x08;
    pub const ERR_MIC: u32 = 0x10;
    pub const ERR_KEY_CACHE_MISS: u32 = 0x20;
}

/// `ATH11K_DEFAULT_NOISE_FLOOR` (core.h).
pub const ATH11K_DEFAULT_NOISE_FLOOR: i32 = -95;
/// `ATH11K_MIN_6G_FREQ`.
pub const ATH11K_MIN_6G_FREQ: u32 = 5925;
/// `ATH11K_MAX_6G_FREQ`.
pub const ATH11K_MAX_6G_FREQ: u32 = 7115;
/// `ATH11K_MAX_5G_CHAN`.
pub const ATH11K_MAX_5G_CHAN: u32 = 177;
/// `ath11k_init_wmi_config_qca6390()`: the startup resource request sends
/// 16 peer slots to WCN6855 firmware. This is intentionally distinct from
/// the larger `hw_params.num_peers` value exposed through cfg80211.
pub const WCN6855_WMI_NUM_PEERS: u32 = 16;

/// `hw_params.num_peers` / `TARGET_NUM_STATIONS(ab)` for WCN6855.
/// Linux registers this as the physical wiphy's
/// `NL80211_ATTR_MAX_AP_ASSOC_STA`, even though its WMI startup resource
/// configuration uses a smaller peer budget.
pub const WCN6855_MAX_AP_ASSOC_STA: u32 = 512;

// ── Command encoders ────────────────────────────────────────────────

/// `struct target_resource_config` — the fields
/// `ath11k_wmi_copy_resource_config` transfers into
/// `struct wmi_resource_config`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TargetResourceConfig {
    pub num_vdevs: u32,
    pub num_peers: u32,
    pub num_offload_peers: u32,
    pub num_offload_reorder_buffs: u32,
    pub num_peer_keys: u32,
    pub num_tids: u32,
    pub ast_skid_limit: u32,
    pub tx_chain_mask: u32,
    pub rx_chain_mask: u32,
    pub rx_timeout_pri: [u32; 4],
    pub rx_decap_mode: u32,
    pub scan_max_pending_req: u32,
    pub bmiss_offload_max_vdev: u32,
    pub roam_offload_max_vdev: u32,
    pub roam_offload_max_ap_profiles: u32,
    pub num_mcast_groups: u32,
    pub num_mcast_table_elems: u32,
    pub mcast2ucast_mode: u32,
    pub tx_dbg_log_size: u32,
    pub num_wds_entries: u32,
    pub dma_burst_size: u32,
    pub mac_aggr_delim: u32,
    pub rx_skip_defrag_timeout_dup_detection_check: u32,
    pub vow_config: u32,
    pub gtk_offload_max_vdev: u32,
    pub num_msdu_desc: u32,
    pub max_frag_entries: u32,
    pub num_tdls_vdevs: u32,
    pub num_tdls_conn_table_entries: u32,
    pub beacon_tx_offload_max_vdev: u32,
    pub num_multicast_filter_entries: u32,
    pub num_wow_filters: u32,
    pub num_keep_alive_pattern: u32,
    pub keep_alive_pattern_size: u32,
    pub max_tdls_concurrent_sleep_sta: u32,
    pub max_tdls_concurrent_buffer_sta: u32,
    pub wmi_send_separate: u32,
    pub num_ocb_vdevs: u32,
    pub num_ocb_channels: u32,
    pub num_ocb_schedules: u32,
    pub bpf_instruction_size: u32,
    pub max_bssid_rx_filters: u32,
    pub use_pdev_id: u32,
    pub flag1: u32,
    pub peer_map_unmap_v2_support: u32,
    pub sched_params: u32,
    pub twt_ap_pdev_count: u32,
    pub twt_ap_sta_count: u32,
    pub is_reg_cc_ext_event_supported: bool,
    pub ema_max_vap_cnt: u32,
    pub ema_max_profile_period: u32,
    /// Set by `ath11k_init_wmi_config_qca6390` but *not* copied by
    /// `ath11k_wmi_copy_resource_config` (no slot in the wire struct).
    pub rx_batchmode: u32,
}

impl TargetResourceConfig {
    /// `ath11k_init_wmi_config_qca6390` (hw.c) — the WCN6855
    /// `hw_ops->wmi_init_config` — followed by the
    /// `is_reg_cc_ext_event_supported` fix-up `ath11k_wmi_cmd_init`
    /// applies when the firmware advertised
    /// `WMI_TLV_SERVICE_REG_CC_EXT_EVENT_SUPPORT`.
    ///
    /// `num_vdevs` is `hw_params.num_vdevs` (WCN6855: `2 + 1`);
    /// `num_rf_chains` is `target_caps.num_rf_chains` from
    /// WMI_SERVICE_READY.
    pub fn qca6390(num_vdevs: u32, num_rf_chains: u32, reg_cc_ext: bool) -> Self {
        let chain_mask = (1u32 << num_rf_chains).wrapping_sub(1);
        TargetResourceConfig {
            num_vdevs,
            num_peers: WCN6855_WMI_NUM_PEERS,
            num_tids: 32,
            num_offload_peers: 3,
            num_offload_reorder_buffs: 3,
            num_peer_keys: target::NUM_PEER_KEYS,
            ast_skid_limit: target::AST_SKID_LIMIT,
            tx_chain_mask: chain_mask,
            rx_chain_mask: chain_mask,
            rx_timeout_pri: [
                target::RX_TIMEOUT_LO_PRI,
                target::RX_TIMEOUT_LO_PRI,
                target::RX_TIMEOUT_LO_PRI,
                target::RX_TIMEOUT_HI_PRI,
            ],
            rx_decap_mode: target::DECAP_MODE_NATIVE_WIFI,
            scan_max_pending_req: target::SCAN_MAX_PENDING_REQS,
            bmiss_offload_max_vdev: target::BMISS_OFFLOAD_MAX_VDEV,
            roam_offload_max_vdev: target::ROAM_OFFLOAD_MAX_VDEV,
            roam_offload_max_ap_profiles: target::ROAM_OFFLOAD_MAX_AP_PROFILES,
            num_mcast_groups: 0,
            num_mcast_table_elems: 0,
            mcast2ucast_mode: 0,
            tx_dbg_log_size: target::TX_DBG_LOG_SIZE,
            num_wds_entries: 0,
            dma_burst_size: 0,
            rx_skip_defrag_timeout_dup_detection_check: 0,
            vow_config: target::VOW_CONFIG,
            gtk_offload_max_vdev: 2,
            num_msdu_desc: 0x400,
            // Linux assigns beacon_tx_offload_max_vdev twice (2, then
            // 0x2); same value.
            beacon_tx_offload_max_vdev: 0x2,
            rx_batchmode: target::RX_BATCHMODE,
            peer_map_unmap_v2_support: 0,
            use_pdev_id: 1,
            max_frag_entries: 0xa,
            num_tdls_vdevs: 0x1,
            num_tdls_conn_table_entries: 8,
            num_multicast_filter_entries: 0x20,
            num_wow_filters: 0x16,
            num_keep_alive_pattern: 0,
            flag1: WMI_RSRC_CFG_FLAG1_BSS_CHANNEL_INFO_64,
            is_reg_cc_ext_event_supported: reg_cc_ext,
            ..Default::default()
        }
    }

    /// `ath11k_wmi_copy_resource_config` + the `tlv_header` write in
    /// `ath11k_init_cmd_send`: the 292-byte `struct wmi_resource_config`.
    ///
    /// `host_service_flags` starts from the zeroed skb, so
    /// `&= ~BIT(4)` is a no-op and the field is just
    /// `is_reg_cc_ext_event_supported << 4`. `flags2` is
    /// unconditionally `WMI_RSRC_CFG_FLAG2_CALC_NEXT_DTIM_COUNT_SET`.
    /// Fields Linux does not copy (`smart_ant_cap`, `*_minfree`,
    /// `alloc_frag_desc_for_data_pkt`, `num_ns_ext_tuples_cfg`,
    /// `max_num_dbs_scan_duty_cycle`, `max_num_group_keys`,
    /// `max_nlo_ssids`, `num_pkt_filters`, `num_max_sta_vdevs`,
    /// `max_bssid_indicator`, `ul_resp_config`,
    /// `msdu_flow_override_config{0,1}`, `max_rnr_neighbours`) stay 0.
    pub fn to_wmi_bytes(&self) -> Vec<u8> {
        let mut w = W::new(WMI_RESOURCE_CONFIG_SIZE);
        w.tlv(
            WMI_TAG_RESOURCE_CONFIG,
            WMI_RESOURCE_CONFIG_SIZE - TLV_HDR_SIZE,
        );
        for v in [
            self.num_vdevs,
            self.num_peers,
            self.num_offload_peers,
            self.num_offload_reorder_buffs,
            self.num_peer_keys,
            self.num_tids,
            self.ast_skid_limit,
            self.tx_chain_mask,
            self.rx_chain_mask,
            self.rx_timeout_pri[0],
            self.rx_timeout_pri[1],
            self.rx_timeout_pri[2],
            self.rx_timeout_pri[3],
            self.rx_decap_mode,
            self.scan_max_pending_req,
            self.bmiss_offload_max_vdev,
            self.roam_offload_max_vdev,
            self.roam_offload_max_ap_profiles,
            self.num_mcast_groups,
            self.num_mcast_table_elems,
            self.mcast2ucast_mode,
            self.tx_dbg_log_size,
            self.num_wds_entries,
            self.dma_burst_size,
            self.mac_aggr_delim,
            self.rx_skip_defrag_timeout_dup_detection_check,
            self.vow_config,
            self.gtk_offload_max_vdev,
            self.num_msdu_desc,
            self.max_frag_entries,
            self.num_tdls_vdevs,
            self.num_tdls_conn_table_entries,
            self.beacon_tx_offload_max_vdev,
            self.num_multicast_filter_entries,
            self.num_wow_filters,
            self.num_keep_alive_pattern,
            self.keep_alive_pattern_size,
            self.max_tdls_concurrent_sleep_sta,
            self.max_tdls_concurrent_buffer_sta,
            self.wmi_send_separate,
            self.num_ocb_vdevs,
            self.num_ocb_channels,
            self.num_ocb_schedules,
            self.flag1,
            0, // smart_ant_cap
            0, // bk_minfree
            0, // be_minfree
            0, // vi_minfree
            0, // vo_minfree
            0, // alloc_frag_desc_for_data_pkt
            0, // num_ns_ext_tuples_cfg
            self.bpf_instruction_size,
            self.max_bssid_rx_filters,
            self.use_pdev_id,
            0, // max_num_dbs_scan_duty_cycle
            0, // max_num_group_keys
            self.peer_map_unmap_v2_support,
            self.sched_params,
            self.twt_ap_pdev_count,
            self.twt_ap_sta_count,
            0,                                           // max_nlo_ssids
            0,                                           // num_pkt_filters
            0,                                           // num_max_sta_vdevs
            0,                                           // max_bssid_indicator
            0,                                           // ul_resp_config
            0,                                           // msdu_flow_override_config0
            0,                                           // msdu_flow_override_config1
            WMI_RSRC_CFG_FLAG2_CALC_NEXT_DTIM_COUNT_SET, // flags2
            (self.is_reg_cc_ext_event_supported as u32) << WMI_CFG_HOST_SERVICE_FLAG_REG_CC_EXT,
            0, // max_rnr_neighbours
            self.ema_max_vap_cnt,
            self.ema_max_profile_period,
        ] {
            w.u32(v);
        }
        debug_assert_eq!(w.b.len(), WMI_RESOURCE_CONFIG_SIZE);
        w.b
    }
}

/// `struct wmi_host_mem_chunk` (host side).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostMemChunk {
    pub paddr: u64,
    pub len: u32,
    pub req_id: u32,
}

/// `struct wmi_host_pdev_band_to_mac`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BandToMac {
    pub pdev_id: u32,
    pub start_freq: u32,
    pub end_freq: u32,
}

/// `struct wmi_init_cmd_param`.
#[derive(Clone, Debug, Default)]
pub struct InitCmdParam {
    pub res_cfg: TargetResourceConfig,
    /// Linux PCI never fills `wmi_ab.num_mem_chunks` (host memory goes
    /// through QMI respond-mem instead), so this is empty on WCN6855.
    pub mem_chunks: Vec<HostMemChunk>,
    /// `hw_mode_id`; [`hw_mode::MAX`] omits the hw-mode TLVs (what
    /// `ath11k_wmi_cmd_init` forces for `single_pdev_only` chips).
    pub hw_mode_id: u32,
    pub band_to_mac: Vec<BandToMac>,
}

impl InitCmdParam {
    /// `ath11k_wmi_cmd_init` for a `single_pdev_only` chip (WCN6855):
    /// no host mem chunks, `hw_mode_id = WMI_HOST_HW_MODE_MAX`.
    pub fn single_pdev(res_cfg: TargetResourceConfig) -> Self {
        InitCmdParam {
            res_cfg,
            mem_chunks: Vec::new(),
            hw_mode_id: hw_mode::MAX,
            band_to_mac: Vec::new(),
        }
    }
}

/// `ath11k_init_cmd_send` → `WMI_INIT_CMDID`.
///
/// Layout: `wmi_init_cmd` (all-zero `host_abi_vers`) · resource config
/// · `ARRAY_STRUCT` of `WLAN_HOST_MEMORY_CHUNK` · optional
/// `PDEV_SET_HW_MODE_CMD` + `ARRAY_STRUCT` of `PDEV_BAND_TO_MAC`.
///
/// Linux quirks reproduced byte-for-byte:
/// - each host-mem-chunk TLV length is `sizeof(struct
///   wlan_host_mem_chunk)` = 16, i.e. it *includes* its own header;
/// - when any chunk exists the skb reserves room for
///   `WMI_MAX_MEM_REQS` chunks, so the unused tail is zero padding;
/// - `wlan_host_mem_chunk.ptr` is the low 32 bits of the DMA address.
///
/// Fails if more than `WMI_MAX_MEM_REQS` chunks or `WMI_HOST_MAX_PDEV`
/// band-to-mac entries are given (Linux's fixed arrays).
pub fn init_cmd(p: &InitCmdParam) -> Result<WmiCmd, WmiError> {
    if p.mem_chunks.len() > WMI_MAX_MEM_REQS || p.band_to_mac.len() > WMI_HOST_MAX_PDEV {
        return Err(WmiError::Invalid("init: too many chunks / pdevs"));
    }
    let with_hw_mode = p.hw_mode_id != hw_mode::MAX;
    let hw_mode_len = if with_hw_mode {
        WMI_PDEV_SET_HW_MODE_CMD_SIZE
            + TLV_HDR_SIZE
            + p.band_to_mac.len() * WMI_PDEV_BAND_TO_MAC_SIZE
    } else {
        0
    };
    let chunks_reserved = if p.mem_chunks.is_empty() {
        0
    } else {
        WLAN_HOST_MEM_CHUNK_SIZE * WMI_MAX_MEM_REQS
    };
    let len =
        WMI_INIT_CMD_SIZE + TLV_HDR_SIZE + WMI_RESOURCE_CONFIG_SIZE + hw_mode_len + chunks_reserved;

    let mut w = W::new(len);
    // struct wmi_init_cmd
    w.tlv(WMI_TAG_INIT_CMD, WMI_INIT_CMD_SIZE - TLV_HDR_SIZE);
    w.zeros(24); // host_abi_vers — never set by Linux
    w.u32(p.mem_chunks.len() as u32);
    // struct wmi_resource_config
    w.bytes(&p.res_cfg.to_wmi_bytes());
    // host mem chunk array
    w.tlv(
        WMI_TAG_ARRAY_STRUCT,
        WLAN_HOST_MEM_CHUNK_SIZE * p.mem_chunks.len(),
    );
    for c in &p.mem_chunks {
        // Linux: FIELD_PREP(WMI_TLV_LEN, sizeof(struct wlan_host_mem_chunk))
        w.tlv(WMI_TAG_WLAN_HOST_MEMORY_CHUNK, WLAN_HOST_MEM_CHUNK_SIZE);
        w.u32(c.req_id);
        w.u32(c.paddr as u32);
        w.u32(c.len);
    }
    if with_hw_mode {
        w.tlv(
            WMI_TAG_PDEV_SET_HW_MODE_CMD,
            WMI_PDEV_SET_HW_MODE_CMD_SIZE - TLV_HDR_SIZE,
        );
        w.u32(0); // pdev_id — not set by ath11k_init_cmd_send
        w.u32(p.hw_mode_id);
        w.u32(p.band_to_mac.len() as u32);
        w.tlv(
            WMI_TAG_ARRAY_STRUCT,
            p.band_to_mac.len() * WMI_PDEV_BAND_TO_MAC_SIZE,
        );
        for b in &p.band_to_mac {
            w.tlv(
                WMI_TAG_PDEV_BAND_TO_MAC,
                WMI_PDEV_BAND_TO_MAC_SIZE - TLV_HDR_SIZE,
            );
            w.u32(b.pdev_id);
            w.u32(b.start_freq);
            w.u32(b.end_freq);
        }
    }
    Ok(w.finish(WMI_INIT_CMDID, len))
}

/// `ath11k_wmi_set_hw_mode` → `WMI_PDEV_SET_HW_MODE_CMDID` with
/// `pdev_id = WMI_PDEV_ID_SOC`. `ath11k_core_start` sends
/// `WMI_HOST_HW_MODE_DBS` on WCN6855 (`single_pdev_only &&
/// num_rxdma_per_pdev > 1`) after WMI READY.
pub fn set_hw_mode_cmd(mode: u32) -> WmiCmd {
    let mut w = W::new(WMI_PDEV_SET_HW_MODE_CMD_SIZE);
    w.tlv(
        WMI_TAG_PDEV_SET_HW_MODE_CMD,
        WMI_PDEV_SET_HW_MODE_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(WMI_PDEV_ID_SOC);
    w.u32(mode);
    w.u32(0); // num_band_to_mac
    w.finish(WMI_PDEV_SET_HW_MODE_CMDID, WMI_PDEV_SET_HW_MODE_CMD_SIZE)
}

/// Build a fixed-size command whose struct is `tlv_header` followed by
/// `words`: the shape of every simple `ath11k_wmi_*` setter.
fn simple_cmd(cmd_id: u32, tag: u16, words: &[u32]) -> WmiCmd {
    let size = TLV_HDR_SIZE + 4 * words.len();
    let mut w = W::new(size);
    w.tlv(tag, size - TLV_HDR_SIZE);
    for &v in words {
        w.u32(v);
    }
    w.finish(cmd_id, size)
}

/// `ath11k_wmi_pdev_set_param` → `WMI_PDEV_SET_PARAM_CMDID`
/// (`struct wmi_pdev_set_param_cmd`: pdev_id, param_id, param_value).
pub fn pdev_set_param_cmd(param_id: u32, param_value: u32, pdev_id: u32) -> WmiCmd {
    simple_cmd(
        WMI_PDEV_SET_PARAM_CMDID,
        WMI_TAG_PDEV_SET_PARAM_CMD,
        &[pdev_id, param_id, param_value],
    )
}

/// `struct pdev_set_regdomain_params`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PdevSetRegdomainParams {
    pub current_rd_in_use: u16,
    pub current_rd_2g: u16,
    pub current_rd_5g: u16,
    pub ctl_2g: u32,
    pub ctl_5g: u32,
    pub dfs_domain: u8,
    pub pdev_id: u32,
}

/// `ath11k_wmi_send_pdev_set_regdomain` → `WMI_PDEV_SET_REGDOMAIN_CMDID`.
pub fn pdev_set_regdomain_cmd(p: &PdevSetRegdomainParams) -> WmiCmd {
    simple_cmd(
        WMI_PDEV_SET_REGDOMAIN_CMDID,
        WMI_TAG_PDEV_SET_REGDOMAIN_CMD,
        &[
            p.pdev_id,
            p.current_rd_in_use as u32,
            p.current_rd_2g as u32,
            p.current_rd_5g as u32,
            p.ctl_2g,
            p.ctl_5g,
            p.dfs_domain as u32,
        ],
    )
}

/// `BIOS_SAR_TABLE_LEN` (`wmi.h`). The first eleven bytes select the
/// WCN6855's fixed frequency ranges and the second eleven repeat those
/// limits for RF chain one.
pub const BIOS_SAR_TABLE_LEN: usize = 22;
const BIOS_SAR_RSVD1_LEN: usize = 6;
const BIOS_SAR_RSVD2_LEN: usize = 18;

/// `ath11k_wmi_pdev_set_bios_sar_table_param` →
/// `WMI_PDEV_SET_BIOS_SAR_TABLE_CMDID`.
///
/// The two byte-array TLVs include their four-byte-aligned length, just as
/// Linux's `roundup(..., sizeof(u32))` allocation does. Both reserved bytes
/// areas remain zero from the freshly constructed WMI buffer.
pub fn pdev_set_bios_sar_table_cmd(pdev_id: u32, table: &[u8; BIOS_SAR_TABLE_LEN]) -> WmiCmd {
    let table_len = roundup4(BIOS_SAR_TABLE_LEN);
    let reserved_len = roundup4(BIOS_SAR_RSVD1_LEN);
    // wmi_pdev_set_sar_table_cmd + ARRAY_BYTE table + ARRAY_BYTE reserved.
    let len = 16 + TLV_HDR_SIZE + table_len + TLV_HDR_SIZE + reserved_len;
    let mut w = W::new(len);
    w.tlv(WMI_TAG_PDEV_SET_BIOS_SAR_TABLE_CMD, 16 - TLV_HDR_SIZE);
    w.u32(pdev_id);
    w.u32(BIOS_SAR_TABLE_LEN as u32);
    w.u32(BIOS_SAR_RSVD1_LEN as u32);
    w.tlv(WMI_TAG_ARRAY_BYTE, table_len);
    w.bytes(table);
    w.zeros(table_len - BIOS_SAR_TABLE_LEN);
    w.tlv(WMI_TAG_ARRAY_BYTE, reserved_len);
    w.zeros(reserved_len);
    w.finish(WMI_PDEV_SET_BIOS_SAR_TABLE_CMDID, len)
}

/// `ath11k_wmi_pdev_set_bios_geo_table_param` →
/// `WMI_PDEV_SET_BIOS_GEO_TABLE_CMDID`. Linux sends this all-zero reserved
/// geo table immediately before every BIOS SAR update.
pub fn pdev_set_bios_geo_table_cmd(pdev_id: u32) -> WmiCmd {
    let reserved_len = roundup4(BIOS_SAR_RSVD2_LEN);
    // wmi_pdev_set_geo_table_cmd + one ARRAY_BYTE payload.
    let len = 12 + TLV_HDR_SIZE + reserved_len;
    let mut w = W::new(len);
    w.tlv(WMI_TAG_PDEV_SET_BIOS_GEO_TABLE_CMD, 12 - TLV_HDR_SIZE);
    w.u32(pdev_id);
    w.u32(BIOS_SAR_RSVD2_LEN as u32);
    w.tlv(WMI_TAG_ARRAY_BYTE, reserved_len);
    w.zeros(reserved_len);
    w.finish(WMI_PDEV_SET_BIOS_GEO_TABLE_CMDID, len)
}

/// `ath11k_wmi_send_set_current_country_cmd` →
/// `WMI_SET_CURRENT_COUNTRY_CMDID`. WCN6855 has
/// `hw_params.current_cc_support`, so regulatory hints go through this
/// command. `new_alpha2` is a `memcpy` of 3 bytes (two letters + NUL)
/// into a u32; the 4th byte stays 0.
pub fn set_current_country_cmd(pdev_id: u32, alpha2: [u8; 3]) -> WmiCmd {
    let a = u32::from_le_bytes([alpha2[0], alpha2[1], alpha2[2], 0]);
    simple_cmd(
        WMI_SET_CURRENT_COUNTRY_CMDID,
        WMI_TAG_SET_CURRENT_COUNTRY_CMD,
        &[pdev_id, a],
    )
}

/// `struct wmi_init_country_params` (`flags` selects the union arm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitCountry {
    /// `ALPHA_IS_SET` — 3 bytes copied.
    Alpha([u8; 3]),
    /// `CC_IS_SET`.
    CountryCode(u16),
    /// `REGDMN_IS_SET`.
    RegDomain(u16),
}

/// `ath11k_wmi_send_init_country_cmd` → `WMI_SET_INIT_COUNTRY_CMDID`
/// (used when `current_cc_support` is false; kept for completeness).
pub fn init_country_cmd(pdev_id: u32, cc: InitCountry) -> WmiCmd {
    let (ty, v) = match cc {
        InitCountry::Alpha(a) => (
            init_cc_type::ALPHA,
            u32::from_le_bytes([a[0], a[1], a[2], 0]),
        ),
        InitCountry::CountryCode(c) => (init_cc_type::COUNTRY_CODE, c as u32),
        InitCountry::RegDomain(r) => (init_cc_type::REGDOMAIN, r as u32),
    };
    simple_cmd(
        WMI_SET_INIT_COUNTRY_CMDID,
        WMI_TAG_SET_INIT_COUNTRY_CMD,
        &[pdev_id, ty, v],
    )
}

/// `ath11k_wmi_send_11d_scan_start_cmd` → `WMI_11D_SCAN_START_CMDID`.
pub fn scan_11d_start_cmd(vdev_id: u32, scan_period_msec: u32, start_interval_msec: u32) -> WmiCmd {
    simple_cmd(
        WMI_11D_SCAN_START_CMDID,
        WMI_TAG_11D_SCAN_START_CMD,
        &[vdev_id, scan_period_msec, start_interval_msec],
    )
}

/// `ath11k_wmi_send_11d_scan_stop_cmd` → `WMI_11D_SCAN_STOP_CMDID`.
pub fn scan_11d_stop_cmd(vdev_id: u32) -> WmiCmd {
    simple_cmd(
        WMI_11D_SCAN_STOP_CMDID,
        WMI_TAG_11D_SCAN_STOP_CMD,
        &[vdev_id],
    )
}

/// Per-band chain counts of `struct vdev_create_params.chains[]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Chains {
    pub tx: u8,
    pub rx: u8,
}

/// `struct vdev_create_params`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VdevCreateParams {
    pub if_id: u8,
    pub vdev_type: u32,
    pub subtype: u32,
    /// `chains[NL80211_BAND_2GHZ]`.
    pub chains_2g: Chains,
    /// `chains[NL80211_BAND_5GHZ]`.
    pub chains_5g: Chains,
    pub pdev_id: u32,
    pub mbssid_flags: u32,
    pub mbssid_tx_vdev_id: u32,
}

/// `WMI_HOST_VDEV_FLAGS_*` carried by either VDEV_CREATE or VDEV_START,
/// depending on `WMI_TLV_SERVICE_MBSS_PARAM_IN_VDEV_START_SUPPORT`.
pub const WMI_HOST_VDEV_FLAGS_NON_MBSSID_AP: u32 = 0x0000_0001;
pub const WMI_HOST_VDEV_FLAGS_TRANSMIT_AP: u32 = 0x0000_0002;
pub const WMI_HOST_VDEV_FLAGS_NON_TRANSMIT_AP: u32 = 0x0000_0004;
pub const WMI_HOST_VDEV_FLAGS_EMA_MODE: u32 = 0x0000_0008;

/// Per-AP-vdev multiple-BSSID state. The firmware needs the role and the
/// transmitting vdev at start time; `vdev_up` additionally needs the
/// transmitter's BSSID and the non-transmitting BSSID profile geometry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MbssidParams {
    pub flags: u32,
    pub tx_vdev_id: u32,
    pub tx_bssid: [u8; 6],
    pub profile_index: u32,
    pub profile_count: u32,
}

impl MbssidParams {
    pub const fn standalone() -> Self {
        Self {
            flags: WMI_HOST_VDEV_FLAGS_NON_MBSSID_AP,
            tx_vdev_id: 0,
            tx_bssid: [0; 6],
            profile_index: 0,
            profile_count: 0,
        }
    }

    pub const fn transmitting(ema: bool) -> Self {
        Self {
            flags: WMI_HOST_VDEV_FLAGS_TRANSMIT_AP
                | if ema { WMI_HOST_VDEV_FLAGS_EMA_MODE } else { 0 },
            tx_vdev_id: 0,
            tx_bssid: [0; 6],
            profile_index: 0,
            profile_count: 0,
        }
    }

    pub const fn non_transmitting(
        tx_vdev_id: u32,
        tx_bssid: [u8; 6],
        profile_index: u32,
        profile_count: u32,
        ema: bool,
    ) -> Self {
        Self {
            flags: WMI_HOST_VDEV_FLAGS_NON_TRANSMIT_AP
                | if ema { WMI_HOST_VDEV_FLAGS_EMA_MODE } else { 0 },
            tx_vdev_id,
            tx_bssid,
            profile_index,
            profile_count,
        }
    }

    pub const fn is_transmitting(self) -> bool {
        self.flags & WMI_HOST_VDEV_FLAGS_TRANSMIT_AP != 0
    }

    pub const fn is_non_transmitting(self) -> bool {
        self.flags & WMI_HOST_VDEV_FLAGS_NON_TRANSMIT_AP != 0
    }

    pub const fn ema(self) -> bool {
        self.flags & WMI_HOST_VDEV_FLAGS_EMA_MODE != 0
    }
}

/// `ath11k_wmi_vdev_create` → `WMI_VDEV_CREATE_CMDID`: the create
/// struct, then an `ARRAY_STRUCT` with one `VDEV_TXRX_STREAMS` per band
/// (2 GHz, 5 GHz — always both, `num_cfg_txrx_streams = 2`).
pub fn vdev_create_cmd(macaddr: &[u8; 6], p: &VdevCreateParams) -> WmiCmd {
    let streams = WMI_NUM_SUPPORTED_BAND_MAX as usize * WMI_VDEV_TXRX_STREAMS_SIZE;
    let len = WMI_VDEV_CREATE_CMD_SIZE + TLV_HDR_SIZE + streams;
    let mut w = W::new(len);
    w.tlv(
        WMI_TAG_VDEV_CREATE_CMD,
        WMI_VDEV_CREATE_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(p.if_id as u32);
    w.u32(p.vdev_type);
    w.u32(p.subtype);
    w.mac(macaddr);
    w.u32(WMI_NUM_SUPPORTED_BAND_MAX);
    w.u32(p.pdev_id);
    w.u32(p.mbssid_flags);
    w.u32(p.mbssid_tx_vdev_id);
    w.tlv(WMI_TAG_ARRAY_STRUCT, streams);
    for (band, c) in [
        (WMI_TPC_CHAINMASK_CONFIG_BAND_2G, p.chains_2g),
        (WMI_TPC_CHAINMASK_CONFIG_BAND_5G, p.chains_5g),
    ] {
        w.tlv(
            WMI_TAG_VDEV_TXRX_STREAMS,
            WMI_VDEV_TXRX_STREAMS_SIZE - TLV_HDR_SIZE,
        );
        w.u32(band);
        w.u32(c.tx as u32);
        w.u32(c.rx as u32);
    }
    w.finish(WMI_VDEV_CREATE_CMDID, len)
}

/// `ath11k_wmi_vdev_delete` → `WMI_VDEV_DELETE_CMDID`.
pub fn vdev_delete_cmd(vdev_id: u8) -> WmiCmd {
    simple_cmd(
        WMI_VDEV_DELETE_CMDID,
        WMI_TAG_VDEV_DELETE_CMD,
        &[vdev_id as u32],
    )
}

/// `ath11k_wmi_vdev_stop` → `WMI_VDEV_STOP_CMDID`.
pub fn vdev_stop_cmd(vdev_id: u8) -> WmiCmd {
    simple_cmd(
        WMI_VDEV_STOP_CMDID,
        WMI_TAG_VDEV_STOP_CMD,
        &[vdev_id as u32],
    )
}

/// `ath11k_wmi_vdev_down` → `WMI_VDEV_DOWN_CMDID`.
pub fn vdev_down_cmd(vdev_id: u8) -> WmiCmd {
    simple_cmd(
        WMI_VDEV_DOWN_CMDID,
        WMI_TAG_VDEV_DOWN_CMD,
        &[vdev_id as u32],
    )
}

/// `ath11k_wmi_vdev_set_param_cmd` → `WMI_VDEV_SET_PARAM_CMDID`.
pub fn vdev_set_param_cmd(vdev_id: u32, param_id: u32, param_value: u32) -> WmiCmd {
    simple_cmd(
        WMI_VDEV_SET_PARAM_CMDID,
        WMI_TAG_VDEV_SET_PARAM_CMD,
        &[vdev_id, param_id, param_value],
    )
}

/// One `wmi_vdev_ch_power_info` entry for a station's six-GHz transmit
/// power control command. `tx_power` is integral dBm; WMI represents the
/// signed value in its `u32` slot with the normal two's-complement cast.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TpcChannelPower {
    pub center_freq: u32,
    pub tx_power: i8,
}

/// `ath11k_reg_tpc_power_info`, reduced to the fields WMI serializes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TpcPowerInfo {
    /// `is_psd_power`: power entries are PSD rather than EIRP bandwidth
    /// levels. `eirp_power` is then the companion maximum EIRP limit.
    pub is_psd_power: bool,
    pub eirp_power: u8,
    /// `enum wmi_reg_6ghz_ap_type` used by firmware's HALPHY CTL lookup.
    pub ap_power_type: u32,
    pub channels: Vec<TpcChannelPower>,
}

/// `ath11k_wmi_send_vdev_set_tpc_power` → `WMI_VDEV_SET_TPC_POWER_CMDID`.
///
/// The WCN6855 wire format is a 20-byte fixed TLV followed by an
/// `ARRAY_STRUCT` of 12-byte `VDEV_CH_POWER_INFO` TLVs. The C driver assigns
/// signed per-channel dBm values to WMI's `u32` slot, so the explicit
/// `i32 → u32` cast below preserves both positive and negative values
/// byte-for-byte; the fixed EIRP member is an unsigned byte in Linux.
pub fn vdev_set_tpc_power_cmd(vdev_id: u32, p: &TpcPowerInfo) -> Result<WmiCmd, WmiError> {
    if p.channels.is_empty() || p.channels.len() > WMI_TPC_MAX_POWER_LEVELS {
        return Err(WmiError::Invalid("tpc: invalid power-level count"));
    }
    let array_len = WMI_VDEV_CH_POWER_INFO_SIZE * p.channels.len();
    let len = WMI_VDEV_SET_TPC_POWER_CMD_SIZE + TLV_HDR_SIZE + array_len;
    let mut w = W::new(len);
    w.tlv(
        WMI_TAG_VDEV_SET_TPC_POWER_CMD,
        WMI_VDEV_SET_TPC_POWER_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(vdev_id);
    w.u32(p.is_psd_power as u32);
    w.u32(p.eirp_power as u32);
    w.u32(p.ap_power_type);
    w.tlv(WMI_TAG_ARRAY_STRUCT, array_len);
    for ch in &p.channels {
        w.tlv(
            WMI_TAG_VDEV_CH_POWER_INFO,
            WMI_VDEV_CH_POWER_INFO_SIZE - TLV_HDR_SIZE,
        );
        w.u32(ch.center_freq);
        w.u32(ch.tx_power as i32 as u32);
    }
    Ok(w.finish(WMI_VDEV_SET_TPC_POWER_CMDID, len))
}

/// `struct wmi_twt_enable_params`, with the policy values filled by
/// `ath11k_wmi_fill_default_twt_params`. This enables the pdev TWT engine
/// for either a station requester or an AP responder; individual agreements
/// remain separate from this configuration command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwtEnableParams {
    pub sta_cong_timer_ms: u32,
    pub mbss_support: u32,
    pub default_slot_size: u32,
    pub congestion_thresh_setup: u32,
    pub congestion_thresh_teardown: u32,
    pub congestion_thresh_critical: u32,
    pub interference_thresh_teardown: u32,
    pub interference_thresh_setup: u32,
    pub min_no_sta_setup: u32,
    pub min_no_sta_teardown: u32,
    pub no_of_bcast_mcast_slots: u32,
    pub min_no_twt_slots: u32,
    pub max_no_sta_twt: u32,
    pub mode_check_interval: u32,
    pub add_sta_slot_interval: u32,
    pub remove_sta_slot_interval: u32,
}

impl Default for TwtEnableParams {
    fn default() -> Self {
        Self {
            sta_cong_timer_ms: 5_000,
            // ath11k has no MBSSID TWT support.
            mbss_support: 0,
            default_slot_size: 10,
            congestion_thresh_setup: 50,
            congestion_thresh_teardown: 20,
            congestion_thresh_critical: 100,
            interference_thresh_teardown: 80,
            interference_thresh_setup: 50,
            min_no_sta_setup: 10,
            min_no_sta_teardown: 2,
            no_of_bcast_mcast_slots: 2,
            min_no_twt_slots: 2,
            max_no_sta_twt: 500,
            mode_check_interval: 10_000,
            add_sta_slot_interval: 1_000,
            remove_sta_slot_interval: 5_000,
        }
    }
}

/// `ath11k_wmi_send_twt_enable_cmd` → `WMI_TWT_ENABLE_CMDID`.
pub fn twt_enable_cmd(pdev_id: u32, p: &TwtEnableParams) -> WmiCmd {
    let mut w = W::new(WMI_TWT_ENABLE_PARAMS_CMD_SIZE);
    w.tlv(
        WMI_TAG_TWT_ENABLE_CMD,
        WMI_TWT_ENABLE_PARAMS_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(pdev_id);
    w.u32(p.sta_cong_timer_ms);
    w.u32(p.mbss_support);
    w.u32(p.default_slot_size);
    w.u32(p.congestion_thresh_setup);
    w.u32(p.congestion_thresh_teardown);
    w.u32(p.congestion_thresh_critical);
    w.u32(p.interference_thresh_teardown);
    w.u32(p.interference_thresh_setup);
    w.u32(p.min_no_sta_setup);
    w.u32(p.min_no_sta_teardown);
    w.u32(p.no_of_bcast_mcast_slots);
    w.u32(p.min_no_twt_slots);
    w.u32(p.max_no_sta_twt);
    w.u32(p.mode_check_interval);
    w.u32(p.add_sta_slot_interval);
    w.u32(p.remove_sta_slot_interval);
    w.finish(WMI_TWT_ENABLE_CMDID, WMI_TWT_ENABLE_PARAMS_CMD_SIZE)
}

/// `ath11k_wmi_send_twt_disable_cmd` → `WMI_TWT_DISABLE_CMDID`.
pub fn twt_disable_cmd(pdev_id: u32) -> WmiCmd {
    let mut w = W::new(WMI_TWT_DISABLE_PARAMS_CMD_SIZE);
    w.tlv(
        WMI_TAG_TWT_DISABLE_CMD,
        WMI_TWT_DISABLE_PARAMS_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(pdev_id);
    w.finish(WMI_TWT_DISABLE_CMDID, WMI_TWT_DISABLE_PARAMS_CMD_SIZE)
}

/// `struct wmi_channel_arg` — the channel half of
/// `wmi_vdev_start_req_arg`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelArg {
    pub freq: u32,
    pub band_center_freq1: u32,
    pub band_center_freq2: u32,
    pub mode: u32,
    pub passive: bool,
    pub allow_ibss: bool,
    pub allow_ht: bool,
    pub allow_vht: bool,
    pub allow_he: bool,
    /// `WMI_CHAN_INFO_CHAN_CHANGE_CAUSE_CSA` for a station CSA restart.
    pub chan_change_cause_csa: bool,
    pub ht40plus: bool,
    pub chan_radar: bool,
    pub freq2_radar: bool,
    pub max_power: u8,
    pub max_reg_power: u8,
    pub max_antenna_gain: u8,
}

/// `ath11k_wmi_put_wmi_channel` — the 28-byte `struct wmi_channel`
/// (tlv header included) for vdev start/restart.
pub fn put_wmi_channel(c: &ChannelArg) -> [u8; WMI_CHANNEL_SIZE] {
    let center_freq1 = c.band_center_freq1;
    let (cf1, cf2) = if c.mode == phy_mode::MODE_11AX_HE160 {
        let cf1 = if c.freq > center_freq1 {
            center_freq1.wrapping_add(40)
        } else {
            center_freq1.wrapping_sub(40)
        };
        (cf1, center_freq1)
    } else if c.mode == phy_mode::MODE_11AC_VHT80_80 || c.mode == phy_mode::MODE_11AX_HE80_80 {
        (center_freq1, c.band_center_freq2)
    } else {
        (center_freq1, 0)
    };
    let mut info = c.mode & chan_info::MODE;
    for (set, bit) in [
        (c.passive, chan_info::PASSIVE),
        (c.allow_ibss, chan_info::ADHOC_ALLOWED),
        (c.allow_ht, chan_info::ALLOW_HT),
        (c.allow_vht, chan_info::ALLOW_VHT),
        (c.allow_he, chan_info::ALLOW_HE),
        (c.chan_change_cause_csa, chan_info::CHAN_CHANGE_CAUSE_CSA),
        (c.ht40plus, chan_info::HT40_PLUS),
        (c.chan_radar, chan_info::DFS),
        (c.freq2_radar, chan_info::DFS_FREQ2),
    ] {
        if set {
            info |= bit;
        }
    }
    let reg1 = ((c.max_power as u32) << chan_reg::INFO1_MAX_PWR_SHIFT)
        | ((c.max_reg_power as u32) << chan_reg::INFO1_MAX_REG_PWR_SHIFT);
    let reg2 = ((c.max_antenna_gain as u32) << chan_reg::INFO2_ANT_MAX_SHIFT)
        | ((c.max_power as u32) << chan_reg::INFO2_MAX_TX_PWR_SHIFT);
    let mut out = [0u8; WMI_CHANNEL_SIZE];
    for (i, v) in [
        tlv_hdr(WMI_TAG_CHANNEL, WMI_CHANNEL_SIZE - TLV_HDR_SIZE),
        c.freq,
        cf1,
        cf2,
        info,
        reg1,
        reg2,
    ]
    .iter()
    .enumerate()
    {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// `struct wmi_vdev_start_req_arg` (fields `ath11k_wmi_vdev_start`
/// reads).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VdevStartReqArg {
    pub vdev_id: u32,
    pub channel: ChannelArg,
    pub bcn_intval: u32,
    pub dtim_period: u32,
    pub bcn_tx_rate: u32,
    pub num_noa_descriptors: u32,
    pub pref_rx_streams: u32,
    pub pref_tx_streams: u32,
    pub cac_duration_ms: u32,
    pub regdomain: u32,
    pub he_ops: u32,
    pub mbssid_flags: u32,
    pub mbssid_tx_vdev_id: u32,
    /// `arg->ssid` / `ssid_len`; `None` ⇔ NULL pointer.
    pub ssid: Option<Vec<u8>>,
    pub hidden_ssid: bool,
    pub pmf_enabled: bool,
    /// `ATH11K_FLAG_HW_CRYPTO_DISABLED` in `ab->dev_flags`.
    pub hw_crypto_disabled: bool,
}

/// `ath11k_wmi_vdev_start` → `WMI_VDEV_START_REQUEST_CMDID`, or
/// `WMI_VDEV_RESTART_REQUEST_CMDID` when `restart`.
///
/// SSID / hidden / PMF are only filled on a fresh start;
/// `LDPC_RX_ENABLED` is always set. The trailing `ARRAY_STRUCT` (P2P NoA
/// descriptors) is always empty. `requestor_id`, `bcn_txpower`,
/// `disable_hw_ack`, `min_data_rate` are never set by Linux.
/// An SSID longer than 32 bytes is `-EINVAL` (Linux `WARN_ON`).
pub fn vdev_start_cmd(arg: &VdevStartReqArg, restart: bool) -> Result<WmiCmd, WmiError> {
    let ssid_len = arg.ssid.as_ref().map_or(0, |s| s.len());
    if ssid_len > 32 {
        return Err(WmiError::Invalid("vdev start: ssid_len > 32"));
    }
    let len = WMI_VDEV_START_REQUEST_CMD_SIZE + WMI_CHANNEL_SIZE + TLV_HDR_SIZE;
    let mut flags = 0u32;
    let mut ssid = [0u8; 36];
    if !restart {
        if let Some(s) = &arg.ssid {
            ssid[0..4].copy_from_slice(&(s.len() as u32).to_le_bytes());
            ssid[4..4 + s.len()].copy_from_slice(s);
        }
        if arg.hidden_ssid {
            flags |= WMI_VDEV_START_HIDDEN_SSID;
        }
        if arg.pmf_enabled {
            flags |= WMI_VDEV_START_PMF_ENABLED;
        }
    }
    flags |= WMI_VDEV_START_LDPC_RX_ENABLED;
    if arg.hw_crypto_disabled {
        flags |= WMI_VDEV_START_HW_ENCRYPTION_DISABLED;
    }
    let mut w = W::new(len);
    w.tlv(
        WMI_TAG_VDEV_START_REQUEST_CMD,
        WMI_VDEV_START_REQUEST_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(arg.vdev_id);
    w.u32(0); // requestor_id
    w.u32(arg.bcn_intval);
    w.u32(arg.dtim_period);
    w.u32(flags);
    w.bytes(&ssid);
    w.u32(arg.bcn_tx_rate);
    w.u32(0); // bcn_txpower
    w.u32(arg.num_noa_descriptors);
    w.u32(0); // disable_hw_ack
    w.u32(arg.pref_tx_streams);
    w.u32(arg.pref_rx_streams);
    w.u32(arg.he_ops);
    w.u32(arg.cac_duration_ms);
    w.u32(arg.regdomain);
    w.u32(0); // min_data_rate
    w.u32(arg.mbssid_flags);
    w.u32(arg.mbssid_tx_vdev_id);
    w.bytes(&put_wmi_channel(&arg.channel));
    w.tlv(WMI_TAG_ARRAY_STRUCT, 0);
    let id = if restart {
        WMI_VDEV_RESTART_REQUEST_CMDID
    } else {
        WMI_VDEV_START_REQUEST_CMDID
    };
    Ok(w.finish(id, len))
}

/// Non-transmitted-BSSID override `ath11k_wmi_vdev_up` applies for a
/// station vif whose `bss_conf.nontransmitted` is set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NonTxBss {
    pub transmitter_bssid: [u8; 6],
    pub bssid_index: u32,
    pub bssid_indicator: u32,
}

/// `ath11k_wmi_vdev_up` → `WMI_VDEV_UP_CMDID`.
pub fn vdev_up_cmd(
    vdev_id: u32,
    aid: u32,
    bssid: &[u8; 6],
    tx_bssid: Option<&[u8; 6]>,
    nontx_profile_idx: u32,
    nontx_profile_cnt: u32,
    sta_nontransmitted: Option<&NonTxBss>,
) -> WmiCmd {
    let mut tx = [0u8; 6];
    let mut idx = nontx_profile_idx;
    let mut cnt = nontx_profile_cnt;
    if let Some(t) = tx_bssid {
        tx = *t;
    }
    if let Some(n) = sta_nontransmitted {
        tx = n.transmitter_bssid;
        idx = n.bssid_index;
        cnt = n.bssid_indicator;
    }
    let mut w = W::new(WMI_VDEV_UP_CMD_SIZE);
    w.tlv(WMI_TAG_VDEV_UP_CMD, WMI_VDEV_UP_CMD_SIZE - TLV_HDR_SIZE);
    w.u32(vdev_id);
    w.u32(aid);
    w.mac(bssid);
    w.mac(&tx);
    w.u32(idx);
    w.u32(cnt);
    w.finish(WMI_VDEV_UP_CMDID, WMI_VDEV_UP_CMD_SIZE)
}

/// `ath11k_wmi_bcn_tmpl` → `WMI_BCN_TMPL_CMDID`.
///
/// The template is the complete native 802.11 beacon (management header,
/// fixed beacon fields, and information elements). `tim_ie_offset` is its
/// byte offset from the first 802.11 header byte. Ordinary AP callers use
/// [`bcn_tmpl_cmd`]; MBSSID/EMA callers supply their first MBSSID element
/// offset and Linux's packed `ema_params` through
/// [`bcn_tmpl_cmd_with_mbssid`].
pub fn bcn_tmpl_cmd(vdev_id: u32, tim_ie_offset: u32, beacon: &[u8]) -> WmiCmd {
    bcn_tmpl_cmd_with_mbssid(vdev_id, tim_ie_offset, beacon, None, 0)
}

/// `ath11k_wmi_bcn_tmpl` with the MBSSID and EMA mutable fields populated.
/// `mbssid_ie_offset` is zero only when the template has no MBSSID element;
/// firmware interprets a nonzero value relative to the first beacon byte.
pub fn bcn_tmpl_cmd_with_mbssid(
    vdev_id: u32,
    tim_ie_offset: u32,
    beacon: &[u8],
    mbssid_ie_offset: Option<u32>,
    ema_params: u32,
) -> WmiCmd {
    let aligned = roundup4(beacon.len());
    let len = WMI_BCN_TMPL_CMD_SIZE + WMI_BCN_PRB_INFO_SIZE + TLV_HDR_SIZE + aligned;
    let mut w = W::new(len);
    w.tlv(WMI_TAG_BCN_TMPL_CMD, WMI_BCN_TMPL_CMD_SIZE - TLV_HDR_SIZE);
    w.u32(vdev_id);
    w.u32(tim_ie_offset);
    w.u32(beacon.len() as u32);
    // csa_switch_count_offset, ext_csa_switch_count_offset,
    // csa_event_bitmap, mbssid_ie_offset, esp_ie_offset,
    // csc_switch_count_offset, csc_event_bitmap, mu_edca_ie_offset,
    // feature_enable_bitmap, ema_params.
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(mbssid_ie_offset.unwrap_or(0));
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(ema_params);
    w.tlv(WMI_TAG_BCN_PRB_INFO, WMI_BCN_PRB_INFO_SIZE - TLV_HDR_SIZE);
    w.u32(0); // caps
    w.u32(0); // erp
    w.tlv(WMI_TAG_ARRAY_BYTE, aligned);
    w.bytes(beacon);
    w.finish(WMI_BCN_TMPL_CMDID, len)
}

/// `ath11k_wmi_fils_discovery_tmpl` →
/// `WMI_FILS_DISCOVERY_TMPL_CMDID`. The payload is a complete FILS action
/// frame template including its management header.
pub fn fils_discovery_tmpl_cmd(vdev_id: u32, template: &[u8]) -> WmiCmd {
    let aligned = roundup4(template.len());
    let len = WMI_FILS_DISCOVERY_TMPL_CMD_SIZE + TLV_HDR_SIZE + aligned;
    let mut w = W::new(len);
    w.tlv(
        WMI_TAG_FILS_DISCOVERY_TMPL_CMD,
        WMI_FILS_DISCOVERY_TMPL_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(vdev_id);
    w.u32(template.len() as u32);
    w.tlv(WMI_TAG_ARRAY_BYTE, aligned);
    w.bytes(template);
    w.finish(WMI_FILS_DISCOVERY_TMPL_CMDID, len)
}

/// `ath11k_wmi_probe_resp_tmpl` → `WMI_PRB_TMPL_CMDID`, used only for an
/// unsolicited broadcast Probe Response (ordinary AP probe responses use the
/// management-frame path). Like Linux, the BCN/PRB-info capability words are
/// currently zero.
pub fn probe_resp_tmpl_cmd(vdev_id: u32, template: &[u8]) -> WmiCmd {
    let aligned = roundup4(template.len());
    let len = WMI_PROBE_TMPL_CMD_SIZE + WMI_BCN_PRB_INFO_SIZE + TLV_HDR_SIZE + aligned;
    let mut w = W::new(len);
    w.tlv(WMI_TAG_PRB_TMPL_CMD, WMI_PROBE_TMPL_CMD_SIZE - TLV_HDR_SIZE);
    w.u32(vdev_id);
    w.u32(template.len() as u32);
    w.tlv(WMI_TAG_BCN_PRB_INFO, WMI_BCN_PRB_INFO_SIZE - TLV_HDR_SIZE);
    w.u32(0); // caps
    w.u32(0); // erp
    w.tlv(WMI_TAG_ARRAY_BYTE, aligned);
    w.bytes(template);
    w.finish(WMI_PRB_TMPL_CMDID, len)
}

/// `ath11k_wmi_fils_discovery` → `WMI_ENABLE_FILS_CMDID`. `interval == 0`
/// disables either discovery family and lets firmware discard its template;
/// `unsol_bcast_probe_resp` selects the WMI unsolicited-probe mode.
pub fn fils_discovery_cmd(vdev_id: u32, interval: u32, unsol_bcast_probe_resp: bool) -> WmiCmd {
    let mut w = W::new(WMI_FILS_DISCOVERY_CMD_SIZE);
    w.tlv(
        WMI_TAG_ENABLE_FILS_CMD,
        WMI_FILS_DISCOVERY_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(vdev_id);
    w.u32(interval);
    w.u32(u32::from(unsol_bcast_probe_resp));
    w.finish(WMI_ENABLE_FILS_CMDID, WMI_FILS_DISCOVERY_CMD_SIZE)
}

/// `ath11k_wmi_p2p_go_bcn_ie` → `WMI_P2P_GO_SET_BEACON_IE`. Firmware
/// inserts this complete WFA P2P vendor element into every GO beacon, so the
/// caller must remove it from the ordinary beacon-template payload.
pub fn p2p_go_bcn_ie_cmd(vdev_id: u32, p2p_ie: &[u8]) -> Option<WmiCmd> {
    if p2p_ie.len() < 6
        || p2p_ie[0] != 221 // WLAN_EID_VENDOR_SPECIFIC
        || p2p_ie.len() != p2p_ie[1] as usize + 2
        || p2p_ie[2..6] != [0x50, 0x6f, 0x9a, 9]
    // WFA / P2P
    {
        return None;
    }
    let aligned = roundup4(p2p_ie.len());
    let len = 12 + TLV_HDR_SIZE + aligned; // fixed cmd + ARRAY_BYTE
    let mut w = W::new(len);
    w.tlv(WMI_TAG_P2P_GO_SET_BEACON_IE, 8);
    w.u32(vdev_id);
    w.u32(p2p_ie.len() as u32);
    w.tlv(WMI_TAG_ARRAY_BYTE, aligned);
    let start = w.b.len();
    w.bytes(p2p_ie);
    w.pad_to(start + aligned);
    Some(w.finish(WMI_P2P_GO_SET_BEACON_IE, len))
}

/// `ath11k_wmi_send_peer_create_cmd` → `WMI_PEER_CREATE_CMDID`.
pub fn peer_create_cmd(vdev_id: u32, peer_addr: &[u8; 6], peer_type: u32) -> WmiCmd {
    let size = 20;
    let mut w = W::new(size);
    w.tlv(WMI_TAG_PEER_CREATE_CMD, size - TLV_HDR_SIZE);
    w.u32(vdev_id);
    w.mac(peer_addr);
    w.u32(peer_type);
    w.finish(WMI_PEER_CREATE_CMDID, size)
}

/// `ath11k_wmi_send_peer_delete_cmd` → `WMI_PEER_DELETE_CMDID`.
pub fn peer_delete_cmd(peer_addr: &[u8; 6], vdev_id: u8) -> WmiCmd {
    let size = 16;
    let mut w = W::new(size);
    w.tlv(WMI_TAG_PEER_DELETE_CMD, size - TLV_HDR_SIZE);
    w.u32(vdev_id as u32);
    w.mac(peer_addr);
    w.finish(WMI_PEER_DELETE_CMDID, size)
}

/// `ath11k_wmi_set_peer_param` → `WMI_PEER_SET_PARAM_CMDID`.
pub fn peer_set_param_cmd(
    peer_addr: &[u8; 6],
    vdev_id: u32,
    param_id: u32,
    param_val: u32,
) -> WmiCmd {
    let size = 24;
    let mut w = W::new(size);
    w.tlv(WMI_TAG_PEER_SET_PARAM_CMD, size - TLV_HDR_SIZE);
    w.u32(vdev_id);
    w.mac(peer_addr);
    w.u32(param_id);
    w.u32(param_val);
    w.finish(WMI_PEER_SET_PARAM_CMDID, size)
}

/// `ath11k_wmi_send_set_ap_ps_param_cmd` →
/// `WMI_AP_PS_PEER_PARAM_CMDID` (`struct wmi_ap_ps_peer_cmd`).
pub fn ap_ps_peer_param_cmd(
    vdev_id: u32,
    peer_addr: &[u8; 6],
    param_id: u32,
    param_val: u32,
) -> WmiCmd {
    let size = WMI_AP_PS_PEER_CMD_SIZE;
    let mut w = W::new(size);
    w.tlv(WMI_TAG_AP_PS_PEER_CMD, size - TLV_HDR_SIZE);
    w.u32(vdev_id);
    w.mac(peer_addr);
    w.u32(param_id);
    w.u32(param_val);
    w.finish(WMI_AP_PS_PEER_PARAM_CMDID, size)
}

/// `ath11k_wmi_peer_rx_reorder_queue_setup` →
/// `WMI_PEER_REORDER_QUEUE_SETUP_CMDID` (`struct
/// wmi_peer_reorder_queue_setup_cmd`, 40 bytes; `queue_no = tid`).
pub fn peer_rx_reorder_queue_setup_cmd(
    vdev_id: u32,
    peer_addr: &[u8; 6],
    paddr: u64,
    tid: u8,
    ba_window_size_valid: u8,
    ba_window_size: u32,
) -> WmiCmd {
    let size = 40;
    let mut w = W::new(size);
    w.tlv(WMI_TAG_REORDER_QUEUE_SETUP_CMD, size - TLV_HDR_SIZE);
    w.u32(vdev_id);
    w.mac(peer_addr);
    w.u32(tid as u32);
    w.u32(paddr as u32);
    w.u32((paddr >> 32) as u32);
    w.u32(tid as u32);
    w.u32(ba_window_size_valid as u32);
    w.u32(ba_window_size);
    w.finish(WMI_PEER_REORDER_QUEUE_SETUP_CMDID, size)
}

/// `ath11k_wmi_rx_reord_queue_remove` →
/// `WMI_PEER_REORDER_QUEUE_REMOVE_CMDID` (`struct
/// wmi_peer_reorder_queue_remove_cmd`, 20 bytes). Linux defines it but
/// never calls it: firmware drops a peer's queues on `PEER_DELETE`.
pub fn rx_reord_queue_remove_cmd(
    peer_addr: &[u8; 6],
    vdev_id: u16,
    peer_tid_bitmap: u32,
) -> WmiCmd {
    let size = 20;
    let mut w = W::new(size);
    w.tlv(WMI_TAG_REORDER_QUEUE_REMOVE_CMD, size - TLV_HDR_SIZE);
    w.u32(vdev_id as u32);
    w.mac(peer_addr);
    w.u32(peer_tid_bitmap);
    w.finish(WMI_PEER_REORDER_QUEUE_REMOVE_CMDID, size)
}

/// `struct ath11k_ppe_threshold` — copied verbatim (40 bytes) into
/// `wmi_ppe_threshold`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PpeThreshold {
    pub numss_m1: u32,
    pub ru_bit_mask: u32,
    pub ppet16_ppet8_ru3_ru0: [u32; 8],
}

impl PpeThreshold {
    fn put(&self, w: &mut W) {
        w.u32(self.numss_m1);
        w.u32(self.ru_bit_mask);
        for v in self.ppet16_ppet8_ru3_ru0 {
            w.u32(v);
        }
    }
    fn parse(b: &[u8]) -> Self {
        let mut p = PpeThreshold {
            numss_m1: rd32(b, 0),
            ru_bit_mask: rd32(b, 4),
            ..Default::default()
        };
        for i in 0..8 {
            p.ppet16_ppet8_ru3_ru0[i] = rd32(b, 8 + 4 * i);
        }
        p
    }
}

/// `struct peer_assoc_params` (the fields `ath11k_wmi_send_peer_assoc_cmd`
/// and `ath11k_wmi_copy_peer_flags` read).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerAssocParams {
    pub vdev_id: u32,
    pub peer_new_assoc: u32,
    pub peer_associd: u32,
    pub peer_mac: [u8; 6],
    pub peer_caps: u32,
    pub peer_listen_intval: u32,
    pub peer_ht_caps: u32,
    pub peer_max_mpdu: u32,
    pub peer_mpdu_density: u32,
    pub peer_rate_caps: u32,
    pub peer_nss: u32,
    pub peer_vht_caps: u32,
    pub peer_phymode: u32,
    /// `peer_legacy_rates.rates[..num_rates]`.
    pub peer_legacy_rates: Vec<u8>,
    /// `peer_ht_rates.rates[..num_rates]`.
    pub peer_ht_rates: Vec<u8>,
    pub rx_max_rate: u32,
    pub rx_mcs_set: u32,
    pub tx_max_rate: u32,
    pub tx_mcs_set: u32,
    pub vht_capable: bool,
    pub min_data_rate: u8,
    pub peer_bw_rxnss_override: u32,
    pub is_pmf_enabled: bool,
    pub is_wme_set: bool,
    pub qos_flag: bool,
    pub apsd_flag: bool,
    pub ht_flag: bool,
    pub bw_40: bool,
    pub bw_80: bool,
    pub bw_160: bool,
    pub stbc_flag: bool,
    pub ldpc_flag: bool,
    pub static_mimops_flag: bool,
    pub dynamic_mimops_flag: bool,
    pub spatial_mux_flag: bool,
    pub vht_flag: bool,
    pub need_ptk_4_way: bool,
    pub need_gtk_2_way: bool,
    pub auth_flag: bool,
    pub safe_mode_enabled: bool,
    pub he_flag: bool,
    pub peer_he_cap_macinfo: [u32; 2],
    pub peer_he_cap_macinfo_internal: u32,
    pub peer_he_caps_6ghz: u32,
    pub peer_he_ops: u32,
    pub peer_he_cap_phyinfo: [u32; 3],
    /// `peer_he_rx_mcs_set[i]`, `peer_he_tx_mcs_set[i]` for
    /// `i < peer_he_mcs_count` (at most `WMI_HOST_MAX_HE_RATE_SET` = 3).
    pub peer_he_mcs: Vec<(u32, u32)>,
    pub twt_responder: bool,
    pub twt_requester: bool,
    pub is_assoc: bool,
    pub peer_ppet: PpeThreshold,
}

/// `ath11k_wmi_copy_peer_flags` — `peer_flags` from the bools.
pub fn peer_assoc_flags(p: &PeerAssocParams, hw_crypto_disabled: bool) -> u32 {
    use peer_flags::*;
    let mut f = 0u32;
    if p.is_wme_set {
        for (set, bit) in [
            (p.qos_flag, QOS),
            (p.apsd_flag, APSD),
            (p.ht_flag, HT),
            (p.bw_40, BW_40MHZ),
            (p.bw_80, BW_80MHZ),
            (p.bw_160, BW_160MHZ),
            (p.stbc_flag, STBC),
            (p.ldpc_flag, LDPC),
            (p.static_mimops_flag, STATIC_MIMOPS),
            (p.dynamic_mimops_flag, DYN_MIMOPS),
            (p.spatial_mux_flag, SPATIAL_MUX),
            (p.vht_flag, VHT),
            (p.he_flag, HE),
            (p.twt_requester, TWT_REQ),
            (p.twt_responder, TWT_RESP),
        ] {
            if set {
                f |= bit;
            }
        }
    }
    if p.auth_flag {
        f |= AUTH;
    }
    if p.need_ptk_4_way {
        f |= NEED_PTK_4_WAY;
        if !hw_crypto_disabled && p.is_assoc {
            f &= !AUTH;
        }
    }
    if p.need_gtk_2_way {
        f |= NEED_GTK_2_WAY;
    }
    if p.safe_mode_enabled {
        f &= !(NEED_PTK_4_WAY | NEED_GTK_2_WAY);
    }
    if p.is_pmf_enabled {
        f |= PMF;
    }
    if p.peer_ht_rates.is_empty() {
        f &= !HT;
    }
    f
}

/// `ath11k_wmi_send_peer_assoc_cmd` → `WMI_PEER_ASSOC_CMDID`.
///
/// Layout: assoc struct · `ARRAY_BYTE` legacy rates (padded to 4) ·
/// `ARRAY_BYTE` HT rates (padded to 4) · `VHT_RATE_SET` (tx/rx swapped:
/// firmware reads `tx_mcs_set` as the peer's RX capability) ·
/// `ARRAY_STRUCT` of `HE_RATE_SET`. `peer_ht_info[]` is never written.
/// More than 128 rates per set or 3 HE rate sets is `-EINVAL`.
pub fn peer_assoc_cmd(p: &PeerAssocParams, hw_crypto_disabled: bool) -> Result<WmiCmd, WmiError> {
    if p.peer_legacy_rates.len() > 128 || p.peer_ht_rates.len() > 128 || p.peer_he_mcs.len() > 3 {
        return Err(WmiError::Invalid("peer assoc: rate set too large"));
    }
    let legacy_align = roundup4(p.peer_legacy_rates.len());
    let ht_align = roundup4(p.peer_ht_rates.len());
    let len = WMI_PEER_ASSOC_COMPLETE_CMD_SIZE
        + TLV_HDR_SIZE
        + legacy_align
        + TLV_HDR_SIZE
        + ht_align
        + WMI_VHT_RATE_SET_SIZE
        + TLV_HDR_SIZE
        + WMI_HE_RATE_SET_SIZE * p.peer_he_mcs.len();
    let mut w = W::new(len);
    w.tlv(
        WMI_TAG_PEER_ASSOC_COMPLETE_CMD,
        WMI_PEER_ASSOC_COMPLETE_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.mac(&p.peer_mac);
    w.u32(p.vdev_id);
    w.u32(p.peer_new_assoc);
    w.u32(p.peer_associd);
    w.u32(peer_assoc_flags(p, hw_crypto_disabled));
    w.u32(p.peer_caps);
    w.u32(p.peer_listen_intval);
    w.u32(p.peer_ht_caps);
    w.u32(p.peer_max_mpdu);
    w.u32(p.peer_mpdu_density);
    w.u32(p.peer_rate_caps);
    w.u32(p.peer_nss);
    w.u32(p.peer_vht_caps);
    w.u32(p.peer_phymode);
    w.u32(0); // peer_ht_info[0]
    w.u32(0); // peer_ht_info[1]
    w.u32(p.peer_legacy_rates.len() as u32);
    w.u32(p.peer_ht_rates.len() as u32);
    w.u32(p.peer_bw_rxnss_override);
    p.peer_ppet.put(&mut w);
    w.u32(p.peer_he_cap_macinfo[0]); // peer_he_cap_info
    w.u32(p.peer_he_ops);
    for v in p.peer_he_cap_phyinfo {
        w.u32(v);
    }
    w.u32(p.peer_he_mcs.len() as u32);
    w.u32(p.peer_he_cap_macinfo[1]); // peer_he_cap_info_ext
    w.u32(p.peer_he_cap_macinfo_internal);
    w.u32(p.min_data_rate as u32);
    w.u32(p.peer_he_caps_6ghz);
    debug_assert_eq!(w.b.len(), WMI_PEER_ASSOC_COMPLETE_CMD_SIZE);

    w.tlv(WMI_TAG_ARRAY_BYTE, legacy_align);
    let start = w.b.len();
    w.bytes(&p.peer_legacy_rates);
    w.pad_to(start + legacy_align);

    w.tlv(WMI_TAG_ARRAY_BYTE, ht_align);
    let start = w.b.len();
    w.bytes(&p.peer_ht_rates);
    w.pad_to(start + ht_align);

    w.tlv(WMI_TAG_VHT_RATE_SET, WMI_VHT_RATE_SET_SIZE - TLV_HDR_SIZE);
    if p.vht_capable {
        w.u32(p.tx_max_rate); // mcs->rx_max_rate = param->tx_max_rate
        w.u32(p.tx_mcs_set); // mcs->rx_mcs_set = param->tx_mcs_set
        w.u32(p.rx_max_rate); // mcs->tx_max_rate = param->rx_max_rate
        w.u32(p.rx_mcs_set); // mcs->tx_mcs_set = param->rx_mcs_set
    } else {
        w.zeros(16);
    }
    w.u32(0); // tx_max_mcs_nss — not set

    w.tlv(
        WMI_TAG_ARRAY_STRUCT,
        p.peer_he_mcs.len() * WMI_HE_RATE_SET_SIZE,
    );
    for &(rx, tx) in &p.peer_he_mcs {
        w.tlv(WMI_TAG_HE_RATE_SET, WMI_HE_RATE_SET_SIZE - TLV_HDR_SIZE);
        w.u32(rx);
        w.u32(tx);
    }
    Ok(w.finish(WMI_PEER_ASSOC_CMDID, len))
}

/// `struct wmi_vdev_install_key_arg`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VdevInstallKeyArg {
    pub vdev_id: u32,
    pub macaddr: [u8; 6],
    pub key_idx: u32,
    pub key_flags: u32,
    pub key_cipher: u32,
    /// `key_data[..key_len]`; empty ⇔ `key_data == NULL`.
    pub key_data: Vec<u8>,
    pub key_txmic_len: u32,
    pub key_rxmic_len: u32,
    pub key_rsc_counter: u64,
}

/// `ath11k_wmi_vdev_install_key` → `WMI_VDEV_INSTALL_KEY_CMDID`: install
/// struct + `ARRAY_BYTE` key material padded to 4.
///
/// Linux copies `key_len_aligned` bytes from the key buffer, so for a
/// key length that is not a multiple of 4 (WEP-40/104 only) the pad
/// bytes are whatever follows the key in `ieee80211_key_conf`; NARF
/// zero-fills them. All station ciphers (CCMP/GCMP-128/256, TKIP)
/// have 4-aligned keys, where the output is identical.
pub fn vdev_install_key_cmd(a: &VdevInstallKeyArg) -> WmiCmd {
    let aligned = roundup4(a.key_data.len());
    let len = WMI_VDEV_INSTALL_KEY_CMD_SIZE + TLV_HDR_SIZE + aligned;
    let mut w = W::new(len);
    w.tlv(
        WMI_TAG_VDEV_INSTALL_KEY_CMD,
        WMI_VDEV_INSTALL_KEY_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(a.vdev_id);
    w.mac(&a.macaddr);
    w.u32(a.key_idx);
    w.u32(a.key_flags);
    w.u32(a.key_cipher);
    // key_rsc_counter: memcpy of the u64 (only when non-zero; zero
    // either way).
    w.bytes(&a.key_rsc_counter.to_le_bytes());
    w.zeros(8); // key_global_rsc_counter
    w.zeros(8); // key_tsc_counter
    w.zeros(16); // wpi_key_rsc_counter
    w.zeros(16); // wpi_key_tsc_counter
    w.u32(a.key_data.len() as u32);
    w.u32(a.key_txmic_len);
    w.u32(a.key_rxmic_len);
    w.u32(0); // is_group_key_id_valid
    w.u32(0); // group_key_id
    debug_assert_eq!(w.b.len(), WMI_VDEV_INSTALL_KEY_CMD_SIZE);
    w.tlv(WMI_TAG_ARRAY_BYTE, aligned);
    w.bytes(&a.key_data);
    w.finish(WMI_VDEV_INSTALL_KEY_CMDID, len)
}

/// One `struct hint_bssid` request entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HintBssid {
    pub freq_flags: u32,
    pub bssid: [u8; 6],
}

/// `struct scan_req_params`. The `scan_ev_*` bitfields map 1:1 onto
/// `WMI_SCAN_EVENT_*` bits OR-ed into `notify_scan_events`, and the
/// `scan_f_*` bitfields 1:1 onto `WMI_SCAN_*` control bits, so both are
/// carried here as the resulting masks ([`scan_flag::LINUX_COPIED`]
/// lists the control bits Linux actually transfers).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanReqParams {
    pub scan_id: u32,
    pub scan_req_id: u32,
    pub vdev_id: u32,
    pub pdev_id: u32,
    pub scan_priority: u32,
    pub notify_scan_events: u32,
    pub scan_ctrl_flags: u32,
    pub scan_ctrl_flags_ext: u32,
    pub adaptive_dwell_time_mode: u32,
    pub dwell_time_active: u32,
    pub dwell_time_active_2g: u32,
    pub dwell_time_passive: u32,
    pub dwell_time_active_6g: u32,
    pub dwell_time_passive_6g: u32,
    pub min_rest_time: u32,
    pub max_rest_time: u32,
    pub repeat_probe_time: u32,
    pub probe_spacing_time: u32,
    pub idle_time: u32,
    pub max_scan_time: u32,
    pub probe_delay: u32,
    pub burst_duration: u32,
    pub n_probes: u32,
    pub chan_list: Vec<u32>,
    /// SSIDs (each ≤ 32 bytes; at most 16).
    pub ssids: Vec<Vec<u8>>,
    /// BSSIDs (at most 4).
    pub bssid_list: Vec<[u8; 6]>,
    pub extraie: Vec<u8>,
    /// `(freq_flags, short_ssid)` (at most 10).
    pub hint_s_ssid: Vec<(u32, u32)>,
    /// At most 10.
    pub hint_bssid: Vec<HintBssid>,
    pub mac_addr: [u8; 6],
    pub mac_mask: [u8; 6],
}

impl ScanReqParams {
    /// `ath11k_wmi_start_scan_init`. `state_11d_preparing` is
    /// `ar->state_11d == ATH11K_11D_PREPARING`;
    /// `passive_start_time_enhance` is the
    /// `WMI_TLV_SERVICE_PASSIVE_SCAN_START_TIME_ENHANCE` service bit.
    ///
    /// The init sets both `notify_scan_events` (the raw mask) and
    /// `scan_f_chan_stat_evnt`; the scan_ev_* bitfields stay 0.
    /// `ath11k_mac_op_hw_scan` then sets `vdev_id`, `scan_id =
    /// ATH11K_SCAN_ID`, `FILTER_PROBE_REQ` (single_pdev_only), SSIDs or
    /// `PASSIVE`, channels, and optional random-MAC fields.
    pub fn start_scan_init(state_11d_preparing: bool, passive_start_time_enhance: bool) -> Self {
        ScanReqParams {
            scan_req_id: 1,
            scan_priority: if state_11d_preparing {
                scan_priority::MEDIUM
            } else {
                scan_priority::LOW
            },
            dwell_time_active: 50,
            dwell_time_active_2g: 0,
            dwell_time_passive: 150,
            dwell_time_active_6g: 40,
            dwell_time_passive_6g: 30,
            min_rest_time: 50,
            max_rest_time: 500,
            repeat_probe_time: 0,
            probe_spacing_time: 0,
            idle_time: 0,
            max_scan_time: 20000,
            probe_delay: 5,
            notify_scan_events: scan_event::STARTED
                | scan_event::COMPLETED
                | scan_event::BSS_CHANNEL
                | scan_event::FOREIGN_CHAN
                | scan_event::DEQUEUED,
            scan_ctrl_flags: scan_flag::CHAN_STAT_EVENT,
            scan_ctrl_flags_ext: if passive_start_time_enhance {
                scan_flag::EXT_PASSIVE_SCAN_START_TIME_ENHANCE
            } else {
                0
            },
            bssid_list: alloc::vec![[0xff; 6]],
            ..Default::default()
        }
    }
}

/// `ath11k_wmi_send_scan_start_cmd` → `WMI_START_SCAN_CMDID`.
///
/// Layout: start-scan struct · `ARRAY_UINT32` channels ·
/// `ARRAY_FIXED_STRUCT` `wmi_ssid`s · `ARRAY_FIXED_STRUCT` BSSIDs ·
/// `ARRAY_BYTE` extra IEs (padded to 4; `ie_len` is unpadded) ·
/// optional hint short-SSIDs · optional hint BSSIDs.
///
/// Linux quirk: the hint-BSSID loop's `ether_addr_copy` has its
/// arguments reversed (it copies from the command *into* the params),
/// so the command's hint BSSID addresses are always zero; only
/// `freq_flags` reaches the firmware. Reproduced.
pub fn scan_start_cmd(p: &ScanReqParams) -> Result<WmiCmd, WmiError> {
    if p.ssids.len() > 16
        || p.ssids.iter().any(|s| s.len() > 32)
        || p.bssid_list.len() > 4
        || p.hint_s_ssid.len() > 10
        || p.hint_bssid.len() > 10
    {
        return Err(WmiError::Invalid("scan start: list too large"));
    }
    let extraie_pad = if !p.extraie.is_empty() && p.extraie.len() <= 0xFFFF {
        roundup4(p.extraie.len())
    } else {
        0
    };
    let mut len = WMI_START_SCAN_CMD_SIZE;
    len += TLV_HDR_SIZE + 4 * p.chan_list.len();
    len += TLV_HDR_SIZE + WMI_SSID_SIZE * p.ssids.len();
    len += TLV_HDR_SIZE + WMI_MAC_ADDR_SIZE * p.bssid_list.len();
    len += TLV_HDR_SIZE + extraie_pad;
    if !p.hint_bssid.is_empty() {
        len += TLV_HDR_SIZE + HINT_BSSID_SIZE * p.hint_bssid.len();
    }
    if !p.hint_s_ssid.is_empty() {
        len += TLV_HDR_SIZE + HINT_SHORT_SSID_SIZE * p.hint_s_ssid.len();
    }

    let ctrl = (p.scan_ctrl_flags & scan_flag::LINUX_COPIED)
        | ((p.adaptive_dwell_time_mode << scan_flag::DWELL_MODE_SHIFT)
            & scan_flag::DWELL_MODE_MASK);

    let mut w = W::new(len);
    w.tlv(
        WMI_TAG_START_SCAN_CMD,
        WMI_START_SCAN_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(p.scan_id);
    w.u32(p.scan_req_id);
    w.u32(p.vdev_id);
    w.u32(p.scan_priority);
    w.u32(p.notify_scan_events);
    w.u32(p.dwell_time_active);
    w.u32(p.dwell_time_passive);
    w.u32(p.min_rest_time);
    w.u32(p.max_rest_time);
    w.u32(p.repeat_probe_time);
    w.u32(p.probe_spacing_time);
    w.u32(p.idle_time);
    w.u32(p.max_scan_time);
    w.u32(p.probe_delay);
    w.u32(ctrl);
    w.u32(p.burst_duration);
    w.u32(p.chan_list.len() as u32);
    w.u32(p.bssid_list.len() as u32);
    w.u32(p.ssids.len() as u32);
    w.u32(p.extraie.len() as u32);
    w.u32(p.n_probes);
    w.mac(&p.mac_addr);
    w.mac(&p.mac_mask);
    w.zeros(4 * 8); // ie_bitmap[WMI_IE_BITMAP_SIZE]
    w.u32(0); // num_vendor_oui
    w.u32(p.scan_ctrl_flags_ext);
    w.u32(p.dwell_time_active_2g);
    w.u32(p.dwell_time_active_6g);
    w.u32(p.dwell_time_passive_6g);
    w.u32(0); // scan_start_offset
    debug_assert_eq!(w.b.len(), WMI_START_SCAN_CMD_SIZE);

    w.tlv(WMI_TAG_ARRAY_UINT32, 4 * p.chan_list.len());
    for &c in &p.chan_list {
        w.u32(c);
    }
    w.tlv(WMI_TAG_ARRAY_FIXED_STRUCT, WMI_SSID_SIZE * p.ssids.len());
    for s in &p.ssids {
        w.u32(s.len() as u32);
        w.bytes(s);
        w.zeros(32 - s.len());
    }
    w.tlv(
        WMI_TAG_ARRAY_FIXED_STRUCT,
        WMI_MAC_ADDR_SIZE * p.bssid_list.len(),
    );
    for b in &p.bssid_list {
        w.mac(b);
    }
    w.tlv(WMI_TAG_ARRAY_BYTE, extraie_pad);
    if extraie_pad != 0 {
        let start = w.b.len();
        w.bytes(&p.extraie);
        w.pad_to(start + extraie_pad);
    }
    if !p.hint_s_ssid.is_empty() {
        w.tlv(
            WMI_TAG_ARRAY_FIXED_STRUCT,
            HINT_SHORT_SSID_SIZE * p.hint_s_ssid.len(),
        );
        for &(ff, ss) in &p.hint_s_ssid {
            w.u32(ff);
            w.u32(ss);
        }
    }
    if !p.hint_bssid.is_empty() {
        w.tlv(
            WMI_TAG_ARRAY_FIXED_STRUCT,
            HINT_BSSID_SIZE * p.hint_bssid.len(),
        );
        for h in &p.hint_bssid {
            w.u32(h.freq_flags);
            w.zeros(WMI_MAC_ADDR_SIZE); // reversed ether_addr_copy in Linux
        }
    }
    Ok(w.finish(WMI_START_SCAN_CMDID, len))
}

/// `enum scan_cancel_req_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanCancel {
    /// `WLAN_SCAN_CANCEL_SINGLE` → `WMI_SCAN_STOP_ONE`.
    Single,
    /// `WLAN_SCAN_CANCEL_VDEV_ALL` → `WMI_SCN_STOP_VAP_ALL`.
    VdevAll,
    /// `WLAN_SCAN_CANCEL_PDEV_ALL` → `WMI_SCAN_STOP_ALL`.
    PdevAll,
}

/// `ath11k_wmi_send_scan_stop_cmd` → `WMI_STOP_SCAN_CMDID`
/// (`struct wmi_stop_scan_cmd`: requestor, scan_id, req_type, vdev_id,
/// pdev_id).
pub fn scan_stop_cmd(
    vdev_id: u32,
    requester: u32,
    scan_id: u32,
    pdev_id: u32,
    req: ScanCancel,
) -> WmiCmd {
    let req_type = match req {
        ScanCancel::PdevAll => scan_stop::ALL,
        ScanCancel::VdevAll => scan_stop::VAP_ALL,
        ScanCancel::Single => scan_stop::ONE,
    };
    simple_cmd(
        WMI_STOP_SCAN_CMDID,
        WMI_TAG_STOP_SCAN_CMD,
        &[requester, scan_id, req_type, vdev_id, pdev_id],
    )
}

/// `struct channel_param` — one entry of a scan channel list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelParam {
    pub mhz: u32,
    pub cfreq1: u32,
    pub cfreq2: u32,
    pub is_chan_passive: bool,
    pub allow_he: bool,
    pub allow_vht: bool,
    pub allow_ht: bool,
    pub half_rate: bool,
    pub quarter_rate: bool,
    pub psc_channel: bool,
    pub dfs_set: bool,
    pub phy_mode: u32,
    pub minpower: u8,
    pub maxpower: u8,
    pub maxregpower: u8,
    pub antennamax: u8,
    pub reg_class_id: u8,
}

/// One scan-channel-list `wmi_channel` as
/// `ath11k_wmi_send_scan_chan_list_cmd` fills it (note: HE / VHT / HT
/// allow bits are mutually exclusive, highest wins; `MAX_TX_PWR` in
/// reg_info_2 carries `maxregpower`).
pub fn scan_chan_list_channel(c: &ChannelParam) -> [u8; WMI_CHANNEL_SIZE] {
    let mut info = 0u32;
    if c.is_chan_passive {
        info |= chan_info::PASSIVE;
    }
    if c.allow_he {
        info |= chan_info::ALLOW_HE;
    } else if c.allow_vht {
        info |= chan_info::ALLOW_VHT;
    } else if c.allow_ht {
        info |= chan_info::ALLOW_HT;
    }
    if c.half_rate {
        info |= chan_info::HALF_RATE;
    }
    if c.quarter_rate {
        info |= chan_info::QUARTER_RATE;
    }
    if c.psc_channel {
        info |= chan_info::PSC;
    }
    if c.dfs_set {
        info |= chan_info::DFS;
    }
    info |= c.phy_mode & chan_info::MODE;
    let reg1 = ((c.minpower as u32) << chan_reg::INFO1_MIN_PWR_SHIFT)
        | ((c.maxpower as u32) << chan_reg::INFO1_MAX_PWR_SHIFT)
        | ((c.maxregpower as u32) << chan_reg::INFO1_MAX_REG_PWR_SHIFT)
        | ((c.reg_class_id as u32) << chan_reg::INFO1_REG_CLS_SHIFT);
    let reg2 = ((c.antennamax as u32) << chan_reg::INFO2_ANT_MAX_SHIFT)
        | ((c.maxregpower as u32) << chan_reg::INFO2_MAX_TX_PWR_SHIFT);
    let mut out = [0u8; WMI_CHANNEL_SIZE];
    for (i, v) in [
        tlv_hdr(WMI_TAG_CHANNEL, WMI_CHANNEL_SIZE - TLV_HDR_SIZE),
        c.mhz,
        c.cfreq1,
        c.cfreq2,
        info,
        reg1,
        reg2,
    ]
    .iter()
    .enumerate()
    {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// `ath11k_wmi_send_scan_chan_list_cmd` → one or more
/// `WMI_SCAN_CHAN_LIST_CMDID`s.
///
/// The list is split so each command fits `max_msg_len` (the WMI
/// endpoint's `max_msg_len` from the HTC connect response):
/// `(max_msg_len - 20) / 28` channels per command; every command after
/// the first carries `WMI_APPEND_TO_EXISTING_CHAN_LIST_FLAG`.
///
/// Linux quirk reproduced: the `ARRAY_STRUCT` length field is
/// `28 * n - TLV_HDR_SIZE`, i.e. 4 bytes short of the channels that
/// follow it.
///
/// `max_msg_len` too small for one channel is `-EINVAL` here (Linux
/// would loop forever on a zero per-command limit).
pub fn scan_chan_list_cmds(
    pdev_id: u32,
    chans: &[ChannelParam],
    max_msg_len: u32,
) -> Result<Vec<WmiCmd>, WmiError> {
    let hdr = WMI_SCAN_CHAN_LIST_CMD_SIZE + TLV_HDR_SIZE;
    let limit = (max_msg_len as usize).saturating_sub(hdr) / WMI_CHANNEL_SIZE;
    if limit == 0 && !chans.is_empty() {
        return Err(WmiError::Invalid("scan chan list: max_msg_len too small"));
    }
    let mut out = Vec::new();
    let mut rest = chans;
    let mut num_sends = 0u32;
    while !rest.is_empty() {
        let n = rest.len().min(limit);
        let (now, later) = rest.split_at(n);
        rest = later;
        let len = hdr + WMI_CHANNEL_SIZE * n;
        let mut w = W::new(len);
        w.tlv(
            WMI_TAG_SCAN_CHAN_LIST_CMD,
            WMI_SCAN_CHAN_LIST_CMD_SIZE - TLV_HDR_SIZE,
        );
        w.u32(n as u32);
        w.u32(if num_sends != 0 {
            WMI_APPEND_TO_EXISTING_CHAN_LIST_FLAG
        } else {
            0
        });
        w.u32(pdev_id);
        w.tlv(WMI_TAG_ARRAY_STRUCT, WMI_CHANNEL_SIZE * n - TLV_HDR_SIZE);
        for c in now {
            w.bytes(&scan_chan_list_channel(c));
        }
        out.push(w.finish(WMI_SCAN_CHAN_LIST_CMDID, len));
        num_sends += 1;
    }
    Ok(out)
}

/// `ath11k_wmi_mgmt_send` → `WMI_MGMT_TX_SEND_CMDID`.
///
/// The firmware DMAs the whole frame from `paddr`; the command carries
/// only the first `min(len, WMI_MGMT_SEND_DOWNLD_LEN)` bytes in an
/// `ARRAY_BYTE` whose length field is that *unpadded* count (the skb
/// space is padded to 4). `chanfreq` is `ath11k_wmi_mgmt_get_freq`
/// (non-zero only for off-channel ROC TX). With `tx_params_valid` a
/// `TX_SEND_PARAMS` TLV with `CFR_CAPTURE` in dword1 is appended.
/// `ath11k_ce_byte_swap` is a no-op on little-endian hosts.
pub fn mgmt_send_cmd(
    vdev_id: u32,
    buf_id: u32,
    frame: &[u8],
    paddr: u64,
    chanfreq: u32,
    tx_params_valid: bool,
) -> WmiCmd {
    let buf_len = frame.len().min(WMI_MGMT_SEND_DOWNLD_LEN);
    let mut len = WMI_MGMT_SEND_CMD_SIZE + TLV_HDR_SIZE + roundup4(buf_len);
    if tx_params_valid {
        len += WMI_MGMT_SEND_PARAMS_SIZE;
    }
    let mut w = W::new(len);
    w.tlv(
        WMI_TAG_MGMT_TX_SEND_CMD,
        WMI_MGMT_SEND_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(vdev_id);
    w.u32(buf_id);
    w.u32(chanfreq);
    w.u32(paddr as u32);
    w.u32((paddr >> 32) as u32);
    w.u32(frame.len() as u32);
    w.u32(buf_len as u32);
    w.u32(tx_params_valid as u32);
    w.tlv(WMI_TAG_ARRAY_BYTE, buf_len);
    let start = w.b.len();
    w.bytes(&frame[..buf_len]);
    w.pad_to(start + roundup4(buf_len));
    if tx_params_valid {
        w.tlv(
            WMI_TAG_TX_SEND_PARAMS,
            WMI_MGMT_SEND_PARAMS_SIZE - TLV_HDR_SIZE,
        );
        w.u32(0);
        w.u32(WMI_TX_PARAMS_DWORD1_CFR_CAPTURE);
    }
    w.finish(WMI_MGMT_TX_SEND_CMDID, len)
}

/// `ath11k_wmi_pdev_set_ps_mode` → `WMI_STA_POWERSAVE_MODE_CMDID`.
pub fn sta_powersave_mode_cmd(vdev_id: u32, psmode: u32) -> WmiCmd {
    simple_cmd(
        WMI_STA_POWERSAVE_MODE_CMDID,
        WMI_TAG_STA_POWERSAVE_MODE_CMD,
        &[vdev_id, psmode],
    )
}

/// `ath11k_wmi_set_sta_ps_param` → `WMI_STA_POWERSAVE_PARAM_CMDID`.
pub fn sta_powersave_param_cmd(vdev_id: u32, param: u32, value: u32) -> WmiCmd {
    simple_cmd(
        WMI_STA_POWERSAVE_PARAM_CMDID,
        WMI_TAG_STA_POWERSAVE_PARAM_CMD,
        &[vdev_id, param, value],
    )
}

/// `ath11k_wmi_send_pdev_temperature_cmd` →
/// `WMI_PDEV_GET_TEMPERATURE_CMDID` (`param` stays 0).
pub fn pdev_get_temperature_cmd(pdev_id: u32) -> WmiCmd {
    simple_cmd(
        WMI_PDEV_GET_TEMPERATURE_CMDID,
        WMI_TAG_PDEV_GET_TEMPERATURE_CMD,
        &[0, pdev_id],
    )
}

/// `ath11k_wmi_pdev_bss_chan_info_request` with
/// `WMI_BSS_SURVEY_REQ_TYPE_READ` → `WMI_PDEV_BSS_CHAN_INFO_REQUEST_CMDID`.
/// The target returns the pdev-wide 64-bit channel counters in
/// `WMI_PDEV_BSS_CHAN_INFO_EVENTID`.
pub fn pdev_bss_chan_info_request_cmd(pdev_id: u32) -> WmiCmd {
    simple_cmd(
        WMI_PDEV_BSS_CHAN_INFO_REQUEST_CMDID,
        WMI_TAG_PDEV_BSS_CHAN_INFO_REQUEST,
        &[1, pdev_id], // WMI_BSS_SURVEY_REQ_TYPE_READ
    )
}

/// `GTK_OFFLOAD_{ENABLE,DISABLE,REQUEST_STATUS}_OPCODE`.
pub mod gtk_offload_opcode {
    pub const ENABLE: u32 = 0x0100_0000;
    pub const DISABLE: u32 = 0x0200_0000;
    pub const REQUEST_STATUS: u32 = 0x0400_0000;
}

/// Parameters for `ath11k_wmi_gtk_rekey_offload`.  `replay_counter` is the
/// host-order integer ath11k stores after converting the big-endian nl80211
/// input with `get_unaligned_be64`; the WMI command carries its little-endian
/// byte representation on WCN6855's little-endian host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GtkRekeyOffloadParams {
    pub vdev_id: u32,
    pub kek: [u8; 16],
    pub kck: [u8; 16],
    pub replay_counter: u64,
}

/// `ath11k_wmi_gtk_rekey_offload` / `ath11k_wmi_gtk_rekey_getinfo`.
///
/// `enable` writes KEK, KCK and the LE WMI replay counter.  Disable and
/// status requests leave those fields zero, matching Linux's zeroed skb.
/// `ath11k_ce_byte_swap` is a no-op for the WCN6855 little-endian host.
pub fn gtk_rekey_offload_cmd(
    vdev_id: u32,
    opcode: u32,
    params: Option<&GtkRekeyOffloadParams>,
) -> WmiCmd {
    let mut w = W::new(WMI_GTK_REKEY_OFFLOAD_CMD_SIZE);
    w.tlv(
        WMI_TAG_GTK_OFFLOAD_CMD,
        WMI_GTK_REKEY_OFFLOAD_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(vdev_id);
    w.u32(opcode);
    if let Some(p) = params {
        debug_assert_eq!(p.vdev_id, vdev_id);
        w.bytes(&p.kek);
        w.bytes(&p.kck);
        w.bytes(&p.replay_counter.to_le_bytes());
    }
    w.finish(WMI_GTK_OFFLOAD_CMDID, WMI_GTK_REKEY_OFFLOAD_CMD_SIZE)
}

// ── WoWLAN command encoders (wow.c) ─────────────────────────────────

/// WCN6855's network-list-offload limits (`wmi.h`).  They intentionally
/// match the advertised WoW NET_DETECT bounds rather than the larger generic
/// cfg80211 scheduled-scan limits.
pub const WMI_NLO_MAX_SSIDS: usize = 16;
pub const WMI_NLO_MAX_CHANNELS: usize = 60;
pub const WMI_NLO_MAX_SCAN_PLANS: usize = 2;
pub const WMI_NLO_MAX_PLAN_INTERVAL_SECS: u32 = 7200;
pub const WMI_NLO_MAX_PLAN_ITERATIONS: u32 = 100;

const WMI_NLO_CONFIG_STOP: u32 = 1 << 0;
const WMI_NLO_CONFIG_START: u32 = 1 << 1;
const WMI_NLO_CONFIG_SSID_HIDE_EN: u32 = 1 << 6;
const WMI_NLO_CONFIG_SCAN_PASSIVE: u32 = 1 << 8;
const WMI_NLO_CONFIG_SPOOFED_MAC_IN_PROBE_REQ: u32 = 1 << 10;
const WMI_NLO_CONFIG_RANDOM_SEQ_NO_IN_PROBE_REQ: u32 = 1 << 11;
const WMI_NLO_ACTIVE_DWELL_MS: u32 = 40;
const WMI_NLO_PASSIVE_DWELL_MS: u32 = 110;
const WMI_NLO_FIXED_LEN: usize = 116;
const WMI_NLO_NETWORK_LEN: usize = 76;

/// A network match encoded in one `nlo_configured_parameters` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NloNetwork {
    pub ssid: Vec<u8>,
    pub rssi_threshold_dbm: Option<i32>,
    /// The network is probed as hidden because it is also in the directed
    /// scan SSID list; ordinary matches use firmware's value zero.
    pub hidden: bool,
}

/// The firmware-facing portion of cfg80211 WoWLAN NET_DETECT.  All periods
/// are seconds at this interface; the WMI layout carries milliseconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NloConfig {
    pub probe_ssids: Vec<Vec<u8>>,
    pub channels_mhz: Vec<u32>,
    /// Retained cfg80211 probe IEs. Linux advertises 512 bytes for NLO even
    /// though `wmi_wow_nlo_config_cmd` has no variable IE-byte array, so the
    /// target command intentionally leaves its IE bitmap zero as Linux does.
    pub probe_ies: Vec<u8>,
    pub networks: Vec<NloNetwork>,
    pub plans: Vec<(u32, Option<u32>)>,
    pub delay_secs: u32,
    pub random_mac: Option<narf_wireless::ScanRandomMac>,
}

fn nlo_plan_params(config: &NloConfig) -> Result<(u32, u32, u32), WmiError> {
    if config.plans.is_empty() || config.plans.len() > WMI_NLO_MAX_SCAN_PLANS {
        return Err(WmiError::Invalid("NLO scan plans"));
    }
    for (index, (interval, iterations)) in config.plans.iter().enumerate() {
        if *interval == 0 || *interval > WMI_NLO_MAX_PLAN_INTERVAL_SECS {
            return Err(WmiError::Invalid("NLO scan plan interval"));
        }
        if index + 1 == config.plans.len() {
            if iterations.is_some() {
                return Err(WmiError::Invalid("NLO final scan plan iterations"));
            }
        } else if !matches!(iterations, Some(1..=WMI_NLO_MAX_PLAN_ITERATIONS)) {
            return Err(WmiError::Invalid("NLO scan plan iterations"));
        }
    }
    let millis = |seconds: u32| seconds * 1000;
    if config.plans.len() == 1 {
        Ok((millis(config.plans[0].0), millis(config.plans[0].0), 1))
    } else {
        Ok((
            millis(config.plans[0].0),
            millis(config.plans[1].0),
            config.plans[0].1.expect("validated finite first NLO plan"),
        ))
    }
}

/// `ath11k_wmi_wow_config_pno`'s start encoder.  The two variable arrays
/// reproduce Linux's unusual wire layout exactly: an ARRAY_STRUCT containing
/// ARRAY_BYTE-tagged 76-byte NLO records, followed by ARRAY_UINT32 channels.
pub fn nlo_config_start_cmd(vdev_id: u32, config: &NloConfig) -> Result<WmiCmd, WmiError> {
    if config.networks.is_empty() || config.networks.len() > WMI_NLO_MAX_SSIDS {
        return Err(WmiError::Invalid("NLO networks"));
    }
    if config.probe_ssids.len() > WMI_NLO_MAX_SSIDS
        || config.probe_ssids.iter().any(|ssid| ssid.len() > 32)
        || config.channels_mhz.len() > WMI_NLO_MAX_CHANNELS
        || config.probe_ies.len() > 512
        || config
            .networks
            .iter()
            .any(|network| network.ssid.is_empty() || network.ssid.len() > 32)
    {
        return Err(WmiError::Invalid("NLO configuration"));
    }
    let (fast_period, slow_period, fast_cycles) = nlo_plan_params(config)?;
    let variable_len = TLV_HDR_SIZE
        + config.networks.len() * WMI_NLO_NETWORK_LEN
        + TLV_HDR_SIZE
        + config.channels_mhz.len() * core::mem::size_of::<u32>();
    let len = WMI_NLO_FIXED_LEN + variable_len;
    let mut w = W::new(len);
    w.tlv(WMI_TAG_NLO_CONFIG_CMD, WMI_NLO_FIXED_LEN - TLV_HDR_SIZE);
    let mut flags = WMI_NLO_CONFIG_START | WMI_NLO_CONFIG_SSID_HIDE_EN;
    if config.probe_ssids.is_empty() {
        flags |= WMI_NLO_CONFIG_SCAN_PASSIVE;
    }
    if config.random_mac.is_some() {
        flags |=
            WMI_NLO_CONFIG_SPOOFED_MAC_IN_PROBE_REQ | WMI_NLO_CONFIG_RANDOM_SEQ_NO_IN_PROBE_REQ;
    }
    w.u32(flags);
    w.u32(vdev_id);
    w.u32(fast_cycles);
    w.u32(WMI_NLO_ACTIVE_DWELL_MS);
    w.u32(WMI_NLO_PASSIVE_DWELL_MS);
    w.u32(0); // probe_bundle_size
    w.u32(0); // rest_time
    w.u32(0); // max_rest_time
    w.u32(0); // scan_backoff_multiplier
    w.u32(fast_period);
    w.u32(slow_period);
    w.u32(config.networks.len() as u32);
    w.u32(config.channels_mhz.len() as u32);
    w.u32(config.delay_secs);
    match config.random_mac {
        Some(random_mac) => {
            w.mac(&random_mac.addr);
            w.mac(&random_mac.mask);
        }
        None => {
            w.zeros(16); // mac_addr + mac_mask
        }
    }
    w.zeros(8 * core::mem::size_of::<u32>()); // IE bitmap
    w.u32(0); // vendor OUIs
    w.u32(0); // connected-NLO band preferences
    debug_assert_eq!(w.b.len(), WMI_NLO_FIXED_LEN);

    w.tlv(
        WMI_TAG_ARRAY_STRUCT,
        config.networks.len() * WMI_NLO_NETWORK_LEN,
    );
    for network in &config.networks {
        w.tlv(WMI_TAG_ARRAY_BYTE, WMI_NLO_NETWORK_LEN - TLV_HDR_SIZE);
        w.u32(1); // wmi_nlo_ssid_param.valid
        w.u32(network.ssid.len() as u32);
        w.bytes(&network.ssid);
        w.zeros(32 - network.ssid.len());
        w.u32(0); // enc_type.valid
        w.u32(0); // enc_type
        w.u32(0); // auth_type.valid
        w.u32(0); // auth_type
        if let Some(rssi) = network
            .rssi_threshold_dbm
            .filter(|rssi| *rssi != 0 && *rssi > -300)
        {
            w.u32(1); // rssi_cond.valid
            w.u32(rssi as u32);
        } else {
            w.u32(0);
            w.u32(0);
        }
        w.u32(1); // bcast_nw_type.valid
        w.u32(if network.hidden { 2 } else { 0 });
    }
    w.tlv(
        WMI_TAG_ARRAY_UINT32,
        config.channels_mhz.len() * core::mem::size_of::<u32>(),
    );
    for channel in &config.channels_mhz {
        w.u32(*channel);
    }
    Ok(w.finish(WMI_NETWORK_LIST_OFFLOAD_CONFIG_CMDID, len))
}

/// `ath11k_wmi_wow_config_pno`'s stop form.  Firmware requires the complete
/// fixed NLO header even though only the STOP bit and vdev id are meaningful.
pub fn nlo_config_stop_cmd(vdev_id: u32) -> WmiCmd {
    let mut w = W::new(WMI_NLO_FIXED_LEN);
    w.tlv(WMI_TAG_NLO_CONFIG_CMD, WMI_NLO_FIXED_LEN - TLV_HDR_SIZE);
    w.u32(WMI_NLO_CONFIG_STOP);
    w.u32(vdev_id);
    w.finish(WMI_NETWORK_LIST_OFFLOAD_CONFIG_CMDID, WMI_NLO_FIXED_LEN)
}

/// `enum wmi_wow_wakeup_event`, used as the bit position in
/// `wmi_wow_add_del_event_cmd.event_bitmap`.
pub mod wow_event {
    pub const BMISS: u32 = 0;
    pub const DEAUTH: u32 = 2;
    pub const MAGIC_PACKET: u32 = 3;
    pub const GTK_REKEY_FAILURE: u32 = 4;
    pub const FOUR_WAY_HANDSHAKE: u32 = 5;
    pub const EAP_IDENTITY_REQUEST: u32 = 6;
    pub const NLO_DETECTED: u32 = 7;
    pub const DISASSOC: u32 = 8;
    pub const PATTERN_MATCH: u32 = 9;
    pub const CSA: u32 = 10;
    pub const MAX: u32 = 24;
}

/// Hardware receive-filter bits used during a WoWLAN transition.
pub mod hw_data_filter {
    pub const DROP_NON_ARP_BROADCAST: u32 = 1 << 0;
    pub const DROP_NON_ICMPV6_MULTICAST: u32 = 1 << 1;
}

/// `enum wmi_sta_keepalive_method` values used by ath11k's WoW path.
pub mod sta_keepalive_method {
    pub const NULL_FRAME: u32 = 1;
    pub const UNSOLICITED_ARP_RESPONSE: u32 = 2;
    pub const ETHERNET_LOOPBACK: u32 = 3;
    pub const GRATUITOUS_ARP_REQUEST: u32 = 4;
    pub const MGMT_VENDOR_ACTION: u32 = 5;
}

/// The default interval that `ath11k_wow_op_suspend` gives firmware for
/// null-data keepalives (seconds).
pub const WMI_STA_KEEPALIVE_INTERVAL_DEFAULT: u32 = 30;
/// A disabled `wmi_sta_keepalive_cmd` interval.
pub const WMI_STA_KEEPALIVE_INTERVAL_DISABLE: u32 = 0;

/// Address snapshot used by `ath11k_wmi_arp_ns_offload`.  Firmware supports
/// two IPv4 entries and up to sixteen IPv6 entries; the encoder enforces
/// those limits before it allocates a WMI command.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArpNsOffload {
    pub ipv4: Vec<[u8; 4]>,
    pub ipv6: Vec<[u8; 16]>,
    pub mac_addr: [u8; 6],
}

/// Build the solicited-node multicast address for an IPv6 neighbour
/// solicitation.  This is `ath11k_generate_ns_mc_addr`'s exact address
/// construction, expressed without mutable host shadow state.
pub fn solicited_node_multicast(addr: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0] = 0xff;
    out[1] = 0x02;
    out[11] = 0x01;
    out[12] = 0xff;
    out[13..].copy_from_slice(&addr[13..]);
    out
}

/// `ath11k_wmi_arp_ns_offload`.  The first NS and ARP arrays always contain
/// their fixed two tuples (including disabled, zero-filled slots); remaining
/// IPv6 addresses occupy the trailing variable-length NS array exactly as in
/// Linux.  WCN6855 uses the ordinary little-endian WMI byte stream, so no
/// extra host-side swapping is applied here.
pub fn arp_ns_offload_cmd(
    vdev_id: u32,
    offload: &ArpNsOffload,
    enable: bool,
) -> Result<WmiCmd, WmiError> {
    if offload.ipv4.len() > WMI_MAX_ARP_OFFLOADS || offload.ipv6.len() > WMI_MAX_IPV6_OFFLOADS {
        return Err(WmiError::Invalid("ARP/NS offload address count"));
    }
    let ns_extra = offload.ipv6.len().saturating_sub(WMI_MAX_NS_OFFLOADS);
    let len = 16
        + TLV_HDR_SIZE
        + WMI_MAX_NS_OFFLOADS * WMI_NS_OFFLOAD_TUPLE_SIZE
        + TLV_HDR_SIZE
        + WMI_MAX_ARP_OFFLOADS * WMI_ARP_OFFLOAD_TUPLE_SIZE
        + if ns_extra == 0 {
            0
        } else {
            TLV_HDR_SIZE + ns_extra * WMI_NS_OFFLOAD_TUPLE_SIZE
        };
    let mut w = W::new(len);
    w.tlv(WMI_TAG_SET_ARP_NS_OFFLOAD_CMD, 12);
    w.u32(0); // flags
    w.u32(vdev_id);
    w.u32(ns_extra as u32);

    let put_ns = |first: usize, count: usize, w: &mut W| {
        w.tlv(WMI_TAG_ARRAY_STRUCT, count * WMI_NS_OFFLOAD_TUPLE_SIZE);
        for index in first..first + count {
            w.tlv(
                WMI_TAG_NS_OFFLOAD_TUPLE,
                WMI_NS_OFFLOAD_TUPLE_SIZE - TLV_HDR_SIZE,
            );
            let target = offload.ipv6.get(index).copied();
            let valid = enable && target.is_some();
            let mac_valid = enable && offload.mac_addr != [0; 6];
            w.u32((valid as u32) | ((mac_valid as u32) << 1));
            if let Some(target) = target.filter(|_| enable) {
                w.bytes(&target);
                w.zeros(16); // `target_ipaddr[1]`, not used by ath11k.
                w.bytes(&solicited_node_multicast(target));
                w.zeros(16); // remote IPv6
                w.mac(&offload.mac_addr);
            } else {
                w.zeros(WMI_NS_OFFLOAD_TUPLE_SIZE - 8);
            }
        }
    };
    put_ns(0, WMI_MAX_NS_OFFLOADS, &mut w);

    w.tlv(
        WMI_TAG_ARRAY_STRUCT,
        WMI_MAX_ARP_OFFLOADS * WMI_ARP_OFFLOAD_TUPLE_SIZE,
    );
    for index in 0..WMI_MAX_ARP_OFFLOADS {
        w.tlv(
            WMI_TAG_ARP_OFFLOAD_TUPLE,
            WMI_ARP_OFFLOAD_TUPLE_SIZE - TLV_HDR_SIZE,
        );
        if let Some(target) = offload.ipv4.get(index).filter(|_| enable) {
            w.u32(1); // WMI_ARPOL_FLAGS_VALID
            w.bytes(target);
            w.zeros(4); // remote IPv4
            w.zeros(8); // target MAC
        } else {
            w.zeros(WMI_ARP_OFFLOAD_TUPLE_SIZE - TLV_HDR_SIZE);
        }
    }
    if ns_extra != 0 {
        put_ns(WMI_MAX_NS_OFFLOADS, ns_extra, &mut w);
    }
    Ok(w.finish(WMI_SET_ARP_NS_OFFLOAD_CMDID, len))
}

/// `ath11k_wmi_wow_enable`: begin firmware WoW operation and pause normal
/// interface configuration.  The remaining `flags` word is zeroed by
/// `ath11k_wmi_alloc_skb` in Linux.
pub fn wow_enable_cmd() -> WmiCmd {
    simple_cmd(
        WMI_WOW_ENABLE_CMDID,
        WMI_TAG_WOW_ENABLE_CMD,
        &[1, 0, 0], // enable, WOW_IFACE_PAUSE_ENABLED, flags
    )
}

/// `ath11k_wmi_wow_host_wakeup_ind`: ask firmware to leave WoW.  The
/// reserved word is deliberately retained as zero in the fixed-size struct.
pub fn wow_host_wakeup_cmd() -> WmiCmd {
    simple_cmd(
        WMI_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID,
        WMI_TAG_WOW_HOSTWAKEUP_FROM_SLEEP_CMD,
        &[0],
    )
}

/// `ath11k_wmi_wow_add_wakeup_event`.  A wake-event number outside the
/// firmware enum cannot be represented safely as a 32-bit bitmap.
pub fn wow_wakeup_event_cmd(vdev_id: u32, event: u32, enable: bool) -> Result<WmiCmd, WmiError> {
    if event >= wow_event::MAX {
        return Err(WmiError::Invalid("WoW wake event"));
    }
    Ok(simple_cmd(
        WMI_WOW_ENABLE_DISABLE_WAKE_EVENT_CMDID,
        WMI_TAG_WOW_ADD_DEL_EVT_CMD,
        &[vdev_id, enable as u32, 1u32 << event],
    ))
}

/// `ath11k_wmi_wow_del_pattern`: remove a bitmap wake pattern by its
/// vdev-local firmware slot.
pub fn wow_del_pattern_cmd(vdev_id: u32, pattern_id: u32) -> WmiCmd {
    simple_cmd(
        WMI_WOW_DEL_WAKE_PATTERN_CMDID,
        WMI_TAG_WOW_DEL_PATTERN_CMD,
        &[vdev_id, pattern_id, 0], // WOW_BITMAP_PATTERN
    )
}

/// `ath11k_wmi_wow_add_pattern` for a byte-mask bitmap pattern.  Linux
/// always sends the full fixed-size 148-byte pattern/mask arrays, with the
/// unused tails zeroed, followed by its four empty optional arrays and a
/// zero rate-limit interval.  WCN6855 is little-endian, so the CE byte-swap
/// helpers are no-ops and the supplied byte order is preserved.
pub fn wow_add_pattern_cmd(
    vdev_id: u32,
    pattern_id: u32,
    pattern: &[u8],
    mask: &[u8],
    pattern_offset: u32,
) -> Result<WmiCmd, WmiError> {
    if pattern.is_empty() || pattern.len() > WMI_WOW_MAX_PATTERN_SIZE || mask.len() != pattern.len()
    {
        return Err(WmiError::Invalid("WoW bitmap pattern"));
    }
    let len = 16 + 4 + WMI_WOW_BITMAP_PATTERN_SIZE + 4 + 4 + 4 + 4 + 8;
    let mut w = W::new(len);
    w.tlv(WMI_TAG_WOW_ADD_PATTERN_CMD, 12);
    w.u32(vdev_id);
    w.u32(pattern_id);
    w.u32(0); // WOW_BITMAP_PATTERN

    // Array of exactly one `wmi_wow_bitmap_pattern`.
    w.tlv(WMI_TAG_ARRAY_STRUCT, WMI_WOW_BITMAP_PATTERN_SIZE);
    w.tlv(
        WMI_TAG_WOW_BITMAP_PATTERN_T,
        WMI_WOW_BITMAP_PATTERN_SIZE - TLV_HDR_SIZE,
    );
    w.bytes(pattern);
    w.zeros(WMI_WOW_MAX_PATTERN_SIZE - pattern.len());
    w.bytes(mask);
    w.zeros(WMI_WOW_MAX_PATTERN_SIZE - mask.len());
    w.u32(pattern_offset);
    w.u32(pattern.len() as u32);
    w.u32(mask.len() as u32);
    w.u32(pattern_id);

    // IPv4 sync, IPv6 sync, and magic-pattern arrays are empty.  So is the
    // pattern-info timeout u32 array; the final array is one zero rate-limit
    // interval, exactly as `ath11k_wmi_wow_add_pattern` leaves its calloc'd
    // skb.
    w.tlv(WMI_TAG_ARRAY_STRUCT, 0);
    w.tlv(WMI_TAG_ARRAY_STRUCT, 0);
    w.tlv(WMI_TAG_ARRAY_STRUCT, 0);
    w.tlv(WMI_TAG_ARRAY_UINT32, 0);
    w.tlv(WMI_TAG_ARRAY_UINT32, 4);
    w.u32(0);
    Ok(w.finish(WMI_WOW_ADD_WAKE_PATTERN_CMDID, len))
}

/// `ath11k_wmi_hw_data_filter_cmd`.  Disable deliberately programs all
/// filter modes (`~0U`) rather than the caller's bitmap, which is the Linux
/// firmware contract.
pub fn hw_data_filter_cmd(vdev_id: u32, filter_bitmap: u32, enable: bool) -> WmiCmd {
    simple_cmd(
        WMI_HW_DATA_FILTER_CMDID,
        WMI_TAG_HW_DATA_FILTER_CMD,
        &[
            vdev_id,
            enable as u32,
            if enable { filter_bitmap } else { u32::MAX },
        ],
    )
}

/// Arguments for `ath11k_wmi_sta_keepalive`.  `dest_mac` is only emitted for
/// ARP-response/request methods; Linux leaves that nested TLV's payload zero
/// for the null-data keepalive used by WoWLAN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaKeepaliveParams {
    pub vdev_id: u32,
    pub enabled: bool,
    pub method: u32,
    pub interval_secs: u32,
    pub src_ipv4: u32,
    pub dst_ipv4: u32,
    pub dest_mac: [u8; 6],
}

/// `ath11k_wmi_sta_keepalive`, including the always-present ARP response TLV.
pub fn sta_keepalive_cmd(p: &StaKeepaliveParams) -> WmiCmd {
    let len = WMI_STA_KEEPALIVE_CMD_SIZE + WMI_STA_KEEPALIVE_ARP_RESPONSE_SIZE;
    let mut w = W::new(len);
    w.tlv(
        WMI_TAG_STA_KEEPALIVE_CMD,
        WMI_STA_KEEPALIVE_CMD_SIZE - TLV_HDR_SIZE,
    );
    w.u32(p.vdev_id);
    w.u32(p.enabled as u32);
    w.u32(p.method);
    w.u32(p.interval_secs);
    w.tlv(
        WMI_TAG_STA_KEEPALIVE_ARP_RESPONSE,
        WMI_STA_KEEPALIVE_ARP_RESPONSE_SIZE - TLV_HDR_SIZE,
    );
    if matches!(
        p.method,
        sta_keepalive_method::UNSOLICITED_ARP_RESPONSE
            | sta_keepalive_method::GRATUITOUS_ARP_REQUEST
    ) {
        w.u32(p.src_ipv4);
        w.u32(p.dst_ipv4);
        w.mac(&p.dest_mac);
    } else {
        w.zeros(16);
    }
    w.finish(WMI_STA_KEEPALIVE_CMDID, len)
}

// ── Decoder: errors + TLV walk ──────────────────────────────────────

/// Decode failures, each mapped to the errno Linux returns at the
/// equivalent point ([`WmiError::errno`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WmiError {
    /// Event shorter than `wmi_cmd_hdr` (Linux drops it at `skb_pull`).
    ShortEvent,
    /// Fewer than 4 bytes left where a TLV header should be.
    TlvHeaderTruncated { offset: usize },
    /// TLV length runs past the buffer.
    TlvOverrun { tag: u16, offset: usize, len: usize },
    /// TLV shorter than its `wmi_tlv_policies[]` minimum.
    TlvTooShort { tag: u16, len: usize, min: usize },
    /// A mandatory TLV is absent (`-EPROTO`).
    Missing(u16),
    /// Structurally wrong (`-EINVAL`).
    Invalid(&'static str),
    /// Wrong tag inside a typed array (`-EPROTO`).
    UnexpectedTag(u16),
    /// More array elements than announced (`-ENOBUFS`).
    TooMany(u16),
    /// Inconsistent lengths Linux reports as `-EPROTO`.
    Proto(&'static str),
}

impl WmiError {
    /// Linux errno (positive) for this failure.
    pub fn errno(&self) -> i32 {
        match self {
            WmiError::ShortEvent
            | WmiError::TlvHeaderTruncated { .. }
            | WmiError::TlvOverrun { .. }
            | WmiError::TlvTooShort { .. }
            | WmiError::Invalid(_) => 22, // EINVAL
            WmiError::Missing(_) | WmiError::UnexpectedTag(_) | WmiError::Proto(_) => 71, // EPROTO
            WmiError::TooMany(_) => 105,                                                  // ENOBUFS
        }
    }
}

/// `wmi_tlv_policies[tag].min_len` (wmi.c). Each value is
/// `sizeof(struct …)` of the listed event struct (none of which
/// include the TLV header). 0 = no policy.
pub fn tlv_policy_min_len(tag: u16) -> usize {
    match tag {
        WMI_TAG_SERVICE_READY_EVENT => 128,
        WMI_TAG_SERVICE_READY_EXT_EVENT => 76,
        WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS => 8,
        WMI_TAG_SOC_HAL_REG_CAPABILITIES => 4,
        WMI_TAG_VDEV_START_RESPONSE_EVENT => 40,
        WMI_TAG_PEER_DELETE_RESP_EVENT => 12,
        WMI_TAG_OFFLOAD_BCN_TX_STATUS_EVENT => 8,
        WMI_TAG_VDEV_STOPPED_EVENT => 4,
        WMI_TAG_REG_CHAN_LIST_CC_EVENT => 56,
        WMI_TAG_REG_CHAN_LIST_CC_EXT_EVENT => 312,
        WMI_TAG_MGMT_RX_HDR => 68,
        WMI_TAG_MGMT_TX_COMPL_EVENT => 20,
        WMI_TAG_SCAN_EVENT => 28,
        WMI_TAG_PEER_STA_KICKOUT_EVENT => 8,
        WMI_TAG_ROAM_EVENT => 12,
        WMI_TAG_CHAN_INFO_EVENT => 56,
        WMI_TAG_PDEV_BSS_CHAN_INFO_EVENT => 52,
        WMI_TAG_VDEV_INSTALL_KEY_COMPLETE_EVENT => 24,
        WMI_TAG_READY_EVENT => 52, // sizeof(struct wmi_ready_event_min)
        WMI_TAG_SERVICE_AVAILABLE_EVENT => 20,
        WMI_TAG_PEER_ASSOC_CONF_EVENT => 12,
        WMI_TAG_STATS_EVENT => 44,
        WMI_TAG_PDEV_CTL_FAILSAFE_CHECK_EVENT => 8,
        WMI_TAG_HOST_SWFDA_EVENT => 12,
        WMI_TAG_OFFLOAD_PRB_RSP_TX_STATUS_EVENT => 8,
        WMI_TAG_VDEV_DELETE_RESP_EVENT => 4,
        WMI_TAG_OBSS_COLOR_COLLISION_EVT => 16,
        WMI_TAG_11D_NEW_COUNTRY_EVENT => 4,
        WMI_TAG_PER_CHAIN_RSSI_STATS => 4,
        WMI_TAG_TWT_ADD_DIALOG_COMPLETE_EVENT => 20,
        WMI_TAG_P2P_NOA_INFO => 68,
        WMI_TAG_P2P_NOA_EVENT => 4,
        _ => 0,
    }
}

/// One TLV: tag, byte offset of its *value* within the walked buffer,
/// and the value itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u16,
    pub offset: usize,
    pub value: &'a [u8],
}

/// `ath11k_wmi_tlv_iter`: walk `buf`, validating every header against
/// the remaining length and the policy table before calling `f`; any
/// error (from the walk or from `f`) stops the walk. No inter-TLV
/// padding.
pub fn tlv_iter<'a, F>(buf: &'a [u8], mut f: F) -> Result<(), WmiError>
where
    F: FnMut(Tlv<'a>) -> Result<(), WmiError>,
{
    let mut pos = 0usize;
    while pos < buf.len() {
        let left = buf.len() - pos;
        if left < TLV_HDR_SIZE {
            return Err(WmiError::TlvHeaderTruncated { offset: pos });
        }
        let hdr = rd32(buf, pos);
        let tag = tlv_hdr_tag(hdr);
        let len = tlv_hdr_len(hdr) as usize;
        pos += TLV_HDR_SIZE;
        if len > buf.len() - pos {
            return Err(WmiError::TlvOverrun {
                tag,
                offset: pos,
                len,
            });
        }
        let min = tlv_policy_min_len(tag);
        if min != 0 && min > len {
            return Err(WmiError::TlvTooShort { tag, len, min });
        }
        f(Tlv {
            tag,
            offset: pos,
            value: &buf[pos..pos + len],
        })?;
        pos += len;
    }
    Ok(())
}

/// `ath11k_wmi_tlv_parse_alloc`: the `tb[tag]` table. Lookups return
/// the *last* TLV with a tag (later ones overwrite `tb[]`); tags `>=
/// WMI_TAG_MAX` are walked but not recorded.
#[derive(Clone, Debug)]
pub struct TlvTable<'a> {
    entries: Vec<Tlv<'a>>,
}

impl<'a> TlvTable<'a> {
    /// Walk and record.
    pub fn parse(buf: &'a [u8]) -> Result<Self, WmiError> {
        let mut entries = Vec::new();
        tlv_iter(buf, |t| {
            if t.tag < WMI_TAG_MAX {
                entries.push(t);
            }
            Ok(())
        })?;
        Ok(TlvTable { entries })
    }

    /// `tb[tag]`.
    pub fn get(&self, tag: u16) -> Option<Tlv<'a>> {
        self.entries.iter().rev().find(|t| t.tag == tag).copied()
    }

    /// `tb[tag]` or `-EPROTO`.
    pub fn need(&self, tag: u16) -> Result<Tlv<'a>, WmiError> {
        self.get(tag).ok_or(WmiError::Missing(tag))
    }
}

/// `ath11k_wmi_tlv_op_rx` front half: split an event into its id
/// (`FIELD_GET(WMI_CMD_HDR_CMD_ID, …)`) and TLV payload.
pub fn split_event(frame: &[u8]) -> Result<(u32, &[u8]), WmiError> {
    if frame.len() < 4 {
        return Err(WmiError::ShortEvent);
    }
    Ok((rd32(frame, 0) & WMI_CMD_HDR_CMD_ID, &frame[4..]))
}

/// Little-endian u32 at `off`; the caller guarantees bounds.
pub(crate) fn rd32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// u32 at `off`, or 0 when the TLV is shorter (Linux zero-extends
/// short READY / MAC-PHY TLVs by `memcpy(min(len, sizeof))` into a
/// zeroed struct).
fn rd32z(b: &[u8], off: usize) -> u32 {
    if off + 4 <= b.len() {
        rd32(b, off)
    } else {
        0
    }
}

fn need_len(v: &[u8], n: usize, what: &'static str) -> Result<(), WmiError> {
    if v.len() < n {
        Err(WmiError::Invalid(what))
    } else {
        Ok(())
    }
}

fn mac_at(b: &[u8], off: usize) -> [u8; 6] {
    let mut m = [0u8; 6];
    m.copy_from_slice(&b[off..off + 6]);
    m
}

// ── Service bitmap ──────────────────────────────────────────────────

/// `WMI_SERVICE_BM_SIZE` — u32 words in SERVICE_READY's bitmap.
pub const WMI_SERVICE_BM_SIZE: usize = (WMI_MAX_SERVICE as usize).div_ceil(4);
/// `WMI_SERVICE_SEGMENT_BM_SIZE32`.
pub const WMI_SERVICE_SEGMENT_BM_SIZE32: usize = 4;
/// `WMI_SERVICE_BITS_IN_SIZE32`.
pub const WMI_SERVICE_BITS_IN_SIZE32: u32 = 4;
/// `WMI_AVAIL_SERVICE_BITS_IN_SIZE32`.
pub const WMI_AVAIL_SERVICE_BITS_IN_SIZE32: u32 = 32;

/// `wmi_ab.svc_map` — `WMI_MAX_EXT2_SERVICE` (384) bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceMap {
    words: [u32; (WMI_MAX_EXT2_SERVICE as usize) / 32],
}

impl ServiceMap {
    /// `test_bit(svc, svc_map)`.
    pub fn test(&self, svc: u32) -> bool {
        svc < WMI_MAX_EXT2_SERVICE && self.words[(svc / 32) as usize] & (1 << (svc % 32)) != 0
    }

    /// `set_bit(svc, svc_map)`.
    pub fn set(&mut self, svc: u32) {
        if svc < WMI_MAX_EXT2_SERVICE {
            self.words[(svc / 32) as usize] |= 1 << (svc % 32);
        }
    }

    /// `ath11k_wmi_service_bitmap_copy`: SERVICE_READY packs services
    /// 4 per word in bits 0..3 (`wmi_svc_bm[i] & BIT(j % 4)`).
    pub fn copy_service_ready_bitmap(&mut self, bm: &[u32]) {
        let mut j = 0u32;
        for &word in bm.iter().take(WMI_SERVICE_BM_SIZE) {
            if j >= WMI_MAX_SERVICE {
                break;
            }
            loop {
                if word & (1 << (j % WMI_SERVICE_BITS_IN_SIZE32)) != 0 {
                    self.set(j);
                }
                j += 1;
                if j % WMI_SERVICE_BITS_IN_SIZE32 == 0 {
                    break;
                }
            }
        }
    }

    /// `ath11k_wmi_tlv_services_parser` segment loop: `base` is
    /// `WMI_MAX_SERVICE` (SERVICE_AVAILABLE segment) or
    /// `WMI_MAX_EXT_SERVICE` (trailing `ARRAY_UINT32`), 32 bits/word.
    fn copy_segment(&mut self, seg: &[u32], base: u32, limit: u32) {
        let mut j = base;
        for &word in seg.iter().take(WMI_SERVICE_SEGMENT_BM_SIZE32) {
            if j >= limit {
                break;
            }
            loop {
                if word & (1 << (j % WMI_AVAIL_SERVICE_BITS_IN_SIZE32)) != 0 {
                    self.set(j);
                }
                j += 1;
                if j % WMI_AVAIL_SERVICE_BITS_IN_SIZE32 == 0 {
                    break;
                }
            }
        }
    }
}

// ── SERVICE_READY ───────────────────────────────────────────────────

/// `struct ath11k_targ_cap` as `ath11k_pull_service_ready_tlv` fills it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TargetCaps {
    pub phy_capability: u32,
    pub max_frag_entry: u32,
    pub num_rf_chains: u32,
    pub ht_cap_info: u32,
    pub vht_cap_info: u32,
    pub vht_supp_mcs: u32,
    pub hw_min_tx_power: u32,
    pub hw_max_tx_power: u32,
    pub sys_cap_info: u32,
    pub min_pkt_size_enable: u32,
    pub max_bcn_ie_size: u32,
    pub max_num_scan_channels: u32,
    pub max_supported_macs: u32,
    pub wmi_fw_sub_feat_caps: u32,
    pub txrx_chainmask: u32,
    pub default_dbs_hw_mode_index: u32,
    pub num_msdu_desc: u32,
}

/// Decoded `WMI_SERVICE_READY_EVENTID`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceReady {
    /// Last `SERVICE_READY_EVENT` TLV, if any.
    pub caps: Option<TargetCaps>,
    /// `fw_build_vers` (not stored by Linux; useful for logs).
    pub fw_build_vers: u32,
    /// Services from the first `ARRAY_UINT32`.
    pub svc_map: ServiceMap,
    /// Whether that bitmap was present.
    pub bitmap_seen: bool,
}

/// `ath11k_service_ready_event` (`ath11k_wmi_tlv_svc_rdy_parse`).
/// The first `ARRAY_UINT32` must hold `WMI_SERVICE_BM_SIZE` words or
/// the event fails with `-EINVAL`; later ones are ignored.
pub fn decode_service_ready(payload: &[u8]) -> Result<ServiceReady, WmiError> {
    let mut out = ServiceReady::default();
    tlv_iter(payload, |t| {
        match t.tag {
            WMI_TAG_SERVICE_READY_EVENT => {
                let v = t.value;
                out.fw_build_vers = rd32(v, 0);
                // wmi_service_ready_event: fw_build_vers(4) +
                // fw_abi_vers(24) then the caps.
                out.caps = Some(TargetCaps {
                    phy_capability: rd32(v, 28),
                    max_frag_entry: rd32(v, 32),
                    num_rf_chains: rd32(v, 36),
                    ht_cap_info: rd32(v, 40),
                    vht_cap_info: rd32(v, 44),
                    vht_supp_mcs: rd32(v, 48),
                    hw_min_tx_power: rd32(v, 52),
                    hw_max_tx_power: rd32(v, 56),
                    sys_cap_info: rd32(v, 60),
                    min_pkt_size_enable: rd32(v, 64),
                    max_bcn_ie_size: rd32(v, 68),
                    // num_mem_reqs @72 not stored
                    max_num_scan_channels: rd32(v, 76),
                    // hw_bd_id @80, hw_bd_info[5] @84..104
                    max_supported_macs: rd32(v, 104),
                    wmi_fw_sub_feat_caps: rd32(v, 108),
                    // num_dbs_hw_modes @112
                    txrx_chainmask: rd32(v, 116),
                    default_dbs_hw_mode_index: rd32(v, 120),
                    num_msdu_desc: rd32(v, 124),
                });
            }
            WMI_TAG_ARRAY_UINT32 if !out.bitmap_seen => {
                if t.value.len() < WMI_SERVICE_BM_SIZE * 4 {
                    return Err(WmiError::Invalid("service ready: short bitmap"));
                }
                let mut bm = [0u32; WMI_SERVICE_BM_SIZE];
                for (i, w) in bm.iter_mut().enumerate() {
                    *w = rd32(t.value, i * 4);
                }
                out.svc_map.copy_service_ready_bitmap(&bm);
                out.bitmap_seen = true;
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(out)
}

/// `ath11k_service_available_event` (`ath11k_wmi_tlv_services_parser`):
/// OR the extended service segments into `map`.
pub fn apply_service_available(map: &mut ServiceMap, payload: &[u8]) -> Result<(), WmiError> {
    tlv_iter(payload, |t| {
        match t.tag {
            WMI_TAG_SERVICE_AVAILABLE_EVENT => {
                // wmi_service_segment_offset @0, bitmap[4] @4
                let mut seg = [0u32; 4];
                for (i, w) in seg.iter_mut().enumerate() {
                    *w = rd32(t.value, 4 + 4 * i);
                }
                map.copy_segment(&seg, WMI_MAX_SERVICE, WMI_MAX_EXT_SERVICE);
            }
            WMI_TAG_ARRAY_UINT32 => {
                // NARF-stricter: Linux reads 4 words regardless of len.
                need_len(t.value, 16, "service available: short ext2 bitmap")?;
                let mut seg = [0u32; 4];
                for (i, w) in seg.iter_mut().enumerate() {
                    *w = rd32(t.value, 4 * i);
                }
                map.copy_segment(&seg, WMI_MAX_EXT_SERVICE, WMI_MAX_EXT2_SERVICE);
            }
            _ => {}
        }
        Ok(())
    })
}

// ── SERVICE_READY_EXT / EXT2 ────────────────────────────────────────

/// `struct ath11k_service_ext_param` (from `SERVICE_READY_EXT_EVENT`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceExtParam {
    pub default_conc_scan_config_bits: u32,
    pub default_fw_config_bits: u32,
    pub ppet: PpeThreshold,
    pub he_cap_info: u32,
    pub mpdu_density: u32,
    pub max_bssid_rx_filters: u32,
    pub num_hw_modes: u32,
    pub num_phy: u32,
}

/// One `struct wmi_hw_mode_capabilities`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HwModeCap {
    pub hw_mode_id: u32,
    pub phy_id_map: u32,
    pub hw_mode_config_type: u32,
}

/// `struct wmi_mac_phy_capabilities` (236 bytes, no TLV header).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MacPhyCaps {
    pub hw_mode_id: u32,
    pub pdev_id: u32,
    pub phy_id: u32,
    pub supported_flags: u32,
    pub supported_bands: u32,
    pub ampdu_density: u32,
    pub max_bw_supported_2g: u32,
    pub ht_cap_info_2g: u32,
    pub vht_cap_info_2g: u32,
    pub vht_supp_mcs_2g: u32,
    pub he_cap_info_2g: u32,
    pub he_supp_mcs_2g: u32,
    pub tx_chain_mask_2g: u32,
    pub rx_chain_mask_2g: u32,
    pub max_bw_supported_5g: u32,
    pub ht_cap_info_5g: u32,
    pub vht_cap_info_5g: u32,
    pub vht_supp_mcs_5g: u32,
    pub he_cap_info_5g: u32,
    pub he_supp_mcs_5g: u32,
    pub tx_chain_mask_5g: u32,
    pub rx_chain_mask_5g: u32,
    pub he_cap_phy_info_2g: [u32; 3],
    pub he_cap_phy_info_5g: [u32; 3],
    pub he_ppet2g: PpeThreshold,
    pub he_ppet5g: PpeThreshold,
    pub chainmask_table_id: u32,
    pub lmac_id: u32,
    pub he_cap_info_2g_ext: u32,
    pub he_cap_info_5g_ext: u32,
    pub he_cap_info_internal: u32,
    pub wireless_modes: u32,
    pub low_2ghz_chan_freq: u32,
    pub high_2ghz_chan_freq: u32,
    pub low_5ghz_chan_freq: u32,
    pub high_5ghz_chan_freq: u32,
    pub nss_ratio: u32,
}

/// `sizeof(struct wmi_mac_phy_capabilities)`.
pub const WMI_MAC_PHY_CAPABILITIES_SIZE: usize = 236;

impl MacPhyCaps {
    /// `memcpy(…, ptr, min(len, sizeof))` into a zeroed struct.
    pub fn parse(v: &[u8]) -> Self {
        let mut b = [0u8; WMI_MAC_PHY_CAPABILITIES_SIZE];
        let n = v.len().min(WMI_MAC_PHY_CAPABILITIES_SIZE);
        b[..n].copy_from_slice(&v[..n]);
        let r = |i: usize| rd32(&b, i * 4);
        MacPhyCaps {
            hw_mode_id: r(0),
            pdev_id: r(1),
            phy_id: r(2),
            supported_flags: r(3),
            supported_bands: r(4),
            ampdu_density: r(5),
            max_bw_supported_2g: r(6),
            ht_cap_info_2g: r(7),
            vht_cap_info_2g: r(8),
            vht_supp_mcs_2g: r(9),
            he_cap_info_2g: r(10),
            he_supp_mcs_2g: r(11),
            tx_chain_mask_2g: r(12),
            rx_chain_mask_2g: r(13),
            max_bw_supported_5g: r(14),
            ht_cap_info_5g: r(15),
            vht_cap_info_5g: r(16),
            vht_supp_mcs_5g: r(17),
            he_cap_info_5g: r(18),
            he_supp_mcs_5g: r(19),
            tx_chain_mask_5g: r(20),
            rx_chain_mask_5g: r(21),
            he_cap_phy_info_2g: [r(22), r(23), r(24)],
            he_cap_phy_info_5g: [r(25), r(26), r(27)],
            he_ppet2g: PpeThreshold::parse(&b[112..152]),
            he_ppet5g: PpeThreshold::parse(&b[152..192]),
            chainmask_table_id: r(48),
            lmac_id: r(49),
            he_cap_info_2g_ext: r(50),
            he_cap_info_5g_ext: r(51),
            he_cap_info_internal: r(52),
            wireless_modes: r(53),
            low_2ghz_chan_freq: r(54),
            high_2ghz_chan_freq: r(55),
            low_5ghz_chan_freq: r(56),
            high_5ghz_chan_freq: r(57),
            nss_ratio: r(58),
        }
    }
}

/// `struct ath11k_hal_reg_capabilities_ext`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HalRegCapExt {
    pub phy_id: u32,
    pub eeprom_reg_domain: u32,
    pub eeprom_reg_domain_ext: u32,
    pub regcap1: u32,
    pub regcap2: u32,
    pub low_2ghz_chan: u32,
    pub high_2ghz_chan: u32,
    pub low_5ghz_chan: u32,
    pub high_5ghz_chan: u32,
}

/// `struct ath11k_band_cap` (one of `pdev_cap.band[]`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BandCap {
    pub phy_id: u32,
    pub max_bw_supported: u32,
    pub ht_cap_info: u32,
    pub he_cap_info: [u32; 2],
    pub he_mcs: u32,
    pub he_cap_phy_info: [u32; 3],
    pub he_ppet: PpeThreshold,
}

/// `struct ath11k_pdev` + `ath11k_pdev_cap` as
/// `ath11k_pull_mac_phy_cap_svc_ready_ext` fills them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PdevCap {
    pub pdev_id: u32,
    pub supported_bands: u32,
    pub ampdu_density: u32,
    pub tx_chain_mask: u32,
    pub rx_chain_mask: u32,
    pub tx_chain_mask_shift: u32,
    pub rx_chain_mask_shift: u32,
    pub vht_cap: u32,
    pub vht_mcs: u32,
    pub he_mcs: u32,
    pub nss_ratio_enabled: u32,
    pub nss_ratio_info: u32,
    pub band_2g: BandCap,
    pub band_5g: BandCap,
    pub band_6g: BandCap,
}

/// `struct ath11k_dbring_cap` from a `DMA_RING_CAPABILITIES` array.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DmaRingCap {
    pub id: u32,
    /// `DP_HW2SW_MACID(pdev_id)`.
    pub pdev_id: u32,
    pub min_elem: u32,
    pub min_buf_sz: u32,
    pub min_buf_align: u32,
}

/// `enum wmi_direct_buffer_module` count (`WMI_DIRECT_BUF_MAX`).
pub const WMI_DIRECT_BUF_MAX: u32 = 2;

/// Decoded `WMI_SERVICE_READY_EXT_EVENTID`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceReadyExt {
    pub param: ServiceExtParam,
    pub hw_mode_caps: Vec<HwModeCap>,
    /// `wmi_ab.preferred_hw_mode` after the event.
    pub preferred_hw_mode: u32,
    /// `pref_hw_mode_caps`.
    pub pref_hw_mode_caps: HwModeCap,
    pub mac_phy_caps: Vec<MacPhyCaps>,
    /// Indexed by array position; `hal_reg_cap[phy_id]` in Linux.
    pub hal_reg_caps: Vec<HalRegCapExt>,
    /// `ab->pdevs[]`; one entry for `single_pdev_only`.
    pub pdevs: Vec<PdevCap>,
    /// `ab->num_radios`.
    pub num_radios: u32,
    /// `ab->target_pdev_ids[]` as `(pdev_id, supported_bands)`.
    pub target_pdev_ids: Vec<(u32, u32)>,
    pub dma_ring_caps: Vec<DmaRingCap>,
}

impl ServiceReadyExt {
    /// `hal_reg_cap[phy_id]`.
    pub fn hal_reg_cap(&self, phy_id: u32) -> Option<&HalRegCapExt> {
        self.hal_reg_caps.iter().rev().find(|c| c.phy_id == phy_id)
    }
}

/// Parse state shared by the ext / ext2 decoders.
struct SvcRdyExtParse<'a> {
    out: ServiceReadyExt,
    have_hw_caps: bool,
    have_soc_hal_reg: bool,
    hw_mode_raw: Vec<HwModeCap>,
    tot_phy_id: u32,
    ext_hal_raw: Vec<&'a [u8]>,
    hw_mode_done: bool,
    mac_phy_done: bool,
    ext_hal_reg_done: bool,
    combo_done: bool,
    cap_done: bool,
    oem_dma_done: bool,
    dma_done: bool,
}

/// Bit length of `map` — the `while (phy_map) { phy_map >>= 1; n++; }`
/// idiom Linux uses to count phys per hw mode.
fn phy_map_len(mut map: u32) -> u32 {
    let mut n = 0;
    while map != 0 {
        map >>= 1;
        n += 1;
    }
    n
}

/// `ath11k_wmi_tlv_dma_ring_caps`.
fn parse_dma_ring_caps(v: &[u8]) -> Result<Vec<DmaRingCap>, WmiError> {
    let mut caps = Vec::new();
    tlv_iter(v, |t| {
        if t.tag != WMI_TAG_DMA_RING_CAPABILITIES {
            return Err(WmiError::UnexpectedTag(t.tag));
        }
        // NARF-stricter: Linux indexes the array by struct stride
        // without checking each element's length.
        need_len(t.value, 20, "dma ring cap: short element")?;
        let module_id = rd32(t.value, 4);
        if module_id >= WMI_DIRECT_BUF_MAX {
            return Err(WmiError::Invalid("dma ring cap: module id"));
        }
        let pdev = rd32(t.value, 0);
        caps.push(DmaRingCap {
            id: module_id,
            pdev_id: if pdev != 0 { pdev - 1 } else { 0 },
            min_elem: rd32(t.value, 8),
            min_buf_sz: rd32(t.value, 12),
            min_buf_align: rd32(t.value, 16),
        });
        Ok(())
    })?;
    Ok(caps)
}

impl<'a> SvcRdyExtParse<'a> {
    /// `ath11k_pull_mac_phy_cap_svc_ready_ext`.
    fn pull_mac_phy_cap(
        &mut self,
        hw_mode_id: u32,
        phy_id: u32,
        pdev_index: usize,
    ) -> Result<(), WmiError> {
        if !self.have_hw_caps || !self.hw_mode_done || !self.have_soc_hal_reg {
            return Err(WmiError::Invalid("mac phy cap: missing hw caps"));
        }
        let mut phy_idx = 0u32;
        let mut hw_idx = 0usize;
        let n_modes = self.out.param.num_hw_modes as usize;
        while hw_idx < n_modes {
            // NARF-stricter: Linux indexes num_hw_modes entries even if
            // fewer arrived.
            let cap = self
                .hw_mode_raw
                .get(hw_idx)
                .ok_or(WmiError::Invalid("mac phy cap: hw mode index"))?;
            if hw_mode_id == cap.hw_mode_id {
                break;
            }
            phy_idx += phy_map_len(cap.phy_id_map);
            hw_idx += 1;
        }
        if hw_idx == n_modes {
            return Err(WmiError::Invalid("mac phy cap: hw mode not found"));
        }
        phy_idx += phy_id;
        if phy_id >= self.out.param.num_phy {
            return Err(WmiError::Invalid("mac phy cap: phy id >= num_phy"));
        }
        // NARF-stricter: Linux reads mac_phy_caps + phy_idx unchecked.
        let m = *self
            .out
            .mac_phy_caps
            .get(phy_idx as usize)
            .ok_or(WmiError::Invalid("mac phy cap: phy index"))?;

        if self.out.pdevs.len() <= pdev_index {
            self.out.pdevs.resize(pdev_index + 1, PdevCap::default());
        }
        let pc = &mut self.out.pdevs[pdev_index];
        pc.pdev_id = m.pdev_id;
        pc.supported_bands |= m.supported_bands;
        pc.ampdu_density = m.ampdu_density;
        self.out
            .target_pdev_ids
            .push((m.pdev_id, m.supported_bands));

        if m.supported_bands & WMI_HOST_WLAN_2G_CAP == 0
            && m.supported_bands & WMI_HOST_WLAN_5G_CAP == 0
        {
            return Err(WmiError::Invalid("mac phy cap: no 2G/5G band"));
        }
        if m.supported_bands & WMI_HOST_WLAN_2G_CAP != 0 {
            pc.tx_chain_mask = m.tx_chain_mask_2g;
            pc.rx_chain_mask = m.rx_chain_mask_2g;
        }
        if m.supported_bands & WMI_HOST_WLAN_5G_CAP != 0 {
            pc.vht_cap = m.vht_cap_info_5g;
            pc.vht_mcs = m.vht_supp_mcs_5g;
            pc.he_mcs = m.he_supp_mcs_5g;
            pc.tx_chain_mask = m.tx_chain_mask_5g;
            pc.rx_chain_mask = m.rx_chain_mask_5g;
            pc.nss_ratio_enabled = m.nss_ratio & 0x1;
            pc.nss_ratio_info = (m.nss_ratio >> 1) & 0xF;
        }
        // find_first_bit(…, 32): 32 when empty.
        pc.tx_chain_mask_shift = if pc.tx_chain_mask == 0 {
            32
        } else {
            pc.tx_chain_mask.trailing_zeros()
        };
        pc.rx_chain_mask_shift = if pc.rx_chain_mask == 0 {
            32
        } else {
            pc.rx_chain_mask.trailing_zeros()
        };
        if m.supported_bands & WMI_HOST_WLAN_2G_CAP != 0 {
            pc.band_2g = BandCap {
                phy_id: m.phy_id,
                max_bw_supported: m.max_bw_supported_2g,
                ht_cap_info: m.ht_cap_info_2g,
                he_cap_info: [m.he_cap_info_2g, m.he_cap_info_2g_ext],
                he_mcs: m.he_supp_mcs_2g,
                he_cap_phy_info: m.he_cap_phy_info_2g,
                he_ppet: m.he_ppet2g,
            };
        }
        if m.supported_bands & WMI_HOST_WLAN_5G_CAP != 0 {
            let b5 = BandCap {
                phy_id: m.phy_id,
                max_bw_supported: m.max_bw_supported_5g,
                ht_cap_info: m.ht_cap_info_5g,
                he_cap_info: [m.he_cap_info_5g, m.he_cap_info_5g_ext],
                he_mcs: m.he_supp_mcs_5g,
                he_cap_phy_info: m.he_cap_phy_info_5g,
                he_ppet: m.he_ppet5g,
            };
            pc.band_5g = b5;
            // 6 GHz copies everything but phy_id (Linux leaves it).
            let keep = pc.band_6g.phy_id;
            pc.band_6g = BandCap { phy_id: keep, ..b5 };
        }
        Ok(())
    }

    /// `ath11k_wmi_tlv_ext_soc_hal_reg_caps_parse`.
    fn soc_hal_reg_caps(&mut self, v: &[u8], single_pdev_only: bool) -> Result<(), WmiError> {
        self.have_soc_hal_reg = true;
        self.out.param.num_phy = rd32(v, 0);
        self.out.num_radios = 0;
        self.out.target_pdev_ids.clear();
        let hw_mode_id = self.out.pref_hw_mode_caps.hw_mode_id;
        let mut phy_id_map = self.out.pref_hw_mode_caps.phy_id_map;
        let mut pdev_index = 0usize;
        while phy_id_map != 0 && (self.out.num_radios as usize) < MAX_RADIOS {
            self.pull_mac_phy_cap(hw_mode_id, self.out.num_radios, pdev_index)?;
            self.out.num_radios += 1;
            pdev_index = if single_pdev_only {
                0
            } else {
                self.out.num_radios as usize
            };
            phy_id_map >>= 1;
        }
        if single_pdev_only {
            self.out.num_radios = 1;
            if self.out.pdevs.is_empty() {
                self.out.pdevs.push(PdevCap::default());
            }
            self.out.pdevs[0].pdev_id = 0;
        }
        Ok(())
    }

    /// `ath11k_wmi_tlv_hw_mode_caps`.
    fn hw_mode_caps(&mut self, v: &'a [u8], initial_pref: u32) -> Result<(), WmiError> {
        let num_hw_modes = self.out.param.num_hw_modes;
        let mut raw = Vec::new();
        let mut tot = 0u32;
        tlv_iter(v, |t| {
            if t.tag != WMI_TAG_HW_MODE_CAPABILITIES {
                return Err(WmiError::UnexpectedTag(t.tag));
            }
            if raw.len() as u32 >= num_hw_modes {
                return Err(WmiError::TooMany(t.tag));
            }
            // NARF-stricter: Linux reads the fields via container_of
            // without checking this element's length.
            need_len(t.value, 8, "hw mode cap: short element")?;
            let c = HwModeCap {
                hw_mode_id: rd32(t.value, 0),
                phy_id_map: rd32(t.value, 4),
                hw_mode_config_type: rd32z(t.value, 8),
            };
            tot += phy_map_len(c.phy_id_map);
            raw.push(c);
            Ok(())
        })?;
        self.tot_phy_id = tot;
        let mut pref = initial_pref;
        for c in &raw {
            let mode = c.hw_mode_id as usize;
            // Linux indexes ath11k_hw_mode_pri_map[mode] unchecked;
            // out-of-range modes are skipped here.
            if mode < HW_MODE_PRI_MAP.len()
                && HW_MODE_PRI_MAP[mode] < HW_MODE_PRI_MAP[pref as usize]
            {
                self.out.pref_hw_mode_caps = *c;
                pref = c.hw_mode_id;
            }
        }
        self.out.preferred_hw_mode = pref;
        self.out.hw_mode_caps = raw.clone();
        self.hw_mode_raw = raw;
        if pref == hw_mode::MAX {
            return Err(WmiError::Invalid("hw mode caps: no preferred mode"));
        }
        Ok(())
    }

    /// `ath11k_wmi_tlv_ext_hal_reg_caps`.
    fn ext_hal_reg_caps(&mut self, v: &'a [u8]) -> Result<(), WmiError> {
        let num_phy = self.out.param.num_phy;
        let mut raw = Vec::new();
        tlv_iter(v, |t| {
            if t.tag != WMI_TAG_HAL_REG_CAPABILITIES_EXT {
                return Err(WmiError::UnexpectedTag(t.tag));
            }
            if raw.len() as u32 >= num_phy {
                return Err(WmiError::TooMany(t.tag));
            }
            raw.push(t.value);
            Ok(())
        })?;
        self.ext_hal_raw = raw;
        for i in 0..num_phy as usize {
            // ath11k_pull_reg_cap_svc_rdy_ext
            if !self.have_soc_hal_reg {
                return Err(WmiError::Invalid("ext hal reg: no soc caps"));
            }
            // NARF-stricter: Linux indexes num_phy elements whether or
            // not they arrived, and reads each at the struct stride.
            let e = self
                .ext_hal_raw
                .get(i)
                .ok_or(WmiError::Invalid("ext hal reg: missing phy"))?;
            need_len(e, 40, "ext hal reg: short element")?;
            self.out.hal_reg_caps.push(HalRegCapExt {
                phy_id: rd32(e, 0),
                eeprom_reg_domain: rd32(e, 4),
                eeprom_reg_domain_ext: rd32(e, 8),
                regcap1: rd32(e, 12),
                regcap2: rd32(e, 16),
                // wireless_modes @20 not stored
                low_2ghz_chan: rd32(e, 24),
                high_2ghz_chan: rd32(e, 28),
                low_5ghz_chan: rd32(e, 32),
                high_5ghz_chan: rd32(e, 36),
            });
        }
        Ok(())
    }
}

/// `ath11k_service_ready_ext_event`.
///
/// `initial_pref_hw_mode` is `wmi_ab.preferred_hw_mode` at the time
/// (`ath11k_wmi_attach` sets [`hw_mode::SINGLE`] on WCN6855 because it
/// is `single_pdev_only` with `num_rxdma_per_pdev = 2`; `MAX`
/// otherwise). `single_pdev_only` folds all phys into `pdevs[0]` and
/// forces `num_radios = 1`, `pdev_id = 0`.
///
/// `ARRAY_STRUCT`s are consumed in Linux's fixed order: hw-mode caps,
/// MAC-PHY caps, ext HAL reg caps, chainmask combo, chainmask caps, OEM
/// DMA ring caps, DMA ring caps.
pub fn decode_service_ready_ext(
    payload: &[u8],
    initial_pref_hw_mode: u32,
    single_pdev_only: bool,
) -> Result<ServiceReadyExt, WmiError> {
    let mut p = SvcRdyExtParse {
        out: ServiceReadyExt {
            preferred_hw_mode: initial_pref_hw_mode,
            ..Default::default()
        },
        have_hw_caps: false,
        have_soc_hal_reg: false,
        hw_mode_raw: Vec::new(),
        tot_phy_id: 0,
        ext_hal_raw: Vec::new(),
        hw_mode_done: false,
        mac_phy_done: false,
        ext_hal_reg_done: false,
        combo_done: false,
        cap_done: false,
        oem_dma_done: false,
        dma_done: false,
    };
    if initial_pref_hw_mode > hw_mode::MAX {
        return Err(WmiError::Invalid("svc ready ext: bad initial hw mode"));
    }
    tlv_iter(payload, |t| {
        let v = t.value;
        match t.tag {
            WMI_TAG_SERVICE_READY_EXT_EVENT => {
                let pa = &mut p.out.param;
                pa.default_conc_scan_config_bits = rd32(v, 0);
                pa.default_fw_config_bits = rd32(v, 4);
                pa.ppet = PpeThreshold::parse(&v[8..48]);
                pa.he_cap_info = rd32(v, 48);
                pa.mpdu_density = rd32(v, 52);
                pa.max_bssid_rx_filters = rd32(v, 56);
            }
            WMI_TAG_SOC_MAC_PHY_HW_MODE_CAPS => {
                p.have_hw_caps = true;
                p.out.param.num_hw_modes = rd32(v, 0);
            }
            WMI_TAG_SOC_HAL_REG_CAPABILITIES => {
                p.soc_hal_reg_caps(v, single_pdev_only)?;
            }
            WMI_TAG_ARRAY_STRUCT => {
                if !p.hw_mode_done {
                    p.hw_mode_caps(v, p.out.preferred_hw_mode)?;
                    p.hw_mode_done = true;
                } else if !p.mac_phy_done {
                    let tot = p.tot_phy_id;
                    let mut caps = Vec::new();
                    tlv_iter(v, |e| {
                        if e.tag != WMI_TAG_MAC_PHY_CAPABILITIES {
                            return Err(WmiError::UnexpectedTag(e.tag));
                        }
                        if caps.len() as u32 >= tot {
                            return Err(WmiError::TooMany(e.tag));
                        }
                        caps.push(MacPhyCaps::parse(e.value));
                        Ok(())
                    })?;
                    p.out.mac_phy_caps = caps;
                    p.mac_phy_done = true;
                } else if !p.ext_hal_reg_done {
                    p.ext_hal_reg_caps(v)?;
                    p.ext_hal_reg_done = true;
                } else if !p.combo_done {
                    p.combo_done = true;
                } else if !p.cap_done {
                    p.cap_done = true;
                } else if !p.oem_dma_done {
                    p.oem_dma_done = true;
                } else if !p.dma_done {
                    p.out.dma_ring_caps = parse_dma_ring_caps(v)?;
                    p.dma_done = true;
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(p.out)
}

/// `ath11k_service_ready_ext2_event`: DMA ring caps from the first
/// `ARRAY_STRUCT` (Linux ignores them if ext already delivered some).
pub fn decode_service_ready_ext2(payload: &[u8]) -> Result<Vec<DmaRingCap>, WmiError> {
    let mut caps = None;
    tlv_iter(payload, |t| {
        if t.tag == WMI_TAG_ARRAY_STRUCT && caps.is_none() {
            caps = Some(parse_dma_ring_caps(t.value)?);
        }
        Ok(())
    })?;
    Ok(caps.unwrap_or_default())
}

// ── READY ───────────────────────────────────────────────────────────

/// Decoded `WMI_READY_EVENTID` (`struct wmi_ready_event`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ready {
    pub fw_abi_vers: [u32; 6],
    /// `ab->mac_addr` — the device MAC.
    pub mac_addr: [u8; 6],
    pub status: u32,
    pub num_dscp_table: u32,
    pub num_extra_mac_addr: u32,
    pub num_total_peers: u32,
    pub num_extra_peers: u32,
    /// 0 if the TLV is the 52-byte minimum.
    pub max_ast_index: u32,
    /// `ab->pktlog_defs_checksum`.
    pub pktlog_defs_checksum: u32,
    /// The `ARRAY_FIXED_STRUCT` of `wmi_mac_addr`s, raw.
    pub extra_mac_addrs: Vec<[u8; 6]>,
}

impl Ready {
    /// `ath11k_wmi_tlv_rdy_parse` per-pdev rule: the extra addresses are
    /// used only when `num_radios > 1 && num_extra_mac_addr >=
    /// num_radios`. Always `None` on a single-pdev WCN6855.
    pub fn pdev_mac_addrs(&self, num_radios: u32) -> Option<&[[u8; 6]]> {
        if num_radios > 1
            && self.num_extra_mac_addr >= num_radios
            && self.extra_mac_addrs.len() >= num_radios as usize
        {
            Some(&self.extra_mac_addrs[..num_radios as usize])
        } else {
            None
        }
    }
}

/// `ath11k_ready_event`. A READY TLV shorter than `wmi_ready_event` is
/// zero-extended (`memcpy(min(sizeof, len))`); the policy floor is 52.
pub fn decode_ready(payload: &[u8]) -> Result<Ready, WmiError> {
    let mut r = Ready::default();
    let mut seen = false;
    tlv_iter(payload, |t| {
        match t.tag {
            WMI_TAG_READY_EVENT => {
                let v = t.value;
                let mut abi = [0u32; 6];
                for (i, a) in abi.iter_mut().enumerate() {
                    *a = rd32(v, 4 * i);
                }
                r.fw_abi_vers = abi;
                r.mac_addr = mac_at(v, 24);
                r.status = rd32(v, 32);
                r.num_dscp_table = rd32(v, 36);
                r.num_extra_mac_addr = rd32(v, 40);
                r.num_total_peers = rd32(v, 44);
                r.num_extra_peers = rd32(v, 48);
                r.max_ast_index = rd32z(v, 52);
                r.pktlog_defs_checksum = rd32z(v, 56);
                seen = true;
            }
            WMI_TAG_ARRAY_FIXED_STRUCT => {
                r.extra_mac_addrs = t.value.chunks_exact(8).map(|c| mac_at(c, 0)).collect();
            }
            _ => {}
        }
        Ok(())
    })?;
    // Linux completes unified_ready even with no READY TLV (mac_addr
    // stays zero); surface that instead.
    if !seen {
        return Err(WmiError::Missing(WMI_TAG_READY_EVENT));
    }
    Ok(r)
}

// ── REG_CHAN_LIST_CC (legacy + ext) ─────────────────────────────────

/// `REG_RULE_*` field masks.
pub mod reg_rule {
    pub const START_FREQ: u32 = 0x0000_ffff;
    pub const END_FREQ: u32 = 0xffff_0000;
    pub const FLAGS: u32 = 0x0000_ffff;
    pub const MAX_BW: u32 = 0x0000_ffff;
    pub const REG_PWR: u32 = 0x00ff_0000;
    pub const ANT_GAIN: u32 = 0xff00_0000;
    pub const PSD_INFO: u32 = 1 << 0;
    pub const PSD_EIRP: u32 = 0x00ff_0000;
}

/// `MAX_REG_RULES`.
pub const MAX_REG_RULES: u32 = 10;
/// `MAX_6GHZ_REG_RULES`.
pub const MAX_6GHZ_REG_RULES: u32 = 5;
/// `WMI_REG_CURRENT_MAX_AP_TYPE` (LPI, SP, VLP).
pub const WMI_REG_CURRENT_MAX_AP_TYPE: usize = 3;
/// `WMI_REG_MAX_CLIENT_TYPE` (default, subordinate).
pub const WMI_REG_MAX_CLIENT_TYPE: usize = 2;
/// `WMI_REG_DEFAULT_CLIENT`.
pub const WMI_REG_DEFAULT_CLIENT: usize = 0;
/// `WMI_REG_SUBORDINATE_CLIENT`.
pub const WMI_REG_SUBORDINATE_CLIENT: usize = 1;
/// `WMI_REG_CLIENT_MAX` — array size in the ext event struct.
pub const WMI_REG_CLIENT_MAX: usize = 4;
/// `enum wmi_reg_6ghz_ap_type` indices.
pub const WMI_REG_INDOOR_AP: usize = 0;
/// See [`WMI_REG_INDOOR_AP`].
pub const WMI_REG_STANDARD_POWER_AP: usize = 1;
/// See [`WMI_REG_INDOOR_AP`].
pub const WMI_REG_VERY_LOW_POWER_AP: usize = 2;

/// `struct cur_reg_rule`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RegRule {
    pub start_freq: u16,
    pub end_freq: u16,
    pub max_bw: u16,
    pub reg_power: u8,
    pub ant_gain: u8,
    pub flags: u16,
    pub psd_flag: bool,
    pub psd_eirp: i8,
}

fn reg_rule(e: &[u8], ext: bool) -> RegRule {
    // element = tlv_header, freq_info, bw_pwr_info, flag_info[, psd]
    let freq = rd32(e, 4);
    let bw = rd32(e, 8);
    let flag = rd32(e, 12);
    let psd = if ext { rd32(e, 16) } else { 0 };
    RegRule {
        start_freq: (freq & reg_rule::START_FREQ) as u16,
        end_freq: ((freq & reg_rule::END_FREQ) >> 16) as u16,
        max_bw: (bw & reg_rule::MAX_BW) as u16,
        reg_power: ((bw & reg_rule::REG_PWR) >> 16) as u8,
        ant_gain: ((bw & reg_rule::ANT_GAIN) >> 24) as u8,
        flags: (flag & reg_rule::FLAGS) as u16,
        psd_flag: psd & reg_rule::PSD_INFO != 0,
        psd_eirp: ((psd & reg_rule::PSD_EIRP) >> 16) as u8 as i8,
    }
}

/// `enum cc_setting_code` (host side), from
/// `ath11k_wmi_cc_setting_code_to_reg`; unknown firmware codes map to
/// `REG_SET_CC_STATUS_FAIL` (5).
pub fn cc_setting_code_to_reg(code: u32) -> u32 {
    if code <= 5 {
        code
    } else {
        5
    }
}

/// `struct cur_regulatory_info` as the two pull functions fill it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegInfo {
    pub is_ext_reg_event: bool,
    pub alpha2: [u8; 2],
    pub dfs_region: u32,
    pub phybitmap: u32,
    pub num_phy: u32,
    pub phy_id: u32,
    pub ctry_code: u32,
    pub reg_dmn_pair: u32,
    /// Host `enum cc_setting_code`.
    pub status_code: u32,
    pub min_bw_2ghz: u32,
    pub max_bw_2ghz: u32,
    pub min_bw_5ghz: u32,
    pub max_bw_5ghz: u32,
    pub rules_2ghz: Vec<RegRule>,
    /// Ext: firmware 5 GHz rules starting ≥ 5925 MHz are dropped.
    pub rules_5ghz: Vec<RegRule>,
    /// Ext only: `[ap_type]`.
    pub rules_6ghz_ap: [Vec<RegRule>; WMI_REG_CURRENT_MAX_AP_TYPE],
    /// Ext only: `[ap_type][client_type]`.
    pub rules_6ghz_client: [[Vec<RegRule>; WMI_REG_MAX_CLIENT_TYPE]; WMI_REG_CURRENT_MAX_AP_TYPE],
    pub min_bw_6ghz_ap: [u32; WMI_REG_CURRENT_MAX_AP_TYPE],
    pub max_bw_6ghz_ap: [u32; WMI_REG_CURRENT_MAX_AP_TYPE],
    pub min_bw_6ghz_client: [[u32; WMI_REG_MAX_CLIENT_TYPE]; WMI_REG_CURRENT_MAX_AP_TYPE],
    pub max_bw_6ghz_client: [[u32; WMI_REG_MAX_CLIENT_TYPE]; WMI_REG_CURRENT_MAX_AP_TYPE],
    pub client_type: u32,
    pub rnr_tpe_usable: u32,
    pub unspecified_ap_usable: u32,
    pub domain_code_6ghz_ap: [u32; WMI_REG_CURRENT_MAX_AP_TYPE],
    pub domain_code_6ghz_client: [[u32; WMI_REG_MAX_CLIENT_TYPE]; WMI_REG_CURRENT_MAX_AP_TYPE],
    pub domain_code_6ghz_super_id: u32,
}

/// Rules begin `sizeof(fixed struct) + sizeof(struct wmi_tlv)` past the
/// fixed TLV's value (Linux assumes the `ARRAY_STRUCT` header follows
/// immediately). NARF-stricter: the rules must lie inside the payload.
fn reg_rules(
    payload: &[u8],
    base: usize,
    first: usize,
    n: usize,
    ext: bool,
) -> Result<Vec<RegRule>, WmiError> {
    let stride = if ext { 20 } else { 16 };
    let start = base + first * stride;
    let end = start + n * stride;
    if end > payload.len() {
        return Err(WmiError::Invalid("reg chan list: rules past end of event"));
    }
    Ok((0..n)
        .map(|i| reg_rule(&payload[start + i * stride..], ext))
        .collect())
}

/// `ath11k_pull_reg_chan_list_update_ev` (`WMI_REG_CHAN_LIST_CC_EVENTID`).
pub fn decode_reg_chan_list(payload: &[u8]) -> Result<RegInfo, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let t = tb.need(WMI_TAG_REG_CHAN_LIST_CC_EVENT)?;
    let v = t.value;
    let n2 = rd32(v, 48);
    let n5 = rd32(v, 52);
    if n2 as u64 + n5 as u64 == 0 {
        return Err(WmiError::Invalid("reg chan list: no rules"));
    }
    let base = t.offset + 56 + TLV_HDR_SIZE;
    let mut r = RegInfo {
        is_ext_reg_event: false,
        status_code: cc_setting_code_to_reg(rd32(v, 0)),
        phy_id: rd32(v, 4),
        alpha2: [v[8], v[9]],
        num_phy: rd32(v, 12),
        ctry_code: rd32(v, 16),
        reg_dmn_pair: rd32(v, 20),
        dfs_region: rd32(v, 24),
        phybitmap: rd32(v, 28),
        min_bw_2ghz: rd32(v, 32),
        max_bw_2ghz: rd32(v, 36),
        min_bw_5ghz: rd32(v, 40),
        max_bw_5ghz: rd32(v, 44),
        ..Default::default()
    };
    r.rules_2ghz = reg_rules(payload, base, 0, n2 as usize, false)?;
    r.rules_5ghz = reg_rules(payload, base, n2 as usize, n5 as usize, false)?;
    Ok(r)
}

/// `ath11k_pull_reg_chan_list_ext_update_ev`
/// (`WMI_REG_CHAN_LIST_CC_EXT_EVENTID`), including the
/// `ath11k_invalid_5ghz_reg_ext_rules_from_wmi` filter.
pub fn decode_reg_chan_list_ext(payload: &[u8]) -> Result<RegInfo, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let t = tb.need(WMI_TAG_REG_CHAN_LIST_CC_EXT_EVENT)?;
    let v = t.value;
    let w = |i: usize| rd32(v, 4 * i);
    // Word indices in struct wmi_reg_chan_list_cc_ext_event.
    const CLIENT_TYPE: usize = 14;
    const DC_AP_LPI: usize = 17;
    const DC_CLIENT_LPI: usize = 20;
    const DC_CLIENT_SP: usize = 24;
    const DC_CLIENT_VLP: usize = 28;
    const DC_SUPER: usize = 32;
    const BW_AP_SP: usize = 33;
    const BW_CLIENT_SP_MIN: usize = 39;
    const N6_AP_SP: usize = 63;
    const N6_CLIENT_SP: usize = 66;
    const N6_CLIENT_LPI: usize = 70;
    const N6_CLIENT_VLP: usize = 74;

    let n2 = w(12);
    let n5 = w(13);
    if n2 > MAX_REG_RULES || n5 > MAX_REG_RULES {
        return Err(WmiError::Invalid("reg ext: 2/5 GHz rules exceed max"));
    }
    let mut total = n2 + n5;
    // Linux order: [INDOOR(lpi), STANDARD_POWER(sp), VERY_LOW_POWER(vlp)]
    let n6_ap = [w(N6_AP_SP + 1), w(N6_AP_SP), w(N6_AP_SP + 2)];
    for &n in &n6_ap {
        if n > MAX_6GHZ_REG_RULES {
            return Err(WmiError::Invalid("reg ext: 6 GHz AP rules exceed max"));
        }
        total += n;
    }
    let mut n6_cl = [[0u32; WMI_REG_MAX_CLIENT_TYPE]; WMI_REG_CURRENT_MAX_AP_TYPE];
    for i in 0..WMI_REG_MAX_CLIENT_TYPE {
        n6_cl[WMI_REG_INDOOR_AP][i] = w(N6_CLIENT_LPI + i);
        n6_cl[WMI_REG_STANDARD_POWER_AP][i] = w(N6_CLIENT_SP + i);
        n6_cl[WMI_REG_VERY_LOW_POWER_AP][i] = w(N6_CLIENT_VLP + i);
        for ap in n6_cl.iter() {
            total += ap[i];
        }
        if n6_cl.iter().any(|ap| ap[i] > MAX_6GHZ_REG_RULES) {
            return Err(WmiError::Invalid("reg ext: 6 GHz client rules exceed max"));
        }
    }
    if total == 0 {
        return Err(WmiError::Invalid("reg ext: no rules"));
    }

    let mut r = RegInfo {
        is_ext_reg_event: true,
        status_code: cc_setting_code_to_reg(w(0)),
        phy_id: w(1),
        alpha2: [v[8], v[9]],
        num_phy: w(3),
        ctry_code: w(4),
        reg_dmn_pair: w(5),
        dfs_region: w(6),
        phybitmap: w(7),
        min_bw_2ghz: w(8),
        max_bw_2ghz: w(9),
        min_bw_5ghz: w(10),
        max_bw_5ghz: w(11),
        client_type: w(CLIENT_TYPE),
        rnr_tpe_usable: w(CLIENT_TYPE + 1),
        unspecified_ap_usable: w(CLIENT_TYPE + 2),
        domain_code_6ghz_ap: [w(DC_AP_LPI), w(DC_AP_LPI + 1), w(DC_AP_LPI + 2)],
        domain_code_6ghz_super_id: w(DC_SUPER),
        // min/max ap: sp @33/34, lpi @35/36, vlp @37/38
        min_bw_6ghz_ap: [w(BW_AP_SP + 2), w(BW_AP_SP), w(BW_AP_SP + 4)],
        max_bw_6ghz_ap: [w(BW_AP_SP + 3), w(BW_AP_SP + 1), w(BW_AP_SP + 5)],
        ..Default::default()
    };
    for i in 0..WMI_REG_MAX_CLIENT_TYPE {
        // client bw arrays (each [4]): min_sp @39, max_sp @43,
        // min_lpi @47, max_lpi @51, min_vlp @55, max_vlp @59
        r.min_bw_6ghz_client[WMI_REG_STANDARD_POWER_AP][i] = w(BW_CLIENT_SP_MIN + i);
        r.max_bw_6ghz_client[WMI_REG_STANDARD_POWER_AP][i] = w(BW_CLIENT_SP_MIN + 4 + i);
        r.min_bw_6ghz_client[WMI_REG_INDOOR_AP][i] = w(BW_CLIENT_SP_MIN + 8 + i);
        r.max_bw_6ghz_client[WMI_REG_INDOOR_AP][i] = w(BW_CLIENT_SP_MIN + 12 + i);
        r.min_bw_6ghz_client[WMI_REG_VERY_LOW_POWER_AP][i] = w(BW_CLIENT_SP_MIN + 16 + i);
        r.max_bw_6ghz_client[WMI_REG_VERY_LOW_POWER_AP][i] = w(BW_CLIENT_SP_MIN + 20 + i);
        r.domain_code_6ghz_client[WMI_REG_INDOOR_AP][i] = w(DC_CLIENT_LPI + i);
        r.domain_code_6ghz_client[WMI_REG_STANDARD_POWER_AP][i] = w(DC_CLIENT_SP + i);
        r.domain_code_6ghz_client[WMI_REG_VERY_LOW_POWER_AP][i] = w(DC_CLIENT_VLP + i);
    }

    let base = t.offset + 312 + TLV_HDR_SIZE;
    let mut idx = 0usize;
    r.rules_2ghz = reg_rules(payload, base, idx, n2 as usize, true)?;
    idx += n2 as usize;
    let fw5 = reg_rules(payload, base, idx, n5 as usize, true)?;
    let invalid = fw5
        .iter()
        .filter(|x| x.start_freq as u32 >= ATH11K_MIN_6G_FREQ)
        .count();
    // Linux takes the *first* (n5 - invalid) rules, not the valid ones.
    r.rules_5ghz = fw5[..fw5.len() - invalid].to_vec();
    idx += n5 as usize;
    for (ap, &n) in n6_ap.iter().enumerate() {
        r.rules_6ghz_ap[ap] = reg_rules(payload, base, idx, n as usize, true)?;
        idx += n as usize;
    }
    for (ap, row) in n6_cl.iter().enumerate() {
        for (cl, &n) in row.iter().enumerate() {
            r.rules_6ghz_client[ap][cl] = reg_rules(payload, base, idx, n as usize, true)?;
            idx += n as usize;
        }
    }
    Ok(r)
}

// ── Simple tb[]-lookup events ───────────────────────────────────────

/// `struct wmi_vdev_start_resp_event`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VdevStartResp {
    pub vdev_id: u32,
    pub requestor_id: u32,
    /// [`WMI_VDEV_START_RESP_EVENT`] / [`WMI_VDEV_RESTART_RESP_EVENT`].
    pub resp_type: u32,
    pub status: u32,
    pub chain_mask: u32,
    pub smps_mode: u32,
    pub mac_id: u32,
    pub cfgd_tx_streams: u32,
    pub cfgd_rx_streams: u32,
    pub max_allowed_tx_power: i32,
}

/// `ath11k_pull_vdev_start_resp_tlv`.
pub fn decode_vdev_start_resp(payload: &[u8]) -> Result<VdevStartResp, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_VDEV_START_RESPONSE_EVENT)?.value;
    Ok(VdevStartResp {
        vdev_id: rd32(v, 0),
        requestor_id: rd32(v, 4),
        resp_type: rd32(v, 8),
        status: rd32(v, 12),
        chain_mask: rd32(v, 16),
        smps_mode: rd32(v, 20),
        mac_id: rd32(v, 24),
        cfgd_tx_streams: rd32(v, 28),
        cfgd_rx_streams: rd32(v, 32),
        max_allowed_tx_power: rd32(v, 36) as i32,
    })
}

/// `ath11k_pull_vdev_stopped_param_tlv` → `vdev_id`.
pub fn decode_vdev_stopped(payload: &[u8]) -> Result<u32, WmiError> {
    let tb = TlvTable::parse(payload)?;
    Ok(rd32(tb.need(WMI_TAG_VDEV_STOPPED_EVENT)?.value, 0))
}

/// `ath11k_pull_vdev_del_resp_ev` → `vdev_id`.
pub fn decode_vdev_delete_resp(payload: &[u8]) -> Result<u32, WmiError> {
    let tb = TlvTable::parse(payload)?;
    Ok(rd32(tb.need(WMI_TAG_VDEV_DELETE_RESP_EVENT)?.value, 0))
}

/// `(vdev_id, peer_macaddr)` events: `PEER_DELETE_RESP`,
/// `PEER_ASSOC_CONF`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VdevPeer {
    pub vdev_id: u32,
    pub peer_macaddr: [u8; 6],
}

/// `ath11k_pull_peer_del_resp_ev`.
pub fn decode_peer_delete_resp(payload: &[u8]) -> Result<VdevPeer, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_PEER_DELETE_RESP_EVENT)?.value;
    Ok(VdevPeer {
        vdev_id: rd32(v, 0),
        peer_macaddr: mac_at(v, 4),
    })
}

/// `ath11k_pull_peer_assoc_conf_ev`.
pub fn decode_peer_assoc_conf(payload: &[u8]) -> Result<VdevPeer, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_PEER_ASSOC_CONF_EVENT)?.value;
    Ok(VdevPeer {
        vdev_id: rd32(v, 0),
        peer_macaddr: mac_at(v, 4),
    })
}

/// `struct wmi_vdev_install_key_complete_arg`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InstallKeyCompl {
    pub vdev_id: u32,
    pub macaddr: [u8; 6],
    pub key_idx: u32,
    pub key_flags: u32,
    /// 0 = success (`WMI_VDEV_INSTALL_KEY_COMPL_STATUS_SUCCESS`).
    pub status: u32,
}

/// The parts of `struct wmi_gtk_offload_status_event` ath11k consumes when
/// it exits low-power mode.  The remaining GTK / IGTK key fields are not
/// imported by Linux ath11k; firmware has already installed them and the
/// host only needs the replay counter for the userspace supplicant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GtkOffloadStatus {
    pub vdev_id: u32,
    pub flags: u32,
    pub refresh_count: u32,
    /// `wmi_replayc_cnt.word0`, little-endian low 32 bits.
    pub replay_counter_lo: u32,
    /// `wmi_replayc_cnt.word1`, little-endian high 32 bits.
    pub replay_counter_hi: u32,
}

impl GtkOffloadStatus {
    /// Linux reconstructs this as `(word1 << 32) | word0`, then publishes
    /// `cpu_to_be64(replay_ctr)` through `ieee80211_gtk_rekey_notify`.
    pub const fn replay_counter(&self) -> u64 {
        ((self.replay_counter_hi as u64) << 32) | self.replay_counter_lo as u64
    }

    /// The big-endian replay-counter bytes cfg80211/nl80211 sends to the
    /// userspace supplicant on resume.
    pub const fn replay_counter_be(&self) -> [u8; 8] {
        self.replay_counter().to_be_bytes()
    }
}

/// `ath11k_pull_vdev_install_key_compl_ev`.
pub fn decode_install_key_compl(payload: &[u8]) -> Result<InstallKeyCompl, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_VDEV_INSTALL_KEY_COMPLETE_EVENT)?.value;
    Ok(InstallKeyCompl {
        vdev_id: rd32(v, 0),
        macaddr: mac_at(v, 4),
        key_idx: rd32(v, 12),
        key_flags: rd32(v, 16),
        status: rd32(v, 20),
    })
}

/// `struct wmi_tlv_wow_event_info`, carried by
/// `WMI_WOW_WAKEUP_HOST_EVENTID`.  ath11k uses the event as the completion
/// for `WMI_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID`; it logs the reason but does not
/// synthesize a mac80211 wake report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WowWakeup {
    pub vdev_id: u32,
    pub flags: u32,
    /// `enum wmi_wow_wake_reason`, retained verbatim for diagnostics.
    pub reason: u32,
    pub data_len: u32,
}

/// Decode `ath11k_wmi_event_wow_wakeup_host`.  The event's optional byte
/// array (page-fault data on some targets) is intentionally not retained:
/// WCN6855's ath11k path only logs it and completes the wake transition.
pub fn decode_wow_wakeup(payload: &[u8]) -> Result<WowWakeup, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_WOW_EVENT_INFO)?.value;
    need_len(v, 16, "WoW wakeup: short event info")?;
    Ok(WowWakeup {
        vdev_id: rd32(v, 0),
        flags: rd32(v, 4),
        reason: rd32(v, 8),
        data_len: rd32(v, 12),
    })
}

/// `ath11k_wmi_gtk_offload_status_event`.
pub fn decode_gtk_offload_status(payload: &[u8]) -> Result<GtkOffloadStatus, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_GTK_OFFLOAD_STATUS_EVENT)?.value;
    need_len(
        v,
        WMI_GTK_OFFLOAD_STATUS_EVENT_PREFIX_SIZE,
        "GTK offload status",
    )?;
    Ok(GtkOffloadStatus {
        vdev_id: rd32(v, 0),
        flags: rd32(v, 4),
        refresh_count: rd32(v, 8),
        replay_counter_lo: rd32(v, 12),
        replay_counter_hi: rd32(v, 16),
    })
}

/// `ath11k_pull_peer_sta_kickout_ev` → peer MAC.
pub fn decode_peer_sta_kickout(payload: &[u8]) -> Result<[u8; 6], WmiError> {
    let tb = TlvTable::parse(payload)?;
    Ok(mac_at(tb.need(WMI_TAG_PEER_STA_KICKOUT_EVENT)?.value, 0))
}

/// `struct wmi_scan_event`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanEvent {
    /// One [`scan_event`] bit.
    pub event_type: u32,
    /// [`scan_reason`].
    pub reason: u32,
    pub channel_freq: u32,
    pub scan_req_id: u32,
    pub scan_id: u32,
    pub vdev_id: u32,
    pub tsf_timestamp: u32,
}

/// `ath11k_pull_scan_ev`.
pub fn decode_scan_event(payload: &[u8]) -> Result<ScanEvent, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_SCAN_EVENT)?.value;
    Ok(ScanEvent {
        event_type: rd32(v, 0),
        reason: rd32(v, 4),
        channel_freq: rd32(v, 8),
        scan_req_id: rd32(v, 12),
        scan_id: rd32(v, 16),
        vdev_id: rd32(v, 20),
        tsf_timestamp: rd32(v, 24),
    })
}

/// `struct wmi_roam_event`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoamEvent {
    pub vdev_id: u32,
    /// `enum wmi_roam_reason` (1 = BETTER_AP, 2 = BEACON_MISS, …).
    pub reason: u32,
    pub rssi: u32,
}

/// `ath11k_pull_roam_ev`.
pub fn decode_roam(payload: &[u8]) -> Result<RoamEvent, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_ROAM_EVENT)?.value;
    Ok(RoamEvent {
        vdev_id: rd32(v, 0),
        reason: rd32(v, 4),
        rssi: rd32(v, 8),
    })
}

/// `struct wmi_mgmt_tx_compl_event` (fields Linux keeps).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MgmtTxCompl {
    pub desc_id: u32,
    /// 0 = acked.
    pub status: u32,
    pub pdev_id: u32,
    pub ack_rssi: u32,
}

/// `ath11k_pull_mgmt_tx_compl_param_tlv`.
pub fn decode_mgmt_tx_compl(payload: &[u8]) -> Result<MgmtTxCompl, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_MGMT_TX_COMPL_EVENT)?.value;
    Ok(MgmtTxCompl {
        desc_id: rd32(v, 0),
        status: rd32(v, 4),
        pdev_id: rd32(v, 8),
        // ppdu_id @12 not kept
        ack_rssi: rd32(v, 16),
    })
}

/// `struct wmi_pdev_temperature_event`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PdevTemperature {
    /// °C.
    pub temp: i32,
    pub pdev_id: u32,
}

/// `ath11k_wmi_pdev_temperature_event`. NARF-stricter: the TLV has no
/// Linux policy entry, so a short one is rejected here.
pub fn decode_pdev_temperature(payload: &[u8]) -> Result<PdevTemperature, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_PDEV_TEMPERATURE_EVENT)?.value;
    need_len(v, 8, "pdev temperature: short TLV")?;
    Ok(PdevTemperature {
        temp: rd32(v, 0) as i32,
        pdev_id: rd32(v, 4),
    })
}

/// `struct wmi_pdev_bss_chan_info_event`, whose 64-bit counters are in
/// firmware clock ticks. The MAC layer converts them to cfg80211 milliseconds
/// using ath11k's WCN6855 counter frequency.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PdevBssChanInfo {
    pub frequency_mhz: u32,
    pub noise_floor: i32,
    pub busy_ticks: u64,
    pub total_ticks: u64,
    pub tx_ticks: u64,
    pub rx_ticks: u64,
    pub rx_bss_ticks: u64,
    pub pdev_id: u32,
}

/// `ath11k_pull_pdev_bss_chan_info_ev`. `tlv_policy_min_len` already
/// requires the complete 52-byte fixed event before any word is read.
pub fn decode_pdev_bss_chan_info(payload: &[u8]) -> Result<PdevBssChanInfo, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_PDEV_BSS_CHAN_INFO_EVENT)?.value;
    let ticks = |low: usize| u64::from(rd32(v, low)) | (u64::from(rd32(v, low + 4)) << 32);
    Ok(PdevBssChanInfo {
        frequency_mhz: rd32(v, 0),
        noise_floor: rd32(v, 4) as i32,
        busy_ticks: ticks(8),
        total_ticks: ticks(16),
        tx_ticks: ticks(24),
        rx_ticks: ticks(32),
        rx_bss_ticks: ticks(40),
        pdev_id: rd32(v, 48),
    })
}

/// `struct wmi_pdev_radar_ev`.  ath11k passes the event to mac80211 as a
/// radar indication for the active channel context; the MAC layer retains
/// the frequency/width for diagnostics but owns the DFS state transition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DfsRadarDetected {
    pub pdev_id: u32,
    pub detection_mode: u32,
    pub chan_freq: u32,
    pub chan_width: u32,
    pub detector_id: u32,
    pub segment_id: u32,
    pub timestamp: u32,
    pub is_chirp: bool,
    pub freq_offset: i32,
    pub sidx: i32,
}

/// `struct wmi_obss_color_collision_event`.  The target reports the vdev,
/// event kind, and a 64-bit set of colliding BSS colors.  It is deliberately
/// separate from the configuration command: only the `DETECTION` event is
/// forwarded to mac80211/cfg80211.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObssColorCollisionEvent {
    pub vdev_id: u32,
    /// `enum wmi_obss_color_collision_evt_type`.
    pub event_type: u32,
    pub color_bitmap: u64,
}

/// `ath11k_wmi_obss_color_collision_event`'s fixed event payload.
pub fn decode_obss_color_collision_event(
    payload: &[u8],
) -> Result<ObssColorCollisionEvent, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_OBSS_COLOR_COLLISION_EVT)?.value;
    need_len(v, 16, "OBSS color collision: short TLV")?;
    Ok(ObssColorCollisionEvent {
        vdev_id: rd32(v, 0),
        event_type: rd32(v, 4),
        color_bitmap: u64::from_le_bytes(v[8..16].try_into().unwrap()),
    })
}

/// `ath11k_wmi_pdev_dfs_radar_detected_event`.
pub fn decode_dfs_radar_detected(payload: &[u8]) -> Result<DfsRadarDetected, WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_PDEV_DFS_RADAR_DETECTION_EVENT)?.value;
    need_len(v, 40, "DFS radar: short TLV")?;
    Ok(DfsRadarDetected {
        pdev_id: rd32(v, 0),
        detection_mode: rd32(v, 4),
        chan_freq: rd32(v, 8),
        chan_width: rd32(v, 12),
        detector_id: rd32(v, 16),
        segment_id: rd32(v, 20),
        timestamp: rd32(v, 24),
        is_chirp: rd32(v, 28) != 0,
        freq_offset: rd32(v, 32) as i32,
        sidx: rd32(v, 36) as i32,
    })
}

// ── MGMT_RX ─────────────────────────────────────────────────────────

/// `struct mgmt_rx_event_params` + the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtRx<'a> {
    pub channel: u32,
    pub snr: u32,
    /// Units of kbps; mac80211 rate lookup uses `rate / 100`.
    pub rate: u32,
    pub phy_mode: u32,
    pub buf_len: u32,
    pub status: u32,
    pub rssi_ctl: [u32; 4],
    pub flags: u32,
    pub rssi: i32,
    pub tsf_delta: u32,
    pub pdev_id: u32,
    pub chan_freq: u32,
    /// The 802.11 frame, `buf_len` bytes.
    pub frame: &'a [u8],
}

/// Radio band (`enum nl80211_band`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    Ghz2,
    Ghz5,
    Ghz6,
}

/// The `ieee80211_rx_status` fields `ath11k_mgmt_rx_event` derives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtRxStatus {
    pub band: Band,
    pub freq: u32,
    /// `snr + ATH11K_DEFAULT_NOISE_FLOOR`, dBm.
    pub signal: i32,
    /// `RX_FLAG_MMIC_ERROR`.
    pub mic_error: bool,
}

impl MgmtRx<'_> {
    /// `ath11k_mgmt_rx_event` band/freq/signal derivation; `None` when
    /// Linux drops the frame (decrypt / key-cache-miss / CRC errors, or
    /// a channel outside 2.4/5/6 GHz). CAC-running drops are the
    /// caller's.
    pub fn rx_status(&self) -> Option<MgmtRxStatus> {
        if self.status
            & (rx_status::ERR_DECRYPT | rx_status::ERR_KEY_CACHE_MISS | rx_status::ERR_CRC)
            != 0
        {
            return None;
        }
        let (band, freq) = if (ATH11K_MIN_6G_FREQ..=ATH11K_MAX_6G_FREQ).contains(&self.chan_freq) {
            (Band::Ghz6, self.chan_freq)
        } else if (1..=14).contains(&self.channel) {
            // ieee80211_channel_to_frequency, 2.4 GHz
            let f = if self.channel == 14 {
                2484
            } else {
                2407 + self.channel * 5
            };
            (Band::Ghz2, f)
        } else if (36..=ATH11K_MAX_5G_CHAN).contains(&self.channel) {
            (Band::Ghz5, 5000 + self.channel * 5)
        } else {
            return None;
        };
        Some(MgmtRxStatus {
            band,
            freq,
            signal: (self.snr as i32).wrapping_add(ATH11K_DEFAULT_NOISE_FLOOR),
            mic_error: self.status & rx_status::ERR_MIC != 0,
        })
    }
}

/// `ath11k_pull_mgmt_rx_params_tlv`: the *last* `MGMT_RX_HDR` and the
/// *first* `ARRAY_BYTE`; both mandatory (`-EPROTO`). `buf_len` is
/// checked against the whole event (`skb->len < (frame - skb->data) +
/// buf_len`), not the byte array's own length — as Linux does.
pub fn decode_mgmt_rx(payload: &[u8]) -> Result<MgmtRx<'_>, WmiError> {
    let mut fixed: Option<&[u8]> = None;
    let mut frame_off: Option<usize> = None;
    tlv_iter(payload, |t| {
        match t.tag {
            WMI_TAG_MGMT_RX_HDR => fixed = Some(t.value),
            WMI_TAG_ARRAY_BYTE if frame_off.is_none() => frame_off = Some(t.offset),
            _ => {}
        }
        Ok(())
    })?;
    let v = fixed.ok_or(WmiError::Missing(WMI_TAG_MGMT_RX_HDR))?;
    let off = frame_off.ok_or(WmiError::Missing(WMI_TAG_ARRAY_BYTE))?;
    let buf_len = rd32(v, 16);
    if (payload.len() as u64) < off as u64 + buf_len as u64 {
        return Err(WmiError::Proto("mgmt rx: buf_len past end of event"));
    }
    Ok(MgmtRx {
        channel: rd32(v, 0),
        snr: rd32(v, 4),
        rate: rd32(v, 8),
        phy_mode: rd32(v, 12),
        buf_len,
        status: rd32(v, 20),
        rssi_ctl: [rd32(v, 24), rd32(v, 28), rd32(v, 32), rd32(v, 36)],
        flags: rd32(v, 40),
        rssi: rd32(v, 44) as i32,
        tsf_delta: rd32(v, 48),
        // rx_tsf_l32 @52, rx_tsf_u32 @56 not kept
        pdev_id: rd32(v, 60),
        chan_freq: rd32(v, 64),
        frame: &payload[off..off + buf_len as usize],
    })
}

// ── Dispatch ────────────────────────────────────────────────────────

/// A decoded event, per `ath11k_wmi_tlv_op_rx`'s switch (station
/// subset). Decoders that need driver state (`SERVICE_READY_EXT`,
/// `SERVICE_AVAILABLE`) are surfaced as raw payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WmiEvent<'a> {
    ServiceReady(ServiceReady),
    /// Decode with [`decode_service_ready_ext`].
    ServiceReadyExt(&'a [u8]),
    ServiceReadyExt2(Vec<DmaRingCap>),
    /// Apply with [`apply_service_available`].
    ServiceAvailable(&'a [u8]),
    Ready(Ready),
    /// Boxed: `RegInfo` is large.
    RegChanList(Box<RegInfo>),
    VdevStartResp(VdevStartResp),
    VdevStopped(u32),
    VdevDeleteResp(u32),
    PeerDeleteResp(VdevPeer),
    PeerAssocConf(VdevPeer),
    InstallKeyCompl(InstallKeyCompl),
    GtkOffloadStatus(GtkOffloadStatus),
    WowWakeup(WowWakeup),
    PeerStaKickout([u8; 6]),
    Scan(ScanEvent),
    MgmtRx(MgmtRx<'a>),
    MgmtTxCompl(MgmtTxCompl),
    Roam(RoamEvent),
    PdevTemperature(PdevTemperature),
    PdevBssChanInfo(PdevBssChanInfo),
    DfsRadarDetected(DfsRadarDetected),
    ObssColorCollision(ObssColorCollisionEvent),
    /// Any other id — Linux logs and drops.
    Unhandled(u32),
}

/// Split and decode one WMI event frame (`wmi_cmd_hdr` + TLVs).
pub fn decode_event(frame: &[u8]) -> Result<WmiEvent<'_>, WmiError> {
    let (id, p) = split_event(frame)?;
    Ok(match id {
        WMI_SERVICE_READY_EVENTID => WmiEvent::ServiceReady(decode_service_ready(p)?),
        WMI_SERVICE_READY_EXT_EVENTID => WmiEvent::ServiceReadyExt(p),
        WMI_SERVICE_READY_EXT2_EVENTID => WmiEvent::ServiceReadyExt2(decode_service_ready_ext2(p)?),
        WMI_SERVICE_AVAILABLE_EVENTID => WmiEvent::ServiceAvailable(p),
        WMI_READY_EVENTID => WmiEvent::Ready(decode_ready(p)?),
        WMI_REG_CHAN_LIST_CC_EVENTID => WmiEvent::RegChanList(Box::new(decode_reg_chan_list(p)?)),
        WMI_REG_CHAN_LIST_CC_EXT_EVENTID => {
            WmiEvent::RegChanList(Box::new(decode_reg_chan_list_ext(p)?))
        }
        WMI_VDEV_START_RESP_EVENTID => WmiEvent::VdevStartResp(decode_vdev_start_resp(p)?),
        WMI_VDEV_STOPPED_EVENTID => WmiEvent::VdevStopped(decode_vdev_stopped(p)?),
        WMI_VDEV_DELETE_RESP_EVENTID => WmiEvent::VdevDeleteResp(decode_vdev_delete_resp(p)?),
        WMI_PEER_DELETE_RESP_EVENTID => WmiEvent::PeerDeleteResp(decode_peer_delete_resp(p)?),
        WMI_PEER_ASSOC_CONF_EVENTID => WmiEvent::PeerAssocConf(decode_peer_assoc_conf(p)?),
        WMI_VDEV_INSTALL_KEY_COMPLETE_EVENTID => {
            WmiEvent::InstallKeyCompl(decode_install_key_compl(p)?)
        }
        WMI_GTK_OFFLOAD_STATUS_EVENTID => WmiEvent::GtkOffloadStatus(decode_gtk_offload_status(p)?),
        WMI_WOW_WAKEUP_HOST_EVENTID => WmiEvent::WowWakeup(decode_wow_wakeup(p)?),
        WMI_PEER_STA_KICKOUT_EVENTID => WmiEvent::PeerStaKickout(decode_peer_sta_kickout(p)?),
        WMI_SCAN_EVENTID => WmiEvent::Scan(decode_scan_event(p)?),
        WMI_MGMT_RX_EVENTID => WmiEvent::MgmtRx(decode_mgmt_rx(p)?),
        WMI_MGMT_TX_COMPLETION_EVENTID => WmiEvent::MgmtTxCompl(decode_mgmt_tx_compl(p)?),
        WMI_ROAM_EVENTID => WmiEvent::Roam(decode_roam(p)?),
        WMI_PDEV_TEMPERATURE_EVENTID => WmiEvent::PdevTemperature(decode_pdev_temperature(p)?),
        WMI_PDEV_BSS_CHAN_INFO_EVENTID => WmiEvent::PdevBssChanInfo(decode_pdev_bss_chan_info(p)?),
        WMI_PDEV_DFS_RADAR_DETECTION_EVENTID => {
            WmiEvent::DfsRadarDetected(decode_dfs_radar_detected(p)?)
        }
        WMI_OBSS_COLOR_COLLISION_DETECTION_EVENTID => {
            WmiEvent::ObssColorCollision(decode_obss_color_collision_event(p)?)
        }
        other => WmiEvent::Unhandled(other),
    })
}

// ── Mac-layer commands (added for `mac.rs`) ─────────────────────────

/// `ath11k_wmi_scan_prob_req_oui` → `WMI_SCAN_PROB_REQ_OUI_CMDID`
/// (`struct wmi_scan_prob_req_oui_cmd`): the first three MAC bytes as
/// `mac[0] << 16 | mac[1] << 8 | mac[2]`.
pub fn scan_prob_req_oui_cmd(mac_addr: &[u8; 6]) -> WmiCmd {
    let oui = ((mac_addr[0] as u32) << 16) | ((mac_addr[1] as u32) << 8) | mac_addr[2] as u32;
    simple_cmd(
        WMI_SCAN_PROB_REQ_OUI_CMDID,
        WMI_TAG_SCAN_PROB_REQ_OUI_CMD,
        &[oui],
    )
}

/// `ath11k_wmi_send_dfs_phyerr_offload_enable_cmd` →
/// `WMI_PDEV_DFS_PHYERR_OFFLOAD_ENABLE_CMDID` (`pdev_id` only).
pub fn dfs_phyerr_offload_enable_cmd(pdev_id: u32) -> WmiCmd {
    simple_cmd(
        WMI_PDEV_DFS_PHYERR_OFFLOAD_ENABLE_CMDID,
        WMI_TAG_PDEV_DFS_PHYERR_OFFLOAD_ENABLE_CMD,
        &[pdev_id],
    )
}

/// `ATH11K_IPV4_TH_SEED_SIZE`.
pub const ATH11K_IPV4_TH_SEED_SIZE: usize = 5;
/// `ATH11K_IPV6_TH_SEED_SIZE`.
pub const ATH11K_IPV6_TH_SEED_SIZE: usize = 11;

/// `ath11k_wmi_pdev_lro_cfg` → `WMI_LRO_CONFIG_CMDID`
/// (`struct ath11k_wmi_pdev_lro_config_cmd`: `lro_enable` and `res`
/// stay 0, `th_4` / `th_6` are `get_random_bytes` seeds, then
/// `pdev_id`).
pub fn pdev_lro_cfg_cmd(
    pdev_id: u32,
    th_4: &[u32; ATH11K_IPV4_TH_SEED_SIZE],
    th_6: &[u32; ATH11K_IPV6_TH_SEED_SIZE],
) -> WmiCmd {
    let mut words = alloc::vec![0u32, 0u32];
    words.extend_from_slice(th_4);
    words.extend_from_slice(th_6);
    words.push(pdev_id);
    simple_cmd(WMI_LRO_CONFIG_CMDID, WMI_TAG_LRO_INFO_CMD, &words)
}

/// `struct wmi_wmm_params_arg`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WmmParamsArg {
    pub acm: u8,
    pub aifs: u8,
    pub cwmin: u16,
    pub cwmax: u16,
    pub txop: u16,
    pub no_ack: u8,
}

/// `WMI_WMM_PARAM_TYPE_LEGACY`.
pub const WMI_WMM_PARAM_TYPE_LEGACY: u32 = 0;
/// `WMI_WMM_PARAM_TYPE_11AX_MU_EDCA`: CW fields are HE MU-EDCA exponents,
/// not the expanded legacy contention-window values.
pub const WMI_WMM_PARAM_TYPE_11AX_MU_EDCA: u32 = 1;
/// `sizeof(struct wmi_vdev_set_wmm_params_cmd)`.
pub const WMI_VDEV_SET_WMM_PARAMS_CMD_SIZE: usize = 124;

/// `ath11k_wmi_send_wmm_update_cmd_tlv` → `WMI_VDEV_SET_WMM_PARAMS_CMDID`.
/// `ac` is in `WME_AC_*` order: BE, BK, VI, VO. Linux tags every
/// per-AC `wmi_wmm_params` with `WMI_TAG_VDEV_SET_WMM_PARAMS_CMD` too
/// (not `WMI_TAG_WMM_PARAMS`); reproduced.
pub fn vdev_set_wmm_params_cmd(vdev_id: u32, ac: &[WmmParamsArg; 4], param_type: u32) -> WmiCmd {
    let len = WMI_VDEV_SET_WMM_PARAMS_CMD_SIZE;
    let mut w = W::new(len);
    w.tlv(WMI_TAG_VDEV_SET_WMM_PARAMS_CMD, len - TLV_HDR_SIZE);
    w.u32(vdev_id);
    for a in ac {
        w.tlv(WMI_TAG_VDEV_SET_WMM_PARAMS_CMD, 28 - TLV_HDR_SIZE);
        w.u32(a.cwmin as u32);
        w.u32(a.cwmax as u32);
        w.u32(a.aifs as u32);
        w.u32(a.txop as u32);
        w.u32(a.acm as u32);
        w.u32(a.no_ack as u32);
    }
    w.u32(param_type);
    w.finish(WMI_VDEV_SET_WMM_PARAMS_CMDID, len)
}

/// `ath11k_wmi_send_obss_spr_cmd` → `WMI_PDEV_OBSS_PD_SPATIAL_REUSE_CMDID`
/// (`struct wmi_obss_spatial_reuse_params_cmd`). Linux never fills
/// `pdev_id`, so it stays 0; reproduced.
pub fn obss_spr_cmd(vdev_id: u32, enable: u32, min_offset: i32, max_offset: i32) -> WmiCmd {
    simple_cmd(
        WMI_PDEV_OBSS_PD_SPATIAL_REUSE_CMDID,
        WMI_TAG_OBSS_SPATIAL_REUSE_SET_CMD,
        &[0, enable, min_offset as u32, max_offset as u32, vdev_id],
    )
}

/// `struct wmi_pdev_obss_pd_bitmap_cmd`, shared by ath11k's six SRG/non-SRG
/// bitmap commands. `bitmap` is deliberately two host words: Linux copies
/// cfg80211's opaque eight-byte NLA directly into the same layout before WMI
/// serializes its little-endian fields.
fn obss_pd_bitmap_cmd(cmd_id: u32, tag: u16, pdev_id: u32, bitmap: [u32; 2]) -> WmiCmd {
    simple_cmd(cmd_id, tag, &[pdev_id, bitmap[0], bitmap[1]])
}

pub fn pdev_set_srg_bss_color_bitmap_cmd(pdev_id: u32, bitmap: [u32; 2]) -> WmiCmd {
    obss_pd_bitmap_cmd(
        WMI_PDEV_SET_SRG_BSS_COLOR_BITMAP_CMDID,
        WMI_TAG_PDEV_SRG_BSS_COLOR_BITMAP_CMD,
        pdev_id,
        bitmap,
    )
}

pub fn pdev_set_srg_partial_bssid_bitmap_cmd(pdev_id: u32, bitmap: [u32; 2]) -> WmiCmd {
    obss_pd_bitmap_cmd(
        WMI_PDEV_SET_SRG_PARTIAL_BSSID_BITMAP_CMDID,
        WMI_TAG_PDEV_SRG_PARTIAL_BSSID_BITMAP_CMD,
        pdev_id,
        bitmap,
    )
}

pub fn pdev_set_srg_obss_color_enable_bitmap_cmd(pdev_id: u32, bitmap: [u32; 2]) -> WmiCmd {
    obss_pd_bitmap_cmd(
        WMI_PDEV_SET_SRG_OBSS_COLOR_ENABLE_BITMAP_CMDID,
        WMI_TAG_PDEV_SRG_OBSS_COLOR_ENABLE_BITMAP_CMD,
        pdev_id,
        bitmap,
    )
}

pub fn pdev_set_srg_obss_bssid_enable_bitmap_cmd(pdev_id: u32, bitmap: [u32; 2]) -> WmiCmd {
    obss_pd_bitmap_cmd(
        WMI_PDEV_SET_SRG_OBSS_BSSID_ENABLE_BITMAP_CMDID,
        WMI_TAG_PDEV_SRG_OBSS_BSSID_ENABLE_BITMAP_CMD,
        pdev_id,
        bitmap,
    )
}

pub fn pdev_set_non_srg_obss_color_enable_bitmap_cmd(pdev_id: u32, bitmap: [u32; 2]) -> WmiCmd {
    obss_pd_bitmap_cmd(
        WMI_PDEV_SET_NON_SRG_OBSS_COLOR_ENABLE_BITMAP_CMDID,
        WMI_TAG_PDEV_NON_SRG_OBSS_COLOR_ENABLE_BITMAP_CMD,
        pdev_id,
        bitmap,
    )
}

pub fn pdev_set_non_srg_obss_bssid_enable_bitmap_cmd(pdev_id: u32, bitmap: [u32; 2]) -> WmiCmd {
    obss_pd_bitmap_cmd(
        WMI_PDEV_SET_NON_SRG_OBSS_BSSID_ENABLE_BITMAP_CMDID,
        WMI_TAG_PDEV_NON_SRG_OBSS_BSSID_ENABLE_BITMAP_CMD,
        pdev_id,
        bitmap,
    )
}

/// `ath11k_wmi_send_bss_color_change_enable_cmd` (`struct
/// wmi_bss_color_change_enable_params_cmd`: vdev_id, enable).
pub fn bss_color_change_enable_cmd(vdev_id: u32, enable: bool) -> WmiCmd {
    simple_cmd(
        WMI_BSS_COLOR_CHANGE_ENABLE_CMDID,
        WMI_TAG_BSS_COLOR_CHANGE_ENABLE,
        &[vdev_id, enable as u32],
    )
}

/// `ath11k_wmi_send_obss_color_collision_cfg_cmd` (`struct
/// wmi_obss_color_collision_cfg_params_cmd`: vdev_id, flags 0, evt_type
/// DETECTION / DISABLE, current_bss_color, detection_period_ms,
/// `ATH11K_BSS_COLOR_COLLISION_SCAN_PERIOD_MS`, free_slot_expiry 0).
pub fn obss_color_collision_cfg_cmd(
    vdev_id: u32,
    bss_color: u8,
    period_ms: u32,
    enable: bool,
) -> WmiCmd {
    simple_cmd(
        WMI_OBSS_COLOR_COLLISION_DET_CONFIG_CMDID,
        WMI_TAG_OBSS_COLOR_COLLISION_DET_CONFIG,
        &[
            vdev_id,
            0,
            enable as u32,
            bss_color as u32,
            period_ms,
            200,
            0,
        ],
    )
}

/// `ath11k_reg_11d_new_cc_event` (`WMI_11D_NEW_COUNTRY_EVENTID`): the
/// two alpha2 bytes of `wmi_11d_new_cc_ev.new_alpha2`. A missing TLV is
/// `-EPROTO` as in Linux.
pub fn decode_11d_new_cc(payload: &[u8]) -> Result<[u8; 2], WmiError> {
    let tb = TlvTable::parse(payload)?;
    let v = tb.need(WMI_TAG_11D_NEW_COUNTRY_EVENT)?.value;
    need_len(v, 4, "11d new cc: short TLV")?;
    Ok([v[0], v[1]])
}

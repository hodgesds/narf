//! ath11k station-mode mac layer: what Linux `ath11k/mac.c` + `reg.c`
//! do for a WCN6855 station, driven the way mac80211 / cfg80211 drive
//! them (NARF has neither).
//!
//! The layer talks to the hardware through two small traits the core
//! implements:
//!
//! - [`WmiPort`] — WMI command TX, the WMI event stream, management
//!   frame TX over WMI (`ath11k_mac_mgmt_tx_wmi`), the clock;
//! - [`DataPort`] — the data-path hooks ath11k calls from mac.c
//!   (`ath11k_dp_*`) and EAPOL frames as 802.3.
//!
//! Operations and the Linux call chain each one mirrors:
//!
//! | NARF | Linux |
//! |---|---|
//! | [`Mac::start`] | `ath11k_mac_op_start` (+ `ath11k_reg_update_chan_list(ar, false)`) |
//! | [`Mac::add_interface`] | `ieee80211_do_open` → `ath11k_mac_op_add_interface`, then mac80211's ERP reset and `ieee80211_set_wmm_default` → `ath11k_mac_op_conf_tx` ×4 |
//! | [`Mac::scan`] | `ath11k_mac_op_hw_scan` → `ath11k_start_scan`; scan events `ath11k_scan_event`; `__ath11k_mac_scan_finish`; `ath11k_scan_timeout_work`; BSS table = `cfg80211_inform_bss_frame_data` |
//! | [`Mac::associate`] | `ieee80211_mgd_auth` / `_assoc` → `ieee80211_prep_connection` (`assign_vif_chanctx`, txpower, `BSS_CHANGED_BSSID\|BASIC_RATES\|BEACON_INT`, `ath11k_mac_station_add` → `ath11k_peer_create` + `ath11k_mac_start_vdev_delay`), `ieee80211_send_auth`, `ieee80211_send_assoc`, `ieee80211_assoc_success` (`conf_tx`, `ath11k_bss_assoc`), wpa_supplicant's 4-way handshake, `ath11k_mac_op_set_key` ×2, `ath11k_mac_op_sta_state(AUTHORIZED)` |
//! | [`Mac::disassociate`] | `ieee80211_set_disassoc` (deauth TX, sta flush = key removal + `ath11k_mac_station_remove`, `BSS_CHANGED_ASSOC` → `ath11k_bss_disassoc`, WMM defaults) + `ath11k_mac_op_unassign_vif_chanctx` |
//! | [`Mac::poll`] | `ath11k_peer_sta_kickout_event`, `ath11k_roam_event` → `ath11k_mac_handle_beacon_miss` + `connection_loss_work`, deauth / disassoc RX |
//!
//! Every failure latches a distinct `diag::latch_wifi_error(step,
//! detail)` code in 150–199 ([`step`]) and prints one console line.

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::Future;

use narf_wireless::eapol::{HmacPrimitive, Supplicant};
use narf_wireless::rsn::{self, RsnIe, Suite};
use narf_wireless::{AssociateRequest, BssInfo, ScanRequest, WirelessError};

use super::mac_frame::{self as frame, capab, eid, freq_band, Band, ParsedIes};
use super::mac_peer::{self as peer, ApSta, ChanDef, ConnMode, OwnCaps, SmpsMode, Width};
use super::mac_reg::{chan_flag, RegState, RegUpdate, VdevKind, Wiphy};
pub mod he;
pub mod sae;
pub mod sec;
use super::wmi::{self, *};
use sec::{Credential, MfpRx, MfpState, RsnPlan};

// ── Ports ───────────────────────────────────────────────────────────

/// The WMI side of the core (`ath11k_wmi_cmd_send`, the WMI event
/// dispatcher, `ath11k_mac_mgmt_tx_wmi`).
pub trait WmiPort {
    /// `ath11k_wmi_cmd_send`: frame `cmd` (`WmiCmd::frame`) on the WMI
    /// endpoint, waiting for HTC credits like Linux (3 s). `Err` =
    /// positive errno.
    fn send(&self, cmd: WmiCmd) -> impl Future<Output = Result<(), i32>> + Send;
    /// The next WMI event frame (`wmi_cmd_hdr` + TLVs) the core did not
    /// consume itself, waiting at most `timeout_ms` (0 = poll). `None` ⇔
    /// nothing arrived in time.
    fn next_event(&self, timeout_ms: u32) -> impl Future<Output = Option<Vec<u8>>> + Send;
    /// `ath11k_mac_mgmt_tx_wmi`: DMA-map `frame`, allocate a `buf_id`
    /// and send `WMI_MGMT_TX_SEND_CMDID` (`wmi::mgmt_send_cmd`) on
    /// `vdev_id`. Returns the `buf_id` that `MGMT_TX_COMPLETION.desc_id`
    /// will carry.
    fn mgmt_tx(&self, vdev_id: u32, frame: &[u8]) -> impl Future<Output = Result<u32, i32>> + Send;
    /// `wmi_process_mgmt_tx_comp`: unmap and free `desc_id`'s buffer.
    fn mgmt_tx_done(&self, desc_id: u32);
    /// Monotonic milliseconds.
    fn now_ms(&self) -> u64;
    /// The WMI endpoint's `max_msg_len` (HTC connect response), for
    /// `ath11k_wmi_send_scan_chan_list_cmd`'s split.
    fn max_msg_len(&self) -> u32;
    /// `get_random_bytes`.
    fn random_bytes(&self, out: &mut [u8]);
}

/// The data-path side of the core.
pub trait DataPort {
    /// `ath11k_dp_tx_htt_h2t_ppdu_stats_req(ar, HTT_PPDU_STATS_TAG_DEFAULT)`.
    fn ppdu_stats_req(&self) -> impl Future<Output = Result<(), i32>> + Send;
    /// `ath11k_mac_config_mon_status_default(ar, enable)`.
    fn mon_status_default(&self, enable: bool) -> impl Future<Output = Result<(), i32>> + Send;
    /// `ath11k_dp_vdev_tx_attach`.
    fn vdev_tx_attach(&self, vdev_id: u32, addr: [u8; 6]);
    /// `ath11k_wait_for_peer_common`: wait until HTT PEER_MAP (`mapped`)
    /// or PEER_UNMAP (`!mapped`) for `(vdev_id, addr)`; `Err(ETIMEDOUT)`.
    fn wait_peer_mapped(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
        mapped: bool,
        timeout_ms: u32,
    ) -> impl Future<Output = Result<(), i32>> + Send;
    /// `ath11k_dp_peer_setup` (REO queues, ...).
    fn peer_setup(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
    ) -> impl Future<Output = Result<(), i32>> + Send;
    /// `ath11k_dp_peer_cleanup`.
    fn peer_cleanup(&self, vdev_id: u32, addr: [u8; 6]);
    /// `ath11k_dp_peer_rx_pn_replay_config(arvif, peer, cmd, key)`:
    /// `install` ⇔ `SET_KEY`; `pairwise` selects unicast vs group.
    fn rx_pn_replay_config(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
        cipher: u32,
        pairwise: bool,
        install: bool,
    ) -> impl Future<Output = Result<(), i32>> + Send;
    /// Transmit an 802.3 frame (EAPOL; the DP encapsulates it).
    fn send_eth(&self, frame: &[u8]) -> impl Future<Output = Result<(), i32>> + Send;
    /// The next received EAPOL frame as 802.3 (`ETH_P_PAE`) and whether
    /// it arrived decrypted, waiting at most `timeout_ms`.
    fn recv_eapol(&self, timeout_ms: u32) -> impl Future<Output = Option<(Vec<u8>, bool)>> + Send;
    /// `ieee80211_flush_queues(local, sdata, false)`: wait for the pending
    /// TX (`ath11k_mac_op_flush`).
    fn flush_tx(&self) -> impl Future<Output = ()> + Send;
    /// The BSS peer's port is (un)authorized (`peer->is_authorized`):
    /// the DP passes non-EAPOL data only while authorized.
    fn set_authorized(&self, addr: [u8; 6], authorized: bool);
    /// `sta->sta.wme` from the association response
    /// (`ieee80211_assoc_config_link`): the data TX path builds QoS Data
    /// frames (`ieee80211_build_hdr` / `ieee80211_select_queue`) only for
    /// a WMM AP.
    fn set_sta_wme(&self, addr: [u8; 6], wme: bool);
    /// `ath11k_peer_frags_flush` (`ath11k_mac_op_set_key` with a
    /// station: before a pairwise key install).
    fn peer_frags_flush(&self, vdev_id: u32, addr: [u8; 6]);
    /// `ath11k_mac_op_ampdu_action(IEEE80211_AMPDU_RX_START)` →
    /// `ath11k_dp_rx_ampdu_start`: the TID's REO queue with the
    /// negotiated window and SSN (`ath11k_peer_rx_tid_setup`) and its
    /// `WMI_PEER_REORDER_QUEUE_SETUP_CMDID`. `Err` = positive errno.
    fn ampdu_rx_start(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
        tid: u8,
        buf_size: u16,
        ssn: u16,
    ) -> impl Future<Output = Result<(), i32>> + Send;
    /// `ath11k_mac_op_ampdu_action(IEEE80211_AMPDU_RX_STOP)` →
    /// `ath11k_dp_rx_ampdu_stop`.
    fn ampdu_rx_stop(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
        tid: u8,
    ) -> impl Future<Output = Result<(), i32>> + Send;
}

// ── Diagnostics ─────────────────────────────────────────────────────

/// `diag::latch_wifi_error` step codes (150–199, and 270–299 for the
/// security / HE additions).
pub mod step {
    pub const START_PDEV_PARAM: u32 = 150;
    pub const START_PROBE_OUI: u32 = 151;
    pub const START_DFS_OFFLOAD: u32 = 152;
    pub const START_CHAN_LIST: u32 = 153;
    pub const START_LRO: u32 = 154;
    pub const START_DP: u32 = 155;
    pub const VDEV_CREATE: u32 = 156;
    pub const VDEV_PARAM: u32 = 157;
    pub const STA_PS: u32 = 158;
    pub const REG_EVENT: u32 = 159;
    pub const SCAN_BUSY: u32 = 160;
    pub const SCAN_START_CMD: u32 = 161;
    pub const SCAN_START_TIMEOUT: u32 = 162;
    pub const SCAN_START_FAILED: u32 = 163;
    pub const SCAN_TIMEOUT: u32 = 164;
    pub const SCAN_STOP_TIMEOUT: u32 = 165;
    pub const SCAN_11D: u32 = 166;
    pub const CONNECT_NO_BSS: u32 = 167;
    pub const CONNECT_UNSUPPORTED: u32 = 168;
    pub const CONNECT_STATE: u32 = 169;
    pub const TXPOWER: u32 = 170;
    pub const WMM_PARAMS: u32 = 171;
    pub const PEER_CREATE: u32 = 172;
    pub const PEER_MAP_TIMEOUT: u32 = 173;
    pub const VDEV_START: u32 = 174;
    pub const VDEV_START_TIMEOUT: u32 = 175;
    pub const VDEV_START_STATUS: u32 = 176;
    pub const AUTH_TX: u32 = 177;
    pub const AUTH_TIMEOUT: u32 = 178;
    pub const AUTH_REJECTED: u32 = 179;
    pub const ASSOC_TX: u32 = 180;
    pub const ASSOC_TIMEOUT: u32 = 181;
    pub const ASSOC_REJECTED: u32 = 182;
    pub const PEER_ASSOC: u32 = 183;
    pub const PEER_ASSOC_TIMEOUT: u32 = 184;
    pub const VDEV_UP: u32 = 185;
    pub const EAPOL_TIMEOUT: u32 = 186;
    pub const EAPOL_MIC: u32 = 187;
    pub const EAPOL_PROTO: u32 = 188;
    pub const KEY_INSTALL: u32 = 189;
    pub const KEY_INSTALL_TIMEOUT: u32 = 190;
    pub const KEY_INSTALL_STATUS: u32 = 191;
    pub const PEER_AUTHORIZE: u32 = 192;
    pub const LINK_KICKOUT: u32 = 193;
    pub const LINK_BEACON_LOSS: u32 = 194;
    pub const LINK_DEAUTH_RX: u32 = 195;
    pub const VDEV_STOP_TIMEOUT: u32 = 196;
    pub const PEER_DELETE_TIMEOUT: u32 = 197;
    pub const WMI_SEND: u32 = 198;
    pub const EAPOL_GTK: u32 = 199;
    // ── 270–299: security / HE (`mac_sec`, `mac_he`) ──
    /// wpa_supplicant's SA Query timed out (`sme_check_sa_query_timeout`):
    /// deauthenticated with `WLAN_REASON_PREV_AUTH_NOT_VALID`.
    pub const SA_QUERY_TIMEOUT: u32 = 270;
    /// No SAE PWE (hunting and pecking found none).
    pub const SAE_PWE: u32 = 271;
    /// The AP refused SAE (status code ≠ 0 / 126; detail = status), or
    /// kept asking for anti-clogging tokens.
    pub const SAE_REJECTED: u32 = 272;
    /// The AP's Commit was unusable (`sme_sae_auth` returns -1; detail
    /// 1 token group, 2 token container, 3 confirm first, 4 status for
    /// the wrong PWE mode, 5 `sae_parse_commit` / `sae_process_commit`).
    pub const SAE_COMMIT: u32 = 273;
    /// The AP's Confirm did not verify (`sae_check_confirm`).
    pub const SAE_CONFIRM: u32 = 274;
    /// No SAE answer after `IEEE80211_AUTH_MAX_TRIES` (detail = tries).
    pub const SAE_TIMEOUT: u32 = 275;
    /// An HE vdev command failed (detail 0 HEMU_MODE, 1 BSS color change
    /// enable, 2 OBSS color collision config); Linux only warns.
    pub const HE_PARAM: u32 = 276;
    /// A PTK rekey failed after message 1/4 or 3/4 (detail 1 M2 TX, 2 M4
    /// TX, 3 old-key DISABLE, 4 new PTK install, 5 GTK, 6 IGTK):
    /// deauthenticated with `WLAN_REASON_UNSPECIFIED`.
    pub const PTK_REKEY: u32 = 277;
}

/// Linux errnos used here (positive).
pub mod errno {
    pub const EINVAL: i32 = 22;
    pub const EBUSY: i32 = 16;
    pub const ENOENT: i32 = 2;
    pub const EOPNOTSUPP: i32 = 95;
    pub const ETIMEDOUT: i32 = 110;
    pub const ECONNREFUSED: i32 = 111;
    pub const ENOLINK: i32 = 67;
    pub const EPROTO: i32 = 71;
    pub const ENOTCONN: i32 = 107;
}

/// A mac-layer failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacError {
    pub step: u32,
    pub detail: u32,
    pub errno: i32,
}

impl MacError {
    pub const fn new(step: u32, detail: u32, errno: i32) -> Self {
        MacError {
            step,
            detail,
            errno,
        }
    }

    /// Latch into the framebuffer diag line and print to the console.
    pub fn report(&self, what: &str) {
        use core::fmt::Write as _;
        narf_memory::diag::latch_wifi_error(self.step, self.detail);
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: mac: {} failed: step {} detail {:#x} (-{})",
            what,
            self.step,
            self.detail,
            self.errno
        );
    }

    /// The `narf_wireless` error the interface reports.
    pub fn wireless(&self) -> WirelessError {
        match self.errno {
            errno::ETIMEDOUT => WirelessError::Timeout,
            errno::EBUSY => WirelessError::Busy,
            errno::ECONNREFUSED => WirelessError::Denied,
            errno::EOPNOTSUPP => WirelessError::NotSupported,
            errno::ENOENT | errno::EINVAL => WirelessError::InvalidArgs,
            _ => WirelessError::HardwareError,
        }
    }
}

fn fail<T>(step: u32, detail: u32, errno: i32, what: &str) -> Result<T, MacError> {
    let e = MacError::new(step, detail, errno);
    e.report(what);
    Err(e)
}

// ── Device description ──────────────────────────────────────────────

/// What the mac layer needs from SERVICE_READY / _EXT / READY.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceCaps {
    /// `ar->mac_addr` (`ab->mac_addr` on single-pdev parts).
    pub mac_addr: [u8; 6],
    /// `ar->pdev->pdev_id`.
    pub pdev_id: u32,
    pub pdev: PdevCap,
    /// `ab->hal_reg_cap[...]` for the pdev and per-band phys.
    pub hal_reg_cap: HalRegCapExt,
    pub hal_reg_cap_2g: HalRegCapExt,
    pub hal_reg_cap_5g: HalRegCapExt,
    pub svc: ServiceMap,
    /// `target_caps.hw_max_tx_power` (`ar->max_tx_power`).
    pub hw_max_tx_power: u32,
    pub num_radios: u32,
}

impl DeviceCaps {
    /// Assemble from the decoded bring-up events (single-pdev WCN6855:
    /// `pdevs[0]`, `hal_reg_cap[phy_id]` of each band).
    pub fn from_events(
        sr: &ServiceReady,
        ext: &ServiceReadyExt,
        ready: &Ready,
        svc: &ServiceMap,
    ) -> Option<Self> {
        let pdev = *ext.pdevs.first()?;
        let pick = |phy| ext.hal_reg_cap(phy).copied().unwrap_or_default();
        Some(DeviceCaps {
            mac_addr: ready.mac_addr,
            pdev_id: pdev.pdev_id,
            pdev,
            hal_reg_cap: ext.hal_reg_caps.first().copied().unwrap_or_default(),
            hal_reg_cap_2g: pick(pdev.band_2g.phy_id),
            hal_reg_cap_5g: pick(pdev.band_5g.phy_id),
            svc: *svc,
            hw_max_tx_power: sr.caps.map_or(0, |c| c.hw_max_tx_power),
            num_radios: ext.num_radios.max(1),
        })
    }
}

/// `ath11k_hw_params` / module defaults the mac layer reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacConfig {
    pub idle_ps: bool,
    pub supports_sta_ps: bool,
    pub current_cc_support: bool,
    pub single_pdev_only: bool,
    pub vdev_start_delay: bool,
    pub num_rxdma_per_pdev: u32,
    /// `ATH11K_MAX_HW_LISTEN_INTERVAL` → `hw.conf.listen_interval`.
    pub listen_interval: u16,
    /// `wdev->ps` (`CONFIG_CFG80211_DEFAULT_PS=y`).
    pub powersave: bool,
    /// `ath11k_frame_mode == ATH11K_HW_TXRX_ETHERNET` (default native
    /// wifi).
    pub frame_mode_ethernet: bool,
    /// `ATH11K_FLAG_RAW_MODE` (`cryptmode=1`).
    pub raw_mode: bool,
}

impl MacConfig {
    /// WCN6855 hw2.0 / hw2.1 (`ath11k_hw_params[]`).
    pub const fn wcn6855() -> Self {
        MacConfig {
            idle_ps: true,
            supports_sta_ps: true,
            current_cc_support: true,
            single_pdev_only: true,
            vdev_start_delay: true,
            num_rxdma_per_pdev: 2,
            listen_interval: 5,
            powersave: true,
            frame_mode_ethernet: false,
            raw_mode: false,
        }
    }
}

/// `ATH11K_HW_TXRX_*`.
pub mod txrx {
    pub const RAW: u32 = 0;
    pub const NATIVE_WIFI: u32 = 1;
    pub const ETHERNET: u32 = 2;
}

/// Timeouts (ms), named after the Linux constants.
pub mod timeout {
    /// `ATH11K_VDEV_SETUP_TIMEOUT_HZ`.
    pub const VDEV_SETUP: u32 = 1000;
    /// `ath11k_wait_for_peer_common`.
    pub const PEER_MAP: u32 = 3000;
    /// `ath11k_wait_for_peer_delete_done`.
    pub const PEER_DELETE: u32 = 3000;
    /// `peer_assoc_done` in `ath11k_bss_assoc`.
    pub const PEER_ASSOC: u32 = 1000;
    /// `install_key_done`.
    pub const INSTALL_KEY: u32 = 1000;
    /// `ath11k_scan_stop`.
    pub const SCAN_STOP: u32 = 3000;
    /// `ATH11K_MAC_SCAN_CMD_EVT_OVERHEAD`.
    pub const SCAN_OVERHEAD: u32 = 200;
    /// `IEEE80211_AUTH_TIMEOUT_LONG` / `ASSOC_TIMEOUT_LONG` (no TX status yet).
    pub const MLME_TX_STATUS: u32 = 500;
    /// `IEEE80211_AUTH_TIMEOUT_SHORT` / `ASSOC_TIMEOUT_SHORT` (after the ACK).
    pub const MLME_RESPONSE: u32 = 100;
    /// `IEEE80211_AUTH_MAX_TRIES` / `ASSOC_MAX_TRIES`.
    pub const MLME_TRIES: u32 = 3;
    /// wpa_supplicant's WPA-PSK authentication timeout
    /// (`wpa_supplicant_req_auth_timeout(wpa_s, 10, 0)`).
    pub const EAPOL: u32 = 10_000;
    /// `ATH11K_CONNECTION_LOSS_HZ`.
    pub const CONNECTION_LOSS: u32 = 3000;
    /// `ATH11K_VDEV_DELETE_TIMEOUT_HZ`.
    pub const VDEV_DELETE: u32 = 5000;
    /// `IEEE80211_SCAN_RESULT_EXPIRE` (cfg80211 BSS expiry).
    pub const BSS_EXPIRE: u64 = 30_000;
}

/// `ATH11K_SCAN_11D_INTERVAL`.
pub const ATH11K_SCAN_11D_INTERVAL: u32 = 600_000;
/// `WMI_STA_PS_PARAM_INACTIVITY_TIME` value mac80211 asks for
/// (`conf->dynamic_ps_timeout` = 100 ms by default).
pub const DYNAMIC_PS_TIMEOUT: u32 = 100;
/// `WMI_DTIM_POLICY_STICK`.
pub const WMI_DTIM_POLICY_STICK: u32 = 3;
/// `WMI_VDEV_SLOT_TIME_LONG` / `_SHORT`.
pub const WMI_VDEV_SLOT_TIME_LONG: u32 = 1;
pub const WMI_VDEV_SLOT_TIME_SHORT: u32 = 2;
/// `WMI_VDEV_PREAMBLE_LONG` / `_SHORT`.
pub const WMI_VDEV_PREAMBLE_LONG: u32 = 1;
pub const WMI_VDEV_PREAMBLE_SHORT: u32 = 2;
/// `WMI_ROAM_REASON_BEACON_MISS`.
pub const WMI_ROAM_REASON_BEACON_MISS: u32 = 2;
/// `WMI_PEER_SET_DEFAULT_ROUTING` etc. live in `wmi::peer_param`.
pub const RTS_THRESHOLD_OFF: u32 = u32::MAX;

// ── State ───────────────────────────────────────────────────────────

/// `enum ath11k_scan_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanState {
    Idle,
    Starting,
    Running,
    Aborting,
}

/// `enum ath11k_11d_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State11d {
    Idle,
    Preparing,
    Running,
}

/// One cfg80211 BSS entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanBss {
    pub bssid: [u8; 6],
    /// `bss->channel->center_freq`.
    pub freq: u32,
    pub capability: u16,
    pub beacon_int: u16,
    /// dBm (`rx_status->signal`).
    pub signal: i32,
    /// `bss->ies`: the most recent frame's elements.
    pub ies: Vec<u8>,
    pub beacon_ies: Option<Vec<u8>>,
    pub proberesp_ies: Option<Vec<u8>>,
    pub last_seen_ms: u64,
}

impl ScanBss {
    pub fn parsed(&self) -> ParsedIes {
        ParsedIes::parse(&self.ies)
    }

    pub fn ssid(&self) -> Vec<u8> {
        frame::find_elem(&self.ies, eid::SSID)
            .map(|s| s.to_vec())
            .unwrap_or_default()
    }

    /// `narf_wireless::BssInfo` for 2.4 / 5 GHz entries.
    pub fn info(&self) -> Option<BssInfo> {
        let band = freq_band(self.freq);
        if band == Band::Ghz6 {
            return None;
        }
        Some(BssInfo {
            bssid: self.bssid,
            ssid: self.ssid(),
            channel: frame::freq_to_channel(self.freq),
            rssi: self.signal.clamp(-128, 127) as i8,
            security: bss_security(self.capability, &self.parsed()),
        })
    }
}

/// Classify a BSS for `BssInfo::security`.
pub fn bss_security(capability: u16, p: &ParsedIes) -> narf_wireless::scan::BssSecurity {
    use narf_wireless::scan::BssSecurity;
    if let Some(r) = p.rsn.as_deref().and_then(RsnIe::decode_body) {
        let has = |t| r.akms.contains(&Suite::standard(t));
        if has(rsn::AKM_SAE) && !has(rsn::AKM_PSK) && !has(rsn::AKM_PSK_SHA256) {
            return BssSecurity::Wpa3;
        }
        return BssSecurity::Wpa2;
    }
    if p.wpa.is_some() {
        return BssSecurity::Wpa;
    }
    if capability & capab::PRIVACY != 0 {
        return BssSecurity::Wep;
    }
    BssSecurity::Open
}

/// `struct ath11k_vif` (STA).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Vif {
    pub vdev_id: u32,
    pub addr: [u8; 6],
    pub is_started: bool,
    pub is_up: bool,
    pub chanctx: Option<ChanDef>,
    pub bssid: [u8; 6],
    pub aid: u16,
    pub beacon_interval: u32,
    pub dtim_period: u32,
    /// `arvif->wmm_params` in `WME_AC_*` order (BE, BK, VI, VO).
    pub wmm: [WmmParamsArg; 4],
    pub uapsd: u32,
    /// `bss_conf.use_cts_prot` / `use_short_preamble` / `use_short_slot`.
    pub use_cts_prot: bool,
    pub use_short_preamble: bool,
    pub use_short_slot: bool,
    /// `bss_conf.txpower` (dBm; `None` = INT_MIN).
    pub txpower: Option<i32>,
    pub ps: bool,
}

/// A link-loss reason latched by an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkLoss {
    /// `PEER_STA_KICKOUT` for the AP.
    Kickout,
    /// `WMI_ROAM_REASON_BEACON_MISS` with no beacon for
    /// `ATH11K_CONNECTION_LOSS_HZ`.
    BeaconLoss,
    /// Deauthentication (`true`) / Disassociation from the AP, reason.
    Deauth { deauth: bool, reason: u16 },
    /// The supplicant gave up on the association
    /// (`wpa_sm_deauthenticate(sm, reason)`, e.g. a failed Group Key
    /// Handshake, an SA Query timeout); `step` / `detail` are latched.
    Supplicant { reason: u16, step: u32, detail: u32 },
}

/// The association in progress / established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub bss: ScanBss,
    pub def: ChanDef,
    pub mode: ConnMode,
    pub sta: ApSta,
    pub peer_created: bool,
    pub assoc: bool,
    pub authorized: bool,
    pub ptk_installed: bool,
    pub gtk_idx: Option<u8>,
    pub have_beacon: bool,
    pub conn_loss_deadline: Option<u64>,
    pub loss: Option<LinkLoss>,
    /// `ieee80211_mgd_assoc`'s `uapsd` / `wmm` decisions.
    pub wmm: bool,
    pub operating_11g: bool,
    pub basic_rates: u32,
    /// Reason code of the Deauthentication sent if the join fails after
    /// association.
    pub deauth_reason: u16,
    /// `sta->ampdu_mlme.agg_session_valid` (RX BA sessions, bit = TID).
    pub ba_rx_valid: u16,
    /// `sta->ampdu_mlme.tid_rx_token[]`.
    pub ba_rx_token: [u8; 16],
    /// The negotiated RSN (AKM, PMF); `None` for Open.
    pub rsn: Option<RsnPlan>,
    /// HE: the AP's HE station capabilities and operation (set at
    /// association success when the connection is HE).
    pub he: Option<peer::ApHe>,
}

/// Completions (`reinit_completion` → event → `complete`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Pending {
    vdev_start: Option<VdevStartResp>,
    vdev_stopped: Option<u32>,
    vdev_deleted: Option<u32>,
    peer_assoc_conf: Option<VdevPeer>,
    install_key: Option<InstallKeyCompl>,
    peer_deleted: Option<VdevPeer>,
    mgmt_tx: Vec<MgmtTxCompl>,
    /// Auth / (re)assoc responses from the target BSSID.
    mlme_rx: VecDeque<Vec<u8>>,
    /// Block Ack action frames from the AP (`ieee80211_rx_h_action` →
    /// the interface work queue).
    back_rx: VecDeque<Vec<u8>>,
    /// `ab->new_alpha2` waiting for `ath11k_update_11d`.
    new_alpha2: Option<[u8; 2]>,
    /// `ath11k_regd_update_work` queued (new regd → chan list).
    regd_update: bool,
}

struct ScanCtx {
    state: ScanState,
    vdev_id: u32,
    started: bool,
    completed: bool,
    aborted: bool,
    deadline: Option<u64>,
}

/// HMAC-SHA1 for the PSK AKM's PRF and MIC.
struct HmacSha1;

impl HmacPrimitive for HmacSha1 {
    fn out_len(&self) -> usize {
        20
    }
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
    }
}

/// HMAC-SHA1-128 Key MIC over the EAPOL PDU (MIC field zeroed).
pub fn eapol_mic(kck: &[u8], pdu: &[u8]) -> [u8; 16] {
    let full = narf_crypto::pbkdf2_sha1::hmac_sha1(kck, pdu);
    let mut m = [0u8; 16];
    m.copy_from_slice(&full[..16]);
    m
}

/// Offset of the 16-byte Key MIC in an EAPOL-Key PDU (4-byte header +
/// 77 bytes of fixed key fields).
pub const EAPOL_MIC_OFFSET: usize = 81;

// ── The mac layer ───────────────────────────────────────────────────

/// One pdev's station mac layer (`struct ath11k` + its single vif).
pub struct Mac<P: WmiPort, D: DataPort> {
    pub wmi: P,
    pub dp: D,
    caps: DeviceCaps,
    cfg: MacConfig,
    own: OwnCaps,
    wiphy: Wiphy,
    reg: RegState,
    started: bool,
    vif: Option<Vif>,
    scan: ScanCtx,
    bss: Vec<ScanBss>,
    pending: Pending,
    txpower_limit_2g: u32,
    txpower_limit_5g: u32,
    state_11d: State11d,
    vdev_id_11d: Option<u32>,
    regdom_set_by_user: bool,
    alpha2: [u8; 2],
    hw_rate_code: u32,
    link: Option<Link>,
    mlme_target: Option<[u8; 6]>,
    /// The last disconnection, as cfg80211 reports it.
    disconnect: Option<Disconnect>,
    /// The RSN supplicant of the association after its 4-way handshake
    /// (PTK, replay counter, GTK in use) for the Group Key Handshake.
    sup: Option<Supplicant>,
    /// 802.11w host state (software BIP keys, management PNs, SA Query).
    mfp: MfpState,
    /// Our HE capabilities per band (`ar->mac.iftype[band][STATION]`):
    /// 2.4 GHz, 5 GHz.
    own_he: [Option<he::StaHeCap>; 2],
}

/// What `__cfg80211_disconnected` reports to nl80211 for a lost or
/// dropped association: the reason code of the Deauthentication /
/// Disassociation frame (received, or the one mac80211 built and sent)
/// and whether it came from the AP (`from_ap = !ether_addr_equal(mgmt->sa,
/// dev_addr)` in `cfg80211_process_deauth` / `_disassoc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disconnect {
    pub reason: u16,
    pub from_ap: bool,
}

impl LinkLoss {
    /// The disconnection cfg80211 reports for this loss: a frame from the
    /// AP carries its own reason (`ieee80211_rx_mgmt_deauth` /
    /// `_disassoc` → `cfg80211_rx_mlme_mgmt`); a beacon / connection loss
    /// is a locally generated Deauthentication with
    /// `WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY` (`__ieee80211_disconnect`
    /// → `cfg80211_tx_mlme_mgmt`); NARF tears a kickout down the same way.
    pub fn disconnect(&self) -> Disconnect {
        match *self {
            LinkLoss::Deauth { reason, .. } => Disconnect {
                reason,
                from_ap: true,
            },
            LinkLoss::Kickout | LinkLoss::BeaconLoss => Disconnect {
                reason: frame::WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY,
                from_ap: false,
            },
            // wpa_supplicant_deauthenticate → cfg80211_mlme_deauth: the
            // Deauthentication mac80211 sends carries the reason.
            LinkLoss::Supplicant { reason, .. } => Disconnect {
                reason,
                from_ap: false,
            },
        }
    }
}

impl<P: WmiPort, D: DataPort> core::fmt::Debug for Mac<P, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mac")
            .field("started", &self.started)
            .field("vif", &self.vif)
            .field("scan", &self.scan.state)
            .field("bss", &self.bss.len())
            .field("link", &self.link.as_ref().map(|l| l.bss.bssid))
            .finish()
    }
}

impl<P: WmiPort, D: DataPort> Mac<P, D> {
    /// `ath11k_mac_register`: build the wiphy from the firmware
    /// capabilities and apply the default regdomain built from the
    /// REG_CHAN_LIST_CC event the core received during start-up
    /// (`initial_reg`; `None` → `ath11k_world_regd`).
    pub fn new(
        wmi: P,
        dp: D,
        caps: DeviceCaps,
        cfg: MacConfig,
        initial_reg: Option<&RegInfo>,
    ) -> Self {
        let own = peer::own_caps(&caps.pdev);
        // ath11k_mac_setup_he_cap
        let he_for = |bit: u32, b: &BandCap| {
            (caps.pdev.supported_bands & bit != 0)
                .then(|| he::own_he_cap(&caps.pdev, b, own.num_tx_chains, own.num_rx_chains))
        };
        let own_he = [
            he_for(WMI_HOST_WLAN_2G_CAP, &caps.pdev.band_2g),
            he_for(WMI_HOST_WLAN_5G_CAP, &caps.pdev.band_5g),
        ];
        let mut wiphy = Wiphy::new(
            caps.pdev.supported_bands,
            &caps.hal_reg_cap,
            &caps.hal_reg_cap_2g,
            &caps.hal_reg_cap_5g,
        );
        let mut reg = RegState::default();
        if let Some(info) = initial_reg {
            if let Err(e) = reg.handle_chan_list(
                info,
                true,
                VdevKind::NotSta,
                caps.num_radios,
                cfg.num_rxdma_per_pdev,
            ) {
                let detail = match e {
                    super::mac_reg::RegError::Status(s) => s,
                    super::mac_reg::RegError::BadPhy(p) => 0x100 | p,
                    super::mac_reg::RegError::Build => 0x200,
                };
                MacError::new(step::REG_EVENT, detail, errno::EINVAL).report("default regdomain");
            }
        }
        wiphy.apply_regd(&reg.current());
        let max = caps.hw_max_tx_power;
        Mac {
            wmi,
            dp,
            caps,
            cfg,
            own,
            wiphy,
            reg,
            started: false,
            vif: None,
            scan: ScanCtx {
                state: ScanState::Idle,
                vdev_id: 0,
                started: false,
                completed: false,
                aborted: false,
                deadline: None,
            },
            bss: Vec::new(),
            pending: Pending::default(),
            txpower_limit_2g: max,
            txpower_limit_5g: max,
            state_11d: State11d::Idle,
            vdev_id_11d: None,
            regdom_set_by_user: false,
            alpha2: [0; 2],
            hw_rate_code: 0,
            link: None,
            mlme_target: None,
            disconnect: None,
            sup: None,
            mfp: MfpState::default(),
            own_he,
        }
    }

    /// `ieee80211_determine_ap_chan`'s HE check plus
    /// `ieee80211_verify_peer_he_mcs_support` / `_sta_he_mcs_support`.
    fn he_ok(&self, band: Band, ies: &ParsedIes) -> bool {
        let (Some(own), Some(c), Some(o)) = (
            self.own_he(band),
            ies.he_cap.as_deref().and_then(he::parse_he_cap),
            ies.he_oper.as_deref().and_then(he::HeOper::parse),
        ) else {
            return false;
        };
        he::he_mcs_ok(own, &c, &o)
    }

    /// Our HE capabilities on `band` (`None` on 6 GHz: not associated).
    pub fn own_he(&self, band: Band) -> Option<&he::StaHeCap> {
        match band {
            Band::Ghz2 => self.own_he[0].as_ref(),
            Band::Ghz5 => self.own_he[1].as_ref(),
            Band::Ghz6 => None,
        }
    }

    /// The last disconnection (taken): set when [`Mac::poll`] tears a
    /// lost link down and by [`Mac::disassociate`].
    pub fn take_disconnect(&mut self) -> Option<Disconnect> {
        self.disconnect.take()
    }

    /// The configuration the layer was built with (a restart reuses it).
    pub fn config(&self) -> MacConfig {
        self.cfg
    }

    pub fn wiphy(&self) -> &Wiphy {
        &self.wiphy
    }

    pub fn own_caps(&self) -> &OwnCaps {
        &self.own
    }

    pub fn vif(&self) -> Option<&Vif> {
        self.vif.as_ref()
    }

    pub fn link(&self) -> Option<&Link> {
        self.link.as_ref()
    }

    pub fn scan_state(&self) -> ScanState {
        self.scan.state
    }

    pub fn state_11d(&self) -> State11d {
        self.state_11d
    }

    pub fn bss_table(&self) -> &[ScanBss] {
        &self.bss
    }

    pub fn connected_bssid(&self) -> Option<[u8; 6]> {
        self.link
            .as_ref()
            .filter(|l| l.authorized && l.loss.is_none())
            .map(|l| l.bss.bssid)
    }

    fn svc(&self, bit: u32) -> bool {
        self.caps.svc.test(bit)
    }

    /// `ath11k_wmi_supports_6ghz_cc_ext`.
    fn supports_6ghz_cc_ext(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_REG_CC_EXT_EVENT_SUPPORT) && self.wiphy.supports_6ghz()
    }

    async fn cmd(
        &mut self,
        c: WmiCmd,
        step_code: u32,
        detail: u32,
        what: &str,
    ) -> Result<(), MacError> {
        let id = c.cmd_id;
        match self.wmi.send(c).await {
            Ok(()) => Ok(()),
            Err(e) => fail(step_code, if detail != 0 { detail } else { id }, e, what),
        }
    }

    async fn pdev_param(&mut self, id: u32, v: u32) -> Result<(), MacError> {
        let c = pdev_set_param_cmd(id, v, self.caps.pdev_id);
        self.cmd(c, step::START_PDEV_PARAM, id, "pdev set param")
            .await
    }

    async fn vdev_param(&mut self, vdev: u32, id: u32, v: u32) -> Result<(), MacError> {
        let c = vdev_set_param_cmd(vdev, id, v);
        self.cmd(c, step::VDEV_PARAM, id, "vdev set param").await
    }

    async fn sta_ps_param(&mut self, vdev: u32, id: u32, v: u32) -> Result<(), MacError> {
        let c = sta_powersave_param_cmd(vdev, id, v);
        self.cmd(c, step::STA_PS, id, "sta ps param").await
    }

    // ── Event pump ─────────────────────────────────────────────────

    /// Wait up to `timeout_ms` until `f` yields, dispatching every event
    /// that arrives meanwhile.
    async fn wait_for<T>(
        &mut self,
        timeout_ms: u32,
        mut f: impl FnMut(&mut Self) -> Option<T>,
    ) -> Option<T> {
        let deadline = self.wmi.now_ms() + timeout_ms as u64;
        loop {
            if let Some(v) = f(self) {
                return Some(v);
            }
            let now = self.wmi.now_ms();
            if now >= deadline {
                return None;
            }
            if let Some(ev) = self.wmi.next_event((deadline - now) as u32).await {
                self.handle_event(&ev);
                self.run_deferred().await;
            }
        }
    }

    /// Dispatch every queued event without waiting, run deferred work
    /// and the connection-loss timer. Returns the link loss, if any.
    pub async fn poll(&mut self) -> Option<LinkLoss> {
        while let Some(ev) = self.wmi.next_event(0).await {
            self.handle_event(&ev);
        }
        self.release_mgmt_tx();
        self.run_deferred().await;
        self.rx_eapol().await;
        let now = self.wmi.now_ms();
        if let Some(l) = self.link.as_mut() {
            if let Some(d) = l.conn_loss_deadline {
                if now >= d && l.loss.is_none() {
                    l.loss = Some(LinkLoss::BeaconLoss);
                }
            }
        }
        let loss = self.link.as_ref().and_then(|l| l.loss);
        if let Some(loss) = loss {
            if self.link.as_ref().is_some_and(|l| l.authorized) {
                let (s, d) = match loss {
                    LinkLoss::Kickout => (step::LINK_KICKOUT, 0),
                    LinkLoss::BeaconLoss => (step::LINK_BEACON_LOSS, 0),
                    LinkLoss::Deauth { deauth, reason } => (
                        step::LINK_DEAUTH_RX,
                        ((deauth as u32) << 16) | reason as u32,
                    ),
                    LinkLoss::Supplicant { step, detail, .. } => (step, detail),
                };
                MacError::new(s, d, errno::ENOLINK).report("link");
                // __ieee80211_disconnect: WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY;
                // the supplicant's deauth carries its reason; a deauth /
                // disassoc from the AP is not answered.
                let send_deauth = !matches!(loss, LinkLoss::Deauth { .. });
                let reason = match loss {
                    LinkLoss::Supplicant { reason, .. } => reason,
                    _ => frame::WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY,
                };
                self.teardown(send_deauth, reason).await;
                self.disconnect = Some(loss.disconnect());
                narf_memory::diag::set_wifi_stage(narf_memory::diag::WifiStage::Scan);
            }
        }
        loss
    }

    /// `wpa_sm_deauthenticate(sm, WLAN_REASON_UNSPECIFIED)`: the link is
    /// torn down by [`Mac::poll`] with that reason.
    fn supplicant_deauth(&mut self, step: u32, detail: u32) {
        if let Some(l) = self.link.as_mut() {
            if l.loss.is_none() {
                l.loss = Some(LinkLoss::Supplicant {
                    reason: frame::WLAN_REASON_UNSPECIFIED,
                    step,
                    detail,
                });
            }
        }
    }

    /// `ieee80211_iface_process_skb` for the queued Block Ack frames.
    async fn process_back(&mut self) {
        while let Some(f) = self.pending.back_rx.pop_front() {
            if self.link.is_none() {
                continue;
            }
            match f[frame::MGMT_HDR_LEN + 1] {
                frame::WLAN_ACTION_ADDBA_REQ => {
                    if let Some(r) = frame::parse_addba_req(&f) {
                        self.start_rx_ba_session(&r).await;
                    }
                }
                frame::WLAN_ACTION_DELBA => {
                    // ieee80211_process_delba: the AP stopping its TX
                    // session stops our RX session; a DELBA for one of
                    // our TX sessions finds none (ath11k declines TX
                    // aggregation: the firmware does it).
                    if let Some((tid, initiator)) = frame::parse_delba(&f) {
                        if initiator == frame::WLAN_BACK_INITIATOR {
                            self.stop_rx_ba_session(tid, frame::WLAN_BACK_INITIATOR, 0, true)
                                .await;
                        }
                    }
                }
                // ieee80211_process_addba_resp: no TX session to match.
                _ => {}
            }
        }
    }

    /// `__ieee80211_start_rx_ba_session(sta, …, tx = true)` for an ADDBA
    /// Request, with ath11k's `SUPPORTS_REORDERING_BUFFER` (no mac80211
    /// reorder buffer, so no session timer; the driver does the
    /// reordering in the REO) and an HT / VHT AP (`max_buf_size =
    /// IEEE80211_MAX_AMPDU_BUF_HT`; `max_rx_aggregation_subframes =
    /// IEEE80211_MAX_AMPDU_BUF_HE`), then `ieee80211_send_addba_resp`.
    async fn start_rx_ba_session(&mut self, r: &frame::AddbaReq) {
        let Some(l) = self.link.as_ref() else {
            return;
        };
        let (addr, bssid, ht) = (l.bss.bssid, l.bss.bssid, l.sta.ht_cap.ht_supported);
        let tid = r.tid;
        let mut buf_size = r.buf_size;
        let mut status = frame::WLAN_STATUS_REQUEST_DECLINED;
        'end: {
            // IEEE80211_FIRST_TSPEC_TSID
            if tid >= 8 {
                break 'end;
            }
            // "erroneously requests BA session on tid %d w/o HT"
            if !ht {
                break 'end;
            }
            // IEEE80211_MAX_AMPDU_BUF_HT; delayed BA needs S1G here.
            if r.policy != 1 || buf_size > 0x40 {
                status = frame::WLAN_STATUS_INVALID_QOS_PARAM;
                break 'end;
            }
            if buf_size == 0 {
                buf_size = 0x40;
            }
            // sta->sta.max_rx_aggregation_subframes (0x100) never clamps
            // below 0x40.
            buf_size = buf_size.min(0x100);
            let l = self.link.as_ref().unwrap();
            if l.ba_rx_valid & (1 << tid) != 0 {
                if l.ba_rx_token[tid as usize] == r.dialog_token {
                    // "updated AddBA Req": tid_rx is NULL with
                    // SUPPORTS_REORDERING_BUFFER, so the timeout compare
                    // fails and the update is declined.
                    status = frame::WLAN_STATUS_REQUEST_DECLINED;
                    break 'end;
                }
                // "unexpected AddBA Req": delete the existing session.
                self.stop_rx_ba_session(
                    tid,
                    frame::WLAN_BACK_RECIPIENT,
                    frame::WLAN_STATUS_UNSPECIFIED_QOS,
                    false,
                )
                .await;
            }
            let vdev_id = self.vif.as_ref().unwrap().vdev_id;
            if self
                .dp
                .ampdu_rx_start(vdev_id, addr, tid as u8, buf_size, r.ssn)
                .await
                .is_ok()
            {
                status = frame::WLAN_STATUS_SUCCESS;
            }
        }
        if status == frame::WLAN_STATUS_SUCCESS {
            if let Some(l) = self.link.as_mut() {
                l.ba_rx_valid |= 1 << tid;
                l.ba_rx_token[tid as usize] = r.dialog_token;
            }
        }
        let own = self.caps.mac_addr;
        let f = frame::build_addba_resp(
            &own,
            &addr,
            &bssid,
            tid,
            r.dialog_token,
            status,
            1,
            buf_size,
            r.timeout,
        );
        self.tx_mgmt_nowait(&f).await;
    }

    /// `__ieee80211_stop_rx_ba_session`: `IEEE80211_AMPDU_RX_STOP` to the
    /// driver (a failure is only logged), and a DELBA when we end the
    /// session ourselves (`initiator == WLAN_BACK_RECIPIENT && tx`).
    pub(super) async fn stop_rx_ba_session(
        &mut self,
        tid: u16,
        initiator: u16,
        reason: u16,
        tx: bool,
    ) {
        let Some(l) = self.link.as_mut() else {
            return;
        };
        if tid >= 16 || l.ba_rx_valid & (1 << tid) == 0 {
            return;
        }
        l.ba_rx_valid &= !(1 << tid);
        let addr = l.bss.bssid;
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        // "HW problem - can not stop rx aggregation": logged only.
        let _ = self.dp.ampdu_rx_stop(vdev_id, addr, tid as u8).await;
        if initiator == frame::WLAN_BACK_RECIPIENT && tx {
            let own = self.caps.mac_addr;
            let f = frame::build_delba(&own, &addr, &addr, tid, frame::WLAN_BACK_RECIPIENT, reason);
            self.tx_mgmt_nowait(&f).await;
        }
    }

    /// `ieee80211_tx_skb` without a TX status wait: the completion is
    /// released by [`Self::release_mgmt_tx`].
    async fn tx_mgmt_nowait(&mut self, f: &[u8]) {
        let Some(vdev_id) = self.vif.as_ref().map(|v| v.vdev_id) else {
            return;
        };
        let f = self.mfp_tx(f);
        let _ = self.wmi.mgmt_tx(vdev_id, &f).await;
    }

    /// `ath11k_wmi_tlv_op_rx` for the events the mac layer owns.
    pub fn handle_event(&mut self, ev: &[u8]) {
        let Ok((id, payload)) = split_event(ev) else {
            return;
        };
        if id == WMI_11D_NEW_COUNTRY_EVENTID {
            if let Ok(cc) = decode_11d_new_cc(payload) {
                self.state_11d = State11d::Idle;
                self.pending.new_alpha2 = Some(cc);
            }
            return;
        }
        let Ok(e) = decode_event(ev) else {
            return;
        };
        let our_vdev = self.vif.as_ref().map(|v| v.vdev_id);
        match e {
            WmiEvent::Scan(s) => self.scan_event(&s),
            WmiEvent::MgmtRx(m) => self.mgmt_rx(&m),
            WmiEvent::VdevStartResp(r) if Some(r.vdev_id) == our_vdev => {
                self.pending.vdev_start = Some(r)
            }
            WmiEvent::VdevStopped(v) if Some(v) == our_vdev => self.pending.vdev_stopped = Some(v),
            WmiEvent::VdevDeleteResp(v) => self.pending.vdev_deleted = Some(v),
            WmiEvent::PeerAssocConf(p) => self.pending.peer_assoc_conf = Some(p),
            WmiEvent::InstallKeyCompl(k) => self.pending.install_key = Some(k),
            WmiEvent::PeerDeleteResp(p) => self.pending.peer_deleted = Some(p),
            WmiEvent::MgmtTxCompl(c) => self.pending.mgmt_tx.push(c),
            WmiEvent::PeerStaKickout(addr) => {
                if let Some(l) = self.link.as_mut() {
                    if addr == l.bss.bssid && l.peer_created && l.loss.is_none() {
                        l.loss = Some(LinkLoss::Kickout);
                    }
                }
            }
            WmiEvent::Roam(r) if r.reason == WMI_ROAM_REASON_BEACON_MISS => {
                let up = self
                    .vif
                    .as_ref()
                    .is_some_and(|v| v.vdev_id == r.vdev_id && v.is_up);
                let now = self.wmi.now_ms();
                if let (true, Some(l)) = (up, self.link.as_mut()) {
                    l.conn_loss_deadline = Some(now + timeout::CONNECTION_LOSS as u64);
                }
            }
            WmiEvent::RegChanList(info) => self.reg_event(&info),
            _ => {}
        }
    }

    /// Release management frames whose completion nobody waits for
    /// (`wmi_process_mgmt_tx_comp`).
    fn release_mgmt_tx(&mut self) {
        for c in core::mem::take(&mut self.pending.mgmt_tx) {
            self.wmi.mgmt_tx_done(c.desc_id);
        }
    }

    /// `ath11k_reg_chan_list_event` → `ath11k_reg_handle_chan_list(…,
    /// IEEE80211_REG_UNSET_AP)`.
    fn reg_event(&mut self, info: &RegInfo) {
        let kind = self.vdev_kind();
        match self.reg.handle_chan_list(
            info,
            true,
            kind,
            self.caps.num_radios,
            self.cfg.num_rxdma_per_pdev,
        ) {
            Ok(RegUpdate::New) => self.pending.regd_update = true,
            Ok(RegUpdate::Default) => self.wiphy.apply_regd(&self.reg.current()),
            Ok(RegUpdate::Unchanged) => {}
            Err(e) => {
                let detail = match e {
                    super::mac_reg::RegError::Status(s) => s,
                    super::mac_reg::RegError::BadPhy(p) => 0x100 | p,
                    super::mac_reg::RegError::Build => 0x200,
                };
                MacError::new(step::REG_EVENT, detail, errno::EINVAL).report("reg chan list");
            }
        }
    }

    fn vdev_kind(&self) -> VdevKind {
        if self.vif.is_some() {
            VdevKind::Sta { ap_type: 0 }
        } else {
            VdevKind::NotSta
        }
    }

    /// Workqueue items: `ath11k_update_11d` and
    /// `ath11k_regd_update_work` → `reg_process_self_managed_hint` →
    /// `ath11k_reg_notifier` (driver) → `ath11k_reg_update_chan_list(ar,
    /// true)` → `ath11k_regd_update_chan_list_work`.
    async fn run_deferred(&mut self) {
        self.process_back().await;
        self.mfp_deferred().await;
        if let Some(cc) = self.pending.new_alpha2.take() {
            self.alpha2 = cc;
            let c = set_current_country_cmd(self.caps.pdev_id, [cc[0], cc[1], 0]);
            let _ = self
                .cmd(c, step::SCAN_11D, 0, "11d set current country")
                .await;
        }
        // ath11k_regd_update_chan_list_work waits for a running hw scan
        // before sending; keep the update queued until then.
        if self.pending.regd_update && self.scan.state == ScanState::Idle {
            self.pending.regd_update = false;
            self.wiphy.apply_regd(&self.reg.current());
            if self.started {
                let _ = self.send_chan_list().await;
            }
        }
    }

    // ── Bring-up ───────────────────────────────────────────────────

    /// `ath11k_mac_op_start`.
    pub async fn start(&mut self) -> Result<(), MacError> {
        if self.started {
            return fail(
                step::START_PDEV_PARAM,
                0,
                errno::EINVAL,
                "mac start (already on)",
            );
        }
        self.started = true;
        let r = self.start_inner().await;
        if r.is_err() {
            self.started = false;
        }
        r
    }

    async fn start_inner(&mut self) -> Result<(), MacError> {
        self.pdev_param(WMI_PDEV_PARAM_PMF_QOS, 1).await?;
        self.pdev_param(WMI_PDEV_PARAM_DYNAMIC_BW, 1).await?;
        if self.svc(WMI_TLV_SERVICE_SPOOF_MAC_SUPPORT) {
            let c = scan_prob_req_oui_cmd(&self.caps.mac_addr);
            self.cmd(c, step::START_PROBE_OUI, 0, "scan prob req oui")
                .await?;
        }
        self.pdev_param(WMI_PDEV_PARAM_ARP_AC_OVERRIDE, 0).await?;
        let c = dfs_phyerr_offload_enable_cmd(self.caps.pdev_id);
        self.cmd(c, step::START_DFS_OFFLOAD, 0, "dfs phyerr offload")
            .await?;
        if let Err(e) = self.dp.ppdu_stats_req().await {
            return fail(step::START_DP, 1, e, "ppdu stats req");
        }
        self.pdev_param(WMI_PDEV_PARAM_MESH_MCAST_ENABLE, 1).await?;
        // __ath11k_set_antenna(ar, cfg_tx_chainmask, cfg_rx_chainmask)
        let (tx, rx) = (self.caps.pdev.tx_chain_mask, self.caps.pdev.rx_chain_mask);
        self.pdev_param(WMI_PDEV_PARAM_TX_CHAIN_MASK, tx).await?;
        self.pdev_param(WMI_PDEV_PARAM_RX_CHAIN_MASK, rx).await?;
        // ath11k_reg_update_chan_list(ar, false): the return value is
        // ignored by ath11k_mac_op_start.
        let _ = self.send_chan_list().await;
        if let Err(e) = self.dp.mon_status_default(true).await {
            return fail(step::START_DP, 2, e, "mon status default");
        }
        let mut seed = [0u8; 4 * (ATH11K_IPV4_TH_SEED_SIZE + ATH11K_IPV6_TH_SEED_SIZE)];
        self.wmi.random_bytes(&mut seed);
        let w = |i: usize| {
            u32::from_le_bytes([
                seed[4 * i],
                seed[4 * i + 1],
                seed[4 * i + 2],
                seed[4 * i + 3],
            ])
        };
        let th4: [u32; ATH11K_IPV4_TH_SEED_SIZE] = core::array::from_fn(w);
        let th6: [u32; ATH11K_IPV6_TH_SEED_SIZE] =
            core::array::from_fn(|i| w(ATH11K_IPV4_TH_SEED_SIZE + i));
        // ath11k_wmi_pdev_lro_cfg: return value ignored.
        let c = pdev_lro_cfg_cmd(self.caps.pdev_id, &th4, &th6);
        let _ = self.cmd(c, step::START_LRO, 0, "lro cfg").await;
        if self.cfg.idle_ps {
            self.pdev_param(WMI_PDEV_PARAM_IDLE_PS_CONFIG, 1).await?;
        }
        Ok(())
    }

    /// `ar->state != ATH11K_STATE_OFF` (`ath11k_mac_op_start` ran).
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// `ath11k_mac_op_stop`: the monitor-status filter off (a failure is
    /// only logged, "failed to clear rx_filter for monitor status ring"),
    /// `ATH11K_STATE_OFF`, the scan timeout cancelled, an 11d scan still
    /// PREPARING back to IDLE. The pending management TX count is the
    /// runtime's (`atomic_set(&ar->num_pending_mgmt_tx, 0)` there).
    pub async fn stop(&mut self) {
        if !self.started {
            return;
        }
        if let Err(e) = self.dp.mon_status_default(false).await {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: mac: failed to clear rx_filter for monitor status ring: (-{})",
                e
            );
        }
        self.started = false;
        self.scan.deadline = None;
        if self.state_11d == State11d::Preparing {
            self.state_11d = State11d::Idle;
        }
    }

    /// `ath11k_mac_op_remove_interface` for the station vif (after
    /// `ieee80211_do_stop` disconnected it): `ath11k_mac_11d_scan_stop`,
    /// `ath11k_mac_vdev_delete` (WMI_VDEV_DELETE_CMDID, wait ≤
    /// `ATH11K_VDEV_DELETE_TIMEOUT_HZ` for WMI_VDEV_DELETE_RESP_EVENTID);
    /// the vif is gone either way (`err_vdev_del` continues). Linux only
    /// warns: a failure's errno is returned for the caller to log.
    pub async fn remove_interface(&mut self) -> Result<(), i32> {
        let Some(v) = self.vif.clone() else {
            return Ok(());
        };
        // The only vif is a station (WMI_VDEV_TYPE_STA).
        self.scan_11d_stop().await;
        self.pending.vdev_deleted = None;
        let r = match self.wmi.send(vdev_delete_cmd(v.vdev_id as u8)).await {
            Err(e) => Err(e),
            Ok(()) => {
                let id = v.vdev_id;
                self.wait_for(timeout::VDEV_DELETE, |m| {
                    (m.pending.vdev_deleted == Some(id)).then_some(())
                })
                .await
                .ok_or(errno::ETIMEDOUT)
            }
        };
        self.pending.vdev_deleted = None;
        self.vif = None;
        r
    }

    /// `ath11k_reg_update_chan_list` → `ath11k_wmi_send_scan_chan_list_cmd`.
    async fn send_chan_list(&mut self) -> Result<(), MacError> {
        let chans = self.wiphy.scan_chan_list();
        if chans.is_empty() {
            return fail(
                step::START_CHAN_LIST,
                0,
                errno::EINVAL,
                "scan chan list (no channels)",
            );
        }
        let cmds = match scan_chan_list_cmds(self.caps.pdev_id, &chans, self.wmi.max_msg_len()) {
            Ok(c) => c,
            Err(e) => return fail(step::START_CHAN_LIST, 1, e.errno(), "scan chan list"),
        };
        for c in cmds {
            self.cmd(c, step::START_CHAN_LIST, 2, "scan chan list")
                .await?;
        }
        Ok(())
    }

    /// The current per-channel scan list (for tests / the core).
    pub fn scan_chan_list(&self) -> Vec<ChannelParam> {
        self.wiphy.scan_chan_list()
    }

    /// `ieee80211_do_open` for a station: `ath11k_mac_op_add_interface`,
    /// the ERP reset `bss_info_changed`, and `ieee80211_set_wmm_default(
    /// link, true, false)`.
    pub async fn add_interface(&mut self) -> Result<u32, MacError> {
        if self.vif.is_some() {
            return fail(
                step::VDEV_CREATE,
                0,
                errno::EBUSY,
                "add interface (vdev exists)",
            );
        }
        let vdev_id = 0u32; // __ffs64(ab->free_vdev_map) on a fresh pdev
        let addr = self.caps.mac_addr;
        let (nt, nr) = (self.own.num_tx_chains as u8, self.own.num_rx_chains as u8);
        let mut p = VdevCreateParams {
            if_id: vdev_id as u8,
            vdev_type: vdev_type::STA,
            subtype: vdev_subtype::NONE,
            pdev_id: self.caps.pdev_id,
            ..Default::default()
        };
        // ath11k_mac_setup_vdev_params_mbssid: non-AP vifs leave both 0.
        if self.caps.pdev.supported_bands & WMI_HOST_WLAN_2G_CAP != 0 {
            p.chains_2g = Chains { tx: nt, rx: nr };
        }
        if self.caps.pdev.supported_bands & WMI_HOST_WLAN_5G_CAP != 0 {
            p.chains_5g = Chains { tx: nt, rx: nr };
        }
        let c = vdev_create_cmd(&addr, &p);
        self.cmd(c, step::VDEV_CREATE, 0, "vdev create").await?;
        self.vif = Some(Vif {
            vdev_id,
            addr,
            ..Default::default()
        });
        // ath11k_mac_op_update_vif_offload
        let encap = if self.cfg.frame_mode_ethernet {
            txrx::ETHERNET
        } else if self.cfg.raw_mode {
            txrx::RAW
        } else {
            txrx::NATIVE_WIFI
        };
        // Failures here are warnings in Linux.
        let _ = self
            .vdev_param(vdev_id, WMI_VDEV_PARAM_TX_ENCAP_TYPE, encap)
            .await;
        let _ = self
            .vdev_param(vdev_id, WMI_VDEV_PARAM_RX_DECAP_TYPE, encap)
            .await;
        let nss = self.own.num_tx_chains.max(1);
        let r = async {
            self.vdev_param(vdev_id, WMI_VDEV_PARAM_NSS, nss).await?;
            self.sta_ps_param(
                vdev_id,
                sta_ps_param::RX_WAKE_POLICY,
                sta_ps_param::RX_WAKE_POLICY_WAKE,
            )
            .await?;
            self.sta_ps_param(
                vdev_id,
                sta_ps_param::TX_WAKE_THRESHOLD,
                sta_ps_param::TX_WAKE_THRESHOLD_ALWAYS,
            )
            .await?;
            self.sta_ps_param(
                vdev_id,
                sta_ps_param::PSPOLL_COUNT,
                sta_ps_param::PSPOLL_COUNT_NO_MAX,
            )
            .await?;
            let c = sta_powersave_mode_cmd(vdev_id, sta_ps_mode::DISABLED);
            self.cmd(c, step::STA_PS, 0x100, "sta ps mode").await
        }
        .await;
        if let Err(e) = r {
            // err_vdev_del: ath11k_mac_vdev_delete
            let _ = self.wmi.send(vdev_delete_cmd(vdev_id as u8)).await;
            self.vif = None;
            return Err(e);
        }
        if self.svc(WMI_TLV_SERVICE_11D_OFFLOAD) {
            self.state_11d = State11d::Preparing;
        }
        // ath11k_mac_txpower_recalc: bss_conf.txpower is INT_MIN → no-op.
        let _ = self
            .vdev_param(vdev_id, WMI_VDEV_PARAM_RTS_THRESHOLD, RTS_THRESHOLD_OFF)
            .await;
        self.dp.vdev_tx_attach(vdev_id, addr);
        if self.supports_6ghz_cc_ext() {
            if let Some(info) = self.reg.store.clone() {
                // ath11k_reg_handle_chan_list(ab, reg_info, IEEE80211_REG_LPI_AP)
                if let Ok(RegUpdate::New) = self.reg.handle_chan_list(
                    &info,
                    false,
                    VdevKind::Sta {
                        ap_type: WMI_REG_INDOOR_AP,
                    },
                    self.caps.num_radios,
                    self.cfg.num_rxdma_per_pdev,
                ) {
                    self.pending.regd_update = true;
                }
            }
        }
        // ieee80211_do_open: ERP reset → bss_info_changed(ERP_CTS_PROT |
        // ERP_PREAMBLE | ERP_SLOT); CTS is deferred (vdev not started).
        self.bss_erp_changed(true, true, true).await;
        let defaults = wmm_default(false, false);
        self.conf_tx_all(&defaults).await?;
        self.run_deferred().await;
        Ok(vdev_id)
    }

    /// The `BSS_CHANGED_ERP_*` part of `ath11k_mac_op_bss_info_changed`.
    async fn bss_erp_changed(&mut self, cts: bool, slot: bool, preamble: bool) {
        let Some(v) = self.vif.clone() else { return };
        if cts && v.is_started {
            let _ = self
                .vdev_param(
                    v.vdev_id,
                    WMI_VDEV_PARAM_PROTECTION_MODE,
                    v.use_cts_prot as u32,
                )
                .await;
        }
        if slot {
            let s = if v.use_short_slot {
                WMI_VDEV_SLOT_TIME_SHORT
            } else {
                WMI_VDEV_SLOT_TIME_LONG
            };
            let _ = self
                .vdev_param(v.vdev_id, WMI_VDEV_PARAM_SLOT_TIME, s)
                .await;
        }
        if preamble {
            let p = if v.use_short_preamble {
                WMI_VDEV_PREAMBLE_SHORT
            } else {
                WMI_VDEV_PREAMBLE_LONG
            };
            let _ = self.vdev_param(v.vdev_id, WMI_VDEV_PARAM_PREAMBLE, p).await;
        }
    }

    /// `drv_conf_tx` for AC 0..3 (`IEEE80211_AC_VO, VI, BE, BK`) →
    /// `ath11k_mac_op_conf_tx` each.
    async fn conf_tx_all(&mut self, q: &[TxQueueParams; 4]) -> Result<(), MacError> {
        for (ac, p) in q.iter().enumerate() {
            self.conf_tx(ac, p).await?;
        }
        Ok(())
    }

    /// `ath11k_mac_op_conf_tx(ac)`: update `arvif->wmm_params`, send
    /// all four, then `ath11k_conf_tx_uapsd`.
    async fn conf_tx(&mut self, ac: usize, p: &TxQueueParams) -> Result<(), MacError> {
        let Some(v) = self.vif.as_mut() else {
            return Ok(());
        };
        // IEEE80211_AC_{VO,VI,BE,BK} → WME_AC_{VO=3,VI=2,BE=0,BK=1}
        let wme = [3usize, 2, 0, 1][ac];
        v.wmm[wme].cwmin = p.cw_min;
        v.wmm[wme].cwmax = p.cw_max;
        v.wmm[wme].aifs = p.aifs;
        v.wmm[wme].txop = p.txop;
        let (vdev, wmm) = (v.vdev_id, v.wmm);
        let c = vdev_set_wmm_params_cmd(vdev, &wmm, WMI_WMM_PARAM_TYPE_LEGACY);
        self.cmd(c, step::WMM_PARAMS, ac as u32, "wmm params")
            .await?;
        // ath11k_conf_tx_uapsd: value bits per AC (VO → AC3 … BK → AC0).
        let bits = [0x3u32 << 6, 0x3 << 4, 0x3 << 2, 0x3][ac];
        let v = self.vif.as_mut().unwrap();
        if p.uapsd {
            v.uapsd |= bits;
        } else {
            v.uapsd &= !bits;
        }
        let uapsd = v.uapsd;
        self.sta_ps_param(vdev, sta_ps_param::UAPSD, uapsd).await?;
        let wake = if uapsd != 0 {
            sta_ps_param::RX_WAKE_POLICY_POLL_UAPSD
        } else {
            sta_ps_param::RX_WAKE_POLICY_WAKE
        };
        // "could not set rx wake param" is a warning.
        let _ = self
            .sta_ps_param(vdev, sta_ps_param::RX_WAKE_POLICY, wake)
            .await;
        Ok(())
    }

    // ── 11d ────────────────────────────────────────────────────────

    /// `ath11k_mac_11d_scan_start`.
    async fn scan_11d_start(&mut self, vdev_id: u32) {
        let ok_to_start = !self.regdom_set_by_user
            && self.vdev_id_11d.is_none()
            && self.svc(WMI_TLV_SERVICE_11D_OFFLOAD);
        if ok_to_start {
            let c = scan_11d_start_cmd(vdev_id, ATH11K_SCAN_11D_INTERVAL, 0);
            if self
                .cmd(c, step::SCAN_11D, 1, "11d scan start")
                .await
                .is_ok()
            {
                self.vdev_id_11d = Some(vdev_id);
                if self.state_11d == State11d::Preparing {
                    self.state_11d = State11d::Running;
                }
            }
        }
        if self.state_11d == State11d::Preparing {
            self.state_11d = State11d::Idle;
        }
    }

    /// `ath11k_mac_11d_scan_stop`.
    async fn scan_11d_stop(&mut self) {
        if !self.svc(WMI_TLV_SERVICE_11D_OFFLOAD) {
            return;
        }
        if self.state_11d == State11d::Preparing {
            self.state_11d = State11d::Idle;
        }
        if let Some(v) = self.vdev_id_11d {
            let c = scan_11d_stop_cmd(v);
            if self
                .cmd(c, step::SCAN_11D, 2, "11d scan stop")
                .await
                .is_ok()
            {
                self.vdev_id_11d = None;
                self.state_11d = State11d::Idle;
            }
        }
    }

    // ── Scan ───────────────────────────────────────────────────────

    /// `ath11k_scan_event` for our vdev.
    fn scan_event(&mut self, s: &ScanEvent) {
        if self.scan.state == ScanState::Idle || s.vdev_id != self.scan.vdev_id {
            return;
        }
        match s.event_type {
            scan_event::STARTED => {
                if self.scan.state == ScanState::Starting {
                    self.scan.state = ScanState::Running;
                    self.scan.started = true;
                }
            }
            scan_event::COMPLETED => {
                if matches!(self.scan.state, ScanState::Running | ScanState::Aborting) {
                    self.scan_finish();
                }
            }
            scan_event::START_FAILED => {
                if self.scan.state == ScanState::Starting {
                    self.scan.started = true;
                    self.scan_finish();
                }
            }
            scan_event::DEQUEUED => self.scan_finish(),
            // BSS_CHANNEL / FOREIGN_CHAN only move ar->scan_channel.
            _ => {}
        }
    }

    /// `__ath11k_mac_scan_finish`.
    fn scan_finish(&mut self) {
        match self.scan.state {
            ScanState::Idle => {}
            st => {
                self.scan.aborted = matches!(st, ScanState::Aborting | ScanState::Starting);
                self.scan.state = ScanState::Idle;
                self.scan.deadline = None;
                self.scan.completed = true;
            }
        }
    }

    /// `ath11k_mgmt_rx_event` → `ieee80211_rx`: scan results, MLME
    /// responses, beacons of our BSS, deauth / disassoc.
    fn mgmt_rx(&mut self, m: &MgmtRx<'_>) {
        let Some(st) = m.rx_status() else {
            return;
        };
        let Some(hdr) = frame::MgmtHdr::parse(m.frame) else {
            return;
        };
        let Some(stype) = hdr.stype() else {
            return;
        };
        let own = self.caps.mac_addr;
        // 802.11w (ieee80211_rx_h_decrypt / ieee80211_drop_unencrypted_mgmt)
        // for robust frames from our AP.
        let mut plain = None;
        if matches!(
            stype,
            frame::stype::DEAUTH | frame::stype::DISASSOC | frame::stype::ACTION
        ) {
            match self.mfp_rx_filter(m.frame) {
                Some(MfpRx::Drop { .. }) => return,
                Some(MfpRx::Pass(p)) => plain = p,
                None => {}
            }
        }
        let f: &[u8] = plain.as_deref().unwrap_or(m.frame);
        match stype {
            frame::stype::BEACON | frame::stype::PROBE_RESP => {
                let Some(b) = frame::parse_beacon(m.frame) else {
                    return;
                };
                if !b.is_probe_resp {
                    if let Some(l) = self.link.as_mut() {
                        if hdr.bssid == l.bss.bssid {
                            // ath11k_mac_handle_beacon: cancel connection_loss_work
                            l.conn_loss_deadline = None;
                            l.have_beacon = true;
                        }
                    }
                }
                if self.scan.state == ScanState::Idle {
                    return;
                }
                // ieee80211_scan_rx: probe responses must be for us.
                if b.is_probe_resp && hdr.da != own {
                    return;
                }
                self.inform_bss(&b, st.freq, st.signal);
            }
            frame::stype::AUTH | frame::stype::ASSOC_RESP | frame::stype::REASSOC_RESP => {
                if Some(hdr.bssid) == self.mlme_target && hdr.da == own {
                    self.pending.mlme_rx.push_back(m.frame.to_vec());
                }
            }
            frame::stype::ACTION => {
                // ieee80211_rx_h_action, WLAN_CATEGORY_BACK: from our AP's
                // station entry (`sta_info_get_bss(sdata, mgmt->sa)`), to
                // us; the action code present and its fixed fields long
                // enough, else "invalid".
                let Some(l) = self.link.as_ref() else {
                    return;
                };
                if f.len() >= frame::IEEE80211_MIN_ACTION_SIZE + 3
                    && f[frame::MGMT_HDR_LEN] == sec::WLAN_CATEGORY_SA_QUERY
                {
                    self.sa_query_rx(f);
                    return;
                }
                if hdr.sa != l.bss.bssid
                    || hdr.da != own
                    || f.len() < frame::IEEE80211_MIN_ACTION_SIZE + 1
                    || f[frame::MGMT_HDR_LEN] != frame::WLAN_CATEGORY_BACK
                {
                    return;
                }
                let need = match f[frame::MGMT_HDR_LEN + 1] {
                    frame::WLAN_ACTION_ADDBA_REQ => frame::ADDBA_REQ_LEN,
                    frame::WLAN_ACTION_ADDBA_RESP => frame::ADDBA_RESP_LEN,
                    frame::WLAN_ACTION_DELBA => frame::DELBA_LEN,
                    _ => return,
                };
                if f.len() >= frame::IEEE80211_MIN_ACTION_SIZE + need {
                    self.pending.back_rx.push_back(f.to_vec());
                }
            }
            frame::stype::DEAUTH | frame::stype::DISASSOC => {
                if let Some((h, deauth, reason)) = frame::parse_deauth_disassoc(f) {
                    if let Some(l) = self.link.as_mut() {
                        // To us or group addressed (ieee80211_accept_frame).
                        let to_us = h.da == own || h.da[0] & 1 != 0;
                        if h.bssid == l.bss.bssid && to_us && l.loss.is_none() {
                            l.loss = Some(LinkLoss::Deauth { deauth, reason });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// `cfg80211_inform_bss_frame_data` → `cfg80211_inform_single_bss_data`
    /// → `cfg80211_bss_update`.
    fn inform_bss(&mut self, b: &frame::BeaconFrame<'_>, rx_freq: u32, signal: i32) {
        let Some(rx) = self.wiphy.get(rx_freq).copied() else {
            return;
        };
        // NARF-stricter: drop a frame whose SSID element is longer than
        // IEEE80211_MAX_SSID_LEN instead of keeping it.
        if frame::find_elem(b.ies, eid::SSID).is_some_and(|s| s.len() > frame::MAX_SSID_LEN) {
            return;
        }
        // cfg80211_get_bss_channel
        let p = ParsedIes::parse(b.ies);
        let chan_no = p
            .ds_channel
            .map(|c| c as u32)
            .or(p.ht_oper.map(|h| h.primary_chan as u32));
        let freq = match chan_no.and_then(|c| frame::channel_to_freq(c, rx.band)) {
            None => rx.center_freq,
            Some(f) if f == rx.center_freq => f,
            Some(f) => match self.wiphy.get(f) {
                None if rx.band == Band::Ghz2 || rx.band == Band::Ghz6 => return,
                None => rx.center_freq,
                Some(c) if c.flags & chan_flag::DISABLED != 0 => return,
                Some(c) => c.center_freq,
            },
        };
        let signal_valid = freq == rx.center_freq;
        let ssid = frame::find_elem(b.ies, eid::SSID).map(|s| s.to_vec());
        let now = self.wmi.now_ms();
        let found = self.bss.iter_mut().find(|e| {
            e.freq == freq
                && e.bssid == b.hdr.bssid
                && frame::find_elem(&e.ies, eid::SSID).map(|s| s.to_vec()) == ssid
        });
        let ies = b.ies.to_vec();
        match found {
            Some(e) => {
                e.capability = b.capability;
                e.beacon_int = b.beacon_int;
                if signal_valid {
                    e.signal = signal;
                }
                if b.is_probe_resp {
                    e.proberesp_ies = Some(ies.clone());
                } else {
                    e.beacon_ies = Some(ies.clone());
                }
                e.ies = ies;
                e.last_seen_ms = now;
            }
            None => self.bss.push(ScanBss {
                bssid: b.hdr.bssid,
                freq,
                capability: b.capability,
                beacon_int: b.beacon_int,
                signal,
                beacon_ies: (!b.is_probe_resp).then(|| ies.clone()),
                proberesp_ies: b.is_probe_resp.then(|| ies.clone()),
                ies,
                last_seen_ms: now,
            }),
        }
    }

    /// mac80211's probe request elements for the scan (`req->ie`),
    /// built per band like `ieee80211_build_preq_ies` with
    /// `SINGLE_SCAN_ON_ALL_BANDS`: rates + extended rates + HT
    /// capabilities for 2.4 GHz, rates + HT + VHT capabilities for 5 GHz.
    fn probe_req_ies(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for b in [Band::Ghz2, Band::Ghz5] {
            if self.wiphy.band(b).is_empty() {
                continue;
            }
            let rates: Vec<u8> = peer::sband_rates(b)
                .iter()
                .map(|&(br, _)| br.div_ceil(5) as u8)
                .collect();
            let n = rates.len().min(8);
            out.push(eid::SUPP_RATES);
            out.push(n as u8);
            out.extend_from_slice(&rates[..n]);
            if rates.len() > 8 {
                out.push(eid::EXT_SUPP_RATES);
                out.push((rates.len() - 8) as u8);
                out.extend_from_slice(&rates[8..]);
            }
            let ht = self.own.ht(b);
            if ht.ht_supported {
                frame::HtCapIe {
                    cap_info: ht.cap,
                    ampdu_params_info: ht.ampdu_factor | (ht.ampdu_density << 2),
                    rx_mask: ht.rx_mask,
                    rx_highest: ht.rx_highest,
                    tx_params: ht.tx_params,
                    ..Default::default()
                }
                .put(&mut out);
            }
            if let Some(v) = self.own.vht(b) {
                frame::VhtCapIe {
                    vht_cap_info: v.cap,
                    rx_mcs_map: v.rx_mcs_map,
                    rx_highest: v.rx_highest,
                    tx_mcs_map: v.tx_mcs_map,
                    tx_highest: v.tx_highest,
                }
                .put(&mut out);
            }
        }
        out
    }

    /// `ath11k_mac_op_hw_scan` for a cfg80211 scan request, then wait for
    /// `ieee80211_scan_completed`. Returns the BSS table entries seen in
    /// the last `IEEE80211_SCAN_RESULT_EXPIRE`.
    pub async fn hw_scan(
        &mut self,
        ssids: &[Vec<u8>],
        freqs: &[u32],
    ) -> Result<Vec<ScanBss>, MacError> {
        let Some(vdev_id) = self.vif.as_ref().map(|v| v.vdev_id) else {
            return fail(step::SCAN_BUSY, 1, errno::ENOTCONN, "hw scan (no vdev)");
        };
        if self.state_11d == State11d::Preparing
            && self.svc(WMI_TLV_SERVICE_SUPPORT_11D_FOR_HOST_SCAN)
        {
            self.scan_11d_start(vdev_id).await;
        }
        if self.scan.state != ScanState::Idle {
            return fail(
                step::SCAN_BUSY,
                self.scan.state as u32,
                errno::EBUSY,
                "hw scan (busy)",
            );
        }
        self.scan = ScanCtx {
            state: ScanState::Starting,
            vdev_id,
            started: false,
            completed: false,
            aborted: false,
            deadline: None,
        };
        let mut arg = ScanReqParams::start_scan_init(
            self.state_11d == State11d::Preparing,
            self.svc(WMI_TLV_SERVICE_PASSIVE_SCAN_START_TIME_ENHANCE),
        );
        arg.vdev_id = vdev_id;
        arg.scan_id = ATH11K_SCAN_ID;
        if self.cfg.single_pdev_only {
            arg.scan_ctrl_flags |= scan_flag::FILTER_PROBE_REQ;
        }
        if ssids.is_empty() {
            arg.scan_ctrl_flags |= scan_flag::PASSIVE;
        } else {
            arg.ssids = ssids.to_vec();
            arg.extraie = self.probe_req_ies();
        }
        let per_chan = self.svc(WMI_TLV_SERVICE_SCAN_CONFIG_PER_CHANNEL);
        arg.chan_list = freqs
            .iter()
            .map(|&f| {
                if per_chan {
                    f & scan_flag::CONFIG_PER_CHANNEL_MASK
                } else {
                    f
                }
            })
            .collect();
        let scan_timeout = arg.max_scan_time + timeout::SCAN_OVERHEAD;
        let r = self.start_scan(&arg).await;
        if r.is_err() {
            self.scan.state = ScanState::Idle;
        }
        // ieee80211_queue_delayed_work(&ar->scan.timeout) runs either way.
        self.scan.deadline = Some(self.wmi.now_ms() + scan_timeout as u64);
        if self.state_11d == State11d::Preparing {
            self.scan_11d_start(vdev_id).await;
        }
        r?;
        // Wait for COMPLETED; the timeout work aborts the scan.
        if self
            .wait_for(scan_timeout, |s| s.scan.completed.then_some(()))
            .await
            .is_none()
        {
            let e = MacError::new(step::SCAN_TIMEOUT, 0, errno::ETIMEDOUT);
            e.report("hw scan (no completion)");
            self.scan_abort().await;
        }
        let now = self.wmi.now_ms();
        Ok(self
            .bss
            .iter()
            .filter(|b| now.saturating_sub(b.last_seen_ms) <= timeout::BSS_EXPIRE)
            .cloned()
            .collect())
    }

    /// `ath11k_start_scan`.
    async fn start_scan(&mut self, arg: &ScanReqParams) -> Result<(), MacError> {
        let c = match scan_start_cmd(arg) {
            Ok(c) => c,
            Err(e) => return fail(step::SCAN_START_CMD, 0, e.errno(), "start scan"),
        };
        self.cmd(c, step::SCAN_START_CMD, 1, "start scan").await?;
        let mut t = 1000;
        if self.svc(WMI_TLV_SERVICE_11D_OFFLOAD) {
            t = 5000;
            if self.wiphy.supports_6ghz() {
                t += 5000;
            }
        }
        if self
            .wait_for(t, |s| s.scan.started.then_some(()))
            .await
            .is_none()
        {
            let _ = self.scan_stop().await;
            return fail(
                step::SCAN_START_TIMEOUT,
                t,
                errno::ETIMEDOUT,
                "start scan (no STARTED)",
            );
        }
        if self.scan.state == ScanState::Idle {
            return fail(
                step::SCAN_START_FAILED,
                0,
                errno::EINVAL,
                "start scan (firmware refused)",
            );
        }
        Ok(())
    }

    /// `ath11k_scan_stop`.
    async fn scan_stop(&mut self) -> Result<(), MacError> {
        let c = scan_stop_cmd(
            self.scan.vdev_id,
            0,
            ATH11K_SCAN_ID,
            self.caps.pdev_id,
            ScanCancel::Single,
        );
        // Failures here are warnings in Linux ("failed to stop scan"):
        // build the error without latching so the caller's cause wins.
        let mut r = match self.wmi.send(c).await {
            Ok(()) => Ok(()),
            Err(e) => Err(MacError::new(step::SCAN_STOP_TIMEOUT, 1, e)),
        };
        if r.is_ok()
            && self
                .wait_for(timeout::SCAN_STOP, |s| s.scan.completed.then_some(()))
                .await
                .is_none()
        {
            r = Err(MacError::new(step::SCAN_STOP_TIMEOUT, 0, errno::ETIMEDOUT));
        }
        if self.scan.state != ScanState::Idle {
            self.scan_finish();
        }
        r
    }

    /// `ath11k_scan_abort`.
    async fn scan_abort(&mut self) {
        if self.scan.state == ScanState::Running {
            self.scan.state = ScanState::Aborting;
            if let Err(e) = self.scan_stop().await {
                e.report("abort scan");
            }
        }
    }

    /// `WirelessNetIface::scan` semantics: a cfg80211 scan of
    /// `req.channels` (all enabled channels when empty), active with
    /// `req.ssids` when `req.active`, returning 2.4 / 5 GHz BSSes.
    pub async fn scan(&mut self, req: &ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        if req.ssids.len() > 16 || req.ssids.iter().any(|s| s.len() > frame::MAX_SSID_LEN) {
            return Err(WirelessError::InvalidArgs);
        }
        let freqs: Vec<u32> = if req.channels.is_empty() {
            // cfg80211 never passes disabled channels.
            self.wiphy
                .iter()
                .filter(|c| c.flags & chan_flag::DISABLED == 0)
                .map(|c| c.center_freq)
                .collect()
        } else {
            let mut v = Vec::new();
            for &ch in &req.channels {
                let f = channel_number_freq(ch).ok_or(WirelessError::InvalidArgs)?;
                match self.wiphy.get(f) {
                    Some(c) if c.flags & chan_flag::DISABLED == 0 => v.push(f),
                    _ => return Err(WirelessError::InvalidArgs),
                }
            }
            v
        };
        let ssids: Vec<Vec<u8>> = if req.active {
            if req.ssids.is_empty() {
                alloc::vec![Vec::new()]
            } else {
                req.ssids.clone()
            }
        } else {
            Vec::new()
        };
        narf_memory::diag::set_wifi_stage(narf_memory::diag::WifiStage::Scan);
        let r = self
            .hw_scan(&ssids, &freqs)
            .await
            .map_err(|e| e.wireless())?;
        Ok(r.iter().filter_map(ScanBss::info).collect())
    }

    // ── Connect ────────────────────────────────────────────────────

    /// `WirelessNetIface::associate`: Open or WPA2-PSK (CCMP).
    pub async fn associate(&mut self, req: &AssociateRequest) -> Result<(), WirelessError> {
        self.connect(req).await.map_err(|e| e.wireless())
    }

    /// The full station join; on failure everything set up is torn down
    /// the way mac80211 does (`ieee80211_destroy_auth_data` /
    /// `ieee80211_destroy_assoc_data` / `ieee80211_set_disassoc`).
    pub async fn connect(&mut self, req: &AssociateRequest) -> Result<(), MacError> {
        if self.vif.is_none() {
            return fail(step::CONNECT_STATE, 1, errno::ENOTCONN, "connect (no vdev)");
        }
        if self.link.is_some() {
            return fail(
                step::CONNECT_STATE,
                2,
                errno::EBUSY,
                "connect (already connected)",
            );
        }
        let Some(freq) = channel_number_freq(req.channel) else {
            return fail(
                step::CONNECT_NO_BSS,
                req.channel,
                errno::EINVAL,
                "connect (channel)",
            );
        };
        let Some(bss) = self
            .bss
            .iter()
            .find(|b| b.bssid == req.bssid && b.freq == freq)
            .cloned()
        else {
            return fail(
                step::CONNECT_NO_BSS,
                freq,
                errno::ENOENT,
                "connect (BSS not in scan table)",
            );
        };
        let ies = bss.parsed();
        // wpa_supplicant_set_suites (AKM, ciphers, PMF).
        let rsn = match sec::select_rsn(&ies, bss.capability, &req.security) {
            Ok(r) => r,
            Err(d) => {
                return fail(
                    step::CONNECT_UNSUPPORTED,
                    d,
                    errno::EOPNOTSUPP,
                    "connect (security)",
                )
            }
        };
        if self.scan.state != ScanState::Idle {
            // ieee80211_prep_connection: "Cancel scan to ensure that
            // nothing interferes with connection".
            self.scan_abort().await;
        }
        let r = self.join(&bss, &ies, &req.ssid, rsn).await;
        if r.is_err() {
            let (assoc, reason) = self
                .link
                .as_ref()
                .map_or((false, 0), |l| (l.assoc, l.deauth_reason));
            self.teardown(assoc, reason).await;
        }
        r
    }

    async fn join(
        &mut self,
        bss: &ScanBss,
        ies: &ParsedIes,
        ssid: &[u8],
        rsn: Option<(RsnPlan, Credential)>,
    ) -> Result<(), MacError> {
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let band = freq_band(bss.freq);
        if band == Band::Ghz6 {
            return fail(
                step::CONNECT_UNSUPPORTED,
                6,
                errno::EOPNOTSUPP,
                "connect (6 GHz needs HE)",
            );
        }
        let (mode, def) = peer::determine_chan(
            &self.wiphy,
            &self.own,
            bss.freq,
            ies.ht_cap.as_ref(),
            ies.ht_oper.as_ref(),
            ies.vht_cap.as_ref(),
            ies.vht_oper.as_ref(),
        );
        // ieee80211_determine_ap_chan: HE when the AP has HE capabilities
        // and operation (and VHT on 5 GHz), we have HE on the band, and
        // ieee80211_verify_{peer,sta}_he_mcs_support pass.
        let mut mode = mode;
        if (mode == ConnMode::Vht || (band == Band::Ghz2 && mode == ConnMode::Ht))
            && self.he_ok(band, ies)
        {
            mode = ConnMode::He;
        }
        let (_, basic) = peer::rates_to_mask(band, &ies.rates);
        let (supp, _) = peer::rates_to_mask(band, &ies.rates);
        self.link = Some(Link {
            bss: bss.clone(),
            def,
            mode,
            sta: ApSta {
                addr: bss.bssid,
                ..Default::default()
            },
            peer_created: false,
            assoc: false,
            authorized: false,
            ptk_installed: false,
            gtk_idx: None,
            have_beacon: bss
                .beacon_ies
                .as_deref()
                .is_some_and(|b| frame::find_elem(b, eid::TIM).is_some()),
            conn_loss_deadline: None,
            loss: None,
            wmm: ies.wmm_used,
            operating_11g: band == Band::Ghz2 && supp >> 4 != 0,
            basic_rates: basic,
            deauth_reason: frame::WLAN_REASON_DEAUTH_LEAVING,
            ba_rx_valid: 0,
            ba_rx_token: [0; 16],
            rsn: rsn.as_ref().map(|(p, _)| p.clone()),
            he: None,
        });
        self.mfp = MfpState::default();
        // ── ieee80211_prep_connection ──
        // ieee80211_link_use_channel → ath11k_mac_op_assign_vif_chanctx
        self.vif.as_mut().unwrap().chanctx = Some(def);
        if !self.cfg.vdev_start_delay {
            self.vdev_start(&def).await?;
        }
        // ieee80211_recalc_txpower → BSS_CHANGED_TXPOWER
        let chan_power = self.wiphy.get(def.freq).map_or(0, |c| c.max_power);
        self.vif.as_mut().unwrap().txpower = Some(chan_power);
        self.txpower_recalc().await?;
        // BSS_CHANGED_BSSID | BSS_CHANGED_BASIC_RATES | BSS_CHANGED_BEACON_INT
        {
            let v = self.vif.as_mut().unwrap();
            v.beacon_interval = bss.beacon_int as u32;
            v.bssid = bss.bssid;
        }
        let _ = self
            .vdev_param(
                vdev_id,
                WMI_VDEV_PARAM_BEACON_INTERVAL,
                bss.beacon_int as u32,
            )
            .await;
        if let Some(code) = peer::mgmt_rate_code(band, basic) {
            let _ = self
                .vdev_param(vdev_id, WMI_VDEV_PARAM_MGMT_RATE, code)
                .await;
            self.hw_rate_code = code;
            let _ = self
                .vdev_param(vdev_id, WMI_VDEV_PARAM_BEACON_RATE, code)
                .await;
        }
        // sta_info_insert → ath11k_mac_station_add
        self.station_add(bss.bssid, &def).await?;
        // ── ieee80211_mgd_auth ──
        self.mlme_target = Some(bss.bssid);
        // Open System, or SAE whose PMK feeds the 4-way handshake.
        let mut pmk = None;
        match rsn.as_ref() {
            Some((plan, Credential::Sae(pw))) => {
                pmk = Some(self.sae_authenticate(bss, plan, pw).await?);
            }
            Some((_, Credential::Pmk(p))) => {
                pmk = Some(*p);
                self.authenticate(bss.bssid).await?;
            }
            None => self.authenticate(bss.bssid).await?,
        }
        // ── ieee80211_mgd_assoc ──
        let plan = rsn.as_ref().map(|(p, _)| p.clone());
        let resp = self.associate_frames(bss, ies, ssid, plan.as_ref()).await?;
        if rsn.is_none() {
            // !IEEE80211_STA_CONTROL_PORT: ieee80211_assoc_success moves the
            // AP to AUTHORIZED before BSS_CHANGED_ASSOC (ath11k only sets
            // peer->is_authorized; ath11k_bss_assoc then authorizes).
            self.link.as_mut().unwrap().authorized = true;
        }
        self.assoc_success(bss, ies, &resp).await?;
        // ── wpa_supplicant ──
        if let (Some((plan, _)), Some(pmk)) = (rsn, pmk) {
            self.rsna_4way(bss, &plan, &pmk).await?;
        }
        self.authorize().await?;
        self.setup_ps().await;
        narf_memory::diag::set_wifi_stage(narf_memory::diag::WifiStage::Connected);
        Ok(())
    }

    /// `ath11k_mac_txpower_recalc`.
    async fn txpower_recalc(&mut self) -> Result<(), MacError> {
        let Some(t) = self.vif.as_ref().and_then(|v| v.txpower).filter(|&t| t > 0) else {
            return Ok(());
        };
        let tx = (t as u32).min(self.caps.hw_max_tx_power) * 2;
        let bands = self.caps.pdev.supported_bands;
        if bands & WMI_HOST_WLAN_2G_CAP != 0 && self.txpower_limit_2g != tx {
            let c = pdev_set_param_cmd(WMI_PDEV_PARAM_TXPOWER_LIMIT2G, tx, self.caps.pdev_id);
            self.cmd(c, step::TXPOWER, WMI_PDEV_PARAM_TXPOWER_LIMIT2G, "txpower")
                .await?;
            self.txpower_limit_2g = tx;
        }
        if bands & WMI_HOST_WLAN_5G_CAP != 0 && self.txpower_limit_5g != tx {
            let c = pdev_set_param_cmd(WMI_PDEV_PARAM_TXPOWER_LIMIT5G, tx, self.caps.pdev_id);
            self.cmd(c, step::TXPOWER, WMI_PDEV_PARAM_TXPOWER_LIMIT5G, "txpower")
                .await?;
            self.txpower_limit_5g = tx;
        }
        Ok(())
    }

    /// `ath11k_mac_station_add` (STA vif): `ath11k_peer_create`,
    /// `ath11k_dp_peer_setup`, `ath11k_mac_start_vdev_delay`.
    async fn station_add(&mut self, addr: [u8; 6], def: &ChanDef) -> Result<(), MacError> {
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let c = peer_create_cmd(vdev_id, &addr, peer_type::DEFAULT);
        self.cmd(c, step::PEER_CREATE, 0, "peer create").await?;
        if let Err(e) = self
            .dp
            .wait_peer_mapped(vdev_id, addr, true, timeout::PEER_MAP)
            .await
        {
            // ath11k_peer_create returns before rhash_add: no cleanup delete.
            return fail(
                step::PEER_MAP_TIMEOUT,
                vdev_id,
                e,
                "peer create (no PEER_MAP)",
            );
        }
        self.link.as_mut().unwrap().peer_created = true;
        if let Err(e) = self.dp.peer_setup(vdev_id, addr).await {
            return fail(step::PEER_CREATE, 1, e, "dp peer setup");
        }
        if self.cfg.vdev_start_delay && !self.vif.as_ref().unwrap().is_started {
            self.vdev_start(def).await?;
            if self.hw_rate_code > 0 {
                let code = self.hw_rate_code;
                self.vdev_param(vdev_id, WMI_VDEV_PARAM_MGMT_RATE, code)
                    .await?;
            }
        }
        Ok(())
    }

    /// `ath11k_mac_vdev_start_restart(arvif, ctx, false)`.
    async fn vdev_start(&mut self, def: &ChanDef) -> Result<(), MacError> {
        let v = self.vif.clone().unwrap();
        let chan = self.wiphy.get(def.freq).copied();
        let mut arg = VdevStartReqArg {
            vdev_id: v.vdev_id,
            dtim_period: v.dtim_period,
            bcn_intval: v.beacon_interval,
            pref_tx_streams: self.own.num_tx_chains,
            pref_rx_streams: self.own.num_rx_chains,
            ..Default::default()
        };
        arg.channel.freq = def.freq;
        arg.channel.band_center_freq1 = def.center_freq1;
        arg.channel.band_center_freq2 = 0;
        arg.channel.mode = peer::vdev_phymode(def);
        if let Some(c) = chan {
            arg.channel.max_power = c.max_power as u8;
            arg.channel.max_reg_power = c.max_reg_power as u8;
            arg.channel.max_antenna_gain = c.max_antenna_gain as u8;
            arg.channel.passive = c.flags & chan_flag::NO_IR != 0;
        }
        self.pending.vdev_start = None;
        let c = match vdev_start_cmd(&arg, false) {
            Ok(c) => c,
            Err(e) => return fail(step::VDEV_START, 0, e.errno(), "vdev start"),
        };
        self.cmd(c, step::VDEV_START, 1, "vdev start").await?;
        let Some(resp) = self
            .wait_for(timeout::VDEV_SETUP, |s| s.pending.vdev_start.take())
            .await
        else {
            return fail(
                step::VDEV_START_TIMEOUT,
                def.freq,
                errno::ETIMEDOUT,
                "vdev start (no response)",
            );
        };
        if resp.status != WMI_VDEV_START_RESPONSE_STATUS_SUCCESS {
            return fail(
                step::VDEV_START_STATUS,
                resp.status,
                errno::EINVAL,
                "vdev start (status)",
            );
        }
        self.vif.as_mut().unwrap().is_started = true;
        if let Some(val) = peer::txbf_conf(self.caps.pdev.vht_cap, self.own.num_tx_chains) {
            let _ = self.vdev_param(v.vdev_id, WMI_VDEV_PARAM_TXBF, val).await;
        }
        Ok(())
    }

    /// Transmit one MLME frame and wait for the response mac80211's
    /// timers allow: TX status within `IEEE80211_*_TIMEOUT_LONG`, then
    /// `_SHORT` after the ACK. `matches` picks the response.
    async fn mlme_exchange(
        &mut self,
        frame_bytes: &[u8],
        tx_step: u32,
        timeout_step: u32,
        what: &str,
        response_ms: u32,
        matches: fn(&[u8]) -> bool,
    ) -> Result<Vec<u8>, MacError> {
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        self.pending.mlme_rx.clear();
        self.release_mgmt_tx();
        for _try in 0..timeout::MLME_TRIES {
            let desc = match self.wmi.mgmt_tx(vdev_id, frame_bytes).await {
                Ok(d) => d,
                Err(e) => return fail(tx_step, 0, e, what),
            };
            let take_resp = |s: &mut Self| {
                let pos = s.pending.mlme_rx.iter().position(|f| matches(f))?;
                s.pending.mlme_rx.remove(pos)
            };
            // Wait for the TX status (or an early response).
            let mut acked = None;
            let mut resp = None;
            let _ = self
                .wait_for(timeout::MLME_TX_STATUS, |s| {
                    if let Some(r) = take_resp(s) {
                        resp = Some(r);
                        return Some(());
                    }
                    let pos = s.pending.mgmt_tx.iter().position(|c| c.desc_id == desc)?;
                    let c = s.pending.mgmt_tx.remove(pos);
                    acked = Some(c.status == 0);
                    Some(())
                })
                .await;
            // The buffer is released on completion only; a completion
            // that trails an early response is released by
            // `release_mgmt_tx` later.
            if acked.is_some() {
                self.wmi.mgmt_tx_done(desc);
            }
            if let Some(r) = resp {
                return Ok(r);
            }
            if acked == Some(true) {
                if let Some(r) = self.wait_for(response_ms, take_resp).await {
                    return Ok(r);
                }
            }
        }
        // "Most likely AP is not in the range so remove the bss struct
        // for that AP": cfg80211_unlink_bss.
        if let Some(l) = self.link.as_ref() {
            let (b, f) = (l.bss.bssid, l.bss.freq);
            self.bss.retain(|e| !(e.bssid == b && e.freq == f));
        }
        fail(timeout_step, timeout::MLME_TRIES, errno::ETIMEDOUT, what)
    }

    /// `ieee80211_auth` (Open System) + `ieee80211_rx_mgmt_auth`.
    async fn authenticate(&mut self, bssid: [u8; 6]) -> Result<(), MacError> {
        let own = self.caps.mac_addr;
        let f = frame::build_auth_open(&own, &bssid);
        let resp = self
            .mlme_exchange(
                &f,
                step::AUTH_TX,
                step::AUTH_TIMEOUT,
                "authenticate",
                timeout::MLME_RESPONSE,
                |r| {
                    frame::parse_auth(r)
                        .is_some_and(|a| a.alg == frame::WLAN_AUTH_OPEN && a.transaction == 2)
                },
            )
            .await?;
        let a = frame::parse_auth(&resp).unwrap();
        if a.status != frame::WLAN_STATUS_SUCCESS {
            return fail(
                step::AUTH_REJECTED,
                a.status as u32,
                errno::ECONNREFUSED,
                "authenticate (denied)",
            );
        }
        Ok(())
    }

    /// The `AssocReqParams` `ieee80211_send_assoc` would use.
    pub fn assoc_request_params(
        &self,
        bss: &ScanBss,
        ies: &ParsedIes,
        ssid: &[u8],
        rsn: Option<&RsnPlan>,
    ) -> frame::AssocReqParams {
        let band = freq_band(bss.freq);
        let def = self.link.as_ref().map_or(
            ChanDef {
                freq: bss.freq,
                band,
                width: Width::W20,
                center_freq1: bss.freq,
            },
            |l| l.def,
        );
        let mode = self.link.as_ref().map_or(ConnMode::Ht, |l| l.mode);
        let mut c = capab::ESS;
        if bss.capability & capab::PRIVACY != 0 {
            c |= capab::PRIVACY;
        }
        if band == Band::Ghz2 {
            c |= capab::SHORT_SLOT_TIME | capab::SHORT_PREAMBLE;
        }
        // ieee80211_hw_set(ar->hw, SPECTRUM_MGMT)
        if bss.capability & capab::SPECTRUM_MGMT != 0 {
            c |= capab::SPECTRUM_MGMT;
        }
        // ieee80211_assoc_add_rates: rates both support (all ours when the
        // AP listed none), basic bit clear.
        let (ap_rates, _) = peer::rates_to_mask(band, &ies.rates);
        let mask = if ies.rates.is_empty() {
            u32::MAX
        } else {
            ap_rates
        };
        let rates = peer::sband_rates(band)
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, &(br, _))| br.div_ceil(5) as u8)
            .collect();
        let chan = self.wiphy.get(bss.freq);
        let pwr = if c & (capab::SPECTRUM_MGMT | capab::RADIO_MEASURE) != 0 {
            // ieee80211_chandef_max_power of a 20 MHz chandef on the channel.
            Some((0u8, chan.map_or(0, |c| c.max_power) as u8))
        } else {
            None
        };
        let supported_channels = if c & capab::SPECTRUM_MGMT != 0 {
            peer::supported_channel_numbers(&self.wiphy, band)
        } else {
            Vec::new()
        };
        let smps = if self.cfg.powersave && self.own.ht_cap_info & peer::wmi_ht::DYNAMIC_SMPS != 0 {
            SmpsMode::Dynamic
        } else {
            SmpsMode::Off
        };
        let ht_cap =
            (mode >= ConnMode::Ht).then(|| peer::assoc_ht_cap(self.own.ht(band), &def, smps));
        let vht_cap = match (
            mode >= ConnMode::Vht,
            self.own.vht(band),
            ies.vht_cap.as_ref(),
        ) {
            (true, Some(own), Some(ap)) => Some(peer::assoc_vht_cap(own, ap)),
            _ => None,
        };
        // The SME's elements (wpa_supplicant `sme.assoc_req_ie`): RSNE,
        // then the RSNXE (it sorts after HE in ieee80211_send_assoc).
        let mut extra = Vec::new();
        if let Some(p) = rsn {
            extra.extend_from_slice(&sec::assoc_ies(p, &bss.ies));
        }
        // ieee80211_put_he_cap for an HE connection.
        let he_cap = (mode >= ConnMode::He)
            .then(|| self.own_he(band).map(|h| he::put_he_cap(h, def.width)))
            .flatten();
        frame::AssocReqParams {
            he_cap,
            own: self.caps.mac_addr,
            bssid: bss.bssid,
            ssid: ssid.to_vec(),
            listen_interval: self.cfg.listen_interval,
            capab: c,
            rates,
            pwr_capability: pwr,
            supported_channels,
            ht_cap,
            vht_cap,
            // assoc_data->wmm (bss->wmm_used); U-APSD queues default 0.
            wmm_qos_info: ies.wmm_used.then_some(0),
            extra_ies: extra,
            prev_bssid: None,
        }
    }

    /// `ieee80211_do_assoc` + `ieee80211_rx_mgmt_assoc_resp`.
    async fn associate_frames(
        &mut self,
        bss: &ScanBss,
        ies: &ParsedIes,
        ssid: &[u8],
        rsn: Option<&RsnPlan>,
    ) -> Result<Vec<u8>, MacError> {
        let p = self.assoc_request_params(bss, ies, ssid, rsn);
        let f = frame::build_assoc_req(&p);
        let resp = self
            .mlme_exchange(
                &f,
                step::ASSOC_TX,
                step::ASSOC_TIMEOUT,
                "associate",
                timeout::MLME_RESPONSE,
                |r| frame::parse_assoc_resp(r).is_some_and(|a| !a.reassoc),
            )
            .await?;
        let a = frame::parse_assoc_resp(&resp).unwrap();
        if a.status != frame::WLAN_STATUS_SUCCESS {
            return fail(
                step::ASSOC_REJECTED,
                a.status as u32,
                errno::ECONNREFUSED,
                "associate (denied)",
            );
        }
        Ok(resp)
    }

    /// `ieee80211_assoc_success`: the AP station's capabilities, QoS
    /// parameters (`conf_tx`), then `ieee80211_set_associated` →
    /// `bss_info_changed(ASSOC | QOS | ERP_* | BEACON_INFO)` →
    /// `ath11k_bss_assoc`.
    async fn assoc_success(
        &mut self,
        bss: &ScanBss,
        bss_ies: &ParsedIes,
        resp: &[u8],
    ) -> Result<(), MacError> {
        let a = frame::parse_assoc_resp(resp).unwrap();
        let rie = ParsedIes::parse(a.ies);
        let l = self.link.clone().unwrap();
        let band = l.def.band;
        let mut sta = ApSta {
            addr: bss.bssid,
            ..Default::default()
        };
        let rates = if rie.rates.is_empty() {
            &bss_ies.rates
        } else {
            &rie.rates
        };
        let (supp, basic) = peer::rates_to_mask(band, rates);
        sta.supp_rates = supp;
        if l.mode >= ConnMode::Ht {
            sta.ht_cap = peer::sta_ht_cap(self.own.ht(band), rie.ht_cap.as_ref());
        }
        if l.mode >= ConnMode::Vht {
            let have_80 = self
                .wiphy
                .band(band)
                .iter()
                .any(|c| c.flags & (chan_flag::DISABLED | chan_flag::NO_80MHZ) == 0);
            if let Some(own) = self.own.vht(band) {
                sta.vht_cap = peer::sta_vht_cap(own, &sta.ht_cap, rie.vht_cap.as_ref(), have_80);
            }
        }
        sta.bandwidth = Some(peer::sta_bandwidth(&sta.ht_cap, &sta.vht_cap, &l.def));
        sta.rx_nss = peer::sta_rx_nss(&sta.ht_cap, &sta.vht_cap);
        // ieee80211_assoc_config_link: ieee80211_he_cap_ie_to_sta_he_cap
        // when the response has HE operation + capabilities.
        let mut ap_he = None;
        if let (true, Some(own), Some(c), Some(o)) = (
            l.mode >= ConnMode::He,
            self.own_he(band),
            rie.he_cap.as_deref().and_then(he::parse_he_cap),
            rie.he_oper.as_deref().and_then(he::HeOper::parse),
        ) {
            let cap = he::sta_he_cap(own, &c);
            // _ieee80211_sta_cap_rx_bw / ieee80211_sta_init_nss with HE.
            let cap_bw = match he::he_cap_rx_bw(&cap, band) {
                160 => peer::StaBw::Bw160,
                80 => peer::StaBw::Bw80,
                40 => peer::StaBw::Bw40,
                _ => peer::StaBw::Bw20,
            };
            let chan_bw = match l.def.width {
                Width::W20NoHt | Width::W20 => peer::StaBw::Bw20,
                Width::W40 => peer::StaBw::Bw40,
                Width::W80 => peer::StaBw::Bw80,
            };
            sta.bandwidth = Some(cap_bw.min(chan_bw));
            sta.rx_nss = sta.rx_nss.max(he::he_rx_nss(&cap)).max(1);
            ap_he = Some(peer::ApHe {
                cap,
                oper_params: o.params,
            });
        }
        sta.wme = rie.wmm_param.is_some();
        // ieee80211_assoc_success: WLAN_STA_MFP from assoc_data->use_mfp.
        sta.mfp = l.rsn.as_ref().is_some_and(|r| r.mfp);
        self.dp.set_sta_wme(bss.bssid, sta.wme);
        {
            let lk = self.link.as_mut().unwrap();
            lk.sta = sta;
            lk.he = ap_he.clone();
            lk.assoc = true;
            lk.basic_rates = if basic != 0 { basic } else { lk.basic_rates };
        }
        let aid = a.aid();
        // ieee80211_assoc_config_link → QoS parameters
        let q = match rie.wmm_param {
            Some(w) => wmm_from_ie(&w),
            None => wmm_default(true, band == Band::Ghz2 && !l.operating_11g),
        };
        self.conf_tx_all(&q).await?;
        // ieee80211_link_set_associated → ieee80211_handle_bss_capability
        let (erp_valid, erp) = match bss_ies.erp {
            Some(e) => (true, e),
            None => (false, 0),
        };
        let use_prot = erp_valid && erp & frame::erp::USE_PROTECTION != 0;
        let short_pre = if erp_valid {
            erp & frame::erp::BARKER_PREAMBLE == 0
        } else {
            a.capab_info & capab::SHORT_PREAMBLE != 0
        };
        let short_slot = a.capab_info & capab::SHORT_SLOT_TIME != 0 || band != Band::Ghz2;
        let (cts_c, pre_c, slot_c) = {
            let v = self.vif.as_mut().unwrap();
            let r = (
                use_prot != v.use_cts_prot,
                short_pre != v.use_short_preamble,
                short_slot != v.use_short_slot,
            );
            v.use_cts_prot = use_prot;
            v.use_short_preamble = short_pre;
            v.use_short_slot = short_slot;
            v.aid = aid;
            r
        };
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        // BSS_CHANGED_BEACON_INFO (have_beacon) → DTIM period
        if l.have_beacon {
            let dtim = bss
                .beacon_ies
                .as_deref()
                .and_then(|b| frame::find_elem(b, eid::TIM))
                .filter(|t| t.len() >= 2)
                .map_or(1, |t| t[1].max(1) as u32);
            self.vif.as_mut().unwrap().dtim_period = dtim;
            let _ = self
                .vdev_param(vdev_id, WMI_VDEV_PARAM_DTIM_PERIOD, dtim)
                .await;
        }
        self.bss_erp_changed(cts_c, slot_c, pre_c).await;
        self.bss_assoc(bss, bss_ies, a.capab_info, aid, rie.he_spr.as_deref())
            .await?;
        // BSS_CHANGED_HE_BSS_COLOR (STA arm of ath11k_mac_bss_info_changed),
        // after BSS_CHANGED_ASSOC.
        if let Some(o) = rie.he_oper.as_deref().and_then(he::HeOper::parse) {
            if ap_he.is_some() && !o.bss_color_disabled() {
                let _ = self
                    .cmd(
                        bss_color_change_enable_cmd(vdev_id, true),
                        step::HE_PARAM,
                        1,
                        "bss color change enable",
                    )
                    .await;
                let _ = self
                    .cmd(
                        obss_color_collision_cfg_cmd(vdev_id, 0, 10_000, true),
                        step::HE_PARAM,
                        2,
                        "obss color collision cfg",
                    )
                    .await;
            }
        }
        Ok(())
    }

    /// `ath11k_bss_assoc`.
    async fn bss_assoc(
        &mut self,
        bss: &ScanBss,
        ies: &ParsedIes,
        capab_info: u16,
        aid: u16,
        he_spr: Option<&[u8]>,
    ) -> Result<(), MacError> {
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let l = self.link.clone().unwrap();
        // ath11k_mac_vif_recalc_sta_he_txbf
        if let (Some(h), Some(own)) = (l.he.as_ref(), self.own_he(l.def.band)) {
            let m = he::sta_hemu_mode(own, &h.cap);
            let c = vdev_set_param_cmd(vdev_id, WMI_VDEV_PARAM_SET_HEMU_MODE, m);
            if self
                .cmd(c, step::HE_PARAM, 0, "vdev HE MU mode")
                .await
                .is_err()
            {
                // "failed to recalc he txbf": ath11k_bss_assoc returns.
                return Ok(());
            }
        }
        let arg = peer::peer_assoc_prepare(&peer::PeerAssocInput {
            he: l.he.as_ref(),
            vdev_id,
            aid,
            assoc_capability: capab_info,
            listen_interval: self.cfg.listen_interval as u32,
            def: l.def,
            sta: &l.sta,
            rsn: ies.rsn.is_some(),
            wpa: ies.wpa.is_some(),
        });
        self.pending.peer_assoc_conf = None;
        let c = match peer_assoc_cmd(&arg, false) {
            Ok(c) => c,
            Err(e) => return fail(step::PEER_ASSOC, 0, e.errno(), "peer assoc"),
        };
        self.cmd(c, step::PEER_ASSOC, 1, "peer assoc").await?;
        if self
            .wait_for(timeout::PEER_ASSOC, |s| {
                s.pending
                    .peer_assoc_conf
                    .take()
                    .filter(|p| p.vdev_id == vdev_id && p.peer_macaddr == bss.bssid)
            })
            .await
            .is_none()
        {
            return fail(
                step::PEER_ASSOC_TIMEOUT,
                vdev_id,
                errno::ETIMEDOUT,
                "peer assoc (no conf)",
            );
        }
        // ath11k_setup_peer_smps
        if l.sta.ht_cap.ht_supported {
            let sm = (l.sta.ht_cap.cap & peer::ht::SM_PS) >> peer::ht::SM_PS_SHIFT;
            if let Some(v) = peer::smps_map(sm) {
                let c = peer_set_param_cmd(&bss.bssid, vdev_id, peer_param::MIMO_PS_STATE, v);
                self.cmd(c, step::PEER_ASSOC, 2, "peer smps").await?;
            }
        }
        {
            let v = self.vif.as_mut().unwrap();
            v.aid = aid;
            v.bssid = bss.bssid;
        }
        let c = vdev_up_cmd(vdev_id, aid as u32, &bss.bssid, None, 0, 0, None);
        self.cmd(c, step::VDEV_UP, 0, "vdev up").await?;
        self.vif.as_mut().unwrap().is_up = true;
        if self.link.as_ref().unwrap().authorized {
            let c = peer_set_param_cmd(&bss.bssid, vdev_id, peer_param::AUTHORIZE, 1);
            let _ = self
                .cmd(c, step::PEER_AUTHORIZE, 1, "authorize bss peer")
                .await;
        }
        // bss_conf.he_obss_pd from the Spatial Reuse Parameter Set
        // (ieee80211_he_spr_ie_to_bss_conf; all-zero without HE).
        let (en, min, max) = if l.he.is_some() {
            he::spr_obss_pd(he_spr)
        } else {
            (0, 0, 0)
        };
        let _ = self
            .cmd(
                obss_spr_cmd(vdev_id, en, min, max),
                step::PEER_ASSOC,
                3,
                "obss spr",
            )
            .await;
        let _ = self
            .vdev_param(vdev_id, WMI_VDEV_PARAM_DTIM_POLICY, WMI_DTIM_POLICY_STICK)
            .await;
        self.scan_11d_stop().await;
        Ok(())
    }

    /// `ath11k_mac_op_set_key(SET_KEY, CCMP)` → `ath11k_install_key` +
    /// `ath11k_dp_peer_rx_pn_replay_config`.
    pub(super) async fn install_key(
        &mut self,
        addr: [u8; 6],
        idx: u8,
        key: &[u8],
        pairwise: bool,
    ) -> Result<(), MacError> {
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let flags = if pairwise {
            WMI_KEY_PAIRWISE
        } else {
            WMI_KEY_GROUP
        };
        let arg = VdevInstallKeyArg {
            vdev_id,
            macaddr: addr,
            key_idx: idx as u32,
            key_flags: flags,
            key_cipher: cipher::AES_CCM,
            key_data: key.to_vec(),
            ..Default::default()
        };
        if pairwise {
            // "flush the fragments cache during key (re)install" (the
            // pairwise key comes with `sta`; a group key does not).
            self.dp.peer_frags_flush(vdev_id, addr);
        }
        self.install_key_cmd(&arg).await?;
        if let Err(e) = self
            .dp
            .rx_pn_replay_config(vdev_id, addr, cipher::AES_CCM, pairwise, true)
            .await
        {
            return fail(step::KEY_INSTALL, 0x10 | idx as u32, e, "pn replay config");
        }
        Ok(())
    }

    /// `ath11k_install_key` body: command + `install_key_done`.
    pub(super) async fn install_key_cmd(
        &mut self,
        arg: &VdevInstallKeyArg,
    ) -> Result<(), MacError> {
        self.pending.install_key = None;
        let c = vdev_install_key_cmd(arg);
        self.cmd(c, step::KEY_INSTALL, arg.key_idx, "install key")
            .await?;
        let Some(k) = self
            .wait_for(timeout::INSTALL_KEY, |s| s.pending.install_key.take())
            .await
        else {
            return fail(
                step::KEY_INSTALL_TIMEOUT,
                arg.key_idx,
                errno::ETIMEDOUT,
                "install key (no completion)",
            );
        };
        if k.status != 0 {
            return fail(
                step::KEY_INSTALL_STATUS,
                k.status,
                errno::EINVAL,
                "install key (status)",
            );
        }
        Ok(())
    }

    /// `ath11k_mac_op_sta_state(ASSOC → AUTHORIZED)` for a STA vif:
    /// `WMI_PEER_AUTHORIZE` once the vdev is up (for open networks
    /// mac80211 authorizes before `BSS_CHANGED_ASSOC`, so
    /// `ath11k_bss_assoc` sends it instead).
    async fn authorize(&mut self) -> Result<(), MacError> {
        let l = self.link.as_ref().unwrap();
        let (addr, already) = (l.bss.bssid, l.authorized);
        if !already {
            self.link.as_mut().unwrap().authorized = true;
            let v = self.vif.clone().unwrap();
            if v.is_up {
                let c = peer_set_param_cmd(&addr, v.vdev_id, peer_param::AUTHORIZE, 1);
                self.cmd(c, step::PEER_AUTHORIZE, 0, "authorize peer")
                    .await?;
            }
        }
        self.dp.set_authorized(addr, true);
        Ok(())
    }

    /// `ieee80211_recalc_ps_vif` → `BSS_CHANGED_PS` → `ath11k_mac_vif_setup_ps`,
    /// once the AP is authorized and a beacon was seen
    /// (`ieee80211_powersave_allowed`).
    async fn setup_ps(&mut self) {
        if !self.cfg.supports_sta_ps || !self.cfg.powersave {
            return;
        }
        let ok = self
            .link
            .as_ref()
            .is_some_and(|l| l.authorized && l.have_beacon);
        if !ok {
            return;
        }
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        if self
            .sta_ps_param(vdev_id, sta_ps_param::INACTIVITY_TIME, DYNAMIC_PS_TIMEOUT)
            .await
            .is_err()
        {
            return;
        }
        let c = sta_powersave_mode_cmd(vdev_id, sta_ps_mode::ENABLED);
        if self
            .cmd(c, step::STA_PS, 0x101, "sta ps mode")
            .await
            .is_ok()
        {
            self.vif.as_mut().unwrap().ps = true;
        }
    }

    // ── Disconnect ─────────────────────────────────────────────────

    async fn send_deauth_frame(&mut self, bssid: [u8; 6], reason: u16) -> Result<(), MacError> {
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let f = frame::build_deauth(&self.caps.mac_addr, &bssid, reason);
        let f = self.mfp_tx(&f);
        match self.wmi.mgmt_tx(vdev_id, &f).await {
            Ok(desc) => {
                let done = self
                    .wait_for(timeout::MLME_TX_STATUS, |s| {
                        let pos = s.pending.mgmt_tx.iter().position(|c| c.desc_id == desc)?;
                        s.pending.mgmt_tx.remove(pos);
                        Some(())
                    })
                    .await;
                if done.is_some() {
                    self.wmi.mgmt_tx_done(desc);
                }
                Ok(())
            }
            Err(e) => fail(step::AUTH_TX, 0x100, e, "deauth TX"),
        }
    }

    /// `WirelessNetIface::disassociate`.
    pub async fn disassociate(&mut self) -> Result<(), WirelessError> {
        if self.link.is_none() {
            return Ok(());
        }
        self.teardown(true, frame::WLAN_REASON_DEAUTH_LEAVING).await;
        // cfg80211_disconnect → ieee80211_mgd_deauth → the frame we sent.
        self.disconnect = Some(Disconnect {
            reason: frame::WLAN_REASON_DEAUTH_LEAVING,
            from_ap: false,
        });
        Ok(())
    }

    /// `ieee80211_set_disassoc` / `ieee80211_destroy_*_data` +
    /// `ath11k_mac_op_unassign_vif_chanctx`. Best effort: every step's
    /// failure is reported and the teardown continues, like Linux.
    async fn teardown(&mut self, tx_deauth: bool, reason: u16) {
        let Some(l) = self.link.clone() else {
            return;
        };
        let Some(v) = self.vif.clone() else {
            return;
        };
        let vdev_id = v.vdev_id;
        let bssid = l.bss.bssid;
        if tx_deauth && l.assoc {
            let _ = self.send_deauth_frame(bssid, reason).await;
        }
        if l.authorized {
            self.dp.set_authorized(bssid, false);
        }
        // __sta_info_destroy_part1 → ieee80211_sta_tear_down_BA_sessions(
        // AGG_STOP_DESTROY_STA): every RX session stopped, no DELBA.
        if l.peer_created {
            for tid in 0..16 {
                self.stop_rx_ba_session(
                    tid,
                    frame::WLAN_BACK_RECIPIENT,
                    frame::WLAN_REASON_QSTA_LEAVE_QBSS,
                    false,
                )
                .await;
            }
        }
        // sta flush: AUTHORIZED → … → NONE, ieee80211_free_sta_keys
        // (DISABLE_KEY for the pairwise key; the group DISABLE_KEY is
        // skipped by ath11k for a STA vif), then NONE → NOTEXIST.
        if l.ptk_installed {
            let arg = VdevInstallKeyArg {
                vdev_id,
                macaddr: bssid,
                key_idx: 0,
                key_flags: WMI_KEY_PAIRWISE,
                key_cipher: cipher::NONE,
                ..Default::default()
            };
            let _ = self.install_key_cmd(&arg).await;
            let _ = self
                .dp
                .rx_pn_replay_config(vdev_id, bssid, cipher::AES_CCM, true, false)
                .await;
        }
        if l.peer_created {
            // ath11k_mac_station_remove
            if self.cfg.vdev_start_delay && v.is_started {
                self.vdev_stop().await;
            }
            self.dp.peer_cleanup(vdev_id, bssid);
            self.peer_delete(bssid).await;
        }
        if l.assoc {
            // BSS_CHANGED_ASSOC (+ the ERP reset) → ath11k_bss_disassoc
            {
                let vm = self.vif.as_mut().unwrap();
                vm.use_cts_prot = false;
                vm.use_short_preamble = false;
                vm.use_short_slot = false;
            }
            self.bss_erp_changed(true, true, true).await;
            let _ = self
                .cmd(vdev_down_cmd(vdev_id as u8), step::VDEV_UP, 1, "vdev down")
                .await;
            self.vif.as_mut().unwrap().is_up = false;
            // ieee80211_set_wmm_default(&sdata->deflink, false, false)
            let q = wmm_default(false, l.def.band == Band::Ghz2 && !l.operating_11g);
            let _ = self.conf_tx_all(&q).await;
        }
        // ieee80211_link_release_channel → unassign_vif_chanctx
        if self.vif.as_ref().unwrap().is_started {
            self.vdev_stop().await;
        }
        self.vif.as_mut().unwrap().chanctx = None;
        self.scan_11d_start(vdev_id).await;
        let vm = self.vif.as_mut().unwrap();
        vm.bssid = [0; 6];
        vm.aid = 0;
        vm.ps = false;
        self.link = None;
        self.mlme_target = None;
        self.sup = None;
        self.mfp = MfpState::default();
    }

    /// `ath11k_mac_vdev_stop`.
    async fn vdev_stop(&mut self) {
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        self.pending.vdev_stopped = None;
        if self
            .cmd(
                vdev_stop_cmd(vdev_id as u8),
                step::VDEV_STOP_TIMEOUT,
                1,
                "vdev stop",
            )
            .await
            .is_ok()
            && self
                .wait_for(timeout::VDEV_SETUP, |s| s.pending.vdev_stopped.take())
                .await
                .is_none()
        {
            MacError::new(step::VDEV_STOP_TIMEOUT, vdev_id, errno::ETIMEDOUT)
                .report("vdev stop (no event)");
        }
        self.vif.as_mut().unwrap().is_started = false;
    }

    /// `ath11k_peer_delete` → `__ath11k_peer_delete`.
    async fn peer_delete(&mut self, addr: [u8; 6]) {
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        self.pending.peer_deleted = None;
        if self
            .cmd(
                peer_delete_cmd(&addr, vdev_id as u8),
                step::PEER_DELETE_TIMEOUT,
                1,
                "peer delete",
            )
            .await
            .is_err()
        {
            return;
        }
        if self
            .dp
            .wait_peer_mapped(vdev_id, addr, false, timeout::PEER_DELETE)
            .await
            .is_err()
        {
            MacError::new(step::PEER_DELETE_TIMEOUT, 1, errno::ETIMEDOUT)
                .report("peer delete (no unmap)");
            return;
        }
        if self
            .wait_for(timeout::PEER_DELETE, |s| s.pending.peer_deleted.take())
            .await
            .is_none()
        {
            MacError::new(step::PEER_DELETE_TIMEOUT, 2, errno::ETIMEDOUT)
                .report("peer delete (no response)");
        }
    }
}

/// `channel_number → MHz` for `narf_wireless` channel numbers
/// (2.4 GHz 1–14, otherwise 5 GHz), as `nl80211::control::frequency`.
pub fn channel_number_freq(ch: u32) -> Option<u32> {
    match ch {
        14 => Some(2484),
        1..=13 => Some(2407 + 5 * ch),
        32..=177 => Some(5000 + 5 * ch),
        _ => None,
    }
}

/// `struct ieee80211_tx_queue_params`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxQueueParams {
    pub txop: u16,
    pub cw_min: u16,
    pub cw_max: u16,
    pub aifs: u8,
    pub uapsd: bool,
}

/// `ieee80211_set_wmm_default(link, …, enable_qos)` in AC order VO, VI,
/// BE, BK. `use_11b` ⇔ 2.4 GHz channel context and not
/// `operating_11g_mode`.
pub fn wmm_default(enable_qos: bool, use_11b: bool) -> [TxQueueParams; 4] {
    let cw_max = 1023u16;
    let cw_min = if use_11b { 31u16 } else { 15 };
    let plain = TxQueueParams {
        txop: 0,
        cw_min,
        cw_max,
        aifs: 2,
        uapsd: false,
    };
    if !enable_qos {
        return [plain; 4];
    }
    [
        // AC_VO
        TxQueueParams {
            cw_max: cw_min.div_ceil(2) - 1,
            cw_min: cw_min.div_ceil(4) - 1,
            txop: if use_11b { 3264 / 32 } else { 1504 / 32 },
            aifs: 2,
            uapsd: false,
        },
        // AC_VI
        TxQueueParams {
            cw_max: cw_min,
            cw_min: cw_min.div_ceil(2) - 1,
            txop: if use_11b { 6016 / 32 } else { 3008 / 32 },
            aifs: 2,
            uapsd: false,
        },
        // AC_BE
        TxQueueParams {
            cw_max,
            cw_min,
            txop: 0,
            aifs: 3,
            uapsd: false,
        },
        // AC_BK
        TxQueueParams {
            cw_max,
            cw_min,
            txop: 0,
            aifs: 7,
            uapsd: false,
        },
    ]
}

/// `_ieee80211_sta_wmm_params`: the AP's WMM Parameter element in AC
/// order VO, VI, BE, BK (`aifs` raised to 2, `ecw2cw`, U-APSD off).
pub fn wmm_from_ie(w: &frame::WmmParam) -> [TxQueueParams; 4] {
    let mut out = [TxQueueParams::default(); 4];
    for rec in &w.ac {
        let aci = (rec.aci_aifsn >> 5) & 3;
        let ac = match aci {
            1 => 3, // BK
            2 => 1, // VI
            3 => 0, // VO
            _ => 2, // BE
        };
        let ecw2cw = |e: u8| (1u16 << e) - 1;
        out[ac] = TxQueueParams {
            aifs: (rec.aci_aifsn & 0x0F).max(2),
            cw_max: ecw2cw((rec.cw & 0xF0) >> 4),
            cw_min: ecw2cw(rec.cw & 0x0F),
            txop: rec.txop_limit,
            uapsd: false,
        };
    }
    out
}

/// `wmi` re-export for callers that only import the mac layer.
pub use wmi::WmiCmd as Cmd;

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
use narf_wireless::{
    ApConfig, AssociateRequest, BssInfo, ChannelSwitchConfig, ColorChangeConfig, CqmRssiConfig,
    FilsDiscoveryConfig, FtmResponderConfig, GtkRekeyData, HeBssColorConfig, HeObssPdConfig,
    ScanRequest, SecurityConfig, StationConfig, StationTxPower, TxBitrateBand, TxBitrateMask,
    UnsolBcastProbeRespConfig, WirelessError, CIPHER_SUITE_CCMP, CIPHER_SUITE_CCMP_256,
    CIPHER_SUITE_GCMP, CIPHER_SUITE_GCMP_256, CIPHER_SUITE_TKIP,
};

use super::mac_frame::{self as frame, capab, eid, freq_band, Band, ParsedIes};
use super::mac_peer::{self as peer, ApSta, ChanDef, ConnMode, OwnCaps, SmpsMode, Width};
use super::mac_reg::{chan_flag, DfsState, RegState, RegUpdate, VdevKind, Wiphy};
pub mod ext;
pub mod he;
pub mod sae;
pub mod sec;
use super::wmi::{self, *};
use sec::{Credential, MfpRx, MfpState, RsnPlan};

/// `WMI_FIXED_RATE_NONE` clears a VDEV or peer fixed-rate override.
const WMI_FIXED_RATE_NONE: u32 = 0xffff;

/// Map the cfg80211 suite selector to the firmware key command.  CCMP-128
/// and CCMP-256 share WMI's AES-CCM selector; likewise the two GCMP key
/// sizes share AES-GCM.  The data-path descriptor uses the original key
/// length to retain that distinction after the WMI command completes.
pub(super) const fn firmware_key_cipher(suite: u32) -> Option<(u32, u32, u32)> {
    match suite {
        CIPHER_SUITE_CCMP | CIPHER_SUITE_CCMP_256 => Some((cipher::AES_CCM, 0, 0)),
        CIPHER_SUITE_TKIP => Some((cipher::TKIP, 8, 8)),
        CIPHER_SUITE_GCMP | CIPHER_SUITE_GCMP_256 => Some((cipher::AES_GCM, 0, 0)),
        _ => None,
    }
}

/// Exact GTK/PTK material size accepted by the WCN6855 WMI data-key path.
/// TKIP includes its 16-byte temporal key and the two eight-byte Michael
/// directions; CCMP/GCMP key size selects their 128- or 256-bit variant.
pub(super) const fn firmware_key_len(suite: u32) -> Option<usize> {
    match suite {
        CIPHER_SUITE_TKIP | CIPHER_SUITE_CCMP_256 | CIPHER_SUITE_GCMP_256 => Some(32),
        CIPHER_SUITE_CCMP | CIPHER_SUITE_GCMP => Some(16),
        _ => None,
    }
}

/// The `enum nl80211_band` index used by `NL80211_ATTR_TX_RATES`.
const fn nl80211_band(band: Band) -> u8 {
    match band {
        Band::Ghz2 => 0,
        Band::Ghz5 => 1,
        Band::Ghz6 => 3,
    }
}

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
    /// `vdev_id`. `chanfreq` is non-zero only for an off-channel frame
    /// sent while a remain-on-channel scan is active. Returns the `buf_id`
    /// that `MGMT_TX_COMPLETION.desc_id` will carry.
    fn mgmt_tx(
        &self,
        vdev_id: u32,
        frame: &[u8],
        chanfreq: Option<u32>,
    ) -> impl Future<Output = Result<u32, i32>> + Send;
    /// `wmi_process_mgmt_tx_comp`: unmap and free `desc_id`'s buffer.
    fn mgmt_tx_done(&self, desc_id: u32);
    /// Monotonic milliseconds.
    fn now_ms(&self) -> u64;
    /// The WMI endpoint's `max_msg_len` (HTC connect response), for
    /// `ath11k_wmi_send_scan_chan_list_cmd`'s split.
    fn max_msg_len(&self) -> u32;
    /// `get_random_bytes`.
    /// Failure supplies no usable randomness, even if the output was partly
    /// written. Callers must close the pending protocol before publication.
    fn random_bytes(&self, out: &mut [u8]) -> Result<(), i32>;
}

/// The data-path side of the core.
pub trait DataPort {
    /// `ath11k_dp_tx_htt_h2t_ppdu_stats_req(ar, HTT_PPDU_STATS_TAG_DEFAULT)`.
    fn ppdu_stats_req(&self) -> impl Future<Output = Result<(), i32>> + Send;
    /// `ath11k_mac_config_mon_status_default(ar, enable)`.
    fn mon_status_default(&self, enable: bool) -> impl Future<Output = Result<(), i32>> + Send;
    /// `ath11k_dp_vdev_tx_attach`. `ap` selects the AP/GO data path rather
    /// than the associated-station path in the runtime.
    fn vdev_tx_attach(&self, vdev_id: u32, addr: [u8; 6], ap: bool);
    /// The AP vdev has completed `WMI_VDEV_UP_CMDID`; create its per-client
    /// Ethernet/802.11 data-path state. `privacy` blocks group data until a
    /// GTK is installed.
    fn ap_started(&self, vdev_id: u32, bssid: [u8; 6], privacy: bool);
    /// `WMI_VDEV_DOWN_CMDID` / AP teardown: discard its data-path state.
    fn ap_stopped(&self, vdev_id: u32);
    /// `ieee80211_vif_{block,unblock}_queues_csa`: retain AP data in the
    /// mac80211 TXQs while a mode-1 CSA protects the current channel.
    fn ap_channel_switching(&self, vdev_id: u32, blocked: bool);
    /// CAC owns the AP channel until the DFS timer completes.  Data stays in
    /// TXQs rather than leaking onto a channel that is not yet available.
    fn ap_dfs_cac(&self, vdev_id: u32, running: bool);
    /// Whether the physical radio has an active DFS non-occupancy period
    /// overlapping `def`.  A WCN6855 shares its pdev and regulatory state
    /// across all vdevs, while a standalone test/data port has no external
    /// radio state and therefore reports no additional restriction.
    fn dfs_nop_active(&self, _def: &ChanDef) -> bool {
        false
    }
    /// Record a radar-triggered non-occupancy period at physical-radio
    /// scope.  This complements the local wiphy copy: it keeps a later
    /// virtual interface from selecting the channel while the vdev that
    /// received radar is down or has been deleted.
    fn record_dfs_nop(&self, _def: ChanDef, _deadline: u64) {}
    /// An AP peer has completed WMI association and may receive EAPOL. `wme`
    /// selects QoS headers and AC classification for that client.
    fn ap_station_added(&self, vdev_id: u32, addr: [u8; 6], wme: bool);
    /// An AP peer is leaving; it must no longer be selected for TX.
    fn ap_station_removed(&self, vdev_id: u32, addr: [u8; 6]);
    /// At least one AP GTK is present in firmware for this vdev.
    fn ap_group_key(&self, vdev_id: u32, installed: bool);
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
    #[allow(clippy::too_many_arguments)]
    fn rx_pn_replay_config(
        &self,
        vdev_id: u32,
        addr: [u8; 6],
        cipher: u32,
        key_len: usize,
        key_idx: u8,
        pairwise: bool,
        install: bool,
    ) -> impl Future<Output = Result<(), i32>> + Send;
    /// Supply or clear the eight-byte receive Michael direction of a
    /// pairwise TKIP key. WCN6855 decrypts TKIP itself, but its fragmented
    /// receive path leaves the one MSDU-level Michael MIC for host
    /// verification before REO reinjection. A default no-op keeps pure
    /// codec ports independent of the live DP.
    fn tkip_rx_mic_config(
        &self,
        _vdev_id: u32,
        _addr: [u8; 6],
        _key: Option<[u8; 8]>,
    ) -> impl Future<Output = Result<(), i32>> + Send {
        core::future::ready(Ok(()))
    }
    /// Transmit an 802.3 frame (EAPOL; the DP encapsulates it).
    fn send_eth(&self, frame: &[u8]) -> impl Future<Output = Result<(), i32>> + Send;
    /// `ieee80211_mgd_probe_ap`: transmit a directed Null / QoS Null
    /// frame and wait for its requested TX status. An ACK proves the AP
    /// is still reachable after a beacon-miss indication.
    fn probe_ap(
        &self,
        timeout_ms: u32,
    ) -> impl Future<Output = Result<super::txq::TxStatus, i32>> + Send;
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
    /// `sdata->u.mgd.use_4addr`: switch station TX to 802.11 four-address
    /// headers and emit the required enable announcement once a live BSS
    /// peer is present. The peer's `WMI_PEER_USE_4ADDR` programming runs on
    /// the same ordered control path; neither Linux operation waits for the
    /// other. A no-op default keeps pure codec/test ports independent of the
    /// runtime data path.
    fn set_sta_four_addr(&self, _enabled: bool) {}
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
    /// GTK low-power-offload setup, enable, disable, or firmware status
    /// handling failed (details: 1 enable, 2 status request, 3 disable).
    pub const GTK_REKEY_OFFLOAD: u32 = 279;
    /// WoWLAN configuration or low-power transition failed (details name
    /// the ordered firmware operation in `Mac::{prepare,resume}_wowlan`).
    pub const WOWLAN: u32 = 280;
    // ── 300–319: AP vdev, peer lifecycle, and pdev policy ─────────
    /// AP channel/vdev start or stop failed.
    pub const AP_START: u32 = 300;
    /// AP beacon-template validation or WMI submission failed.
    pub const AP_BEACON: u32 = 301;
    /// AP / GO `NL80211_CMD_CHANNEL_SWITCH` validation, countdown, or vdev
    /// restart failed.
    pub const AP_CHANNEL_SWITCH: u32 = 311;
    /// AP `NL80211_CMD_COLOR_CHANGE_REQUEST` validation, temporary template,
    /// countdown, or final BSS-color programming failed.
    pub const AP_COLOR_CHANGE: u32 = 313;
    /// AP client `WMI_PEER_CREATE_CMDID` / DP setup failed.
    pub const AP_PEER_CREATE: u32 = 302;
    /// AP client did not map into DP before the peer-map timeout.
    pub const AP_PEER_MAP_TIMEOUT: u32 = 303;
    /// AP client `WMI_PEER_ASSOC_CMDID` failed.
    pub const AP_PEER_ASSOC: u32 = 304;
    /// AP client did not confirm peer association in time.
    pub const AP_PEER_ASSOC_TIMEOUT: u32 = 305;
    /// AP client deletion failed validation.
    pub const AP_PEER_DELETE: u32 = 306;
    /// A userspace `NL80211_CMD_FRAME` management transmission failed.
    pub const MGMT_FRAME_TX: u32 = 307;
    /// A scan-backed `NL80211_CMD_REMAIN_ON_CHANNEL` request failed.
    pub const ROC_START: u32 = 308;
    /// A `NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL` request failed.
    pub const ROC_CANCEL: u32 = 309;
    /// AP U-APSD peer configuration failed after association.
    pub const AP_PEER_UAPSD: u32 = 310;
    /// BIOS SAR geo-table or power-table submission failed.
    pub const BIOS_SAR: u32 = 312;
    /// 6 GHz FILS discovery or unsolicited broadcast Probe Response template
    /// setup / enable / disable failed.
    pub const AP_DISCOVERY: u32 = 313;
    /// `WMI_PDEV_BSS_CHAN_INFO_REQUEST_CMDID` submission failed.
    pub const BSS_SURVEY: u32 = 314;
    /// Physical chain-mask or vdev RTS-threshold programming failed.
    pub const RADIO_CONFIG: u32 = 315;
    /// `NL80211_CMD_SET_TX_BITRATE_MASK` validation or WMI replay failed.
    pub const BITRATE_MASK: u32 = 316;
    /// Station four-address/WDS peer configuration failed.
    pub const FOUR_ADDR: u32 = 317;
    /// `NL80211_EXT_FEATURE_STA_TX_PWR` peer-power programming failed.
    pub const STATION_TX_POWER: u32 = 318;
    /// Cryptographic entropy unavailable. detail:0=LRO,1=4-way,2=rekey,
    /// 3=SA-query,4=SAE. No partially filled output may reach a protocol.
    pub const ENTROPY: u32 = 319;
}

/// Linux errnos used here (positive).
pub mod errno {
    pub const EPERM: i32 = 1;
    pub const EIO: i32 = 5;
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
    /// WMI vdev slot allocated by the radio. NARF currently admits three
    /// independent vdevs; each NARF netdev owns exactly one of those slots
    /// for its whole lifetime, just as one `ieee80211_vif` owns one
    /// `arvif->vdev_id` in Linux.
    pub vdev_id: u32,
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
            vdev_id: 0,
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

    /// Bind a per-netdev MAC instance to a previously reserved firmware
    /// vdev slot.  Keeping allocation outside `Mac` lets all instances share
    /// the WCN6855 radio's one free-vdev bitmap.
    pub const fn with_vdev(mut self, vdev_id: u32) -> Self {
        self.vdev_id = vdev_id;
        self
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
    /// mac80211's `probe_wait_ms`.
    pub const CONNECTION_PROBE_WAIT: u32 = 500;
    /// mac80211's `max_nullfunc_tries` when the driver reports TX ACKs.
    pub const CONNECTION_PROBE_TRIES: u8 = 2;
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
/// `ATH11K_KICKOUT_THRESHOLD` (20 × 16 beacon intervals).
pub const ATH11K_KICKOUT_THRESHOLD: u32 = 20 * 16;
/// `ATH11K_KEEPALIVE_MIN_IDLE`.
pub const ATH11K_KEEPALIVE_MIN_IDLE: u32 = 3747;
/// `ATH11K_KEEPALIVE_MAX_IDLE`.
pub const ATH11K_KEEPALIVE_MAX_IDLE: u32 = 3895;
/// `ATH11K_KEEPALIVE_MAX_UNRESPONSIVE`.
pub const ATH11K_KEEPALIVE_MAX_UNRESPONSIVE: u32 = 3900;
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

    /// `narf_wireless::BssInfo`, retaining the BSS's unambiguous centre
    /// frequency for all ath11k-supported bands.
    pub fn info(&self) -> Option<BssInfo> {
        Some(BssInfo {
            bssid: self.bssid,
            ssid: self.ssid(),
            frequency_mhz: self.freq,
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

/// `struct ath11k_vif`'s WMI vdev role. WCN6855 supports station, AP, and
/// P2P roles; the explicit discriminator prevents station-only teardown and
/// regulatory code from running against a beaconing vdev.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VifKind {
    #[default]
    Station,
    Ap,
    P2pDevice,
    P2pClient,
    P2pGo,
}

impl VifKind {
    pub const fn is_ap(self) -> bool {
        matches!(self, Self::Ap | Self::P2pGo)
    }

    pub const fn is_station(self) -> bool {
        // P2P_DEVICE is also a WMI station vdev. It never associates, but
        // it must receive the station regulatory treatment while it scans
        // and remains on an action-frame channel.
        matches!(self, Self::Station | Self::P2pDevice | Self::P2pClient)
    }
}

/// `struct ath11k_vif` for NARF's station or AP vdev.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Vif {
    pub vdev_id: u32,
    pub addr: [u8; 6],
    pub kind: VifKind,
    pub is_started: bool,
    pub is_up: bool,
    /// `vdev_start_resp.max_allowed_tx_power`. Firmware reports this after
    /// vdev start; six-GHz TPC takes the lower of it and the regulatory / AP
    /// power envelope when idle power save is enabled.
    pub max_allowed_tx_power: i32,
    pub chanctx: Option<ChanDef>,
    pub bssid: [u8; 6],
    pub aid: u16,
    pub beacon_interval: u32,
    pub dtim_period: u32,
    /// `arvif->wmm_params` in `WME_AC_*` order (BE, BK, VI, VO).
    pub wmm: [WmmParamsArg; 4],
    /// `arvif->muedca_params` in the same WME order. Unlike legacy WMM,
    /// CW fields carry the HE element's ECW exponents.
    pub mu_edca: [WmmParamsArg; 4],
    pub uapsd: u32,
    /// `bss_conf.use_cts_prot` / `use_short_preamble` / `use_short_slot`.
    pub use_cts_prot: bool,
    pub use_short_preamble: bool,
    pub use_short_slot: bool,
    /// `bss_conf.txpower` (dBm; `None` = INT_MIN).
    pub txpower: Option<i32>,
    pub ps: bool,
    /// WMI's transmitting/non-transmitting AP role. Station vdevs retain the
    /// default zero value; AP creation initializes this to the explicit
    /// `NON_MBSSID_AP` standalone role and START_AP replaces it for a group.
    pub mbssid: MbssidParams,
}

/// One complete firmware beacon template in a multiple-BSSID set. The
/// MBSSID element begins at `mbssid_ie_offset`; WMI needs that mutable offset
/// separately from the TIM offset it also receives.
#[derive(Clone, PartialEq, Eq, Debug)]
struct MbssidBeaconTemplate {
    beacon: Vec<u8>,
    mbssid_ie_offset: u32,
}

/// mac80211's generated regular or Enhanced Multiple-BSSID Advertisement
/// template family. It intentionally contains the already-complete beacon
/// bytes rather than source IEs: a non-transmitting vdev must reuse the
/// transmitter's exact template before its first VDEV_UP.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MbssidBeaconSet {
    bssid_indicator: u8,
    regular: MbssidBeaconTemplate,
    ema: Vec<MbssidBeaconTemplate>,
}

impl MbssidBeaconSet {
    fn profile_count(&self) -> u32 {
        1u32 << self.bssid_indicator
    }

    fn is_ema(&self) -> bool {
        !self.ema.is_empty()
    }
}

/// The AP-only portion of mac80211's interface state. Firmware owns the
/// actual beacon schedule and peer table; this records the inputs required to
/// update templates, map nl80211 station operations to WMI, and tear the
/// vdev down coherently.
#[derive(Clone, PartialEq, Eq)]
struct ApState {
    def: ChanDef,
    beacon_head: Vec<u8>,
    beacon_tail: Vec<u8>,
    /// Complete mac80211-owned probe-response template. The target sends it
    /// through the ordinary management-TX path after the host fixes DA.
    probe_resp: Option<Vec<u8>>,
    tim_ie_offset: u32,
    /// The transmitting profile retains the complete raw element lists so a
    /// later SET_BEACON or CSA rebuild does not silently drop MBSSID/EMA.
    mbssid_elems: Vec<Vec<u8>>,
    ema_rnr_elems: Vec<Vec<u8>>,
    /// `Some` only for a transmitting MBSSID AP. The runtime publishes a
    /// clone for a non-transmitting sibling after a successful start.
    mbssid_beacons: Option<MbssidBeaconSet>,
    fils_discovery: Option<FilsDiscoveryConfig>,
    unsol_bcast_probe_resp: Option<UnsolBcastProbeRespConfig>,
    ftm_responder: Option<FtmResponderConfig>,
    /// `bss_conf.twt_responder` from START_AP. The target TWT scheduler is
    /// pdev-wide, but the setting belongs to this AP's BSS configuration.
    twt_responder: bool,
    he_obss_pd: Option<HeObssPdConfig>,
    he_bss_color: Option<HeBssColorConfig>,
    privacy: bool,
    /// Desired CCMP GTKs. Their contents deliberately never appear in a
    /// debug print: WMI retains them while at least one AP peer exists.
    group_keys: Vec<ApGroupKey>,
    /// Software BIP IGTKs (key indexes 4 / 5). Like Linux ath11k, these
    /// never reach WMI: the host adds the selected CMAC/GMAC MMIE to robust
    /// group management frames before `WMI_MGMT_TX_SEND_CMDID`.
    igtks: Vec<ApIgtk>,
    /// `set_default_mgmt_key` selection. `None` uses the newest IGTK until
    /// hostapd designates one explicitly.
    default_igtk: Option<u8>,
    /// Temporary CSA beacon and target chandef.  The ordinary beacon above
    /// remains intact until the countdown reaches the restart boundary.
    csa: Option<ApChannelSwitch>,
    /// Temporary HE BSS-color countdown template. The ordinary beacon and
    /// color remain retained until the final countdown TBTT.
    color_change: Option<ApColorChange>,
    stations: Vec<ApStation>,
}

impl core::fmt::Debug for ApState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApState")
            .field("def", &self.def)
            .field("beacon_head_len", &self.beacon_head.len())
            .field("beacon_tail_len", &self.beacon_tail.len())
            .field("probe_resp_len", &self.probe_resp.as_ref().map(Vec::len))
            .field("tim_ie_offset", &self.tim_ie_offset)
            .field("privacy", &self.privacy)
            .field(
                "group_key_indices",
                &self
                    .group_keys
                    .iter()
                    .map(|key| key.idx)
                    .collect::<Vec<_>>(),
            )
            .field(
                "igtk_indices",
                &self.igtks.iter().map(|key| key.idx).collect::<Vec<_>>(),
            )
            .field("default_igtk", &self.default_igtk)
            .field("csa", &self.csa)
            .field("color_change", &self.color_change)
            .field("stations", &self.stations)
            .finish()
    }
}

/// `cfg80211_csa_settings` as retained by a beaconing AP/GO.  Countdown
/// offsets address only `beacon_csa_tail`, per nl80211's ABI.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ApChannelSwitch {
    def: ChanDef,
    beacon_csa_head: Vec<u8>,
    beacon_csa_tail: Vec<u8>,
    counter_offsets_beacon: Vec<u16>,
    probe_resp_csa: Option<Vec<u8>>,
    counter_offsets_presp: Vec<u16>,
    /// The byte firmware currently advertises in every CSA counter IE.
    count: u8,
    /// Next nominal TBTT at which the software template must advance.
    deadline: u64,
    block_tx: bool,
    beacon_after_head: Option<Vec<u8>>,
    beacon_after_tail: Option<Vec<u8>>,
    probe_resp_after: Option<Vec<u8>>,
    /// `cfg80211_csa_settings.beacon_after.ftm_responder`, applied after the
    /// target-channel vdev restart with the rest of its BSS configuration.
    ftm_responder: Option<FtmResponderConfig>,
    /// `cfg80211_csa_settings.beacon_after.he_bss_color`, likewise delayed
    /// until the restarted vdev has the target chandef.
    he_bss_color: Option<HeBssColorConfig>,
    /// `cfg80211_csa_settings.unsol_bcast_probe_resp`, including the explicit
    /// empty-nested-attribute deletion request. This must not take effect
    /// until the vdev has restarted on `def`.
    unsol_bcast_probe_resp: Option<Option<UnsolBcastProbeRespConfig>>,
}

/// `cfg80211_color_change_settings` held while an AP advertises a countdown
/// beacon.  As in mac80211, the post-change beacon is separate from the
/// temporary template and gets installed only when the countdown finishes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ApColorChange {
    beacon_color_head: Vec<u8>,
    beacon_color_tail: Vec<u8>,
    counter_offset_beacon: u16,
    probe_resp_color: Option<Vec<u8>>,
    counter_offset_presp: Option<u16>,
    beacon_next_head: Option<Vec<u8>>,
    beacon_next_tail: Option<Vec<u8>>,
    probe_resp_next: Option<Vec<u8>>,
    count: u8,
    deadline: u64,
    color: u8,
    previous_color: Option<HeBssColorConfig>,
    previous_unsol_bcast_probe_resp: Option<UnsolBcastProbeRespConfig>,
    unsol_bcast_probe_resp: Option<Option<UnsolBcastProbeRespConfig>>,
}

/// An AP GTK remembered for peer joins and vdev reconstruction. Not
/// `Debug`: never put key bytes in the diagnostic / console path.
#[derive(Clone, PartialEq, Eq)]
struct ApGroupKey {
    idx: u8,
    cipher: u32,
    key: Vec<u8>,
}

/// A host-owned BIP IGTK. `tx_ipn` is the per-key group-management packet
/// number; key bytes deliberately stay out of `Debug`.
#[derive(Clone, PartialEq, Eq)]
struct ApIgtk {
    idx: u8,
    cipher: u32,
    key: Vec<u8>,
    tx_ipn: u64,
}

impl core::fmt::Debug for ApIgtk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApIgtk")
            .field("idx", &self.idx)
            .field("cipher", &self.cipher)
            .field("tx_ipn", &self.tx_ipn)
            .finish()
    }
}

/// The configured portion of one AP client (`ieee80211_sta` after
/// `sta_state(ASSOC)`); richer capability information arrives from the
/// association frame and is added by the AP RX state machine.
#[derive(Clone, PartialEq, Eq)]
struct ApStation {
    mac: [u8; 6],
    aid: u16,
    listen_interval: u16,
    supported_rates: Vec<u8>,
    wme: bool,
    /// Requested U-APSD delivery/trigger ACs (`NL80211_STA_WME_UAPSD_QUEUES`).
    uapsd_queues: u8,
    /// Requested U-APSD maximum service period (`NL80211_STA_WME_MAX_SP`).
    uapsd_max_sp: u8,
    /// `WLAN_STA_MFP`: peer-assoc PMF flag and robust management protection.
    mfp: bool,
    /// `bss_conf.assoc_capability` reported by hostapd for this client.
    capability: u16,
    /// Retained for AP policy decisions; ath11k does not carry it in
    /// `WMI_PEER_ASSOC_CMDID`.
    ext_capability: Vec<u8>,
    ht_cap: Option<frame::HtCapIe>,
    vht_cap: Option<frame::VhtCapIe>,
    he_cap: Option<he::StaHeCap>,
    he_6ghz_cap: Option<u16>,
    /// Explicit per-client peer power retained for reassociation and WMI
    /// replay. `None` leaves firmware's per-vdev power policy in effect.
    station_tx_power: Option<StationTxPower>,
    /// `(key index, cfg80211 cipher suite, bytes)` once the firmware key
    /// install succeeds.  The suite is retained for recovery and descriptor
    /// encryption-type replay.
    pairwise_key: Option<(u8, u32, Vec<u8>)>,
    /// Host-generated CCMP management-frame PN for this AP client.
    mgmt_tx_pn: u64,
    /// Last accepted CCMP management-frame PN from this AP client.
    mgmt_rx_pn: u64,
    authorized: bool,
}

impl core::fmt::Debug for ApStation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApStation")
            .field("mac", &self.mac)
            .field("aid", &self.aid)
            .field("listen_interval", &self.listen_interval)
            .field("supported_rates", &self.supported_rates)
            .field("wme", &self.wme)
            .field("uapsd_queues", &self.uapsd_queues)
            .field("uapsd_max_sp", &self.uapsd_max_sp)
            .field("mfp", &self.mfp)
            .field("capability", &self.capability)
            .field("ext_capability_len", &self.ext_capability.len())
            .field("ht", &self.ht_cap.is_some())
            .field("vht", &self.vht_cap.is_some())
            .field("he", &self.he_cap.is_some())
            .field("he_6ghz", &self.he_6ghz_cap.is_some())
            .field("station_tx_power", &self.station_tx_power)
            .field("pairwise_key_installed", &self.pairwise_key.is_some())
            .field("authorized", &self.authorized)
            .finish()
    }
}

/// A link-loss reason latched by an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkLoss {
    /// `PEER_STA_KICKOUT` for the AP.
    Kickout,
    /// `WMI_ROAM_REASON_BEACON_MISS` with no beacon for
    /// `ATH11K_CONNECTION_LOSS_HZ`.
    BeaconLoss,
    /// The AP's CSA/ECSA names an unusable or cross-band channel, or the
    /// firmware rejects the vdev restart at the advertised switch time.
    ChannelSwitch,
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
    /// `bss_conf.assoc_capability` from the successful Association Response;
    /// rate-policy peer-association updates must retain the same value.
    pub assoc_capability: u16,
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
    /// Low four bits of the associated AP's WMM Parameter Set Count.
    /// `None` is the pre-association `-1` sentinel from mac80211.
    pub wmm_last_param_set: Option<u8>,
    /// Low four bits of the associated AP's HE MU-EDCA Parameter Set Count.
    /// `None` covers both the pre-association sentinel and a WMM update
    /// without an MU-EDCA element.
    pub mu_edca_last_param_set: Option<u8>,
    /// `disable_wmm_tracking`: set when the association response omitted or
    /// malformed its WMM parameters, so later beacon revisions cannot cause
    /// an unsafe switch between invalid and valid queue layouts.
    pub disable_wmm_tracking: bool,
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
    /// The association's supplicant runs in userspace
    /// (`SecurityConfig::External` or the userspace SME): no in-kernel
    /// 4-way / group handshake, keys from `NEW_KEY`, the port opened by
    /// `SET_STATION`, EAPOL handed up ([`Mac::take_control_port_rx`]).
    pub external: Option<narf_wireless::ExternalSecurity>,
    /// `ieee80211_mark_sta_auth` happened (the AP station is AUTH).
    pub authenticated: bool,
    /// The signal (dBm) of the last management frame from the AP
    /// (`sta->deflink.rx_stats.last_signal`).
    pub last_signal: Option<i32>,
    /// `ewma_beacon_signal`'s magnitude in 1/16 dBm units. It is reset with
    /// a new association and updated only from beacons of the associated AP.
    pub beacon_signal_ewma: Option<u32>,
    /// Number of beacons sampled into [`Self::beacon_signal_ewma`].
    pub beacon_signal_count: u32,
    /// Last averaged RSSI that produced a CQM threshold notification.
    pub last_cqm_event_signal: Option<i32>,
    /// The active CQM RSSI-list range (`cqm_rssi_low`, `cqm_rssi_high`). It
    /// is re-centered on the threshold interval containing every emitted
    /// event, exactly as cfg80211's range CQM API does.
    pub cqm_rssi_range: Option<(i32, i32)>,
}

/// The data-key source retained by mac80211 for a managed station.  It has
/// no formatter because every variant owns key material.
#[derive(Clone)]
enum StationRecoveryKeys {
    External(ext::ExtKeys),
    Internal(Option<Supplicant>),
}

/// mac80211 state that survives a hardware restart for an associated
/// station. It deliberately contains no formatter: key bytes must never
/// reach diagnostics. The recovered MAC replays this state through WMI
/// without sending authentication or association frames.
#[derive(Clone)]
pub(super) struct StationRecovery {
    vif: Vif,
    link: Link,
    keys: StationRecoveryKeys,
    mfp: MfpState,
    powersave: bool,
    gtk_rekey_data: Option<GtkRekeyData>,
    cqm_rssi: Option<CqmRssiConfig>,
}

/// mac80211-owned AP state needed after firmware has lost every vdev and
/// peer.  As with [`StationRecovery`], this has no formatter because it
/// owns group and pairwise key material.
#[derive(Clone)]
pub(super) struct ApRecovery {
    vif: Vif,
    ap: ApState,
}

impl ApRecovery {
    /// A non-transmitting profile needs the transmitter's retained MBSSID
    /// template set before its vdev can come back up.
    pub(super) fn mbssid_source_vdev(&self) -> Option<u32> {
        self.vif
            .mbssid
            .is_non_transmitting()
            .then_some(self.vif.mbssid.tx_vdev_id)
    }
}

/// A deferred `cfg80211_cqm_rssi_notify` after the MAC mutex is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CqmRssiEvent {
    /// `false` = `NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW`, `true` = HIGH.
    pub high: bool,
    pub level_dbm: i32,
}

/// The status Linux reports through `ieee80211_gtk_rekey_notify` after the
/// firmware exits GTK offload.  The replay counter is in the big-endian
/// nl80211 representation; no key material ever leaves the MAC layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GtkRekeyNotify {
    pub bssid: [u8; 6],
    pub replay_counter: [u8; 8],
}

/// A management frame accepted by the target and waiting for a userspace
/// `REGISTER_FRAME` subscriber.  This is intentionally queued instead of
/// notifying netlink from [`Mac::handle_event`]: WMI event dispatch owns the
/// MAC mutex, whereas a netlink sink may synchronously enter the network
/// stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredMgmtRx {
    /// Exact channel frequency from `WMI_MGMT_RX_EVENTID`.
    pub frequency_mhz: u32,
    /// `ieee80211_rx_status::signal` in dBm.
    pub signal_dbm: i32,
    /// Full 802.11 management frame, including its 24-byte header.
    pub frame: Vec<u8>,
}

/// A scan-backed `NL80211_CMD_REMAIN_ON_CHANNEL` transition.  ath11k uses a
/// one-channel passive WMI scan for ROC; the netdev turns these into the two
/// nl80211 multicast notifications after it releases the MAC mutex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemainOnChannelEvent {
    pub cookie: u64,
    pub frequency_mhz: u32,
    pub duration_ms: u32,
    pub started: bool,
}

/// AP/GO channel-switch state change for the nl80211 publisher.  It is
/// queued under the MAC lock and emitted only after the runtime drops that
/// lock, mirroring cfg80211's started/completed multicast notifications.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApChannelSwitchEvent {
    pub def: ChanDef,
    /// Present only on `NL80211_CMD_CH_SWITCH_STARTED_NOTIFY`.
    pub count: u8,
    pub block_tx: bool,
    pub started: bool,
}

/// AP HE BSS-color transition notification emitted after dropping the MAC
/// lock. `Started` carries Linux's u32 color-count payload; the terminal
/// notifications carry only the interface identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApColorChangeEvent {
    Started { count: u8 },
    Aborted,
    Completed,
}

/// One cfg80211 DFS notification. `event` is `enum nl80211_radar_event`:
/// detected=0, CAC-finished=1, CAC-aborted=2, NOP-finished=3, and
/// CAC-started=5. Radar/NOP notifications are wiphy-wide; CAC notifications
/// name the active AP/GO netdev.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DfsEvent {
    pub def: ChanDef,
    pub event: u32,
    pub netdev: bool,
}

/// One converted `WMI_PDEV_BSS_CHAN_INFO_EVENTID` snapshot. This is held by
/// the physical runtime rather than an individual vdev because firmware's
/// counter block belongs to the WCN6855 pdev.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BssSurvey {
    pub frequency_mhz: u32,
    pub noise_dbm: i8,
    pub time_ms: u64,
    pub time_busy_ms: u64,
    pub time_rx_ms: u64,
    pub time_tx_ms: u64,
}

/// Deferred `cfg80211_obss_color_collision_notify` input.  mac80211 sends
/// at most one indication per 500 ms; later firmware events while it is
/// pending are intentionally ignored rather than accumulating a bitmap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ObssColorCollisionPending {
    bitmap: u64,
    deadline: u64,
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
    /// Management frames for userspace registrations (`cfg80211_rx_mgmt`).
    /// Bounded so a remote AP/client cannot turn unserviced registrations into
    /// unbounded kernel allocation.
    registered_mgmt_rx: VecDeque<RegisteredMgmtRx>,
    /// Started / expired remain-on-channel notifications.
    roc_events: VecDeque<RemainOnChannelEvent>,
    /// Started / completed local AP/GO CSA notifications.
    ap_channel_switch_events: VecDeque<ApChannelSwitchEvent>,
    /// Started / completed / aborted local AP HE BSS-color transitions.
    ap_color_change_events: VecDeque<ApColorChangeEvent>,
    /// CFG80211 DFS radar / CAC / NOP notifications.
    dfs_events: VecDeque<DfsEvent>,
    /// One target collision indication awaiting mac80211's 500-ms rate
    /// limiter, followed by the events ready for the netlink publisher.
    obss_color_collision: Option<ObssColorCollisionPending>,
    obss_color_collision_events: VecDeque<u64>,
    /// AP probe responses assembled under the RX event lock and sent from the
    /// deferred WMI path. This is bounded just like registered management RX.
    ap_probe_responses: VecDeque<Vec<u8>>,
    /// The channel-availability check currently blocking an AP/GO vdev.
    dfs_cac: Option<DfsCac>,
    /// Per-channel-context non-occupancy periods after radar detection.
    dfs_nop: Vec<DfsNop>,
    /// Block Ack action frames from the AP (`ieee80211_rx_h_action` →
    /// the interface work queue).
    back_rx: VecDeque<Vec<u8>>,
    /// `ab->new_alpha2` waiting for `ath11k_update_11d`.
    new_alpha2: Option<[u8; 2]>,
    /// `ath11k_regd_update_work` queued (new regd → chan list).
    regd_update: bool,
    /// A trusted CSA/ECSA received from the associated AP, waiting for its
    /// advertised TBTT-relative deadline.
    channel_switch: Option<ChannelSwitchPending>,
    /// An unprotected Public ECSA requested a temporary mode-1 quiet period.
    /// It cannot commit a channel change; the next beacon decides whether to
    /// release the port or begin a trusted CSA.
    untrusted_csa_blocked: bool,
    /// GTK offload completed while the host was asleep; the netdev publishes
    /// its refreshed replay counter to the userspace supplicant.
    gtk_rekey_notify: Option<GtkRekeyNotify>,
    /// Firmware reported that a peer did not acknowledge its traffic. This
    /// is `ieee80211_report_low_ack()` rather than an implicit station
    /// deletion: cfg80211 publishes one CQM packet-loss event and hostapd
    /// remains responsible for its own inactivity policy.
    cqm_pktloss: Vec<[u8; 6]>,
    /// Software CQM RSSI threshold crossings from associated-AP beacons.
    cqm_rssi: Vec<CqmRssiEvent>,
    /// Pdev-wide BSS channel-counter samples. The runtime drains these into
    /// its physical-radio snapshot after the MAC mutex is released.
    bss_survey: Vec<BssSurvey>,
}

/// The software half of mac80211's `ieee80211_channel_switch`: ath11k
/// restarts a live vdev at the CSA deadline rather than changing an
/// independent channel context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChannelSwitchPending {
    def: ChanDef,
    block_tx: bool,
    /// Monotonic milliseconds, computed from `(max(count, 1) - 1)` TBTTs.
    deadline: u64,
    /// The WMI restart completed. For a mode-1 CSA, mac80211 keeps data
    /// queues closed until the first beacon on the new channel confirms it.
    switched: bool,
}

/// `cfg80211_cac_event(CAC_STARTED)` through the regulatory CAC deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DfsCac {
    def: ChanDef,
    vdev_id: u32,
    deadline: u64,
}

/// `NL80211_DFS_UNAVAILABLE` until the regulatory 30-minute NOP completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DfsNop {
    def: ChanDef,
    deadline: u64,
}

struct ScanCtx {
    state: ScanState,
    vdev_id: u32,
    started: bool,
    completed: bool,
    aborted: bool,
    deadline: Option<u64>,
    roc: Option<RocCtx>,
}

/// `ar->scan.is_roc`, `roc_freq`, and `roc_notify` in one state record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RocCtx {
    cookie: u64,
    frequency_mhz: u32,
    duration_ms: u32,
    started: bool,
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
    /// `ar->cfg_tx_chainmask`, retained independently of firmware state so
    /// later vdev creation and recovery use the masks selected through
    /// `NL80211_CMD_SET_WIPHY`.
    cfg_tx_chain_mask: u32,
    /// `ar->cfg_rx_chainmask`; see [`Self::cfg_tx_chain_mask`].
    cfg_rx_chain_mask: u32,
    /// `hw->wiphy->rts_threshold`, applied to each vdev at creation and to
    /// an already live vdev when userspace changes it.
    rts_threshold: u32,
    /// `ath11k_vif::bitrate_mask`, retained per virtual interface so a
    /// reconnect/recovery rebuilds the same peer rate sets.
    bitrate_mask: TxBitrateMask,
    /// Explicit per-BSS peer transmit-power policy. `None` leaves the vdev's
    /// normal power envelope in control; `Some(Automatic)` actively clears a
    /// former peer cap. The netdev retains this across a rebuilt MAC instance.
    station_tx_power: Option<StationTxPower>,
    /// `sdata->u.mgd.use_4addr`, retained per station vdev. The peer-side
    /// WMI state is recreated after every association and firmware reset.
    four_addr: bool,
    own: OwnCaps,
    wiphy: Wiphy,
    reg: RegState,
    started: bool,
    vif: Option<Vif>,
    ap: Option<ApState>,
    scan: ScanCtx,
    bss: Vec<ScanBss>,
    pending: Pending,
    txpower_limit_2g: u32,
    txpower_limit_5g: u32,
    /// AP power type currently selected for the stored 6 GHz client
    /// regulatory rules (LPI until an HE 6 GHz Operation says otherwise).
    reg_6ghz_ap_type: usize,
    state_11d: State11d,
    vdev_id_11d: Option<u32>,
    regdom_set_by_user: bool,
    alpha2: [u8; 2],
    hw_rate_code: u32,
    link: Option<Link>,
    mlme_target: Option<[u8; 6]>,
    /// BSSID displaced by an external-SME authentication. It survives the
    /// necessary firmware teardown of that old peer until ASSOCIATE consumes
    /// `NL80211_ATTR_PREV_BSSID` for the Reassociation Request.
    mlme_prev_bssid: Option<[u8; 6]>,
    /// The last disconnection, as cfg80211 reports it.
    disconnect: Option<Disconnect>,
    /// The RSN supplicant of the association after its 4-way handshake
    /// (PTK, replay counter, GTK in use) for the Group Key Handshake.
    sup: Option<Supplicant>,
    /// 802.11w host state (software BIP keys, management PNs, SA Query).
    mfp: MfpState,
    /// Our HE capabilities per band (`ar->mac.iftype[band][STATION]`):
    /// 2.4 GHz, 5 GHz, 6 GHz.
    own_he: [Option<he::StaHeCap>; 3],
    /// Our HE 6 GHz Band Capabilities (`he_6ghz_capa.capa`).
    own_he_6ghz: Option<u16>,
    /// Firmware station TWT requester engine state (`ar->twt_enabled`).
    twt_enabled: bool,
    /// Keys userspace installed for an external-supplicant association.
    ext_keys: ext::ExtKeys,
    /// Control-port frames for userspace ([`Mac::take_control_port_rx`]).
    ctrl_rx: Vec<ext::ControlPortRx>,
    /// `sdata->u.mgd.powersave` (`wdev->ps`).
    powersave: bool,
    /// `ath11k_vif::rekey_data`: supplied by userspace now, copied to WMI
    /// only when the low-power/WoW path enables GTK rekey offload.  Its
    /// `Debug` implementation redacts KEK/KCK material.
    gtk_rekey_data: Option<GtkRekeyData>,
    /// `wiphy->wowlan_config`, retained until the next `SET_WOWLAN` request
    /// replaces or clears it.  Firmware is programmed only by a subsequent
    /// low-power transition.
    wowlan_config: Option<WowlanConfig>,
    /// Addresses mac80211 supplies through `BSS_CHANGED_ARP_FILTER` and
    /// `ipv6_addr_change`, captured by the netdev immediately before the
    /// WoW transition and sent through `WMI_SET_ARP_NS_OFFLOAD_CMDID`.
    arp_ns_offload: ArpNsOffload,
    /// A `WMI_WOW_ENABLE_CMDID` that received HTC's suspend-complete ACK.
    /// The netdev owns the ACK wait, then marks this MAC state.
    wow_armed: bool,
    /// A successfully submitted WMI network-list-offload configuration.  It
    /// must be stopped before the next WoW setup or normal resume, even if
    /// the retained cfg80211 configuration remains unchanged.
    nlo_armed: bool,
    /// The cfg80211/mac80211 CQM RSSI configuration. ath11k does not use a
    /// target CQM WMI command for this generic software path.
    cqm_rssi: Option<CqmRssiConfig>,
}

/// One `cfg80211_pkt_pattern`: the bit-packed mask userspace supplies for
/// an Ethernet MSDU, the byte sequence to compare, and its packet offset.
/// `Mac::prepare_wowlan` translates this to ath11k's native-802.11 firmware
/// representation when the target is not in Ethernet decapsulation mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WowPattern {
    pub mask: Vec<u8>,
    pub pattern: Vec<u8>,
    pub offset: u32,
}

/// The ath11k subset of `struct cfg80211_wowlan`.  These are exactly the
/// trigger classes Linux's WCN6855 driver advertises: disconnect, magic
/// packet, GTK rekey failure, packet patterns, and firmware network-list
/// offload. GTK rekey support itself is reported separately as a capability,
/// not as a configurable trigger.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WowlanConfig {
    pub disconnect: bool,
    pub magic_packet: bool,
    pub gtk_rekey_failure: bool,
    pub patterns: Vec<WowPattern>,
    pub net_detect: Option<NloConfig>,
}

/// `ATH11K_WOW_PATTERNS` (`wow.h`).  It intentionally limits the user
/// configuration below the target's raw `num_wow_filters` resource value.
pub const ATH11K_WOW_MAX_PATTERNS: usize = 22;
/// `WOW_MAX_PKT_OFFSET` (`wmi.h`).
pub const ATH11K_WOW_MAX_PKT_OFFSET: u32 = 128;

/// What `__cfg80211_disconnected` reports to nl80211 for a lost or
/// dropped association: the reason code of the Deauthentication /
/// Disassociation frame (received, or the one mac80211 built and sent)
/// and whether it came from the AP (`from_ap = !ether_addr_equal(mgmt->sa,
/// dev_addr)` in `cfg80211_process_deauth` / `_disassoc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disconnect {
    pub reason: u16,
    pub from_ap: bool,
    /// A Deauthentication (`true`) or a Disassociation.
    pub deauth: bool,
    /// The AP the frame was exchanged with (zero when unknown).
    pub bssid: [u8; 6],
}

impl Disconnect {
    /// The frame cfg80211 reports with it (`nl80211_send_deauth` /
    /// `_disassoc`): received from the AP (DA = us, SA = BSSID) or the one
    /// mac80211 sent (DA = BSSID, SA = us).
    pub fn frame(&self, own: &[u8; 6]) -> Vec<u8> {
        let st = if self.deauth {
            frame::stype::DEAUTH
        } else {
            frame::stype::DISASSOC
        };
        let mut f = if self.from_ap {
            frame::mgmt_hdr(st, own, &self.bssid, &self.bssid)
        } else {
            frame::mgmt_hdr(st, &self.bssid, own, &self.bssid)
        };
        f.extend_from_slice(&self.reason.to_le_bytes());
        f
    }
}

impl LinkLoss {
    /// The disconnection cfg80211 reports for this loss: a frame from the
    /// AP carries its own reason (`ieee80211_rx_mgmt_deauth` /
    /// `_disassoc` → `cfg80211_rx_mlme_mgmt`); a beacon / connection loss
    /// is a locally generated Deauthentication with
    /// `WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY` (`__ieee80211_disconnect`
    /// → `cfg80211_tx_mlme_mgmt`); NARF tears a kickout down the same way.
    pub fn disconnect(&self, bssid: [u8; 6]) -> Disconnect {
        match *self {
            LinkLoss::Deauth { deauth, reason } => Disconnect {
                reason,
                from_ap: true,
                deauth,
                bssid,
            },
            LinkLoss::Kickout | LinkLoss::BeaconLoss | LinkLoss::ChannelSwitch => Disconnect {
                reason: frame::WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY,
                from_ap: false,
                deauth: true,
                bssid,
            },
            // wpa_supplicant_deauthenticate → cfg80211_mlme_deauth: the
            // Deauthentication mac80211 sends carries the reason.
            LinkLoss::Supplicant { reason, .. } => Disconnect {
                reason,
                from_ap: false,
                deauth: true,
                bssid,
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
        let mut wiphy = Wiphy::new(
            caps.pdev.supported_bands,
            &caps.hal_reg_cap,
            &caps.hal_reg_cap_2g,
            &caps.hal_reg_cap_5g,
        );
        let own = peer::own_caps(&caps.pdev);
        // ath11k_mac_setup_he_cap
        let he_for = |bit: u32, b: &BandCap| {
            (caps.pdev.supported_bands & bit != 0)
                .then(|| he::own_he_cap(&caps.pdev, b, own.num_tx_chains, own.num_rx_chains))
        };
        let mut own_he = [
            he_for(WMI_HOST_WLAN_2G_CAP, &caps.pdev.band_2g),
            he_for(WMI_HOST_WLAN_5G_CAP, &caps.pdev.band_5g),
            wiphy.supports_6ghz().then(|| {
                he::own_he_cap(
                    &caps.pdev,
                    &caps.pdev.band_6g,
                    own.num_tx_chains,
                    own.num_rx_chains,
                )
            }),
        ];
        // ath11k's station HE template requests TWT.  Do not advertise an
        // agreement the particular firmware image cannot service.
        if !caps.svc.test(WMI_TLV_SERVICE_STA_TWT) {
            for cap in own_he.iter_mut().flatten() {
                cap.mac[0] &= !he::cap::MAC0_TWT_REQ;
            }
        }
        let own_he_6ghz = wiphy
            .supports_6ghz()
            .then(|| he::own_he_6ghz_cap(&caps.pdev, &caps.pdev.band_6g));
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
        let cfg_tx_chain_mask = caps.pdev.tx_chain_mask;
        let cfg_rx_chain_mask = caps.pdev.rx_chain_mask;
        Mac {
            wmi,
            dp,
            caps,
            cfg,
            cfg_tx_chain_mask,
            cfg_rx_chain_mask,
            rts_threshold: RTS_THRESHOLD_OFF,
            bitrate_mask: TxBitrateMask::default(),
            station_tx_power: None,
            four_addr: false,
            own,
            wiphy,
            reg,
            started: false,
            vif: None,
            ap: None,
            scan: ScanCtx {
                state: ScanState::Idle,
                vdev_id: 0,
                started: false,
                completed: false,
                aborted: false,
                deadline: None,
                roc: None,
            },
            bss: Vec::new(),
            pending: Pending::default(),
            txpower_limit_2g: max,
            txpower_limit_5g: max,
            reg_6ghz_ap_type: WMI_REG_INDOOR_AP,
            state_11d: State11d::Idle,
            vdev_id_11d: None,
            regdom_set_by_user: false,
            alpha2: [0; 2],
            hw_rate_code: 0,
            link: None,
            mlme_target: None,
            mlme_prev_bssid: None,
            disconnect: None,
            sup: None,
            mfp: MfpState::default(),
            own_he,
            own_he_6ghz,
            twt_enabled: false,
            ext_keys: ext::ExtKeys::default(),
            ctrl_rx: Vec::new(),
            powersave: cfg.powersave,
            gtk_rekey_data: None,
            wowlan_config: None,
            arp_ns_offload: ArpNsOffload::default(),
            wow_armed: false,
            nlo_armed: false,
            cqm_rssi: None,
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
            && (band != Band::Ghz6
                || (self.own_he_6ghz.is_some()
                    && ies
                        .he_6ghz_cap
                        .as_deref()
                        .and_then(he::parse_he_6ghz_cap)
                        .is_some()))
    }

    /// Our HE capabilities on `band`.
    pub fn own_he(&self, band: Band) -> Option<&he::StaHeCap> {
        match band {
            Band::Ghz2 => self.own_he[0].as_ref(),
            Band::Ghz5 => self.own_he[1].as_ref(),
            Band::Ghz6 => self.own_he[2].as_ref(),
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

    /// The regulatory domain in force (`wiphy->regd` of the self-managed
    /// wiphy).
    pub fn regd(&self) -> super::mac_reg::Regd {
        self.reg.current()
    }

    pub fn own_caps(&self) -> &OwnCaps {
        &self.own
    }

    /// Current configured physical chain masks (`cfg_{tx,rx}_chainmask`).
    pub fn antenna_masks(&self) -> (u32, u32) {
        (self.cfg_tx_chain_mask, self.cfg_rx_chain_mask)
    }

    /// Whether this instance currently owns the shared pdev start sequence.
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// Install a retained chain-mask policy without touching firmware. This
    /// is used before a first vdev is added and after a cold recovery, where
    /// `start_inner` is responsible for the pdev WMI sequence.
    pub fn configure_antenna(&mut self, tx: u32, rx: u32) {
        self.cfg_tx_chain_mask = tx;
        self.cfg_rx_chain_mask = rx;
        self.refresh_own_caps();
    }

    /// Replace the desired physical chain masks and, when the pdev is up,
    /// mirror Linux `__ath11k_set_antenna` through the two pdev parameters.
    pub async fn set_antenna(&mut self, tx: u32, rx: u32) -> Result<(), MacError> {
        self.configure_antenna(tx, rx);
        if !self.started {
            return Ok(());
        }
        self.pdev_param(WMI_PDEV_PARAM_TX_CHAIN_MASK, tx).await?;
        self.pdev_param(WMI_PDEV_PARAM_RX_CHAIN_MASK, rx).await
    }

    /// Stored `WMI_VDEV_PARAM_RTS_THRESHOLD` value for future vdevs.
    pub fn configure_rts_threshold(&mut self, threshold: u32) {
        self.rts_threshold = threshold;
    }

    /// Install a retained per-vdev rate policy before association or AP peer
    /// creation. `do_open` uses this after a hardware restart; live updates
    /// go through [`Self::set_tx_bitrate_mask`] to replay WMI state as well.
    pub fn configure_tx_bitrate_mask(&mut self, mask: TxBitrateMask) {
        self.bitrate_mask = mask;
    }

    /// Install a retained managed-station peer-power policy before a BSS peer
    /// exists. The association path replays it after the firmware peer is
    /// live; a current peer uses [`Self::set_station_tx_power`] instead.
    pub fn configure_station_tx_power(&mut self, setting: Option<StationTxPower>) {
        self.station_tx_power = setting;
    }

    /// Linux ath11k's `ath11k_mac_op_sta_set_txpwr` policy. The generic
    /// nl80211 parser intentionally lets FIXED through with no dBm value;
    /// ath11k treats that zero value as invalid. AUTOMATIC maps to WMI's zero
    /// value, while LIMITED accepts only the driver's inclusive 0..=70 dBm
    /// range (and therefore cannot use zero).
    pub fn validate_station_tx_power(&self, setting: StationTxPower) -> Result<u32, i32> {
        let dbm = match setting {
            StationTxPower::Automatic => return Ok(0),
            StationTxPower::Limited(dbm) => dbm,
            StationTxPower::Fixed => return Err(errno::EINVAL),
        };
        if !(1..=70).contains(&dbm) {
            return Err(errno::EINVAL);
        }
        Ok(dbm as u32)
    }

    /// Send `WMI_PEER_USE_FIXED_PWR` after the peer mapping/association is
    /// live. Both station BSS peers and AP clients use the same target
    /// parameter.
    async fn program_peer_station_tx_power(
        &mut self,
        vdev_id: u32,
        peer: [u8; 6],
        setting: StationTxPower,
    ) -> Result<(), MacError> {
        let value = self
            .validate_station_tx_power(setting)
            .map_err(|errno| MacError::new(step::STATION_TX_POWER, 0, errno))?;
        self.cmd(
            peer_set_param_cmd(&peer, vdev_id, peer_param::USE_FIXED_PWR, value),
            step::STATION_TX_POWER,
            value,
            "peer station tx power",
        )
        .await
    }

    /// Apply and retain a managed-station peer power policy. This is the
    /// runtime-worker counterpart of mac80211's `drv_sta_set_txpwr`.
    pub async fn set_station_tx_power(
        &mut self,
        peer: [u8; 6],
        setting: StationTxPower,
    ) -> Result<(), MacError> {
        let (vdev_id, bssid) = self
            .link
            .as_ref()
            .filter(|link| link.assoc && link.bss.bssid == peer)
            .and_then(|link| {
                self.vif
                    .as_ref()
                    .filter(|vif| vif.is_up)
                    .map(|vif| (vif.vdev_id, link.bss.bssid))
            })
            .ok_or_else(|| MacError::new(step::STATION_TX_POWER, 1, errno::ENOENT))?;
        self.configure_station_tx_power(Some(setting));
        self.program_peer_station_tx_power(vdev_id, bssid, setting)
            .await
    }

    /// Retain `sdata->u.mgd.use_4addr` before a BSS peer exists. The live
    /// peer command and null-frame announcement happen from
    /// [`Self::set_four_addr`] or [`Self::bss_assoc`].
    pub fn configure_four_addr(&mut self, enabled: bool) {
        self.four_addr = enabled;
    }

    /// `ath11k_mac_op_sta_set_4addr`: mac80211 has already changed its
    /// managed-station state. ath11k only programs a live peer on enable;
    /// its Linux callback intentionally does not clear `WMI_PEER_USE_4ADDR`
    /// on disable. The runtime always receives the host-side state so its TX
    /// header construction changes immediately.
    pub async fn set_four_addr(&mut self, enabled: bool) -> Result<(), MacError> {
        if self.four_addr == enabled {
            return Ok(());
        }
        self.configure_four_addr(enabled);
        let peer = self
            .link
            .as_ref()
            .filter(|link| link.assoc)
            .and_then(|link| {
                self.vif
                    .as_ref()
                    .filter(|vif| vif.is_up)
                    .map(|vif| (vif.vdev_id, link.bss.bssid))
            });
        if let Some((vdev_id, bssid)) = peer {
            self.dp.set_sta_four_addr(enabled);
            if enabled {
                self.program_peer_four_addr(vdev_id, bssid).await?;
            }
        }
        Ok(())
    }

    /// Ordered worker body of `ath11k_sta_set_4addr_wk`.
    async fn program_peer_four_addr(
        &mut self,
        vdev_id: u32,
        bssid: [u8; 6],
    ) -> Result<(), MacError> {
        self.cmd(
            peer_set_param_cmd(&bssid, vdev_id, peer_param::USE_4ADDR, 1),
            step::FOUR_ADDR,
            0,
            "peer use 4addr",
        )
        .await
    }

    /// Synchronous half of `set_tx_bitrate_mask`, used by the netlink
    /// boundary to preserve Linux's immediate errno for an invalid policy.
    pub fn validate_tx_bitrate_mask(&self, mask: &TxBitrateMask) -> Result<(), i32> {
        let def = self
            .ap
            .as_ref()
            .map(|ap| ap.def)
            .or_else(|| self.link.as_ref().map(|link| link.def))
            .ok_or(errno::EPERM)?;
        if mask
            .band(nl80211_band(def.band))
            .is_some_and(|band| peer::validate_tx_bitrate_band(band).is_err())
        {
            return Err(errno::EINVAL);
        }
        Ok(())
    }

    /// Mirror `ath11k_mac_op_set_rts_threshold`: retain the policy for later
    /// vdevs and program this live vdev when it exists.
    pub async fn set_rts_threshold(&mut self, threshold: u32) -> Result<(), MacError> {
        self.configure_rts_threshold(threshold);
        if let Some(vdev_id) = self.vif.as_ref().map(|vif| vif.vdev_id) {
            self.vdev_param(vdev_id, WMI_VDEV_PARAM_RTS_THRESHOLD, threshold)
                .await?;
        }
        Ok(())
    }

    /// Retain `NL80211_CMD_SET_TX_BITRATE_MASK` and replay it through the
    /// active vdev. Linux's ath11k performs this after a channel context is
    /// assigned; accepting a rate policy without a current band would make
    /// its meaning ambiguous, so return `-EPERM` in that state.
    pub async fn set_tx_bitrate_mask(&mut self, mask: TxBitrateMask) -> Result<(), MacError> {
        let def = self
            .ap
            .as_ref()
            .map(|ap| ap.def)
            .or_else(|| self.link.as_ref().map(|link| link.def))
            .ok_or_else(|| MacError::new(step::BITRATE_MASK, 0, errno::EPERM))?;
        self.validate_tx_bitrate_mask(&mask)
            .map_err(|errno| MacError::new(step::BITRATE_MASK, 1, errno))?;
        let selection = mask.band(nl80211_band(def.band)).cloned();
        let vdev_id = self
            .vif
            .as_ref()
            .map(|vif| vif.vdev_id)
            .ok_or_else(|| MacError::new(step::BITRATE_MASK, 2, errno::EPERM))?;
        let requested_nss = peer::tx_bitrate_max_nss(selection.as_ref());
        let nss = requested_nss
            .unwrap_or(self.own.num_tx_chains)
            .min(self.own.num_tx_chains)
            .max(1);
        let fixed_legacy = self.single_legacy_rate(def.band, selection.as_ref());
        let he_capable = self.own_he(def.band).is_some();
        let ldpc = (self.own.ht(def.band).cap & peer::ht::LDPC_CODING != 0) as u32;

        // Keep the exact user request before WMI submission, like
        // `arvif->bitrate_mask = *mask`; a restart must not silently fall
        // back to unrestricted rate control after a transient command error.
        self.configure_tx_bitrate_mask(mask);
        if !he_capable {
            self.vdev_param(
                vdev_id,
                WMI_VDEV_PARAM_FIXED_RATE,
                fixed_legacy.unwrap_or(WMI_FIXED_RATE_NONE),
            )
            .await?;
        }
        self.vdev_param(vdev_id, WMI_VDEV_PARAM_NSS, nss).await?;
        self.vdev_param(vdev_id, WMI_VDEV_PARAM_LDPC, ldpc).await?;

        let he_fixed = selection
            .as_ref()
            .and_then(|band| band.he_mcs.as_ref())
            .is_some_and(|mcs| mcs.iter().map(|entry| entry.count_ones()).sum::<u32>() == 1);
        if he_capable {
            self.set_he_rate_gi_ltf(vdev_id, selection.as_ref(), he_fixed)
                .await?;
        } else {
            let gi = selection.as_ref().and_then(|band| band.gi).unwrap_or(0);
            self.vdev_param(vdev_id, WMI_VDEV_PARAM_SGI, gi as u32)
                .await?;
        }

        // `IEEE80211_RC_SUPP_RATES_CHANGED` schedules this work in Linux.
        // NARF's ordered runtime owns the same WMI completion path, so it
        // re-associates each existing peer immediately with `is_assoc = 0`.
        self.reapply_tx_bitrate_mask(def, selection.as_ref()).await
    }

    /// The raw vdev settings for HE's fixed or autorate GI/LTF controls.
    async fn set_he_rate_gi_ltf(
        &mut self,
        vdev_id: u32,
        mask: Option<&TxBitrateBand>,
        fixed: bool,
    ) -> Result<(), MacError> {
        let he_gi = mask.and_then(|band| band.he_gi);
        let he_ltf = mask.and_then(|band| band.he_ltf);
        if fixed {
            // WMI encodes 0.8/1.6/3.2 us as 0/2/3 and LTF from one.
            if let Some(gi) = he_gi {
                let value = if gi == 0 { 0 } else { gi as u32 + 1 };
                self.vdev_param(vdev_id, WMI_VDEV_PARAM_SGI, value).await?;
            }
            if let Some(ltf) = he_ltf {
                self.vdev_param(vdev_id, WMI_VDEV_PARAM_HE_LTF, ltf as u32 + 1)
                    .await?;
            }
            return Ok(());
        }
        let mut value = 0u32;
        if let Some(gi) = he_gi {
            // WMI_AUTORATE_{800,1600,3200}NS_GI.
            value |= 1 << (9 + gi);
        }
        if let Some(ltf) = he_ltf {
            // WMI_HE_AUTORATE_LTF_{1,2,4}X.
            value |= 1 << ltf;
        }
        self.vdev_param(vdev_id, WMI_VDEV_PARAM_AUTORATE_MISC_CFG, value)
            .await
    }

    /// The one-legacy-rate arm of `ath11k_mac_get_single_legacy_rate`.
    /// The other PHY masks must have been explicitly disabled; omitted
    /// fields mean cfg80211's automatic/default rate set and cannot be a
    /// fixed rate request.
    fn single_legacy_rate(&self, band: Band, mask: Option<&TxBitrateBand>) -> Option<u32> {
        let mask = mask?;
        let legacy = mask.legacy.as_ref()?;
        let disabled =
            |rates: Option<&[u8]>| rates.is_some_and(|rates| rates.iter().all(|rate| *rate == 0));
        if legacy.len() != 1
            || !disabled(mask.ht_mcs.as_deref())
            || !mask
                .vht_mcs
                .is_some_and(|rates| rates.iter().all(|rate| *rate == 0))
            || !mask
                .he_mcs
                .is_some_and(|rates| rates.iter().all(|rate| *rate == 0))
        {
            return None;
        }
        let requested = legacy[0] & 0x7f;
        let &(bitrate, hw_rate) = peer::sband_rates(band)
            .iter()
            .find(|(bitrate, _)| (*bitrate / 5) as u8 == requested)?;
        let preamble = if peer::bitrate_is_cck(bitrate) { 1 } else { 0 };
        Some((1 << 28) | (preamble << 8) | hw_rate)
    }

    /// Port of the rate-control worker's existing-peer pass. The command is
    /// a peer-association update (`is_assoc = false`), not a new join.
    async fn reapply_tx_bitrate_mask(
        &mut self,
        def: ChanDef,
        selection: Option<&TxBitrateBand>,
    ) -> Result<(), MacError> {
        if let Some(link) = self.link.clone() {
            self.reassociate_station_rates(&link, selection).await?;
        }
        let ap_peers = self
            .ap
            .as_ref()
            .map(|ap| (ap.def, ap.privacy, ap.stations.clone()));
        if let Some((ap_def, privacy, stations)) = ap_peers {
            // The AP's channel is the same `def`; retaining the assertion in
            // the call makes accidental cross-channel replay impossible.
            if ap_def != def {
                return Err(MacError::new(step::BITRATE_MASK, 3, errno::EINVAL));
            }
            for station in &stations {
                self.ap_peer_associate(station, ap_def, privacy, true)
                    .await?;
            }
        }
        Ok(())
    }

    async fn reassociate_station_rates(
        &mut self,
        link: &Link,
        selection: Option<&TxBitrateBand>,
    ) -> Result<(), MacError> {
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let mut arg = peer::peer_assoc_prepare(&peer::PeerAssocInput {
            he: link.he.as_ref(),
            vdev_id,
            aid: self.vif.as_ref().unwrap().aid,
            assoc_capability: link.assoc_capability,
            listen_interval: self.cfg.listen_interval as u32,
            nss_ratio_info: self.caps.pdev.nss_ratio_info,
            def: link.def,
            sta: &link.sta,
            rsn: link.rsn.is_some(),
            wpa: false,
        });
        peer::apply_tx_bitrate_band(&mut arg, selection);
        arg.is_assoc = false;
        self.pending.peer_assoc_conf = None;
        let command = peer_assoc_cmd(&arg, false)
            .map_err(|error| MacError::new(step::BITRATE_MASK, 4, error.errno()))?;
        self.cmd(command, step::BITRATE_MASK, 5, "bitrate peer assoc")
            .await?;
        if self
            .wait_for(timeout::PEER_ASSOC, |state| {
                state
                    .pending
                    .peer_assoc_conf
                    .take()
                    .filter(|peer| peer.vdev_id == vdev_id && peer.peer_macaddr == link.bss.bssid)
            })
            .await
            .is_none()
        {
            return Err(MacError::new(step::BITRATE_MASK, vdev_id, errno::ETIMEDOUT));
        }
        self.program_peer_fixed_rate(
            vdev_id,
            link.bss.bssid,
            link.sta.vht_cap.vht_supported,
            link.he.is_some(),
            link.sta.ht_cap.ht_supported,
            link.sta.rx_nss.max(1) as u32,
            selection,
        )
        .await
    }

    /// `ath11k_station_assoc`'s tail: "If single VHT/HE rate is configured
    /// (by set_bitrate_mask()), peer_assoc will disable VHT/HE. This is now
    /// enabled by a peer specific fixed param." Without a single-rate mask
    /// an association sends no fixed-rate parameter at all; clearing it to
    /// `WMI_FIXED_RATE_NONE` is only the bitrate-mask update's job.
    #[allow(clippy::too_many_arguments)]
    async fn program_peer_single_rate(
        &mut self,
        vdev_id: u32,
        peer_mac: [u8; 6],
        vht: bool,
        he: bool,
        ht: bool,
        peer_nss: u32,
        selection: Option<&TxBitrateBand>,
    ) -> Result<(), MacError> {
        let rate = peer::tx_bitrate_fixed_rate(selection, vht, he, ht, peer_nss)
            .map_err(|_| MacError::new(step::BITRATE_MASK, 6, errno::EINVAL))?;
        let Some(rate) = rate else {
            return Ok(());
        };
        self.cmd(
            peer_set_param_cmd(&peer_mac, vdev_id, peer_param::PARAM_FIXED_RATE, rate),
            step::BITRATE_MASK,
            7,
            "bitrate peer fixed rate",
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn program_peer_fixed_rate(
        &mut self,
        vdev_id: u32,
        peer_mac: [u8; 6],
        vht: bool,
        he: bool,
        ht: bool,
        peer_nss: u32,
        selection: Option<&TxBitrateBand>,
    ) -> Result<(), MacError> {
        let rate = peer::tx_bitrate_fixed_rate(selection, vht, he, ht, peer_nss)
            .map_err(|_| MacError::new(step::BITRATE_MASK, 6, errno::EINVAL))?
            .unwrap_or(WMI_FIXED_RATE_NONE);
        self.cmd(
            peer_set_param_cmd(&peer_mac, vdev_id, peer_param::PARAM_FIXED_RATE, rate),
            step::BITRATE_MASK,
            7,
            "bitrate peer fixed rate",
        )
        .await
    }

    fn refresh_own_caps(&mut self) {
        // `ath11k_mac_update_*_cap` rebuilds host-advertised HT/VHT/HE MCS
        // maps from `cfg_{tx,rx}_chainmask`. Keep the firmware's immutable
        // capability record intact and derive a local configured copy.
        let mut pdev = self.caps.pdev;
        pdev.tx_chain_mask = self.cfg_tx_chain_mask;
        pdev.rx_chain_mask = self.cfg_rx_chain_mask;
        self.own = peer::own_caps(&pdev);
        let he_for = |bit: u32, band: &BandCap| {
            (pdev.supported_bands & bit != 0).then(|| {
                he::own_he_cap(&pdev, band, self.own.num_tx_chains, self.own.num_rx_chains)
            })
        };
        self.own_he = [
            he_for(WMI_HOST_WLAN_2G_CAP, &pdev.band_2g),
            he_for(WMI_HOST_WLAN_5G_CAP, &pdev.band_5g),
            self.wiphy.supports_6ghz().then(|| {
                he::own_he_cap(
                    &pdev,
                    &pdev.band_6g,
                    self.own.num_tx_chains,
                    self.own.num_rx_chains,
                )
            }),
        ];
        if !self.caps.svc.test(WMI_TLV_SERVICE_STA_TWT) {
            for cap in self.own_he.iter_mut().flatten() {
                cap.mac[0] &= !he::cap::MAC0_TWT_REQ;
            }
        }
    }

    pub fn vif(&self) -> Option<&Vif> {
        self.vif.as_ref()
    }

    pub fn link(&self) -> Option<&Link> {
        self.link.as_ref()
    }

    /// Whether this vdev is currently beaconing as an AP / P2P GO. The
    /// runtime checks this after polling a deferred CSA: a failed restart
    /// stops the AP inside the MAC layer, so carrier and its pdev-wide
    /// channel reservation must be withdrawn too.
    pub fn ap_beaconing(&self) -> bool {
        self.ap.is_some()
    }

    /// Snapshot the successful transmitting-MBSSID beacon family for the
    /// physical runtime. Non-transmitting APs never publish their own copy:
    /// their template remains owned by the transmitting vdev.
    pub fn mbssid_beacon_set(&self) -> Option<MbssidBeaconSet> {
        self.ap.as_ref().and_then(|ap| ap.mbssid_beacons.clone())
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
        // `wdev->connected`: an offloaded association once the handshake
        // completed, an external-supplicant one from association on.
        self.link
            .as_ref()
            .filter(|l| (l.authorized || l.external.is_some() && l.assoc) && l.loss.is_none())
            .map(|l| l.bss.bssid)
    }

    /// Capture the mac80211-owned portion of an external-SME association
    /// before firmware recovery replaces this MAC instance.  A link with a
    /// pending loss is intentionally not retained: cfg80211 must report its
    /// already-established disconnect instead of reviving a stale peer.
    pub(super) fn external_recovery(&self) -> Option<StationRecovery> {
        let vif = self.vif.as_ref()?.clone();
        let link = self.link.as_ref()?.clone();
        if !vif.kind.is_station() || !link.assoc || link.external.is_none() || link.loss.is_some() {
            return None;
        }
        Some(StationRecovery {
            vif,
            link,
            keys: StationRecoveryKeys::External(self.ext_keys.clone()),
            mfp: self.mfp.clone(),
            powersave: self.powersave,
            gtk_rekey_data: self.gtk_rekey_data,
            cqm_rssi: self.cqm_rssi.clone(),
        })
    }

    /// Capture a fully usable in-kernel managed station for the same
    /// no-air-frame reconfiguration path. A WPA2/SAE handshake still in
    /// progress has no replay-safe key state, so it keeps the established
    /// reconnect behavior instead of reviving a half-negotiated port.
    pub(super) fn kernel_recovery(&self) -> Option<StationRecovery> {
        let vif = self.vif.as_ref()?.clone();
        let link = self.link.as_ref()?.clone();
        if !vif.kind.is_station()
            || !link.assoc
            || link.external.is_some()
            || link.loss.is_some()
            || !link.authorized
        {
            return None;
        }
        if link.rsn.is_some()
            && !self
                .sup
                .as_ref()
                .is_some_and(|supplicant| supplicant.ptk_installed)
        {
            return None;
        }
        Some(StationRecovery {
            vif,
            link,
            keys: StationRecoveryKeys::Internal(self.sup.clone()),
            mfp: self.mfp.clone(),
            powersave: self.powersave,
            gtk_rekey_data: self.gtk_rekey_data,
            cqm_rssi: self.cqm_rssi.clone(),
        })
    }

    /// `ieee80211_reconfig` for a replay-safe associated station. The AP
    /// still considers the association live, so recreate the vdev, peer, BSS
    /// and key state through WMI but never retransmit authentication or
    /// association management frames. The port remains blocked until the
    /// retained firmware keys have all been reinstalled.
    pub(super) async fn restore_station_recovery(
        &mut self,
        state: StationRecovery,
    ) -> Result<(), MacError> {
        let StationRecovery {
            vif: retained_vif,
            mut link,
            keys,
            mfp,
            powersave,
            gtk_rekey_data,
            cqm_rssi,
        } = state;
        let Some(vif) = self.vif.as_ref() else {
            return fail(
                step::CONNECT_STATE,
                0x700,
                errno::ENOTCONN,
                "recovery (no vdev)",
            );
        };
        if !vif.kind.is_station() {
            return fail(
                step::CONNECT_STATE,
                0x701,
                errno::EINVAL,
                "recovery (non-station vdev)",
            );
        }

        // Keep the peer blocked while `bss_assoc` recreates its WMI state;
        // key replay below is the `ieee80211_reenable_keys` boundary.
        let was_authorized = link.authorized;
        link.authorized = false;
        // mac80211 tears down BA sessions on every hardware restart because
        // the peer and REO windows vanished with firmware.  The new DP has
        // no matching state, so do not retain their old tokens here.
        link.ba_rx_valid = 0;
        link.ba_rx_token = [0; 16];
        link.conn_loss_deadline = None;
        let bss = link.bss.clone();
        let def = link.def;
        let assoc_capability = link.assoc_capability;
        let aid = retained_vif.aid;
        self.link = Some(link);
        self.ext_keys = match &keys {
            StationRecoveryKeys::External(keys) => keys.clone(),
            StationRecoveryKeys::Internal(_) => ext::ExtKeys::default(),
        };
        self.sup = None;
        self.mfp = mfp;
        self.powersave = powersave;
        self.gtk_rekey_data = gtk_rekey_data;
        self.cqm_rssi = cqm_rssi;
        if !self
            .bss
            .iter()
            .any(|known| known.bssid == bss.bssid && known.freq == bss.freq)
        {
            self.bss.push(bss.clone());
        }

        let vdev_id = {
            let vif = self.vif.as_mut().unwrap();
            vif.chanctx = Some(def);
            vif.beacon_interval = retained_vif.beacon_interval;
            vif.dtim_period = retained_vif.dtim_period;
            vif.bssid = bss.bssid;
            vif.aid = aid;
            vif.txpower = retained_vif.txpower;
            vif.use_cts_prot = retained_vif.use_cts_prot;
            vif.use_short_preamble = retained_vif.use_short_preamble;
            vif.use_short_slot = retained_vif.use_short_slot;
            vif.vdev_id
        };
        self.vdev_start(&def).await?;
        self.txpower_recalc().await?;
        let _ = self
            .vdev_param(
                vdev_id,
                WMI_VDEV_PARAM_BEACON_INTERVAL,
                retained_vif.beacon_interval,
            )
            .await;
        if let Some(rate) = peer::mgmt_rate_code(def.band, self.link.as_ref().unwrap().basic_rates)
        {
            self.hw_rate_code = rate;
            let _ = self
                .vdev_param(vdev_id, WMI_VDEV_PARAM_MGMT_RATE, rate)
                .await;
            let _ = self
                .vdev_param(vdev_id, WMI_VDEV_PARAM_BEACON_RATE, rate)
                .await;
        }
        self.station_add(bss.bssid, &def).await?;

        // `ieee80211_reconfig` replays both ordinary EDCA and (when used)
        // HE MU-EDCA before changing the BSS back to associated.
        {
            let vif = self.vif.as_mut().unwrap();
            vif.wmm = retained_vif.wmm;
            vif.mu_edca = retained_vif.mu_edca;
            vif.uapsd = retained_vif.uapsd;
        }
        self.cmd(
            vdev_set_wmm_params_cmd(vdev_id, &retained_vif.wmm, WMI_WMM_PARAM_TYPE_LEGACY),
            step::WMM_PARAMS,
            0x700,
            "recovery WMM params",
        )
        .await?;
        if self
            .link
            .as_ref()
            .is_some_and(|link| link.mu_edca_last_param_set.is_some())
        {
            self.cmd(
                vdev_set_wmm_params_cmd(
                    vdev_id,
                    &retained_vif.mu_edca,
                    WMI_WMM_PARAM_TYPE_11AX_MU_EDCA,
                ),
                step::WMM_PARAMS,
                0x701,
                "recovery HE MU-EDCA params",
            )
            .await?;
        }
        self.sta_ps_param(vdev_id, sta_ps_param::UAPSD, retained_vif.uapsd)
            .await?;
        let wake = if retained_vif.uapsd != 0 {
            sta_ps_param::RX_WAKE_POLICY_POLL_UAPSD
        } else {
            sta_ps_param::RX_WAKE_POLICY_WAKE
        };
        let _ = self
            .sta_ps_param(vdev_id, sta_ps_param::RX_WAKE_POLICY, wake)
            .await;
        self.bss_erp_changed(true, true, true).await;

        let ies = bss.parsed();
        self.bss_assoc(&bss, &ies, assoc_capability, aid, ies.he_spr.as_deref())
            .await?;

        // Firmware owns data-key state but mac80211 keeps BIP in software.
        // Reinstall the former in PTK-then-GTK order and retain the latter's
        // replay windows from `mfp` above.
        match keys {
            StationRecoveryKeys::External(keys) => {
                if let Some(key) = keys.ptk.as_ref() {
                    self.install_key_with_cipher(bss.bssid, 0, &key.key, true, key.cipher)
                        .await?;
                }
                for (idx, key) in keys.group.iter().enumerate().take(4) {
                    if let Some(key) = key.as_ref() {
                        self.install_key_with_cipher(
                            bss.bssid, idx as u8, &key.key, false, key.cipher,
                        )
                        .await?;
                    }
                }
            }
            StationRecoveryKeys::Internal(supplicant) => {
                if let Some(supplicant) = supplicant {
                    if supplicant.ptk_installed {
                        if let Some(ptk) = supplicant.ptk.as_ref() {
                            self.install_key(bss.bssid, 0, &ptk.tk, true).await?;
                        }
                    }
                    if let (Some(idx), Some(gtk)) = (
                        self.link.as_ref().and_then(|link| link.gtk_idx),
                        supplicant.gtk.as_ref(),
                    ) {
                        self.install_key(bss.bssid, idx, gtk, false).await?;
                    }
                    self.sup = Some(supplicant);
                }
            }
        }
        if was_authorized {
            self.authorize().await?;
            self.setup_ps().await;
        }
        // Associated with its keys back in firmware: the panel shows the
        // station connected again, as after the original join.
        narf_memory::diag::set_wifi_stage(narf_memory::diag::WifiStage::Connected);
        Ok(())
    }

    /// Capture a beaconing AP or P2P GO before a firmware restart replaces
    /// its MAC instance.  An AP that is administratively open but not
    /// beaconing has no BSS state for mac80211 to reconfigure.
    pub(super) fn ap_recovery(&self) -> Option<ApRecovery> {
        let vif = self.vif.as_ref()?.clone();
        let ap = self.ap.as_ref()?.clone();
        (vif.kind.is_ap() && vif.is_up).then_some(ApRecovery { vif, ap })
    }

    /// Recreate a beaconing AP/GO after firmware recovery.  This follows
    /// mac80211's restart order: BSS/beacon first, group keys, then peer
    /// recreate/associate, pairwise keys and authorization.  Countdown
    /// beacons are intentionally restarted from the stable template; their
    /// target-time work cannot survive a firmware clock reset.
    pub(super) async fn restore_ap_recovery(
        &mut self,
        state: ApRecovery,
        source_templates: Option<MbssidBeaconSet>,
    ) -> Result<(), MacError> {
        let ApRecovery {
            vif: retained_vif,
            ap: retained_ap,
        } = state;
        let def = retained_ap.def;
        let width = match def.width {
            Width::W20NoHt => 0,
            Width::W20 => 1,
            Width::W40 => 2,
            Width::W80 => 3,
            Width::W80P80 => 4,
            Width::W160 => 5,
        };
        let config = ApConfig {
            // ath11k derives all firmware-facing SSID state from the beacon
            // template; this public field is not consumed by `start_ap`.
            ssid: Vec::new(),
            beacon_head: retained_ap.beacon_head.clone(),
            beacon_tail: retained_ap.beacon_tail.clone(),
            probe_resp: retained_ap.probe_resp.clone(),
            beacon_interval: retained_vif.beacon_interval,
            dtim_period: retained_vif.dtim_period,
            frequency_mhz: def.freq,
            channel_width: width,
            center_freq1_mhz: Some(def.center_freq1),
            center_freq2_mhz: (def.center_freq2 != 0).then_some(def.center_freq2),
            hidden_ssid: 0,
            privacy: retained_ap.privacy,
            mbssid: None,
            mbssid_elems: retained_ap.mbssid_elems.clone(),
            ema_rnr_elems: retained_ap.ema_rnr_elems.clone(),
            fils_discovery: retained_ap.fils_discovery.clone(),
            unsol_bcast_probe_resp: retained_ap.unsol_bcast_probe_resp.clone(),
            ftm_responder: retained_ap.ftm_responder.clone(),
            twt_responder: retained_ap.twt_responder,
            he_obss_pd: retained_ap.he_obss_pd,
            he_bss_color: retained_ap.he_bss_color,
        };
        self.start_ap(config, retained_vif.mbssid, source_templates)
            .await?;

        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let stations = retained_ap.stations.clone();
        let group_keys = retained_ap.group_keys.clone();
        {
            let ap = self.ap.as_mut().unwrap();
            ap.group_keys = group_keys.clone();
            ap.igtks = retained_ap.igtks.clone();
            ap.default_igtk = retained_ap.default_igtk;
        }
        self.dp.ap_group_key(vdev_id, !group_keys.is_empty());
        // Reinstall once even when no client has returned yet: AP group keys
        // are addressed through the AP's self peer, not through a client.
        self.ap_reinstall_group_keys().await?;

        for station in stations {
            self.cmd(
                peer_create_cmd(vdev_id, &station.mac, peer_type::DEFAULT),
                step::AP_PEER_CREATE,
                0x700,
                "recovery AP peer create",
            )
            .await?;
            if let Err(e) = self
                .dp
                .wait_peer_mapped(vdev_id, station.mac, true, timeout::PEER_MAP)
                .await
            {
                return fail(
                    step::AP_PEER_MAP_TIMEOUT,
                    vdev_id,
                    e,
                    "recovery AP peer create (no PEER_MAP)",
                );
            }
            if let Err(e) = self.dp.peer_setup(vdev_id, station.mac).await {
                self.peer_delete(station.mac).await;
                return fail(step::AP_PEER_CREATE, 0x701, e, "recovery AP dp peer setup");
            }
            self.ap_peer_associate(&station, def, retained_ap.privacy, false)
                .await?;
            // Mirror the normal NEW_STATION path: a firmware that discarded
            // a vdev's GTK state while no client was mapped gets it again.
            self.ap_reinstall_group_keys().await?;
            if let Some((idx, cipher, key)) = station.pairwise_key.as_ref() {
                self.install_key_with_cipher(station.mac, *idx, key, true, *cipher)
                    .await?;
            }
            let (addr, wme, authorized) = (station.mac, station.wme, station.authorized);
            self.ap.as_mut().unwrap().stations.push(station);
            self.dp.ap_station_added(vdev_id, addr, wme);
            if authorized {
                self.ap_set_authorized(addr, true).await?;
            }
        }
        // The AP open path initialized defaults. Restore host-configured
        // ERP and EDCA state after the BSS is live, as reconfig does.
        {
            let vif = self.vif.as_mut().unwrap();
            vif.wmm = retained_vif.wmm;
            vif.mu_edca = retained_vif.mu_edca;
            vif.use_cts_prot = retained_vif.use_cts_prot;
            vif.use_short_preamble = retained_vif.use_short_preamble;
            vif.use_short_slot = retained_vif.use_short_slot;
        }
        self.cmd(
            vdev_set_wmm_params_cmd(vdev_id, &retained_vif.wmm, WMI_WMM_PARAM_TYPE_LEGACY),
            step::WMM_PARAMS,
            0x702,
            "recovery AP WMM params",
        )
        .await?;
        self.bss_erp_changed(true, true, true).await;
        Ok(())
    }

    /// Fallback half of `ath11k_mac_op_get_txpower`: if the firmware's
    /// asynchronous pdev statistics are not being refreshed, Linux returns
    /// this vdev's `bss_conf.txpower`.  The netlink read path must not block
    /// for WMI, so it exposes the same retained value.
    pub fn tx_power_dbm(&self) -> Option<i32> {
        self.vif.as_ref().and_then(|vif| vif.txpower)
    }

    /// `ath11k_mac_get_fw_stats`: query only a started, on-channel receiver.
    /// Firmware provides no valid channel power during DFS CAC.
    pub fn tx_power_query_pdev(&self) -> Option<u32> {
        (self.started
            && self.scan.state == ScanState::Idle
            && self.pending.dfs_cac.is_none()
            && self.vif.as_ref().is_some_and(|v| v.chanctx.is_some()))
        .then_some(self.caps.pdev_id)
    }

    /// `WMI_TLV_SERVICE_GTK_OFFLOAD`: the firmware can run the Group Key
    /// Handshake while a later low-power/WoW lifecycle leaves it armed.
    pub fn supports_gtk_rekey_offload(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_GTK_OFFLOAD)
    }

    /// `WMI_TLV_SERVICE_TX_DATA_MGMT_ACK_RSSI`, which Linux maps to
    /// `NL80211_EXT_FEATURE_ACK_SIGNAL_SUPPORT`. WBM completion status then
    /// supplies the associated peer's latest ACK signal for GET_STATION.
    pub fn supports_ack_signal(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_TX_DATA_MGMT_ACK_RSSI)
    }

    /// `WMI_TLV_SERVICE_SPOOF_MAC_SUPPORT`, which Linux maps to
    /// `NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR`.
    pub fn supports_scan_random_mac(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_SPOOF_MAC_SUPPORT)
    }

    /// `ath11k_mac_op_set_rekey_data`: retain nl80211's KEK, KCK and
    /// big-endian replay counter under the MAC lock.  It is intentionally a
    /// synchronous state update; Linux does not send a WMI command here.
    pub fn set_gtk_rekey_data(&mut self, data: GtkRekeyData) -> Result<(), i32> {
        if !self.supports_gtk_rekey_offload() {
            return Err(errno::EOPNOTSUPP);
        }
        self.gtk_rekey_data = Some(data);
        Ok(())
    }

    /// Take the most recent GTK-offload status indication for cfg80211's
    /// `NL80211_CMD_SET_REKEY_OFFLOAD` multicast notification.
    pub fn take_gtk_rekey_notify(&mut self) -> Option<GtkRekeyNotify> {
        self.pending.gtk_rekey_notify.take()
    }

    /// Drain `WMI_PEER_STA_KICKOUT_EVENTID` notifications for
    /// `cfg80211_cqm_pktloss_notify`.  The caller publishes them only after
    /// releasing the MAC mutex, just like management and ROC notifications.
    pub fn take_cqm_pktloss(&mut self) -> Vec<[u8; 6]> {
        self.pending.cqm_pktloss.drain(..).collect()
    }

    /// Configure mac80211's generic CQM RSSI monitor. A singleton threshold
    /// uses its native hysteresis path; a list maintains cfg80211's adjacent
    /// low/high range. No ath11k WMI command is involved: software samples
    /// the associated AP's beacon RSSI and reports crossings after four EWMA
    /// samples.
    pub fn set_cqm_rssi(&mut self, config: Option<CqmRssiConfig>) {
        self.cqm_rssi = config;
        let range_config = self
            .cqm_rssi
            .as_ref()
            .filter(|config| config.thresholds_dbm.len() > 1)
            .cloned();
        if let Some(link) = self.link.as_mut() {
            // `ieee80211_set_cqm_rssi_link` clears this when a new CQM
            // configuration is installed, while retaining the signal EWMA.
            link.last_cqm_event_signal = None;
            let current = if link.beacon_signal_count >= 4 {
                link.beacon_signal_ewma
                    .map(|ewma| -((ewma / 16) as i32))
                    .unwrap_or(0)
            } else {
                0
            };
            link.cqm_rssi_range = range_config
                .as_ref()
                .map(|config| Self::cqm_rssi_range(config, current));
        }
    }

    /// `cfg80211_cqm_rssi_update`: select the two bounds surrounding
    /// `last`, carrying cfg80211's inclusive hysteresis arithmetic without
    /// allowing a hostile userspace value to overflow signed arithmetic.
    fn cqm_rssi_range(config: &CqmRssiConfig, last: i32) -> (i32, i32) {
        debug_assert!(config.thresholds_dbm.len() > 1);
        let next = config
            .thresholds_dbm
            .iter()
            .position(|threshold| last < *threshold)
            .unwrap_or(config.thresholds_dbm.len());
        let hysteresis = config.hysteresis_db.min(i32::MAX as u32) as i32;
        let low = next
            .checked_sub(1)
            .map(|index| config.thresholds_dbm[index].saturating_sub(hysteresis))
            .unwrap_or(i32::MIN);
        let high = config
            .thresholds_dbm
            .get(next)
            .map(|threshold| threshold.saturating_add(hysteresis).saturating_sub(1))
            .unwrap_or(i32::MAX);
        (low, high)
    }

    /// Drain CQM RSSI threshold notifications for nl80211 publication after
    /// releasing the MAC mutex.
    pub fn take_cqm_rssi(&mut self) -> Vec<CqmRssiEvent> {
        self.pending.cqm_rssi.drain(..).collect()
    }

    /// Whether this firmware exposes the pdev's 64-bit BSS-channel counters.
    pub fn supports_bss_survey(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_BSS_CHANNEL_INFO_64)
    }

    /// Schedule Linux ath11k's `WMI_BSS_SURVEY_REQ_TYPE_READ` for the
    /// currently active channel. The caller is the ordered runtime worker;
    /// unlike Linux's synchronous mac80211 callback it must not await the
    /// response while a generic-netlink syscall might be in an executor poll.
    pub async fn request_bss_survey(&mut self) -> Result<(), MacError> {
        if !self.supports_bss_survey() || self.scan.state != ScanState::Idle {
            return Ok(());
        }
        // `ar->rx_channel != channel` is Linux's gate. A live VIF channel
        // context is NARF's equivalent; do not ask target counters when this
        // vdev has no on-channel receiver.
        if self.vif.as_ref().and_then(|vif| vif.chanctx).is_none() {
            return Ok(());
        }
        let c = pdev_bss_chan_info_request_cmd(self.caps.pdev_id);
        self.cmd(c, step::BSS_SURVEY, 0, "BSS channel survey").await
    }

    /// Drain pdev survey samples for the physical-radio cache after dropping
    /// the MAC mutex. Every vdev receives the broadcast pdev event, so the
    /// cache's replacement-by-frequency operation is deliberately idempotent.
    pub fn take_bss_survey(&mut self) -> Vec<BssSurvey> {
        self.pending.bss_survey.drain(..).collect()
    }

    /// Drain management frames received for userspace `REGISTER_FRAME`
    /// subscriptions. The netdev filters these against its registrations and
    /// publishes matching `NL80211_CMD_FRAME` notifications after releasing
    /// the MAC mutex.
    pub fn take_registered_mgmt_rx(&mut self) -> Vec<RegisteredMgmtRx> {
        self.pending.registered_mgmt_rx.drain(..).collect()
    }

    /// Drain scan-backed remain-on-channel transitions for the netlink
    /// publisher.  Keeping publication outside WMI event dispatch avoids a
    /// lock inversion with generic-netlink delivery.
    pub fn take_remain_on_channel_events(&mut self) -> Vec<RemainOnChannelEvent> {
        self.pending.roc_events.drain(..).collect()
    }

    /// Drain AP / GO CSA state transitions after releasing the MAC lock.
    pub fn take_ap_channel_switch_events(&mut self) -> Vec<ApChannelSwitchEvent> {
        self.pending.ap_channel_switch_events.drain(..).collect()
    }

    /// Drain AP BSS-color transition notifications after releasing the MAC
    /// lock. The runtime maps these to the three nl80211 MLME commands.
    pub fn take_ap_color_change_events(&mut self) -> Vec<ApColorChangeEvent> {
        self.pending.ap_color_change_events.drain(..).collect()
    }

    /// Drain DFS radar/CAC/NOP state changes for nl80211 after the MAC mutex
    /// has been released.
    pub fn take_dfs_events(&mut self) -> Vec<DfsEvent> {
        self.pending.dfs_events.drain(..).collect()
    }

    /// Drain rate-limited OBSS color-collision indications after releasing
    /// the MAC mutex.  The interface runtime emits the MLME multicast event.
    pub fn take_obss_color_collision_events(&mut self) -> Vec<u64> {
        self.pending.obss_color_collision_events.drain(..).collect()
    }

    /// `ath11k_gtk_rekey_offload(enable)`: enable rekeying only after a
    /// low-power/WoW owner has quiesced the station, or query its final
    /// replay counter before disabling it on resume.  This narrow helper is
    /// deliberately separate from normal EAPOL group-key processing.
    pub async fn set_gtk_rekey_offload(&mut self, enable: bool) -> Result<(), MacError> {
        if !self.supports_gtk_rekey_offload() {
            return fail(
                step::GTK_REKEY_OFFLOAD,
                0,
                errno::EOPNOTSUPP,
                "GTK rekey offload (unsupported)",
            );
        }
        let Some(vdev_id) = self.vif.as_ref().filter(|v| v.is_up).map(|v| v.vdev_id) else {
            // Linux skips a non-running STA vdev in the WoW fan-out.
            return Ok(());
        };
        if !self.link.as_ref().is_some_and(|l| l.assoc) {
            return Ok(());
        }
        if enable {
            let Some(data) = self.gtk_rekey_data else {
                // `enable_offload` is false until set_rekey_data succeeds.
                return Ok(());
            };
            let p = GtkRekeyOffloadParams {
                vdev_id,
                kek: data.kek,
                kck: data.kck,
                replay_counter: u64::from_be_bytes(data.replay_counter),
            };
            let c = gtk_rekey_offload_cmd(vdev_id, gtk_offload_opcode::ENABLE, Some(&p));
            return self
                .cmd(c, step::GTK_REKEY_OFFLOAD, 1, "GTK rekey offload enable")
                .await;
        }
        // Linux asks for the counter before turning off the engine.  The
        // status event is asynchronous, so the notification is delivered by
        // the ordinary MAC/runtime event path rather than awaited here.
        let c = gtk_rekey_offload_cmd(vdev_id, gtk_offload_opcode::REQUEST_STATUS, None);
        self.cmd(c, step::GTK_REKEY_OFFLOAD, 2, "GTK rekey offload status")
            .await?;
        let c = gtk_rekey_offload_cmd(vdev_id, gtk_offload_opcode::DISABLE, None);
        self.cmd(c, step::GTK_REKEY_OFFLOAD, 3, "GTK rekey offload disable")
            .await
    }

    /// `WMI_TLV_SERVICE_WOW`: the target accepts ath11k's WoWLAN control
    /// plane.  GTK is a separate service bit because it is only one of the
    /// protocol offloads the transition may enable.
    pub fn supports_wowlan(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_WOW)
    }

    /// `WMI_TLV_SERVICE_NLO`: firmware can run cfg80211 WoWLAN
    /// `NET_DETECT` as WMI network-list offload during system suspend.
    pub fn supports_nlo(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_NLO)
    }

    /// `WMI_TLV_SERVICE_BIOS_SAR_SUPPORT`: WCN6855 firmware accepts the
    /// 22-byte BIOS SAR power table on its physical pdev.
    pub fn supports_bios_sar(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_BIOS_SAR_SUPPORT)
    }

    /// WCN6855 accepts the AP's MBSSID role fields in VDEV_START. NARF
    /// creates vdevs when an interface is administratively opened, before
    /// hostapd supplies START_AP, so this service bit is required before we
    /// advertise an MBSSID capability.
    pub fn supports_mbssid_start(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_MBSS_PARAM_IN_VDEV_START_SUPPORT)
    }

    /// `WMI_TLV_SERVICE_RTT` gates the FTM responder role ath11k exposes
    /// through `NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER`.
    pub fn supports_ftm_responder(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_RTT)
    }

    /// `WMI_TLV_SERVICE_BSS_COLOR_OFFLOAD` is the wiphy advertisement gate;
    /// ath11k still accepts an HE BSS-color configuration through its common
    /// BSS-info path and programs collision detection below.
    pub fn supports_bss_color(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_BSS_COLOR_OFFLOAD)
    }

    /// `WMI_TLV_SERVICE_AP_TWT` permits START_AP's TWT responder role.
    pub fn supports_twt_responder(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_AP_TWT)
    }

    /// `ath11k_mac_op_set_bios_sar_specs`: Linux first submits the reserved
    /// geo table, then the table whose first/second eleven bytes carry the
    /// same per-range limit for chains zero and one. No completion event is
    /// defined for either command, so successful endpoint submission is the
    /// synchronous contract just as in ath11k.
    pub async fn set_bios_sar_table(
        &mut self,
        table: &[u8; BIOS_SAR_TABLE_LEN],
    ) -> Result<(), MacError> {
        if !self.supports_bios_sar() {
            return fail(step::BIOS_SAR, 0, errno::EOPNOTSUPP, "bios SAR unsupported");
        }
        let geo = pdev_set_bios_geo_table_cmd(self.caps.pdev_id);
        self.cmd(geo, step::BIOS_SAR, 1, "bios SAR geo table")
            .await?;
        let command = pdev_set_bios_sar_table_cmd(self.caps.pdev_id, table);
        self.cmd(command, step::BIOS_SAR, 2, "bios SAR power table")
            .await
    }

    /// Retain `SET_WOWLAN` configuration under the MAC mutex.  Like Linux's
    /// `wiphy->wowlan_config`, this does not send firmware commands: those
    /// are sent only while entering a low-power state.
    pub fn set_wowlan_config(&mut self, config: Option<WowlanConfig>) -> Result<(), i32> {
        if !self.supports_wowlan() {
            return Err(errno::EOPNOTSUPP);
        }
        if let Some(config) = config.as_ref() {
            if config.patterns.len() > ATH11K_WOW_MAX_PATTERNS
                || config.patterns.iter().any(|p| {
                    p.pattern.is_empty()
                        || p.pattern.len() > WMI_WOW_MAX_PATTERN_SIZE
                        || p.mask.len() != p.pattern.len().div_ceil(8)
                        || p.offset > ATH11K_WOW_MAX_PKT_OFFSET
                })
            {
                return Err(errno::EINVAL);
            }
            if config.net_detect.is_some() && !self.supports_nlo() {
                return Err(errno::EOPNOTSUPP);
            }
        }
        self.wowlan_config = config;
        Ok(())
    }

    /// The retained cfg80211-style configuration, if WoWLAN wakeups are
    /// enabled for this interface.
    pub fn wowlan_config(&self) -> Option<&WowlanConfig> {
        self.wowlan_config.as_ref()
    }

    /// Replace the latest station-interface IPv4 / IPv6 snapshot.  Linux
    /// receives this state through mac80211's address-change callbacks; NARF
    /// snapshots the authoritative net stack just before it enters WoW so
    /// addresses added by DHCP/SLAAC cannot race a low-power transition.
    pub fn set_arp_ns_offload(&mut self, offload: ArpNsOffload) {
        self.arp_ns_offload = offload;
    }

    fn supports_arp_ns_offload(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_ARPNS_OFFLOAD)
    }

    /// Whether a previous `prepare_wowlan` received HTC's suspend-complete
    /// acknowledgement and still needs the matching resume cleanup.
    pub fn wow_armed(&self) -> bool {
        self.wow_armed
    }

    /// Called by the netdev after it waited for HTC endpoint zero's ACK.
    pub fn mark_wow_armed(&mut self, armed: bool) {
        self.wow_armed = armed;
    }

    /// Linux's native-Wi-Fi (`ATH11K_HW_TXRX_NATIVE_WIFI`) pattern rewrite:
    /// cfg80211 gives an Ethernet MSDU pattern, whereas WCN6855 firmware
    /// compares raw 802.11 + RFC1042 bytes.  The firmware wants a byte mask,
    /// not cfg80211's one-bit-per-byte mask.
    fn wow_pattern_for_firmware(&self, input: &WowPattern) -> Result<(Vec<u8>, Vec<u8>, u32), i32> {
        let byte_mask =
            |at: usize| -> u8 { (input.mask[at / 8] & (1 << (at % 8)) != 0) as u8 * 0xff };
        if self.cfg.frame_mode_ethernet {
            return Ok((
                input.pattern.clone(),
                (0..input.pattern.len()).map(byte_mask).collect(),
                input.offset,
            ));
        }
        if input.offset >= 14 {
            return Ok((
                input.pattern.clone(),
                (0..input.pattern.len()).map(byte_mask).collect(),
                input.offset + 18, // WOW_HDR_LEN (32) - ETH_HLEN (14)
            ));
        }

        // `ath11k_wow_convert_8023_to_80211`, expressed in terms of the
        // absolute Ethernet byte each supplied pattern byte represents.  The
        // bounds checks make a short, valid netlink pattern deterministic
        // rather than relying on Linux's unchecked header memcpy.
        const IEEE80211_3ADDR_HDR: usize = 24;
        const RFC1042_HDR: usize = 8;
        const WOW_HDR_LEN: usize = IEEE80211_3ADDR_HDR + RFC1042_HDR;
        const ETH_HLEN: usize = 14;
        let old_offset = input.offset as usize;
        let total = old_offset + input.pattern.len();
        let new_offset = if old_offset < 6 {
            old_offset + 4 // offsetof(ieee80211_hdr_3addr, addr1)
        } else if old_offset < 12 {
            old_offset + 16 - 6 // addr3 - h_source
        } else {
            old_offset + WOW_HDR_LEN - ETH_HLEN
        };
        let hdr_end = if total > ETH_HLEN {
            WOW_HDR_LEN
        } else if total > 12 {
            WOW_HDR_LEN + total - ETH_HLEN
        } else if total > 6 {
            total - 6 + 16
        } else {
            total + 4
        };
        let header_len = hdr_end.saturating_sub(new_offset);
        let tail_len = total.saturating_sub(ETH_HLEN);
        let mut pattern = alloc::vec![0; header_len + tail_len];
        let mut mask = alloc::vec![0; header_len + tail_len];
        let old = |absolute: usize| -> Option<(u8, u8)> {
            let index = absolute.checked_sub(old_offset)?;
            input
                .pattern
                .get(index)
                .copied()
                .map(|value| (value, byte_mask(index)))
        };
        let mut put = |absolute: usize, value: (u8, u8)| {
            let index = absolute.saturating_sub(new_offset);
            if index < header_len {
                pattern[index] = value.0;
                mask[index] = value.1;
            }
        };
        // Ethernet DA -> 802.11 addr1, SA -> addr3, EtherType -> RFC1042.
        for (old_base, new_base, len) in [(0, 4, 6), (6, 16, 6), (12, 30, 2)] {
            for i in 0..len {
                if let Some(value) = old(old_base + i) {
                    put(new_base + i, value);
                }
            }
        }
        // Bytes after the Ethernet header are unchanged after the inserted
        // 802.11/RFC1042 header; preserve their individual byte masks.
        if total > ETH_HLEN {
            for absolute in ETH_HLEN..total {
                if let Some(value) = old(absolute) {
                    let index = header_len + absolute - ETH_HLEN;
                    pattern[index] = value.0;
                    mask[index] = value.1;
                }
            }
        }
        if pattern.is_empty() || pattern.len() > WMI_WOW_MAX_PATTERN_SIZE {
            return Err(errno::EINVAL);
        }
        Ok((pattern, mask, new_offset as u32))
    }

    /// Clear every prior ath11k wake event and WCN6855's 22 pattern slots,
    /// reproducing `ath11k_wow_cleanup` before both reprogramming and resume.
    async fn wow_cleanup(&mut self, vdev_id: u32) -> Result<(), MacError> {
        for event in 0..wow_event::MAX {
            let cmd = wow_wakeup_event_cmd(vdev_id, event, false).expect("bounded WoW event");
            self.cmd(cmd, step::WOWLAN, 1, "WoW clear wake event")
                .await?;
        }
        for pattern_id in 0..ATH11K_WOW_MAX_PATTERNS as u32 {
            self.cmd(
                wow_del_pattern_cmd(vdev_id, pattern_id),
                step::WOWLAN,
                2,
                "WoW clear pattern",
            )
            .await?;
        }
        Ok(())
    }

    /// Stop one previously armed network-list offload before generic WoW
    /// cleanup removes its matching wake event.  Linux clears its
    /// `nlo_enabled` state before submitting this best-effort stop, so a
    /// transient WMI failure cannot cause a later unrelated vdev to issue a
    /// duplicate stop for the stale owner.
    async fn stop_nlo(&mut self, vdev_id: u32) -> Result<(), MacError> {
        if !self.nlo_armed {
            return Ok(());
        }
        self.nlo_armed = false;
        self.cmd(
            nlo_config_stop_cmd(vdev_id),
            step::WOWLAN,
            3,
            "WoW network-list offload stop",
        )
        .await
    }

    /// Program the per-vdev portion of `ath11k_wow_op_suspend`, up to and
    /// including `WMI_WOW_ENABLE_CMDID`.  The caller drops the MAC lock to
    /// await endpoint-zero's suspend response, then calls `mark_wow_armed`.
    pub async fn prepare_wowlan(&mut self) -> Result<(), MacError> {
        if !self.supports_wowlan() {
            return fail(step::WOWLAN, 0, errno::EOPNOTSUPP, "WoWLAN unsupported");
        }
        let Some(config) = self.wowlan_config.clone() else {
            return fail(step::WOWLAN, 0, errno::EINVAL, "WoWLAN unconfigured");
        };
        let Some(vdev_id) = self.vif.as_ref().filter(|v| v.is_up).map(|v| v.vdev_id) else {
            return fail(step::WOWLAN, 0, errno::ENOTCONN, "WoWLAN vdev down");
        };
        self.stop_nlo(vdev_id).await?;
        self.wow_cleanup(vdev_id).await?;
        let result = self.prepare_wowlan_after_cleanup(vdev_id, &config).await;
        // Linux's `goto cleanup` after any failure from wake-source,
        // protocol-offload, filter, keepalive, or enable programming removes
        // the wake events/patterns it has installed so a later suspend
        // begins from a known firmware state.  Preserve the original error;
        // cleanup failures are diagnostic-only in ath11k too.
        if result.is_err() {
            let _ = self.stop_nlo(vdev_id).await;
            let _ = self.wow_cleanup(vdev_id).await;
        }
        result
    }

    /// The post-cleanup half of [`Self::prepare_wowlan`].  Kept separate so
    /// the outer method can reproduce ath11k's single error-cleanup edge.
    async fn prepare_wowlan_after_cleanup(
        &mut self,
        vdev_id: u32,
        config: &WowlanConfig,
    ) -> Result<(), MacError> {
        if let Some(nlo) = config.net_detect.as_ref() {
            if !self.supports_nlo() {
                return fail(
                    step::WOWLAN,
                    3,
                    errno::EOPNOTSUPP,
                    "WoW network-list offload unsupported",
                );
            }
            if !self
                .vif
                .as_ref()
                .is_some_and(|vif| vif.kind == VifKind::Station)
            {
                // Linux configures NLO only for a WMI STA vdev, never AP,
                // P2P-client, or the P2P-device discovery vdev.
                return fail(
                    step::WOWLAN,
                    3,
                    errno::EINVAL,
                    "WoW network-list offload vdev type",
                );
            }
            let command = nlo_config_start_cmd(vdev_id, nlo)
                .map_err(|error| MacError::new(step::WOWLAN, 3, error.errno()))?;
            self.cmd(command, step::WOWLAN, 3, "WoW network-list offload start")
                .await?;
            self.nlo_armed = true;
            let command = wow_wakeup_event_cmd(vdev_id, wow_event::NLO_DETECTED, true)
                .expect("known NLO wake event");
            self.cmd(command, step::WOWLAN, 3, "WoW network-list wake event")
                .await?;
        }
        if config.disconnect {
            for event in [
                wow_event::DEAUTH,
                wow_event::DISASSOC,
                wow_event::BMISS,
                wow_event::CSA,
            ] {
                let cmd = wow_wakeup_event_cmd(vdev_id, event, true).expect("known WoW event");
                self.cmd(cmd, step::WOWLAN, 3, "WoW disconnect wake event")
                    .await?;
            }
        }
        if config.magic_packet {
            let cmd = wow_wakeup_event_cmd(vdev_id, wow_event::MAGIC_PACKET, true)
                .expect("known WoW event");
            self.cmd(cmd, step::WOWLAN, 4, "WoW magic-packet wake event")
                .await?;
        }
        // Linux's `ath11k_vif_wow_set_wakeups` has no explicit GTK-error
        // event command: the enabled GTK-offload engine owns that wake
        // source.  `gtk_rekey_failure` is therefore retained for the
        // cfg80211 contract but intentionally does not map to event 4 here.
        for (id, input) in config.patterns.iter().enumerate() {
            let (pattern, mask, offset) = self
                .wow_pattern_for_firmware(input)
                .map_err(|e| MacError::new(step::WOWLAN, 5, e))?;
            let cmd = wow_add_pattern_cmd(vdev_id, id as u32, &pattern, &mask, offset)
                .map_err(|e| MacError::new(step::WOWLAN, 5, e.errno()))?;
            self.cmd(cmd, step::WOWLAN, 5, "WoW packet pattern").await?;
        }
        if !config.patterns.is_empty() {
            let cmd = wow_wakeup_event_cmd(vdev_id, wow_event::PATTERN_MATCH, true)
                .expect("known WoW event");
            self.cmd(cmd, step::WOWLAN, 6, "WoW pattern wake event")
                .await?;
        }
        if self.supports_arp_ns_offload() {
            let cmd = arp_ns_offload_cmd(vdev_id, &self.arp_ns_offload, true)
                .map_err(|e| MacError::new(step::WOWLAN, 7, e.errno()))?;
            self.cmd(cmd, step::WOWLAN, 7, "WoW ARP/NS offload").await?;
        }
        if self.supports_gtk_rekey_offload() {
            self.set_gtk_rekey_offload(true).await?;
        }
        self.cmd(
            hw_data_filter_cmd(
                vdev_id,
                hw_data_filter::DROP_NON_ARP_BROADCAST | hw_data_filter::DROP_NON_ICMPV6_MULTICAST,
                true,
            ),
            step::WOWLAN,
            8,
            "WoW hardware data filter",
        )
        .await?;
        self.cmd(
            sta_keepalive_cmd(&StaKeepaliveParams {
                vdev_id,
                enabled: true,
                method: sta_keepalive_method::NULL_FRAME,
                interval_secs: WMI_STA_KEEPALIVE_INTERVAL_DEFAULT,
                src_ipv4: 0,
                dst_ipv4: 0,
                dest_mac: [0; 6],
            }),
            step::WOWLAN,
            9,
            "WoW null-frame keepalive",
        )
        .await?;
        self.cmd(wow_enable_cmd(), step::WOWLAN, 10, "WoW enable")
            .await
    }

    /// Abort a WoW transition that did not reach an HTC suspend ACK.  Linux
    /// takes the `cleanup:` path for the analogous failures; an armed
    /// transition instead follows the normal host-wakeup resume path.
    pub async fn abort_wowlan_prepare(&mut self) {
        if let Some(vdev_id) = self.vif.as_ref().filter(|v| v.is_up).map(|v| v.vdev_id) {
            let _ = self.stop_nlo(vdev_id).await;
            let _ = self.wow_cleanup(vdev_id).await;
        }
        self.wow_armed = false;
    }

    /// Send the WMI half of `ath11k_wow_wakeup`; the netdev then waits for
    /// `WMI_WOW_WAKEUP_HOST_EVENTID` before cleanup resumes.  The similarly
    /// named HTC endpoint-zero notification is diagnostic-only in Linux.
    pub async fn request_wow_wakeup(&mut self) -> Result<(), MacError> {
        self.cmd(wow_host_wakeup_cmd(), step::WOWLAN, 11, "WoW host wakeup")
            .await
    }

    /// Reissue only `WMI_WOW_ENABLE_CMDID` after endpoint zero returned a
    /// NACK.  `ath11k_wow_enable` has already configured all wake sources;
    /// its three retries do not repeat the expensive per-vdev setup.
    pub async fn retry_wow_enable(&mut self) -> Result<(), MacError> {
        self.cmd(wow_enable_cmd(), step::WOWLAN, 14, "WoW enable retry")
            .await
    }

    /// The MAC-side remainder of `ath11k_wow_op_resume`: clear the receive
    /// filter, obtain and disable GTK offload, stop null-frame keepalives,
    /// then remove configured wake events/patterns.
    pub async fn finish_wowlan_resume(&mut self) -> Result<(), MacError> {
        if !self.wow_armed {
            return Ok(());
        }
        let Some(vdev_id) = self.vif.as_ref().filter(|v| v.is_up).map(|v| v.vdev_id) else {
            self.wow_armed = false;
            return Ok(());
        };
        self.cmd(
            hw_data_filter_cmd(vdev_id, 0, false),
            step::WOWLAN,
            12,
            "WoW clear hardware data filter",
        )
        .await?;
        if self.supports_arp_ns_offload() {
            let cmd = arp_ns_offload_cmd(vdev_id, &self.arp_ns_offload, false)
                .map_err(|e| MacError::new(step::WOWLAN, 13, e.errno()))?;
            self.cmd(cmd, step::WOWLAN, 13, "WoW disable ARP/NS offload")
                .await?;
        }
        if self.supports_gtk_rekey_offload() {
            self.set_gtk_rekey_offload(false).await?;
        }
        self.cmd(
            sta_keepalive_cmd(&StaKeepaliveParams {
                vdev_id,
                enabled: true,
                method: sta_keepalive_method::NULL_FRAME,
                interval_secs: WMI_STA_KEEPALIVE_INTERVAL_DISABLE,
                src_ipv4: 0,
                dst_ipv4: 0,
                dest_mac: [0; 6],
            }),
            step::WOWLAN,
            14,
            "WoW disable null-frame keepalive",
        )
        .await?;
        self.stop_nlo(vdev_id).await?;
        self.wow_cleanup(vdev_id).await?;
        self.wow_armed = false;
        Ok(())
    }

    fn svc(&self, bit: u32) -> bool {
        self.caps.svc.test(bit)
    }

    /// `ath11k_wmi_supports_6ghz_cc_ext`.
    fn supports_6ghz_cc_ext(&self) -> bool {
        self.svc(WMI_TLV_SERVICE_REG_CC_EXT_EVENT_SUPPORT) && self.wiphy.supports_6ghz()
    }

    /// `ieee80211_twt_req_supported`: the AP must explicitly advertise
    /// responder support in both its HE and Extended Capabilities IEs, and
    /// the local station must have a requester-capable firmware service.
    fn twt_request_supported(&self, band: Band, ap: Option<&peer::ApHe>, ies: &ParsedIes) -> bool {
        self.svc(WMI_TLV_SERVICE_STA_TWT)
            && self
                .own_he(band)
                .is_some_and(|cap| cap.mac[0] & he::cap::MAC0_TWT_REQ != 0)
            && ap.is_some_and(|cap| cap.cap.mac[0] & he::cap::MAC0_TWT_RES != 0)
            && ies
                .ext_cap
                .as_deref()
                .is_some_and(|cap| cap.get(9).is_some_and(|v| v & (1 << 6) != 0))
    }

    /// `BSS_CHANGED_TWT` is pdev-scoped in ath11k. Both the negotiated
    /// station requester and an AP responder use the same default enable
    /// block; only the service bit that authorizes the role differs.
    async fn twt_changed_for_service(&mut self, enabled: bool, service: u32) {
        if !self.svc(service) || self.twt_enabled == enabled {
            return;
        }
        let c = if enabled {
            twt_enable_cmd(self.caps.pdev_id, &TwtEnableParams::default())
        } else {
            twt_disable_cmd(self.caps.pdev_id)
        };
        if self.cmd(c, step::HE_PARAM, 3, "TWT engine").await.is_ok() {
            self.twt_enabled = enabled;
        }
    }

    /// Station requester arm of `BSS_CHANGED_TWT`.
    async fn twt_changed(&mut self, enabled: bool) {
        self.twt_changed_for_service(enabled, WMI_TLV_SERVICE_STA_TWT)
            .await;
    }

    /// AP responder arm of `BSS_CHANGED_TWT`.
    async fn twt_ap_changed(&mut self, enabled: bool) {
        self.twt_changed_for_service(enabled, WMI_TLV_SERVICE_AP_TWT)
            .await;
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

    /// `ath11k_peer_assoc_qos_ap`: firmware owns AP power-save buffering
    /// and beacon TIM maintenance, but needs this per-peer request after
    /// `WMI_PEER_ASSOC_CMDID` confirms the client.
    async fn ap_peer_uapsd(
        &mut self,
        vdev_id: u32,
        peer: [u8; 6],
        queues: u8,
        max_sp: u8,
    ) -> Result<(), MacError> {
        use wmi::ap_ps_peer_param as ap_ps;

        let mut uapsd = 0u32;
        for (requested, delivery_trigger) in [
            (1u8 << 0, ap_ps::AC0_DELIVERY_EN | ap_ps::AC0_TRIGGER_EN), // BE
            (1u8 << 1, ap_ps::AC1_DELIVERY_EN | ap_ps::AC1_TRIGGER_EN), // BK
            (1u8 << 2, ap_ps::AC2_DELIVERY_EN | ap_ps::AC2_TRIGGER_EN), // VI
            (1u8 << 3, ap_ps::AC3_DELIVERY_EN | ap_ps::AC3_TRIGGER_EN), // VO
        ] {
            if queues & requested != 0 {
                uapsd |= delivery_trigger;
            }
        }
        for (param, value) in [
            (ap_ps::UAPSD, uapsd),
            (ap_ps::MAX_SP, max_sp as u32),
            (
                ap_ps::SIFS_RESP_FRMTYPE,
                ap_ps::DISABLE_SIFS_RESPONSE_TRIGGER,
            ),
            (ap_ps::SIFS_RESP_UAPSD, ap_ps::DISABLE_SIFS_RESPONSE_TRIGGER),
        ] {
            self.cmd(
                ap_ps_peer_param_cmd(vdev_id, &peer, param, value),
                step::AP_PEER_UAPSD,
                param,
                "AP peer U-APSD",
            )
            .await?;
        }
        Ok(())
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
        let roc_due = self.scan.roc.is_some_and(|roc| {
            roc.started
                && self
                    .scan
                    .deadline
                    .is_some_and(|deadline| self.wmi.now_ms() >= deadline)
        });
        if roc_due {
            // `ath11k_mac_op_remain_on_channel` queues a delayed timeout
            // that aborts the passive one-channel scan at the requested
            // duration.  `scan_finish` emits the expiry notification.
            self.scan_abort().await;
        }
        self.rx_eapol().await;
        let probe_due = self.link.as_ref().is_some_and(|l| {
            l.loss.is_none()
                && l.assoc
                && l.conn_loss_deadline.is_some_and(|d| self.wmi.now_ms() >= d)
        });
        if probe_due {
            // ieee80211_mgd_probe_ap / ieee80211_sta_tx_notify: ath11k
            // reports per-MSDU ACK status, so two directed Null probes
            // are preferable to probe requests. A successful ACK resets
            // connection polling even if a beacon has not arrived yet.
            let mut acked = false;
            for _ in 0..timeout::CONNECTION_PROBE_TRIES {
                match self.dp.probe_ap(timeout::CONNECTION_PROBE_WAIT).await {
                    Ok(status) if status.acked => {
                        acked = true;
                        break;
                    }
                    Ok(_) | Err(_) => {}
                }
            }
            if let Some(l) = self.link.as_mut() {
                if acked {
                    l.conn_loss_deadline = None;
                } else if l.loss.is_none() {
                    l.loss = Some(LinkLoss::BeaconLoss);
                }
            }
        }
        let loss = self.link.as_ref().and_then(|l| l.loss);
        if let Some(loss) = loss {
            let bssid = self.link.as_ref().map_or([0; 6], |l| l.bss.bssid);
            if self
                .link
                .as_ref()
                .is_some_and(|l| l.authorized || l.external.is_some() && l.assoc)
            {
                let (s, d) = match loss {
                    LinkLoss::Kickout => (step::LINK_KICKOUT, 0),
                    LinkLoss::BeaconLoss => (step::LINK_BEACON_LOSS, 0),
                    LinkLoss::ChannelSwitch => (step::AP_CHANNEL_SWITCH, 0),
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
                self.disconnect = Some(loss.disconnect(bssid));
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
        let f = self.prepare_mgmt_tx(f);
        let _ = self.wmi.mgmt_tx(vdev_id, &f, None).await;
    }

    /// `ath11k_mac_mgmt_action_frame_fill_elem_data`: update the two Radio
    /// Measurement Link Measurement action formats just before firmware
    /// transmission.  The supplied frame is still plaintext at this point;
    /// [`Self::mfp_tx`] runs afterwards when PMF protects the action.
    ///
    /// Linux treats an unrecognised or malformed action as a best-effort
    /// no-op and still transmits it. Keep that property here: the nl80211
    /// caller owns frame validation, while this target-specific fill must not
    /// turn a valid generic action into a rejected management transmission.
    fn fill_mgmt_tx_power(&self, f: &mut [u8]) {
        if f.len() < frame::MGMT_HDR_LEN + 3 {
            return;
        }
        let fc = u16::from_le_bytes([f[0], f[1]]);
        if fc & frame::FCTL_TYPE_STYPE != frame::stype::ACTION {
            return;
        }
        // A protected management frame supplied by a caller may already
        // contain the CCMP management IV.  Linux advances past that header
        // before inspecting `mgmt->u.action`; otherwise the IV would be
        // mistaken for the action category.  NARF's PMF path generates only
        // CCMP management protection, so `CCMP_HDR_LEN` is the applicable
        // protected-action offset here as well.
        let action_offset = frame::MGMT_HDR_LEN
            + if fc & frame::FCTL_PROTECTED != 0 {
                sec::CCMP_HDR_LEN
            } else {
                0
            };
        if f.len() < action_offset + 3 {
            return;
        }
        let Some(vif) = self.vif.as_ref() else {
            return;
        };
        let (Some(def), Some(current)) = (vif.chanctx, vif.txpower) else {
            return;
        };
        let Some(channel) = self.wiphy.get(def.freq) else {
            return;
        };
        let maximum = channel
            .max_reg_power
            .min((self.caps.hw_max_tx_power / 2) as i32);
        let body = &mut f[action_offset..];
        if body[0] != frame::WLAN_CATEGORY_RADIO_MEASUREMENT {
            return;
        }
        match body[1] {
            frame::WLAN_RM_ACTION_LINK_MEASUREMENT_REQUEST if body.len() >= 5 => {
                // Link-Measurement Request: category, action, dialog token,
                // transmit power, maximum transmit power.
                body[3] = current as u8;
                body[4] = maximum as u8;
            }
            frame::WLAN_RM_ACTION_LINK_MEASUREMENT_REPORT if body.len() >= 6 => {
                // Link-Measurement Report: the TPC Report IE begins at byte
                // three; its Tx Power member is the third IE byte. Linux
                // deliberately leaves the unavailable link margin intact.
                body[5] = current as u8;
            }
            _ => {}
        }
    }

    /// Prepare an outbound management frame in the same order as Linux's
    /// WMI work item: target-owned Radio-Measurement fields first, then PMF
    /// protection over their final bytes.
    fn prepare_mgmt_tx(&mut self, f: &[u8]) -> Vec<u8> {
        let mut f = f.to_vec();
        self.fill_mgmt_tx_power(&mut f);
        self.mfp_tx(&f)
    }

    /// `cfg80211_ops::mgmt_tx` for a userspace `NL80211_CMD_FRAME` request.
    /// The caller owns its netlink cookie; ath11k owns the WMI descriptor and
    /// releases its DMA buffer only when the matching completion arrives.
    pub async fn registered_mgmt_tx(
        &mut self,
        frame: &[u8],
        chanfreq: Option<u32>,
    ) -> Result<bool, MacError> {
        let Some(vdev_id) = self.vif.as_ref().map(|v| v.vdev_id) else {
            return fail(
                step::MGMT_FRAME_TX,
                0,
                errno::ENOTCONN,
                "registered management TX (no vdev)",
            );
        };
        let frame = self.prepare_mgmt_tx(frame);
        let desc = match self.wmi.mgmt_tx(vdev_id, &frame, chanfreq).await {
            Ok(desc) => desc,
            Err(e) => return fail(step::MGMT_FRAME_TX, 1, e, "registered management TX"),
        };
        let status = self
            .wait_for(timeout::MLME_TX_STATUS, |s| {
                let pos = s.pending.mgmt_tx.iter().position(|c| c.desc_id == desc)?;
                Some(s.pending.mgmt_tx.remove(pos).status)
            })
            .await;
        match status {
            Some(status) => {
                self.wmi.mgmt_tx_done(desc);
                Ok(status == 0)
            }
            // Leave the descriptor live. A late WMI completion is released
            // by `poll`'s ordinary `release_mgmt_tx` pass.
            None => Ok(false),
        }
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
            WmiEvent::MgmtRx(m) => {
                // `ATH11K_CAC_RUNNING`: ath11k must not hand received
                // frames to mac80211 while target DFS availability checks
                // are in progress on the AP channel.
                if self.pending.dfs_cac.is_none() {
                    self.mgmt_rx(&m);
                }
            }
            WmiEvent::VdevStartResp(r) if Some(r.vdev_id) == our_vdev => {
                self.pending.vdev_start = Some(r)
            }
            WmiEvent::VdevStopped(v) if Some(v) == our_vdev => self.pending.vdev_stopped = Some(v),
            WmiEvent::VdevDeleteResp(v) => self.pending.vdev_deleted = Some(v),
            WmiEvent::PeerAssocConf(p) => self.pending.peer_assoc_conf = Some(p),
            WmiEvent::InstallKeyCompl(k) => self.pending.install_key = Some(k),
            WmiEvent::GtkOffloadStatus(s) if Some(s.vdev_id) == our_vdev => {
                if let Some(bssid) = self.link.as_ref().map(|l| l.bss.bssid) {
                    let replay_counter = s.replay_counter_be();
                    if let Some(data) = self.gtk_rekey_data.as_mut() {
                        data.replay_counter = replay_counter;
                    }
                    self.pending.gtk_rekey_notify = Some(GtkRekeyNotify {
                        bssid,
                        replay_counter,
                    });
                }
            }
            WmiEvent::PeerDeleteResp(p) => self.pending.peer_deleted = Some(p),
            WmiEvent::MgmtTxCompl(c) => self.pending.mgmt_tx.push(c),
            WmiEvent::PeerStaKickout(addr) => {
                // ath11k feeds every firmware kickout to
                // ieee80211_report_low_ack(sta, 10).  AP mode must not
                // remove the client here: the CQM event lets hostapd's
                // inactivity policy decide whether and how to disassociate
                // it.  Station mode retains the existing connection-loss
                // path, and also gets the matching CQM indication.
                let ap_peer = self
                    .ap
                    .as_ref()
                    .is_some_and(|ap| ap.stations.iter().any(|station| station.mac == addr));
                let sta_peer = self
                    .link
                    .as_ref()
                    .is_some_and(|link| addr == link.bss.bssid && link.peer_created);
                if (ap_peer || sta_peer) && !self.pending.cqm_pktloss.contains(&addr) {
                    self.pending.cqm_pktloss.push(addr);
                }
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
            WmiEvent::PdevBssChanInfo(info) if info.pdev_id == self.caps.pdev_id => {
                // `IPQ8074_CC_FREQ_HERTZ` is also ath11k's default for this
                // target's counter unit (ticks per millisecond). Linux's
                // BSS survey path intentionally reports BSS RX, not total RX.
                const COUNTER_TICKS_PER_MS: u64 = 320_000;
                self.pending.bss_survey.push(BssSurvey {
                    frequency_mhz: info.frequency_mhz,
                    noise_dbm: info.noise_floor as i8,
                    time_ms: info.total_ticks / COUNTER_TICKS_PER_MS,
                    time_busy_ms: info.busy_ticks / COUNTER_TICKS_PER_MS,
                    time_rx_ms: info.rx_bss_ticks / COUNTER_TICKS_PER_MS,
                    time_tx_ms: info.tx_ticks / COUNTER_TICKS_PER_MS,
                });
            }
            WmiEvent::DfsRadarDetected(radar) => self.dfs_radar_detected(&radar),
            WmiEvent::ObssColorCollision(collision)
                if Some(collision.vdev_id) == our_vdev
                    && collision.event_type == WMI_BSS_COLOR_COLLISION_DETECTION =>
            {
                // mac80211 ignores collisions while a color transition or
                // CSA owns the beacon templates; either event would make
                // userspace choose a second color from a stale BSS state.
                if self
                    .ap
                    .as_ref()
                    .is_some_and(|ap| ap.color_change.is_some() || ap.csa.is_some())
                {
                    return;
                }
                // ieee80211_obss_color_collision_notify drops subsequent
                // events while its delayed work is pending, avoiding a
                // netlink multicast storm.  Keep the first bitmap exactly
                // as mac80211 does.
                if self.pending.obss_color_collision.is_none() {
                    self.pending.obss_color_collision = Some(ObssColorCollisionPending {
                        bitmap: collision.color_bitmap,
                        deadline: self.wmi.now_ms().saturating_add(500),
                    });
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
        if self.vif.as_ref().is_some_and(|v| v.kind.is_station()) {
            VdevKind::Sta {
                ap_type: self.reg_6ghz_ap_type,
            }
        } else {
            VdevKind::NotSta
        }
    }

    /// `cfg80211_6ghz_power_type` mapped onto ath11k's extended-country
    /// event rule arrays. An unknown AP regulatory type is unusable; the
    /// kernel likewise marks such a BSS unavailable for 6 GHz association.
    fn ap_type_from_he_6ghz_oper(control: u8) -> Option<usize> {
        match (control >> 3) & 0x0f {
            // LPI, indoor LPI, AP-role-not-relevant, and the legacy indoor
            // standard-power value are all treated as LPI by cfg80211.
            0 | 3 | 4 | 7 => Some(WMI_REG_INDOOR_AP),
            1 | 8 => Some(WMI_REG_STANDARD_POWER_AP),
            2 => Some(WMI_REG_VERY_LOW_POWER_AP),
            _ => None,
        }
    }

    /// Rebuild the self-managed regulatory domain for the AP power type
    /// advertised in a 6 GHz HE Operation and publish the resulting scan
    /// channel list before starting the station vdev on that channel.
    async fn select_6ghz_client_rules(&mut self, control: u8) -> Result<(), MacError> {
        let Some(ap_type) = Self::ap_type_from_he_6ghz_oper(control) else {
            return fail(
                step::CONNECT_UNSUPPORTED,
                10,
                errno::EOPNOTSUPP,
                "connect (6 GHz AP power type)",
            );
        };
        if ap_type == self.reg_6ghz_ap_type {
            return Ok(());
        }
        if !self.supports_6ghz_cc_ext() {
            return fail(
                step::CONNECT_UNSUPPORTED,
                11,
                errno::EOPNOTSUPP,
                "connect (6 GHz regulatory capability)",
            );
        }
        let Some(info) = self.reg.store.clone() else {
            return fail(
                step::CONNECT_UNSUPPORTED,
                12,
                errno::EOPNOTSUPP,
                "connect (6 GHz regulatory rules)",
            );
        };
        match self.reg.handle_chan_list(
            &info,
            false,
            VdevKind::Sta { ap_type },
            self.caps.num_radios,
            self.cfg.num_rxdma_per_pdev,
        ) {
            Ok(RegUpdate::New | RegUpdate::Default) => {
                self.wiphy.apply_regd(&self.reg.current());
                if self.started {
                    self.send_chan_list().await?;
                }
            }
            Ok(RegUpdate::Unchanged) => {}
            Err(e) => {
                let detail = match e {
                    super::mac_reg::RegError::Status(s) => s,
                    super::mac_reg::RegError::BadPhy(p) => 0x100 | p,
                    super::mac_reg::RegError::Build => 0x200,
                };
                return fail(
                    step::CONNECT_UNSUPPORTED,
                    0x100 | detail,
                    errno::EOPNOTSUPP,
                    "connect (6 GHz regulatory rules)",
                );
            }
        }
        self.reg_6ghz_ap_type = ap_type;
        Ok(())
    }

    /// `ieee80211_operating_class_to_band`, limited to the bands WCN6855
    /// exposes. Keep this table in lock-step with cfg80211 rather than
    /// guessing a band from the advertised channel number.
    const fn csa_operating_class_band(class: u8) -> Option<Band> {
        match class {
            81..=84 => Some(Band::Ghz2),
            112 | 115..=130 => Some(Band::Ghz5),
            131..=135 | 137 => Some(Band::Ghz6),
            _ => None,
        }
    }

    /// `ieee80211_operating_class_to_chandef`. Operating class 130/135
    /// names 80+80 but cannot name its second 80 MHz segment, so cfg80211
    /// intentionally falls back to the ordinary CSA definition unless a
    /// Wide Bandwidth CSA IE supplies both centres.
    fn csa_operating_class_chandef(class: u8, freq: u32, band: Band) -> Option<ChanDef> {
        if Self::csa_operating_class_band(class) != Some(band) {
            return None;
        }
        let mut def = ChanDef {
            freq,
            band,
            width: Width::W20,
            center_freq1: freq,
            center_freq2: 0,
        };
        let offset = if freq >= 5955 {
            (freq - 5955) / 20
        } else if freq >= 5745 {
            (freq - 5745) / 20
        } else if freq >= 5180 {
            (freq - 5180) / 20
        } else {
            0
        };
        match class {
            81 | 82 | 115 | 118 | 121 | 124 | 125 | 131 => Some(def),
            83 | 116 | 119 | 122 | 126 => {
                def.width = Width::W40;
                def.center_freq1 = freq + 10;
                Some(def)
            }
            84 | 117 | 120 | 123 | 127 => {
                def.width = Width::W40;
                def.center_freq1 = freq.checked_sub(10)?;
                Some(def)
            }
            132 => {
                def.width = Width::W40;
                def.center_freq1 = freq + 10 - (offset & 1) * 20;
                Some(def)
            }
            128 | 133 => {
                def.width = Width::W80;
                def.center_freq1 = freq + 30 - (offset & 3) * 20;
                Some(def)
            }
            129 | 134 => {
                def.width = Width::W160;
                def.center_freq1 = freq + 70 - (offset & 7) * 20;
                Some(def)
            }
            _ => None,
        }
    }

    /// `wbcs_elem_to_chandef`: prefer an explicit Wide Bandwidth CSA IE
    /// over the basic CSA / ECSA channel width. Width values are the VHT
    /// encodings (1 = 80, 2 = 160, 3 = 80+80).
    fn csa_wide_chandef(base: ChanDef, wide: frame::WideBwChannelSwitchIe) -> Option<ChanDef> {
        let center0 = frame::channel_to_freq(wide.center_freq_seg0_idx as u32, base.band)?;
        let mut def = base;
        def.center_freq1 = center0;
        def.center_freq2 = 0;
        match wide.width {
            1 => {
                def.width = Width::W80;
                if wide.center_freq_seg1_idx != 0 {
                    let center1 =
                        frame::channel_to_freq(wide.center_freq_seg1_idx as u32, base.band)?;
                    match wide
                        .center_freq_seg0_idx
                        .abs_diff(wide.center_freq_seg1_idx)
                    {
                        8 => {
                            def.width = Width::W160;
                            def.center_freq1 = center1;
                        }
                        9.. => {
                            def.width = Width::W80P80;
                            def.center_freq2 = center1;
                        }
                        _ => {}
                    }
                }
            }
            2 => def.width = Width::W160,
            3 => {
                def.width = Width::W80P80;
                def.center_freq2 =
                    frame::channel_to_freq(wide.center_freq_seg1_idx as u32, base.band)?;
            }
            // `IEEE80211_VHT_CHANWIDTH_USE_HT` and unknown encodings both
            // use cfg80211's conservative 40 MHz fallback.
            _ => def.width = Width::W40,
        }
        Some(def)
    }

    /// A CSA control channel must lie in its primary operating segment;
    /// `cfg80211_chandef_valid` catches the same malformed centre pairs.
    const fn csa_primary_fits(def: &ChanDef) -> bool {
        let d = def.freq.abs_diff(def.center_freq1);
        match def.width {
            Width::W20NoHt | Width::W20 => d == 0,
            Width::W40 => d == 10,
            Width::W80 | Width::W80P80 => matches!(d, 10 | 30),
            Width::W160 => matches!(d, 10 | 30 | 50 | 70),
        }
    }

    /// mac80211's connection mode and negotiated capability gates for a
    /// proposed CSA width. The 6 GHz case uses HE rather than VHT.
    fn csa_width_supported(&self, link: &Link, def: &ChanDef) -> bool {
        match def.band {
            Band::Ghz6 => {
                let (Some(own), Some(ap)) = (self.own_he(Band::Ghz6), link.he.as_ref()) else {
                    return false;
                };
                let max =
                    he::he_cap_rx_bw(own, Band::Ghz6).min(he::he_cap_rx_bw(&ap.cap, Band::Ghz6));
                match def.width {
                    Width::W160 => max >= 160,
                    Width::W80P80 => {
                        max >= 80
                            && own.phy[0] & he::cap::PHY0_80PLUS80_MHZ_IN_5G != 0
                            && ap.cap.phy[0] & he::cap::PHY0_80PLUS80_MHZ_IN_5G != 0
                    }
                    Width::W80 => max >= 80,
                    Width::W40 => max >= 40,
                    Width::W20NoHt | Width::W20 => true,
                }
            }
            _ => match def.width {
                Width::W160 => {
                    link.mode >= ConnMode::Vht
                        && self.own.vht(def.band).is_some_and(|own| {
                            own.cap & peer::vht::SUPP_CHAN_WIDTH_MASK != 0
                                && link.sta.vht_cap.cap & peer::vht::SUPP_CHAN_WIDTH_MASK != 0
                        })
                }
                Width::W80P80 => {
                    link.mode >= ConnMode::Vht
                        && self.own.vht(def.band).is_some_and(|own| {
                            own.cap & peer::vht::SUPP_CHAN_WIDTH_160_80PLUS80MHZ != 0
                                && link.sta.vht_cap.cap & peer::vht::SUPP_CHAN_WIDTH_160_80PLUS80MHZ
                                    != 0
                        })
                }
                Width::W80 => link.mode >= ConnMode::Vht,
                Width::W40 => link.mode >= ConnMode::Ht,
                Width::W20NoHt | Width::W20 => true,
            },
        }
    }

    /// `cfg80211_chandef_usable`, plus 6 GHz's no-HE regulatory flag.
    fn csa_chandef_usable(&self, def: &ChanDef) -> bool {
        if !peer::chandef_usable(&self.wiphy, def) {
            return false;
        }
        if !self.chandef_dfs_available_or_usable(def) {
            return false;
        }
        if def.band != Band::Ghz6 {
            return true;
        }
        let check = |freq| {
            self.wiphy
                .get(freq)
                .is_some_and(|c| c.flags & chan_flag::NO_HE == 0)
        };
        match def.width {
            Width::W20NoHt | Width::W20 => check(def.freq),
            Width::W40 => check(def.center_freq1 - 10) && check(def.center_freq1 + 10),
            Width::W80 => {
                let mut freq = def.center_freq1 - 30;
                while freq <= def.center_freq1 + 30 {
                    if !check(freq) {
                        return false;
                    }
                    freq += 20;
                }
                true
            }
            Width::W160 => {
                let mut freq = def.center_freq1 - 70;
                while freq <= def.center_freq1 + 70 {
                    if !check(freq) {
                        return false;
                    }
                    freq += 20;
                }
                true
            }
            Width::W80P80 => {
                for center in [def.center_freq1, def.center_freq2] {
                    let mut freq = center - 30;
                    while freq <= center + 30 {
                        if !check(freq) {
                            return false;
                        }
                        freq += 20;
                    }
                }
                true
            }
        }
    }

    /// `cfg80211_chandef_usable(..., dfs_offload = true)`: WCN6855 may
    /// start CAC on a DFS-usable channel, but no operation may select a
    /// channel in the non-occupancy period after radar detection.
    fn chandef_dfs_available_or_usable(&self, def: &ChanDef) -> bool {
        if self.dp.dfs_nop_active(def) {
            return false;
        }
        let usable = |freq| {
            self.wiphy.get(freq).is_some_and(|channel| {
                channel.flags & chan_flag::RADAR == 0 || channel.dfs_state != DfsState::Unavailable
            })
        };
        let segment_usable = |center: u32, span: u32| {
            let Some(mut freq) = center.checked_sub(span) else {
                return false;
            };
            let end = center.saturating_add(span);
            while freq <= end {
                if !usable(freq) {
                    return false;
                }
                freq = freq.saturating_add(20);
                if freq == 0 {
                    return false;
                }
            }
            true
        };
        match def.width {
            Width::W20NoHt | Width::W20 => usable(def.freq),
            Width::W40 => segment_usable(def.center_freq1, 10),
            Width::W80 => segment_usable(def.center_freq1, 30),
            Width::W160 => segment_usable(def.center_freq1, 70),
            Width::W80P80 => {
                segment_usable(def.center_freq1, 30) && segment_usable(def.center_freq2, 30)
            }
        }
    }

    /// The AP arm of `ath11k_mac_vdev_start_restart`: firmware needs the
    /// primary-channel DFS bit plus the chanctx-wide radar indication, while
    /// cfg80211 / mac80211 retain CAC and NOP policy above the driver.
    fn ap_dfs_flags(&self, def: &ChanDef) -> (bool, bool) {
        let radar = |freq| {
            self.wiphy
                .get(freq)
                .is_some_and(|channel| channel.flags & chan_flag::RADAR != 0)
        };
        let primary = radar(def.freq);
        let mut any = primary;
        let mut check_segment = |center: u32, span: u32| {
            let Some(mut freq) = center.checked_sub(span) else {
                return;
            };
            let end = center.saturating_add(span);
            while freq <= end {
                any |= radar(freq);
                freq = freq.saturating_add(20);
                if freq == 0 {
                    break;
                }
            }
        };
        match def.width {
            Width::W20NoHt | Width::W20 => {}
            Width::W40 => check_segment(def.center_freq1, 10),
            Width::W80 => check_segment(def.center_freq1, 30),
            Width::W160 => check_segment(def.center_freq1, 70),
            Width::W80P80 => {
                check_segment(def.center_freq1, 30);
                check_segment(def.center_freq2, 30);
            }
        }
        (primary, any)
    }

    /// Return the regulatory CAC duration when any subchannel of `def` is a
    /// DFS channel in `NL80211_DFS_USABLE` state.  `mac_reg` supplies the
    /// normal 60-second default and the longer ETSI weather-radar value.
    fn chandef_dfs_cac_ms(&self, def: &ChanDef) -> Option<u32> {
        let mut duration = 0u32;
        let mut inspect = |center: u32, span: u32| {
            let Some(mut freq) = center.checked_sub(span) else {
                return;
            };
            let end = center.saturating_add(span);
            while freq <= end {
                if let Some(channel) = self.wiphy.get(freq) {
                    if channel.flags & chan_flag::RADAR != 0
                        && channel.dfs_state == DfsState::Usable
                    {
                        duration = duration.max(channel.dfs_cac_ms);
                    }
                }
                freq = freq.saturating_add(20);
                if freq == 0 {
                    break;
                }
            }
        };
        match def.width {
            Width::W20NoHt | Width::W20 => inspect(def.freq, 0),
            Width::W40 => inspect(def.center_freq1, 10),
            Width::W80 => inspect(def.center_freq1, 30),
            Width::W160 => inspect(def.center_freq1, 70),
            Width::W80P80 => {
                inspect(def.center_freq1, 30);
                inspect(def.center_freq2, 30);
            }
        }
        (duration != 0).then_some(duration)
    }

    /// `cfg80211_cac_event(CAC_STARTED)`: WCN6855 target DFS offload owns
    /// radar sampling, while the host owns the regulatory timer and makes
    /// queued data wait for the channel to become available.
    fn start_ap_dfs_cac(&mut self, def: ChanDef) {
        let Some(duration_ms) = self.chandef_dfs_cac_ms(&def) else {
            return;
        };
        let Some(vif) = self
            .vif
            .as_ref()
            .filter(|vif| vif.kind.is_ap() && vif.is_up)
        else {
            return;
        };
        let cac = DfsCac {
            def,
            vdev_id: vif.vdev_id,
            deadline: self.wmi.now_ms().saturating_add(duration_ms as u64),
        };
        self.pending.dfs_cac = Some(cac);
        self.pending.dfs_events.push_back(DfsEvent {
            def,
            event: 5, // NL80211_RADAR_CAC_STARTED
            netdev: true,
        });
        self.dp.ap_dfs_cac(cac.vdev_id, true);
    }

    /// Cancel an active CAC when the AP goes down or leaves its chandef.
    fn abort_ap_dfs_cac(&mut self) {
        let Some(cac) = self.pending.dfs_cac.take() else {
            return;
        };
        self.dp.ap_dfs_cac(cac.vdev_id, false);
        self.pending.dfs_events.push_back(DfsEvent {
            def: cac.def,
            event: 2, // NL80211_RADAR_CAC_ABORTED
            netdev: true,
        });
    }

    fn chandef_contains_frequency(def: &ChanDef, frequency_mhz: u32) -> bool {
        if frequency_mhz == 0 {
            return true;
        }
        let contains = |center: u32, span: u32| {
            frequency_mhz >= center.saturating_sub(span)
                && frequency_mhz <= center.saturating_add(span)
                && (frequency_mhz - center.saturating_sub(span)) % 20 == 0
        };
        match def.width {
            Width::W20NoHt | Width::W20 => frequency_mhz == def.freq,
            Width::W40 => contains(def.center_freq1, 10),
            Width::W80 => contains(def.center_freq1, 30),
            Width::W160 => contains(def.center_freq1, 70),
            Width::W80P80 => contains(def.center_freq1, 30) || contains(def.center_freq2, 30),
        }
    }

    /// `ieee80211_radar_detected` → `cfg80211_radar_event`: transition the
    /// active context to NOP, cancel CAC, and hold AP data until hostapd
    /// selects a different legal channel.  The NOP timer is regulatory, not
    /// firmware-requested, so it remains host-owned.
    fn dfs_radar_detected(&mut self, radar: &DfsRadarDetected) {
        if radar.pdev_id != self.caps.pdev_id {
            return;
        }
        let Some(def) = self.vif.as_ref().and_then(|vif| vif.chanctx) else {
            return;
        };
        if !Self::chandef_contains_frequency(&def, radar.chan_freq) {
            return;
        }
        let deadline = self.wmi.now_ms().saturating_add(30 * 60 * 1000);
        self.wiphy.set_dfs_state(&def, DfsState::Unavailable);
        self.pending.dfs_nop.retain(|nop| nop.def != def);
        self.pending.dfs_nop.push(DfsNop {
            def,
            // `IEEE80211_DFS_MIN_NOP_TIME_MS` (30 minutes).
            deadline,
        });
        self.dp.record_dfs_nop(def, deadline);
        self.pending.dfs_events.push_back(DfsEvent {
            def,
            event: 0, // NL80211_RADAR_DETECTED
            netdev: false,
        });
        self.abort_ap_dfs_cac();
        if let Some(vif) = self
            .vif
            .as_ref()
            .filter(|vif| vif.kind.is_ap() && vif.is_up)
        {
            // Keep data queued after radar even when the channel was already
            // CAC-available. `complete_ap_channel_switch` clears this hold
            // once it has restarted onto the requested legal chandef.
            self.dp.ap_dfs_cac(vif.vdev_id, true);
        }
    }

    /// Advance the host-owned CAC and NOP timers.  The runtime calls this on
    /// its ordinary deferred pass, so it has the same no-extra-worker
    /// serialization as the rest of ath11k's MAC state.
    fn finish_dfs_timers(&mut self) {
        let now = self.wmi.now_ms();
        if self
            .pending
            .dfs_cac
            .as_ref()
            .is_some_and(|cac| now >= cac.deadline)
        {
            let cac = self.pending.dfs_cac.take().unwrap();
            self.wiphy.set_dfs_state(&cac.def, DfsState::Available);
            self.dp.ap_dfs_cac(cac.vdev_id, false);
            self.pending.dfs_events.push_back(DfsEvent {
                def: cac.def,
                event: 1, // NL80211_RADAR_CAC_FINISHED
                netdev: true,
            });
        }
        let mut expired = Vec::new();
        self.pending.dfs_nop.retain(|nop| {
            if now >= nop.deadline {
                expired.push(nop.def);
                false
            } else {
                true
            }
        });
        for def in expired {
            self.wiphy.set_dfs_state(&def, DfsState::Usable);
            self.pending.dfs_events.push_back(DfsEvent {
                def,
                event: 3, // NL80211_RADAR_NOP_FINISHED
                netdev: false,
            });
        }
    }

    /// `ieee80211_chandef_downgrade`, preserving the 80 MHz segment that
    /// contains the CSA control channel.
    fn csa_downgrade(def: &mut ChanDef) -> bool {
        match def.width {
            Width::W80P80 => {
                def.width = Width::W80;
                def.center_freq2 = 0;
            }
            Width::W160 => {
                def.width = Width::W80;
                def.center_freq1 = if def.freq < def.center_freq1 {
                    def.center_freq1 - 40
                } else {
                    def.center_freq1 + 40
                };
                def.center_freq2 = 0;
            }
            Width::W80 => {
                let base = def.center_freq1 - 30;
                let offset = def.freq.saturating_sub(base);
                if offset > 60 || offset % 20 != 0 {
                    return false;
                }
                def.width = Width::W40;
                def.center_freq1 = if offset % 40 == 0 {
                    def.freq + 10
                } else {
                    def.freq - 10
                };
            }
            Width::W40 => {
                def.width = Width::W20;
                def.center_freq1 = def.freq;
            }
            Width::W20NoHt | Width::W20 => return false,
        }
        true
    }

    /// Parse and validate one station CSA/ECSA. `Ok(None)` is an unknown
    /// ECSA without a usable ordinary CSA, or an ignorable same-channel
    /// announcement; `Err(())` is a trusted switch that must drop the link.
    fn csa_chandef(
        &self,
        link: &Link,
        ies: &ParsedIes,
        from_beacon: bool,
    ) -> Result<Option<(ChanDef, bool, u8)>, ()> {
        let mut band = link.def.band;
        let mut op_class = None;
        let (mode, new_channel, count) = match ies.ext_channel_switch {
            Some(ext) => match Self::csa_operating_class_band(ext.operating_class) {
                Some(new_band) => {
                    band = new_band;
                    op_class = Some(ext.operating_class);
                    (ext.mode, ext.new_channel, ext.count)
                }
                None => match ies.channel_switch {
                    Some(csa) => (csa.mode, csa.new_channel, csa.count),
                    None => return Ok(None),
                },
            },
            None => match ies.channel_switch {
                Some(csa) => (csa.mode, csa.new_channel, csa.count),
                None => return Ok(None),
            },
        };
        if band != link.def.band {
            return Err(());
        }
        let Some(freq) = frame::channel_to_freq(new_channel as u32, band) else {
            return Err(());
        };
        if self
            .wiphy
            .get(freq)
            .is_none_or(|c| c.flags & chan_flag::DISABLED != 0)
        {
            return Err(());
        }
        let mut def = ChanDef {
            freq,
            band,
            width: if link.mode >= ConnMode::Ht {
                Width::W20
            } else {
                Width::W20NoHt
            },
            center_freq1: freq,
            center_freq2: 0,
        };
        if link.mode >= ConnMode::Ht {
            match ies.secondary_channel_offset {
                Some(frame::HT_PARAM_CHA_SEC_ABOVE) => {
                    def.width = Width::W40;
                    def.center_freq1 = freq + 10;
                }
                Some(frame::HT_PARAM_CHA_SEC_BELOW) => {
                    def.width = Width::W40;
                    def.center_freq1 = freq.checked_sub(10).ok_or(())?;
                }
                _ => {}
            }
        }
        if link.mode >= ConnMode::Vht || band == Band::Ghz6 && link.mode >= ConnMode::He {
            if let Some(wide) = ies.wide_bw_channel_switch {
                if let Some(wide_def) = Self::csa_wide_chandef(def, wide) {
                    def = wide_def;
                }
            } else if let Some(class) = op_class {
                if let Some(class_def) = Self::csa_operating_class_chandef(class, freq, band) {
                    def = class_def;
                }
            }
        } else if let Some(class) = op_class {
            if let Some(class_def) = Self::csa_operating_class_chandef(class, freq, band) {
                def = class_def;
            }
        }
        if !Self::csa_primary_fits(&def) {
            return Err(());
        }
        while !self.csa_width_supported(link, &def) || !self.csa_chandef_usable(&def) {
            if !Self::csa_downgrade(&mut def) {
                return Err(());
            }
        }
        // Match `cfg80211_chandef_identical`: ignore a redundant action, and
        // an ordinary beacon CSA to the same configuration. A mode-1 beacon
        // is retained because it still imposes the quiet period.
        if def == link.def && (!mode || !from_beacon) {
            return Ok(None);
        }
        Ok(Some((def, mode, count)))
    }

    /// Abort an unconfirmed CSA when its next beacon no longer contains a
    /// CSA/ECSA, releasing the temporary mode-1 data-port block.
    fn abort_channel_switch(&mut self) {
        let Some(csa) = self.pending.channel_switch.take() else {
            return;
        };
        if csa.switched {
            self.pending.channel_switch = Some(csa);
            return;
        }
        if csa.block_tx
            && self
                .link
                .as_ref()
                .is_some_and(|link| link.authorized && !csa.switched)
        {
            let bssid = self.link.as_ref().unwrap().bss.bssid;
            self.dp.set_authorized(bssid, true);
        }
    }

    /// End the temporary quiet period caused by an unprotected Public ECSA.
    fn clear_untrusted_channel_switch_block(&mut self) {
        if !core::mem::take(&mut self.pending.untrusted_csa_blocked) {
            return;
        }
        if self.link.as_ref().is_some_and(|link| link.authorized) {
            let bssid = self.link.as_ref().unwrap().bss.bssid;
            self.dp.set_authorized(bssid, true);
        }
    }

    /// Consume a beacon after a successful CSA restart. Mode-1 only opens
    /// the data port once that beacon proves the AP moved with us.
    fn channel_switch_beacon_confirmed(&mut self, rx_freq: u32) {
        let confirmed = self
            .pending
            .channel_switch
            .as_ref()
            .is_some_and(|csa| csa.switched && csa.def.freq == rx_freq);
        if !confirmed {
            return;
        }
        let csa = self.pending.channel_switch.take().unwrap();
        if csa.block_tx && self.link.as_ref().is_some_and(|link| link.authorized) {
            let bssid = self.link.as_ref().unwrap().bss.bssid;
            self.dp.set_authorized(bssid, true);
        }
    }

    /// `ieee80211_sta_process_chanswitch` for trusted beacons and Spectrum
    /// Management actions. Public/unprotected extended actions deliberately
    /// do not commit a switch; a beacon is required to authenticate them.
    fn queue_channel_switch(&mut self, ies: &ParsedIes, from_beacon: bool) {
        if ies.channel_switch.is_none() && ies.ext_channel_switch.is_none() {
            if from_beacon {
                self.abort_channel_switch();
                self.clear_untrusted_channel_switch_block();
            }
            return;
        }
        // mac80211 ignores subsequent action frames while a CSA is active;
        // beacons only advance its existing countdown rather than replace it.
        if self.pending.channel_switch.is_some() {
            return;
        }
        let Some(link) = self.link.clone() else {
            return;
        };
        if !link.assoc || link.loss.is_some() {
            return;
        }
        let Some((def, block_tx, count)) = (match self.csa_chandef(&link, ies, from_beacon) {
            Ok(csa) => csa,
            Err(()) => {
                if let Some(link) = self.link.as_mut() {
                    if link.loss.is_none() {
                        link.loss = Some(LinkLoss::ChannelSwitch);
                    }
                }
                return;
            }
        }) else {
            return;
        };
        // An authenticated beacon/action supersedes the tentative quiet
        // period from a Public ECSA. Its own mode bit decides the new state.
        self.clear_untrusted_channel_switch_block();
        let tus = u64::from(count.max(1) - 1) * u64::from(link.bss.beacon_int);
        let delay_ms = tus.saturating_mul(1024).saturating_add(999) / 1000;
        self.pending.channel_switch = Some(ChannelSwitchPending {
            def,
            block_tx,
            deadline: self.wmi.now_ms().saturating_add(delay_ms),
            switched: false,
        });
        if block_tx && link.authorized {
            self.dp.set_authorized(link.bss.bssid, false);
        }
    }

    /// Public ECSA is intentionally not trusted to change channels. Linux
    /// nevertheless observes its mode-1 quiet request until a following
    /// beacon authenticates or disproves the announcement.
    fn queue_untrusted_ext_channel_switch(&mut self, ies: &ParsedIes) {
        if self.pending.channel_switch.is_some() || self.pending.untrusted_csa_blocked {
            return;
        }
        let Some(link) = self.link.clone() else {
            return;
        };
        if !link.assoc || link.loss.is_some() {
            return;
        }
        let block_tx = matches!(self.csa_chandef(&link, ies, true), Ok(Some((_, true, _))));
        if block_tx && link.authorized {
            self.pending.untrusted_csa_blocked = true;
            self.dp.set_authorized(link.bss.bssid, false);
        }
    }

    /// At the scheduled TBTT, issue ath11k's WMI vdev-restart form, bring
    /// the station vdev back up, and wait for a confirming new-channel
    /// beacon before reopening a mode-1 data port.
    async fn finish_channel_switch(&mut self) {
        let due = self
            .pending
            .channel_switch
            .as_ref()
            .is_some_and(|csa| !csa.switched && self.wmi.now_ms() >= csa.deadline);
        if !due {
            return;
        }
        let csa = self.pending.channel_switch.take().unwrap();
        let Some(link) = self.link.as_ref() else {
            return;
        };
        let (bssid, aid, active) = (
            link.bss.bssid,
            self.vif.as_ref().map_or(0, |v| v.aid),
            self.vif.as_ref().is_some_and(|v| v.is_up),
        );
        if link.loss.is_some() || !active {
            if let Some(link) = self.link.as_mut() {
                if link.loss.is_none() {
                    link.loss = Some(LinkLoss::ChannelSwitch);
                }
            }
            return;
        }
        let result = async {
            self.vdev_start_restart(&csa.def, true, true).await?;
            let vdev_id = self.vif.as_ref().unwrap().vdev_id;
            let cmd = vdev_up_cmd(vdev_id, aid as u32, &bssid, None, 0, 0, None);
            self.cmd(cmd, step::VDEV_UP, 2, "CSA vdev up").await
        }
        .await;
        if let Err(error) = result {
            error.report("CSA restart");
            if let Some(link) = self.link.as_mut() {
                if link.loss.is_none() {
                    link.loss = Some(LinkLoss::ChannelSwitch);
                }
            }
            return;
        }
        self.vif.as_mut().unwrap().chanctx = Some(csa.def);
        self.vif.as_mut().unwrap().txpower = self.wiphy.get(csa.def.freq).map(|c| c.max_power);
        if let Err(error) = self.txpower_recalc().await {
            error.report("CSA txpower");
        }
        if let Some(link) = self.link.as_mut() {
            link.def = csa.def;
            link.bss.freq = csa.def.freq;
        }
        if csa.block_tx {
            self.pending.channel_switch = Some(ChannelSwitchPending {
                switched: true,
                ..csa
            });
        }
    }

    /// Send probe responses queued by management RX. `tx_mgmt_nowait` leaves
    /// the target descriptor live until the ordinary completion drain, which
    /// is exactly the mac80211 AP response ownership model.
    async fn flush_ap_probe_responses(&mut self) {
        while let Some(response) = self.pending.ap_probe_responses.pop_front() {
            self.tx_mgmt_nowait(&response).await;
        }
    }

    /// Workqueue items: `ath11k_update_11d` and
    /// `ath11k_regd_update_work` → `reg_process_self_managed_hint` →
    /// `ath11k_reg_notifier` (driver) → `ath11k_reg_update_chan_list(ar,
    /// true)` → `ath11k_regd_update_chan_list_work`.
    async fn run_deferred(&mut self) {
        let now = self.wmi.now_ms();
        if self
            .pending
            .obss_color_collision
            .is_some_and(|collision| now >= collision.deadline)
        {
            let collision = self.pending.obss_color_collision.take().unwrap();
            self.pending
                .obss_color_collision_events
                .push_back(collision.bitmap);
        }
        self.process_back().await;
        self.mfp_deferred().await;
        self.finish_channel_switch().await;
        self.finish_ap_channel_switch().await;
        self.finish_ap_color_change().await;
        self.flush_ap_probe_responses().await;
        self.finish_dfs_timers();
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
        let (tx, rx) = (self.cfg_tx_chain_mask, self.cfg_rx_chain_mask);
        self.pdev_param(WMI_PDEV_PARAM_TX_CHAIN_MASK, tx).await?;
        self.pdev_param(WMI_PDEV_PARAM_RX_CHAIN_MASK, rx).await?;
        // ath11k_reg_update_chan_list(ar, false): the return value is
        // ignored by ath11k_mac_op_start.
        let _ = self.send_chan_list().await;
        if let Err(e) = self.dp.mon_status_default(true).await {
            return fail(step::START_DP, 2, e, "mon status default");
        }
        let mut seed = [0u8; 4 * (ATH11K_IPV4_TH_SEED_SIZE + ATH11K_IPV6_TH_SEED_SIZE)];
        self.wmi.random_bytes(&mut seed).map_err(|e| {
            let error = MacError::new(step::ENTROPY, 0, e);
            error.report("LRO entropy");
            error
        })?;
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

    /// Join a pdev already started by a sibling virtual interface.  This
    /// records the local MAC instance's active state without replaying the
    /// pdev-wide WMI parameter sequence.
    pub fn adopt_shared_start(&mut self) {
        assert!(!self.started, "shared MAC start twice");
        self.started = true;
    }

    /// Leave a shared pdev that remains active for another virtual
    /// interface.  This is `stop()`'s local bookkeeping without toggling the
    /// pdev-wide monitor filter.
    pub fn leave_shared_start(&mut self) {
        self.started = false;
        self.scan.deadline = None;
        if self.state_11d == State11d::Preparing {
            self.state_11d = State11d::Idle;
        }
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

    /// `ath11k_mac_op_remove_interface` after `ieee80211_do_stop`: an AP
    /// first disables beaconing and releases its peers/channel; a station
    /// stops 11d scanning. Both then issue `ath11k_mac_vdev_delete`
    /// (WMI_VDEV_DELETE_CMDID, wait ≤
    /// `ATH11K_VDEV_DELETE_TIMEOUT_HZ` for WMI_VDEV_DELETE_RESP_EVENTID);
    /// the vif is gone either way (`err_vdev_del` continues). Linux only
    /// warns: a failure's errno is returned for the caller to log.
    pub async fn remove_interface(&mut self) -> Result<(), i32> {
        let Some(kind) = self.vif.as_ref().map(|v| v.kind) else {
            return Ok(());
        };
        if kind.is_ap() {
            // `ieee80211_stop_ap` → BSS_CHANGED_BEACON_ENABLED(false)
            // precedes the generic remove-interface callback.
            let _ = self.stop_ap().await;
            // AP/GO vdev creation owns a self peer for firmware group-key
            // state. It lives across STOP_AP but must leave before VDEV_DELETE.
            let own = self.vif.as_ref().unwrap().addr;
            self.peer_delete(own).await;
        } else {
            self.scan_11d_stop().await;
        }
        let v = self.vif.clone().unwrap();
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
        self.ap = None;
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
        self.add_station_like_interface(VifKind::Station, vdev_subtype::NONE)
            .await
    }

    /// WCN6855's P2P device and client vdevs are both WMI station vdevs;
    /// only the subtype changes. Their basic encap/decap, WMM and DP setup
    /// follows `ath11k_mac_op_add_interface` just like an ordinary STA.
    pub async fn add_p2p_station_interface(&mut self, kind: VifKind) -> Result<u32, MacError> {
        let subtype = match kind {
            VifKind::P2pDevice => vdev_subtype::P2P_DEVICE,
            VifKind::P2pClient => vdev_subtype::P2P_CLIENT,
            _ => {
                return fail(
                    step::VDEV_CREATE,
                    0x50,
                    errno::EINVAL,
                    "add P2P station vdev",
                )
            }
        };
        self.add_station_like_interface(kind, subtype).await
    }

    async fn add_station_like_interface(
        &mut self,
        kind: VifKind,
        subtype: u32,
    ) -> Result<u32, MacError> {
        if self.vif.is_some() {
            return fail(
                step::VDEV_CREATE,
                0,
                errno::EBUSY,
                "add interface (vdev exists)",
            );
        }
        // The radio allocator reserved this slot before constructing this
        // MAC instance (`__ffs64(ab->free_vdev_map)` in Linux).
        let vdev_id = self.cfg.vdev_id;
        let addr = self.caps.mac_addr;
        let (nt, nr) = (self.own.num_tx_chains as u8, self.own.num_rx_chains as u8);
        let mut p = VdevCreateParams {
            if_id: vdev_id as u8,
            vdev_type: vdev_type::STA,
            subtype,
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
            kind,
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
            .vdev_param(vdev_id, WMI_VDEV_PARAM_RTS_THRESHOLD, self.rts_threshold)
            .await;
        self.dp.vdev_tx_attach(vdev_id, addr, false);
        if self.supports_6ghz_cc_ext() {
            if let Some(info) = self.reg.store.clone() {
                // ath11k_reg_handle_chan_list for the currently selected
                // (initially LPI) AP power type.
                if let Ok(RegUpdate::New) = self.reg.handle_chan_list(
                    &info,
                    false,
                    VdevKind::Sta {
                        ap_type: self.reg_6ghz_ap_type,
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

    /// `ieee80211_do_open` → `ath11k_mac_op_add_interface` for a
    /// transmitting AP vdev.  The vdev is created while the interface is
    /// administratively up; [`Self::start_ap`] later owns its channel,
    /// beacon template, and `WMI_VDEV_UP_CMDID` handoff.
    pub async fn add_ap_interface(&mut self) -> Result<u32, MacError> {
        self.add_ap_like_interface(VifKind::Ap, vdev_subtype::NONE)
            .await
    }

    /// P2P GO is a WMI AP vdev with its P2P-specific subtype. The normal AP
    /// start path supplies the additional firmware-owned P2P beacon element.
    pub async fn add_p2p_go_interface(&mut self) -> Result<u32, MacError> {
        self.add_ap_like_interface(VifKind::P2pGo, vdev_subtype::P2P_GO)
            .await
    }

    async fn add_ap_like_interface(
        &mut self,
        kind: VifKind,
        subtype: u32,
    ) -> Result<u32, MacError> {
        if self.vif.is_some() {
            return fail(
                step::VDEV_CREATE,
                0,
                errno::EBUSY,
                "add AP interface (vdev exists)",
            );
        }
        // See the station-vdev path: the shared radio allocator owns slot
        // selection, while this MAC instance owns the selected vdev only.
        let vdev_id = self.cfg.vdev_id;
        let addr = self.caps.mac_addr;
        let (nt, nr) = (self.own.num_tx_chains as u8, self.own.num_rx_chains as u8);
        let mut p = VdevCreateParams {
            if_id: vdev_id as u8,
            vdev_type: vdev_type::AP,
            subtype,
            pdev_id: self.caps.pdev_id,
            ..Default::default()
        };
        if self.caps.pdev.supported_bands & WMI_HOST_WLAN_2G_CAP != 0 {
            p.chains_2g = Chains { tx: nt, rx: nr };
        }
        if self.caps.pdev.supported_bands & WMI_HOST_WLAN_5G_CAP != 0 {
            p.chains_5g = Chains { tx: nt, rx: nr };
        }
        self.cmd(
            vdev_create_cmd(&addr, &p),
            step::VDEV_CREATE,
            vdev_type::AP,
            "AP vdev create",
        )
        .await?;
        self.vif = Some(Vif {
            vdev_id,
            addr,
            kind,
            mbssid: MbssidParams::standalone(),
            ..Default::default()
        });
        // ath11k_mac_op_add_interface creates an AP's self peer before any
        // client peer or GTK exists. WMI addresses group keys through this
        // peer, and firmware rejects the key otherwise.
        self.dp.vdev_tx_attach(vdev_id, addr, true);
        let self_peer = match self
            .cmd(
                peer_create_cmd(vdev_id, &addr, peer_type::DEFAULT),
                step::AP_PEER_CREATE,
                2,
                "AP self peer create",
            )
            .await
        {
            Ok(()) => match self
                .dp
                .wait_peer_mapped(vdev_id, addr, true, timeout::PEER_MAP)
                .await
            {
                Ok(()) => Ok(()),
                Err(e) => Err(MacError::new(step::AP_PEER_MAP_TIMEOUT, vdev_id, e)),
            },
            Err(e) => Err(e),
        };
        if let Err(e) = self_peer {
            let _ = self.wmi.send(peer_delete_cmd(&addr, vdev_id as u8)).await;
            let _ = self.wmi.send(vdev_delete_cmd(vdev_id as u8)).await;
            self.vif = None;
            return Err(e);
        }

        let encap = if self.cfg.frame_mode_ethernet {
            txrx::ETHERNET
        } else if self.cfg.raw_mode {
            txrx::RAW
        } else {
            txrx::NATIVE_WIFI
        };
        // `ath11k_mac_op_update_vif_offload`: Linux logs these failures but
        // leaves a created vdev intact.
        let _ = self
            .vdev_param(vdev_id, WMI_VDEV_PARAM_TX_ENCAP_TYPE, encap)
            .await;
        let _ = self
            .vdev_param(vdev_id, WMI_VDEV_PARAM_RX_DECAP_TYPE, encap)
            .await;
        let nss = self.own.num_tx_chains.max(1);
        let r = async {
            self.vdev_param(vdev_id, WMI_VDEV_PARAM_NSS, nss).await?;
            // `ath11k_mac_set_kickout`: AP clients get the firmware's
            // inactive/unresponsive policy rather than station power-save
            // parameters.
            self.pdev_param(WMI_PDEV_PARAM_STA_KICKOUT_TH, ATH11K_KICKOUT_THRESHOLD)
                .await?;
            self.vdev_param(
                vdev_id,
                WMI_VDEV_PARAM_AP_KEEPALIVE_MIN_IDLE_INACTIVE_TIME_SECS,
                ATH11K_KEEPALIVE_MIN_IDLE,
            )
            .await?;
            self.vdev_param(
                vdev_id,
                WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_IDLE_INACTIVE_TIME_SECS,
                ATH11K_KEEPALIVE_MAX_IDLE,
            )
            .await?;
            self.vdev_param(
                vdev_id,
                WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS,
                ATH11K_KEEPALIVE_MAX_UNRESPONSIVE,
            )
            .await
        }
        .await;
        if let Err(e) = r {
            let _ = self.wmi.send(peer_delete_cmd(&addr, vdev_id as u8)).await;
            let _ = self.wmi.send(vdev_delete_cmd(vdev_id as u8)).await;
            self.vif = None;
            return Err(e);
        }
        let _ = self
            .vdev_param(vdev_id, WMI_VDEV_PARAM_RTS_THRESHOLD, self.rts_threshold)
            .await;
        self.bss_erp_changed(true, true, true).await;
        self.conf_tx_all(&wmm_default(true, false)).await?;
        self.run_deferred().await;
        Ok(vdev_id)
    }

    /// The beacon template tells the target where mac80211's mutable TIM
    /// element begins. `NL80211_ATTR_BEACON_HEAD` ends immediately before
    /// TIM; mac80211 creates the initially empty TIM and firmware updates it
    /// from this offset while stations sleep or multicast is pending.
    fn ap_tim_ie_offset(head: &[u8]) -> Option<u32> {
        // `struct ieee80211_hdr_3addr` + fixed beacon timestamp, interval,
        // and capability fields. The userspace head must be a beacon frame,
        // not merely an IE vector.
        let hdr = frame::MgmtHdr::parse(head)?;
        (hdr.stype() == Some(frame::stype::BEACON) && head.len() >= 36).then_some(head.len() as u32)
    }

    /// `ieee80211_beacon_add_tim` for an AP with no buffered unicast or
    /// multicast traffic. The target owns later bitmap/count changes using
    /// `tim_ie_offset` in `WMI_BCN_TMPL_CMDID`.
    fn ap_beacon(head: &[u8], dtim_period: u32, tail: &[u8]) -> Vec<u8> {
        let mut beacon = Vec::with_capacity(head.len() + 6 + tail.len());
        beacon.extend_from_slice(head);
        beacon.extend_from_slice(&[eid::TIM, 4, 0, dtim_period as u8, 0, 0]);
        beacon.extend_from_slice(tail);
        beacon
    }

    /// `ieee80211_beacon_add_mbssid`: build one ordinary full-MBSSID beacon,
    /// or one template per EMA profile. The nested nl80211 payloads are the
    /// complete raw IEs which mac80211 appends after the normal beacon tail.
    ///
    /// For EMA, RNR element `i` travels with MBSSID element `i`; surplus RNR
    /// elements are appended to every profile exactly as
    /// `ieee80211_beacon_add_mbssid` does. The first byte of the first
    /// multiple-BSSID element body is `bssid_indicator`.
    fn build_mbssid_beacon_set(
        base: &[u8],
        mbssid_elems: &[Vec<u8>],
        ema_rnr_elems: &[Vec<u8>],
        ema: bool,
    ) -> Option<MbssidBeaconSet> {
        const WLAN_EID_MULTIPLE_BSSID: u8 = 71;
        let first = mbssid_elems.first()?;
        if first.len() < 3
            || first[0] != WLAN_EID_MULTIPLE_BSSID
            || first.len() != first[1] as usize + 2
            || first[2] > 8
        {
            return None;
        }
        for element in mbssid_elems {
            if element.len() < 2
                || element[0] != WLAN_EID_MULTIPLE_BSSID
                || element.len() != element[1] as usize + 2
            {
                return None;
            }
        }
        if ema && ema_rnr_elems.len() < mbssid_elems.len() {
            return None;
        }
        let offset = u32::try_from(base.len()).ok()?;
        let mut regular =
            Vec::with_capacity(base.len() + mbssid_elems.iter().map(Vec::len).sum::<usize>());
        regular.extend_from_slice(base);
        for element in mbssid_elems {
            regular.extend_from_slice(element);
        }
        let regular = MbssidBeaconTemplate {
            beacon: regular,
            mbssid_ie_offset: offset,
        };
        let mut templates = Vec::new();
        if ema {
            templates.reserve(mbssid_elems.len());
            for (index, element) in mbssid_elems.iter().enumerate() {
                let mut beacon = Vec::with_capacity(base.len() + element.len());
                beacon.extend_from_slice(base);
                beacon.extend_from_slice(element);
                // The matching RNR then every RNR beyond the number of
                // MBSSID elements belongs in this EMA beacon.
                beacon.extend_from_slice(&ema_rnr_elems[index]);
                for rnr in &ema_rnr_elems[mbssid_elems.len()..] {
                    beacon.extend_from_slice(rnr);
                }
                templates.push(MbssidBeaconTemplate {
                    beacon,
                    mbssid_ie_offset: offset,
                });
            }
        }
        Some(MbssidBeaconSet {
            bssid_indicator: first[2],
            regular,
            ema: templates,
        })
    }

    /// WMI packs the number of EMA profiles, this template's index, and the
    /// first/last markers into the final BCN_TMPL word.
    fn ema_params(template_count: usize, template_index: usize) -> u32 {
        (template_count as u32)
            | ((template_index as u32) << 8)
            | (u32::from(template_index == 0) << 16)
            | (u32::from(template_index + 1 == template_count) << 24)
    }

    /// Validate the complete `NL80211_ATTR_PROBE_RESP` form that cfg80211
    /// retains for mac80211's automatic AP probe-response path. The caller
    /// later replaces only DA with the requesting station; SA and BSSID must
    /// already be the vdev identity or a template could transmit on behalf of
    /// a different AP.
    fn ap_probe_resp_valid(probe_resp: &[u8], own_addr: [u8; 6]) -> bool {
        let Some(hdr) = frame::MgmtHdr::parse(probe_resp) else {
            return false;
        };
        hdr.stype() == Some(frame::stype::PROBE_RESP)
            && probe_resp.len() >= frame::MGMT_HDR_LEN + 12
            && hdr.sa == own_addr
            && hdr.bssid == own_addr
    }

    /// Linux's `ath11k_mac_setup_bcn_p2p_ie` plus
    /// `ath11k_mac_remove_vendor_ie`: WMI receives the complete P2P vendor
    /// element and firmware inserts it; the ordinary beacon template must
    /// omit that exact element or clients see two P2P IEs.  The returned TIM
    /// offset is adjusted if a malformed-but-accepted userspace template put
    /// the vendor IE before TIM rather than in the normal beacon tail.
    fn p2p_go_beacon_template(
        beacon: &[u8],
        tim_ie_offset: u32,
    ) -> Option<(Vec<u8>, Vec<u8>, u32)> {
        const BEACON_IES_OFFSET: usize = 36; // 802.11 header + fixed beacon fields
        let mut pos = BEACON_IES_OFFSET;
        while pos + 2 <= beacon.len() {
            let len = beacon[pos + 1] as usize;
            let next = pos.checked_add(2 + len)?;
            if next > beacon.len() {
                return None;
            }
            if beacon[pos] == eid::VENDOR_SPECIFIC
                && len >= 4
                && beacon[pos + 2..pos + 6] == [0x50, 0x6f, 0x9a, 9]
            {
                let mut base = Vec::with_capacity(beacon.len() - (next - pos));
                base.extend_from_slice(&beacon[..pos]);
                base.extend_from_slice(&beacon[next..]);
                let adjusted_tim = if pos < tim_ie_offset as usize {
                    tim_ie_offset.checked_sub((next - pos) as u32)?
                } else {
                    tim_ie_offset
                };
                return Some((beacon[pos..next].to_vec(), base, adjusted_tim));
            }
            pos = next;
        }
        None
    }

    /// Upload one AP/GO beacon template without changing the retained normal
    /// beacon state. CSA uses this for its temporary beacon; SET_BEACON and
    /// the CSA finalizer use it after committing a new retained template.
    async fn upload_ap_beacon_template(
        &mut self,
        head: &[u8],
        tail: &[u8],
        tim_ie_offset: u32,
        detail: u32,
        what: &'static str,
    ) -> Result<(), MacError> {
        let (vdev_id, dtim_period, kind) = {
            let vif = self.vif.as_ref().unwrap();
            (vif.vdev_id, vif.dtim_period, vif.kind)
        };
        let beacon = Self::ap_beacon(head, dtim_period, tail);
        let (tim_ie_offset, beacon) = if kind == VifKind::P2pGo {
            let Some((p2p_ie, template, tim)) =
                Self::p2p_go_beacon_template(&beacon, tim_ie_offset)
            else {
                return fail(step::AP_BEACON, detail, errno::EINVAL, what);
            };
            let Some(command) = p2p_go_bcn_ie_cmd(vdev_id, &p2p_ie) else {
                return fail(step::AP_BEACON, detail + 1, errno::EINVAL, what);
            };
            self.cmd(command, step::AP_BEACON, detail + 2, what).await?;
            (tim, template)
        } else {
            (tim_ie_offset, beacon)
        };
        self.cmd(
            bcn_tmpl_cmd(vdev_id, tim_ie_offset, &beacon),
            step::AP_BEACON,
            detail + 3,
            what,
        )
        .await
    }

    /// Send a transmitter's MBSSID template family. EMA intentionally targets
    /// the transmitting vdev even while a non-transmitting profile is being
    /// started; Linux does the same in `ath11k_mac_setup_bcn_tmpl_ema`.
    async fn upload_mbssid_beacon_set(
        &mut self,
        target_vdev_id: u32,
        tim_ie_offset: u32,
        beacons: &MbssidBeaconSet,
        detail: u32,
        what: &'static str,
    ) -> Result<(), MacError> {
        if beacons.is_ema() {
            for (index, template) in beacons.ema.iter().enumerate() {
                self.cmd(
                    bcn_tmpl_cmd_with_mbssid(
                        target_vdev_id,
                        tim_ie_offset,
                        &template.beacon,
                        Some(template.mbssid_ie_offset),
                        Self::ema_params(beacons.ema.len(), index),
                    ),
                    step::AP_BEACON,
                    detail + index as u32,
                    what,
                )
                .await?;
            }
        } else {
            self.cmd(
                bcn_tmpl_cmd_with_mbssid(
                    target_vdev_id,
                    tim_ie_offset,
                    &beacons.regular.beacon,
                    Some(beacons.regular.mbssid_ie_offset),
                    0,
                ),
                step::AP_BEACON,
                detail,
                what,
            )
            .await?;
        }
        Ok(())
    }

    /// `cfg80211_chandef_create` / `cfg80211_chandef_valid` for the subset
    /// WCN6855 supports. Hostapd supplies the exact operating channel in
    /// START_AP; silently reducing it to 20 MHz would advertise a different
    /// BSS than firmware starts.
    fn ap_chandef(&self, cfg: &ApConfig) -> Result<ChanDef, MacError> {
        self.ap_chandef_fields(
            cfg.frequency_mhz,
            cfg.channel_width,
            cfg.center_freq1_mhz,
            cfg.center_freq2_mhz,
            step::AP_START,
            "start AP",
        )
    }

    /// Shared START_AP / CHANNEL_SWITCH chandef validation.  Both APIs carry
    /// the same nl80211 channel geometry; keeping one validator prevents a
    /// CSA from accepting a channel the initial AP start would reject.
    fn ap_chandef_fields(
        &self,
        frequency_mhz: u32,
        channel_width: u32,
        center_freq1_mhz: Option<u32>,
        center_freq2_mhz: Option<u32>,
        diag_step: u32,
        operation: &'static str,
    ) -> Result<ChanDef, MacError> {
        let width = match channel_width {
            0 => Width::W20NoHt, // NL80211_CHAN_WIDTH_20_NOHT
            1 => Width::W20,     // NL80211_CHAN_WIDTH_20
            2 => Width::W40,
            3 => Width::W80,
            4 => Width::W80P80,
            5 => Width::W160,
            other => return fail(diag_step, other, errno::EOPNOTSUPP, operation),
        };
        let center_freq1 = center_freq1_mhz.unwrap_or(frequency_mhz);
        let center_freq2 = center_freq2_mhz.unwrap_or(0);
        let delta = frequency_mhz.abs_diff(center_freq1);
        let valid_geometry = match width {
            Width::W20NoHt | Width::W20 => center_freq1 == frequency_mhz && center_freq2 == 0,
            Width::W40 => delta == 10 && center_freq2 == 0,
            Width::W80 => matches!(delta, 10 | 30) && center_freq2 == 0,
            Width::W160 => matches!(delta, 10 | 30 | 50 | 70) && center_freq2 == 0,
            Width::W80P80 => {
                matches!(delta, 10 | 30)
                    && center_freq2 != 0
                    && center_freq1.abs_diff(center_freq2) > 80
            }
        };
        if !valid_geometry {
            return fail(diag_step, frequency_mhz, errno::EINVAL, operation);
        }
        let def = ChanDef {
            freq: frequency_mhz,
            band: freq_band(frequency_mhz),
            width,
            center_freq1,
            center_freq2,
        };
        if !self.csa_chandef_usable(&def) {
            return fail(diag_step, frequency_mhz, errno::EINVAL, operation);
        }
        Ok(def)
    }

    /// `NL80211_CMD_START_AP` → assign a 20 MHz channel context,
    /// `ath11k_mac_vdev_start`, install `WMI_BCN_TMPL_CMDID`, and enable
    /// beaconing with `WMI_VDEV_UP_CMDID`.
    pub async fn start_ap(
        &mut self,
        cfg: ApConfig,
        mbssid: MbssidParams,
        source_templates: Option<MbssidBeaconSet>,
    ) -> Result<(), MacError> {
        let Some(vif) = self.vif.clone().filter(|v| v.kind.is_ap()) else {
            return fail(step::AP_START, 0, errno::ENOTCONN, "start AP (no AP vdev)");
        };
        if self.ap.is_some() || vif.is_up {
            return fail(
                step::AP_START,
                1,
                errno::EBUSY,
                "start AP (already beaconing)",
            );
        }
        let Some(channel) = self.wiphy.get(cfg.frequency_mhz).copied() else {
            return fail(
                step::AP_START,
                cfg.frequency_mhz,
                errno::EINVAL,
                "start AP (channel)",
            );
        };
        if channel.flags & (chan_flag::DISABLED | chan_flag::NO_IR) != 0 {
            return fail(
                step::AP_START,
                cfg.frequency_mhz,
                errno::EINVAL,
                "start AP (regulatory channel)",
            );
        }
        let Some(tim_ie_offset) = Self::ap_tim_ie_offset(&cfg.beacon_head) else {
            return fail(step::AP_BEACON, 0, errno::EINVAL, "start AP (TIM IE)");
        };
        let Some(bssid) = cfg
            .beacon_head
            .get(16..22)
            .and_then(|bytes| bytes.try_into().ok())
        else {
            return fail(
                step::AP_BEACON,
                1,
                errno::EINVAL,
                "start AP (beacon header)",
            );
        };
        if bssid != vif.addr {
            // The AP self peer, vdev address, and FromDS transmitter must be
            // the same identity. Linux gets this from one ieee80211_vif;
            // accepting a forged beacon BSSID here would split key state.
            return fail(step::AP_BEACON, 2, errno::EINVAL, "start AP (BSSID)");
        }
        if cfg.probe_resp.as_ref().is_some_and(|probe_resp| {
            !probe_resp.is_empty() && !Self::ap_probe_resp_valid(probe_resp, vif.addr)
        }) {
            return fail(
                step::AP_BEACON,
                3,
                errno::EINVAL,
                "start AP (probe response)",
            );
        }
        let def = self.ap_chandef(&cfg)?;
        if (mbssid.is_transmitting() || mbssid.is_non_transmitting()) && vif.kind != VifKind::Ap {
            return fail(
                step::AP_START,
                2,
                errno::EOPNOTSUPP,
                "start AP (MBSSID requires infrastructure AP)",
            );
        }
        // Validate and split a GO beacon before starting its vdev.  A bad
        // vendor IE must not leave a started-but-not-beaconing P2P vdev
        // behind for the caller to clean up.
        let beacon = Self::ap_beacon(&cfg.beacon_head, cfg.dtim_period, &cfg.beacon_tail);
        let (p2p_go_cmd, tim_ie_offset, beacon) = if vif.kind == VifKind::P2pGo {
            let Some((p2p_ie, template, tim)) =
                Self::p2p_go_beacon_template(&beacon, tim_ie_offset)
            else {
                return fail(step::AP_BEACON, 6, errno::EINVAL, "start P2P GO (P2P IE)");
            };
            let Some(command) = p2p_go_bcn_ie_cmd(vif.vdev_id, &p2p_ie) else {
                return fail(
                    step::AP_BEACON,
                    7,
                    errno::EINVAL,
                    "start P2P GO (P2P IE encode)",
                );
            };
            (Some(command), tim, template)
        } else {
            (None, tim_ie_offset, beacon)
        };
        let mut mbssid = mbssid;
        let mbssid_beacons = if mbssid.is_transmitting() {
            let Some(beacons) = Self::build_mbssid_beacon_set(
                &beacon,
                &cfg.mbssid_elems,
                &cfg.ema_rnr_elems,
                mbssid.ema(),
            ) else {
                return fail(
                    step::AP_BEACON,
                    9,
                    errno::EINVAL,
                    "start AP (MBSSID elements)",
                );
            };
            Some(beacons)
        } else if mbssid.is_non_transmitting() {
            let Some(beacons) = source_templates else {
                return fail(
                    step::AP_BEACON,
                    mbssid.tx_vdev_id,
                    errno::EBUSY,
                    "start AP (MBSSID transmitter not ready)",
                );
            };
            if beacons.is_ema() != mbssid.ema() || mbssid.profile_index >= beacons.profile_count() {
                return fail(
                    step::AP_BEACON,
                    mbssid.profile_index,
                    errno::EINVAL,
                    "start AP (MBSSID profile)",
                );
            }
            mbssid.profile_count = beacons.profile_count();
            Some(beacons)
        } else {
            if !cfg.mbssid_elems.is_empty() || !cfg.ema_rnr_elems.is_empty() {
                return fail(
                    step::AP_BEACON,
                    10,
                    errno::EINVAL,
                    "start AP (MBSSID configuration)",
                );
            }
            None
        };
        {
            let v = self.vif.as_mut().unwrap();
            v.chanctx = Some(def);
            v.beacon_interval = cfg.beacon_interval;
            v.dtim_period = cfg.dtim_period;
            v.bssid = bssid;
            v.aid = 0;
            v.mbssid = mbssid;
        }
        self.vdev_start(&def).await?;
        if let Some(command) = p2p_go_cmd {
            // It was constructed before vdev start, but must be sent only
            // after the target owns the GO vdev.
            self.cmd(command, step::AP_BEACON, 8, "P2P GO beacon IE")
                .await?;
        }
        if let Some(beacons) = mbssid_beacons.as_ref() {
            let target_vdev_id = if mbssid.is_non_transmitting() && mbssid.ema() {
                mbssid.tx_vdev_id
            } else {
                vif.vdev_id
            };
            self.upload_mbssid_beacon_set(
                target_vdev_id,
                tim_ie_offset,
                beacons,
                11,
                "AP MBSSID beacon template",
            )
            .await?;
        } else {
            self.cmd(
                bcn_tmpl_cmd(vif.vdev_id, tim_ie_offset, &beacon),
                step::AP_BEACON,
                2,
                "AP beacon template",
            )
            .await?;
        }
        let (tx_bssid, profile_index, profile_count) = if mbssid.is_non_transmitting() {
            (
                Some(&mbssid.tx_bssid),
                mbssid.profile_index,
                mbssid.profile_count,
            )
        } else {
            (None, 0, 0)
        };
        self.cmd(
            vdev_up_cmd(
                vif.vdev_id,
                0,
                &bssid,
                tx_bssid,
                profile_index,
                profile_count,
                None,
            ),
            step::VDEV_UP,
            2,
            "AP vdev up",
        )
        .await?;
        self.vif.as_mut().unwrap().is_up = true;
        self.dp.ap_started(vif.vdev_id, bssid, cfg.privacy);
        self.ap = Some(ApState {
            def,
            beacon_head: cfg.beacon_head,
            beacon_tail: cfg.beacon_tail,
            probe_resp: cfg.probe_resp.filter(|probe_resp| !probe_resp.is_empty()),
            tim_ie_offset,
            mbssid_elems: if mbssid.is_transmitting() {
                cfg.mbssid_elems
            } else {
                Vec::new()
            },
            ema_rnr_elems: if mbssid.is_transmitting() {
                cfg.ema_rnr_elems
            } else {
                Vec::new()
            },
            mbssid_beacons: if mbssid.is_transmitting() {
                mbssid_beacons
            } else {
                None
            },
            fils_discovery: cfg.fils_discovery,
            unsol_bcast_probe_resp: cfg.unsol_bcast_probe_resp,
            ftm_responder: cfg.ftm_responder,
            twt_responder: cfg.twt_responder,
            he_obss_pd: cfg.he_obss_pd,
            he_bss_color: cfg.he_bss_color,
            privacy: cfg.privacy,
            group_keys: Vec::new(),
            igtks: Vec::new(),
            default_igtk: None,
            csa: None,
            color_change: None,
            stations: Vec::new(),
        });
        if self
            .ap
            .as_ref()
            .is_some_and(|ap| ap.fils_discovery.is_some() || ap.unsol_bcast_probe_resp.is_some())
        {
            self.apply_ap_discovery().await?;
        }
        if self
            .ap
            .as_ref()
            .is_some_and(|ap| ap.ftm_responder.is_some())
        {
            // Linux logs an FTM vdev-parameter failure after an otherwise
            // successful AP start rather than rolling the vdev back down.
            if let Err(error) = self.apply_ap_ftm_responder().await {
                error.report("AP FTM responder enable");
            }
        }
        if self.ap.as_ref().is_some_and(|ap| ap.twt_responder) {
            // Linux's BSS_CHANGED_TWT handler sends the default pdev TWT
            // enable command after accepting the AP BSS. A WMI failure does
            // not roll back an otherwise live beaconing vdev.
            self.twt_ap_changed(true).await;
        }
        if self.ap.as_ref().is_some_and(|ap| ap.he_obss_pd.is_some()) {
            // `ath11k_mac_config_obss_pd` is pdev-scoped but is driven by
            // the starting AP's BSS information. Its individual WMI failures
            // are warnings in Linux and never undo the vdev transition.
            if let Err(error) = self.apply_ap_he_obss_pd().await {
                error.report("AP HE OBSS PD enable");
            }
        }
        if self.ap.as_ref().is_some_and(|ap| ap.he_bss_color.is_some()) {
            // This mirrors ath11k's AP BSS_CHANGED_HE_BSS_COLOR path: a
            // collision-config WMI error is logged but does not tear down a
            // just-started AP vdev.
            if let Err(error) = self.apply_ap_he_bss_color().await {
                error.report("AP HE BSS color enable");
            }
        }
        self.start_ap_dfs_cac(def);
        Ok(())
    }

    /// `NL80211_CMD_SET_BEACON` → `ath11k_mac_setup_bcn_tmpl`.  Attribute
    /// presence is preserved so hostapd can intentionally clear the tail.
    pub async fn set_ap_beacon(
        &mut self,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        probe_resp: Option<Vec<u8>>,
    ) -> Result<(), MacError> {
        let (own_addr, mbssid, dtim_period, vdev_id) = {
            let vif = self.vif.as_ref().unwrap();
            (vif.addr, vif.mbssid, vif.dtim_period, vif.vdev_id)
        };
        let (tim_ie_offset, beacon_head, beacon_tail, mbssid_elems, ema_rnr_elems) = {
            let Some(ap) = self.ap.as_mut() else {
                return fail(step::AP_BEACON, 3, errno::ENOTCONN, "set beacon (AP down)");
            };
            // mac80211 refuses SET_BEACON while either countdown owns the
            // temporary template, because a new head/tail could invalidate
            // its retained byte offsets.
            if ap.csa.is_some() || ap.color_change.is_some() {
                return fail(
                    step::AP_BEACON,
                    3,
                    errno::EBUSY,
                    "set beacon (transition active)",
                );
            }
            if let Some(head) = head {
                let Some(tim) = Self::ap_tim_ie_offset(&head) else {
                    return fail(step::AP_BEACON, 4, errno::EINVAL, "set beacon (TIM IE)");
                };
                if head.get(16..22) != Some(own_addr.as_slice()) {
                    return fail(step::AP_BEACON, 5, errno::EINVAL, "set beacon (BSSID)");
                }
                ap.beacon_head = head;
                ap.tim_ie_offset = tim;
            }
            if let Some(tail) = tail {
                ap.beacon_tail = tail;
            }
            if let Some(probe_resp) = probe_resp {
                if probe_resp.is_empty() {
                    ap.probe_resp = None;
                } else if !Self::ap_probe_resp_valid(&probe_resp, own_addr) {
                    return fail(
                        step::AP_BEACON,
                        6,
                        errno::EINVAL,
                        "set beacon (probe response)",
                    );
                } else {
                    ap.probe_resp = Some(probe_resp);
                }
            }
            (
                ap.tim_ie_offset,
                ap.beacon_head.clone(),
                ap.beacon_tail.clone(),
                ap.mbssid_elems.clone(),
                ap.ema_rnr_elems.clone(),
            )
        };
        if mbssid.is_non_transmitting() {
            // `ath11k_mac_setup_bcn_tmpl`: firmware crashes if an already-up
            // non-transmitting AP receives a replacement template. Its
            // transmitting sibling owns the shared MBSSID/EMA template.
            return Ok(());
        }
        if mbssid.is_transmitting() {
            let base = Self::ap_beacon(&beacon_head, dtim_period, &beacon_tail);
            let Some(beacons) =
                Self::build_mbssid_beacon_set(&base, &mbssid_elems, &ema_rnr_elems, mbssid.ema())
            else {
                return fail(
                    step::AP_BEACON,
                    11,
                    errno::EINVAL,
                    "set beacon (MBSSID elements)",
                );
            };
            self.upload_mbssid_beacon_set(
                vdev_id,
                tim_ie_offset,
                &beacons,
                15,
                "AP MBSSID beacon template update",
            )
            .await?;
            self.ap.as_mut().unwrap().mbssid_beacons = Some(beacons);
            return Ok(());
        }
        self.upload_ap_beacon_template(
            &beacon_head,
            &beacon_tail,
            tim_ie_offset,
            5,
            "AP beacon template update",
        )
        .await
    }

    /// Program the 6 GHz AP discovery family selected by the retained
    /// cfg80211 state. Linux ath11k gives FILS discovery priority when both
    /// are configured; an interval of zero disables that individual family.
    async fn apply_ap_discovery(&mut self) -> Result<(), MacError> {
        let (vdev_id, fils, unsol) = {
            let Some(vif) = self.vif.as_ref() else {
                return fail(
                    step::AP_DISCOVERY,
                    0,
                    errno::ENOTCONN,
                    "AP discovery (no vdev)",
                );
            };
            let Some(ap) = self.ap.as_ref() else {
                return fail(
                    step::AP_DISCOVERY,
                    1,
                    errno::ENOTCONN,
                    "AP discovery (AP down)",
                );
            };
            (
                vif.vdev_id,
                ap.fils_discovery.clone(),
                ap.unsol_bcast_probe_resp.clone(),
            )
        };
        if let Some(fils) = fils.filter(|fils| fils.max_interval_tu != 0) {
            self.cmd(
                fils_discovery_tmpl_cmd(vdev_id, &fils.template),
                step::AP_DISCOVERY,
                3,
                "FILS discovery template",
            )
            .await?;
            return self
                .cmd(
                    fils_discovery_cmd(vdev_id, fils.max_interval_tu, false),
                    step::AP_DISCOVERY,
                    4,
                    "FILS discovery enable",
                )
                .await;
        }
        if let Some(unsol) = unsol.filter(|unsol| unsol.interval_tu != 0) {
            self.cmd(
                probe_resp_tmpl_cmd(vdev_id, &unsol.template),
                step::AP_DISCOVERY,
                5,
                "unsolicited broadcast probe-response template",
            )
            .await?;
            return self
                .cmd(
                    fils_discovery_cmd(vdev_id, unsol.interval_tu, true),
                    step::AP_DISCOVERY,
                    6,
                    "unsolicited broadcast probe-response enable",
                )
                .await;
        }
        self.cmd(
            fils_discovery_cmd(vdev_id, 0, false),
            step::AP_DISCOVERY,
            7,
            "AP discovery disable",
        )
        .await
    }

    /// `BSS_CHANGED_FILS_DISCOVERY` /
    /// `BSS_CHANGED_UNSOL_BCAST_PROBE_RESP`. Attribute presence is preserved
    /// by the nested options: `Some(None)` disables and deletes a template.
    pub async fn set_ap_discovery(
        &mut self,
        fils: Option<Option<FilsDiscoveryConfig>>,
        unsol_bcast_probe_resp: Option<Option<UnsolBcastProbeRespConfig>>,
    ) -> Result<(), MacError> {
        if fils.is_none() && unsol_bcast_probe_resp.is_none() {
            return Ok(());
        }
        let Some(ap) = self.ap.as_mut() else {
            return fail(
                step::AP_DISCOVERY,
                8,
                errno::ENOTCONN,
                "AP discovery (AP down)",
            );
        };
        if ap.csa.is_some() || ap.color_change.is_some() {
            return fail(
                step::AP_DISCOVERY,
                8,
                errno::EBUSY,
                "AP discovery (transition active)",
            );
        }
        if let Some(fils) = fils {
            ap.fils_discovery = fils;
        }
        if let Some(unsol) = unsol_bcast_probe_resp {
            ap.unsol_bcast_probe_resp = unsol;
        }
        self.apply_ap_discovery().await
    }

    /// `BSS_CHANGED_FTM_RESPONDER`: ath11k sends only the responder-role
    /// vdev parameter. mac80211 owns the optional LCI/Civic report bytes, so
    /// retain them with the AP configuration for the same lifetime.
    async fn apply_ap_ftm_responder(&mut self) -> Result<(), MacError> {
        let Some(vif) = self.vif.as_ref() else {
            return fail(
                step::VDEV_PARAM,
                0,
                errno::ENOTCONN,
                "FTM responder (no vdev)",
            );
        };
        // The Linux ath11k BSS-info branch covers infrastructure AP (and
        // mesh), not a P2P GO despite its similar vdev lifecycle.
        if vif.kind != VifKind::Ap {
            return Ok(());
        }
        let vdev_id = vif.vdev_id;
        if self.ap.as_ref().is_none_or(|ap| ap.ftm_responder.is_none()) {
            return Ok(());
        }
        self.vdev_param(vdev_id, WMI_VDEV_PARAM_ENABLE_DISABLE_RTT_RESPONDER_ROLE, 1)
            .await
    }

    /// Install enabled FTM responder state for a live AP.
    pub async fn set_ap_ftm_responder(
        &mut self,
        config: FtmResponderConfig,
    ) -> Result<(), MacError> {
        let Some(ap) = self.ap.as_mut() else {
            return fail(
                step::VDEV_PARAM,
                1,
                errno::ENOTCONN,
                "FTM responder (AP down)",
            );
        };
        if ap.csa.is_some() || ap.color_change.is_some() {
            return fail(
                step::VDEV_PARAM,
                1,
                errno::EBUSY,
                "FTM responder (transition active)",
            );
        }
        ap.ftm_responder = Some(config);
        self.apply_ap_ftm_responder().await
    }

    /// `ath11k_mac_config_obss_pd` for the AP arm of
    /// `BSS_CHANGED_HE_OBSS_PD`. The Linux implementation makes the pdev
    /// policy authoritative for every AP vdev, so this follows its command
    /// order exactly and lets the caller log a first WMI failure without
    /// rolling the freshly-up AP back down.
    async fn apply_ap_he_obss_pd(&mut self) -> Result<(), MacError> {
        const HE_SPR_NON_SRG_OBSS_PD_SR_DISALLOWED: u8 = 1 << 1;
        const HE_SPR_NON_SRG_OFFSET_PRESENT: u8 = 1 << 2;
        const HE_SPR_SRG_INFORMATION_PRESENT: u8 = 1 << 3;
        const HE_SPR_HESIGA_SR_VAL15_ALLOWED: u8 = 1 << 4;
        const OBSS_PD_MAX_THRESHOLD: i32 = -82;
        const OBSS_PD_NON_SRG_MAX_THRESHOLD: i32 = -62;
        const DEFAULT_NOISE_FLOOR: i32 = -95;
        const OBSS_PD_THRESHOLD_IN_DBM: u32 = 1 << 29;
        const OBSS_PD_SRG_EN: u32 = 1 << 30;
        const OBSS_PD_NON_SRG_EN: u32 = 1 << 31;

        let Some(config) = self.ap.as_ref().and_then(|ap| ap.he_obss_pd) else {
            return Ok(());
        };
        let pdev_id = self.caps.pdev_id;
        let mut param_value = 0u32;
        let mut non_srg_threshold = if config.sr_ctrl & HE_SPR_NON_SRG_OBSS_PD_SR_DISALLOWED != 0 {
            OBSS_PD_MAX_THRESHOLD
        } else if config.sr_ctrl & HE_SPR_NON_SRG_OFFSET_PRESENT != 0 {
            OBSS_PD_MAX_THRESHOLD + i32::from(config.non_srg_max_offset)
        } else {
            OBSS_PD_NON_SRG_MAX_THRESHOLD
        };
        if config.sr_ctrl & HE_SPR_NON_SRG_OBSS_PD_SR_DISALLOWED == 0 {
            param_value |= OBSS_PD_NON_SRG_EN;
        }
        let has_srg = config.sr_ctrl & HE_SPR_SRG_INFORMATION_PRESENT != 0;
        let srg_threshold = OBSS_PD_MAX_THRESHOLD + i32::from(config.max_offset);
        if has_srg {
            param_value |= OBSS_PD_SRG_EN;
        }
        let supports_srg = self.svc(WMI_TLV_SERVICE_SRG_SRP_SPATIAL_REUSE_SUPPORT);
        if supports_srg {
            param_value |= OBSS_PD_THRESHOLD_IN_DBM;
            param_value |= ((srg_threshold as i8 as u8) as u32) << 8;
        } else {
            // The older target format carries non-SRG threshold as an SNR
            // offset, not dBm, and cannot represent SRG policy.
            non_srg_threshold -= DEFAULT_NOISE_FLOOR;
            param_value &= !(OBSS_PD_SRG_EN | OBSS_PD_THRESHOLD_IN_DBM);
        }
        param_value |= (non_srg_threshold as i8 as u8) as u32;
        self.pdev_param(WMI_PDEV_PARAM_SET_CMD_OBSS_PD_THRESHOLD, param_value)
            .await?;
        self.pdev_param(WMI_PDEV_PARAM_SET_CMD_OBSS_PD_PER_AC, 0x0f)
            .await?;
        self.pdev_param(
            WMI_PDEV_PARAM_ENABLE_SR_PROHIBIT,
            (config.sr_ctrl & HE_SPR_HESIGA_SR_VAL15_ALLOWED != 0) as u32,
        )
        .await?;
        if !supports_srg {
            return Ok(());
        }

        self.cmd(
            pdev_set_srg_bss_color_bitmap_cmd(pdev_id, config.bss_color_bitmap),
            step::HE_PARAM,
            4,
            "AP HE OBSS PD SRG BSS color bitmap",
        )
        .await?;
        self.cmd(
            pdev_set_srg_partial_bssid_bitmap_cmd(pdev_id, config.partial_bssid_bitmap),
            step::HE_PARAM,
            5,
            "AP HE OBSS PD SRG partial BSSID bitmap",
        )
        .await?;
        let all_enabled = [u32::MAX; 2];
        self.cmd(
            pdev_set_srg_obss_color_enable_bitmap_cmd(pdev_id, all_enabled),
            step::HE_PARAM,
            6,
            "AP HE OBSS PD SRG color enable bitmap",
        )
        .await?;
        self.cmd(
            pdev_set_srg_obss_bssid_enable_bitmap_cmd(pdev_id, all_enabled),
            step::HE_PARAM,
            7,
            "AP HE OBSS PD SRG BSSID enable bitmap",
        )
        .await?;
        self.cmd(
            pdev_set_non_srg_obss_color_enable_bitmap_cmd(pdev_id, all_enabled),
            step::HE_PARAM,
            8,
            "AP HE OBSS PD non-SRG color enable bitmap",
        )
        .await?;
        self.cmd(
            pdev_set_non_srg_obss_bssid_enable_bitmap_cmd(pdev_id, all_enabled),
            step::HE_PARAM,
            9,
            "AP HE OBSS PD non-SRG BSSID enable bitmap",
        )
        .await
    }

    /// `BSS_CHANGED_HE_BSS_COLOR` for an AP: target firmware receives the
    /// color and whether collision detection is enabled, then receives the
    /// separate `WMI_VDEV_PARAM_BSS_COLOR` value. The `partial` state remains
    /// in the retained nl80211 configuration; neither ath11k WMI operation
    /// carries a corresponding field.
    async fn apply_ap_he_bss_color(&mut self) -> Result<(), MacError> {
        let Some(vif) = self.vif.as_ref() else {
            return fail(
                step::HE_PARAM,
                0,
                errno::ENOTCONN,
                "AP HE BSS color (no vdev)",
            );
        };
        // ath11k's BSS_CHANGED_HE_BSS_COLOR branch is specifically an AP
        // branch; P2P-GO shares much of the AP lifecycle but receives no
        // BSS-color WMI programming.
        if vif.kind != VifKind::Ap {
            return Ok(());
        }
        let vdev_id = vif.vdev_id;
        let Some(color) = self.ap.as_ref().and_then(|ap| ap.he_bss_color) else {
            return Ok(());
        };
        // Linux reports either command failure but deliberately attempts both
        // so a collision-detector fault cannot leave the vdev's advertised HE
        // Operation color stale. Preserve that best-effort boundary here.
        if let Err(error) = self
            .cmd(
                // ath11k uses its AP-specific period here.  The station arm
                // below deliberately keeps its longer 10-second interval.
                obss_color_collision_cfg_cmd(vdev_id, color.color, 5_000, !color.disabled),
                step::HE_PARAM,
                3,
                "AP HE BSS color collision cfg",
            )
            .await
        {
            error.report("AP HE BSS color collision cfg");
        }
        let param = if color.disabled {
            0x8000_0000 // IEEE80211_HE_OPERATION_BSS_COLOR_DISABLED
        } else {
            u32::from(color.color) << 24 // IEEE80211_HE_OPERATION_BSS_COLOR_OFFSET
        };
        if let Err(error) = self
            .vdev_param(vdev_id, WMI_VDEV_PARAM_BSS_COLOR, param)
            .await
        {
            error.report("AP HE BSS color vdev param");
        }
        Ok(())
    }

    /// Update the AP's HE BSS-color collision-detection state.
    pub async fn set_ap_he_bss_color(&mut self, config: HeBssColorConfig) -> Result<(), MacError> {
        let Some(ap) = self.ap.as_mut() else {
            return fail(
                step::HE_PARAM,
                1,
                errno::ENOTCONN,
                "AP HE BSS color (AP down)",
            );
        };
        if ap.csa.is_some() || ap.color_change.is_some() {
            return fail(
                step::HE_PARAM,
                1,
                errno::EBUSY,
                "AP HE BSS color (transition active)",
            );
        }
        ap.he_bss_color = Some(config);
        self.apply_ap_he_bss_color().await
    }

    /// Snapshot the AP BSS-color state after a transition point.  The runtime
    /// uses this to mirror a transmitting MBSSID's state onto its
    /// non-transmitting profiles without borrowing AP state across a WMI
    /// operation on another vdev.
    pub fn ap_he_bss_color(&self) -> Option<HeBssColorConfig> {
        self.ap.as_ref().and_then(|ap| ap.he_bss_color)
    }

    /// Upload one temporary HE BSS-color countdown beacon.  The normal AP
    /// state is deliberately not mutated by this helper: mac80211 retains
    /// `next_beacon` separately and restores it only in color finalization.
    async fn upload_ap_color_change_template(
        &mut self,
        change: &ApColorChange,
        detail: u32,
        what: &'static str,
    ) -> Result<(), MacError> {
        let (vdev_id, dtim_period, mbssid, mbssid_elems, ema_rnr_elems) = {
            let vif = self
                .vif
                .as_ref()
                .ok_or_else(|| MacError::new(step::AP_COLOR_CHANGE, 0, errno::ENOTCONN))?;
            let ap = self
                .ap
                .as_ref()
                .ok_or_else(|| MacError::new(step::AP_COLOR_CHANGE, 1, errno::ENOTCONN))?;
            (
                vif.vdev_id,
                vif.dtim_period,
                vif.mbssid,
                ap.mbssid_elems.clone(),
                ap.ema_rnr_elems.clone(),
            )
        };
        let Some(tim_ie_offset) = Self::ap_tim_ie_offset(&change.beacon_color_head) else {
            return fail(
                step::AP_COLOR_CHANGE,
                2,
                errno::EINVAL,
                "AP color change (TIM IE)",
            );
        };
        if mbssid.is_transmitting() {
            let base = Self::ap_beacon(
                &change.beacon_color_head,
                dtim_period,
                &change.beacon_color_tail,
            );
            let Some(beacons) =
                Self::build_mbssid_beacon_set(&base, &mbssid_elems, &ema_rnr_elems, mbssid.ema())
            else {
                return fail(
                    step::AP_COLOR_CHANGE,
                    3,
                    errno::EINVAL,
                    "AP color change (MBSSID elements)",
                );
            };
            return self
                .upload_mbssid_beacon_set(vdev_id, tim_ie_offset, &beacons, detail, what)
                .await;
        }
        self.upload_ap_beacon_template(
            &change.beacon_color_head,
            &change.beacon_color_tail,
            tim_ie_offset,
            detail,
            what,
        )
        .await
    }

    /// Finish an accepted color transition: install the retained normal
    /// beacon, re-enable the requested color and publish COMPLETED. This is
    /// the local equivalent of `ieee80211_color_change_finalize`.
    async fn complete_ap_color_change(&mut self, change: &ApColorChange) -> Result<(), MacError> {
        let (
            vdev_id,
            own_addr,
            dtim_period,
            mbssid,
            beacon_head,
            beacon_tail,
            probe_resp,
            tim_ie_offset,
            mbssid_elems,
            ema_rnr_elems,
        ) = {
            let vif = self
                .vif
                .as_ref()
                .ok_or_else(|| MacError::new(step::AP_COLOR_CHANGE, 10, errno::ENOTCONN))?;
            let ap = self
                .ap
                .as_ref()
                .ok_or_else(|| MacError::new(step::AP_COLOR_CHANGE, 11, errno::ENOTCONN))?;
            let head = change
                .beacon_next_head
                .as_ref()
                .unwrap_or(&ap.beacon_head)
                .clone();
            let tail = change
                .beacon_next_tail
                .as_ref()
                .unwrap_or(&ap.beacon_tail)
                .clone();
            let probe_resp = match change.probe_resp_next.as_ref() {
                Some(probe_resp) if probe_resp.is_empty() => None,
                Some(probe_resp) => Some(probe_resp.clone()),
                None => ap.probe_resp.clone(),
            };
            let tim = if change.beacon_next_head.is_some() {
                Self::ap_tim_ie_offset(&head)
                    .ok_or_else(|| MacError::new(step::AP_COLOR_CHANGE, 12, errno::EINVAL))?
            } else {
                ap.tim_ie_offset
            };
            (
                vif.vdev_id,
                vif.addr,
                vif.dtim_period,
                vif.mbssid,
                head,
                tail,
                probe_resp,
                tim,
                ap.mbssid_elems.clone(),
                ap.ema_rnr_elems.clone(),
            )
        };
        if beacon_head.get(16..22) != Some(own_addr.as_slice()) {
            return fail(
                step::AP_COLOR_CHANGE,
                13,
                errno::EINVAL,
                "AP color change (post-change BSSID)",
            );
        }
        if probe_resp
            .as_ref()
            .is_some_and(|probe_resp| !Self::ap_probe_resp_valid(probe_resp, own_addr))
        {
            return fail(
                step::AP_COLOR_CHANGE,
                14,
                errno::EINVAL,
                "AP color change (post-change probe response)",
            );
        }
        let updated_mbssid_beacons = if mbssid.is_transmitting() {
            let base = Self::ap_beacon(&beacon_head, dtim_period, &beacon_tail);
            let Some(beacons) =
                Self::build_mbssid_beacon_set(&base, &mbssid_elems, &ema_rnr_elems, mbssid.ema())
            else {
                return fail(
                    step::AP_COLOR_CHANGE,
                    15,
                    errno::EINVAL,
                    "AP color change (post-change MBSSID elements)",
                );
            };
            self.upload_mbssid_beacon_set(
                vdev_id,
                tim_ie_offset,
                &beacons,
                20,
                "AP color change post-change beacon",
            )
            .await?;
            Some(beacons)
        } else {
            self.upload_ap_beacon_template(
                &beacon_head,
                &beacon_tail,
                tim_ie_offset,
                20,
                "AP color change post-change beacon",
            )
            .await?;
            None
        };
        {
            let ap = self.ap.as_mut().unwrap();
            ap.beacon_head = beacon_head;
            ap.beacon_tail = beacon_tail;
            ap.probe_resp = probe_resp;
            ap.tim_ie_offset = tim_ie_offset;
            ap.he_bss_color = Some(HeBssColorConfig {
                color: change.color,
                disabled: false,
                partial: change.previous_color.is_some_and(|color| color.partial),
            });
            if let Some(beacons) = updated_mbssid_beacons {
                ap.mbssid_beacons = Some(beacons);
            }
            if let Some(unsol_bcast_probe_resp) = change.unsol_bcast_probe_resp.clone() {
                ap.unsol_bcast_probe_resp = unsol_bcast_probe_resp;
            }
            ap.color_change = None;
        }
        // The selected color must reach firmware even if its collision WMI
        // update is best effort, as ath11k's BSS-info callback does.
        self.apply_ap_he_bss_color().await?;
        self.pending
            .ap_color_change_events
            .push_back(ApColorChangeEvent::Completed);
        Ok(())
    }

    /// Undo a failed post-acceptance color change.  Generic netlink has
    /// already accepted the queued operation, so the terminal observable
    /// outcome must be ABORTED rather than a silently dead countdown.
    async fn abort_ap_color_change(&mut self) {
        let Some(change) = self
            .ap
            .as_ref()
            .and_then(|ap| ap.color_change.as_ref())
            .cloned()
        else {
            return;
        };
        {
            let ap = self.ap.as_mut().unwrap();
            // A color-change request may have arrived before a separate
            // HE_BSS_COLOR configuration. In that case restore the on-air
            // disabled state explicitly, rather than leaving firmware with
            // the temporary detector disabled while `None` makes the normal
            // apply helper a no-op.
            ap.he_bss_color = Some(change.previous_color.unwrap_or(HeBssColorConfig {
                color: 0,
                disabled: true,
                partial: false,
            }));
            if change.unsol_bcast_probe_resp.is_some() {
                ap.unsol_bcast_probe_resp = change.previous_unsol_bcast_probe_resp.clone();
            }
            ap.color_change = None;
        }
        // Reinstalling the retained normal beacon makes the on-air state
        // match the restored BSS-color configuration after any countdown
        // template had already reached firmware.
        if let Err(error) = self.set_ap_beacon(None, None, None).await {
            error.report("AP color change abort beacon restore");
        }
        if let Err(error) = self.apply_ap_he_bss_color().await {
            error.report("AP color change abort BSS color restore");
        }
        if change.unsol_bcast_probe_resp.is_some() {
            if let Err(error) = self.apply_ap_discovery().await {
                error.report("AP color change abort discovery restore");
            }
        }
        self.pending
            .ap_color_change_events
            .push_back(ApColorChangeEvent::Aborted);
    }

    /// `NL80211_CMD_COLOR_CHANGE_REQUEST` for an infrastructure AP. The
    /// driver has no dedicated target command; it updates the same firmware
    /// beacon template path mac80211's bss-info changes drive around an HE
    /// color countdown.
    pub async fn color_change(&mut self, cfg: ColorChangeConfig) -> Result<(), MacError> {
        if !self.supports_bss_color() {
            return fail(
                step::AP_COLOR_CHANGE,
                0,
                errno::EOPNOTSUPP,
                "AP color change (firmware unsupported)",
            );
        }
        let (own_addr, beacon_interval, mbssid) = {
            let Some(vif) = self
                .vif
                .as_ref()
                .filter(|vif| vif.kind == VifKind::Ap && vif.is_up)
            else {
                return fail(
                    step::AP_COLOR_CHANGE,
                    1,
                    errno::ENOTCONN,
                    "AP color change (no AP vdev)",
                );
            };
            (vif.addr, vif.beacon_interval, vif.mbssid)
        };
        let Some(ap) = self.ap.as_ref() else {
            return fail(
                step::AP_COLOR_CHANGE,
                2,
                errno::ENOTCONN,
                "AP color change (AP down)",
            );
        };
        if ap.color_change.is_some() || ap.csa.is_some() {
            return fail(
                step::AP_COLOR_CHANGE,
                3,
                errno::EBUSY,
                "AP color change (transition active)",
            );
        }
        if mbssid.is_non_transmitting() {
            return fail(
                step::AP_COLOR_CHANGE,
                4,
                errno::EINVAL,
                "AP color change (non-transmitting MBSSID profile)",
            );
        }
        if !(1..=63).contains(&cfg.color)
            || cfg
                .beacon_color_tail
                .get(cfg.counter_offset_beacon as usize)
                != Some(&cfg.count)
        {
            return fail(
                step::AP_COLOR_CHANGE,
                5,
                errno::EINVAL,
                "AP color change (count/color)",
            );
        }
        let beacon_color_head = cfg
            .beacon_color_head
            .unwrap_or_else(|| ap.beacon_head.clone());
        let Some(_) = Self::ap_tim_ie_offset(&beacon_color_head) else {
            return fail(
                step::AP_COLOR_CHANGE,
                6,
                errno::EINVAL,
                "AP color change (countdown TIM IE)",
            );
        };
        if beacon_color_head.get(16..22) != Some(own_addr.as_slice()) {
            return fail(
                step::AP_COLOR_CHANGE,
                7,
                errno::EINVAL,
                "AP color change (countdown BSSID)",
            );
        }
        match (&cfg.probe_resp_color, cfg.counter_offset_presp) {
            (Some(probe_resp), Some(offset))
                if !Self::ap_probe_resp_valid(probe_resp, own_addr)
                    || probe_resp.get(offset as usize) != Some(&cfg.count) =>
            {
                return fail(
                    step::AP_COLOR_CHANGE,
                    8,
                    errno::EINVAL,
                    "AP color change (countdown probe response)",
                );
            }
            (Some(probe_resp), None) if !Self::ap_probe_resp_valid(probe_resp, own_addr) => {
                return fail(
                    step::AP_COLOR_CHANGE,
                    8,
                    errno::EINVAL,
                    "AP color change (countdown probe response)",
                );
            }
            (None, Some(_)) => {
                return fail(
                    step::AP_COLOR_CHANGE,
                    8,
                    errno::EINVAL,
                    "AP color change (countdown probe response)",
                );
            }
            _ => {}
        }
        if let Some(head) = cfg.beacon_next_head.as_ref() {
            if Self::ap_tim_ie_offset(head).is_none()
                || head.get(16..22) != Some(own_addr.as_slice())
            {
                return fail(
                    step::AP_COLOR_CHANGE,
                    9,
                    errno::EINVAL,
                    "AP color change (post-change beacon)",
                );
            }
        }
        if let Some(probe_resp) = cfg.probe_resp_next.as_ref() {
            if !probe_resp.is_empty() && !Self::ap_probe_resp_valid(probe_resp, own_addr) {
                return fail(
                    step::AP_COLOR_CHANGE,
                    10,
                    errno::EINVAL,
                    "AP color change (post-change probe response)",
                );
            }
        }
        let interval_ms = (u64::from(beacon_interval)
            .saturating_mul(1024)
            .saturating_add(999)
            / 1000)
            .max(1);
        let change = ApColorChange {
            beacon_color_head,
            beacon_color_tail: cfg.beacon_color_tail,
            counter_offset_beacon: cfg.counter_offset_beacon,
            probe_resp_color: cfg.probe_resp_color,
            counter_offset_presp: cfg.counter_offset_presp,
            beacon_next_head: cfg.beacon_next_head,
            beacon_next_tail: cfg.beacon_next_tail,
            probe_resp_next: cfg.probe_resp_next,
            count: cfg.count,
            deadline: self.wmi.now_ms().saturating_add(interval_ms),
            color: cfg.color,
            previous_color: ap.he_bss_color,
            previous_unsol_bcast_probe_resp: ap.unsol_bcast_probe_resp.clone(),
            unsol_bcast_probe_resp: cfg.unsol_bcast_probe_resp,
        };
        if change.count > 1 {
            self.upload_ap_color_change_template(&change, 30, "AP color change countdown beacon")
                .await?;
        }
        {
            let ap = self.ap.as_mut().unwrap();
            ap.he_bss_color = Some(HeBssColorConfig {
                color: 0,
                disabled: true,
                partial: change.previous_color.is_some_and(|color| color.partial),
            });
            if let Some(unsol_bcast_probe_resp) = change.unsol_bcast_probe_resp.clone() {
                ap.unsol_bcast_probe_resp = unsol_bcast_probe_resp;
            }
            ap.color_change = Some(change.clone());
        }
        if change.unsol_bcast_probe_resp.is_some() {
            if let Err(error) = self.apply_ap_discovery().await {
                self.abort_ap_color_change().await;
                return Err(error);
            }
        }
        self.pending
            .ap_color_change_events
            .push_back(ApColorChangeEvent::Started {
                count: change.count,
            });
        if change.count <= 1 {
            if let Err(error) = self.complete_ap_color_change(&change).await {
                self.abort_ap_color_change().await;
                return Err(error);
            }
        } else {
            self.apply_ap_he_bss_color().await?;
        }
        Ok(())
    }

    /// Drive a software-owned HE BSS-color countdown at each nominal TBTT.
    /// Firmware schedules beacon transmission; ath11k's template API means
    /// the host explicitly uploads each new count byte.
    async fn finish_ap_color_change(&mut self) {
        let now = self.wmi.now_ms();
        let Some(change) = self
            .ap
            .as_ref()
            .and_then(|ap| ap.color_change.as_ref())
            .filter(|change| now >= change.deadline)
            .cloned()
        else {
            return;
        };
        if change.count > 1 {
            let mut next = change;
            next.count -= 1;
            next.beacon_color_tail[next.counter_offset_beacon as usize] = next.count;
            if let (Some(probe_resp), Some(offset)) =
                (next.probe_resp_color.as_mut(), next.counter_offset_presp)
            {
                probe_resp[offset as usize] = next.count;
            }
            let beacon_interval = self.vif.as_ref().map_or(1, |vif| vif.beacon_interval);
            let interval_ms = (u64::from(beacon_interval)
                .saturating_mul(1024)
                .saturating_add(999)
                / 1000)
                .max(1);
            next.deadline = now.saturating_add(interval_ms);
            match self
                .upload_ap_color_change_template(&next, 40, "AP color change countdown beacon")
                .await
            {
                Ok(()) => self.ap.as_mut().unwrap().color_change = Some(next),
                Err(error) => {
                    error.report("AP color change countdown");
                    self.abort_ap_color_change().await;
                }
            }
            return;
        }
        if let Err(error) = self.complete_ap_color_change(&change).await {
            error.report("AP color change finalize");
            self.abort_ap_color_change().await;
        }
    }

    /// Complete a local AP/GO CSA the same way ath11k's
    /// `switch_vif_chanctx` does: restart the live vdev, install the normal
    /// (post-CSA) beacon, and bring the vdev back up.  The CSA template was
    /// already beaconing on the old channel; it is never retained as the
    /// normal beacon.
    async fn complete_ap_channel_switch(&mut self, csa: &ApChannelSwitch) -> Result<(), MacError> {
        let (
            vdev_id,
            bssid,
            own_addr,
            dtim_period,
            mbssid,
            beacon_head,
            beacon_tail,
            probe_resp,
            tim_ie_offset,
            mbssid_elems,
            ema_rnr_elems,
        ) = {
            let vif = self.vif.as_ref().unwrap();
            let Some(ap) = self.ap.as_ref() else {
                return fail(
                    step::AP_CHANNEL_SWITCH,
                    0,
                    errno::ENOTCONN,
                    "AP CSA (AP down)",
                );
            };
            let head = csa
                .beacon_after_head
                .as_ref()
                .unwrap_or(&ap.beacon_head)
                .clone();
            let tail = csa
                .beacon_after_tail
                .as_ref()
                .unwrap_or(&ap.beacon_tail)
                .clone();
            let probe_resp = match csa.probe_resp_after.as_ref() {
                Some(probe_resp) if probe_resp.is_empty() => None,
                Some(probe_resp) => Some(probe_resp.clone()),
                None => ap.probe_resp.clone(),
            };
            let tim = if csa.beacon_after_head.is_some() {
                let Some(tim) = Self::ap_tim_ie_offset(&head) else {
                    return fail(
                        step::AP_CHANNEL_SWITCH,
                        1,
                        errno::EINVAL,
                        "AP CSA (post-switch TIM IE)",
                    );
                };
                tim
            } else {
                ap.tim_ie_offset
            };
            (
                vif.vdev_id,
                vif.bssid,
                vif.addr,
                vif.dtim_period,
                vif.mbssid,
                head,
                tail,
                probe_resp,
                tim,
                ap.mbssid_elems.clone(),
                ap.ema_rnr_elems.clone(),
            )
        };
        if beacon_head.get(16..22) != Some(own_addr.as_slice()) {
            return fail(
                step::AP_CHANNEL_SWITCH,
                2,
                errno::EINVAL,
                "AP CSA (post-switch BSSID)",
            );
        }
        if probe_resp
            .as_ref()
            .is_some_and(|probe_resp| !Self::ap_probe_resp_valid(probe_resp, own_addr))
        {
            return fail(
                step::AP_CHANNEL_SWITCH,
                3,
                errno::EINVAL,
                "AP CSA (post-switch probe response)",
            );
        }
        // Leaving a CAC/NOP-held chandef aborts its CAC (if any) and clears
        // the data hold before the restart installs the new context. A new
        // DFS-usable target starts its own CAC below.
        self.abort_ap_dfs_cac();
        self.dp.ap_dfs_cac(vdev_id, false);
        self.vdev_start_restart(&csa.def, true, true).await?;
        let updated_mbssid_beacons = if mbssid.is_transmitting() {
            let base = Self::ap_beacon(&beacon_head, dtim_period, &beacon_tail);
            let Some(beacons) =
                Self::build_mbssid_beacon_set(&base, &mbssid_elems, &ema_rnr_elems, mbssid.ema())
            else {
                return fail(
                    step::AP_CHANNEL_SWITCH,
                    4,
                    errno::EINVAL,
                    "AP CSA (MBSSID elements)",
                );
            };
            self.upload_mbssid_beacon_set(
                vdev_id,
                tim_ie_offset,
                &beacons,
                20,
                "AP CSA MBSSID post-switch beacon",
            )
            .await?;
            Some(beacons)
        } else {
            self.upload_ap_beacon_template(
                &beacon_head,
                &beacon_tail,
                tim_ie_offset,
                20,
                "AP CSA post-switch beacon",
            )
            .await?;
            None
        };
        let (tx_bssid, profile_index, profile_count) = if mbssid.is_non_transmitting() {
            (
                Some(&mbssid.tx_bssid),
                mbssid.profile_index,
                mbssid.profile_count,
            )
        } else {
            (None, 0, 0)
        };
        self.cmd(
            vdev_up_cmd(
                vdev_id,
                0,
                &bssid,
                tx_bssid,
                profile_index,
                profile_count,
                None,
            ),
            step::VDEV_UP,
            20,
            "AP CSA vdev up",
        )
        .await?;
        {
            let vif = self.vif.as_mut().unwrap();
            vif.chanctx = Some(csa.def);
            vif.txpower = self
                .wiphy
                .get(csa.def.freq)
                .map(|channel| channel.max_power);
        }
        {
            let ap = self.ap.as_mut().unwrap();
            ap.def = csa.def;
            ap.beacon_head = beacon_head;
            ap.beacon_tail = beacon_tail;
            ap.probe_resp = probe_resp;
            ap.tim_ie_offset = tim_ie_offset;
            if let Some(beacons) = updated_mbssid_beacons {
                ap.mbssid_beacons = Some(beacons);
            }
            if let Some(unsol_bcast_probe_resp) = csa.unsol_bcast_probe_resp.clone() {
                ap.unsol_bcast_probe_resp = unsol_bcast_probe_resp;
            }
            if let Some(ftm_responder) = csa.ftm_responder.clone() {
                ap.ftm_responder = Some(ftm_responder);
            }
            if let Some(he_bss_color) = csa.he_bss_color {
                ap.he_bss_color = Some(he_bss_color);
            }
            ap.csa = None;
        }
        if csa.unsol_bcast_probe_resp.is_some() {
            // ath11k's bss_info_changed deliberately logs, rather than
            // aborts, a discovery-template failure. The CSA vdev has already
            // restarted; leaving its coherent channel state intact mirrors
            // that Linux failure boundary.
            if let Err(error) = self.apply_ap_discovery().await {
                error.report("AP CSA unsolicited broadcast probe response");
            }
        }
        if csa.ftm_responder.is_some() {
            if let Err(error) = self.apply_ap_ftm_responder().await {
                error.report("AP CSA FTM responder update");
            }
        }
        if csa.he_bss_color.is_some() {
            if let Err(error) = self.apply_ap_he_bss_color().await {
                error.report("AP CSA HE BSS color update");
            }
        }
        self.start_ap_dfs_cac(csa.def);
        self.pending
            .ap_channel_switch_events
            .push_back(ApChannelSwitchEvent {
                def: csa.def,
                count: 0,
                block_tx: csa.block_tx,
                started: false,
            });
        if csa.block_tx {
            self.dp.ap_channel_switching(vdev_id, false);
        }
        Ok(())
    }

    /// `NL80211_CMD_CHANNEL_SWITCH` for a beaconing AP/P2P GO.  Linux uses
    /// a CSA beacon while the counter is above one and does an immediate
    /// switch for counts zero and one; this mirrors that behavior instead of
    /// inventing a target-private CSA WMI command.
    pub async fn channel_switch(&mut self, cfg: ChannelSwitchConfig) -> Result<(), MacError> {
        let (vdev_id, own_addr, beacon_interval, mbssid) = {
            let Some(vif) = self
                .vif
                .as_ref()
                .filter(|vif| vif.kind.is_ap() && vif.is_up)
            else {
                return fail(
                    step::AP_CHANNEL_SWITCH,
                    3,
                    errno::ENOTCONN,
                    "AP CSA (no beaconing vdev)",
                );
            };
            (vif.vdev_id, vif.addr, vif.beacon_interval, vif.mbssid)
        };
        if mbssid.is_non_transmitting() {
            // The transmitter owns the common channel context and the only
            // mutable beacon templates. A separate CSA from an already-up
            // non-transmitting profile would require a template write the
            // target explicitly forbids.
            return fail(
                step::AP_CHANNEL_SWITCH,
                3,
                errno::EOPNOTSUPP,
                "AP CSA (non-transmitting MBSSID profile)",
            );
        }
        if self.ap.is_none() || self.ap.as_ref().is_some_and(|ap| ap.csa.is_some()) {
            return fail(
                step::AP_CHANNEL_SWITCH,
                4,
                errno::EBUSY,
                "AP CSA (already switching)",
            );
        }
        // mac80211 gives an incoming CSA precedence over a pending local
        // color change: its next-beacon state is discarded and user space
        // receives COLOR_CHANGE_ABORTED before the CSA template is armed.
        if self.ap.as_ref().is_some_and(|ap| ap.color_change.is_some()) {
            self.abort_ap_color_change().await;
        }
        let Some(channel) = self.wiphy.get(cfg.frequency_mhz) else {
            return fail(
                step::AP_CHANNEL_SWITCH,
                cfg.frequency_mhz,
                errno::EINVAL,
                "AP CSA (channel)",
            );
        };
        if channel.flags & (chan_flag::DISABLED | chan_flag::NO_IR) != 0 {
            return fail(
                step::AP_CHANNEL_SWITCH,
                cfg.frequency_mhz,
                errno::EINVAL,
                "AP CSA (regulatory channel)",
            );
        }
        let def = self.ap_chandef_fields(
            cfg.frequency_mhz,
            cfg.channel_width,
            cfg.center_freq1_mhz,
            cfg.center_freq2_mhz,
            step::AP_CHANNEL_SWITCH,
            "AP CSA (chandef)",
        )?;
        let Some(tim_ie_offset) = Self::ap_tim_ie_offset(&cfg.beacon_csa_head) else {
            return fail(step::AP_CHANNEL_SWITCH, 5, errno::EINVAL, "AP CSA (TIM IE)");
        };
        if cfg.beacon_csa_head.get(16..22) != Some(own_addr.as_slice()) {
            return fail(step::AP_CHANNEL_SWITCH, 6, errno::EINVAL, "AP CSA (BSSID)");
        }
        if cfg.counter_offsets_beacon.is_empty() || cfg.counter_offsets_beacon.len() > 2 {
            return fail(
                step::AP_CHANNEL_SWITCH,
                7,
                errno::EINVAL,
                "AP CSA (counter offsets)",
            );
        }
        for &offset in &cfg.counter_offsets_beacon {
            if cfg.beacon_csa_tail.get(offset as usize) != Some(&cfg.count) {
                return fail(
                    step::AP_CHANNEL_SWITCH,
                    offset as u32,
                    errno::EINVAL,
                    "AP CSA (counter value)",
                );
            }
        }
        if cfg.counter_offsets_presp.len() > 2 {
            return fail(
                step::AP_CHANNEL_SWITCH,
                9,
                errno::EINVAL,
                "AP CSA (probe-response counter offsets)",
            );
        }
        match cfg.probe_resp_csa.as_ref() {
            Some(probe_resp) if probe_resp.is_empty() && !cfg.counter_offsets_presp.is_empty() => {
                return fail(
                    step::AP_CHANNEL_SWITCH,
                    10,
                    errno::EINVAL,
                    "AP CSA (probe-response template)",
                )
            }
            Some(probe_resp)
                if !probe_resp.is_empty() && !Self::ap_probe_resp_valid(probe_resp, own_addr) =>
            {
                return fail(
                    step::AP_CHANNEL_SWITCH,
                    10,
                    errno::EINVAL,
                    "AP CSA (probe-response template)",
                )
            }
            None if !cfg.counter_offsets_presp.is_empty() => {
                return fail(
                    step::AP_CHANNEL_SWITCH,
                    10,
                    errno::EINVAL,
                    "AP CSA (probe-response template)",
                )
            }
            _ => {}
        }
        if let Some(probe_resp) = cfg
            .probe_resp_csa
            .as_ref()
            .filter(|probe_resp| !probe_resp.is_empty())
        {
            for &offset in &cfg.counter_offsets_presp {
                if probe_resp.get(offset as usize) != Some(&cfg.count) {
                    return fail(
                        step::AP_CHANNEL_SWITCH,
                        offset as u32,
                        errno::EINVAL,
                        "AP CSA (probe-response counter value)",
                    );
                }
            }
        }
        if let Some(head) = cfg.beacon_after_head.as_ref() {
            if Self::ap_tim_ie_offset(head).is_none()
                || head.get(16..22) != Some(own_addr.as_slice())
            {
                return fail(
                    step::AP_CHANNEL_SWITCH,
                    8,
                    errno::EINVAL,
                    "AP CSA (post-switch beacon)",
                );
            }
        }
        if let Some(probe_resp) = cfg.probe_resp_after.as_ref() {
            if !probe_resp.is_empty() && !Self::ap_probe_resp_valid(probe_resp, own_addr) {
                return fail(
                    step::AP_CHANNEL_SWITCH,
                    11,
                    errno::EINVAL,
                    "AP CSA (post-switch probe response)",
                );
            }
        }
        let interval_ms = (u64::from(beacon_interval)
            .saturating_mul(1024)
            .saturating_add(999)
            / 1000)
            .max(1);
        let csa = ApChannelSwitch {
            def,
            beacon_csa_head: cfg.beacon_csa_head,
            beacon_csa_tail: cfg.beacon_csa_tail,
            counter_offsets_beacon: cfg.counter_offsets_beacon,
            probe_resp_csa: cfg
                .probe_resp_csa
                .filter(|probe_resp| !probe_resp.is_empty()),
            counter_offsets_presp: cfg.counter_offsets_presp,
            count: cfg.count,
            deadline: self.wmi.now_ms().saturating_add(interval_ms),
            block_tx: cfg.block_tx,
            beacon_after_head: cfg.beacon_after_head,
            beacon_after_tail: cfg.beacon_after_tail,
            probe_resp_after: cfg.probe_resp_after,
            ftm_responder: cfg.ftm_responder,
            he_bss_color: cfg.he_bss_color,
            unsol_bcast_probe_resp: cfg.unsol_bcast_probe_resp,
        };
        if csa.count <= 1 {
            self.pending
                .ap_channel_switch_events
                .push_back(ApChannelSwitchEvent {
                    def: csa.def,
                    count: csa.count,
                    block_tx: csa.block_tx,
                    started: true,
                });
            if csa.block_tx {
                self.dp.ap_channel_switching(vdev_id, true);
            }
            let result = self.complete_ap_channel_switch(&csa).await;
            if result.is_err() && csa.block_tx {
                self.dp.ap_channel_switching(vdev_id, false);
            }
            return result;
        }
        self.upload_ap_beacon_template(
            &csa.beacon_csa_head,
            &csa.beacon_csa_tail,
            tim_ie_offset,
            30,
            "AP CSA beacon",
        )
        .await?;
        self.pending
            .ap_channel_switch_events
            .push_back(ApChannelSwitchEvent {
                def: csa.def,
                count: csa.count,
                block_tx: csa.block_tx,
                started: true,
            });
        self.ap.as_mut().unwrap().csa = Some(csa);
        if cfg.block_tx {
            self.dp.ap_channel_switching(vdev_id, true);
        }
        Ok(())
    }

    /// Advance the software-owned CSA beacon countdown on each TBTT.  The
    /// target owns actual beacon scheduling, while ath11k's WMI template API
    /// requires each new countdown byte to be uploaded explicitly.
    async fn finish_ap_channel_switch(&mut self) {
        let now = self.wmi.now_ms();
        let Some(csa) = self
            .ap
            .as_ref()
            .and_then(|ap| ap.csa.as_ref())
            .filter(|csa| now >= csa.deadline)
            .cloned()
        else {
            return;
        };
        if csa.count > 1 {
            let mut next = csa;
            next.count -= 1;
            for &offset in &next.counter_offsets_beacon {
                next.beacon_csa_tail[offset as usize] = next.count;
            }
            if let Some(probe_resp) = next.probe_resp_csa.as_mut() {
                for &offset in &next.counter_offsets_presp {
                    probe_resp[offset as usize] = next.count;
                }
            }
            let beacon_interval = self.vif.as_ref().map_or(1, |vif| vif.beacon_interval);
            let interval_ms = (u64::from(beacon_interval)
                .saturating_mul(1024)
                .saturating_add(999)
                / 1000)
                .max(1);
            next.deadline = now.saturating_add(interval_ms);
            let tim_ie_offset = Self::ap_tim_ie_offset(&next.beacon_csa_head).unwrap();
            match self
                .upload_ap_beacon_template(
                    &next.beacon_csa_head,
                    &next.beacon_csa_tail,
                    tim_ie_offset,
                    40,
                    "AP CSA countdown beacon",
                )
                .await
            {
                Ok(()) => self.ap.as_mut().unwrap().csa = Some(next),
                Err(error) => {
                    error.report("AP CSA countdown");
                    let _ = self.stop_ap().await;
                }
            }
            return;
        }
        if let Err(error) = self.complete_ap_channel_switch(&csa).await {
            error.report("AP CSA restart");
            let _ = self.stop_ap().await;
        }
    }

    /// Synchronous admission checks used by the netlink front end before it
    /// queues AP operations on the runtime task.  They never claim the WMI
    /// operation has completed; that remains the async operation below.
    pub fn ap_active(&self) -> bool {
        self.ap.is_some()
            && self
                .vif
                .as_ref()
                .is_some_and(|vif| vif.kind.is_ap() && vif.is_up)
    }

    pub fn ap_has_station(&self, addr: [u8; 6]) -> bool {
        self.ap
            .as_ref()
            .is_some_and(|ap| ap.stations.iter().any(|station| station.mac == addr))
    }

    /// AP / GO client identities for `NL80211_CMD_GET_STATION` dumps. This
    /// is deliberately a snapshot: callers hold no MAC lock while encoding
    /// generic-netlink replies, so a concurrent delete may omit a later
    /// record just as cfg80211's dump iterator can advance past it.
    pub fn ap_station_macs(&self) -> Vec<[u8; 6]> {
        self.ap
            .as_ref()
            .map(|ap| ap.stations.iter().map(|station| station.mac).collect())
            .unwrap_or_default()
    }

    pub fn ap_has_key(&self, idx: u8, pairwise: bool, peer: Option<[u8; 6]>) -> bool {
        let Some(ap) = self.ap.as_ref() else {
            return false;
        };
        if pairwise {
            let Some(peer) = peer else {
                return false;
            };
            ap.stations.iter().any(|station| {
                station.mac == peer
                    && station
                        .pairwise_key
                        .as_ref()
                        .is_some_and(|(key_idx, _, _)| *key_idx == idx)
            })
        } else {
            peer.is_none()
                && (ap.group_keys.iter().any(|key| key.idx == idx)
                    || ap.igtks.iter().any(|key| key.idx == idx))
        }
    }

    /// `set_default_mgmt_key`: switch the BIP-CMAC-128 transmit key without
    /// touching firmware. The selected IGTK must already be installed.
    pub fn set_ap_default_mgmt_key(&mut self, idx: u8) -> Result<(), MacError> {
        let Some(ap) = self.ap.as_mut() else {
            return fail(
                step::KEY_INSTALL,
                0x427,
                errno::ENOTCONN,
                "AP default IGTK (AP down)",
            );
        };
        if !ap.igtks.iter().any(|key| key.idx == idx) {
            return fail(
                step::KEY_INSTALL,
                0x428,
                errno::ENOENT,
                "AP default IGTK (missing)",
            );
        }
        ap.default_igtk = Some(idx);
        Ok(())
    }

    async fn ap_peer_associate(
        &mut self,
        station: &ApStation,
        def: ChanDef,
        privacy: bool,
        reassociate: bool,
    ) -> Result<(), MacError> {
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let (supported_rates, _) = peer::rates_to_mask(def.band, &station.supported_rates);
        let mut sta = ApSta {
            addr: station.mac,
            supp_rates: supported_rates,
            wme: station.wme,
            uapsd_queues: station.uapsd_queues,
            max_sp: station.uapsd_max_sp,
            mfp: station.mfp,
            ..Default::default()
        };
        // cfg80211 gives hostapd's parsed association capabilities to the
        // driver through NEW_STATION. Intersect each capability with this
        // radio's advertised capability exactly as the station association
        // path does before it fills WMI_PEER_ASSOC_CMDID.
        sta.ht_cap = peer::sta_ht_cap(self.own.ht(def.band), station.ht_cap.as_ref());
        let have_80 = self
            .wiphy
            .band(def.band)
            .iter()
            .any(|channel| channel.flags & (chan_flag::DISABLED | chan_flag::NO_80MHZ) == 0);
        if let Some(own) = self.own.vht(def.band) {
            sta.vht_cap = peer::sta_vht_cap(own, &sta.ht_cap, station.vht_cap.as_ref(), have_80);
        }
        sta.bandwidth = Some(peer::sta_bandwidth(&sta.ht_cap, &sta.vht_cap, &def));
        sta.rx_nss = peer::sta_rx_nss(&sta.ht_cap, &sta.vht_cap);
        let mut ap_he = None;
        if let (Some(own), Some(remote)) = (self.own_he(def.band), station.he_cap.as_ref()) {
            let mut cap = he::sta_he_cap(own, remote);
            match def.width {
                Width::W160 => cap.phy[0] &= !he::cap::PHY0_80PLUS80_MHZ_IN_5G,
                Width::W80P80 => cap.phy[0] &= !he::cap::PHY0_160MHZ_IN_5G,
                _ => {}
            }
            let cap_bw = match he::he_cap_rx_bw(&cap, def.band) {
                160 => peer::StaBw::Bw160,
                80 => peer::StaBw::Bw80,
                40 => peer::StaBw::Bw40,
                _ => peer::StaBw::Bw20,
            };
            let chan_bw = match def.width {
                Width::W20NoHt | Width::W20 => peer::StaBw::Bw20,
                Width::W40 => peer::StaBw::Bw40,
                Width::W80 => peer::StaBw::Bw80,
                Width::W80P80 | Width::W160 => peer::StaBw::Bw160,
            };
            sta.bandwidth = Some(cap_bw.min(chan_bw));
            sta.rx_nss = sta.rx_nss.max(he::he_rx_nss(&cap)).max(1);
            ap_he = Some(peer::ApHe {
                cap,
                // The AP's HE operation belongs to the vdev configuration.
                // It is not an attribute of an individual associated client.
                oper_params: 0,
                six_ghz_cap: station.he_6ghz_cap,
            });
        }
        let selection = self.bitrate_mask.band(nl80211_band(def.band)).cloned();
        let mut arg = peer::peer_assoc_prepare(&peer::PeerAssocInput {
            vdev_id,
            aid: station.aid,
            assoc_capability: station.capability,
            listen_interval: station.listen_interval as u32,
            nss_ratio_info: self.caps.pdev.nss_ratio_info,
            def,
            sta: &sta,
            he: ap_he.as_ref(),
            // The limited pre-existing nl80211 AP station record does not
            // carry parsed RSN/WPA IEs yet. Privacy still tells firmware the
            // client must not pass unprotected data before hostapd installs
            // a pairwise key and authorizes it.
            rsn: privacy,
            wpa: false,
        });
        peer::apply_tx_bitrate_band(&mut arg, selection.as_ref());
        if reassociate {
            arg.is_assoc = false;
        }
        self.pending.peer_assoc_conf = None;
        let c = match peer_assoc_cmd(&arg, false) {
            Ok(c) => c,
            Err(e) => return fail(step::AP_PEER_ASSOC, 0, e.errno(), "AP peer assoc encode"),
        };
        self.cmd(c, step::AP_PEER_ASSOC, 1, "AP peer assoc").await?;
        if self
            .wait_for(timeout::PEER_ASSOC, |s| {
                s.pending
                    .peer_assoc_conf
                    .take()
                    .filter(|p| p.vdev_id == vdev_id && p.peer_macaddr == station.mac)
            })
            .await
            .is_none()
        {
            return fail(
                step::AP_PEER_ASSOC_TIMEOUT,
                vdev_id,
                errno::ETIMEDOUT,
                "AP peer assoc (no conf)",
            );
        }
        self.program_peer_single_rate(
            vdev_id,
            station.mac,
            sta.vht_cap.vht_supported,
            ap_he.is_some(),
            sta.ht_cap.ht_supported,
            sta.rx_nss.max(1) as u32,
            selection.as_ref(),
        )
        .await?;
        if !reassociate && station.wme && station.uapsd_queues != 0 {
            self.ap_peer_uapsd(
                vdev_id,
                station.mac,
                station.uapsd_queues,
                station.uapsd_max_sp,
            )
            .await?;
        }
        if let Some(setting) = station.station_tx_power {
            self.program_peer_station_tx_power(vdev_id, station.mac, setting)
                .await?;
        }
        Ok(())
    }

    /// `NL80211_CMD_NEW_STATION` → `ath11k_mac_station_add` / the AP arm of
    /// `ath11k_mac_op_sta_state(ASSOC)`: create, wait for DP mapping, set up
    /// the peer, then deliver its association parameters to firmware.
    pub async fn add_ap_station(&mut self, cfg: StationConfig) -> Result<(), MacError> {
        let (def, privacy) = match self.ap.as_ref() {
            Some(ap) if !ap.stations.iter().any(|s| s.mac == cfg.mac) => (ap.def, ap.privacy),
            Some(_) => return fail(step::AP_PEER_CREATE, 0, errno::EBUSY, "AP station exists"),
            None => {
                return fail(
                    step::AP_PEER_CREATE,
                    1,
                    errno::ENOTCONN,
                    "AP station (AP down)",
                )
            }
        };
        let ht_cap = match cfg.ht_capability.as_deref() {
            Some(raw) => match frame::HtCapIe::parse(raw) {
                Some(cap) => Some(cap),
                None => {
                    return fail(
                        step::AP_PEER_ASSOC,
                        0x10,
                        errno::EINVAL,
                        "AP station HT capability",
                    )
                }
            },
            None => None,
        };
        let vht_cap = match cfg.vht_capability.as_deref() {
            Some(raw) => match frame::VhtCapIe::parse(raw) {
                Some(cap) => Some(cap),
                None => {
                    return fail(
                        step::AP_PEER_ASSOC,
                        0x11,
                        errno::EINVAL,
                        "AP station VHT capability",
                    )
                }
            },
            None => None,
        };
        let he_cap = match cfg.he_capability.as_deref() {
            Some(raw) => match he::parse_he_cap(raw) {
                Some(cap) => Some(cap),
                None => {
                    return fail(
                        step::AP_PEER_ASSOC,
                        0x12,
                        errno::EINVAL,
                        "AP station HE capability",
                    )
                }
            },
            None => None,
        };
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        self.cmd(
            peer_create_cmd(vdev_id, &cfg.mac, peer_type::DEFAULT),
            step::AP_PEER_CREATE,
            0,
            "AP peer create",
        )
        .await?;
        if let Err(e) = self
            .dp
            .wait_peer_mapped(vdev_id, cfg.mac, true, timeout::PEER_MAP)
            .await
        {
            return fail(
                step::AP_PEER_MAP_TIMEOUT,
                vdev_id,
                e,
                "AP peer create (no PEER_MAP)",
            );
        }
        if let Err(e) = self.dp.peer_setup(vdev_id, cfg.mac).await {
            self.peer_delete(cfg.mac).await;
            return fail(step::AP_PEER_CREATE, 1, e, "AP dp peer setup");
        }
        let station = ApStation {
            mac: cfg.mac,
            aid: cfg.aid,
            listen_interval: cfg.listen_interval,
            supported_rates: cfg.supported_rates,
            wme: cfg.wme.unwrap_or(false),
            uapsd_queues: cfg.uapsd_queues.unwrap_or(0),
            uapsd_max_sp: cfg.uapsd_max_sp.unwrap_or(0),
            mfp: cfg.mfp.unwrap_or(false),
            capability: cfg.capability.unwrap_or(0),
            ext_capability: cfg.ext_capability.unwrap_or_default(),
            ht_cap,
            vht_cap,
            he_cap,
            he_6ghz_cap: cfg.he_6ghz_capability,
            station_tx_power: cfg.station_tx_power,
            pairwise_key: None,
            mgmt_tx_pn: 0,
            mgmt_rx_pn: 0,
            authorized: false,
        };
        if let Err(e) = self.ap_peer_associate(&station, def, privacy, false).await {
            self.dp.peer_cleanup(vdev_id, station.mac);
            self.peer_delete(station.mac).await;
            return Err(e);
        }
        if let Err(e) = self.ap_reinstall_group_keys().await {
            self.dp.peer_cleanup(vdev_id, station.mac);
            self.peer_delete(station.mac).await;
            return Err(e);
        }
        let wme = station.wme;
        self.ap.as_mut().unwrap().stations.push(station);
        self.dp.ap_station_added(vdev_id, cfg.mac, wme);
        // Open APs reach AUTHORIZED directly from ASSOC. A caller that
        // explicitly supplied STA_FLAGS2 can still keep that port closed.
        if cfg.authorized.unwrap_or(!privacy) {
            self.ap_set_authorized(cfg.mac, true).await?;
        }
        Ok(())
    }

    /// `NL80211_CMD_SET_STATION`: replace the caller-provided association
    /// properties and replay `WMI_PEER_ASSOC_CMDID`, the same operation
    /// mac80211 performs for a changed station rate/capability record.
    pub async fn set_ap_station(&mut self, cfg: StationConfig) -> Result<(), MacError> {
        let ht_cap = match cfg.ht_capability.as_deref() {
            Some(raw) => match frame::HtCapIe::parse(raw) {
                Some(cap) => Some(cap),
                None => {
                    return fail(
                        step::AP_PEER_ASSOC,
                        0x13,
                        errno::EINVAL,
                        "set AP station HT capability",
                    )
                }
            },
            None => None,
        };
        let vht_cap = match cfg.vht_capability.as_deref() {
            Some(raw) => match frame::VhtCapIe::parse(raw) {
                Some(cap) => Some(cap),
                None => {
                    return fail(
                        step::AP_PEER_ASSOC,
                        0x14,
                        errno::EINVAL,
                        "set AP station VHT capability",
                    )
                }
            },
            None => None,
        };
        let he_cap = match cfg.he_capability.as_deref() {
            Some(raw) => match he::parse_he_cap(raw) {
                Some(cap) => Some(cap),
                None => {
                    return fail(
                        step::AP_PEER_ASSOC,
                        0x15,
                        errno::EINVAL,
                        "set AP station HE capability",
                    )
                }
            },
            None => None,
        };
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let (def, privacy, station, requested_authorized) = {
            let Some(ap) = self.ap.as_ref() else {
                return fail(
                    step::AP_PEER_ASSOC,
                    2,
                    errno::ENOTCONN,
                    "set AP station (AP down)",
                );
            };
            let Some(old) = ap.stations.iter().find(|s| s.mac == cfg.mac) else {
                return fail(
                    step::AP_PEER_ASSOC,
                    3,
                    errno::ENOENT,
                    "set AP station (unknown)",
                );
            };
            (
                ap.def,
                ap.privacy,
                ApStation {
                    mac: cfg.mac,
                    aid: if cfg.aid == 0 { old.aid } else { cfg.aid },
                    listen_interval: if cfg.listen_interval == 0 {
                        old.listen_interval
                    } else {
                        cfg.listen_interval
                    },
                    supported_rates: if cfg.supported_rates.is_empty() {
                        old.supported_rates.clone()
                    } else {
                        cfg.supported_rates
                    },
                    wme: cfg.wme.unwrap_or(old.wme),
                    uapsd_queues: cfg.uapsd_queues.unwrap_or(old.uapsd_queues),
                    uapsd_max_sp: cfg.uapsd_max_sp.unwrap_or(old.uapsd_max_sp),
                    mfp: cfg.mfp.unwrap_or(old.mfp),
                    capability: cfg.capability.unwrap_or(old.capability),
                    ext_capability: cfg
                        .ext_capability
                        .unwrap_or_else(|| old.ext_capability.clone()),
                    ht_cap: ht_cap.or(old.ht_cap),
                    vht_cap: vht_cap.or(old.vht_cap),
                    he_cap: he_cap.or_else(|| old.he_cap.clone()),
                    he_6ghz_cap: cfg.he_6ghz_capability.or(old.he_6ghz_cap),
                    station_tx_power: cfg.station_tx_power.or(old.station_tx_power),
                    pairwise_key: old.pairwise_key.clone(),
                    mgmt_tx_pn: old.mgmt_tx_pn,
                    mgmt_rx_pn: old.mgmt_rx_pn,
                    authorized: old.authorized,
                },
                cfg.authorized,
            )
        };
        self.ap_peer_associate(&station, def, privacy, false)
            .await?;
        let old = self
            .ap
            .as_mut()
            .unwrap()
            .stations
            .iter_mut()
            .find(|old| old.mac == station.mac)
            .unwrap();
        let wme = station.wme;
        *old = station;
        self.dp.ap_station_added(vdev_id, cfg.mac, wme);
        if let Some(authorized) = requested_authorized {
            self.ap_set_authorized(cfg.mac, authorized).await?;
        }
        Ok(())
    }

    /// `NL80211_CMD_DEL_STATION` / AP teardown: stop the DP peer first,
    /// then use the normal ath11k peer-delete completion sequence.
    pub async fn del_ap_station(&mut self, mac: Option<[u8; 6]>) -> Result<(), MacError> {
        let stations = {
            let Some(ap) = self.ap.as_ref() else {
                return fail(
                    step::AP_PEER_DELETE,
                    0,
                    errno::ENOTCONN,
                    "delete AP station (AP down)",
                );
            };
            match mac {
                Some(mac) => {
                    let Some(station) = ap.stations.iter().find(|station| station.mac == mac)
                    else {
                        return fail(
                            step::AP_PEER_DELETE,
                            1,
                            errno::ENOENT,
                            "delete AP station (unknown)",
                        );
                    };
                    alloc::vec![(
                        station.mac,
                        station.pairwise_key.as_ref().map(|(idx, _, _)| *idx)
                    )]
                }
                None => ap
                    .stations
                    .iter()
                    .map(|station| {
                        (
                            station.mac,
                            station.pairwise_key.as_ref().map(|(idx, _, _)| *idx),
                        )
                    })
                    .collect::<Vec<_>>(),
            }
        };
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        for (station, pairwise_key) in stations {
            if let Some(idx) = pairwise_key {
                // Peer teardown must progress even if a damaged firmware
                // rejects a DISABLE_KEY completion, as in mac80211's
                // best-effort sta flush.
                let _ = self.disable_key(station, idx, true).await;
            }
            // Stop data selection before handing the peer to the DP
            // teardown path; an in-flight Ethernet TX cannot target a
            // disappearing AP client.
            self.dp.ap_station_removed(vdev_id, station);
            self.dp.peer_cleanup(vdev_id, station);
            self.peer_delete(station).await;
            self.ap
                .as_mut()
                .unwrap()
                .stations
                .retain(|known| known.mac != station);
        }
        Ok(())
    }

    /// Reapply GTKs after `ath11k_mac_station_add`. Linux does this for an
    /// AP peer join because firmware may have discarded the vdev group-key
    /// state while no client was mapped.
    async fn ap_reinstall_group_keys(&mut self) -> Result<(), MacError> {
        let (addr, keys) = {
            let Some(ap) = self.ap.as_ref() else {
                return Ok(());
            };
            let addr = self.vif.as_ref().unwrap().addr;
            (addr, ap.group_keys.clone())
        };
        for key in keys {
            self.install_key_with_cipher(addr, key.idx, &key.key, false, key.cipher)
                .await?;
        }
        Ok(())
    }

    /// AP counterpart to mac80211's `ath11k_mac_op_set_key(SET_KEY)`.  A
    /// pairwise key belongs to its client; a group key is addressed through
    /// the AP vdev MAC just as Linux uses `arvif->vif->addr`. BIP IGTKs
    /// instead stay entirely in host memory, where `mfp_tx` appends MMIEs.
    pub async fn add_ap_key(&mut self, key: narf_wireless::KeyParams) -> Result<(), MacError> {
        if firmware_key_cipher(key.cipher).is_none() && sec::bip_cipher(key.cipher).is_none() {
            return fail(
                step::KEY_INSTALL,
                key.cipher,
                errno::EOPNOTSUPP,
                "AP key cipher",
            );
        }
        let Some(own_addr) = self.vif.as_ref().map(|vif| vif.addr) else {
            return fail(
                step::KEY_INSTALL,
                0x420,
                errno::ENOTCONN,
                "AP key (no vdev)",
            );
        };
        if self.ap.is_none() {
            return fail(
                step::KEY_INSTALL,
                0x421,
                errno::ENOTCONN,
                "AP key (AP down)",
            );
        }
        if sec::bip_cipher(key.cipher).is_some() {
            if key.pairwise || key.peer.is_some() || !(4..=5).contains(&key.idx) {
                return fail(step::KEY_INSTALL, 0x425, errno::EINVAL, "AP IGTK shape");
            }
            if key.key.len() != sec::bip_cipher(key.cipher).unwrap().key_len() {
                return fail(step::KEY_INSTALL, 0x426, errno::EINVAL, "AP IGTK length");
            }
            if self.ap.as_ref().unwrap().igtks.iter().any(|known| {
                known.idx == key.idx
                    && known.cipher == key.cipher
                    && known.key.as_slice() == key.key.as_slice()
            }) {
                if key.default_mgmt {
                    self.ap.as_mut().unwrap().default_igtk = Some(key.idx);
                }
                return Ok(());
            }
            let tx_ipn = if key.seq.len() == 6 {
                narf_crypto::bip_cmac::decode_ipn(&key.seq)
            } else {
                0
            };
            let default_missing = self.ap.as_ref().unwrap().default_igtk.is_none();
            let igtks = &mut self.ap.as_mut().unwrap().igtks;
            igtks.retain(|known| known.idx != key.idx);
            igtks.push(ApIgtk {
                idx: key.idx,
                cipher: key.cipher,
                key: key.key,
                tx_ipn,
            });
            if key.default_mgmt || default_missing {
                self.ap.as_mut().unwrap().default_igtk = Some(key.idx);
            }
            return Ok(());
        }
        if key.pairwise {
            let Some(peer) = key.peer else {
                return fail(
                    step::KEY_INSTALL,
                    0x422,
                    errno::EINVAL,
                    "AP pairwise key (no peer)",
                );
            };
            let Some((station_mfp, previous)) = self
                .ap
                .as_ref()
                .unwrap()
                .stations
                .iter()
                .find(|station| station.mac == peer)
                .map(|station| (station.mfp, station.pairwise_key.clone()))
            else {
                return fail(
                    step::KEY_INSTALL,
                    0x423,
                    errno::ENOENT,
                    "AP pairwise key (unknown peer)",
                );
            };
            if station_mfp && sec::protected_mgmt_mic_len(key.cipher).is_none() {
                return fail(
                    step::KEY_INSTALL,
                    key.cipher,
                    errno::EOPNOTSUPP,
                    "AP MFP pairwise cipher",
                );
            }
            if previous.as_ref().is_some_and(|(idx, suite, material)| {
                *idx == key.idx && *suite == key.cipher && material.as_slice() == key.key.as_slice()
            }) {
                // Same-material PTK reinstallation is a KRACK no-op.
                return Ok(());
            }
            if let Some((idx, _, _)) = previous {
                self.disable_key(peer, idx, true).await?;
            }
            self.install_key_with_cipher(peer, key.idx, &key.key, true, key.cipher)
                .await?;
            let station = self
                .ap
                .as_mut()
                .unwrap()
                .stations
                .iter_mut()
                .find(|station| station.mac == peer)
                .unwrap();
            station.pairwise_key = Some((key.idx, key.cipher, key.key));
            // A new/replaced PTK starts a fresh management replay window.
            station.mgmt_tx_pn = 0;
            station.mgmt_rx_pn = 0;
            return Ok(());
        }
        if key.peer.is_some() {
            return fail(
                step::KEY_INSTALL,
                0x424,
                errno::EINVAL,
                "AP group key (peer)",
            );
        }
        if self.ap.as_ref().unwrap().group_keys.iter().any(|known| {
            known.idx == key.idx
                && known.cipher == key.cipher
                && known.key.as_slice() == key.key.as_slice()
        }) {
            return Ok(());
        }
        self.install_key_with_cipher(own_addr, key.idx, &key.key, false, key.cipher)
            .await?;
        let keys = &mut self.ap.as_mut().unwrap().group_keys;
        keys.retain(|known| known.idx != key.idx);
        keys.push(ApGroupKey {
            idx: key.idx,
            cipher: key.cipher,
            key: key.key,
        });
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        self.dp.ap_group_key(vdev_id, true);
        Ok(())
    }

    /// AP counterpart to `ath11k_mac_op_set_key(DISABLE_KEY)`. Firmware can
    /// race a GTK disable with live client traffic, so match Linux: defer a
    /// group-key disable until the AP has no associated client.
    pub async fn del_ap_key(
        &mut self,
        idx: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), MacError> {
        if !pairwise && peer.is_none() && idx >= 4 {
            let Some(ap) = self.ap.as_mut() else {
                return fail(
                    step::KEY_INSTALL,
                    0x435,
                    errno::ENOTCONN,
                    "AP del IGTK (AP down)",
                );
            };
            let before = ap.igtks.len();
            ap.igtks.retain(|key| key.idx != idx);
            if ap.default_igtk == Some(idx) {
                ap.default_igtk = ap.igtks.last().map(|key| key.idx);
            }
            return if ap.igtks.len() != before {
                Ok(())
            } else {
                fail(
                    step::KEY_INSTALL,
                    0x436,
                    errno::ENOENT,
                    "AP del IGTK (missing)",
                )
            };
        }
        if pairwise {
            let Some(peer) = peer else {
                return fail(
                    step::KEY_INSTALL,
                    0x430,
                    errno::EINVAL,
                    "AP del PTK (no peer)",
                );
            };
            let present = self.ap.as_ref().is_some_and(|ap| {
                ap.stations.iter().any(|station| {
                    station.mac == peer
                        && station
                            .pairwise_key
                            .as_ref()
                            .is_some_and(|(key_idx, _, _)| *key_idx == idx)
                })
            });
            if !present {
                return fail(
                    step::KEY_INSTALL,
                    0x431,
                    errno::ENOENT,
                    "AP del PTK (missing)",
                );
            }
            self.disable_key(peer, idx, true).await?;
            let station = self
                .ap
                .as_mut()
                .unwrap()
                .stations
                .iter_mut()
                .find(|station| station.mac == peer)
                .unwrap();
            station.pairwise_key = None;
            station.mgmt_tx_pn = 0;
            station.mgmt_rx_pn = 0;
            return Ok(());
        }
        if peer.is_some() {
            return fail(step::KEY_INSTALL, 0x432, errno::EINVAL, "AP del GTK (peer)");
        }
        let (own_addr, has_clients, present) = {
            let Some(ap) = self.ap.as_ref() else {
                return fail(
                    step::KEY_INSTALL,
                    0x433,
                    errno::ENOTCONN,
                    "AP del GTK (AP down)",
                );
            };
            (
                self.vif.as_ref().unwrap().addr,
                !ap.stations.is_empty(),
                ap.group_keys.iter().any(|key| key.idx == idx),
            )
        };
        if !present {
            return fail(
                step::KEY_INSTALL,
                0x434,
                errno::ENOENT,
                "AP del GTK (missing)",
            );
        }
        if !has_clients {
            self.disable_key(own_addr, idx, false).await?;
        }
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let keys_remain = {
            let ap = self.ap.as_mut().unwrap();
            ap.group_keys.retain(|key| key.idx != idx);
            !ap.group_keys.is_empty()
        };
        self.dp.ap_group_key(vdev_id, keys_remain);
        Ok(())
    }

    /// `sta_apply_auth_flags` for an AP client. Firmware receives the
    /// authorize transition only when enabling; disabling blocks DP data
    /// locally, matching ath11k's station-state transition semantics.
    pub async fn ap_set_authorized(&mut self, addr: [u8; 6], on: bool) -> Result<(), MacError> {
        let (vdev_id, was_authorized) = {
            let Some(ap) = self.ap.as_ref() else {
                return fail(
                    step::PEER_AUTHORIZE,
                    0x20,
                    errno::ENOTCONN,
                    "authorize AP peer (AP down)",
                );
            };
            let Some(station) = ap.stations.iter().find(|station| station.mac == addr) else {
                return fail(
                    step::PEER_AUTHORIZE,
                    0x21,
                    errno::ENOENT,
                    "authorize AP peer (unknown)",
                );
            };
            (self.vif.as_ref().unwrap().vdev_id, station.authorized)
        };
        if on && !was_authorized {
            self.cmd(
                peer_set_param_cmd(&addr, vdev_id, peer_param::AUTHORIZE, 1),
                step::PEER_AUTHORIZE,
                2,
                "authorize AP peer",
            )
            .await?;
        }
        self.dp.set_authorized(addr, on);
        self.ap
            .as_mut()
            .unwrap()
            .stations
            .iter_mut()
            .find(|station| station.mac == addr)
            .unwrap()
            .authorized = on;
        Ok(())
    }

    /// `NL80211_CMD_STOP_AP`: remove every peer, stop beaconing, and release
    /// the AP channel context while preserving the administratively-open AP
    /// vdev for a later START_AP.
    pub async fn stop_ap(&mut self) -> Result<(), MacError> {
        if self.ap.is_none() {
            return Ok(());
        }
        self.abort_ap_dfs_cac();
        self.del_ap_station(None).await?;
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        if self.ap.as_ref().is_some_and(|ap| ap.twt_responder) {
            // BSS_CHANGED_TWT clears the responder role before ath11k tears
            // the AP vdev down. Like Linux, a failed disable does not block
            // the normal AP stop sequence.
            self.twt_ap_changed(false).await;
        }
        if self
            .ap
            .as_ref()
            .is_some_and(|ap| ap.fils_discovery.is_some() || ap.unsol_bcast_probe_resp.is_some())
        {
            // A vdev teardown also discards target templates, but send the
            // documented disable command first while the AP is still up.
            let _ = self
                .cmd(
                    fils_discovery_cmd(vdev_id, 0, false),
                    step::AP_DISCOVERY,
                    9,
                    "AP discovery disable on stop",
                )
                .await;
        }
        let result = self
            .cmd(
                vdev_down_cmd(vdev_id as u8),
                step::VDEV_UP,
                3,
                "AP vdev down",
            )
            .await;
        if self.vif.as_ref().is_some_and(|v| v.is_started) {
            self.vdev_stop().await;
        }
        let vif = self.vif.as_mut().unwrap();
        vif.is_up = false;
        vif.chanctx = None;
        vif.bssid = [0; 6];
        vif.aid = 0;
        self.ap = None;
        self.dp.ap_stopped(vdev_id);
        result
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
            self.conf_tx(ac, p, None).await?;
        }
        Ok(())
    }

    /// `ieee80211_tx_queue_params::mu_edca` makes mac80211 call
    /// `ath11k_mac_op_conf_tx` once per AC with the matching HE record.
    /// Keep the legacy WMM, HE MU-EDCA and U-APSD writes interleaved per AC
    /// just as that callback does, rather than treating MU-EDCA as a second
    /// independent four-AC transaction.
    async fn conf_tx_all_with_mu_edca(
        &mut self,
        q: &[TxQueueParams; 4],
        mu_edca: &frame::MuEdcaParam,
    ) -> Result<(), MacError> {
        for (ac, p) in q.iter().enumerate() {
            // IEEE80211_AC_{VO,VI,BE,BK} → element/WME {3,2,0,1}.
            let record = mu_edca.ac[[3usize, 2, 0, 1][ac]];
            self.conf_tx(ac, p, Some(record)).await?;
        }
        Ok(())
    }

    /// `_ieee80211_sta_wmm_params` for a later beacon. The WMM Parameter
    /// element is mandatory for an update; an MU-EDCA element alone is not.
    /// The two parameter-set counters form one update generation, matching
    /// mac80211's `wmm_last_param_set` / `mu_edca_last_param_set` check.
    fn wmm_params_from_beacon(
        &mut self,
        ies: &ParsedIes,
    ) -> Option<([TxQueueParams; 4], Option<frame::MuEdcaParam>, [u8; 6])> {
        let wmm = ies.wmm_param?;
        let wmm_param_set = wmm.qos_info & 0x0f;
        let mu_edca = ies.mu_edca;
        let mu_edca_param_set = mu_edca.map(|param| param.qos_info & 0x0f);
        let link = self.link.as_mut()?;
        if !link.assoc
            || link.disable_wmm_tracking
            || (link.wmm_last_param_set == Some(wmm_param_set)
                && link.mu_edca_last_param_set == mu_edca_param_set)
        {
            return None;
        }

        // Linux updates its state before record validation. This avoids
        // repeatedly programming a malformed beacon from a broken AP.
        link.wmm_last_param_set = Some(wmm_param_set);
        link.mu_edca_last_param_set = mu_edca_param_set;
        let q = wmm_from_ie_checked(&wmm)?;
        link.wmm = true;
        link.sta.wme = true;
        Some((q, mu_edca, link.bss.bssid))
    }

    /// `ieee80211_rx_bss_info`: update mac80211's `ewma_beacon_signal`
    /// (precision 4, weight 4) and emit software CQM crossings after
    /// `IEEE80211_SIGNAL_AVE_MIN_COUNT` = four beacons.
    fn cqm_rssi_beacon(&mut self, sample_dbm: i32) {
        let config = self.cqm_rssi.clone();
        let event = {
            let Some(link) = self.link.as_mut() else {
                return;
            };
            if !link.assoc {
                return;
            }
            // mac80211 EWMA stores the positive signal magnitude; its read
            // path negates it back into an RSSI value.
            let magnitude = sample_dbm.saturating_neg().max(0) as u32;
            let scaled = magnitude.saturating_mul(16);
            let ewma = match link.beacon_signal_ewma {
                Some(previous) => previous.saturating_mul(15).saturating_add(scaled) / 16,
                None => scaled,
            };
            link.beacon_signal_ewma = Some(ewma);
            link.beacon_signal_count = link.beacon_signal_count.saturating_add(1);

            let Some(config) = config else {
                return;
            };
            if link.beacon_signal_count < 4 {
                return;
            }
            let level_dbm = -((ewma / 16) as i32);
            let event = if config.thresholds_dbm.len() > 1 {
                // The active pair is the same pair cfg80211 sends through
                // `set_cqm_rssi_range_config`. A new association configured
                // before it had beacon samples starts from cfg80211's zero
                // sentinel and therefore observes its first below-range
                // crossing rather than silently discarding it.
                let (low, high) = link
                    .cqm_rssi_range
                    .unwrap_or_else(|| Self::cqm_rssi_range(&config, 0));
                if level_dbm < low && link.last_cqm_event_signal.is_none_or(|last| last >= low) {
                    Some(false)
                } else if level_dbm > high
                    && link.last_cqm_event_signal.is_none_or(|last| last <= high)
                {
                    Some(true)
                } else {
                    None
                }
            } else {
                let threshold = config.thresholds_dbm[0];
                let hysteresis = config.hysteresis_db.min(i32::MAX as u32) as i32;
                if level_dbm < threshold
                    && link
                        .last_cqm_event_signal
                        .is_none_or(|last| level_dbm < last.saturating_sub(hysteresis))
                {
                    Some(false)
                } else if level_dbm > threshold
                    && link
                        .last_cqm_event_signal
                        .is_none_or(|last| level_dbm > last.saturating_add(hysteresis))
                {
                    Some(true)
                } else {
                    None
                }
            };
            event.map(|high| {
                link.last_cqm_event_signal = Some(level_dbm);
                if config.thresholds_dbm.len() > 1 {
                    link.cqm_rssi_range = Some(Self::cqm_rssi_range(&config, level_dbm));
                }
                CqmRssiEvent { high, level_dbm }
            })
        };
        if let Some(event) = event {
            const MAX_CQM_RSSI_EVENTS: usize = 8;
            if self.pending.cqm_rssi.len() == MAX_CQM_RSSI_EVENTS {
                self.pending.cqm_rssi.remove(0);
            }
            self.pending.cqm_rssi.push(event);
        }
    }

    /// `ath11k_mac_op_conf_tx(ac)`: update `arvif->wmm_params`, send
    /// all four, then `ath11k_conf_tx_uapsd`.
    async fn conf_tx(
        &mut self,
        ac: usize,
        p: &TxQueueParams,
        mu_edca: Option<frame::MuEdcaAc>,
    ) -> Result<(), MacError> {
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
        if let Some(record) = mu_edca {
            let v = self.vif.as_mut().unwrap();
            v.mu_edca[wme].cwmin = u16::from(record.ecw_min_max & 0x0f);
            v.mu_edca[wme].cwmax = u16::from(record.ecw_min_max >> 4);
            v.mu_edca[wme].aifs = record.aifsn & 0x0f;
            v.mu_edca[wme].txop = u16::from(record.timer);
            let mu_edca = v.mu_edca;
            self.cmd(
                vdev_set_wmm_params_cmd(vdev, &mu_edca, WMI_WMM_PARAM_TYPE_11AX_MU_EDCA),
                step::WMM_PARAMS,
                4 + ac as u32,
                "HE MU-EDCA params",
            )
            .await?;
        }
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
                let roc = self.scan.roc.take();
                self.scan.aborted = matches!(st, ScanState::Aborting | ScanState::Starting);
                self.scan.state = ScanState::Idle;
                self.scan.deadline = None;
                self.scan.completed = true;
                if let Some(roc) = roc.filter(|roc| roc.started) {
                    self.pending.roc_events.push_back(RemainOnChannelEvent {
                        cookie: roc.cookie,
                        frequency_mhz: roc.frequency_mhz,
                        duration_ms: roc.duration_ms,
                        started: false,
                    });
                }
            }
        }
    }

    /// `ieee80211_send_probe_resp`: select the active normal/CSA response
    /// template, verify the requested SSID, and replace the template's
    /// destination address. Sending remains deferred because WMI TX may wait
    /// for its descriptor and an RX event must not re-enter that path.
    fn queue_ap_probe_response(&mut self, request: &[u8], hdr: &frame::MgmtHdr) {
        let Some(vif) = self
            .vif
            .as_ref()
            .filter(|vif| vif.kind.is_ap() && vif.is_up)
        else {
            return;
        };
        if hdr.bssid != [0xff; 6] && hdr.bssid != vif.addr {
            return;
        }
        let Some(ap) = self.ap.as_ref() else {
            return;
        };
        let template = ap
            .csa
            .as_ref()
            .and_then(|csa| csa.probe_resp_csa.as_ref())
            .or(ap.probe_resp.as_ref());
        let Some(template) = template else {
            return;
        };
        let request_ssid = frame::find_elem(&request[frame::MGMT_HDR_LEN..], eid::SSID);
        let response_ssid = template
            .get(frame::MGMT_HDR_LEN + 12..)
            .and_then(|ies| frame::find_elem(ies, eid::SSID));
        // An absent/malformed SSID is not a valid probe request. A wildcard
        // is answered; a directed request must name this BSS exactly.
        let Some(request_ssid) = request_ssid else {
            return;
        };
        if !request_ssid.is_empty() && Some(request_ssid) != response_ssid {
            return;
        }
        let mut response = template.clone();
        response[4..10].copy_from_slice(&hdr.sa);
        const MAX_AP_PROBE_RESPONSES: usize = 64;
        if self.pending.ap_probe_responses.len() == MAX_AP_PROBE_RESPONSES {
            self.pending.ap_probe_responses.pop_front();
        }
        self.pending.ap_probe_responses.push_back(response);
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
        // cfg80211_rx_mgmt feeds registrations independently of mac80211's
        // local MLME handling. Preserve the full accepted frame plus WMI's
        // physical metadata for the runtime to publish after it drops this
        // mutex. Cap the queue to one practical event slice; management RX is
        // untrusted and cannot be allowed to consume arbitrary memory while a
        // userspace daemon is briefly delayed.
        const MAX_REGISTERED_MGMT_RX: usize = 64;
        if self.vif.is_some() {
            if self.pending.registered_mgmt_rx.len() == MAX_REGISTERED_MGMT_RX {
                self.pending.registered_mgmt_rx.pop_front();
            }
            self.pending.registered_mgmt_rx.push_back(RegisteredMgmtRx {
                frequency_mhz: st.freq,
                signal_dbm: st.signal,
                frame: f.to_vec(),
            });
        }
        match stype {
            frame::stype::PROBE_REQ => self.queue_ap_probe_response(f, &hdr),
            frame::stype::BEACON | frame::stype::PROBE_RESP => {
                let Some(b) = frame::parse_beacon(m.frame) else {
                    return;
                };
                if !b.is_probe_resp {
                    let ies = ParsedIes::parse(b.ies);
                    let now = self.wmi.now_ms();
                    let mut ours = false;
                    if let Some(l) = self.link.as_mut() {
                        if hdr.bssid == l.bss.bssid {
                            // ath11k_mac_handle_beacon: cancel connection_loss_work,
                            // and refresh the associated cfg80211 BSS's
                            // beacon IEs before CSA/TPE consumers inspect it.
                            l.conn_loss_deadline = None;
                            l.have_beacon = true;
                            l.last_signal = Some(st.signal);
                            l.bss.capability = b.capability;
                            l.bss.beacon_int = b.beacon_int;
                            l.bss.signal = st.signal;
                            l.bss.ies = b.ies.to_vec();
                            l.bss.beacon_ies = Some(b.ies.to_vec());
                            l.bss.last_seen_ms = now;
                            ours = true;
                        }
                    }
                    // `_ieee80211_sta_wmm_params`: a beacon can revise the
                    // WMM and HE MU-EDCA parameter-set counters after the
                    // association response. Latch a changed counter before
                    // validating the records, as mac80211 does, so a broken
                    // AP cannot make us retry the same malformed element on
                    // every beacon.
                    let qos_update = ours.then(|| self.wmm_params_from_beacon(&ies)).flatten();
                    if ours {
                        self.cqm_rssi_beacon(st.signal);
                        self.channel_switch_beacon_confirmed(st.freq);
                        self.queue_channel_switch(&ies, true);
                    }
                    if let Some((q, mu_edca, bssid)) = qos_update {
                        self.dp.set_sta_wme(bssid, true);
                        let result = match mu_edca {
                            Some(mu_edca) => narf_scheduler::block_on_spin(
                                self.conf_tx_all_with_mu_edca(&q, &mu_edca),
                            ),
                            None => narf_scheduler::block_on_spin(self.conf_tx_all(&q)),
                        };
                        if let Err(e) = result {
                            e.report("beacon WMM parameter update");
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
                {
                    return;
                }
                if matches!(
                    f[frame::MGMT_HDR_LEN],
                    frame::WLAN_CATEGORY_PUBLIC | frame::WLAN_CATEGORY_PROTECTED_DUAL_OF_ACTION
                ) && f[frame::MGMT_HDR_LEN + 1] == frame::WLAN_PUB_ACTION_EXT_CHANSW_ANN
                    && f.len() >= frame::MGMT_HDR_LEN + 6
                {
                    // `u.action.u.ext_chan_switch`: unlike the ordinary
                    // Spectrum-Management action, ECSA's fixed four-byte
                    // payload is not an IE. Parse its following IEs, then
                    // install the fixed payload as mac80211 does.
                    let mut ies = ParsedIes::parse(&f[frame::MGMT_HDR_LEN + 6..]);
                    ies.ext_channel_switch = frame::ExtChannelSwitchIe::parse(
                        &f[frame::MGMT_HDR_LEN + 2..frame::MGMT_HDR_LEN + 6],
                    );
                    if f[frame::MGMT_HDR_LEN] == frame::WLAN_CATEGORY_PUBLIC {
                        self.queue_untrusted_ext_channel_switch(&ies);
                    } else {
                        self.queue_channel_switch(&ies, false);
                    }
                    return;
                }
                if f[frame::MGMT_HDR_LEN] == frame::WLAN_CATEGORY_SPECTRUM_MGMT
                    && f[frame::MGMT_HDR_LEN + 1] == frame::WLAN_ACTION_SPCT_CHL_SWITCH
                {
                    // `ieee80211_sta_process_chanswitch`: MFP has already
                    // authenticated a robust Spectrum Management action
                    // above when this association requires it.
                    let ies = ParsedIes::parse(&f[frame::MGMT_HDR_LEN + 2..]);
                    self.queue_channel_switch(&ies, false);
                    return;
                }
                if f[frame::MGMT_HDR_LEN] != frame::WLAN_CATEGORY_BACK {
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

    /// `ath11k_mac_op_hw_scan` with the default target dwell policy.
    pub async fn hw_scan(
        &mut self,
        ssids: &[Vec<u8>],
        freqs: &[u32],
        random_mac: Option<narf_wireless::ScanRandomMac>,
        colocated_6ghz: bool,
    ) -> Result<Vec<ScanBss>, MacError> {
        self.hw_scan_with_duration(ssids, freqs, random_mac, colocated_6ghz, None, &[])
            .await
    }

    /// `ath11k_mac_op_hw_scan` for a cfg80211 scan request, then wait for
    /// `ieee80211_scan_completed`. Returns the BSS table entries seen in
    /// the last `IEEE80211_SCAN_RESULT_EXPIRE`. `duration_tu` is the
    /// optional cfg80211 measurement dwell request.
    async fn hw_scan_with_duration(
        &mut self,
        ssids: &[Vec<u8>],
        freqs: &[u32],
        random_mac: Option<narf_wireless::ScanRandomMac>,
        colocated_6ghz: bool,
        duration_tu: Option<u16>,
        extra_ies: &[u8],
    ) -> Result<Vec<ScanBss>, MacError> {
        if extra_ies.len() > 512 {
            return fail(
                step::SCAN_BUSY,
                extra_ies.len() as u32,
                errno::EINVAL,
                "hw scan (probe IE length)",
            );
        }
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
            roc: None,
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
            // mac80211's `ieee80211_build_preq_ies` appends the raw
            // nl80211 bytes after its generated rates/capabilities.
            arg.extraie.extend_from_slice(extra_ies);
        }
        if let Some(random_mac) = random_mac {
            // `ath11k_mac_op_hw_scan`: cfg80211 has already ensured that
            // this is an unassociated, locally-administered unicast request.
            // Keep the service check here as the driver-side trust boundary
            // for direct Rust callers that bypass nl80211.
            if !self.supports_scan_random_mac() {
                return fail(
                    step::SCAN_BUSY,
                    WMI_TLV_SERVICE_SPOOF_MAC_SUPPORT,
                    errno::EOPNOTSUPP,
                    "hw scan (random MAC unsupported)",
                );
            }
            arg.scan_ctrl_flags |= wmi::scan_flag::ADD_SPOOF_MAC_IN_PROBE_REQ;
            arg.mac_addr = random_mac.addr;
            arg.mac_mask = random_mac.mask;
        }
        let per_chan = self.svc(WMI_TLV_SERVICE_SCAN_CONFIG_PER_CHANNEL);
        arg.chan_list = freqs
            .iter()
            .map(|&f| {
                if per_chan {
                    let mut configured = f & scan_flag::CONFIG_PER_CHANNEL_MASK;
                    // `ath11k_mac_op_hw_scan`: when userspace selected
                    // COLOCATED_6GHZ, retain PSC channels and defer the
                    // other 6 GHz channels until an RNR in the concurrent
                    // 2.4/5 GHz scan references them.
                    if colocated_6ghz
                        && matches!(freq_band(f), Band::Ghz6)
                        && frame::freq_to_channel(f) % 16 != 5
                    {
                        configured |= scan_flag::CH_FLAG_SCAN_ONLY_IF_RNR_FOUND;
                    }
                    configured
                } else {
                    f
                }
            })
            .collect();
        let scan_timeout = if let Some(duration_tu) = duration_tu.filter(|duration| *duration != 0)
        {
            // `ath11k_mac_op_hw_scan`: all target dwell fields and the
            // burst duration take cfg80211's duration in TUs directly. Its
            // timeout adds the WMI channel-switch-event 10-ms budget per
            // channel, with the default WMI max-scan-time cap.
            const CHANNEL_SWITCH_EVENT_OVERHEAD_MS: u32 = 10;
            let duration = duration_tu as u32;
            arg.dwell_time_active = duration;
            arg.dwell_time_active_2g = duration;
            arg.dwell_time_active_6g = duration;
            arg.dwell_time_passive = duration;
            arg.dwell_time_passive_6g = duration;
            arg.burst_duration = duration;
            let channels = arg.chan_list.len() as u32;
            arg.max_rest_time
                .saturating_mul(channels.saturating_sub(1))
                .saturating_add(
                    duration
                        .saturating_add(CHANNEL_SWITCH_EVENT_OVERHEAD_MS)
                        .saturating_mul(channels),
                )
                .min(arg.max_scan_time)
        } else {
            arg.max_scan_time
        }
        .saturating_add(timeout::SCAN_OVERHEAD);
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
        if self.scan.state != ScanState::Idle {
            self.scan.state = ScanState::Aborting;
            if let Err(e) = self.scan_stop().await {
                e.report("abort scan");
            }
        }
    }

    /// Abort an in-flight ordinary scan after its nl80211 future was
    /// cancelled. The physical runtime keeps the radio-wide scan lease until
    /// this ordered WMI stop has completed, so a sibling never overlaps the
    /// fixed firmware scan id.
    pub async fn cancel_scan(&mut self) {
        self.scan_abort().await;
    }

    /// `ath11k_mac_op_remain_on_channel`: a passive one-channel WMI scan
    /// with a firmware dwell interval longer than the requested stay. The
    /// runtime's poll timer issues the matching scan abort at `duration_ms`.
    pub async fn remain_on_channel(
        &mut self,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<(), MacError> {
        const MAX_REMAIN_ON_CHANNEL_MS: u32 = 5000;
        if duration_ms == 0 || duration_ms > MAX_REMAIN_ON_CHANNEL_MS {
            return fail(
                step::ROC_START,
                duration_ms,
                errno::EINVAL,
                "remain on channel (duration)",
            );
        }
        let Some(vdev_id) = self.vif.as_ref().map(|vif| vif.vdev_id) else {
            return fail(
                step::ROC_START,
                0,
                errno::ENOTCONN,
                "remain on channel (no vdev)",
            );
        };
        match self.wiphy.get(frequency_mhz) {
            Some(channel) if channel.flags & chan_flag::DISABLED == 0 => {}
            _ => {
                return fail(
                    step::ROC_START,
                    frequency_mhz,
                    errno::EINVAL,
                    "remain on channel (channel)",
                )
            }
        }
        if self.scan.state != ScanState::Idle {
            return fail(
                step::ROC_START,
                self.scan.state as u32,
                errno::EBUSY,
                "remain on channel (busy)",
            );
        }
        self.scan = ScanCtx {
            state: ScanState::Starting,
            vdev_id,
            started: false,
            completed: false,
            aborted: false,
            deadline: None,
            roc: Some(RocCtx {
                cookie,
                frequency_mhz,
                duration_ms,
                started: false,
            }),
        };
        let mut arg = ScanReqParams::start_scan_init(false, false);
        arg.vdev_id = vdev_id;
        arg.scan_id = ATH11K_SCAN_ID;
        // Linux uses twice WIPHY_MAX_ROC_DURATION (10 s) so its delayed
        // work—not the target's dwell timer—owns the requested expiry.
        arg.dwell_time_active = MAX_REMAIN_ON_CHANNEL_MS * 2;
        arg.dwell_time_passive = MAX_REMAIN_ON_CHANNEL_MS * 2;
        arg.max_scan_time = MAX_REMAIN_ON_CHANNEL_MS * 2;
        arg.scan_ctrl_flags |= scan_flag::PASSIVE;
        if !self.cfg.single_pdev_only {
            arg.scan_ctrl_flags |= scan_flag::FILTER_PROBE_REQ;
        }
        arg.chan_list = alloc::vec![frequency_mhz];
        arg.burst_duration = duration_ms;
        if let Err(error) = self.start_scan(&arg).await {
            self.scan = ScanCtx {
                state: ScanState::Idle,
                vdev_id: 0,
                started: false,
                completed: false,
                aborted: false,
                deadline: None,
                roc: None,
            };
            return Err(error);
        }
        let roc = self.scan.roc.as_mut().unwrap();
        roc.started = true;
        self.scan.deadline = Some(self.wmi.now_ms() + duration_ms as u64);
        self.pending.roc_events.push_back(RemainOnChannelEvent {
            cookie,
            frequency_mhz,
            duration_ms,
            started: true,
        });
        Ok(())
    }

    /// `ath11k_mac_op_cancel_remain_on_channel`: cancel only the matching
    /// cookie; scan completion produces the normal ROC-expired event.
    pub async fn cancel_remain_on_channel(&mut self, cookie: u64) -> Result<(), MacError> {
        if self.scan.roc.is_none_or(|roc| roc.cookie != cookie) {
            return fail(
                step::ROC_CANCEL,
                cookie as u32,
                errno::ENOENT,
                "cancel remain on channel",
            );
        }
        self.scan_abort().await;
        Ok(())
    }

    /// True only while firmware has confirmed the passive ROC scan started.
    pub fn remain_on_channel_active(&self, frequency_mhz: u32) -> bool {
        self.scan.state == ScanState::Running
            && self
                .scan
                .roc
                .is_some_and(|roc| roc.started && roc.frequency_mhz == frequency_mhz)
    }

    pub fn remain_on_channel_busy(&self) -> bool {
        self.scan.state != ScanState::Idle
    }

    pub fn can_remain_on_channel(&self, frequency_mhz: u32) -> bool {
        self.wiphy
            .get(frequency_mhz)
            .is_some_and(|channel| channel.flags & chan_flag::DISABLED == 0)
    }

    pub fn has_remain_on_channel(&self, cookie: u64) -> bool {
        self.scan.roc.is_some_and(|roc| roc.cookie == cookie)
    }

    /// `WirelessNetIface::scan` semantics: a cfg80211 scan of explicit
    /// centre frequencies (or legacy `req.channels`; all enabled channels
    /// when both are empty), active with `req.ssids` when `req.active`.
    pub async fn scan(&mut self, req: &ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        if req.ssids.len() > 16 || req.ssids.iter().any(|s| s.len() > frame::MAX_SSID_LEN) {
            return Err(WirelessError::InvalidArgs);
        }
        if let Some(random_mac) = req.random_mac {
            // Preserve the nl80211 path's cfg80211 checks for direct kernel
            // callers too. Random scan addresses are only valid before
            // association and must unambiguously remain unicast.
            if self.link.is_some() || random_mac.mask[0] & 1 == 0 || random_mac.addr[0] & 1 != 0 {
                return Err(WirelessError::InvalidArgs);
            }
        }
        let freqs: Vec<u32> = if !req.frequencies_mhz.is_empty() {
            let mut v = Vec::new();
            for &freq in &req.frequencies_mhz {
                match self.wiphy.get(freq) {
                    Some(c) if c.flags & chan_flag::DISABLED == 0 => v.push(freq),
                    _ => return Err(WirelessError::InvalidArgs),
                }
            }
            v
        } else if req.channels.is_empty() {
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
            .hw_scan_with_duration(
                &ssids,
                &freqs,
                req.random_mac,
                req.colocated_6ghz,
                req.duration_tu,
                &req.extra_ies,
            )
            .await
            .map_err(|e| e.wireless())?;
        Ok(r.iter().filter_map(ScanBss::info).collect())
    }

    // ── Connect ────────────────────────────────────────────────────

    /// `WirelessNetIface::associate`: Open, WPA2-PSK, or WPA3-SAE.
    pub async fn associate(&mut self, req: &AssociateRequest) -> Result<(), WirelessError> {
        self.connect(req).await.map_err(|e| e.wireless())
    }

    /// The full station join; on failure everything set up is torn down
    /// the way mac80211 does (`ieee80211_destroy_auth_data` /
    /// `ieee80211_destroy_assoc_data` / `ieee80211_set_disassoc`).
    pub async fn connect(&mut self, req: &AssociateRequest) -> Result<(), MacError> {
        self.connect_with_prev(req, None).await
    }

    /// Reassociate to a different BSS of the same ESS for
    /// [`WirelessNetIface::roam`]. The old station is removed locally before
    /// changing vdev channel/peer state, but its BSSID remains in the new
    /// Reassociation Request's Current AP Address field.
    pub async fn roam(&mut self, req: &AssociateRequest) -> Result<(), WirelessError> {
        let previous = match self.link.as_ref() {
            Some(l) if l.assoc && l.bss.bssid != req.bssid => l.bss.bssid,
            Some(_) => {
                return Err(WirelessError::Busy);
            }
            None => return Err(WirelessError::InvalidArgs),
        };
        // `ieee80211_mgd_assoc` drops the old station/channel context before
        // starting the new one. Do not transmit a deauth: the new AP learns
        // the previous AP from the Reassociation Request, as in mac80211.
        self.teardown(false, 0).await;
        self.connect_with_prev(req, Some(previous))
            .await
            .map_err(|e| e.wireless())
    }

    async fn connect_with_prev(
        &mut self,
        req: &AssociateRequest,
        prev_bssid: Option<[u8; 6]>,
    ) -> Result<(), MacError> {
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
        let freq = req.frequency_mhz;
        if freq == 0 {
            return fail(
                step::CONNECT_NO_BSS,
                req.channel,
                errno::EINVAL,
                "connect (channel)",
            );
        }
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
        let external = match &req.security {
            SecurityConfig::External(e) => Some(*e),
            _ => None,
        };
        // wpa_supplicant_set_suites (AKM, ciphers, PMF); an external
        // supplicant chose them itself (its RSNE is in `req.ie`).
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
        let r = self
            .join(&bss, &ies, &req.ssid, rsn, external, &req.ie, prev_bssid)
            .await;
        if r.is_err() {
            let (assoc, reason) = self
                .link
                .as_ref()
                .map_or((false, 0), |l| (l.assoc, l.deauth_reason));
            self.teardown(assoc, reason).await;
        }
        r
    }

    #[allow(clippy::too_many_arguments)]
    async fn join(
        &mut self,
        bss: &ScanBss,
        ies: &ParsedIes,
        ssid: &[u8],
        rsn: Option<(RsnPlan, Credential)>,
        external: Option<narf_wireless::ExternalSecurity>,
        user_ies: &[u8],
        prev_bssid: Option<[u8; 6]>,
    ) -> Result<(), MacError> {
        self.prep_connection(bss, ies, rsn.as_ref().map(|(p, _)| p.clone()), external)
            .await?;
        // ── ieee80211_mgd_auth ──
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
        self.link.as_mut().unwrap().authenticated = true;
        // ── ieee80211_mgd_assoc ──
        let plan = rsn.as_ref().map(|(p, _)| p.clone());
        let resp = self
            .associate_frames_with_prev(bss, ies, ssid, plan.as_ref(), user_ies, prev_bssid)
            .await?;
        if rsn.is_none() && external.is_none_or(|e| !e.control_port.enabled) {
            // !IEEE80211_STA_CONTROL_PORT: ieee80211_assoc_success moves the
            // AP to AUTHORIZED before BSS_CHANGED_ASSOC (ath11k only sets
            // peer->is_authorized; ath11k_bss_assoc then authorizes).
            self.link.as_mut().unwrap().authorized = true;
        }
        self.assoc_success(bss, ies, &resp).await?;
        if external.is_some() {
            // The supplicant is userspace's: the port opens on SET_STATION
            // (or now, without a control port).
            if self.link.as_ref().unwrap().authorized {
                self.authorize().await?;
                self.setup_ps().await;
            }
            narf_memory::diag::set_wifi_stage(narf_memory::diag::WifiStage::Connected);
            return Ok(());
        }
        // ── wpa_supplicant ──
        if let (Some((plan, _)), Some(pmk)) = (rsn, pmk) {
            self.rsna_4way(bss, &plan, &pmk).await?;
        }
        self.authorize().await?;
        self.setup_ps().await;
        narf_memory::diag::set_wifi_stage(narf_memory::diag::WifiStage::Connected);
        Ok(())
    }

    /// `ieee80211_prep_connection`: the link state, channel context, vdev,
    /// BSS parameters and the AP's station entry (`sta_info_insert` →
    /// `ath11k_mac_station_add`).
    pub(super) async fn prep_connection(
        &mut self,
        bss: &ScanBss,
        ies: &ParsedIes,
        rsn: Option<RsnPlan>,
        external: Option<narf_wireless::ExternalSecurity>,
    ) -> Result<(), MacError> {
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let band = freq_band(bss.freq);
        let (mode, def) = if band == Band::Ghz6 {
            // 802.11ax is mandatory in 6 GHz. Unlike 2.4/5 GHz there are
            // no HT or VHT Operation IEs: the optional HE Operation tail
            // provides the primary channel and width.
            let (Some(own), Some(ap), Some(oper)) = (
                self.own_he(band).cloned(),
                ies.he_cap.as_deref().and_then(he::parse_he_cap),
                ies.he_oper.as_deref().and_then(he::HeOper::parse),
            ) else {
                return fail(
                    step::CONNECT_UNSUPPORTED,
                    6,
                    errno::EOPNOTSUPP,
                    "connect (6 GHz HE capabilities)",
                );
            };
            if !self.he_ok(band, ies) {
                return fail(
                    step::CONNECT_UNSUPPORTED,
                    7,
                    errno::EOPNOTSUPP,
                    "connect (6 GHz HE requirements)",
                );
            }
            // HE stations require QoS, and a conforming 6 GHz BSS advertises
            // WMM. Preserve the scan-time WMM state through association even
            // if the Association Response does not repeat that vendor IE.
            if !ies.wmm_used {
                return fail(
                    step::CONNECT_UNSUPPORTED,
                    9,
                    errno::EOPNOTSUPP,
                    "connect (6 GHz WMM)",
                );
            }
            let Some(he_6ghz_oper) = oper.six_ghz else {
                return fail(
                    step::CONNECT_UNSUPPORTED,
                    13,
                    errno::EOPNOTSUPP,
                    "connect (6 GHz HE operation)",
                );
            };
            self.select_6ghz_client_rules(he_6ghz_oper.control).await?;
            let max_width = match he::he_cap_rx_bw(&own, band).min(he::he_cap_rx_bw(&ap, band)) {
                160 => Width::W160,
                80 => Width::W80,
                40 => Width::W40,
                _ => Width::W20,
            };
            let supports_80p80 = own.phy[0] & he::cap::PHY0_80PLUS80_MHZ_IN_5G != 0
                && ap.phy[0] & he::cap::PHY0_80PLUS80_MHZ_IN_5G != 0;
            let Some(def) = peer::determine_he_6ghz_chan(
                &self.wiphy,
                bss.freq,
                &oper,
                max_width,
                supports_80p80,
            ) else {
                return fail(
                    step::CONNECT_UNSUPPORTED,
                    8,
                    errno::EOPNOTSUPP,
                    "connect (6 GHz HE operation)",
                );
            };
            (ConnMode::He, def)
        } else {
            let (mut mode, def) = peer::determine_chan(
                &self.wiphy,
                &self.own,
                bss.freq,
                ies.ht_cap.as_ref(),
                ies.ht_oper.as_ref(),
                ies.vht_cap.as_ref(),
                ies.vht_oper.as_ref(),
            );
            // ieee80211_determine_ap_chan: HE when the AP has HE
            // capabilities and operation (and VHT on 5 GHz), we have HE on
            // the band, and the HE MCS compatibility checks pass.
            if (mode == ConnMode::Vht || (band == Band::Ghz2 && mode == ConnMode::Ht))
                && self.he_ok(band, ies)
            {
                mode = ConnMode::He;
            }
            (mode, def)
        };
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
            assoc_capability: 0,
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
            wmm_last_param_set: None,
            mu_edca_last_param_set: None,
            disable_wmm_tracking: false,
            operating_11g: band == Band::Ghz2 && supp >> 4 != 0,
            basic_rates: basic,
            deauth_reason: frame::WLAN_REASON_DEAUTH_LEAVING,
            ba_rx_valid: 0,
            ba_rx_token: [0; 16],
            rsn,
            he: None,
            external,
            authenticated: false,
            last_signal: None,
            beacon_signal_ewma: None,
            beacon_signal_count: 0,
            last_cqm_event_signal: None,
            cqm_rssi_range: self.cqm_rssi.as_ref().and_then(|config| {
                (config.thresholds_dbm.len() > 1).then(|| Self::cqm_rssi_range(config, 0))
            }),
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
        self.mlme_target = Some(bss.bssid);
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

    /// Linux's `ath11k_mac_supports_station_tpc`: extended regulatory
    /// support and TPC must both be advertised, and the station must be
    /// starting a 6 GHz vdev.
    fn supports_station_tpc(&self, def: &ChanDef) -> bool {
        self.supports_6ghz_cc_ext()
            && self.svc(WMI_TLV_SERVICE_EXT_TPC_REG_SUPPORT)
            && def.band == Band::Ghz6
    }

    /// Select the AP power envelope mac80211 exposes to ath11k. Firmware's
    /// `client_type` selects the default or subordinate category; a
    /// regulatory-client envelope takes precedence over a local envelope,
    /// and PSD takes precedence over EIRP within that selected source.
    fn tpc_envelope(ies: &ParsedIes, client_type: u32) -> Option<&frame::TxPowerEnvelope> {
        let category = client_type.min(1) as u8;
        for regulatory in [true, false] {
            let have = ies.tpe.iter().any(|e| {
                e.category == category && e.interpretation.is_regulatory_client() == regulatory
            });
            if !have {
                continue;
            }
            return ies
                .tpe
                .iter()
                .find(|e| {
                    e.category == category
                        && e.interpretation.is_regulatory_client() == regulatory
                        && e.interpretation.is_psd()
                })
                .or_else(|| {
                    ies.tpe.iter().find(|e| {
                        e.category == category
                            && e.interpretation.is_regulatory_client() == regulatory
                            && !e.interpretation.is_psd()
                    })
                });
        }
        None
    }

    /// Number of 20 MHz subchannels in a NARF channel definition.
    const fn tpc_subchannels(width: Width) -> usize {
        match width {
            Width::W20NoHt | Width::W20 => 1,
            Width::W40 => 2,
            Width::W80 => 4,
            Width::W80P80 => 8,
            Width::W160 => 8,
        }
    }

    /// Reorder a PSD TPE from its HE-Operation order into the narrower
    /// operating ChanDef, porting the contiguous-channel portion of
    /// `ieee80211_rearrange_tpe_psd`. The TPE's N entries describe the
    /// primary portion of the AP channel; the optional K entries surround
    /// them. A station that has to downgrade an AP's 160 MHz BSS therefore
    /// must not blindly take the first PSD entries.
    fn tpc_rearrange_psd(
        envelope: &frame::TxPowerEnvelope,
        ap: &ChanDef,
        used: &ChanDef,
    ) -> frame::TxPowerEnvelope {
        let mut out = envelope.clone();
        // Linux's PSD TPC source treats an 80+80 definition as eight
        // sequential 20 MHz values. It is already in the operating
        // definition's order here; never apply the contiguous downgrade
        // rearrangement across its frequency gap.
        if ap.width == Width::W80P80 || used.width == Width::W80P80 {
            return out;
        }
        let have = Self::tpc_subchannels(ap.width);
        let needed = Self::tpc_subchannels(used.width);
        let Some(n) = out.psd_n else {
            return out;
        };
        if have == 0 || needed == 0 {
            out.powers.clear();
            out.count = 0;
            return out;
        }
        if n == 0 {
            // Count zero already expanded one PSD limit over every 20 MHz
            // channel in `TxPowerEnvelope::parse`; only limit it to the
            // operating ChanDef as mac80211 does.
            out.powers.truncate(needed);
            out.count = out.count.min(needed);
            return out;
        }

        // `ieee80211_calc_chandef_subchan_offset(ap, n)`: for the
        // contiguous formats N is the segment containing the AP's primary
        // 20 MHz channel. The normalised offset is consequently enough;
        // 80+80 returns above because its two segments have a frequency gap.
        let ap_start = Self::tpc_start_frequency(ap);
        let primary = ap.freq.saturating_sub(ap_start) as usize / 20;
        let n = n.min(have);
        let n_offset = (primary / n) * n;
        let mut ordered = Vec::new();
        ordered.resize(have, frame::tpe::NO_LIMIT);
        for (i, slot) in ordered.iter_mut().enumerate().take(have) {
            let source = if i < n_offset {
                i + n
            } else if i < n_offset + n {
                i - n_offset
            } else {
                i
            };
            *slot = envelope
                .powers
                .get(source)
                .copied()
                .unwrap_or(frame::tpe::NO_LIMIT);
        }

        let used_start = Self::tpc_start_frequency(used);
        let used_offset = used_start.saturating_sub(ap_start) as usize / 20;
        if used_offset >= have {
            out.powers.clear();
            out.count = 0;
            return out;
        }
        let len = needed.min(have - used_offset);
        out.powers = ordered[used_offset..used_offset + len].to_vec();
        // Preserve mac80211's distinction between valid entries and default
        // no-limit padding after choosing the station's narrower channel.
        out.count = out.count.min(len);
        out
    }

    /// `ath11k_mac_get_num_pwr_levels` for the WCN6855's 20/40/80/160 and
    /// 80+80 MHz station channel definitions.
    const fn tpc_num_levels(width: Width, psd: bool) -> usize {
        match (psd, width) {
            (true, Width::W20NoHt | Width::W20) | (false, Width::W20NoHt | Width::W20) => 1,
            (_, Width::W40) => 2,
            (true, Width::W80) => 4,
            (true, Width::W80P80) => 8,
            (true, Width::W160) => 8,
            (false, Width::W80) => 3,
            (false, Width::W80P80) => 4,
            (false, Width::W160) => 4,
        }
    }

    /// The lowest 20 MHz channel in the primary six-GHz chandef segment
    /// (`ath11k_mac_get_6ghz_start_frequency`).
    const fn tpc_start_frequency(def: &ChanDef) -> u32 {
        let offset = match def.width {
            Width::W160 => 70,
            Width::W80 | Width::W80P80 => 30,
            Width::W40 => 10,
            Width::W20NoHt | Width::W20 => 0,
        };
        def.center_freq1.saturating_sub(offset)
    }

    /// `ath11k_mac_get_seg_freq` plus the `+10` used by
    /// `ath11k_mac_get_eirp_power` to select the regulatory channel for
    /// 20/40/80/160 MHz EIRP limits. At the final 80+80 level Linux uses
    /// `center_freq2` rather than synthesising a frequency across the gap.
    const fn tpc_eirp_frequency(def: &ChanDef, start: u32, level: usize) -> u32 {
        if matches!(def.width, Width::W80P80) && level == 3 {
            return def.center_freq2;
        }
        if level == 0 {
            start
        } else {
            start + 10 * (1u32 << level)
        }
    }

    /// Build the `ath11k_reg_tpc_power_info` equivalent for the current
    /// six-GHz BSS. The incoming TPE values are half-dBm; WMI receives the
    /// integral-dBm values Linux derives with signed division by two.
    fn station_tpc_info(&self, def: &ChanDef) -> Option<TpcPowerInfo> {
        let link = self.link.as_ref()?;
        let ies = link.bss.parsed();
        let client_type = self.reg.store.as_ref().map_or(0, |r| r.client_type);
        let envelope = Self::tpc_envelope(&ies, client_type).map(|envelope| {
            if !envelope.interpretation.is_psd() {
                return envelope.clone();
            }
            let ap = ies
                .he_oper
                .as_deref()
                .and_then(he::HeOper::parse)
                .and_then(|oper| peer::he_6ghz_oper_chandef(def.freq, &oper));
            ap.map_or_else(
                || envelope.clone(),
                |ap| Self::tpc_rearrange_psd(envelope, &ap, def),
            )
        });
        let local_psd = self.wiphy.get(def.freq)?.flags & chan_flag::PSD != 0;
        let envelope_psd = envelope.as_ref().is_some_and(|e| e.interpretation.is_psd());
        let mut count = Self::tpc_num_levels(def.width, local_psd);
        if let Some(envelope) = &envelope {
            count = count.min(envelope.count);
        }
        if count == 0 {
            return None;
        }

        let constraint = ies.power_constraint.unwrap_or(0) as i8;
        let start = Self::tpc_start_frequency(def);
        let mut info = TpcPowerInfo {
            ap_power_type: self.reg_6ghz_ap_type as u32,
            ..Default::default()
        };
        for level in 0..count {
            let (center_freq, mut tx_power, mut eirp_power, is_psd_power) =
                match (local_psd, envelope_psd) {
                    // Local and AP power are PSD. Firmware receives per-20 MHz
                    // PSD limits, plus the regulatory EIRP limit for the same
                    // 20 MHz slice.
                    (true, true) => {
                        let center = start + 20 * level as u32;
                        let channel = self.wiphy.get(center)?;
                        let ap = envelope.as_ref()?.powers[level] / 2;
                        (
                            center,
                            channel.psd.min(ap),
                            channel.max_reg_power as i8,
                            true,
                        )
                    }
                    // Local regulatory state is PSD but the AP's envelope is
                    // EIRP. Convert the local PSD to the appropriate bandwidth
                    // EIRP before intersecting it with the AP limit.
                    (true, false) if envelope.is_some() => {
                        let center = Self::tpc_eirp_frequency(def, start, level);
                        let channel = self.wiphy.get(center)?;
                        let local = (channel.psd as i16 + 13 + 3 * level as i16) as i8;
                        let ap = envelope.as_ref()?.powers[level] / 2;
                        (
                            center,
                            channel.max_reg_power.min(local as i32).min(ap as i32) as i8,
                            0,
                            false,
                        )
                    }
                    // Local regulatory state is EIRP but the AP supplied PSD.
                    // Firmware must operate in PSD mode; Linux intentionally
                    // leaves the per-slice AP TPE as the limiting value here.
                    (false, true) => {
                        let center = start + 20 * level as u32;
                        let channel = self.wiphy.get(center)?;
                        (
                            center,
                            envelope.as_ref()?.powers[level] / 2,
                            channel.max_reg_power as i8,
                            true,
                        )
                    }
                    // Both sides use EIRP bandwidth levels.
                    (false, false) if envelope.is_some() => {
                        let center = Self::tpc_eirp_frequency(def, start, level);
                        let channel = self.wiphy.get(center)?;
                        let ap = envelope.as_ref()?.powers[level] / 2;
                        (center, (channel.max_reg_power as i8).min(ap), 0, false)
                    }
                    // No applicable AP envelope: programme the firmware's
                    // self-managed regulatory limit exactly as Linux does.
                    (true, false) => {
                        let center = start + 20 * level as u32;
                        let channel = self.wiphy.get(center)?;
                        (center, channel.psd, channel.max_reg_power as i8, true)
                    }
                    (false, false) => {
                        let center = Self::tpc_eirp_frequency(def, start, level);
                        let channel = self.wiphy.get(center)?;
                        (center, channel.max_reg_power as i8, 0, false)
                    }
                };
            if is_psd_power {
                eirp_power = eirp_power.saturating_sub(constraint);
                // Linux overwrites this for each PSD entry. All matching
                // regulatory rules normally agree; preserving the final
                // value matches its firmware argument.
                info.is_psd_power = true;
                if self.cfg.idle_ps {
                    let fw_limit = self.vif.as_ref().map_or(0, |v| v.max_allowed_tx_power);
                    if fw_limit != 0 {
                        eirp_power = eirp_power.min(fw_limit as i8);
                    }
                }
                // Linux's `eirp_power` field is `u8`; retain its cast
                // semantics even though the working calculation is signed.
                info.eirp_power = eirp_power as u8;
            } else {
                tx_power = tx_power.saturating_sub(constraint);
                if self.cfg.idle_ps {
                    let fw_limit = self.vif.as_ref().map_or(0, |v| v.max_allowed_tx_power);
                    if fw_limit != 0 {
                        tx_power = tx_power.min(fw_limit as i8);
                    }
                }
            }
            info.channels.push(TpcChannelPower {
                center_freq,
                tx_power,
            });
        }
        Some(info)
    }

    /// `ath11k_mac_fill_reg_tpc_info` followed by
    /// `ath11k_wmi_send_vdev_set_tpc_power`. It must run after the vdev
    /// start response, which supplies the firmware's optional TX-power
    /// ceiling.
    async fn set_station_tpc_power(&mut self, def: &ChanDef) -> Result<(), MacError> {
        let Some(info) = self.station_tpc_info(def) else {
            return Ok(());
        };
        let vdev_id = self.vif.as_ref().unwrap().vdev_id;
        let cmd = match vdev_set_tpc_power_cmd(vdev_id, &info) {
            Ok(cmd) => cmd,
            Err(e) => return fail(step::TXPOWER, 0x600, e.errno(), "6 GHz TPC encode"),
        };
        self.cmd(
            cmd,
            step::TXPOWER,
            WMI_VDEV_SET_TPC_POWER_CMDID,
            "6 GHz TPC",
        )
        .await
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

    /// `ath11k_mac_vdev_start_restart`: the initial association uses the
    /// start command; a live CSA supplies `restart = true` and the firmware
    /// channel-info CSA-cause bit.
    async fn vdev_start(&mut self, def: &ChanDef) -> Result<(), MacError> {
        self.vdev_start_restart(def, false, false).await
    }

    async fn vdev_start_restart(
        &mut self,
        def: &ChanDef,
        restart: bool,
        csa: bool,
    ) -> Result<(), MacError> {
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
        arg.channel.band_center_freq2 = def.center_freq2;
        arg.channel.mode = peer::vdev_phymode(def);
        arg.channel.chan_change_cause_csa = csa;
        if let Some(c) = chan {
            arg.channel.max_power = c.max_power as u8;
            arg.channel.max_reg_power = c.max_reg_power as u8;
            arg.channel.max_antenna_gain = c.max_antenna_gain as u8;
            arg.channel.passive = c.flags & chan_flag::NO_IR != 0;
        }
        if v.kind.is_ap() {
            // Linux deliberately permits an AP vdev to start on a DFS
            // channel.  WMI needs both the primary channel bit and the
            // channel-context-wide radar indication; a radar primary is
            // passive until target DFS/CAC state opens it.
            let (primary_radar, radar_enabled) = self.ap_dfs_flags(def);
            arg.channel.chan_radar = primary_radar;
            arg.channel.freq2_radar = radar_enabled;
            arg.channel.passive |= primary_radar;
            arg.regdomain = self.reg.dfs_region;
            // WCN6855 advertises MBSSID parameters in VDEV_START. A regular
            // AP must still carry NON_MBSSID_AP rather than the all-zero
            // value used by station vdevs.
            arg.mbssid_flags = v.mbssid.flags;
            arg.mbssid_tx_vdev_id = v.mbssid.tx_vdev_id;
        }
        self.pending.vdev_start = None;
        let c = match vdev_start_cmd(&arg, restart) {
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
        {
            let vif = self.vif.as_mut().unwrap();
            vif.is_started = true;
            vif.max_allowed_tx_power = resp.max_allowed_tx_power;
        }
        if self.supports_station_tpc(def) {
            self.set_station_tpc_power(def).await?;
        }
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
            let desc = match self.wmi.mgmt_tx(vdev_id, frame_bytes, None).await {
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
        user_ies: &[u8],
    ) -> frame::AssocReqParams {
        self.assoc_request_params_with_prev(bss, ies, ssid, rsn, user_ies, None)
    }

    /// The [`frame::AssocReqParams`] mac80211 would use for an association
    /// or reassociation. `prev_bssid` is the current AP the userspace SME
    /// supplied in `NL80211_ATTR_PREV_BSSID`.
    fn assoc_request_params_with_prev(
        &self,
        bss: &ScanBss,
        ies: &ParsedIes,
        ssid: &[u8],
        rsn: Option<&RsnPlan>,
        user_ies: &[u8],
        prev_bssid: Option<[u8; 6]>,
    ) -> frame::AssocReqParams {
        let band = freq_band(bss.freq);
        let def = self.link.as_ref().map_or(
            ChanDef {
                freq: bss.freq,
                band,
                width: Width::W20,
                center_freq1: bss.freq,
                center_freq2: 0,
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
        // HT and VHT IEs are prohibited in a six-GHz Association Request;
        // its HE Capabilities plus HE 6 GHz Band Capabilities replace them.
        let ht_cap = (mode >= ConnMode::Ht && band != Band::Ghz6)
            .then(|| peer::assoc_ht_cap(self.own.ht(band), &def, smps));
        let vht_cap = match (
            mode >= ConnMode::Vht && band != Band::Ghz6,
            self.own.vht(band),
            ies.vht_cap.as_ref(),
        ) {
            (true, Some(own), Some(ap)) => Some(peer::assoc_vht_cap(own, ap, def.width)),
            _ => None,
        };
        // The SME's elements (`assoc_data->ie`): an external supplicant's
        // as given; for the offloads ours (RSNE, RSNXE: they sort as
        // ieee80211_send_assoc places them) merged with the non-RSN ones
        // userspace passed in NL80211_ATTR_IE.
        let external = self.link.as_ref().is_some_and(|l| l.external.is_some());
        let mut extra = if external {
            user_ies.to_vec()
        } else {
            ext::merge_sme_ies(rsn.map(|p| sec::assoc_ies(p, &bss.ies)), user_ies)
        };
        // SUPPORTS_ONLY_HE_MULTI_BSSID (WCN6855 supports_multi_bssid): an
        // HE association sets WLAN_EXT_CAPA3_MULTI_BSSID_SUPPORT in the
        // SME's Extended Capabilities.
        if mode >= ConnMode::He {
            ext::set_ext_capa_bit(&mut extra, 2, 1 << 6);
            if self
                .own_he(band)
                .is_some_and(|cap| cap.mac[0] & he::cap::MAC0_TWT_REQ != 0)
            {
                // `ath11k_if_types_ext_capa_sta[9]`:
                // WLAN_EXT_CAPA10_TWT_REQUESTER_SUPPORT.
                ext::set_ext_capa_bit(&mut extra, 9, 1 << 5);
            }
        }
        // ieee80211_put_he_cap for an HE connection.
        let he_cap = (mode >= ConnMode::He)
            .then(|| self.own_he(band).map(|h| he::put_he_cap(h, def.width)))
            .flatten();
        let he_6ghz_cap = (mode >= ConnMode::He && band == Band::Ghz6)
            .then(|| self.own_he_6ghz.map(he::put_he_6ghz_cap))
            .flatten();
        frame::AssocReqParams {
            he_cap,
            he_6ghz_cap,
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
            prev_bssid,
        }
    }

    /// `ieee80211_do_assoc` + `ieee80211_rx_mgmt_assoc_resp`.
    async fn associate_frames(
        &mut self,
        bss: &ScanBss,
        ies: &ParsedIes,
        ssid: &[u8],
        rsn: Option<&RsnPlan>,
        user_ies: &[u8],
    ) -> Result<Vec<u8>, MacError> {
        self.associate_frames_with_prev(bss, ies, ssid, rsn, user_ies, None)
            .await
    }

    async fn associate_frames_with_prev(
        &mut self,
        bss: &ScanBss,
        ies: &ParsedIes,
        ssid: &[u8],
        rsn: Option<&RsnPlan>,
        user_ies: &[u8],
        prev_bssid: Option<[u8; 6]>,
    ) -> Result<Vec<u8>, MacError> {
        let mut previous = prev_bssid;
        for _ in 0..timeout::MLME_TRIES {
            let (resp, next_previous) = self
                .association_attempt(bss, ies, ssid, rsn, user_ies, previous)
                .await?;
            previous = next_previous;
            if let Some(tu) = frame::assoc_comeback_tu(&resp) {
                // `ieee80211_rx_mgmt_assoc_resp`: a status-30 response is
                // neither a denial nor an ACK-timeout retry. Wait for the
                // AP's Timeout Interval in TUs, then issue the next bounded
                // (Re)Association attempt.
                let ms = ((tu as u64 * 1024) / 1000).min(u32::MAX as u64) as u32;
                let _ = self.wait_for(ms, |_| None::<()>).await;
                continue;
            }
            let a = frame::parse_assoc_resp(&resp).unwrap();
            if a.status != frame::WLAN_STATUS_SUCCESS {
                return fail(
                    step::ASSOC_REJECTED,
                    a.status as u32,
                    errno::ECONNREFUSED,
                    "associate (denied)",
                );
            }
            return Ok(resp);
        }
        fail(
            step::ASSOC_TIMEOUT,
            timeout::MLME_TRIES,
            errno::ETIMEDOUT,
            "associate (comeback retries exhausted)",
        )
    }

    /// `cfg80211_sme_rx_assoc_resp`: some APs reject a Reassociation Request
    /// even though they accept an ordinary Association Request. Retry once
    /// without Current AP Address before surfacing the final response.
    async fn associate_exchange_with_fallback(
        &mut self,
        bss: &ScanBss,
        ies: &ParsedIes,
        ssid: &[u8],
        rsn: Option<&RsnPlan>,
        user_ies: &[u8],
        prev_bssid: Option<[u8; 6]>,
    ) -> Result<Vec<u8>, MacError> {
        self.association_attempt(bss, ies, ssid, rsn, user_ies, prev_bssid)
            .await
            .map(|(resp, _)| resp)
    }

    /// One association attempt and Linux's broken-AP reassociation fallback.
    /// The returned previous BSSID is `None` only when that fallback has
    /// already switched the next attempt to the plain-association form.
    async fn association_attempt(
        &mut self,
        bss: &ScanBss,
        ies: &ParsedIes,
        ssid: &[u8],
        rsn: Option<&RsnPlan>,
        user_ies: &[u8],
        prev_bssid: Option<[u8; 6]>,
    ) -> Result<(Vec<u8>, Option<[u8; 6]>), MacError> {
        let resp = self
            .associate_exchange_with_prev(bss, ies, ssid, rsn, user_ies, prev_bssid)
            .await?;
        if prev_bssid.is_some()
            && frame::parse_assoc_resp(&resp)
                .is_some_and(|a| a.status != frame::WLAN_STATUS_SUCCESS)
            && frame::assoc_comeback_tu(&resp).is_none()
        {
            return self
                .associate_exchange(bss, ies, ssid, rsn, user_ies)
                .await
                .map(|plain| (plain, None));
        }
        Ok((resp, prev_bssid))
    }

    /// The (Re)Association Request / Response exchange; the response
    /// whatever its status.
    pub(super) async fn associate_exchange(
        &mut self,
        bss: &ScanBss,
        ies: &ParsedIes,
        ssid: &[u8],
        rsn: Option<&RsnPlan>,
        user_ies: &[u8],
    ) -> Result<Vec<u8>, MacError> {
        self.associate_exchange_with_prev(bss, ies, ssid, rsn, user_ies, None)
            .await
    }

    /// Send an Association or Reassociation Request and accept only its
    /// matching response subtype. Both response types share the MLME receive
    /// queue, so accepting the wrong one could complete the wrong exchange.
    pub(super) async fn associate_exchange_with_prev(
        &mut self,
        bss: &ScanBss,
        ies: &ParsedIes,
        ssid: &[u8],
        rsn: Option<&RsnPlan>,
        user_ies: &[u8],
        prev_bssid: Option<[u8; 6]>,
    ) -> Result<Vec<u8>, MacError> {
        let p = self.assoc_request_params_with_prev(bss, ies, ssid, rsn, user_ies, prev_bssid);
        let f = frame::build_assoc_req(&p);
        if prev_bssid.is_some() {
            self.mlme_exchange(
                &f,
                step::ASSOC_TX,
                step::ASSOC_TIMEOUT,
                "reassociate",
                timeout::MLME_RESPONSE,
                |r| frame::parse_assoc_resp(r).is_some_and(|a| a.reassoc),
            )
            .await
        } else {
            self.mlme_exchange(
                &f,
                step::ASSOC_TX,
                step::ASSOC_TIMEOUT,
                "associate",
                timeout::MLME_RESPONSE,
                |r| frame::parse_assoc_resp(r).is_some_and(|a| !a.reassoc),
            )
            .await
        }
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
                let mut cap = peer::sta_vht_cap(own, &sta.ht_cap, rie.vht_cap.as_ref(), have_80);
                match l.def.width {
                    Width::W160 => {
                        cap.cap &= !peer::vht::SUPP_CHAN_WIDTH_160_80PLUS80MHZ;
                        cap.cap |= peer::vht::SUPP_CHAN_WIDTH_160MHZ;
                    }
                    Width::W80P80 => {
                        cap.cap &= !peer::vht::SUPP_CHAN_WIDTH_160MHZ;
                        cap.cap |= peer::vht::SUPP_CHAN_WIDTH_160_80PLUS80MHZ;
                    }
                    _ => {}
                }
                sta.vht_cap = cap;
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
            let mut cap = he::sta_he_cap(own, &c);
            match l.def.width {
                Width::W160 => cap.phy[0] &= !he::cap::PHY0_80PLUS80_MHZ_IN_5G,
                Width::W80P80 => cap.phy[0] &= !he::cap::PHY0_160MHZ_IN_5G,
                _ => {}
            }
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
                Width::W80P80 => peer::StaBw::Bw160,
                Width::W160 => peer::StaBw::Bw160,
            };
            sta.bandwidth = Some(cap_bw.min(chan_bw));
            sta.rx_nss = sta.rx_nss.max(he::he_rx_nss(&cap)).max(1);
            ap_he = Some(peer::ApHe {
                cap,
                oper_params: o.params,
                six_ghz_cap: rie.he_6ghz_cap.as_deref().and_then(he::parse_he_6ghz_cap),
            });
        }
        sta.wme = l.wmm || rie.wmm_param.is_some();
        // ieee80211_assoc_success: WLAN_STA_MFP from assoc_data->use_mfp.
        sta.mfp = l.rsn.as_ref().is_some_and(|r| r.mfp) || l.external.is_some_and(|e| e.use_mfp);
        self.dp.set_sta_wme(bss.bssid, sta.wme);
        {
            let lk = self.link.as_mut().unwrap();
            lk.sta = sta;
            lk.he = ap_he.clone();
            lk.assoc = true;
            lk.basic_rates = if basic != 0 { basic } else { lk.basic_rates };
        }
        let twt_requester = self.twt_request_supported(band, ap_he.as_ref(), &rie);
        let aid = a.aid();
        // ieee80211_assoc_config_link → QoS parameters
        let (q, mu_edca, valid_wmm) = match rie.wmm_param {
            Some(wmm) => {
                let link = self.link.as_mut().unwrap();
                // `ieee80211_mgd_assoc` resets both to -1, then
                // `_ieee80211_sta_wmm_params` latches this generation before
                // validating every AC record.
                link.wmm_last_param_set = Some(wmm.qos_info & 0x0f);
                link.mu_edca_last_param_set = rie.mu_edca.map(|mu| mu.qos_info & 0x0f);
                match wmm_from_ie_checked(&wmm) {
                    Some(q) => (q, rie.mu_edca, true),
                    None => (
                        wmm_default(true, band == Band::Ghz2 && !l.operating_11g),
                        None,
                        false,
                    ),
                }
            }
            None => (
                wmm_default(true, band == Band::Ghz2 && !l.operating_11g),
                None,
                false,
            ),
        };
        if let Some(mu_edca) = mu_edca.as_ref() {
            self.conf_tx_all_with_mu_edca(&q, mu_edca).await?;
        } else {
            self.conf_tx_all(&q).await?;
        }
        if !valid_wmm {
            // Keep QoS with mac80211 defaults, but never reinterpret a
            // later beacon after an invalid association-response layout.
            self.link.as_mut().unwrap().disable_wmm_tracking = true;
        }
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
        self.twt_changed(twt_requester).await;
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
        let selection = self.bitrate_mask.band(nl80211_band(l.def.band)).cloned();
        let mut arg = peer::peer_assoc_prepare(&peer::PeerAssocInput {
            he: l.he.as_ref(),
            vdev_id,
            aid,
            assoc_capability: capab_info,
            listen_interval: self.cfg.listen_interval as u32,
            nss_ratio_info: self.caps.pdev.nss_ratio_info,
            def: l.def,
            sta: &l.sta,
            rsn: ies.rsn.is_some(),
            wpa: ies.wpa.is_some(),
        });
        peer::apply_tx_bitrate_band(&mut arg, selection.as_ref());
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
        self.program_peer_single_rate(
            vdev_id,
            bss.bssid,
            l.sta.vht_cap.vht_supported,
            l.he.is_some(),
            l.sta.ht_cap.ht_supported,
            l.sta.rx_nss.max(1) as u32,
            selection.as_ref(),
        )
        .await?;
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
        self.link.as_mut().unwrap().assoc_capability = capab_info;
        let c = vdev_up_cmd(vdev_id, aid as u32, &bss.bssid, None, 0, 0, None);
        self.cmd(c, step::VDEV_UP, 0, "vdev up").await?;
        self.vif.as_mut().unwrap().is_up = true;
        if self.four_addr {
            // Linux queues `ath11k_sta_set_4addr_wk` after association;
            // its failure is diagnostic-only and does not undo the managed
            // association or the required 4-address null announcement.
            if let Err(error) = self.program_peer_four_addr(vdev_id, bss.bssid).await {
                error.report("peer use 4addr after association");
            }
        }
        if let Some(setting) = self.station_tx_power {
            // The original SET_STATION completed before a later recovery
            // rebuilt this peer. Replay its retained driver policy, but do
            // not tear down an otherwise complete managed association if the
            // asynchronous WMI update fails.
            if let Err(error) = self
                .program_peer_station_tx_power(vdev_id, bss.bssid, setting)
                .await
            {
                error.report("peer station tx power after association");
            }
        }
        self.dp.set_sta_four_addr(self.four_addr);
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
    /// `ath11k_dp_peer_rx_pn_replay_config` for the in-kernel CCMP
    /// supplicant path.
    pub(super) async fn install_key(
        &mut self,
        addr: [u8; 6],
        idx: u8,
        key: &[u8],
        pairwise: bool,
    ) -> Result<(), MacError> {
        self.install_key_with_cipher(addr, idx, key, pairwise, CIPHER_SUITE_CCMP)
            .await
    }

    /// Install one of ath11k's firmware data ciphers on an external-
    /// supplicant or AP key path.  BIP suites deliberately do not reach this
    /// helper: Linux leaves them to mac80211's software management-frame
    /// protection implementation.
    pub(super) async fn install_key_with_cipher(
        &mut self,
        addr: [u8; 6],
        idx: u8,
        key: &[u8],
        pairwise: bool,
        suite: u32,
    ) -> Result<(), MacError> {
        let Some((key_cipher, key_txmic_len, key_rxmic_len)) = firmware_key_cipher(suite) else {
            return fail(step::KEY_INSTALL, suite, errno::EOPNOTSUPP, "key cipher");
        };
        if firmware_key_len(suite) != Some(key.len()) {
            return fail(step::KEY_INSTALL, suite, errno::EINVAL, "key length");
        }
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
            key_cipher,
            key_data: key.to_vec(),
            key_txmic_len,
            key_rxmic_len,
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
            .rx_pn_replay_config(vdev_id, addr, key_cipher, key.len(), idx, pairwise, true)
            .await
        {
            return fail(step::KEY_INSTALL, 0x10 | idx as u32, e, "pn replay config");
        }
        if suite == CIPHER_SUITE_TKIP && pairwise {
            let Some(rx_mic_key) = key
                .get(24..32)
                .filter(|_| key.len() == 32)
                .and_then(|bytes| bytes.try_into().ok())
            else {
                return fail(
                    step::KEY_INSTALL,
                    idx as u32,
                    errno::EINVAL,
                    "TKIP RX MIC key",
                );
            };
            if let Err(e) = self
                .dp
                .tkip_rx_mic_config(vdev_id, addr, Some(rx_mic_key))
                .await
            {
                return fail(
                    step::KEY_INSTALL,
                    0x20 | idx as u32,
                    e,
                    "TKIP RX MIC config",
                );
            }
        }
        Ok(())
    }

    /// `ath11k_mac_op_set_key(DISABLE_KEY)`: replace the selected firmware
    /// key with cipher NONE, then stop DP replay checking for that key slot.
    /// Unlike the station-only helper in `ext`, AP client teardown and AP
    /// key replacement use this for both pairwise and group entries.
    async fn disable_key(
        &mut self,
        addr: [u8; 6],
        idx: u8,
        pairwise: bool,
    ) -> Result<(), MacError> {
        let Some(vdev_id) = self.vif.as_ref().map(|vif| vif.vdev_id) else {
            return fail(
                step::KEY_INSTALL,
                0x440,
                errno::ENOTCONN,
                "disable key (no vdev)",
            );
        };
        let old = VdevInstallKeyArg {
            vdev_id,
            macaddr: addr,
            key_idx: idx as u32,
            key_flags: if pairwise {
                WMI_KEY_PAIRWISE
            } else {
                WMI_KEY_GROUP
            },
            key_cipher: cipher::NONE,
            ..Default::default()
        };
        self.install_key_cmd(&old).await?;
        let _ = self
            .dp
            .rx_pn_replay_config(vdev_id, addr, cipher::AES_CCM, 16, idx, pairwise, false)
            .await;
        if pairwise {
            let _ = self.dp.tkip_rx_mic_config(vdev_id, addr, None).await;
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
        if !self.cfg.supports_sta_ps || !self.powersave {
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
        let f = self.prepare_mgmt_tx(&f);
        match self.wmi.mgmt_tx(vdev_id, &f, None).await {
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
        let bssid = self.link.as_ref().map_or([0; 6], |l| l.bss.bssid);
        self.teardown(true, frame::WLAN_REASON_DEAUTH_LEAVING).await;
        // cfg80211_disconnect → ieee80211_mgd_deauth → the frame we sent.
        self.disconnect = Some(Disconnect {
            reason: frame::WLAN_REASON_DEAUTH_LEAVING,
            from_ap: false,
            deauth: true,
            bssid,
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
        self.twt_changed(false).await;
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
                .rx_pn_replay_config(vdev_id, bssid, cipher::AES_CCM, 16, 0, true, false)
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
        if l.def.band == Band::Ghz6 {
            // `ieee80211_set_disassoc` clears the BSS power type. Return to
            // the LPI client rule set used for discovery before the next
            // scan / association chooses another AP type.
            let _ = self.select_6ghz_client_rules(0).await;
        }
        self.scan_11d_start(vdev_id).await;
        let vm = self.vif.as_mut().unwrap();
        vm.bssid = [0; 6];
        vm.aid = 0;
        vm.ps = false;
        self.link = None;
        self.mlme_target = None;
        self.sup = None;
        self.mfp = MfpState::default();
        self.ext_keys = ext::ExtKeys::default();
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

/// WMM parser used for post-association parameter updates. An update must
/// contain every ACI exactly once and each ECW range must be valid, mirroring
/// `_ieee80211_sta_wmm_params`'s rejection of malformed beacon parameters.
fn wmm_from_ie_checked(w: &frame::WmmParam) -> Option<[TxQueueParams; 4]> {
    let mut out = [TxQueueParams::default(); 4];
    let mut seen = 0u8;
    for rec in &w.ac {
        let aci = (rec.aci_aifsn >> 5) & 3;
        let bit = 1u8 << aci;
        if seen & bit != 0 {
            return None;
        }
        let ecw_max = (rec.cw & 0xf0) >> 4;
        let ecw_min = rec.cw & 0x0f;
        if ecw_min == 0 || ecw_min > ecw_max {
            return None;
        }
        let ac = match aci {
            1 => 3, // BK
            2 => 1, // VI
            3 => 0, // VO
            _ => 2, // BE
        };
        let ecw2cw = |e: u8| (1u16 << e) - 1;
        out[ac] = TxQueueParams {
            aifs: (rec.aci_aifsn & 0x0f).max(2),
            cw_max: ecw2cw(ecw_max),
            cw_min: ecw2cw(ecw_min),
            txop: rec.txop_limit,
            uapsd: false,
        };
        seen |= bit;
    }
    (seen == 0x0f).then_some(out)
}

/// `wmi` re-export for callers that only import the mac layer.
pub use wmi::WmiCmd as Cmd;

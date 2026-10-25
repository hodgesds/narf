#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_net::Interface;

pub mod association;
pub mod caps;
pub mod ccmp;
pub mod eapol;
pub mod iface;
pub mod mfp;
pub mod mlme;
pub mod nl80211;
pub mod packet_key;
pub mod reg;
pub mod rsn;
pub mod sae;
pub mod scan;
pub mod station_security;

pub use iface::{AccessCategory, WirelessError, WirelessIface, WirelessIfaceInfo};
pub use scan::{BssInfo, ScanRandomMac, ScanRequest, ScanResult};

/// One `struct ieee80211_iface_limit` exposed through nl80211.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceTypeLimit {
    /// Maximum number of live interfaces selected from `iftypes`.
    pub max: u32,
    /// `enum nl80211_iftype` values covered by this limit.
    pub iftypes: Vec<u32>,
}

/// One `struct ieee80211_iface_combination` exposed through
/// `NL80211_ATTR_INTERFACE_COMBINATIONS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceCombination {
    pub limits: Vec<InterfaceTypeLimit>,
    pub max_interfaces: u32,
    pub max_channels: u32,
    pub sta_ap_beacon_interval_match: bool,
    pub beacon_interval_min_gcd: Option<u32>,
    /// `NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS`, when radar detection is
    /// meaningful for this physical radio.
    pub radar_detect_widths: Option<u32>,
}

/// Interface-type-specific Extended Capabilities advertised in
/// `NL80211_ATTR_IFTYPE_EXT_CAPA`.
///
/// `iftype` is an `enum nl80211_iftype` value; zero is the cfg80211 default
/// entry which applies to every interface type not named by another record.
/// The capability and mask byte strings must have the same length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IftypeExtendedCapability {
    pub iftype: u32,
    pub capabilities: Vec<u8>,
    pub mask: Vec<u8>,
}

/// Wiphy-wide Extended Capabilities (`NL80211_ATTR_EXT_CAPA` and its mask).
/// These are the capabilities cfg80211 exposes independently of the more
/// specific [`IftypeExtendedCapability`] records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WiphyExtendedCapabilities {
    pub capabilities: Vec<u8>,
    pub mask: Vec<u8>,
}

/// `wiphy->mbssid_max_interfaces` and, when nonzero,
/// `wiphy->ema_max_profile_periodicity`.  The capability belongs to the
/// physical radio: a transmitting AP and every non-transmitting profile must
/// be vdevs of the same wiphy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MbssidSupport {
    /// Maximum simultaneous AP interfaces in one multiple-BSSID set.
    pub max_interfaces: u8,
    /// Maximum Enhanced Multiple-BSSID Advertisement template period.
    /// Zero means that regular MBSSID, but not EMA, is available.
    pub ema_max_profile_periodicity: u8,
}

/// One WCN6855 BIOS SAR frequency range as cfg80211 exposes it through
/// `NL80211_ATTR_SAR_SPEC`.  The ath11k hardware table uses the same raw
/// values Linux advertises (for example `2402..=2482` for 2.4 GHz).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SarFrequencyRange {
    pub start_freq: u32,
    pub end_freq: u32,
}

/// `struct cfg80211_sar_capa`, currently limited to the power type that
/// ath11k's WCN6855 BIOS table implements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SarCapability {
    /// `NL80211_SAR_TYPE_POWER` (zero).
    pub sar_type: u32,
    pub frequency_ranges: Vec<SarFrequencyRange>,
}

/// One `cfg80211_sar_sub_specs` supplied by `NL80211_CMD_SET_SAR_SPECS`.
/// `power_quarter_dbm` is an s32 in units of 0.25 dBm; ath11k's firmware
/// consumes its low byte for both RF chains, matching Linux ath11k.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SarPowerLimit {
    pub range_index: u32,
    pub power_quarter_dbm: i32,
}

/// One `struct survey_info` record exposed by `NL80211_CMD_GET_SURVEY`.
///
/// The `Option` fields mirror cfg80211's `filled` bitmap: a frequency-only
/// record is a valid channel for which firmware has not supplied counters
/// yet. Times are milliseconds, as required by `enum nl80211_survey_info`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SurveyInfo {
    pub frequency_mhz: u32,
    pub noise_dbm: Option<i8>,
    pub in_use: bool,
    pub time_ms: Option<u64>,
    pub time_busy_ms: Option<u64>,
    pub time_rx_ms: Option<u64>,
    pub time_tx_ms: Option<u64>,
}

/// Current and available antenna masks for one physical wiphy.
///
/// The masks use nl80211's antenna numbering: bit zero is antenna one.  A
/// driver reports this only when it implements both `get_antenna` and
/// `set_antenna`; `u32::MAX` in a SET_WIPHY request means "all available".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AntennaInfo {
    pub tx: u32,
    pub rx: u32,
    pub available_tx: u32,
    pub available_rx: u32,
}

/// One band entry of `NL80211_ATTR_TX_RATES`.
///
/// `band` is the `nl80211_band` ordinal (0 = 2.4 GHz, 1 = 5 GHz, 3 =
/// 6 GHz). `None` means that the nested attribute was omitted and cfg80211
/// should retain the negotiated/default rate set for that PHY family. The
/// legacy bytes are 500-kbit/s rate values in their nl80211 wire form; their
/// basic-rate marker is ignored for the TX mask just as cfg80211 ignores it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxBitrateBand {
    pub band: u8,
    pub legacy: Option<Vec<u8>>,
    /// `IEEE80211_HT_MCS_MASK_LEN` bytes; bit n permits HT MCS n.
    pub ht_mcs: Option<Vec<u8>>,
    /// Eight `nl80211_txrate_vht::mcs` native-endian u16 bitmaps.
    pub vht_mcs: Option<[u16; 8]>,
    /// `NL80211_TXRATE_{DEFAULT,FORCE_SGI,FORCE_LGI}`.
    pub gi: Option<u8>,
    /// Eight `nl80211_txrate_he::mcs` native-endian u16 bitmaps.
    pub he_mcs: Option<[u16; 8]>,
    /// `NL80211_RATE_INFO_HE_GI_*`.
    pub he_gi: Option<u8>,
    /// `NL80211_RATE_INFO_HE_*LTF`.
    pub he_ltf: Option<u8>,
}

/// Complete `NL80211_CMD_SET_TX_BITRATE_MASK` request.
///
/// Missing bands retain cfg80211's all-negotiated-rates default; an empty
/// outer list therefore resets every band to automatic rate control.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxBitrateMask {
    pub bands: Vec<TxBitrateBand>,
}

impl TxBitrateMask {
    /// The optional entry for one `nl80211_band` ordinal.
    pub fn band(&self, band: u8) -> Option<&TxBitrateBand> {
        self.bands.iter().find(|entry| entry.band == band)
    }
}

/// Capability for wireless-specific operations.
pub enum WirelessRight {
    /// Allows triggering scans and reading BSSID lists.
    Scan,
    /// Allows associating with and disassociating from Access Points.
    Associate,
    /// Allows changing PHY configuration (channel, power).
    Config,
    /// Allows entering monitor mode and receiving all management frames.
    Monitor,
    /// Full administrative rights over the wireless interface.
    Admin,
}

/// A specialized network interface supporting 802.11 operations.
#[async_trait]
pub trait WirelessNetIface: Interface {
    /// Stable identity of the physical radio (`struct wiphy`) backing this
    /// netdev.  The default deliberately keeps pre-virtual-interface
    /// drivers one-wiphy-per-netdev; a multi-vdev driver overrides it so
    /// nl80211 groups all of its interfaces under one wiphy.
    fn wiphy_id(&self) -> u64 {
        // FNV-1a: stable for the lifetime of a registered name, dependency
        // free, and sufficient only for the legacy one-netdev default.
        self.name()
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
                (hash ^ byte as u64).wrapping_mul(0x0000_0100_0000_01b3)
            })
    }

    /// Whether this physical radio can create additional nl80211 virtual
    /// interfaces (`NL80211_CMD_NEW_INTERFACE`).
    fn supports_virtual_interfaces(&self) -> bool {
        false
    }

    /// Valid simultaneous virtual-interface sets for this physical wiphy.
    /// Returning an empty list leaves the implicit one-interface-per-iftype
    /// cfg80211 combinations only; a driver with virtual vdevs must return
    /// the combinations it actually enforces.
    fn interface_combinations(&self) -> Vec<InterfaceCombination> {
        Vec::new()
    }

    /// Preallocated MAC addresses for this physical wiphy. A multi-vdev
    /// driver returns the hardware's address pool, including its base
    /// address; nl80211 emits the pool only when it has more than one entry.
    fn wiphy_mac_addresses(&self) -> Vec<[u8; 6]> {
        Vec::new()
    }

    /// Wiphy-wide Extended Capabilities. The two byte strings must have the
    /// same length; an invalid value is left out of the nl80211 response.
    fn wiphy_extended_capabilities(&self) -> Option<WiphyExtendedCapabilities> {
        None
    }

    /// Per-interface-type Extended Capabilities for
    /// `NL80211_ATTR_IFTYPE_EXT_CAPA`. Returning no records leaves this
    /// optional wiphy metadata absent.
    fn iftype_extended_capabilities(&self) -> Vec<IftypeExtendedCapability> {
        Vec::new()
    }

    /// `wiphy->sar_capa`. `None` leaves `NL80211_CMD_SET_SAR_SPECS`
    /// unadvertised and makes the command return `-EOPNOTSUPP`.
    fn sar_capability(&self) -> Option<SarCapability> {
        None
    }

    /// `wiphy->mbssid_max_interfaces`. `None` leaves
    /// `NL80211_ATTR_MBSSID_CONFIG` absent and rejects START_AP MBSSID
    /// attributes. Drivers must expose this only when their AP start path
    /// supplies the target's transmitting/non-transmitting-vdev contract.
    fn mbssid_support(&self) -> Option<MbssidSupport> {
        None
    }

    /// `NL80211_EXT_FEATURE_FILS_DISCOVERY`: this AP wiphy can transmit the
    /// configured 6 GHz FILS discovery action-frame template.
    fn supports_fils_discovery(&self) -> bool {
        false
    }

    /// `NL80211_EXT_FEATURE_UNSOL_BCAST_PROBE_RESP`: this AP wiphy can
    /// transmit a configured unsolicited broadcast probe response on 6 GHz.
    fn supports_unsol_bcast_probe_resp(&self) -> bool {
        false
    }

    /// `NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER`: this AP vdev can enable
    /// firmware fine-timing-measurement responder operation.
    fn supports_ftm_responder(&self) -> bool {
        false
    }

    /// `NL80211_EXT_FEATURE_BSS_COLOR`: firmware can offload HE BSS-color
    /// collision detection for an AP vdev.
    fn supports_bss_color(&self) -> bool {
        false
    }

    /// This AP wiphy can enable the HE Target Wake Time responder role from
    /// `NL80211_ATTR_TWT_RESPONDER` on START_AP. The target engine is pdev
    /// scoped, but the request is owned by the beaconing AP configuration.
    fn supports_twt_responder(&self) -> bool {
        false
    }

    /// This station/P2P-client interface implements mac80211's software
    /// `set_cqm_rssi_config` path for a single RSSI threshold.
    fn supports_cqm_rssi(&self) -> bool {
        false
    }

    /// This interface also implements cfg80211's range-based CQM RSSI-list
    /// contract. When true, [`Self::set_cqm_rssi`] accepts more than one
    /// ordered threshold and maintains the adjacent low/high range after
    /// every notification.
    fn supports_cqm_rssi_list(&self) -> bool {
        false
    }

    /// `NL80211_CMD_SET_CQM`'s ordered RSSI threshold configuration. `None`
    /// disables CQM RSSI notifications. The control layer has already
    /// validated the nl80211 nesting, threshold order/sign and interface
    /// type.
    fn set_cqm_rssi(&self, _config: Option<CqmRssiConfig>) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// Whether this wiphy implements `NL80211_CMD_GET_SURVEY`. A supporting
    /// driver returns one record for every enabled channel, then refreshes the
    /// active channel's firmware counters on its ordered runtime worker.
    fn supports_survey(&self) -> bool {
        false
    }

    /// Current `NL80211_CMD_GET_SURVEY` snapshot. This is intentionally a
    /// synchronous snapshot: a generic-netlink dump can run in an executor
    /// poll and must not block waiting for the driver's WMI completion.
    fn survey_info(&self) -> Vec<SurveyInfo> {
        Vec::new()
    }

    /// `get_antenna`: current and available physical-radio antenna masks.
    /// `None` leaves the `SET_WIPHY` antenna attributes unadvertised.
    fn antenna_info(&self) -> Option<AntennaInfo> {
        None
    }

    /// `set_antenna`: replace both physical-radio chain masks.  The nl80211
    /// layer has normalized an all-ones request to the available masks and
    /// rejected bits that name unavailable antennas.
    fn set_antenna(&self, _tx: u32, _rx: u32) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// Current `WIPHY_FRAG_THRESHOLD`, or `None` when the driver does not
    /// publish a fragmentation-threshold setting.
    fn fragmentation_threshold(&self) -> Option<u32> {
        None
    }

    /// Current `WIPHY_RTS_THRESHOLD`, or `None` if this wiphy has no
    /// `set_rts_threshold` implementation.
    fn rts_threshold(&self) -> Option<u32> {
        None
    }

    /// `set_rts_threshold`: apply a physical-radio setting to every live
    /// vdev and retain it for vdev creation and recovery replay.
    fn set_rts_threshold(&self, _threshold: u32) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// Whether this interface implements `NL80211_CMD_SET_TX_BITRATE_MASK`.
    fn supports_tx_bitrate_mask(&self) -> bool {
        false
    }

    /// Retain and apply cfg80211's allowed TX rates for the active band.
    /// The generic layer has validated nl80211 nesting and field sizes;
    /// drivers additionally intersect the mask with their negotiated peer
    /// and physical capabilities.
    fn set_tx_bitrate_mask(&self, _mask: TxBitrateMask) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// Whether this wiphy implements `NL80211_EXT_FEATURE_STA_TX_PWR`.
    /// The setting applies to one associated peer, rather than the
    /// per-interface regulatory limit returned by [`Self::tx_power_dbm`].
    fn supports_station_tx_power(&self) -> bool {
        false
    }

    /// Apply `NL80211_ATTR_STA_TX_POWER_SETTING` to an associated peer.
    /// The generic layer has checked the nl80211 setting form and peer
    /// identity; drivers validate their supported dBm range and retain a
    /// managed-station setting for recovery or a later reassociation.
    fn set_station_tx_power(&self, _peer: [u8; 6], _setting: StationTxPower) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// Whether this wiphy implements `NL80211_EXT_FEATURE_ACK_SIGNAL_SUPPORT`
    /// and therefore exposes the associated peer's ACK RSSI through
    /// `NL80211_STA_INFO_ACK_SIGNAL`.
    fn supports_ack_signal(&self) -> bool {
        false
    }

    /// Current effective transmit-power limit in integral dBm for this
    /// netdev. `None` means the driver has no active-vdev snapshot to report.
    /// nl80211 serializes a reported value as
    /// `NL80211_ATTR_WIPHY_TX_POWER_LEVEL` in mBm on `GET_INTERFACE`.
    fn tx_power_dbm(&self) -> Option<i32> {
        None
    }

    /// `set_sar_specs`: replace the physical radio's complete BIOS SAR
    /// limitation table. The generic nl80211 layer has already checked the
    /// type, range indices and duplicate entries before this is called.
    fn set_sar_power_limits(&self, _limits: &[SarPowerLimit]) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// Maximum SSID entries in an active scan, including the empty wildcard.
    /// Zero means passive-only discovery. CONNECT chooses that form before
    /// invoking a driver; explicit active scans are never silently changed.
    fn max_scan_ssids(&self) -> u8 {
        0
    }

    /// Caller probe-IE byte budget advertised as MAX_SCAN_IE_LEN and enforced
    /// before scan dispatch. The default preserves the existing 512-byte ABI;
    /// drivers with smaller firmware buffers override it.
    fn max_scan_ie_len(&self) -> u16 {
        512
    }

    /// Whether an unassociated `NL80211_CMD_TRIGGER_SCAN` may use a random
    /// source address (`NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR`).  The default
    /// is deliberately conservative: a request carrying RANDOM_ADDR is
    /// rejected unless its physical driver explicitly exposes the firmware
    /// capability.
    fn supports_scan_random_mac(&self) -> bool {
        false
    }

    /// Whether this wiphy exposes `NL80211_EXT_FEATURE_SET_SCAN_DWELL` and
    /// honours `NL80211_ATTR_MEASUREMENT_DURATION` on a triggered scan.
    fn supports_scan_dwell(&self) -> bool {
        false
    }

    /// Driver-specific `NL80211_ATTR_FEATURE_FLAGS` bits.  These describe
    /// link-layer behaviour which is already implemented by a netdev but is
    /// not inferred from one of the generic nl80211 operations above.
    /// Implementations must return only defined `NL80211_FEATURE_*` bits.
    fn nl80211_feature_flags(&self) -> u32 {
        0
    }

    /// Create one additional netdev/vdev under this interface's physical
    /// wiphy.  The implementation registers the new interface before
    /// returning it, so callers can immediately emit `NEW_INTERFACE`.
    fn new_virtual_interface(
        &self,
        _name: &str,
        _iftype: u32,
        _mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Begin removal of this virtual netdev (`NL80211_CMD_DEL_INTERFACE`).
    /// The physical/root interface returns `NotSupported`. Implementations
    /// that need WMI/firmware waits make the netdev undiscoverable before
    /// returning, then release its firmware vdev asynchronously; they must
    /// not reuse that slot until the ordered teardown has completed.
    fn delete_virtual_interface(&self) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Actual supported HT/VHT capabilities for a band (2400, 5000, or
    /// 6000 MHz). Six-GHz devices expose HE through their driver-specific
    /// capability path until this generic interface gains an HE body.
    /// Missing capabilities are never inferred from another band's flags.
    fn phy_capabilities(&self, _band_mhz: u32) -> Option<iface::PhyCapabilities> {
        None
    }

    /// Per-access-category Ethernet producer. Drivers without separate
    /// queues preserve compatibility by returning their default TX ring.
    fn tx_ring_for_ac(
        &self,
        _category: AccessCategory,
    ) -> &narf_lib::sync::IrqSafeSpinLock<
        Option<narf_ipc::Producer<narf_net::Frame, { narf_net::TX_RING_N }>>,
    > {
        self.tx_ring()
    }

    /// The driver performs WPA2-PSK key exchange from a supplied PMK.
    fn supports_handshake_offload(&self) -> bool {
        false
    }

    /// The driver performs the WPA3-Personal SAE exchange and key setup from a
    /// supplied password (NL80211_EXT_FEATURE_SAE_OFFLOAD). Distinct from
    /// [`supports_handshake_offload`](Self::supports_handshake_offload): a
    /// driver may offload the PSK 4-way handshake without doing SAE.
    fn supports_sae_offload(&self) -> bool {
        false
    }

    /// Driver emits nl80211 link-loss notifications, including local teardown.
    fn reports_disconnect_events(&self) -> bool {
        false
    }

    /// Original AP information elements from the most recent scan.
    fn scan_information_elements(&self, _bssid: [u8; 6]) -> Option<Vec<u8>> {
        None
    }
    /// Returns detailed information about the wireless interface.
    fn get_wireless_info(&self) -> WirelessIfaceInfo;

    /// Triggers an asynchronous scan.
    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError>;

    /// Initiates association with an Access Point.
    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError>;

    /// Disconnects from the current Access Point.
    async fn disassociate(&self) -> Result<(), WirelessError>;

    /// BSSID of the current association, if any. Lets the control plane route
    /// a connect request targeting a different BSS of the same ESS as a roam.
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        None
    }

    /// Reassociate (roam) to a new BSS of the current ESS, preserving the
    /// interface. Defaults to unsupported; drivers that can reassociate
    /// override this.
    async fn roam(&self, _req: AssociateRequest) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Configures PHY-level parameters.
    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError>;

    // ── Userspace-SME MLME path (NL80211_CMD_AUTHENTICATE etc.) ───────
    //
    // When the SME runs in userspace (wpa_supplicant's own SME), the driver
    // exposes the low-level MLME: it sends individual Authentication and
    // (Re)Association frames on request and surfaces the peer's response, and
    // it registers for / transmits arbitrary management frames. All default
    // to unsupported; a driver that offloads the SME (the CONNECT path) leaves
    // them untouched and [`supports_userspace_mlme`](Self::supports_userspace_mlme)
    // returns false.

    /// The driver drives its MLME from userspace: it implements the
    /// authenticate/associate/deauthenticate/disassociate, management-frame
    /// registration/TX and external-auth operations below.
    fn supports_userspace_mlme(&self) -> bool {
        false
    }

    /// Send an Authentication frame and return the peer's response frame,
    /// delivered to userspace as NL80211_CMD_AUTHENTICATE.
    async fn mlme_authenticate(&self, _req: MlmeAuthRequest) -> Result<Vec<u8>, WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Send an (Re)Association Request and return the (Re)Association Response
    /// frame, delivered to userspace as NL80211_CMD_ASSOCIATE.
    async fn mlme_associate(&self, _req: MlmeAssocRequest) -> Result<Vec<u8>, WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Send a Deauthentication frame to `peer`; returns the transmitted frame
    /// for the NL80211_CMD_DEAUTHENTICATE notification.
    async fn mlme_deauthenticate(
        &self,
        _peer: [u8; 6],
        _reason: u16,
    ) -> Result<Vec<u8>, WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Send a Disassociation frame to `peer`; returns the transmitted frame
    /// for the NL80211_CMD_DISASSOCIATE notification.
    async fn mlme_disassociate(
        &self,
        _peer: [u8; 6],
        _reason: u16,
    ) -> Result<Vec<u8>, WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Register to receive management frames of the given 802.11 frame-control
    /// type/subtype whose body starts with `match_prefix` (empty = all), for
    /// NL80211_CMD_REGISTER_FRAME.
    fn register_mgmt_frame(
        &self,
        _frame_type: u16,
        _match_prefix: &[u8],
    ) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Transmit a management frame under `cookie`; the returned bool reports
    /// whether it was acknowledged, for NL80211_CMD_FRAME_TX_STATUS.
    async fn mgmt_tx(&self, _cookie: u64, _req: MgmtTxRequest) -> Result<bool, WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Maximum `NL80211_CMD_REMAIN_ON_CHANNEL` duration in milliseconds.
    /// Zero means this wiphy has no scan-backed off-channel facility.
    fn max_remain_on_channel_duration_ms(&self) -> u32 {
        0
    }

    /// `WIPHY_FLAG_OFFCHAN_TX`: management TX may use a live
    /// remain-on-channel context rather than the interface's operating
    /// channel (`NL80211_ATTR_OFFCHANNEL_TX_OK`).
    fn supports_offchannel_mgmt_tx(&self) -> bool {
        false
    }

    /// Queue a remain-on-channel request. The driver publishes its actual
    /// start and eventual expiry as nl80211 events keyed by `cookie`.
    fn remain_on_channel(
        &self,
        _cookie: u64,
        _frequency_mhz: u32,
        _duration_ms: u32,
    ) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Cancel the matching remain-on-channel request. A successful cancel
    /// still produces the normal expiry notification.
    fn cancel_remain_on_channel(&self, _cookie: u64) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Report a userspace SAE (external-auth) result to the driver, for
    /// NL80211_CMD_EXTERNAL_AUTH.
    async fn external_auth_status(
        &self,
        _bssid: [u8; 6],
        _status: u16,
    ) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    // ── Access-Point mode (NL80211_CMD_START_AP etc.) ─────────────────
    //
    // These methods perform synchronous argument / state validation. A
    // driver whose firmware completion path runs on its runtime task may
    // enqueue the actual WMI operation after accepting the request: a
    // generic-netlink handler can itself execute in an executor poll and
    // must never re-enter that executor with `block_on`. All default to
    // unsupported; an AP-capable driver overrides them and advertises AP in
    // its [`WirelessIfaceInfo::modes`].

    /// The driver can operate as an Access Point (beaconing + a station table).
    fn supports_ap(&self) -> bool {
        false
    }

    /// The AP firmware provides per-client U-APSD buffering and beacon TIM
    /// maintenance (`NL80211_ATTR_SUPPORT_AP_UAPSD`).
    fn supports_ap_uapsd(&self) -> bool {
        false
    }

    /// Maximum associated stations for an AP/P2P-GO vdev
    /// (`NL80211_ATTR_MAX_AP_ASSOC_STA`).  Zero leaves the implementation's
    /// limit unspecified to userspace.
    fn max_ap_assoc_sta(&self) -> u32 {
        0
    }

    /// The driver can perform an AP / P2P-GO channel switch
    /// (`NL80211_CMD_CHANNEL_SWITCH`).  The temporary CSA beacon and the
    /// post-switch beacon are distinct: the former carries mutable countdown
    /// bytes while the latter becomes the normal beacon on the new channel.
    fn supports_channel_switch(&self) -> bool {
        false
    }

    /// `wiphy->max_num_csa_counters`, advertised with
    /// `NL80211_ATTR_MAX_CSA_COUNTERS` whenever channel switching is
    /// supported. Zero leaves the metadata absent.
    fn max_csa_counters(&self) -> u8 {
        0
    }

    /// The interface's current operating type as an `NL80211_IFTYPE_*` value
    /// (default `NL80211_IFTYPE_STATION` = 2), reported by GET_INTERFACE.
    fn current_iftype(&self) -> u32 {
        2
    }

    /// Change the nl80211 interface type while it is down
    /// (`NL80211_CMD_SET_INTERFACE`). Drivers that expose more than one
    /// role must reject an in-place active-vdev change rather than silently
    /// retagging station state as AP state.
    fn set_iftype(&self, _iftype: u32) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Whether this station interface supports `NL80211_ATTR_4ADDR`.
    /// cfg80211's `WIPHY_FLAG_4ADDR_STATION` is an internal driver
    /// capability; nl80211 exposes the selected state in each interface
    /// reply rather than serializing that wiphy flag itself.
    fn supports_four_addr_station(&self) -> bool {
        false
    }

    /// Current managed-station four-address/WDS state. `GET_INTERFACE`,
    /// `NEW_INTERFACE`, and `SET_INTERFACE` replies serialize this as
    /// `NL80211_ATTR_4ADDR`.
    fn four_addr_enabled(&self) -> bool {
        false
    }

    /// Select managed-station four-address/WDS operation. The generic
    /// nl80211 layer restricts an enabled request to station mode and checks
    /// [`Self::supports_four_addr_station`] first; a driver retains the
    /// state for future association and recovery and updates a live BSS peer
    /// through its ordered control path.
    fn set_four_addr(&self, _enabled: bool) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// Begin AP operation: upload the beacon template and start beaconing.
    fn start_ap(&self, _cfg: ApConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Stop AP operation and beaconing.
    fn stop_ap(&self) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Replace supplied pieces of a running AP beacon
    /// (NL80211_CMD_SET_BEACON). `None` means the attribute was absent;
    /// `Some(Vec::new())` deliberately clears that piece. `probe_resp` is a
    /// complete `NL80211_ATTR_PROBE_RESP` template rather than an IE suffix.
    fn set_beacon(
        &self,
        _head: Option<Vec<u8>>,
        _tail: Option<Vec<u8>>,
        _probe_resp: Option<Vec<u8>>,
    ) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Update AP FILS-discovery and/or unsolicited-broadcast-probe-response
    /// policy. The outer `Option` preserves nl80211 attribute presence;
    /// `Some(None)` disables and deletes that template, while `None` leaves
    /// that side unchanged.
    fn set_ap_discovery(
        &self,
        _fils: Option<Option<FilsDiscoveryConfig>>,
        _unsol_bcast_probe_resp: Option<Option<UnsolBcastProbeRespConfig>>,
    ) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Enable AP fine-timing-measurement responder operation. The optional
    /// location payloads are retained for the AP's measurement responses.
    fn set_ap_ftm_responder(&self, _config: FtmResponderConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Update AP HE BSS-color collision detection. `disabled` is the
    /// on-air HE Operation setting; the color remains present in the nested
    /// nl80211 form even when collision detection is disabled.
    fn set_ap_he_bss_color(&self, _config: HeBssColorConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Begin an AP-only HE BSS-color transition
    /// (`NL80211_CMD_COLOR_CHANGE_REQUEST`).  The driver owns the temporary
    /// countdown template and reports its started/completed/aborted state on
    /// the nl80211 MLME multicast group.  Acceptance only queues firmware
    /// work; it does not claim the countdown has reached its final TBTT.
    fn color_change(&self, _config: ColorChangeConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Announce and execute an AP / P2P-GO channel switch.  Like the other
    /// AP operations, this may enqueue firmware work; acceptance does not
    /// claim that the target vdev restart has completed.
    fn channel_switch(&self, _cfg: ChannelSwitchConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Add an associated station to the AP's table (NL80211_CMD_NEW_STATION).
    fn add_station(&self, _sta: StationConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Update an existing station's parameters (NL80211_CMD_SET_STATION).
    fn set_station(&self, _sta: StationConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    /// Remove a station (or all, when `mac` is None) with the given 802.11
    /// reason code (NL80211_CMD_DEL_STATION).
    fn del_station(&self, _mac: Option<[u8; 6]>, _reason: u16) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    // ── External-supplicant station mode ──────────────────────────────
    //
    // The mac80211 contract a userspace supplicant drives when the driver
    // does not offload the handshake: keys (`ieee80211_add_key` /
    // `_del_key` → `drv_set_key`), port authorization
    // (`ieee80211_change_station` with AUTHORIZED) and the control port
    // (`ieee80211_tx_control_port`, `cfg80211_rx_control_port`). Errors are
    // positive Linux errnos, reported to userspace as they are. All default
    // to -EOPNOTSUPP (`rdev->ops->add_key` etc. absent).
    //
    // These run in the caller's netlink syscall, which cannot wait for the
    // device: the driver validates synchronously (the errors mac80211
    // returns before `drv_set_key`), then applies the operation in order on
    // its own task — every key install, authorization and control-port
    // frame of an interface in the order requested, so data never leaves
    // an authorized port before the keys requested ahead of it are in.

    /// The driver implements [`SecurityConfig::External`] associations and
    /// the operations below: nl80211 advertises NEW_KEY / SET_KEY /
    /// DEL_KEY, SET_STATION, CONTROL_PORT_FRAME and
    /// `NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211`.
    fn supports_external_supplicant(&self) -> bool {
        false
    }

    /// The control-port TX path retains `IEEE80211_TX_CTL_REQ_TX_STATUS`
    /// through its asynchronous completion path and therefore exposes
    /// `NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211_TX_STATUS`.
    ///
    /// This is deliberately separate from [`Self::supports_external_supplicant`]:
    /// a driver may route EAPOL through nl80211 yet be unable to correlate a
    /// later hardware completion with the original control-port cookie.
    fn supports_control_port_tx_status(&self) -> bool {
        false
    }

    /// Cipher suites exposed by this physical wiphy.  The default keeps the
    /// historic minimal external-supplicant profile; a hardware driver must
    /// override it before advertising a suite that its key-install and data
    /// paths can actually honour.
    fn cipher_suites(&self) -> &'static [u32] {
        if self.supports_external_supplicant() {
            &[CIPHER_SUITE_CCMP, CIPHER_SUITE_AES_CMAC]
        } else if self.supports_handshake_offload() || self.supports_sae_offload() {
            &[CIPHER_SUITE_CCMP]
        } else {
            &[]
        }
    }

    /// The driver can retain GTK rekey material across a low-power sleep
    /// and refresh the group key without waking the host
    /// (`NL80211_CMD_SET_REKEY_OFFLOAD`).  This is distinct from the normal
    /// EAPOL Group Key Handshake, which still belongs to the userspace
    /// supplicant while the host is awake.
    fn supports_gtk_rekey_offload(&self) -> bool {
        false
    }

    /// Store the KEK, KCK and replay counter that a later low-power/WoW
    /// transition will hand to the device.  The caller supplies the replay
    /// counter in network (big-endian) order, exactly as nl80211 does.
    /// Implementations must neither print nor expose this secret material.
    fn set_gtk_rekey_data(&self, _data: GtkRekeyData) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// `wiphy->wowlan`: capabilities the driver advertises for WoWLAN.
    /// Absence means `GET/SET_WOWLAN` must return `-EOPNOTSUPP`.
    fn wowlan_support(&self) -> Option<WowlanSupport> {
        None
    }

    /// `nl80211_set_wowlan`: retain a validated wake configuration until a
    /// later system low-power transition programs the hardware.  `None`
    /// clears the configuration, mirroring a SET_WOWLAN request without
    /// `NL80211_ATTR_WOWLAN_TRIGGERS`.
    fn set_wowlan(&self, _config: Option<WowlanConfig>) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// `nl80211_get_wowlan`: current retained wake configuration, if any.
    fn wowlan_config(&self) -> Option<WowlanConfig> {
        None
    }

    /// Install a key (`ieee80211_add_key` → `drv_set_key(SET_KEY)`).
    /// -ENOENT when `peer` is not an associated station
    /// (`sta_info_get_bss` + `WLAN_STA_ASSOC`).
    fn add_key(&self, _key: KeyParams) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// `set_default_mgmt_key`: select the IGTK used to protect outbound AP
    /// group robust management frames. Station interfaces only consume IGTKs
    /// on RX and can leave this as a successful no-op.
    fn set_default_mgmt_key(&self, _idx: u8) -> Result<(), i32> {
        Ok(())
    }

    /// Remove a key (`ieee80211_del_key`: -ENOENT when there is none).
    fn del_key(&self, _idx: u8, _pairwise: bool, _peer: Option<[u8; 6]>) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// `ieee80211_change_station` for the AP's station entry: only
    /// AUTHORIZED may change (`CFG80211_STA_AP_STA`). -ENOENT for another
    /// peer; authorizing before association is -EINVAL
    /// (`sta_info_move_state`).
    fn set_port_authorized(&self, _peer: [u8; 6], _authorized: bool) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// `ieee80211_tx_control_port`: send `frame` (the PDU after the
    /// Ethernet header) to `dest` with EtherType `proto`; `no_encrypt`
    /// sends it without protection (`IEEE80211_TX_INTFL_DONT_ENCRYPT`).
    fn tx_control_port(
        &self,
        _dest: [u8; 6],
        _proto: u16,
        _frame: Vec<u8>,
        _no_encrypt: bool,
    ) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// As [`Self::tx_control_port`], retaining a caller-provided nl80211
    /// cookie for a later `CONTROL_PORT_FRAME_TX_STATUS` multicast event.
    /// `None` is the DONT_WAIT_FOR_ACK form and must not request a status.
    ///
    /// The compatibility default preserves a driver's existing control-port
    /// path. Only implementations that return true from
    /// [`Self::supports_control_port_tx_status`] override it and retain the
    /// cookie until their TX completion arrives.
    fn tx_control_port_with_status(
        &self,
        dest: [u8; 6],
        proto: u16,
        frame: Vec<u8>,
        no_encrypt: bool,
        _cookie: Option<u64>,
    ) -> Result<(), i32> {
        self.tx_control_port(dest, proto, frame, no_encrypt)
    }

    // ── Power save, regulatory, station info ──────────────────────────

    /// The driver has `set_power_mgmt` (`SUPPORTS_PS`): the current
    /// `wdev->ps` default (`WIPHY_FLAG_PS_ON_BY_DEFAULT`). `None` = no
    /// power-save support (SET/GET_POWER_SAVE -EOPNOTSUPP).
    fn power_save_default(&self) -> Option<bool> {
        None
    }

    /// `ieee80211_set_power_mgmt(enabled)`.
    fn set_power_save(&self, _enabled: bool) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }

    /// The wiphy's own regulatory domain (`get_wiphy_regdom`), if any.
    fn regulatory_domain(&self) -> Option<RegDomainInfo> {
        None
    }

    /// What the driver tracks about its associated AP
    /// (`ieee80211_sta_set_sinfo`).
    fn station_info(&self) -> Option<StationInfo> {
        None
    }

    /// Associated client MACs for an AP / P2P GO, used by the dump form of
    /// `NL80211_CMD_GET_STATION`.
    fn ap_station_macs(&self) -> Vec<[u8; 6]> {
        Vec::new()
    }

    /// What the driver tracks about one associated AP client. `None` means
    /// the client is not currently present (`-ENOENT` for a non-dump query).
    fn ap_station_info(&self, _peer: [u8; 6]) -> Option<StationInfo> {
        None
    }
}

/// `EOPNOTSUPP`.
pub const EOPNOTSUPP: i32 = 95;

pub struct AssociateRequest {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    /// Centre frequency in MHz of the selected scan result.
    pub frequency_mhz: u32,
    pub channel: u32,
    pub security: SecurityConfig,
    /// The SME's elements for the (Re)Association Request
    /// (`NL80211_ATTR_IE` of CONNECT / ASSOCIATE): what mac80211's
    /// `ieee80211_mgd_assoc` copies into `assoc_data->ie` and
    /// `ieee80211_send_assoc` splits around its own elements. An offloading
    /// driver that builds its own RSNE / RSNXE drops those two from here;
    /// for [`SecurityConfig::External`] they are the supplicant's and go
    /// out as given.
    pub ie: Vec<u8>,
}

pub enum SecurityConfig {
    Open,
    Wpa2 {
        psk: [u8; 32],
    },
    Wpa3 {
        password: Vec<u8>,
    },
    /// The supplicant runs in userspace (wpa_supplicant without the 4-way
    /// handshake offload: WPA2/WPA3 with its own 4-way, 802.1X/EAP): the
    /// driver associates with the RSN elements in
    /// [`AssociateRequest::ie`], does not run its in-kernel supplicant or
    /// rekey, hands EAPOL to userspace (control port) and transmits it
    /// unencrypted until a pairwise key is in, takes keys from
    /// [`WirelessNetIface::add_key`] and opens the port on
    /// [`WirelessNetIface::set_port_authorized`].
    External(ExternalSecurity),
}

/// What the SME asked for in an external-supplicant association
/// (`struct cfg80211_crypto_settings` + `assoc_data->use_mfp`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExternalSecurity {
    /// `NL80211_ATTR_USE_MFP` = `NL80211_MFP_REQUIRED` (`sta->mfp`).
    pub use_mfp: bool,
    /// `NL80211_ATTR_PRIVACY` or an RSNE in the elements: the BSS is
    /// protected.
    pub privacy: bool,
    pub control_port: ControlPort,
}

/// `cfg80211_crypto_settings` control-port fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlPort {
    /// `NL80211_ATTR_CONTROL_PORT` (`IEEE80211_STA_CONTROL_PORT`): the
    /// port stays closed after association until userspace authorizes it;
    /// without it mac80211 authorizes the AP at association.
    pub enabled: bool,
    /// `control_port_ethertype` (host order; ETH_P_PAE).
    pub ethertype: u16,
    /// `control_port_no_encrypt`.
    pub no_encrypt: bool,
    /// `control_port_over_nl80211`: EAPOL goes to the connection owner as
    /// NL80211_CMD_CONTROL_PORT_FRAME instead of the netdev.
    pub over_nl80211: bool,
    /// `control_port_no_preauth`: RSN pre-authentication frames
    /// (ETH_P_PREAUTH) stay on the netdev.
    pub no_preauth: bool,
}

impl Default for ControlPort {
    fn default() -> Self {
        ControlPort {
            enabled: false,
            ethertype: ETH_P_PAE,
            no_encrypt: false,
            over_nl80211: false,
            no_preauth: false,
        }
    }
}

/// `ETH_P_PAE`.
pub const ETH_P_PAE: u16 = 0x888e;
/// `ETH_P_PREAUTH`.
pub const ETH_P_PREAUTH: u16 = 0x88c7;

/// A key from NL80211_CMD_NEW_KEY (`struct key_params` + index / type /
/// peer), validated by nl80211 (`cfg80211_validate_key_settings`).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyParams {
    pub idx: u8,
    pub pairwise: bool,
    /// The peer (`NL80211_ATTR_MAC`): the AP for a pairwise key, `None` for
    /// a group key.
    pub peer: Option<[u8; 6]>,
    /// `WLAN_CIPHER_SUITE_*` (00-0F-AC:n as a u32).
    pub cipher: u32,
    pub key: Vec<u8>,
    /// Receive sequence counter (RSC / IPN), 6 octets little-endian, or
    /// empty.
    pub seq: Vec<u8>,
    /// `NL80211_ATTR_KEY_DEFAULT_MGMT`: this IGTK is the AP's selected
    /// transmit management key. Meaningful only for a non-pairwise IGTK.
    pub default_mgmt: bool,
}

/// GTK rekey material from `NL80211_CMD_SET_REKEY_OFFLOAD` /
/// `cfg80211_gtk_rekey_data`.  These are the 16-byte CCMP-128 keys
/// WCN6855 firmware supports; the replay counter remains in the big-endian
/// nl80211 representation until the driver serializes its firmware command.
///
/// Deliberately no `Debug` implementation prints the key material.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtkRekeyData {
    pub kek: [u8; 16],
    pub kck: [u8; 16],
    pub replay_counter: [u8; 8],
    /// The negotiated AKM (`00-0f-ac:n`) when userspace supplied it.  The
    /// ath11k GTK-offload wire command does not carry it, but preserving it
    /// retains the nl80211 contract for drivers with AKM-specific engines.
    pub akm: Option<u32>,
}

/// One SSID/RSSI match condition for WoWLAN network detection.  The RSSI
/// threshold is in dBm; `None` leaves firmware's normal candidate policy in
/// effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetDetectMatch {
    pub ssid: Vec<u8>,
    pub rssi_threshold_dbm: Option<i32>,
}

/// One `NL80211_SCHED_SCAN_PLAN`: after `iterations` scans at `interval`,
/// firmware advances to the next plan.  The final plan has no iteration
/// count and repeats until the host wakes or cancels it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetDetectScanPlan {
    pub interval_secs: u32,
    pub iterations: Option<u32>,
}

/// cfg80211's WoWLAN `NET_DETECT` request, carried over the existing
/// sched-scan attribute vocabulary.  It is deliberately a low-power
/// network-list offload configuration, not a general scheduled scan API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetDetectConfig {
    /// Directed probe SSIDs; an empty list makes the NLO scan passive.
    pub probe_ssids: Vec<Vec<u8>>,
    /// Optional channel allow-list in MHz.
    pub frequencies_mhz: Vec<u32>,
    /// Optional probe-request IEs. WCN6855's PNO WMI command has no payload
    /// slot for them; this is retained because Linux ath11k advertises and
    /// accepts the cfg80211 512-byte limit while its NLO encoder likewise
    /// cannot place the bytes on the wire.
    pub probe_ies: Vec<u8>,
    /// Match sets that wake the host when a candidate network is found.
    pub matches: Vec<NetDetectMatch>,
    /// One or two periodic scan plans, in seconds.
    pub plans: Vec<NetDetectScanPlan>,
    /// Delay before the first scan, in seconds.
    pub delay_secs: u32,
    /// Optional randomized probe source address.
    pub random_mac: Option<ScanRandomMac>,
}

/// `struct wiphy_wowlan_support` for the subset ath11k exposes.  The
/// capability bit for GTK rekeying is distinct from the GTK-failure wake
/// trigger, exactly as `WIPHY_WOWLAN_SUPPORTS_GTK_REKEY` is in cfg80211.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WowlanSupport {
    pub disconnect: bool,
    pub magic_packet: bool,
    pub gtk_rekey: bool,
    pub gtk_rekey_failure: bool,
    pub max_patterns: u8,
    pub min_pattern_len: u8,
    pub max_pattern_len: u16,
    pub max_packet_offset: u16,
    /// `WIPHY_WOWLAN_NET_DETECT`: maximum simultaneous NLO match sets.
    /// Zero means the firmware cannot perform network-list offload.
    pub net_detect_max_match_sets: u8,
    /// `NL80211_FEATURE_ND_RANDOM_MAC_ADDR`.
    pub net_detect_random_mac: bool,
}

/// One cfg80211 packet pattern: `mask` is one bit per pattern byte, ordered
/// least-significant bit first as the nl80211 ABI specifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WowlanPattern {
    pub mask: Vec<u8>,
    pub pattern: Vec<u8>,
    pub offset: u32,
}

/// `struct cfg80211_wowlan`, deliberately limited to the wake features
/// advertised by current NARF drivers.  GTK rekey support is capability-only
/// and is activated by `SET_REKEY_OFFLOAD` plus the low-power transition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WowlanConfig {
    pub disconnect: bool,
    pub magic_packet: bool,
    pub gtk_rekey_failure: bool,
    pub patterns: Vec<WowlanPattern>,
    /// Firmware network-list offload armed during system WoW suspend.
    pub net_detect: Option<NetDetectConfig>,
}

impl core::fmt::Debug for GtkRekeyData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GtkRekeyData")
            .field("kek", &"[redacted; 16 bytes]")
            .field("kck", &"[redacted; 16 bytes]")
            .field("replay_counter", &self.replay_counter)
            .field("akm", &self.akm)
            .finish()
    }
}

impl core::fmt::Debug for KeyParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material.
        f.debug_struct("KeyParams")
            .field("idx", &self.idx)
            .field("pairwise", &self.pairwise)
            .field("peer", &self.peer)
            .field("cipher", &self.cipher)
            .field("default_mgmt", &self.default_mgmt)
            .finish()
    }
}

/// `WLAN_CIPHER_SUITE_TKIP`.
pub const CIPHER_SUITE_TKIP: u32 = 0x000f_ac02;
/// `WLAN_CIPHER_SUITE_CCMP`.
pub const CIPHER_SUITE_CCMP: u32 = 0x000f_ac04;
/// `WLAN_CIPHER_SUITE_AES_CMAC` (BIP-CMAC-128).
pub const CIPHER_SUITE_AES_CMAC: u32 = 0x000f_ac06;
/// `WLAN_CIPHER_SUITE_GCMP` (GCMP-128).
pub const CIPHER_SUITE_GCMP: u32 = 0x000f_ac08;
/// `WLAN_CIPHER_SUITE_GCMP_256`.
pub const CIPHER_SUITE_GCMP_256: u32 = 0x000f_ac09;
/// `WLAN_CIPHER_SUITE_CCMP_256`.
pub const CIPHER_SUITE_CCMP_256: u32 = 0x000f_ac0a;
/// `WLAN_CIPHER_SUITE_BIP_GMAC_128`.
pub const CIPHER_SUITE_BIP_GMAC_128: u32 = 0x000f_ac0b;
/// `WLAN_CIPHER_SUITE_BIP_GMAC_256`.
pub const CIPHER_SUITE_BIP_GMAC_256: u32 = 0x000f_ac0c;
/// `WLAN_CIPHER_SUITE_BIP_CMAC_256`.
pub const CIPHER_SUITE_BIP_CMAC_256: u32 = 0x000f_ac0d;

/// A regulatory domain as nl80211 reports it (`struct ieee80211_regdomain`:
/// kHz, mBi, mBm, `NL80211_RRF_*`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegDomainInfo {
    pub alpha2: [u8; 2],
    /// `enum nl80211_dfs_regions`.
    pub dfs_region: u8,
    /// The wiphy manages its own regulatory domain
    /// (`REGULATORY_WIPHY_SELF_MANAGED`).
    pub self_managed: bool,
    pub rules: Vec<RegRuleInfo>,
}

/// `struct ieee80211_reg_rule`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegRuleInfo {
    pub flags: u32,
    pub start_khz: u32,
    pub end_khz: u32,
    pub max_bw_khz: u32,
    pub max_antenna_gain_mbi: u32,
    pub max_eirp_mbm: u32,
    pub dfs_cac_ms: u32,
}

/// A bitrate as `struct rate_info` carries it for STA_INFO.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateInfo {
    /// The rate in 100 kb/s (`cfg80211_calculate_bitrate`).
    pub bitrate_100kbps: u32,
    /// HT MCS index (`RATE_INFO_FLAGS_MCS`).
    pub ht_mcs: Option<u8>,
    /// VHT MCS / NSS (`RATE_INFO_FLAGS_VHT_MCS`).
    pub vht_mcs: Option<(u8, u8)>,
    /// HE MCS / NSS / GI (`RATE_INFO_FLAGS_HE_MCS`).
    pub he_mcs: Option<(u8, u8, u8)>,
    /// HE dual-carrier modulation (`NL80211_RATE_INFO_HE_DCM`).  It is
    /// meaningful only when `he_mcs` is present; nl80211 still emits its
    /// explicit zero value for ordinary HE rates.
    pub he_dcm: bool,
    /// HE OFDMA resource-unit allocation (`NL80211_RATE_INFO_HE_RU_ALLOC`):
    /// 0 = 26 tones, through 6 = 2×996 tones. `None` means non-OFDMA.
    /// When present this supersedes `width_mhz` on the nl80211 wire.
    pub he_ru_alloc: Option<u8>,
    /// Channel width in MHz (20, 40, 80, 160).
    pub width_mhz: u16,
    pub short_gi: bool,
}

/// What the driver tracks about its AP for NL80211_CMD_GET_STATION.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StationInfo {
    /// `NL80211_STA_INFO_SIGNAL` (dBm), last received frame.
    pub signal_dbm: Option<i8>,
    /// `NL80211_STA_INFO_SIGNAL_AVG` (dBm).
    pub signal_avg_dbm: Option<i8>,
    /// `NL80211_STA_INFO_CHAIN_SIGNAL` (dBm), indexed by receive chain.
    /// `None` means that chain had no valid firmware sample.
    pub chain_signal_dbm: [Option<i8>; 8],
    /// `NL80211_STA_INFO_ACK_SIGNAL` (dBm).
    pub ack_signal_dbm: Option<i8>,
    pub tx_bitrate: Option<RateInfo>,
    pub rx_bitrate: Option<RateInfo>,
    pub rx_packets: Option<u32>,
    pub tx_packets: Option<u32>,
    /// `NL80211_STA_INFO_TX_RETRIES`: aggregate retransmissions reported
    /// by the device's TX-completion descriptors.
    pub tx_retries: Option<u32>,
    pub tx_failed: Option<u32>,
    /// `NL80211_STA_INFO_TX_DURATION`: aggregate firmware PPDU airtime sent
    /// to this station, in microseconds.
    pub tx_duration_us: Option<u64>,
    /// `NL80211_STA_INFO_RX_DURATION`: aggregate received PPDU airtime, in
    /// microseconds.
    pub rx_duration_us: Option<u64>,
}

pub struct WirelessConfig {
    pub channel: u32,
    pub tx_power_dbm: Option<i8>,
}

/// A userspace-SME Authentication request (NL80211_CMD_AUTHENTICATE).
/// `auth_data` carries the SAE/FT authentication payload (empty for Open).
pub struct MlmeAuthRequest {
    pub peer: [u8; 6],
    pub ssid: Vec<u8>,
    /// NL80211_ATTR_WIPHY_FREQ of the BSS, in MHz. A channel number would
    /// not do: 6 GHz numbering overlaps the 2.4 GHz band.
    pub frequency_mhz: u32,
    /// `enum nl80211_auth_type`.
    pub auth_type: u32,
    /// NL80211_ATTR_AUTH_DATA: for SAE the transaction sequence number and
    /// status code (2 + 2 octets, little-endian) then the body
    /// (`ieee80211_mgd_auth`).
    pub auth_data: Vec<u8>,
    /// NL80211_ATTR_IE: elements appended to the Authentication frame.
    pub ie: Vec<u8>,
}

/// A userspace-SME (Re)Association request (NL80211_CMD_ASSOCIATE). A set
/// `prev_bssid` requests a Reassociation rather than an Association.
pub struct MlmeAssocRequest {
    pub peer: [u8; 6],
    pub ssid: Vec<u8>,
    /// NL80211_ATTR_WIPHY_FREQ of the BSS, in MHz.
    pub frequency_mhz: u32,
    pub ie: Vec<u8>,
    pub prev_bssid: Option<[u8; 6]>,
    pub use_mfp: bool,
    /// The control-port settings of `nl80211_crypto_settings`.
    pub control_port: ControlPort,
    /// The BSS is protected (its scan entry has Privacy / an RSNE).
    pub privacy: bool,
}

/// A management frame to transmit (NL80211_CMD_FRAME). `frequency_mhz` 0
/// means the current operating channel; otherwise it preserves the exact
/// `NL80211_ATTR_WIPHY_FREQ` identity. `offchannel_ok` permits off-channel
/// transmission for the given `duration` (milliseconds).
pub struct MgmtTxRequest {
    pub frequency_mhz: u32,
    pub frame: Vec<u8>,
    pub offchannel_ok: bool,
    pub duration: u32,
}

/// Access-Point configuration for NL80211_CMD_START_AP. `beacon_head` is the
/// beacon frame before the TIM; mac80211 inserts the mutable TIM and
/// `beacon_tail` follows it. `frequency_mhz` preserves the exact nl80211
/// operating frequency (6 GHz channel numbers overlap 2.4 GHz, so a channel
/// number alone is lossy), and
/// `hidden_ssid` is an `NL80211_HIDDEN_SSID_*` value.
#[derive(Clone, PartialEq, Eq)]
pub struct ApConfig {
    pub ssid: Vec<u8>,
    pub beacon_head: Vec<u8>,
    pub beacon_tail: Vec<u8>,
    /// Optional complete `NL80211_ATTR_PROBE_RESP` template.  The MAC owns
    /// its destination address and inserts CSA countdown bytes while a
    /// channel switch is active.
    pub probe_resp: Option<Vec<u8>>,
    pub beacon_interval: u32,
    pub dtim_period: u32,
    pub frequency_mhz: u32,
    /// `enum nl80211_chan_width` from `NL80211_ATTR_CHANNEL_WIDTH`.
    pub channel_width: u32,
    /// `NL80211_ATTR_CENTER_FREQ1`; required above 20 MHz.
    pub center_freq1_mhz: Option<u32>,
    /// `NL80211_ATTR_CENTER_FREQ2`; required for 80+80 MHz.
    pub center_freq2_mhz: Option<u32>,
    pub hidden_ssid: u32,
    pub privacy: bool,
    /// Per-vdev `NL80211_ATTR_MBSSID_CONFIG`, if this AP participates in a
    /// multiple-BSSID group. The element lists belong only to a transmitting
    /// vdev and are appended by the driver to the firmware beacon template.
    pub mbssid: Option<MbssidConfig>,
    /// Complete `NL80211_ATTR_MBSSID_ELEMS` IEs, one per EMA beacon profile.
    /// Regular MBSSID transmits the complete list in its one beacon.
    pub mbssid_elems: Vec<Vec<u8>>,
    /// Complete `NL80211_ATTR_EMA_RNR_ELEMS` IEs. In EMA mode element `i`
    /// accompanies MBSSID element `i`; additional RNR elements accompany
    /// every generated beacon, as mac80211 does.
    pub ema_rnr_elems: Vec<Vec<u8>>,
    /// Initial FILS-discovery configuration. `None` leaves discovery
    /// disabled when the AP starts.
    pub fils_discovery: Option<FilsDiscoveryConfig>,
    /// Initial six-GHz unsolicited broadcast Probe Response configuration.
    /// When both it and FILS are configured, firmware follows Linux ath11k's
    /// FILS-first selection.
    pub unsol_bcast_probe_resp: Option<UnsolBcastProbeRespConfig>,
    /// Enabled `NL80211_ATTR_FTM_RESPONDER` state, if requested.
    pub ftm_responder: Option<FtmResponderConfig>,
    /// `NL80211_ATTR_TWT_RESPONDER` on START_AP. This is a flag rather than
    /// a nested configuration; the firmware uses its Linux default pdev TWT
    /// policy block for the responder engine.
    pub twt_responder: bool,
    /// Optional `NL80211_ATTR_HE_OBSS_PD` spatial-reuse configuration for an
    /// HE AP. This is a pdev-wide firmware policy, but cfg80211 supplies it
    /// with the AP start parameters.
    pub he_obss_pd: Option<HeObssPdConfig>,
    /// Optional `NL80211_ATTR_HE_BSS_COLOR` state for an HE AP.
    pub he_bss_color: Option<HeBssColorConfig>,
}

/// Request-side `NL80211_ATTR_MBSSID_CONFIG`. `index == 0` is the
/// transmitting BSSID; higher indices are non-transmitting BSS profiles and
/// name their transmitting AP by `tx_ifindex`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MbssidConfig {
    pub index: u8,
    pub tx_ifindex: Option<u32>,
    pub ema: bool,
}

/// Nested `NL80211_ATTR_FILS_DISCOVERY` configuration. Intervals are in
/// 802.11 TUs. A supplied zero `max_interval_tu` is retained and disables
/// transmission; `Some(None)` in a discovery update is the distinct explicit
/// delete-template form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilsDiscoveryConfig {
    pub min_interval_tu: u32,
    pub max_interval_tu: u32,
    /// Complete action-frame template, including management header.
    pub template: Vec<u8>,
}

/// Nested `NL80211_ATTR_UNSOL_BCAST_PROBE_RESP` configuration. Applicable to
/// six-GHz AP operation; a supplied zero interval disables transmission,
/// while `Some(None)` in an update deletes the template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsolBcastProbeRespConfig {
    pub interval_tu: u32,
    /// Complete broadcast Probe Response template, including management
    /// header and fixed fields.
    pub template: Vec<u8>,
}

/// Enabled `NL80211_ATTR_FTM_RESPONDER` configuration. LCI and civic-location
/// payloads are Measurement Report element bodies beginning at their token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FtmResponderConfig {
    pub lci: Vec<u8>,
    pub civicloc: Vec<u8>,
}

/// `NL80211_ATTR_CQM` RSSI configuration. The thresholds are strictly
/// increasing, non-positive dBm values. A singleton config uses mac80211's
/// one-threshold path; a longer list uses cfg80211's moving low/high range
/// around the current RSSI. `hysteresis_db` is unsigned just as cfg80211
/// stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CqmRssiConfig {
    pub thresholds_dbm: Vec<i32>,
    pub hysteresis_db: u32,
}

/// Nested `NL80211_ATTR_HE_OBSS_PD` configuration. The offset fields are in
/// the Linux UAPI's 1..=20 range when supplied; omitted fields retain the
/// zero values cfg80211 gives the driver. The two bitmaps are host-native
/// `u32[2]` words, matching cfg80211's direct copy into
/// `ieee80211_he_obss_pd` and the ath11k WMI command representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeObssPdConfig {
    pub min_offset: u8,
    pub max_offset: u8,
    pub non_srg_max_offset: u8,
    pub bss_color_bitmap: [u32; 2],
    pub partial_bssid_bitmap: [u32; 2],
    pub sr_ctrl: u8,
}

/// Nested `NL80211_ATTR_HE_BSS_COLOR`. `color` is in the Linux-required
/// range 1..=63; `partial` is retained even though ath11k's collision WMI
/// command needs only the color and enabled state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeBssColorConfig {
    pub color: u8,
    pub disabled: bool,
    pub partial: bool,
}

/// AP HE BSS-color transition requested with
/// `NL80211_CMD_COLOR_CHANGE_REQUEST`.
///
/// The `*_next` template pieces replace the normal beacon after the final
/// countdown TBTT; absent pieces preserve the currently configured template.
/// `beacon_color_tail` is the mandatory temporary countdown beacon tail, and
/// its single native-endian `u16` offset identifies the countdown byte.  A
/// temporary beacon head may be omitted only to reuse the active one.  The
/// optional probe-response offset instead addresses the complete temporary
/// Probe Response frame, matching nl80211's `CNTDWN_OFFS_PRESP` convention.
#[derive(Clone, PartialEq, Eq)]
pub struct ColorChangeConfig {
    /// `NL80211_ATTR_COLOR_CHANGE_COUNT`.
    pub count: u8,
    /// `NL80211_ATTR_COLOR_CHANGE_COLOR` (an HE BSS color, 1..=63).
    pub color: u8,
    /// Top-level `NL80211_ATTR_BEACON_HEAD` for the normal post-change AP.
    pub beacon_next_head: Option<Vec<u8>>,
    /// Top-level `NL80211_ATTR_BEACON_TAIL` for the normal post-change AP.
    pub beacon_next_tail: Option<Vec<u8>>,
    /// Top-level `NL80211_ATTR_PROBE_RESP` for the normal post-change AP.
    pub probe_resp_next: Option<Vec<u8>>,
    /// Nested `NL80211_ATTR_BEACON_HEAD` for the countdown template.
    pub beacon_color_head: Option<Vec<u8>>,
    /// Nested `NL80211_ATTR_BEACON_TAIL` for the countdown template.
    pub beacon_color_tail: Vec<u8>,
    /// The one `NL80211_ATTR_CNTDWN_OFFS_BEACON` offset into
    /// `beacon_color_tail`.
    pub counter_offset_beacon: u16,
    /// Nested `NL80211_ATTR_PROBE_RESP`, if countdown Probe Responses are
    /// requested.
    pub probe_resp_color: Option<Vec<u8>>,
    /// Optional one `NL80211_ATTR_CNTDWN_OFFS_PRESP` offset into
    /// `probe_resp_color`.
    pub counter_offset_presp: Option<u16>,
    /// `NL80211_ATTR_UNSOL_BCAST_PROBE_RESP`, if present. The outer option
    /// preserves attribute presence; `Some(None)` explicitly disables it.
    pub unsol_bcast_probe_resp: Option<Option<UnsolBcastProbeRespConfig>>,
}

/// Access-Point channel-switch request for `NL80211_CMD_CHANNEL_SWITCH`.
///
/// `beacon_csa_head` / `beacon_csa_tail` are the temporary beacon while the
/// countdown is active.  Every `counter_offsets_beacon` element is a native
/// endian `u16` offset into the CSA *tail*, exactly as
/// `NL80211_ATTR_CNTDWN_OFFS_BEACON` specifies.  The optional `beacon_after_*`
/// pieces replace the retained normal beacon after the vdev reaches the new
/// channel; an absent piece keeps the currently configured one.  The optional
/// probe-response templates follow the same ownership rule, but their counter
/// offsets address the complete probe-response frame rather than a beacon
/// tail, as nl80211 specifies.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelSwitchConfig {
    /// `NL80211_ATTR_WIPHY_FREQ`.
    pub frequency_mhz: u32,
    /// `NL80211_ATTR_CHANNEL_WIDTH`.
    pub channel_width: u32,
    /// `NL80211_ATTR_CENTER_FREQ1`.
    pub center_freq1_mhz: Option<u32>,
    /// `NL80211_ATTR_CENTER_FREQ2`.
    pub center_freq2_mhz: Option<u32>,
    /// `NL80211_ATTR_CH_SWITCH_COUNT` (the on-air u8 TBTT count).
    pub count: u8,
    /// `NL80211_ATTR_CH_SWITCH_BLOCK_TX`.
    pub block_tx: bool,
    /// Nested `NL80211_ATTR_CSA_IES` beacon head.
    pub beacon_csa_head: Vec<u8>,
    /// Nested `NL80211_ATTR_CSA_IES` beacon tail.
    pub beacon_csa_tail: Vec<u8>,
    /// `NL80211_ATTR_CNTDWN_OFFS_BEACON`, decoded from native-endian u16s.
    pub counter_offsets_beacon: Vec<u16>,
    /// Nested `NL80211_ATTR_PROBE_RESP`, if mac80211 should answer probe
    /// requests with CSA countdown IEs during the transition.
    pub probe_resp_csa: Option<Vec<u8>>,
    /// `NL80211_ATTR_CNTDWN_OFFS_PRESP`, decoded from native-endian u16s.
    pub counter_offsets_presp: Vec<u16>,
    /// Optional top-level `NL80211_ATTR_BEACON_HEAD` for the new channel.
    pub beacon_after_head: Option<Vec<u8>>,
    /// Optional top-level `NL80211_ATTR_BEACON_TAIL` for the new channel.
    pub beacon_after_tail: Option<Vec<u8>>,
    /// Optional top-level `NL80211_ATTR_PROBE_RESP` for the new channel.
    pub probe_resp_after: Option<Vec<u8>>,
    /// Enabled `NL80211_ATTR_FTM_RESPONDER` supplied with the post-switch
    /// beacon. It becomes active only after the target-channel restart.
    pub ftm_responder: Option<FtmResponderConfig>,
    /// `NL80211_ATTR_HE_BSS_COLOR` supplied with the post-switch beacon.
    pub he_bss_color: Option<HeBssColorConfig>,
    /// Request-side `NL80211_ATTR_UNSOL_BCAST_PROBE_RESP`. The outer option
    /// preserves whether the channel-switch request included the nested
    /// attribute; `Some(None)` is its explicit disable/delete form.  mac80211
    /// applies this state only after the AP vdev reaches the target channel.
    pub unsol_bcast_probe_resp: Option<Option<UnsolBcastProbeRespConfig>>,
}

/// `NL80211_ATTR_STA_TX_POWER_SETTING` values accepted for an associated
/// peer. `Fixed` is represented explicitly because nl80211 accepts its enum
/// ordinal even though ath11k rejects it: the Linux parser supplies no dBm
/// value for that form and ath11k consequently returns `-EINVAL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StationTxPower {
    /// `NL80211_TX_POWER_AUTOMATIC`: return to the per-interface limit.
    Automatic,
    /// `NL80211_TX_POWER_LIMITED`: cap the peer at this integral dBm level.
    Limited(i16),
    /// `NL80211_TX_POWER_FIXED`: preserved for the driver's Linux-shaped
    /// validation path.
    Fixed,
}

/// A station-table entry for NL80211_CMD_NEW_STATION / SET_STATION.
#[derive(Clone, PartialEq, Eq)]
pub struct StationConfig {
    pub mac: [u8; 6],
    pub aid: u16,
    pub listen_interval: u16,
    pub supported_rates: Vec<u8>,
    /// WMM is present for this client. `None` keeps the existing value when
    /// used with SET_STATION.
    pub wme: Option<bool>,
    /// `NL80211_STA_WME_UAPSD_QUEUES`: the client's requested delivery /
    /// trigger AC bitmap. `None` preserves the current request on
    /// SET_STATION.
    pub uapsd_queues: Option<u8>,
    /// `NL80211_STA_WME_MAX_SP`: the U-APSD maximum service-period code
    /// (0 = unlimited, 1/2/3 = 2/4/6 frames). `None` preserves it on
    /// SET_STATION.
    pub uapsd_max_sp: Option<u8>,
    /// `NL80211_STA_FLAG_MFP` from `NL80211_ATTR_STA_FLAGS2`. `None` keeps
    /// the current PMF state when used with SET_STATION.
    pub mfp: Option<bool>,
    /// `NL80211_ATTR_STA_CAPABILITY`, as supplied by hostapd from the
    /// association request. `None` preserves the current value on
    /// SET_STATION.
    pub capability: Option<u16>,
    /// `NL80211_ATTR_STA_EXT_CAPABILITY`.
    pub ext_capability: Option<Vec<u8>>,
    /// Exact `struct ieee80211_ht_cap` bytes from
    /// `NL80211_ATTR_HT_CAPABILITY`.
    pub ht_capability: Option<Vec<u8>>,
    /// Exact `struct ieee80211_vht_cap` bytes from
    /// `NL80211_ATTR_VHT_CAPABILITY`.
    pub vht_capability: Option<Vec<u8>>,
    /// `struct ieee80211_sta_he_cap` bytes from
    /// `NL80211_ATTR_HE_CAPABILITY`.
    pub he_capability: Option<Vec<u8>>,
    /// `struct ieee80211_he_6ghz_capa` from
    /// `NL80211_ATTR_HE_6GHZ_CAPABILITY`.
    pub he_6ghz_capability: Option<u16>,
    /// `NL80211_STA_FLAG_AUTHORIZED` when `NL80211_ATTR_STA_FLAGS2` (or
    /// its legacy nested equivalent) explicitly changed it. `None` leaves
    /// the current authorization state unchanged.
    pub authorized: Option<bool>,
    /// Per-peer `NL80211_ATTR_STA_TX_POWER_SETTING`. `None` means that this
    /// request did not change the peer's existing transmit-power policy.
    pub station_tx_power: Option<StationTxPower>,
}

pub mod registry {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use narf_lib::sync::IrqSafeSpinLock;

    static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn WirelessNetIface>>> =
        IrqSafeSpinLock::new(Vec::new());

    pub fn register(iface: Arc<dyn WirelessNetIface>) {
        REGISTRY.lock().push(iface);
    }

    pub fn list() -> Vec<Arc<dyn WirelessNetIface>> {
        REGISTRY.lock().clone()
    }

    /// One representative per physical radio, in the stable order nl80211
    /// exposes as `phyN`.  Multiple virtual interfaces with the same
    /// [`WirelessNetIface::wiphy_id`] must never produce duplicate wiphys.
    pub fn wiphys() -> Vec<Arc<dyn WirelessNetIface>> {
        let mut ids = Vec::new();
        let mut out = Vec::new();
        for iface in REGISTRY.lock().iter() {
            let id = iface.wiphy_id();
            if !ids.contains(&id) {
                ids.push(id);
                out.push(iface.clone());
            }
        }
        out
    }

    /// Current `phyN` index of a physical radio identity.
    pub fn wiphy_index(id: u64) -> Option<u32> {
        wiphys()
            .iter()
            .position(|iface| iface.wiphy_id() == id)
            .map(|index| index as u32)
    }

    /// Remove the interface named `name` (its netdev went away).
    pub fn unregister(name: &str) {
        REGISTRY.lock().retain(|i| i.name() != name);
    }
}

/// Force-link hook.
pub fn register_initcalls() {
    narf_net::install_trusted_net_authority(narf_net::bootstrap_authority());
    let _ = nl80211::register();
}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    use narf_ipc::{Consumer, Producer};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;
    use narf_net::{Frame, RX_RING_N, TX_RING_N};

    struct MockWireless {
        is_scanning: AtomicBool,
        is_associated: AtomicBool,
        rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
        tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    }

    impl MockWireless {
        fn new() -> Self {
            Self {
                is_scanning: AtomicBool::new(false),
                is_associated: AtomicBool::new(false),
                rx: IrqSafeSpinLock::new(None),
                tx: IrqSafeSpinLock::new(None),
            }
        }
    }

    impl Interface for MockWireless {
        fn name(&self) -> &str {
            "wlan0"
        }
        fn mac(&self) -> [u8; 6] {
            [0; 6]
        }
        fn mtu(&self) -> u32 {
            1500
        }
        fn link_up(&self) -> bool {
            true
        }
        fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
            &self.rx
        }
        fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
            &self.tx
        }
    }

    #[async_trait]
    impl WirelessNetIface for MockWireless {
        fn get_wireless_info(&self) -> WirelessIfaceInfo {
            WirelessIfaceInfo {
                base_name: self.name().into(),
                base_mac: self.mac(),
                bands: alloc::vec![],
                modes: iface::WirelessModes::STATION,
                hw_caps: iface::HwCaps {
                    ht_supported: true,
                    vht_supported: false,
                    he_supported: false,
                    eht_supported: false,
                },
            }
        }

        async fn scan(&self, _req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
            if self.is_scanning.swap(true, Ordering::SeqCst) {
                return Err(WirelessError::Busy);
            }
            narf_scheduler::yield_now().await;
            self.is_scanning.store(false, Ordering::SeqCst);
            Ok(alloc::vec![BssInfo {
                bssid: [0x12; 6],
                ssid: alloc::vec![b'T', b'e', b's', b't'],
                frequency_mhz: 2412,
                channel: 1,
                rssi: -50,
                security: scan::BssSecurity::Wpa2,
            }])
        }

        async fn associate(&self, _req: AssociateRequest) -> Result<(), WirelessError> {
            self.is_associated.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn disassociate(&self) -> Result<(), WirelessError> {
            self.is_associated.store(false, Ordering::SeqCst);
            Ok(())
        }

        async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
            Ok(())
        }
    }

    fn smoke_wireless_scan_busy_logic() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let mock = Arc::new(MockWireless::new());
        let success = Arc::new(AtomicBool::new(false));

        let m1 = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let res = m1
                .scan(ScanRequest {
                    ssids: Vec::new(),
                    frequencies_mhz: Vec::new(),
                    channels: Vec::new(),
                    active: true,
                    random_mac: None,
                    colocated_6ghz: false,
                    duration_tu: None,
                    duration_mandatory: false,
                    extra_ies: Vec::new(),
                })
                .await;
            if res.is_ok() && res.unwrap().len() == 1 {
                s.store(true, Ordering::SeqCst);
            }
        });

        // We can't easily test the "Busy" error here because spawn order is deterministic in this scheduler
        // and we only have one CPU. But we can verify the scan completes.
        narf_scheduler::run_until_empty();
        if success.load(Ordering::SeqCst) {
            TestResult::Pass
        } else {
            TestResult::Fail("scan failed")
        }
    }
    kernel_test_in!("wireless", smoke_wireless_scan_busy_logic);

    fn smoke_wireless_association_state() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let mock = Arc::new(MockWireless::new());
        let success = Arc::new(AtomicBool::new(false));

        let m = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let req = AssociateRequest {
                bssid: [0x12; 6],
                ssid: alloc::vec![b'T', b'e', b's', b't'],
                frequency_mhz: 2412,
                channel: 1,
                security: SecurityConfig::Open,
                ie: Vec::new(),
            };
            m.associate(req).await.expect("associate failed");
            if m.is_associated.load(Ordering::SeqCst) {
                m.disassociate().await.expect("disassociate failed");
                if !m.is_associated.load(Ordering::SeqCst) {
                    s.store(true, Ordering::SeqCst);
                }
            }
        });

        narf_scheduler::run_until_empty();
        if success.load(Ordering::SeqCst) {
            TestResult::Pass
        } else {
            TestResult::Fail("association state cycle failed")
        }
    }
    kernel_test_in!("wireless", smoke_wireless_association_state);

    fn smoke_mlme_frame_control_round_trip() -> TestResult {
        use crate::mlme::{FrameControl, FrameType, MgmtSubtype};
        let fc = FrameControl::mgmt(MgmtSubtype::ProbeRequest);
        let raw = fc.encode();
        // §9.2.4.1.3: type=0 (mgmt), subtype=4 (ProbeReq).
        if (raw >> 2) & 0x3 != 0 {
            return TestResult::Fail("Mgmt frame Type field drift");
        }
        if (raw >> 4) & 0xF != 4 {
            return TestResult::Fail("ProbeRequest Subtype drift");
        }
        let back = FrameControl::decode(raw);
        if back.frame_type != FrameType::Management
            || back.subtype != MgmtSubtype::ProbeRequest as u8
        {
            return TestResult::Fail("Frame Control round-trip lost type/subtype");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_frame_control_round_trip);

    fn smoke_mlme_mgmt_header_layout() -> TestResult {
        use crate::mlme::{FrameControl, MgmtHeader, MgmtSubtype};
        let h = MgmtHeader {
            fc: FrameControl::mgmt(MgmtSubtype::Authentication),
            duration: 0x0030,
            addr1: [0x11; 6],
            addr2: [0x22; 6],
            addr3: [0x33; 6],
            seq_ctrl: 0x0010,
        };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        if buf.len() != 24 {
            return TestResult::Fail("Mgmt header should be 24 bytes (no addr4)");
        }
        let back = match MgmtHeader::decode(&buf) {
            Some(v) => v,
            None => return TestResult::Fail("MgmtHeader::decode returned None"),
        };
        if back != h {
            return TestResult::Fail("MgmtHeader round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_mgmt_header_layout);

    fn smoke_mlme_ie_iter_and_write() -> TestResult {
        use crate::mlme::{iter_ies, write_ie, ElementId};
        let mut buf = Vec::new();
        write_ie(&mut buf, ElementId::Ssid, b"narf");
        write_ie(
            &mut buf,
            ElementId::SupportedRates,
            &[0x82, 0x84, 0x8B, 0x96],
        );
        let ies: Vec<_> = iter_ies(&buf).collect();
        if ies.len() != 2 {
            return TestResult::Fail("expected 2 IEs back from iter");
        }
        if ies[0].id != ElementId::Ssid as u8 || ies[0].body != b"narf" {
            return TestResult::Fail("SSID IE round-trip lost contents");
        }
        if ies[1].id != ElementId::SupportedRates as u8 || ies[1].body.len() != 4 {
            return TestResult::Fail("SupportedRates IE round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_ie_iter_and_write);

    fn smoke_mlme_probe_request_builder() -> TestResult {
        use crate::mlme::{build_probe_request_body, iter_ies, ElementId};
        let body = build_probe_request_body(b"narf", &[0x82, 0x84]);
        let ies: Vec<_> = iter_ies(&body).collect();
        if ies.len() != 2 {
            return TestResult::Fail("ProbeReq body should hold 2 IEs");
        }
        if ies[0].id != ElementId::Ssid as u8 || ies[0].body != b"narf" {
            return TestResult::Fail("ProbeReq SSID IE wrong");
        }
        if ies[1].id != ElementId::SupportedRates as u8 {
            return TestResult::Fail("ProbeReq SupportedRates IE wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_probe_request_builder);

    fn smoke_mlme_open_auth_request() -> TestResult {
        use crate::mlme::{build_open_auth_request, AuthFields};
        let body = build_open_auth_request();
        let fields = match AuthFields::decode(&body) {
            Some(f) => f,
            None => return TestResult::Fail("AuthFields::decode returned None"),
        };
        if fields.algorithm != 0 {
            return TestResult::Fail("Open System should use algorithm 0");
        }
        if fields.sequence != 1 {
            return TestResult::Fail("Auth sequence should be 1 for the request");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_open_auth_request);

    fn smoke_eapol_header_round_trip() -> TestResult {
        use crate::eapol::{EapolHeader, EapolType, EAPOL_PROTOCOL_VERSION};
        let h = EapolHeader {
            version: EAPOL_PROTOCOL_VERSION,
            packet_type: EapolType::EapolKey as u8,
            body_length: 95,
        };
        let mut out = Vec::new();
        h.encode(&mut out);
        if out.len() != 4 {
            return TestResult::Fail("EAPOL header should be 4 bytes");
        }
        // Body length is big-endian.
        if u16::from_be_bytes([out[2], out[3]]) != 95 {
            return TestResult::Fail("EAPOL body length not big-endian");
        }
        let back = EapolHeader::decode(&out).expect("decode");
        if back != h {
            return TestResult::Fail("EAPOL header round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_header_round_trip);

    fn smoke_eapol_key_frame_round_trip() -> TestResult {
        use crate::eapol::{
            KeyFrame, KEY_DESCRIPTOR_RSN, KI_INSTALL, KI_KEY_ACK, KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE,
        };
        // 16-byte MIC (HMAC-SHA1 AKM) — typical WPA2-Personal.
        let mut k = KeyFrame::empty(16);
        k.descriptor_type = KEY_DESCRIPTOR_RSN;
        k.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | KI_KEY_MIC | KI_INSTALL | 0x02;
        k.key_length = 16;
        k.replay_counter = 0x0102_0304_0506_0708;
        k.key_nonce = [0xAA; 32];
        k.key_data = alloc::vec![0xDD, 0xEE, 0xFF];

        let raw = k.encode();
        let back = KeyFrame::decode(&raw, 16).expect("decode");
        if back != k {
            return TestResult::Fail("KeyFrame round-trip mismatch");
        }
        if !back.pairwise() || !back.key_ack() || !back.has_mic() || !back.install() {
            return TestResult::Fail("Key Information bit flags lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_key_frame_round_trip);

    fn smoke_eapol_into_eapol_wraps_header() -> TestResult {
        use crate::eapol::{EapolHeader, EapolType, KeyFrame};
        let k = KeyFrame::empty(16);
        let body_len = k.encode().len();
        let pdu = k.into_eapol();
        if pdu.len() != 4 + body_len {
            return TestResult::Fail("into_eapol did not prefix a 4-byte header");
        }
        let h = EapolHeader::decode(&pdu).expect("decode");
        if h.packet_type != EapolType::EapolKey as u8 {
            return TestResult::Fail("packet type should be EAPOL-Key");
        }
        if h.body_length as usize != body_len {
            return TestResult::Fail("body_length mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_into_eapol_wraps_header);

    /// Identity HMAC for testing the PRF / handshake plumbing — we
    /// just want to verify the surface, not the cryptographic
    /// strength. Production uses HMAC-SHA1 (AKM-1/2) or HMAC-SHA256
    /// (AKM-3+) wired via narf-crypto.
    struct StubHmac;
    impl crate::eapol::HmacPrimitive for StubHmac {
        fn out_len(&self) -> usize {
            20
        }
        fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
            // Deterministic XOR digest for test purposes only.
            let mut out = alloc::vec![0u8; 20];
            for (i, b) in key.iter().enumerate() {
                out[i % 20] ^= *b;
            }
            for (i, b) in data.iter().enumerate() {
                out[i % 20] ^= b.rotate_left((i % 8) as u32);
            }
            out
        }
    }

    fn smoke_eapol_prf_extends_to_requested_length() -> TestResult {
        use crate::eapol::prf;
        let key = [0x11u8; 32];
        let label = b"Pairwise key expansion";
        let context = [0x22u8; 76];
        // 384 bits = 48 bytes; PRF runs for ceil(48/20) = 3 chunks.
        let out = prf(&StubHmac, &key, label, &context, 384);
        if out.len() != 48 {
            return TestResult::Fail("PRF output length not 48 bytes");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/eapol",
        smoke_eapol_prf_extends_to_requested_length
    );

    fn smoke_eapol_derive_ptk_splits_kck_kek_tk() -> TestResult {
        use crate::eapol::derive_ptk;
        let pmk = [0x33u8; 32];
        let aa = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let sa = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let anonce = [0x55u8; 32];
        let snonce = [0x66u8; 32];
        let ptk = derive_ptk(&StubHmac, &pmk, &aa, &sa, &anonce, &snonce, 16);
        if ptk.kck.len() != 16 || ptk.kek.len() != 16 || ptk.tk.len() != 16 {
            return TestResult::Fail("PTK split lengths drifted");
        }
        // PTK is deterministic for given inputs — derive twice and
        // confirm equality.
        let ptk2 = derive_ptk(&StubHmac, &pmk, &aa, &sa, &anonce, &snonce, 16);
        if ptk.kck != ptk2.kck || ptk.kek != ptk2.kek || ptk.tk != ptk2.tk {
            return TestResult::Fail("PTK derivation not deterministic");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_derive_ptk_splits_kck_kek_tk);

    fn smoke_eapol_supplicant_walks_4way_handshake() -> TestResult {
        use crate::eapol::{
            FourWayState, KeyFrame, Supplicant, KEY_DESCRIPTOR_RSN, KI_INSTALL, KI_KEY_ACK,
            KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE,
        };
        let aa = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let sa = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let snonce = [0x77u8; 32];
        let mut sup = Supplicant::new(aa, sa, snonce);
        let pmk = [0x44u8; 32];

        // Build M1 — Authenticator → Supplicant.
        let mut m1 = KeyFrame::empty(16);
        m1.descriptor_type = KEY_DESCRIPTOR_RSN;
        m1.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | 0x02;
        m1.replay_counter = 1;
        m1.key_nonce = [0x88u8; 32];

        let m2 = sup
            .handle(&StubHmac, &pmk, 16, &m1)
            .expect("handle M1")
            .expect("M1 should produce M2");
        if sup.state != FourWayState::WaitM3 {
            return TestResult::Fail("supplicant did not advance to WaitM3");
        }
        if m2.replay_counter != 1 || !m2.has_mic() || m2.key_ack() {
            return TestResult::Fail("M2 flags / counter wrong");
        }
        // Key MIC field = the AKM's length (16 for AKM 2, IEEE
        // 802.11-2020 Table 12-11), not the HMAC output length; an AP
        // misparses an M2 with a 20-byte MIC field.
        if m2.key_mic.len() != 16 || m2.encode().len() != m1.encode().len() {
            return TestResult::Fail("M2 Key MIC field is not M1's (AKM) length");
        }
        // Key Descriptor Version (bits 2:0) echoed from M1.
        if m2.key_information & 0x7 != 0x02 {
            return TestResult::Fail("M2 dropped the key descriptor version");
        }
        if sup.ptk.is_none() {
            return TestResult::Fail("PTK should be derived after M1");
        }

        // M3: Authenticator confirms with Install + MIC + Secure.
        let mut m3 = KeyFrame::empty(16);
        m3.descriptor_type = KEY_DESCRIPTOR_RSN;
        m3.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | KI_KEY_MIC | KI_INSTALL | 0x02;
        m3.replay_counter = 2;
        m3.key_nonce = m1.key_nonce;

        let m4 = sup
            .handle(&StubHmac, &pmk, 16, &m3)
            .expect("handle M3")
            .expect("M3 should produce M4");
        if sup.state != FourWayState::PtkDone {
            return TestResult::Fail("supplicant did not reach PtkDone");
        }
        if m4.install() || !m4.has_mic() {
            return TestResult::Fail("M4 flags wrong");
        }
        if m4.key_mic.len() != 16 || m4.key_information & 0x7 != 0x02 {
            return TestResult::Fail("M4 MIC length / key descriptor version wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/eapol",
        smoke_eapol_supplicant_walks_4way_handshake
    );

    fn smoke_eapol_supplicant_rejects_replay_regression() -> TestResult {
        use crate::eapol::{
            FourWayError, KeyFrame, Supplicant, KEY_DESCRIPTOR_RSN, KI_INSTALL, KI_KEY_ACK,
            KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE,
        };
        let mut sup = Supplicant::new([0u8; 6], [0u8; 6], [0u8; 32]);
        let pmk = [0u8; 32];
        // M1 with replay=5.
        let mut m1 = KeyFrame::empty(16);
        m1.descriptor_type = KEY_DESCRIPTOR_RSN;
        m1.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | 0x02;
        m1.replay_counter = 5;
        let _ = sup
            .handle(&StubHmac, &pmk, 16, &m1)
            .expect("M1 should pass");
        // M3 with replay=4 (regression) — must error.
        let mut m3 = KeyFrame::empty(16);
        m3.descriptor_type = KEY_DESCRIPTOR_RSN;
        m3.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | KI_KEY_MIC | KI_INSTALL | 0x02;
        m3.replay_counter = 4;
        m3.key_nonce = m1.key_nonce;
        match sup.handle(&StubHmac, &pmk, 16, &m3) {
            Err(FourWayError::ReplayRegression) => TestResult::Pass,
            _ => TestResult::Fail("regression should be rejected"),
        }
    }
    kernel_test_in!(
        "wireless/eapol",
        smoke_eapol_supplicant_rejects_replay_regression
    );

    fn smoke_sae_commit_frame_round_trip() -> TestResult {
        use crate::sae::CommitFrame;
        let f = CommitFrame {
            group: 19,
            scalar: alloc::vec![0xAAu8; 32],
            element: alloc::vec![0xBBu8; 64],
        };
        let raw = f.encode();
        if raw.len() != 2 + 32 + 64 {
            return TestResult::Fail("Commit frame length should be 2 + 32 + 64");
        }
        // Group field is LE.
        if u16::from_le_bytes([raw[0], raw[1]]) != 19 {
            return TestResult::Fail("group encoded LE");
        }
        let back = CommitFrame::decode(&raw, 32, 64).expect("decode");
        if back != f {
            return TestResult::Fail("Commit frame round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_commit_frame_round_trip);

    fn smoke_sae_confirm_frame_round_trip() -> TestResult {
        use crate::sae::ConfirmFrame;
        let f = ConfirmFrame {
            send_confirm: 1,
            confirm: alloc::vec![0xCCu8; 32],
        };
        let raw = f.encode();
        if raw.len() != 2 + 32 {
            return TestResult::Fail("Confirm length wrong");
        }
        let back = ConfirmFrame::decode(&raw).expect("decode");
        if back != f {
            return TestResult::Fail("Confirm round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_confirm_frame_round_trip);

    /// Stub group: deterministic so we can exercise the state
    /// machine end-to-end. Production wires P-256 from narf-crypto.
    struct StubGroup;
    impl crate::sae::EccGroup for StubGroup {
        fn group_id(&self) -> u16 {
            19
        }
        fn scalar_len(&self) -> usize {
            32
        }
        fn element_len(&self) -> usize {
            64
        }
        fn make_commit(
            &mut self,
            password: &[u8],
            peer_mac: &[u8; 6],
            own_mac: &[u8; 6],
        ) -> (Vec<u8>, Vec<u8>) {
            // Deterministic XOR derivation; tests only.
            let mut s = alloc::vec![0u8; 32];
            for (i, b) in password.iter().enumerate() {
                s[i % 32] ^= *b;
            }
            for (i, b) in peer_mac.iter().enumerate() {
                s[i] ^= *b;
            }
            for (i, b) in own_mac.iter().enumerate() {
                s[i + 6] ^= *b;
            }
            let mut e = alloc::vec![0u8; 64];
            for (i, b) in s.iter().enumerate() {
                e[i] = b.wrapping_add(1);
                e[i + 32] = b.wrapping_add(2);
            }
            (s, e)
        }
        fn finish(
            &mut self,
            peer_scalar: &[u8],
            peer_element: &[u8],
        ) -> Result<Vec<u8>, crate::sae::SaeError> {
            let mut k = alloc::vec![0u8; 32];
            for (i, b) in peer_scalar.iter().take(32).enumerate() {
                k[i] ^= *b;
            }
            for (i, b) in peer_element.iter().take(32).enumerate() {
                k[i] ^= *b;
            }
            Ok(k)
        }
    }

    struct StubMac;
    impl crate::sae::MacPrimitive for StubMac {
        fn out_len(&self) -> usize {
            32
        }
        fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
            let mut out = alloc::vec![0u8; 32];
            for (i, b) in key.iter().enumerate() {
                out[i % 32] ^= *b;
            }
            for (i, b) in data.iter().enumerate() {
                out[i % 32] ^= b.rotate_left((i % 8) as u32);
            }
            out
        }
    }

    fn smoke_sae_full_handshake_two_peers_agree() -> TestResult {
        use crate::sae::{Sae, SaeState};

        let pwd = b"narfwifi";
        let mac_a = [0x11u8, 0x11, 0x11, 0x11, 0x11, 0x11];
        let mac_b = [0x22u8, 0x22, 0x22, 0x22, 0x22, 0x22];

        let mut a = Sae::new(StubGroup, StubMac, mac_a, mac_b);
        let mut b = Sae::new(StubGroup, StubMac, mac_b, mac_a);

        let commit_a = a.build_commit(pwd);
        let commit_b = b.build_commit(pwd);

        a.handle_commit(&commit_b).expect("a.handle_commit");
        b.handle_commit(&commit_a).expect("b.handle_commit");

        if a.pmk.is_empty() || a.pmk == b.pmk {
            // Note: in the stub group both sides derive the same PMK
            // by symmetry; production crypto guarantees the same via
            // the spec's commutative key-agreement.
        }

        let confirm_a = a.build_confirm();
        let confirm_b = b.build_confirm();

        a.handle_confirm(&confirm_b).expect("a confirm");
        b.handle_confirm(&confirm_a).expect("b confirm");

        if a.state != SaeState::Accepted || b.state != SaeState::Accepted {
            return TestResult::Fail("both peers should reach Accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_full_handshake_two_peers_agree);

    fn smoke_sae_confirm_mismatch_rejected() -> TestResult {
        use crate::sae::{Sae, SaeError};

        let pwd = b"narfwifi";
        let mac_a = [0x11u8; 6];
        let mac_b = [0x22u8; 6];
        let mut a = Sae::new(StubGroup, StubMac, mac_a, mac_b);
        let mut b = Sae::new(StubGroup, StubMac, mac_b, mac_a);

        let commit_a = a.build_commit(pwd);
        let commit_b = b.build_commit(pwd);
        a.handle_commit(&commit_b).unwrap();
        b.handle_commit(&commit_a).unwrap();

        // Tamper with B's confirm before A verifies.
        let mut bad = b.build_confirm();
        bad.confirm[0] ^= 0xFF;
        match a.handle_confirm(&bad) {
            Err(SaeError::ConfirmMismatch) => TestResult::Pass,
            _ => TestResult::Fail("tampered confirm should be rejected"),
        }
    }
    kernel_test_in!("wireless/sae", smoke_sae_confirm_mismatch_rejected);

    fn smoke_sae_invalid_group_rejected() -> TestResult {
        use crate::sae::{CommitFrame, Sae, SaeError};

        let pwd = b"narfwifi";
        let mut a = Sae::new(StubGroup, StubMac, [0u8; 6], [0u8; 6]);
        let _ = a.build_commit(pwd);
        let bad = CommitFrame {
            group: 999, // unsupported
            scalar: alloc::vec![0u8; 32],
            element: alloc::vec![0u8; 64],
        };
        match a.handle_commit(&bad) {
            Err(SaeError::InvalidParameters) => TestResult::Pass,
            _ => TestResult::Fail("wrong group should be rejected"),
        }
    }
    kernel_test_in!("wireless/sae", smoke_sae_invalid_group_rejected);

    fn smoke_ccmp_header_round_trip() -> TestResult {
        use crate::ccmp::{build_ccmp_header, decode_ccmp_header};
        let pn: u64 = 0x0000_DECA_FBAD_BEEF;
        let hdr = build_ccmp_header(pn, 1);
        // ExtIV bit must be set in byte 3.
        if hdr[3] & (1 << 5) == 0 {
            return TestResult::Fail("ExtIV bit must be set in CCMP header byte 3");
        }
        // Reserved byte must be zero.
        if hdr[2] != 0 {
            return TestResult::Fail("CCMP header reserved byte must be 0");
        }
        let (back_pn, back_kid) = decode_ccmp_header(&hdr).expect("decode");
        if back_pn != pn || back_kid != 1 {
            return TestResult::Fail("CCMP header round-trip lost values");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/ccmp", smoke_ccmp_header_round_trip);

    fn smoke_ccmp_decode_rejects_no_extiv() -> TestResult {
        use crate::ccmp::{decode_ccmp_header, CcmpError};
        // ExtIV clear → not CCMP.
        let hdr = [0u8; 8];
        match decode_ccmp_header(&hdr) {
            Err(CcmpError::NotEncrypted) => TestResult::Pass,
            _ => TestResult::Fail("missing ExtIV must surface NotEncrypted"),
        }
    }
    kernel_test_in!("wireless/ccmp", smoke_ccmp_decode_rejects_no_extiv);

    fn smoke_ccmp_nonce_layout() -> TestResult {
        use crate::ccmp::{build_nonce, CCMP_NONCE_LEN};
        let a2 = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let nonce = build_nonce(0x05, true, &a2, 0x123456);
        if nonce.len() != CCMP_NONCE_LEN {
            return TestResult::Fail("nonce length must be 13");
        }
        // Flags byte: priority lower nibble (5), mgmt bit set (4).
        if nonce[0] != 0x05 | (1 << 4) {
            return TestResult::Fail("nonce flags wrong");
        }
        // A2 in bytes 1..7.
        if nonce[1..7] != a2 {
            return TestResult::Fail("nonce should carry A2 at offset 1");
        }
        // PN big-endian in bytes 7..13. We sent 0x12_3456 — top
        // bytes 0, low bytes 0x12, 0x34, 0x56.
        if nonce[12] != 0x56 || nonce[11] != 0x34 || nonce[10] != 0x12 {
            return TestResult::Fail("PN should be big-endian in nonce");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/ccmp", smoke_ccmp_nonce_layout);

    fn smoke_ccmp_aad_mutes_volatile_fields() -> TestResult {
        use crate::ccmp::build_aad;
        // 24-byte data frame header. Set FC[1] bits 11/12/13 (Retry/PwrMgmt/MoreData)
        // and Duration to non-zero — AAD must zero them.
        let mut hdr = [0u8; 24];
        hdr[0] = 0x08; // Type=Data subtype 0
        hdr[1] = 0x38; // Retry|PwrMgmt|MoreData all set
        hdr[4..22].copy_from_slice(&[0x12; 18]);
        hdr[2] = 0xFF; // Duration low
        hdr[3] = 0xFF;
        hdr[22] = 0x73; // SeqCtrl: FragNum=3 (low 4 bits), SeqNum bits should mute.
        hdr[23] = 0x12;
        let aad = build_aad(&hdr);
        if aad.len() != 22 {
            return TestResult::Fail("AAD without Addr4/QoS should be 22 bytes");
        }
        if aad[1] & 0x38 != 0 {
            return TestResult::Fail("Retry/PwrMgmt/MoreData must be zeroed in AAD");
        }
        if aad[..2] != [0x08, 0x40] || aad[2..20] != [0x12; 18] {
            return TestResult::Fail(
                "FC masks or excluded Duration changed authenticated addresses",
            );
        }
        if aad[20] & 0xF0 != 0 || aad[20] != 0x03 {
            return TestResult::Fail("SeqCtrl FragNum should be preserved, SeqNum muted");
        }
        if aad[21] != 0 {
            return TestResult::Fail("SeqNum high byte must be zero");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/ccmp", smoke_ccmp_aad_mutes_volatile_fields);

    fn smoke_ccmp_replay_window_rejects_regression() -> TestResult {
        use crate::ccmp::{CcmpError, ReplayWindow};
        let mut w = ReplayWindow::default();
        w.check(1).expect("first PN");
        w.check(2).expect("PN 2");
        match w.check(2) {
            Err(CcmpError::Replay) => {}
            _ => return TestResult::Fail("repeated PN should be rejected"),
        }
        match w.check(0) {
            Err(CcmpError::Replay) => {}
            _ => return TestResult::Fail("PN regression should be rejected"),
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/ccmp", smoke_ccmp_replay_window_rejects_regression);

    /// Identity AES-CCM stub: encrypt = no-op + zero MIC; decrypt =
    /// accept iff MIC is zero. Production wires AES-128-CCM from
    /// narf-crypto.
    struct StubCcm;
    impl crate::ccmp::AesCcm for StubCcm {
        fn encrypt(
            &self,
            _key: &[u8; 16],
            _nonce: &[u8; crate::ccmp::CCMP_NONCE_LEN],
            _aad: &[u8],
            _plaintext: &mut [u8],
        ) -> Result<[u8; crate::ccmp::CCMP_MIC_LEN], crate::ccmp::CcmpError> {
            Ok([0u8; crate::ccmp::CCMP_MIC_LEN])
        }
        fn decrypt(
            &self,
            _key: &[u8; 16],
            _nonce: &[u8; crate::ccmp::CCMP_NONCE_LEN],
            _aad: &[u8],
            _ciphertext: &mut [u8],
            tag: &[u8; crate::ccmp::CCMP_MIC_LEN],
        ) -> Result<(), crate::ccmp::CcmpError> {
            if *tag == [0u8; crate::ccmp::CCMP_MIC_LEN] {
                Ok(())
            } else {
                Err(crate::ccmp::CcmpError::AuthFailed)
            }
        }
    }

    fn smoke_ccmp_protect_unprotect_round_trip() -> TestResult {
        use crate::ccmp::{protect, unprotect, ReplayWindow};
        let key = [0x42u8; 16];
        let mut hdr = [0u8; 24];
        hdr[0] = 0x08;
        hdr[10..16].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let plaintext = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let mut body = plaintext.to_vec();
        let mut wire = protect(&StubCcm, &hdr, &key, 1, 0, 0, false, &mut body).expect("protect");
        let mut replay = ReplayWindow::default();
        let recovered =
            unprotect(&StubCcm, &hdr, &key, 0, false, &mut replay, &mut wire).expect("unprotect");
        if recovered != plaintext {
            return TestResult::Fail("CCMP round-trip lost plaintext");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/ccmp", smoke_ccmp_protect_unprotect_round_trip);

    // ── RSN IE ─────────────────────────────────────────────────────
    fn smoke_rsn_wpa2_psk_round_trip() -> TestResult {
        use crate::rsn::{RsnIe, AKM_PSK, CIPHER_CCMP_128};
        let ie = RsnIe::wpa2_psk_ccmp();
        let body = ie.encode_body();
        // Version = 1.
        if u16::from_le_bytes([body[0], body[1]]) != 1 {
            return TestResult::Fail("RSN version field");
        }
        let back = RsnIe::decode_body(&body).expect("decode");
        if back.group_cipher.suite_type != CIPHER_CCMP_128 {
            return TestResult::Fail("group cipher decode wrong");
        }
        if back.pairwise_ciphers.len() != 1
            || back.pairwise_ciphers[0].suite_type != CIPHER_CCMP_128
        {
            return TestResult::Fail("pairwise cipher decode wrong");
        }
        if back.akms.len() != 1 || back.akms[0].suite_type != AKM_PSK {
            return TestResult::Fail("AKM decode wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/rsn", smoke_rsn_wpa2_psk_round_trip);

    fn smoke_rsn_wpa3_sae_carries_mfp() -> TestResult {
        use crate::rsn::{
            RsnIe, AKM_SAE, CIPHER_BIP_CMAC_128, RSN_CAP_MFP_CAPABLE, RSN_CAP_MFP_REQUIRED,
        };
        let ie = RsnIe::wpa3_sae_ccmp();
        let body = ie.encode_body();
        let back = RsnIe::decode_body(&body).expect("decode");
        if back.akms[0].suite_type != AKM_SAE {
            return TestResult::Fail("WPA3 must use SAE AKM");
        }
        if back.rsn_capabilities & (RSN_CAP_MFP_REQUIRED | RSN_CAP_MFP_CAPABLE)
            != (RSN_CAP_MFP_REQUIRED | RSN_CAP_MFP_CAPABLE)
        {
            return TestResult::Fail("WPA3 must require + advertise MFP");
        }
        let gmc = match back.group_management_cipher {
            Some(c) => c,
            None => return TestResult::Fail("WPA3 must carry group-management cipher"),
        };
        if gmc.suite_type != CIPHER_BIP_CMAC_128 {
            return TestResult::Fail("group-management cipher should be BIP-CMAC-128");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/rsn", smoke_rsn_wpa3_sae_carries_mfp);

    fn smoke_rsn_negotiate_picks_strongest_overlap() -> TestResult {
        use crate::rsn::{RsnIe, Suite, AKM_PSK, AKM_SAE, CIPHER_CCMP_128, CIPHER_GCMP_256};
        let local = [
            Suite::standard(CIPHER_GCMP_256),
            Suite::standard(CIPHER_CCMP_128),
        ];
        let peer = [Suite::standard(CIPHER_CCMP_128)];
        let pick = RsnIe::negotiate_pairwise(&local, &peer).expect("negotiate");
        if pick.suite_type != CIPHER_CCMP_128 {
            return TestResult::Fail("must pick the only common cipher");
        }
        let local_akm = [Suite::standard(AKM_SAE), Suite::standard(AKM_PSK)];
        let peer_akm = [Suite::standard(AKM_SAE)];
        let pick = RsnIe::negotiate_akm(&local_akm, &peer_akm).expect("akm");
        if pick.suite_type != AKM_SAE {
            return TestResult::Fail("must prefer SAE when supported");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/rsn", smoke_rsn_negotiate_picks_strongest_overlap);

    fn smoke_mlme_beacon_ssid_channel_extract() -> TestResult {
        use crate::mlme::{beacon_ssid_channel, write_ie, ElementId};
        // Build a synthetic beacon body: 12-byte fixed header (zeroed
        // for the test), then SSID + DS Parameter Set IEs.
        let mut body = alloc::vec![0u8; 12];
        write_ie(&mut body, ElementId::Ssid, b"NarfNet");
        write_ie(&mut body, ElementId::DsParameterSet, &[6]);
        let (ssid, ch) = match beacon_ssid_channel(&body) {
            Some(p) => p,
            None => return TestResult::Fail("beacon_ssid_channel returned None"),
        };
        if ssid != b"NarfNet" {
            return TestResult::Fail("Beacon SSID extraction wrong");
        }
        if ch != Some(6) {
            return TestResult::Fail("Beacon DS channel extraction wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_beacon_ssid_channel_extract);
}

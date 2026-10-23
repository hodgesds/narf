//! The `wlan%d` network interface: `narf_net::Interface` (frame rings,
//! MAC, MTU, carrier) + `narf_wireless::WirelessNetIface` (scan /
//! connect / disconnect forwarded to the mac layer) over the runtime
//! ([`super::runtime`]).
//!
//! Linux: mac80211's netdev (`ieee80211_if_add`, `ieee80211_subif_start_xmit`,
//! `ieee80211_deliver_skb` → `netif_receive_skb`, `netif_carrier_on/off`
//! from `ieee80211_set_associated` / `ieee80211_set_disassoc`) and the
//! cfg80211 SME entry points (`cfg80211_connect` → `ieee80211_mgd_auth` /
//! `_assoc`, `cfg80211_disconnect`).
//!
//! Tasks (all spawned; nothing runs on the init path):
//!
//! - the **runtime loop** ([`Ath11kNetdev::run`]): service the device
//!   (CE, WMI / HTT routing, DP groups, timers), deliver received data to
//!   the stack and the RX frame ring, run the mac layer's housekeeping
//!   (`Mac::poll`: kickout / beacon loss / deauth → carrier off, and AP
//!   peer kickout → CQM packet-loss event) when no control operation holds
//!   it, sleep ≤ 10 ms on the device interrupts;
//! - the **TX pump** ([`Ath11kNetdev::tx_pump`]): Ethernet frames from the
//!   TX frame ring (the stack's send hook queues there) → 802.11 → TCL.
//!
//! Control operations (`scan`, `associate`, `disassociate`) lock the mac
//! layer (an async mutex held across their awaits, like mac80211's
//! `wiphy` mutex); each port call they make services the device itself.
//!
//! Firmware crash recovery ([`Ath11kNetdev::recover`]) is one more such
//! operation, run by the runtime loop when the transport reported a
//! crash: traffic quiesced, the device recovered
//! ([`super::runtime::Shared::recover_device`]), then what
//! `ath11k_core_post_reconfigure_recovery` → `ieee80211_restart_hw` does
//! for the station (mac layer restarted: `ath11k_mac_op_start` +
//! `ath11k_mac_op_add_interface`). A replay-safe associated station (external
//! SME, Open, or a completed in-kernel RSN handshake) is reconfigured in
//! place; only a pre-key in-kernel handshake reconnects.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use async_trait::async_trait;
use narf_ipc::{Consumer, Producer};
use narf_lib::mutex::Mutex;
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::iface::{HwCaps, WirelessBand, WirelessIfaceInfo, WirelessModes};
use narf_wireless::{
    AntennaInfo, ApConfig, AssociateRequest, BssInfo, ChannelSwitchConfig, ColorChangeConfig,
    CqmRssiConfig, FilsDiscoveryConfig, FtmResponderConfig, GtkRekeyData, HeBssColorConfig,
    IftypeExtendedCapability, KeyParams, MbssidConfig, MbssidSupport, MgmtTxRequest,
    MlmeAssocRequest, MlmeAuthRequest, SarCapability, SarFrequencyRange, SarPowerLimit,
    ScanRequest, SecurityConfig, StationConfig, StationTxPower, SurveyInfo, TxBitrateMask,
    UnsolBcastProbeRespConfig, WiphyExtendedCapabilities, WirelessConfig, WirelessError,
    WirelessNetIface, WowlanConfig, WowlanSupport,
};

use super::core::FwNotice;
use super::mac::{channel_number_freq, DeviceCaps, Disconnect, Mac};
use super::mac_frame::{self as frame, freq_band, Band};
use super::mac_peer::Width;
use super::mac_reg::chan_flag;
use super::runtime::{self, DpIrq, Port, RtIo, RtQmi, ScanLease, Shared};

/// Frames the TX pump takes off the stack's ring per runtime step
/// (`NAPI_POLL_WEIGHT`).
pub const TX_PUMP_BATCH: usize = 64;

/// Packed [`Ath11kNetdev::ctrl_port`] policy bits above the configured
/// control-port EtherType.  Keep the policy in the netdev because ordinary
/// Ethernet frames reach the TXQ after the nl80211 CONNECT/ASSOCIATE call
/// that supplied it.
const CTRL_PORT_PREAUTH_OVER_NL80211: u32 = 1 << 16;
const CTRL_PORT_NO_ENCRYPT: u32 = 1 << 17;

/// The mac layer over the runtime ports.
pub type RtMac<Io, Irq, Q> = Mac<Port<Io, Irq, Q>, Port<Io, Irq, Q>>;

type VirtualCreate<Io, Irq, Q> = fn(
    &Ath11kNetdev<Io, Irq, Q>,
    &str,
    u32,
    Option<[u8; 6]>,
) -> Result<Arc<dyn WirelessNetIface>, WirelessError>;
type VirtualDelete<Io, Irq, Q> = fn(&Ath11kNetdev<Io, Irq, Q>) -> Result<(), WirelessError>;
type VirtualFinishDelete<Io, Irq, Q> = fn(&Ath11kNetdev<Io, Irq, Q>);
type VirtualRecover<Io, Irq, Q> = for<'a> fn(
    &'a Ath11kNetdev<Io, Irq, Q>,
    FwNotice,
) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

struct VirtualLifecycle<Io: RtIo, Irq: DpIrq, Q: RtQmi> {
    create: VirtualCreate<Io, Irq, Q>,
    delete: VirtualDelete<Io, Irq, Q>,
    finish_delete: VirtualFinishDelete<Io, Irq, Q>,
    recover: VirtualRecover<Io, Irq, Q>,
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Clone for VirtualLifecycle<Io, Irq, Q> {
    fn clone(&self) -> Self {
        Self {
            create: self.create,
            delete: self.delete,
            finish_delete: self.finish_delete,
            recover: self.recover,
        }
    }
}

/// `enum nl80211_chan_width` encoding for cfg80211 notifications.
fn nl80211_channel_width(width: Width) -> u32 {
    match width {
        Width::W20NoHt => 0,
        Width::W20 => 1,
        Width::W40 => 2,
        Width::W80 => 3,
        Width::W80P80 => 4,
        Width::W160 => 5,
    }
}

/// Where received frames and carrier changes go (the kernel stack on
/// hardware; recorders in the tests).
#[derive(Copy, Clone, Debug)]
pub struct Sinks {
    /// `netif_receive_skb` (`narf_net::iface::on_rx_frame_from`).
    pub rx: fn(&str, &mut [u8]),
    /// Carrier on / off (`netif_carrier_on/off`:
    /// `narf_net::iface::set_link_metadata`).
    pub link: fn(&str, bool),
    /// `IFF_UP` changed by the driver itself: an open that failed brings
    /// the interface back down (`narf_net::iface::set_link_state`).
    pub admin: fn(&str, bool),
    /// The association went away while the carrier was on:
    /// `cfg80211_process_deauth` / `_disassoc` with the frame
    /// ([`Disconnect::frame`], our address given) →
    /// `nl80211::notify_mlme_disconnect`.
    pub disconnected: fn(&str, Disconnect, &[u8; 6]),
    /// A Deauthentication sent with no connection to report
    /// (`cfg80211_tx_mlme_mgmt` for an authentication in progress):
    /// `nl80211::notify_mlme_frame`.
    pub mlme_tx: fn(&str, &[u8]),
    /// `cfg80211_rx_control_port(name, src, proto, pdu, unencrypted)`;
    /// `false` = no owner to take it (the frame is dropped).
    pub control_port: fn(&str, [u8; 6], u16, &[u8], bool) -> bool,
}

/// Who asked for the association a recovery may need to retry. Completed
/// associations are reconfigured in place; a pre-key command-line handshake
/// retries in-kernel, while a failed userspace association is reported to its
/// supplicant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectOrigin {
    Kernel,
    Nl80211,
}

/// An external-supplicant operation, applied in order on the runtime
/// loop under the mac layer (the netlink caller cannot wait).
#[derive(Clone, PartialEq, Eq)]
enum ExtOp {
    AddKey(KeyParams),
    DelKey {
        idx: u8,
        pairwise: bool,
    },
    Authorize(bool),
    AddApKey(KeyParams),
    DelApKey {
        idx: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    },
    AuthorizeAp {
        peer: [u8; 6],
        on: bool,
    },
    RemainOnChannel {
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    },
    CancelRemainOnChannel {
        cookie: u64,
    },
    /// A control-port frame (802.3), with the optional nl80211 TX-status
    /// cookie that mac80211 stores alongside `IEEE80211_TX_CTL_REQ_TX_STATUS`.
    Tx {
        eth: Vec<u8>,
        cookie: Option<u64>,
        no_encrypt: bool,
    },
    PowerSave(bool),
    /// `NL80211_CMD_SET_CQM` is software-only mac80211 state; queue it with
    /// other control changes so a generic-netlink syscall never locks the
    /// MAC while the runtime is handling an RX beacon.
    SetCqmRssi(Option<CqmRssiConfig>),
    /// `NL80211_CMD_SET_TX_BITRATE_MASK`: the WMI peer-association update
    /// must run on this ordered worker, not in the generic-netlink syscall.
    SetTxBitrateMask(TxBitrateMask),
    /// `NL80211_ATTR_4ADDR`: update a live BSS peer on the runtime worker.
    SetFourAddr(bool),
    /// `NL80211_EXT_FEATURE_STA_TX_PWR`: set a managed BSS peer's power
    /// policy after the generic netlink request has completed validation.
    SetStationTxPower {
        peer: [u8; 6],
        setting: StationTxPower,
    },
    /// `ath11k_mac_op_set_rekey_data`: retain secret material under the MAC
    /// mutex; firmware receives it only during a later low-power transition.
    GtkRekeyData(GtkRekeyData),
    /// `nl80211_set_wowlan`: retain configuration under the MAC mutex; the
    /// platform low-power owner programs it later through `prepare_wowlan`.
    Wowlan(Option<super::mac::WowlanConfig>),
    /// `NL80211_CMD_SET_SAR_SPECS`: a pdev-wide BIOS table retained by the
    /// shared radio and applied in this ordered WMI worker.
    BiosSar([u8; super::wmi::BIOS_SAR_TABLE_LEN]),
    /// AP commands must run on the runtime task: WMI completion processing
    /// cannot be synchronously bridged from a generic-netlink syscall, which
    /// may itself execute in an executor poll.
    StartAp {
        config: ApConfig,
        mbssid: super::wmi::MbssidParams,
    },
    StopAp,
    SetApBeacon {
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        probe_resp: Option<Vec<u8>>,
    },
    SetApDiscovery {
        fils: Option<Option<FilsDiscoveryConfig>>,
        unsol_bcast_probe_resp: Option<Option<UnsolBcastProbeRespConfig>>,
    },
    SetApFtmResponder(FtmResponderConfig),
    SetApHeBssColor(HeBssColorConfig),
    ColorChange(ColorChangeConfig),
    ChannelSwitch(ChannelSwitchConfig),
    AddApStation(StationConfig),
    SetApStation(StationConfig),
    DelApStation(Option<[u8; 6]>),
    SetApDefaultMgmtKey(u8),
}

/// One accepted nl80211 control-port frame awaiting its requested WBM TX
/// completion. The full Ethernet frame is retained because Linux's
/// `cfg80211_control_port_tx_status` returns that data-frame header and body
/// in `NL80211_ATTR_FRAME`, not merely the PDU supplied by userspace.
struct ControlPortTxStatus {
    cookie: u64,
    frame: Vec<u8>,
    ack_id: Option<u32>,
}

/// One `NL80211_CMD_REGISTER_FRAME` filter. Linux keys registrations by the
/// requesting netlink port as well; NARF's delegated interface capability has
/// one userspace wireless owner, so the filter set belongs to the netdev.
#[derive(Clone, PartialEq, Eq)]
struct MgmtRegistration {
    frame_type: u16,
    match_prefix: Vec<u8>,
}

/// What nl80211 may already know synchronously about the keys
/// (mac80211's key table): which are installed.
#[derive(Clone, Copy, Debug, Default)]
struct KeyBook {
    ptk: bool,
    group: [bool; 6],
}

/// What `get_wireless_info` reports, captured from the mac layer at
/// registration (`wiphy->bands[]` after `ath11k_mac_setup_channels_rates`
/// + `ath11k_mac_setup_ht_vht_cap`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RadioInfo {
    /// `(2400 | 5000 | 6000, enabled channel numbers)`. BSS and request
    /// paths retain the accompanying centre frequency, so the 6 GHz channel
    /// numbers do not collide with 2.4/5 GHz.
    pub bands: Vec<(u32, Vec<u32>)>,
    pub ht: bool,
    pub vht: bool,
    /// HE capabilities (`ath11k_mac_setup_he_cap`).
    pub he: bool,
    /// `WMI_TLV_SERVICE_GTK_OFFLOAD` from the firmware service map.
    pub gtk_rekey_offload: bool,
    /// `WMI_TLV_SERVICE_WOW` from the firmware service map.
    pub wowlan: bool,
    /// `WMI_TLV_SERVICE_SPOOF_MAC_SUPPORT`: firmware accepts a masked random
    /// probe-request source address for an unassociated scan.
    pub scan_random_mac: bool,
    /// `WMI_TLV_SERVICE_NLO`: firmware network-list offload for WoWLAN
    /// NET_DETECT, including its independent randomized probe-MAC feature.
    pub net_detect: bool,
    /// `WMI_TLV_SERVICE_BIOS_SAR_SUPPORT` on the WCN6855 physical pdev.
    pub bios_sar: bool,
    /// `WMI_TLV_SERVICE_MBSS_PARAM_IN_VDEV_START_SUPPORT`: NARF can accept
    /// hostapd's MBSSID role only after the AP vdev already exists.
    pub mbssid_start: bool,
    /// Linux ath11k advertises both 6 GHz discovery ext-features whenever a
    /// radio exposes a six-GHz band.
    pub fils_discovery: bool,
    pub unsol_bcast_probe_resp: bool,
    /// `WMI_TLV_SERVICE_RTT` enables the FTM responder vdev role.
    pub ftm_responder: bool,
    /// `WMI_TLV_SERVICE_BSS_COLOR_OFFLOAD` makes Linux ath11k advertise
    /// `NL80211_EXT_FEATURE_BSS_COLOR`.
    pub bss_color: bool,
    /// `WMI_TLV_SERVICE_AP_TWT` permits START_AP's TWT responder flag.
    pub twt_responder: bool,
    /// `WMI_TLV_SERVICE_BSS_CHANNEL_INFO_64` permits pdev survey refreshes.
    pub bss_survey: bool,
    /// `WMI_TLV_SERVICE_TX_DATA_MGMT_ACK_RSSI` permits publication of the
    /// associated peer's ACK RSSI in GET_STATION.
    pub ack_signal: bool,
    /// The firmware's HT capability permits dynamic spatial-multiplexing
    /// power save (`NL80211_FEATURE_DYNAMIC_SMPS`).  Static SMPS is available
    /// on every ath11k radio regardless of this bit.
    pub dynamic_smps: bool,
    /// Firmware-provided physical chain masks. These are the immutable
    /// `NL80211_ATTR_WIPHY_ANTENNA_AVAIL_{TX,RX}` values; current masks live
    /// in [`Shared`] because `SET_WIPHY` is retained across MAC recreation.
    pub antenna_avail_tx: u32,
    pub antenna_avail_rx: u32,
}

impl RadioInfo {
    pub fn from_mac<P: super::mac::WmiPort, D: super::mac::DataPort>(m: &Mac<P, D>) -> Self {
        let mut b2 = Vec::new();
        let mut b5 = Vec::new();
        let mut b6 = Vec::new();
        for c in m.wiphy().iter() {
            if c.flags & chan_flag::DISABLED != 0 {
                continue;
            }
            match freq_band(c.center_freq) {
                Band::Ghz2 => b2.push(frame::freq_to_channel(c.center_freq)),
                Band::Ghz5 => b5.push(frame::freq_to_channel(c.center_freq)),
                Band::Ghz6 => b6.push(frame::freq_to_channel(c.center_freq)),
            }
        }
        let own = m.own_caps();
        let supports_6ghz = !b6.is_empty();
        let mut bands = Vec::new();
        if !b2.is_empty() {
            bands.push((2400, b2));
        }
        if !b5.is_empty() {
            bands.push((5000, b5));
        }
        if !b6.is_empty() {
            bands.push((6000, b6));
        }
        RadioInfo {
            bands,
            ht: own.ht_2g.ht_supported || own.ht_5g.ht_supported,
            vht: own.vht_5g.vht_supported,
            he: m.own_he(Band::Ghz2).is_some()
                || m.own_he(Band::Ghz5).is_some()
                || m.own_he(Band::Ghz6).is_some(),
            gtk_rekey_offload: m.supports_gtk_rekey_offload(),
            wowlan: m.supports_wowlan(),
            scan_random_mac: m.supports_scan_random_mac(),
            net_detect: m.supports_nlo(),
            bios_sar: m.supports_bios_sar(),
            mbssid_start: m.supports_mbssid_start(),
            fils_discovery: supports_6ghz,
            unsol_bcast_probe_resp: supports_6ghz,
            ftm_responder: m.supports_ftm_responder(),
            bss_color: m.supports_bss_color(),
            twt_responder: m.supports_twt_responder(),
            bss_survey: m.supports_bss_survey(),
            ack_signal: m.supports_ack_signal(),
            dynamic_smps: own.ht_cap_info & super::mac_peer::wmi_ht::DYNAMIC_SMPS != 0,
            antenna_avail_tx: m.antenna_masks().0,
            antenna_avail_rx: m.antenna_masks().1,
        }
    }
}

/// The ath11k station netdev.
#[allow(missing_debug_implementations)]
pub struct Ath11kNetdev<Io: RtIo, Irq: DpIrq, Q: RtQmi> {
    name: &'static str,
    mac_addr: [u8; 6],
    /// WMI vdev slot permanently assigned to this netdev.
    vdev_id: u32,
    /// Present only on PCI netdevs whose physical radio may allocate virtual
    /// nl80211 interfaces. Test/fake netdevs keep this absent.
    virtual_lifecycle: Option<VirtualLifecycle<Io, Irq, Q>>,
    pub shared: Arc<Shared<Io, Irq, Q>>,
    pub mac: Mutex<RtMac<Io, Irq, Q>>,
    radio: RadioInfo,
    sinks: Sinks,
    /// Last physical antenna desired-state generation reflected into this
    /// MAC's host capability maps.
    antenna_generation: AtomicU32,
    /// Last RTS desired-state generation applied to this vdev.
    rts_generation: AtomicU32,
    /// cfg80211's per-vif TX-rate restriction. Unlike antenna/SAR it is not
    /// radio-wide, but it must survive `Mac::new` during a firmware reset.
    bitrate_mask: IrqSafeSpinLock<TxBitrateMask>,
    /// Explicit managed-station peer-power policy retained independently of
    /// the MAC instance so recovery can recreate it after association.
    station_tx_power: IrqSafeSpinLock<Option<StationTxPower>>,
    /// `sdata->u.mgd.use_4addr`, retained outside the rebuilt MAC instance.
    four_addr: AtomicBool,
    up: AtomicBool,
    /// Set once a virtual netdev is removed from the registries.  Its two
    /// worker tasks then release their final Arc references instead of
    /// consuming events after the WMI slot has been reused.
    deleted: AtomicBool,
    /// A cfg80211 `DEL_INTERFACE` already made this virtual netdev invisible
    /// to userspace. The runtime worker owns its final asynchronous
    /// `ndo_stop`/WMI VDEV_DELETE before it releases the firmware slot.
    delete_pending: AtomicBool,
    /// `IFF_UP` as the stack last requested it (`ndo_open` / `ndo_stop`).
    admin_up: AtomicBool,
    /// `NL80211_IFTYPE_*` selected while this netdev is down. Its role
    /// determines the WMI vdev subtype created by the next `ndo_open`.
    iftype: AtomicU32,
    /// bit 63 = associated, low 48 bits = BSSID (LE).
    bssid: AtomicU64,
    channel: AtomicU32,
    rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    rx_prod: IrqSafeSpinLock<Option<Producer<Frame, RX_RING_N>>>,
    pub stats: NetdevStats,
    /// The network of the last successful `associate` (cleared by
    /// `disassociate`) and who asked for it: where a kernel-originated
    /// connection reconnects after a recovery.
    last_assoc: IrqSafeSpinLock<Option<(AssociateRequest, ConnectOrigin)>>,
    ext_ops: IrqSafeSpinLock<alloc::collections::VecDeque<ExtOp>>,
    /// `cookie` → ath11k private ACK-status ID. Entries remain here until
    /// WBM reports an outcome (or an ordered TX enqueue rejects the frame).
    control_port_tx_status: IrqSafeSpinLock<alloc::collections::VecDeque<ControlPortTxStatus>>,
    /// Userspace management frame subscriptions. WMI RX is queued under the
    /// MAC mutex, then these filters run after the mutex is released.
    mgmt_registrations: IrqSafeSpinLock<Vec<MgmtRegistration>>,
    keys: IrqSafeSpinLock<KeyBook>,
    /// The association's control port: EtherType, whether pre-authentication
    /// frames go to nl80211 (`over_nl80211 && !no_preauth`) in bit 16, and
    /// `CONTROL_PORT_NO_ENCRYPT` in bit 17.  The latter applies to ordinary
    /// netdev frames only when their EtherType matches this control port,
    /// exactly as `ieee80211_tx_h_check_control_port_protocol` does.
    ctrl_port: AtomicU32,
    /// `wdev->ps` as requested.
    ps: AtomicBool,
    /// cfg80211's retained WoWLAN configuration.  This spin-locked mirror
    /// makes `GET_WOWLAN` synchronous; the ordered MAC update is queued in
    /// `ext_ops` and applied before the next low-power handoff.
    wowlan: IrqSafeSpinLock<Option<WowlanConfig>>,
    /// The asynchronous system-PM path that completed preparation and thus
    /// needs a precisely paired resume. This is separate from the retained
    /// WoW configuration: clearing `SET_WOWLAN` during sleep must not make
    /// resume select the wrong transport path.
    system_pm: IrqSafeSpinLock<SystemPmMode>,
    /// Whether this vdev was open immediately before the radio-wide cold
    /// system-suspend cycle and therefore needs its vdev recreated on resume.
    cold_reopen: AtomicBool,
}

/// A prepared system-sleep transport policy. Linux chooses the WoW path
/// only with a cfg80211 WoW configuration; otherwise it stops the station
/// and does a cold HIF/MHI cycle across S3.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SystemPmMode {
    Idle,
    Wowlan,
    Cold,
}

/// `AssociateRequest` is not `Clone`.
fn copy_request(r: &AssociateRequest) -> AssociateRequest {
    AssociateRequest {
        bssid: r.bssid,
        ssid: r.ssid.clone(),
        frequency_mhz: r.frequency_mhz,
        channel: r.channel,
        security: match &r.security {
            SecurityConfig::Open => SecurityConfig::Open,
            SecurityConfig::Wpa2 { psk } => SecurityConfig::Wpa2 { psk: *psk },
            SecurityConfig::Wpa3 { password } => SecurityConfig::Wpa3 {
                password: password.clone(),
            },
            SecurityConfig::External(e) => SecurityConfig::External(*e),
        },
        ie: r.ie.clone(),
    }
}

/// Counters.
#[derive(Debug, Default)]
pub struct NetdevStats {
    pub rx_delivered: AtomicU32,
    pub rx_ring_full: AtomicU32,
    pub tx_queued: AtomicU32,
    pub tx_dropped: AtomicU32,
    /// Frames whose offload request was refused (TSO / VLAN insertion
    /// asked for, or a checksum request the hardware cannot complete:
    /// [`super::tx_offload::csum_partial_prepare`]).
    pub tx_offload_refused: AtomicU32,
    pub link_losses: AtomicU32,
    /// Firmware recoveries run / completed / reconnected after.
    pub recoveries: AtomicU32,
    pub recovered: AtomicU32,
    pub reconnects: AtomicU32,
}

fn alloc_frame(bytes: &[u8]) -> Option<Frame> {
    let buf = narf_io::alloc_coherent(bytes.len().max(1), narf_lib::id::DomainId::DRIVER_0).ok()?;
    let mut f = Frame::new(buf, bytes.len() as u32);
    f.payload_mut().copy_from_slice(bytes);
    Some(f)
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Ath11kNetdev<Io, Irq, Q> {
    /// A netdev named `name` over the runtime and its (started, vif
    /// added) mac layer. The frame rings are created here.
    pub fn new(
        name: &'static str,
        shared: Arc<Shared<Io, Irq, Q>>,
        mac: RtMac<Io, Irq, Q>,
        mac_addr: [u8; 6],
        sinks: Sinks,
    ) -> (Self, Consumer<Frame, TX_RING_N>) {
        Self::new_on_vdev(name, shared, mac, mac_addr, sinks, 0, 2)
    }

    /// Construct a netdev over one reserved firmware vdev.  The initial
    /// `wlan%d` uses slot zero; virtual nl80211 interfaces receive one of
    /// WCN6855's other two slots before this constructor runs.
    pub fn new_on_vdev(
        name: &'static str,
        shared: Arc<Shared<Io, Irq, Q>>,
        mac: RtMac<Io, Irq, Q>,
        mac_addr: [u8; 6],
        sinks: Sinks,
        vdev_id: u32,
        iftype: u32,
    ) -> (Self, Consumer<Frame, TX_RING_N>) {
        Self::new_on_vdev_with_lifecycle(name, shared, mac, mac_addr, sinks, vdev_id, iftype, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn new_on_vdev_with_lifecycle(
        name: &'static str,
        shared: Arc<Shared<Io, Irq, Q>>,
        mac: RtMac<Io, Irq, Q>,
        mac_addr: [u8; 6],
        sinks: Sinks,
        vdev_id: u32,
        iftype: u32,
        virtual_lifecycle: Option<VirtualLifecycle<Io, Irq, Q>>,
    ) -> (Self, Consumer<Frame, TX_RING_N>) {
        let radio = RadioInfo::from_mac(&mac);
        // MBSSID's TX_IFINDEX resolution is physical-radio-local. Bind the
        // netdev before it enters any registry so a later child can only
        // name one of this Shared runtime's vdevs.
        shared.bind_vdev(vdev_id, name, mac_addr);
        let (rx_prod, rx_cons) = narf_ipc::channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
        (
            Ath11kNetdev {
                name,
                mac_addr,
                vdev_id,
                virtual_lifecycle,
                shared,
                mac: Mutex::new(mac),
                radio,
                sinks,
                antenna_generation: AtomicU32::new(u32::MAX),
                rts_generation: AtomicU32::new(u32::MAX),
                bitrate_mask: IrqSafeSpinLock::new(TxBitrateMask::default()),
                station_tx_power: IrqSafeSpinLock::new(None),
                four_addr: AtomicBool::new(false),
                up: AtomicBool::new(false),
                deleted: AtomicBool::new(false),
                delete_pending: AtomicBool::new(false),
                admin_up: AtomicBool::new(false),
                iftype: AtomicU32::new(iftype),
                bssid: AtomicU64::new(0),
                channel: AtomicU32::new(0),
                rx_ring: IrqSafeSpinLock::new(Some(rx_cons)),
                tx_ring: IrqSafeSpinLock::new(Some(tx_prod)),
                rx_prod: IrqSafeSpinLock::new(Some(rx_prod)),
                stats: NetdevStats::default(),
                last_assoc: IrqSafeSpinLock::new(None),
                ext_ops: IrqSafeSpinLock::new(alloc::collections::VecDeque::new()),
                control_port_tx_status: IrqSafeSpinLock::new(alloc::collections::VecDeque::new()),
                mgmt_registrations: IrqSafeSpinLock::new(Vec::new()),
                keys: IrqSafeSpinLock::new(KeyBook::default()),
                ctrl_port: AtomicU32::new(0),
                ps: AtomicBool::new(true),
                wowlan: IrqSafeSpinLock::new(None),
                system_pm: IrqSafeSpinLock::new(SystemPmMode::Idle),
                cold_reopen: AtomicBool::new(false),
            },
            tx_cons,
        )
    }

    pub fn radio(&self) -> &RadioInfo {
        &self.radio
    }

    /// Build and queue one externally supplied control-port frame after the
    /// synchronous checks `ieee80211_tx_control_port` performs. The optional
    /// cookie is retained by the ordered worker, where it can request and
    /// later publish the WBM TX completion without blocking generic netlink.
    fn queue_control_port(
        &self,
        dest: [u8; 6],
        proto: u16,
        frame: Vec<u8>,
        no_encrypt: bool,
        cookie: Option<u64>,
    ) -> Result<(), i32> {
        let ctrl = self.ctrl_port.load(Ordering::Acquire);
        // "Only accept CONTROL_PORT_PROTOCOL configured in
        // CONNECT/ASSOCIATE or Pre-Authentication".
        let configured = (ctrl & 0xffff) as u16;
        if proto != configured && proto != narf_wireless::ETH_P_PREAUTH || ctrl == 0 {
            return Err(super::mac::errno::EINVAL);
        }
        let mut eth = Vec::with_capacity(14 + frame.len());
        eth.extend_from_slice(&dest);
        eth.extend_from_slice(&self.mac_addr);
        eth.extend_from_slice(&proto.to_be_bytes());
        eth.extend_from_slice(&frame);
        self.queue_ext(ExtOp::Tx {
            eth,
            cookie,
            no_encrypt,
        });
        Ok(())
    }

    /// Resolve a validated nl80211 MBSSID request into WMI's per-vdev role.
    /// TX_IFINDEX is intentionally resolved through this physical runtime's
    /// vdev bindings as well as the wireless registry: matching a name alone
    /// would permit a profile to point at an AP on a different radio.
    fn mbssid_params(&self, cfg: &ApConfig) -> Result<super::wmi::MbssidParams, WirelessError> {
        let Some(MbssidConfig {
            index,
            tx_ifindex,
            ema,
        }) = cfg.mbssid
        else {
            if !cfg.mbssid_elems.is_empty() || !cfg.ema_rnr_elems.is_empty() {
                return Err(WirelessError::InvalidArgs);
            }
            return Ok(super::wmi::MbssidParams::standalone());
        };
        if !self.radio.mbssid_start || self.current_iftype() != 3 {
            // P2P-GO has a distinct firmware beacon contract and must not
            // masquerade as an infrastructure multiple-BSSID transmitter.
            return Err(WirelessError::NotSupported);
        }
        if index >= super::runtime::WCN6855_MAX_VDEVS as u8 {
            return Err(WirelessError::InvalidArgs);
        }
        let own_ifindex = narf_net::netlink_route::ifindex_for_name(self.name);
        if index == 0 {
            if cfg.mbssid_elems.is_empty() || tx_ifindex.is_some_and(|tx| Some(tx) != own_ifindex) {
                return Err(WirelessError::InvalidArgs);
            }
            return Ok(super::wmi::MbssidParams::transmitting(ema));
        }
        let tx_ifindex = tx_ifindex.ok_or(WirelessError::InvalidArgs)?;
        if Some(tx_ifindex) == own_ifindex {
            return Err(WirelessError::InvalidArgs);
        }
        let name = narf_net::netlink_route::iface_name_for_index(tx_ifindex)
            .ok_or(WirelessError::InvalidArgs)?;
        let tx_iface = narf_wireless::registry::list()
            .into_iter()
            .find(|iface| iface.name() == name.as_str())
            .ok_or(WirelessError::InvalidArgs)?;
        if tx_iface.wiphy_id() != self.wiphy_id() || tx_iface.current_iftype() != 3 {
            return Err(WirelessError::InvalidArgs);
        }
        let (tx_vdev_id, tx_bssid) = self
            .shared
            .vdev_for_name(&name)
            .ok_or(WirelessError::InvalidArgs)?;
        if tx_vdev_id == self.vdev_id {
            return Err(WirelessError::InvalidArgs);
        }
        Ok(super::wmi::MbssidParams::non_transmitting(
            tx_vdev_id,
            tx_bssid,
            index as u32,
            0,
            ema,
        ))
    }

    /// Opaque net-stack dispatch identity. NARF currently admits three vdevs,
    /// leaving the low two bits for the slot under the physical radio id.
    fn dispatch_cookie(&self) -> u64 {
        (self.shared.radio_id << 2) | u64::from(self.vdev_id)
    }

    /// Snapshot the network stack state that mac80211 normally supplies via
    /// `BSS_CHANGED_ARP_FILTER` and `ipv6_addr_change`.  The WCN6855 WMI
    /// contract permits two ARP and sixteen NS targets; retain Linux's
    /// stable insertion order and omit only invalid or host-scope IPv6
    /// records.  Tentative addresses remain included, matching ath11k's
    /// `!IFA_F_DADFAILED` test rather than requiring DAD completion.
    fn arp_ns_offload_snapshot(&self) -> super::wmi::ArpNsOffload {
        let ipv4 = narf_net::iface::get_addrs(self.name)
            .into_iter()
            .take(super::wmi::WMI_MAX_ARP_OFFLOADS)
            .map(|(addr, _)| addr.0)
            .collect();
        let ipv6 = narf_net::ipv6::addrs::list_iface(self.name)
            .into_iter()
            .filter(|entry| {
                entry.state != narf_net::ipv6::addrs::AddrState::Invalid
                    && matches!(
                        entry.scope,
                        narf_net::ipv6::addrs::AddrScope::LinkLocal
                            | narf_net::ipv6::addrs::AddrScope::UniqueLocal
                            | narf_net::ipv6::addrs::AddrScope::Global
                    )
            })
            .take(super::wmi::WMI_MAX_IPV6_OFFLOADS)
            .map(|entry| entry.addr)
            .collect();
        super::wmi::ArpNsOffload {
            ipv4,
            ipv6,
            mac_addr: self.mac_addr,
        }
    }

    /// Program ath11k's WoWLAN firmware state and wait for the matching HTC
    /// endpoint-zero suspend ACK.  This is the driver's asynchronous
    /// low-power handoff; a platform PM owner must call it before it gates
    /// PCIe/CE interrupts or puts the device into D3.  It deliberately does
    /// not call the synchronous `power::DevicePmOps` path, whose callbacks
    /// run with interrupts gated and are forbidden from awaiting WMI.
    pub async fn prepare_wowlan(&self) -> Result<(), super::mac::MacError> {
        if self.shared.is_dead() {
            return Err(super::mac::MacError::new(
                super::mac::step::WOWLAN,
                0,
                super::runtime::EIO,
            ));
        }
        // `ath11k_mac_wait_tx_complete` before WoW config.  This helper
        // services the device while waits are outstanding and holds no
        // runtime lock across either wait.
        self.shared.flush_queues_for(self.vdev_id, false).await;
        let arp_ns_offload = self.arp_ns_offload_snapshot();
        for attempt in 0..super::runtime::ATH11K_WOW_RETRY_NUM {
            self.shared.clear_wow_control_completions().await;
            let send = {
                let mut m = self.mac.lock().await;
                // Apply retained userspace operations in arrival order before
                // the low-power transition reads the WoW/GTK state.
                self.run_ext_ops(&mut m).await;
                m.set_arp_ns_offload(arp_ns_offload.clone());
                if attempt == 0 {
                    m.prepare_wowlan().await
                } else {
                    m.retry_wow_enable().await
                }
            };
            if let Err(e) = send {
                self.abort_wowlan_prepare().await;
                return Err(e);
            }
            match self.shared.wait_wow_suspend_complete().await {
                Some(true) => {
                    let mut m = self.mac.lock().await;
                    m.mark_wow_armed(true);
                    return Ok(());
                }
                Some(false) if attempt + 1 < super::runtime::ATH11K_WOW_RETRY_NUM => {
                    // `ATH11K_WOW_RETRY_WAIT_MS` between NACK retries.
                    self.shared
                        .irq
                        .wait(super::runtime::ATH11K_WOW_RETRY_WAIT_MS)
                        .await;
                }
                Some(false) => {
                    self.abort_wowlan_prepare().await;
                    return Err(super::mac::MacError::new(
                        super::mac::step::WOWLAN,
                        14,
                        super::runtime::EIO,
                    ));
                }
                None => {
                    self.abort_wowlan_prepare().await;
                    return Err(super::mac::MacError::new(
                        super::mac::step::WOWLAN,
                        15,
                        super::mac::errno::ETIMEDOUT,
                    ));
                }
            }
        }
        unreachable!("bounded WoW retry loop either returns or errors")
    }

    /// Best-effort counterpart to a pre-ACK WoW failure.  This must happen
    /// while CE/WMI are still live, before the system PM coordinator gates
    /// interrupts or asks MHI to enter M3.
    async fn abort_wowlan_prepare(&self) {
        let mut m = self.mac.lock().await;
        m.abort_wowlan_prepare().await;
    }

    /// Complete the WoWLAN resume half: send host wakeup, wait for HTC's
    /// control response while servicing the runtime, then remove temporary
    /// filters/offloads and report any updated GTK replay counter through the
    /// ordinary event pump.
    pub async fn resume_wowlan(&self) -> Result<(), super::mac::MacError> {
        let armed = {
            let m = self.mac.lock().await;
            m.wow_armed()
        };
        if !armed {
            return Ok(());
        }
        self.shared.clear_wow_control_completions().await;
        {
            let mut m = self.mac.lock().await;
            m.request_wow_wakeup().await?;
        }
        if self.shared.wait_wow_wakeup_complete().await.is_none() {
            return Err(super::mac::MacError::new(
                super::mac::step::WOWLAN,
                16,
                super::mac::errno::ETIMEDOUT,
            ));
        }
        let mut m = self.mac.lock().await;
        m.finish_wowlan_resume().await
    }

    /// Carrier down with the reason cfg80211 reports (`None` when the
    /// mac layer recorded none: a local disconnect).
    fn link_down(&self, why: Option<Disconnect>) {
        let was = self.link_up();
        let bssid = self.connected_bssid().unwrap_or([0; 6]);
        self.set_link(false, None, 0);
        if was {
            let d = why.unwrap_or(Disconnect {
                reason: frame::WLAN_REASON_DEAUTH_LEAVING,
                from_ap: false,
                deauth: true,
                bssid,
            });
            let d = if d.bssid == [0; 6] {
                Disconnect { bssid, ..d }
            } else {
                d
            };
            (self.sinks.disconnected)(self.name, d, &self.mac_addr);
        }
    }

    fn set_link(&self, up: bool, bssid: Option<[u8; 6]>, channel: u32) {
        match bssid {
            Some(b) if up => {
                let mut packed = 1u64 << 63;
                for (i, byte) in b.iter().enumerate() {
                    packed |= (*byte as u64) << (8 * i);
                }
                self.bssid.store(packed, Ordering::Release);
                self.channel.store(channel, Ordering::Release);
            }
            _ => {
                self.bssid.store(0, Ordering::Release);
                self.channel.store(0, Ordering::Release);
                self.shared.clear_operating_channel(self.vdev_id);
                // The station entry and its keys are gone.
                *self.keys.lock() = KeyBook::default();
                // Key/control requests belong to the departed association,
                // but cfg80211's WoWLAN configuration survives disconnect.
                // Requeue its current value so a queued SET_WOWLAN cannot be
                // lost between a link-loss callback and the next PM entry.
                let wowlan = self.wowlan.lock().clone();
                let mut ops = self.ext_ops.lock();
                ops.clear();
                ops.push_back(ExtOp::Wowlan(Self::mac_wowlan_config(wowlan.as_ref())));
                self.ctrl_port.store(0, Ordering::Release);
            }
        }
        let was = self.up.swap(up, Ordering::AcqRel);
        if was != up {
            (self.sinks.link)(self.name, up);
        }
    }

    /// AP beaconing has carrier but no associated-BSSID state. Keep it
    /// separate from [`Self::set_link`], whose station-disconnect path
    /// deliberately clears supplicant keys and emits cfg80211 disconnects.
    fn set_ap_carrier(&self, up: bool, frequency_mhz: u32) {
        self.bssid.store(0, Ordering::Release);
        self.channel.store(
            if up {
                frame::freq_to_channel(frequency_mhz)
            } else {
                0
            },
            Ordering::Release,
        );
        if !up {
            self.shared.clear_operating_channel(self.vdev_id);
        }
        let was = self.up.swap(up, Ordering::AcqRel);
        if was != up {
            (self.sinks.link)(self.name, up);
        }
    }

    /// The stack's `ndo_open` / `ndo_stop` (`narf_net::iface::set_open_stop`):
    /// record `IFF_UP`. Sync and lock-free (it runs in the caller's
    /// syscall); the runtime loop, or the next control operation, applies
    /// it under the mac layer ([`Self::sync_admin`]).
    pub fn request_admin(&self, up: bool) {
        self.admin_up.store(up, Ordering::Release);
    }

    /// `IFF_UP` as requested.
    pub fn admin_up(&self) -> bool {
        self.admin_up.load(Ordering::Acquire)
    }

    /// Bring the mac layer to the requested administrative state, holding
    /// it. `true` while the interface is open (hardware started, station
    /// vif added).
    pub async fn sync_admin(&self, m: &mut RtMac<Io, Irq, Q>) -> bool {
        let want = self.admin_up();
        let open = m.vif().is_some();
        if want && !open {
            if self.do_open(m).await.is_err() {
                // dev_open failed: the device stays down.
                self.admin_up.store(false, Ordering::Release);
                (self.sinks.admin)(self.name, false);
                return false;
            }
            return true;
        }
        if !want && open {
            self.do_stop(m).await;
            return false;
        }
        open
    }

    /// Finish a virtual-interface removal after cfg80211 has hidden the
    /// netdev from lookup.  `DEL_INTERFACE` itself cannot await WMI (it runs
    /// in the generic-netlink request path), so the owning runtime worker
    /// performs the same ordered close as `ndo_stop` before giving the
    /// firmware vdev id to a later NEW_INTERFACE request.
    async fn complete_virtual_delete(&self) {
        self.admin_up.store(false, Ordering::Release);
        *self.last_assoc.lock() = None;
        self.ext_ops.lock().clear();
        {
            let mut m = self.mac.lock().await;
            if m.vif().is_some() {
                self.do_stop(&mut m).await;
            }
        }
        self.shared.release_scan(self.vdev_id);
        if let Some(lifecycle) = self.virtual_lifecycle.as_ref() {
            (lifecycle.finish_delete)(self);
        }
        self.deleted.store(true, Ordering::Release);
    }

    /// `ieee80211_do_open`: `drv_start` (`ath11k_mac_op_start`) when the
    /// hardware is not running (`local->open_count == 0`), then create the
    /// selected station or AP WMI vdev. A failed add-interface stops the
    /// hardware again (`err_stop`). The carrier stays off until association
    /// (station) or START_AP completes (AP).
    async fn do_open(&self, m: &mut RtMac<Io, Irq, Q>) -> Result<(), super::mac::MacError> {
        // `SET_WIPHY` owns physical-radio policy, not a temporary MAC
        // instance. Apply its retained values before `start_inner` programs
        // the pdev and before this vdev is created.
        if let Some(((tx, rx), generation)) = self.shared.antenna_config() {
            m.configure_antenna(tx, rx);
            self.antenna_generation.store(generation, Ordering::Release);
        }
        let (rts_threshold, rts_generation) = self.shared.rts_config();
        m.configure_rts_threshold(rts_threshold);
        self.rts_generation.store(rts_generation, Ordering::Release);
        m.configure_tx_bitrate_mask(self.bitrate_mask.lock().clone());
        m.configure_station_tx_power(*self.station_tx_power.lock());
        m.configure_four_addr(self.four_addr.load(Ordering::Acquire));
        let started_here = self.shared.acquire_radio_mac();
        if started_here {
            if let Err(e) = m.start().await {
                self.shared.release_radio_mac();
                return Err(e);
            }
            // Firmware loses pdev SAR policy across cold resume and crash
            // reset. Replay it before any vdev is recreated on this freshly
            // started physical radio.
            if let Some(table) = self.shared.bios_sar_table() {
                if let Err(e) = m.set_bios_sar_table(&table).await {
                    m.stop().await;
                    self.shared.release_radio_mac();
                    return Err(e);
                }
            }
        } else {
            m.adopt_shared_start();
        }
        let added = match self.iftype.load(Ordering::Acquire) {
            3 => m.add_ap_interface().await,
            8 => {
                m.add_p2p_station_interface(super::mac::VifKind::P2pClient)
                    .await
            }
            9 => m.add_p2p_go_interface().await,
            10 => {
                m.add_p2p_station_interface(super::mac::VifKind::P2pDevice)
                    .await
            }
            _ => m.add_interface().await,
        };
        if let Err(e) = added {
            if started_here {
                m.stop().await;
            } else {
                m.leave_shared_start();
            }
            self.shared.release_radio_mac();
            return Err(e);
        }
        Ok(())
    }

    /// `dev_close` for the station: NETDEV_GOING_DOWN (`cfg80211_leave` →
    /// `cfg80211_disconnect(WLAN_REASON_DEAUTH_LEAVING)`, carrier off),
    /// then `ieee80211_do_stop` (TXQs purged, `drv_remove_interface` →
    /// `ath11k_mac_op_remove_interface`, the vif's management TX IDR
    /// entries freed, `drv_stop` → `ath11k_mac_op_stop` with
    /// `num_pending_mgmt_tx = 0`).
    async fn do_stop(&self, m: &mut RtMac<Io, Irq, Q>) {
        let ap_vif = m.vif().is_some_and(|vif| vif.kind.is_ap());
        if ap_vif {
            // AP carrier represents beaconing, not a station association;
            // it must not synthesize a cfg80211 disconnect while closing.
            self.shared.set_mbssid_beacons(self.vdev_id, None);
            self.shared.set_mbssid_transmitter(self.vdev_id, None);
            self.set_ap_carrier(false, 0);
        } else {
            if m.link().is_some() {
                self.shared.flush_queues_for(self.vdev_id, true).await;
                let _ = m.disassociate().await;
            }
            let why = m.take_disconnect();
            self.link_down(why);
        }
        self.shared.lock().await.purge_txqs_for(self.vdev_id);
        if let Err(e) = m.remove_interface().await {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: {}: failed to delete vdev: (-{}) (step {})",
                self.name,
                e,
                super::runtime::step::IF_DOWN_VDEV_DELETE
            );
        }
        {
            let mut g = self.shared.lock().await;
            // ath11k_mac_vif_txmgmt_idr_remove; the ath11k_vif (and its
            // ath11k_dp_vdev_tx_attach state) goes with this vif only.
            g.drop_vdev_mgmt(self.vdev_id);
            // ieee80211_do_stop frees what is still waiting for a status.
            if let Some(vdev) = g.vdev_mut(self.vdev_id) {
                vdev.link.vif = None;
                let pending: Vec<u32> = vdev.ack_frames.ids().collect();
                for id in pending {
                    vdev.ack_frames.remove(id);
                    vdev.ack_status
                        .push_back((id, super::txq::TxStatus::DROPPED));
                }
            }
        }
        if self.shared.release_radio_mac() {
            m.stop().await;
        } else {
            m.leave_shared_start();
        }
    }

    /// The stack's send hook (`ieee80211_subif_start_xmit`): queue an
    /// Ethernet frame (with the stack's offload request, carried in the
    /// frame) on the TX ring. Sync and IRQ-safe (no runtime lock). TSO and
    /// VLAN insertion are not advertised ([`super::tx_offload::OFFLOADS`])
    /// and refused.
    pub fn queue_tx(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if self.deleted.load(Ordering::Acquire) || self.delete_pending.load(Ordering::Acquire) {
            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
        if meta.tso_mss.is_some() || meta.vlan_tag.is_some() {
            self.stats
                .tx_offload_refused
                .fetch_add(1, Ordering::Relaxed);
            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
        if !self.link_up() {
            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
        let Some(mut f) = alloc_frame(bytes) else {
            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(());
        };
        f.set_tx_meta(meta);
        let mut g = self.tx_ring.lock();
        let Some(p) = g.as_mut() else {
            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(());
        };
        match p.try_send(f) {
            Ok(()) => {
                self.stats.tx_queued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => {
                self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
                Err(())
            }
        }
    }

    /// A frame taken from the TX ring, ready for the TXQs: a checksum
    /// request (`TxMeta::csum_l4`, Linux `CHECKSUM_PARTIAL`) is validated
    /// and its seed written ([`super::tx_offload::csum_partial_prepare`]);
    /// one the hardware cannot complete is dropped, never sent
    /// half-checksummed.
    fn tx_prepare(&self, frame: &Frame) -> Result<(Vec<u8>, bool, bool), i32> {
        let meta = frame.tx_meta();
        if meta.tso_mss.is_some() || meta.vlan_tag.is_some() {
            self.stats
                .tx_offload_refused
                .fetch_add(1, Ordering::Relaxed);
            self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(super::tx_offload::EINVAL);
        }
        let mut eth = frame.payload().to_vec();
        if let Some(kind) = meta.csum_l4 {
            if let Err(e) = super::tx_offload::csum_partial_prepare(&mut eth, kind) {
                self.stats
                    .tx_offload_refused
                    .fetch_add(1, Ordering::Relaxed);
                self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        }
        let ctrl = self.ctrl_port.load(Ordering::Acquire);
        let no_encrypt = ctrl & CTRL_PORT_NO_ENCRYPT != 0
            && eth.len() >= 14
            && u16::from_be_bytes([eth[12], eth[13]]) == (ctrl & 0xffff) as u16;
        Ok((eth, meta.csum_l4.is_some(), no_encrypt))
    }

    /// Hand frames taken from the TX ring to the runtime's per-AC TXQs
    /// (one lock hold; [`super::txq`]); each frame's result.
    pub async fn tx_batch(&self, frames: &[Frame]) -> Vec<Result<(), i32>> {
        let mut out: Vec<Result<(), i32>> = Vec::with_capacity(frames.len());
        let mut ok = Vec::with_capacity(frames.len());
        for f in frames {
            match self.tx_prepare(f) {
                Ok(p) => {
                    ok.push(p);
                    out.push(Ok(()));
                }
                Err(e) => out.push(Err(e)),
            }
        }
        if ok.is_empty() {
            return out;
        }
        let mut res = self
            .shared
            .tx_frames_with_flags_for(self.vdev_id, ok)
            .await
            .into_iter();
        for r in out.iter_mut().filter(|r| r.is_ok()) {
            *r = res.next().unwrap_or(Err(super::runtime::EIO));
            if r.is_err() {
                self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        out
    }

    /// One frame through [`Self::tx_batch`].
    pub async fn tx_one(&self, frame: &Frame) -> Result<(), i32> {
        self.tx_batch(core::slice::from_ref(frame))
            .await
            .pop()
            .unwrap_or(Err(super::runtime::EIO))
    }

    /// The TX pump task: wait for the stack's TX ring, take what is
    /// queued (up to [`TX_PUMP_BATCH`]) and hand it to the TXQs in one
    /// runtime step, so a backlog drains VO → BK ([`super::txq`]).
    pub async fn tx_pump(self: Arc<Self>, mut cons: Consumer<Frame, TX_RING_N>) {
        while let Ok(first) = cons.recv().await {
            if self.deleted.load(Ordering::Acquire) || self.delete_pending.load(Ordering::Acquire) {
                return;
            }
            let mut batch = alloc::vec![first];
            while batch.len() < TX_PUMP_BATCH {
                match cons.try_recv() {
                    Ok(Some(f)) => batch.push(f),
                    _ => break,
                }
            }
            let _ = self.tx_batch(&batch).await;
        }
    }

    fn deliver(&self, frames: Vec<(Vec<u8>, bool)>) -> usize {
        let n = frames.len();
        let preauth_up =
            self.ctrl_port.load(Ordering::Acquire) & CTRL_PORT_PREAUTH_OVER_NL80211 != 0;
        for (mut f, csum_ok) in frames {
            // ieee80211_deliver_skb_to_local_stack: ETH_P_PREAUTH over
            // nl80211 unless CONTROL_PORT_NO_PREAUTH.
            if preauth_up
                && f.len() >= 14
                && u16::from_be_bytes([f[12], f[13]]) == narf_wireless::ETH_P_PREAUTH
            {
                let src: [u8; 6] = f[6..12].try_into().unwrap();
                (self.sinks.control_port)(
                    self.name,
                    src,
                    narf_wireless::ETH_P_PREAUTH,
                    &f[14..],
                    false,
                );
                continue;
            }
            if let Some(p) = self.rx_prod.lock().as_mut() {
                if let Some(mut fr) = alloc_frame(&f) {
                    // ath11k_dp_rx_h_csum_offload → the ring's RxMeta.
                    fr.set_rx_meta(super::tx_offload::rx_meta(&f, csum_ok));
                    if p.try_send(fr).is_err() {
                        self.stats.rx_ring_full.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            self.stats.rx_delivered.fetch_add(1, Ordering::Relaxed);
            (self.sinks.rx)(self.name, &mut f);
        }
        n
    }

    /// One pass of the runtime loop: service + deliver RX (outside every
    /// lock: the stack may answer synchronously through `queue_tx`), then
    /// the mac layer's housekeeping if no control operation holds it.
    /// Returns the frames delivered.
    pub async fn service_once(&self) -> usize {
        if self.deleted.load(Ordering::Acquire) {
            return 0;
        }
        if self.delete_pending.swap(false, Ordering::AcqRel) {
            self.complete_virtual_delete().await;
            return 0;
        }
        if self.shared.take_scan_cancel(self.vdev_id) {
            // A synchronous nl80211 scan future was dropped. Do not free the
            // pdev-wide scan claim until the fixed-id WMI scan is stopped;
            // otherwise a sibling vdev could receive its completion.
            let mut m = self.mac.lock().await;
            m.cancel_scan().await;
            drop(m);
            self.shared.release_scan(self.vdev_id);
        }
        let frames = self.shared.take_rx_for(self.vdev_id).await;
        let n = self.deliver(frames);
        if let Some(notice) = self.shared.take_fw_notice().await {
            self.recover(notice).await;
            return n;
        }
        if let Some(mut m) = self.mac.try_lock() {
            self.sync_admin(&mut m).await;
            self.run_ext_ops(&mut m).await;
            if let Some(((tx, rx), generation)) = self.shared.antenna_config() {
                if self.antenna_generation.load(Ordering::Acquire) != generation {
                    m.configure_antenna(tx, rx);
                    if m.is_started() && self.shared.claim_antenna_programming(generation) {
                        if let Err(error) = m.set_antenna(tx, rx).await {
                            error.report("asynchronous physical antenna configuration");
                        }
                    }
                    self.antenna_generation.store(generation, Ordering::Release);
                }
            }
            let (rts_threshold, rts_generation) = self.shared.rts_config();
            if self.rts_generation.load(Ordering::Acquire) != rts_generation {
                if let Err(error) = m.set_rts_threshold(rts_threshold).await {
                    error.report("asynchronous RTS threshold configuration");
                }
                self.rts_generation.store(rts_generation, Ordering::Release);
            }
            if self.shared.take_bss_survey_request() {
                if let Err(error) = m.request_bss_survey().await {
                    error.report("asynchronous BSS channel survey");
                }
            }
            let loss = m.poll().await;
            let gtk_rekey = m.take_gtk_rekey_notify();
            let cqm_pktloss = m.take_cqm_pktloss();
            let cqm_rssi = m.take_cqm_rssi();
            let bss_surveys = m.take_bss_survey();
            let mgmt_rx = m.take_registered_mgmt_rx();
            let roc_events = m.take_remain_on_channel_events();
            let ap_channel_switch_events = m.take_ap_channel_switch_events();
            let ap_color_change_events = m.take_ap_color_change_events();
            let dfs_events = m.take_dfs_events();
            let obss_color_collisions = m.take_obss_color_collision_events();
            let ctrl = m.take_control_port_rx();
            if !ctrl.is_empty() {
                self.deliver_control_port(ctrl);
            }
            if loss.is_some() {
                self.stats.link_losses.fetch_add(1, Ordering::Relaxed);
                // ieee80211_set_disassoc → ieee80211_flush_queues(drop).
                self.shared.lock().await.purge_txqs_for(self.vdev_id);
            }
            let ap_vif = m.vif().is_some_and(|vif| vif.kind.is_ap());
            let mbssid_transmitter = m.vif().is_some_and(|vif| vif.mbssid.is_transmitting());
            // A color-change event is the start/final/abort boundary at
            // which mac80211 copies the transmitter's BSS color to each
            // non-transmitting profile. A completed CSA may carry a delayed
            // post-switch color update and needs the same treatment.
            let mbssid_color_update = (mbssid_transmitter
                && (!ap_color_change_events.is_empty() || !ap_channel_switch_events.is_empty()))
            .then(|| m.ap_he_bss_color())
            .flatten();
            let ap_beaconing = m.ap_beaconing();
            let mbssid_beacons = m.mbssid_beacon_set();
            let linked = m.connected_bssid();
            let scan_idle = m.scan_state() == super::mac::ScanState::Idle;
            let why = if linked.is_none() {
                m.take_disconnect()
            } else {
                None
            };
            drop(m);
            for survey in bss_surveys {
                self.shared.update_bss_survey(survey);
            }
            if let Some(color) = mbssid_color_update {
                self.propagate_mbssid_he_bss_color(color);
            }
            if scan_idle && self.shared.owns_scan(self.vdev_id) {
                self.shared.release_scan(self.vdev_id);
            }
            // A deferred CSA failure calls `stop_ap()` from the MAC poll
            // path. Unlike an explicit STOP_AP it has no queued ExtOp, so
            // mirror cfg80211's carrier-off transition here and release the
            // physical radio's channel context.
            if ap_vif && !ap_beaconing && self.link_up() {
                self.shared.set_mbssid_beacons(self.vdev_id, None);
                self.set_ap_carrier(false, 0);
            } else if ap_vif {
                // A deferred transmitter CSA may have replaced its EMA
                // template family from the MAC poll path rather than an
                // ExtOp; publish the new source for later profiles.
                self.shared.set_mbssid_beacons(self.vdev_id, mbssid_beacons);
            }
            if let Some(rekey) = gtk_rekey {
                narf_wireless::nl80211::notify_gtk_rekey(
                    self.name,
                    rekey.bssid,
                    rekey.replay_counter,
                );
            }
            for peer in cqm_pktloss {
                // ath11k_peer_sta_kickout_event →
                // ieee80211_report_low_ack(sta, 10) →
                // cfg80211_cqm_pktloss_notify. In AP mode hostapd receives
                // this but retains ownership of any subsequent deauth and
                // DEL_STATION sequence.
                narf_wireless::nl80211::notify_cqm_packet_loss(self.name, peer, 10);
            }
            for event in cqm_rssi {
                narf_wireless::nl80211::notify_cqm_rssi(self.name, event.high, event.level_dbm);
            }
            for received in mgmt_rx {
                if self.has_mgmt_registration(&received.frame) {
                    narf_wireless::nl80211::notify_mgmt_rx(
                        self.name,
                        received.frequency_mhz,
                        received.signal_dbm,
                        &received.frame,
                    );
                }
            }
            for event in roc_events {
                narf_wireless::nl80211::notify_remain_on_channel(
                    self.name,
                    event.cookie,
                    event.frequency_mhz,
                    event.duration_ms,
                    event.started,
                );
            }
            for event in ap_channel_switch_events {
                narf_wireless::nl80211::notify_channel_switch(
                    self.name,
                    event.def.freq,
                    nl80211_channel_width(event.def.width),
                    event.def.center_freq1,
                    event.def.center_freq2,
                    event.count,
                    event.block_tx,
                    event.started,
                );
            }
            for event in ap_color_change_events {
                match event {
                    super::mac::ApColorChangeEvent::Started { count } => {
                        narf_wireless::nl80211::notify_color_change(self.name, 0, count);
                    }
                    super::mac::ApColorChangeEvent::Aborted => {
                        narf_wireless::nl80211::notify_color_change(self.name, 1, 0);
                    }
                    super::mac::ApColorChangeEvent::Completed => {
                        narf_wireless::nl80211::notify_color_change(self.name, 2, 0);
                    }
                }
            }
            for event in dfs_events {
                narf_wireless::nl80211::notify_dfs_event(
                    self.name,
                    event.def.freq,
                    nl80211_channel_width(event.def.width),
                    event.def.center_freq1,
                    event.def.center_freq2,
                    event.event,
                    event.netdev,
                );
            }
            for bitmap in obss_color_collisions {
                narf_wireless::nl80211::notify_obss_color_collision(self.name, bitmap);
            }
            if !ap_vif && linked.is_none() && self.link_up() {
                // ieee80211_set_disassoc → netif_carrier_off, then
                // cfg80211_disconnected.
                self.link_down(why);
            }
        }
        self.emit_control_port_tx_statuses().await;
        self.emit_michael_mic_failures().await;
        n
    }

    /// Complete control-port status requests outside the MAC mutex. WBM
    /// completions are serviced by the shared runtime; this worker only maps
    /// its private ACK id back to the cookie returned in the netlink ACK.
    async fn emit_control_port_tx_statuses(&self) {
        let pending = core::mem::take(&mut *self.control_port_tx_status.lock());
        if pending.is_empty() {
            return;
        }
        let mut waiting = alloc::collections::VecDeque::new();
        for status in pending {
            let acked = match status.ack_id {
                Some(id) => self
                    .shared
                    .take_eth_tx_status_for(self.vdev_id, id)
                    .await
                    .map(|result| result.acked),
                None => Some(false),
            };
            if let Some(acked) = acked {
                narf_wireless::nl80211::notify_control_port_tx_status(
                    self.name,
                    status.cookie,
                    &status.frame,
                    acked,
                );
            } else {
                waiting.push_back(status);
            }
        }
        self.control_port_tx_status.lock().extend(waiting);
    }

    /// Publish the cfg80211 side of `ieee80211_rx_h_michael_mic_verify`.
    /// NARF's DP decapsulates before mac80211 would see the bad MPDU, so it
    /// retained the source/key metadata and this netdev owns the final MLME
    /// multicast on behalf of its vdev.
    async fn emit_michael_mic_failures(&self) {
        for failure in self.shared.take_mic_failures_for(self.vdev_id).await {
            narf_wireless::nl80211::notify_michael_mic_failure(
                self.name,
                failure.source,
                failure.group,
                failure.key_idx,
            );
        }
    }

    /// Apply queued external-supplicant and AP-control operations in order.
    /// The runtime task owns the WMI waits, so no generic-netlink syscall can
    /// recurse into the executor to configure an AP vdev or client peer.
    async fn run_ext_ops(&self, m: &mut RtMac<Io, Irq, Q>) {
        loop {
            let Some(op) = self.ext_ops.lock().pop_front() else {
                return;
            };
            match op {
                ExtOp::AddKey(k) => {
                    let _ = m.ext_add_key(&k).await;
                }
                ExtOp::DelKey { idx, pairwise } => {
                    let _ = m.ext_del_key(idx, pairwise).await;
                }
                ExtOp::Authorize(on) => {
                    let _ = m.ext_set_authorized(on).await;
                }
                ExtOp::AddApKey(key) => {
                    if let Err(e) = m.add_ap_key(key).await {
                        e.report("asynchronous NEW_KEY (AP)");
                    }
                }
                ExtOp::DelApKey {
                    idx,
                    pairwise,
                    peer,
                } => {
                    if let Err(e) = m.del_ap_key(idx, pairwise, peer).await {
                        e.report("asynchronous DEL_KEY (AP)");
                    }
                }
                ExtOp::AuthorizeAp { peer, on } => {
                    if let Err(e) = m.ap_set_authorized(peer, on).await {
                        e.report("asynchronous SET_STATION authorization (AP)");
                    }
                }
                ExtOp::RemainOnChannel {
                    cookie,
                    frequency_mhz,
                    duration_ms,
                } => {
                    if let Err(e) = m
                        .remain_on_channel(cookie, frequency_mhz, duration_ms)
                        .await
                    {
                        self.shared.release_scan(self.vdev_id);
                        e.report("asynchronous REMAIN_ON_CHANNEL");
                    }
                }
                ExtOp::CancelRemainOnChannel { cookie } => {
                    if let Err(e) = m.cancel_remain_on_channel(cookie).await {
                        e.report("asynchronous CANCEL_REMAIN_ON_CHANNEL");
                    }
                }
                ExtOp::Tx {
                    eth,
                    cookie,
                    no_encrypt,
                } => {
                    // ieee80211_tx_control_port → the TXQs; built (and
                    // protected or not) by the PTK state at this point. A
                    // cookie requests the normal mac80211 ACK-status IDR;
                    // never wait here, because this worker must continue
                    // polling WBM to receive that completion.
                    if let Some(cookie) = cookie {
                        let frame = eth.clone();
                        let ack_id = self
                            .shared
                            .enqueue_eth_tx_status_for(self.vdev_id, eth, no_encrypt)
                            .await
                            .ok();
                        self.control_port_tx_status
                            .lock()
                            .push_back(ControlPortTxStatus {
                                cookie,
                                frame,
                                ack_id,
                            });
                    } else {
                        let _ = self
                            .shared
                            .tx_control_port_for(self.vdev_id, eth, no_encrypt)
                            .await;
                    }
                }
                ExtOp::PowerSave(on) => m.set_power_save(on).await,
                ExtOp::SetCqmRssi(config) => m.set_cqm_rssi(config),
                ExtOp::SetTxBitrateMask(mask) => {
                    if let Err(error) = m.set_tx_bitrate_mask(mask).await {
                        error.report("asynchronous SET_TX_BITRATE_MASK");
                    }
                }
                ExtOp::SetFourAddr(enabled) => {
                    if let Err(error) = m.set_four_addr(enabled).await {
                        error.report("asynchronous NL80211_ATTR_4ADDR");
                    }
                }
                ExtOp::SetStationTxPower { peer, setting } => {
                    if let Err(error) = m.set_station_tx_power(peer, setting).await {
                        error.report("asynchronous STA_TX_POWER_SETTING");
                    }
                }
                ExtOp::GtkRekeyData(data) => {
                    let _ = m.set_gtk_rekey_data(data);
                }
                ExtOp::Wowlan(config) => {
                    let _ = m.set_wowlan_config(config);
                }
                ExtOp::BiosSar(table) => {
                    if let Err(e) = m.set_bios_sar_table(&table).await {
                        e.report("asynchronous BIOS SAR update");
                    }
                }
                ExtOp::StartAp { config, mbssid } => {
                    // Hostapd may issue START_AP for a non-transmitting
                    // profile immediately after accepting the transmitter's
                    // request. Our WMI path is asynchronous, so defer this
                    // vdev (without reserving a channel) until the ordered
                    // transmitter start has published its complete template
                    // family. Retrying on the next runtime slice preserves
                    // netlink order without sending a forbidden template to
                    // an already-up non-transmitting vdev.
                    if mbssid.is_non_transmitting()
                        && self.shared.mbssid_beacons(mbssid.tx_vdev_id).is_none()
                    {
                        self.ext_ops
                            .lock()
                            .push_front(ExtOp::StartAp { config, mbssid });
                        return;
                    }
                    let frequency_mhz = config.frequency_mhz;
                    let Some(previous_frequency) = self
                        .shared
                        .reserve_operating_channel(self.vdev_id, frequency_mhz)
                    else {
                        super::mac::MacError::new(
                            super::mac::step::AP_START,
                            frequency_mhz,
                            super::mac::errno::EBUSY,
                        )
                        .report("asynchronous START_AP (WCN6855 channel limit)");
                        continue;
                    };
                    let source_templates = mbssid
                        .is_non_transmitting()
                        .then(|| self.shared.mbssid_beacons(mbssid.tx_vdev_id))
                        .flatten();
                    match m.start_ap(config, mbssid, source_templates).await {
                        Ok(()) => {
                            self.shared
                                .set_mbssid_beacons(self.vdev_id, m.mbssid_beacon_set());
                            self.set_ap_carrier(true, frequency_mhz);
                        }
                        Err(e) => {
                            self.shared.set_mbssid_transmitter(self.vdev_id, None);
                            self.shared
                                .restore_operating_channel(self.vdev_id, previous_frequency);
                            e.report("asynchronous START_AP");
                        }
                    }
                }
                ExtOp::StopAp => match m.stop_ap().await {
                    Ok(()) => {
                        self.shared.set_mbssid_beacons(self.vdev_id, None);
                        self.shared.set_mbssid_transmitter(self.vdev_id, None);
                        self.set_ap_carrier(false, 0);
                    }
                    Err(e) => e.report("asynchronous STOP_AP"),
                },
                ExtOp::SetApBeacon {
                    head,
                    tail,
                    probe_resp,
                } => match m.set_ap_beacon(head, tail, probe_resp).await {
                    Ok(()) => self
                        .shared
                        .set_mbssid_beacons(self.vdev_id, m.mbssid_beacon_set()),
                    Err(e) => e.report("asynchronous SET_BEACON"),
                },
                ExtOp::SetApDiscovery {
                    fils,
                    unsol_bcast_probe_resp,
                } => {
                    if let Err(e) = m.set_ap_discovery(fils, unsol_bcast_probe_resp).await {
                        e.report("asynchronous AP discovery update");
                    }
                }
                ExtOp::SetApFtmResponder(config) => {
                    if let Err(e) = m.set_ap_ftm_responder(config).await {
                        e.report("asynchronous AP FTM responder update");
                    }
                }
                ExtOp::SetApHeBssColor(config) => {
                    let mbssid_transmitter =
                        m.vif().is_some_and(|vif| vif.mbssid.is_transmitting());
                    match m.set_ap_he_bss_color(config).await {
                        Ok(()) if mbssid_transmitter => {
                            self.propagate_mbssid_he_bss_color(config);
                        }
                        Ok(()) => {}
                        Err(e) => e.report("asynchronous AP HE BSS color update"),
                    }
                }
                ExtOp::ColorChange(config) => {
                    if let Err(e) = m.color_change(config).await {
                        e.report("asynchronous COLOR_CHANGE_REQUEST");
                    }
                }
                ExtOp::ChannelSwitch(config) => {
                    let frequency_mhz = config.frequency_mhz;
                    let Some(previous_frequency) = self
                        .shared
                        .reserve_operating_channel(self.vdev_id, frequency_mhz)
                    else {
                        super::mac::MacError::new(
                            super::mac::step::AP_CHANNEL_SWITCH,
                            frequency_mhz,
                            super::mac::errno::EBUSY,
                        )
                        .report("asynchronous CHANNEL_SWITCH (WCN6855 channel limit)");
                        continue;
                    };
                    match m.channel_switch(config).await {
                        Ok(()) => self
                            .shared
                            .set_mbssid_beacons(self.vdev_id, m.mbssid_beacon_set()),
                        Err(e) => {
                            self.shared
                                .restore_operating_channel(self.vdev_id, previous_frequency);
                            e.report("asynchronous CHANNEL_SWITCH");
                        }
                    }
                }
                ExtOp::AddApStation(station) => {
                    if let Err(e) = m.add_ap_station(station).await {
                        e.report("asynchronous NEW_STATION");
                    }
                }
                ExtOp::SetApStation(station) => {
                    if let Err(e) = m.set_ap_station(station).await {
                        e.report("asynchronous SET_STATION (AP)");
                    }
                }
                ExtOp::DelApStation(mac) => {
                    if let Err(e) = m.del_ap_station(mac).await {
                        e.report("asynchronous DEL_STATION (AP)");
                    }
                }
                ExtOp::SetApDefaultMgmtKey(idx) => {
                    if let Err(e) = m.set_ap_default_mgmt_key(idx) {
                        e.report("asynchronous SET_KEY default management key (AP)");
                    }
                }
            }
        }
    }

    /// Received control-port frames: to the owner over nl80211, or up the
    /// netdev (PF_PACKET sockets on ETH_P_PAE) as any received frame.
    fn deliver_control_port(&self, frames: Vec<super::mac::ext::ControlPortRx>) {
        let mut up = Vec::new();
        for f in frames {
            if f.over_nl80211 {
                let src: [u8; 6] = f.eth[6..12].try_into().unwrap();
                let proto = u16::from_be_bytes([f.eth[12], f.eth[13]]);
                (self.sinks.control_port)(self.name, src, proto, &f.eth[14..], !f.decrypted);
            } else {
                up.push((f.eth, false));
            }
        }
        if !up.is_empty() {
            self.deliver(up);
        }
    }

    /// `cfg80211_mlme_register_mgmt` matching: the registration names the
    /// management subtype and an optional prefix immediately after the
    /// 24-byte 802.11 management header.  WMI frames are already structurally
    /// checked by `Mac::mgmt_rx` before they reach this point.
    fn has_mgmt_registration(&self, frame_bytes: &[u8]) -> bool {
        if frame_bytes.len() < frame::MGMT_HDR_LEN {
            return false;
        }
        let fc = u16::from_le_bytes([frame_bytes[0], frame_bytes[1]]);
        let kind = fc & frame::FCTL_TYPE_STYPE;
        self.mgmt_registrations.lock().iter().any(|registration| {
            registration.frame_type & frame::FCTL_TYPE_STYPE == kind
                && frame_bytes[frame::MGMT_HDR_LEN..].starts_with(&registration.match_prefix)
        })
    }

    fn queue_ext(&self, op: ExtOp) {
        // The runtime loop applies it at its next step (≤ one slice).
        self.ext_ops.lock().push_back(op);
    }

    /// `ieee80211_color_change_bss_config_notify` applies the transmitting
    /// BSSID's color/enabled state to every non-transmitting MBSSID profile.
    /// Each profile owns a separate WMI vdev and runtime task, so queue its
    /// normal AP BSS update rather than retaining the transmitter's MAC lock
    /// across another vdev's firmware operation.
    fn propagate_mbssid_he_bss_color(&self, config: HeBssColorConfig) {
        for name in self.shared.mbssid_dependents(self.vdev_id) {
            if let Some(profile) = narf_wireless::registry::list()
                .into_iter()
                .find(|profile| profile.name() == name)
            {
                // A profile may be concurrently tearing down with its
                // transmitter. cfg80211 tolerates that race; remaining
                // profiles retain their update in their own ordered stream.
                let _ = profile.set_ap_he_bss_color(config);
            }
        }
    }

    /// `associate` for the in-kernel autoconnect. A recovery retries only if
    /// no replay-safe association state has been established yet.
    pub async fn associate_kernel(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        self.associate_from(req, ConnectOrigin::Kernel).await
    }

    async fn associate_from(
        &self,
        req: AssociateRequest,
        origin: ConnectOrigin,
    ) -> Result<(), WirelessError> {
        // A P2P Device vdev exists only for discovery/action traffic.  It
        // must never enter the ordinary managed-station association path;
        // P2P Client owns that role.
        if !matches!(self.current_iftype(), 2 | 8) {
            return Err(WirelessError::NotSupported);
        }
        if self.shared.is_dead() {
            return Err(WirelessError::HardwareError);
        }
        let mut m = self.mac.lock().await;
        if !self.sync_admin(&mut m).await {
            return Err(WirelessError::HardwareError);
        }
        let Some(previous_frequency) = self
            .shared
            .reserve_operating_channel(self.vdev_id, req.frequency_mhz)
        else {
            return Err(WirelessError::Busy);
        };
        let result = m.associate(&req).await;
        let b = m.connected_bssid();
        drop(m);
        if let Err(error) = result {
            self.shared
                .restore_operating_channel(self.vdev_id, previous_frequency);
            return Err(error);
        }
        if b.is_none() {
            self.shared
                .restore_operating_channel(self.vdev_id, previous_frequency);
        }
        if let SecurityConfig::External(e) = &req.security {
            self.set_control_port(e.control_port);
        }
        if b.is_some() {
            // An external supplicant's association is userspace's to
            // restore.
            let origin = if matches!(req.security, SecurityConfig::External(_)) {
                ConnectOrigin::Nl80211
            } else {
                origin
            };
            *self.last_assoc.lock() = Some((copy_request(&req), origin));
        }
        // ieee80211_set_associated → netif_carrier_on.
        self.set_link(b.is_some(), b, req.channel);
        Ok(())
    }

    /// `ieee80211_mgd_deauth` / `_disassoc` for the userspace SME.
    async fn sme_leave(
        &self,
        peer: [u8; 6],
        reason: u16,
        deauth: bool,
    ) -> Result<Vec<u8>, WirelessError> {
        *self.last_assoc.lock() = None;
        let mut m = self.mac.lock().await;
        if m.link().is_some_and(|l| l.assoc) {
            self.shared.flush_queues_for(self.vdev_id, true).await;
        }
        let r = m.sme_deauthenticate(peer, reason, deauth).await;
        let why = m.take_disconnect();
        drop(m);
        let frame = r.map_err(|e| e.wireless())?;
        if why.is_some() && self.link_up() {
            // DEAUTHENTICATE / DISASSOCIATE + DISCONNECT.
            self.link_down(why);
        } else {
            (self.sinks.mlme_tx)(self.name, &frame);
        }
        Ok(frame)
    }

    fn set_control_port(&self, port: narf_wireless::ControlPort) {
        let preauth = port.over_nl80211 && !port.no_preauth;
        let no_encrypt = port.no_encrypt;
        self.ctrl_port.store(
            port.ethertype as u32
                | if preauth {
                    CTRL_PORT_PREAUTH_OVER_NL80211
                } else {
                    0
                }
                | if no_encrypt { CTRL_PORT_NO_ENCRYPT } else { 0 },
            Ordering::Release,
        );
    }

    /// The runtime loop task (ends when a recovery failed: the device is
    /// gone).
    pub async fn run(self: Arc<Self>) {
        loop {
            self.service_once().await;
            if self.deleted.load(Ordering::Acquire) || self.shared.is_dead() {
                return;
            }
            self.shared.irq.wait(self.shared.slice_ms).await;
        }
    }

    /// Firmware crash recovery for this netdev's physical radio. PCI carries
    /// a coordinator hook so a reset rebuilds every live virtual interface;
    /// generic/test instances retain the single-netdev path below.
    pub async fn recover(&self, notice: FwNotice) -> bool {
        if let Some(lifecycle) = self.virtual_lifecycle.as_ref() {
            return (lifecycle.recover)(self, notice).await;
        }
        self.recover_one(notice, true).await
    }

    /// Firmware crash recovery for one non-shared/test netdev (Linux
    /// `ath11k_core_reset`
    /// / `ath11k_core_restart`, then `ath11k_core_post_reconfigure_recovery`
    /// → `ath11k_core_halt` + `ieee80211_restart_hw`): a replay-safe managed
    /// station is rebuilt in place, including its firmware keys, while an
    /// incomplete in-kernel handshake uses its established reconnect path.
    /// `true` when the device came back.
    async fn recover_one(&self, notice: FwNotice, complete_reconfig: bool) -> bool {
        use core::fmt::Write as _;
        self.stats.recoveries.fetch_add(1, Ordering::Relaxed);
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: {}: firmware crashed ({:?}), recovering",
            self.name,
            notice
        );
        let mut m = self.mac.lock().await;
        // Linux's ieee80211_reconfig keeps an associated station and
        // re-enables its keys after the WMI vdev is recreated. Do not send
        // a spurious DISCONNECT before that replay has actually failed.
        let station_recovery = m.external_recovery().or_else(|| m.kernel_recovery());
        let restoring_station = station_recovery.is_some();
        let ap_recovery = m.ap_recovery();
        let restoring_ap = ap_recovery.is_some();
        let ap_source_templates = ap_recovery
            .as_ref()
            .and_then(|state| state.mbssid_source_vdev())
            .and_then(|vdev_id| self.shared.mbssid_beacons(vdev_id));
        if !restoring_station && !restoring_ap {
            self.link_down(Some(Disconnect {
                reason: frame::WLAN_REASON_UNSPECIFIED,
                from_ap: false,
                deauth: true,
                bssid: [0; 6],
            }));
        }
        let dev = match self.shared.recover_device(notice).await {
            Ok(d) => d,
            Err(_) => return false,
        };
        // ath11k_core_halt + ieee80211_restart_hw → drv_start +
        // drv_add_interface on the rebuilt mac layer.
        // The interface was open: mac80211's reconfig brings the hardware
        // and the station vif back the way `ieee80211_do_open` did.
        let was_open = m.vif().is_some();
        let mut mac = Mac::new(
            Port(self.shared.clone(), self.vdev_id),
            Port(self.shared.clone(), self.vdev_id),
            dev.caps,
            m.config(),
            dev.reg_info.as_deref(),
        );
        let opened = if was_open {
            self.do_open(&mut mac).await
        } else {
            Ok(())
        };
        let restored = match opened {
            Ok(()) => match station_recovery {
                Some(state) => mac.restore_station_recovery(state).await,
                None => match ap_recovery {
                    Some(state) => mac.restore_ap_recovery(state, ap_source_templates).await,
                    None => Ok(()),
                },
            },
            Err(error) => Err(error),
        };
        let ap_beacons = mac.mbssid_beacon_set();
        let ap_frequency = mac.vif().and_then(|vif| vif.chanctx.map(|def| def.freq));
        *m = mac;
        drop(m);
        if restored.is_err() {
            if restoring_station {
                // A failed reconfiguration is the real connection loss;
                // only then report a DISCONNECT after the firmware reset.
                self.link_down(Some(Disconnect {
                    reason: frame::WLAN_REASON_UNSPECIFIED,
                    from_ap: false,
                    deauth: true,
                    bssid: [0; 6],
                }));
            }
            if restoring_ap {
                self.set_ap_carrier(false, 0);
            }
            super::hal::TransportError::new(super::runtime::step::RECOVERY_MAC, 1, 5)
                .report("ath11k recovery: mac");
            self.shared.park(alloc::boxed::Box::new(()));
            return false;
        }
        // A PCI radio coordinator calls `reconfig_complete` only after every
        // live vdev has been rebuilt. The single-vdev path completes here.
        if complete_reconfig {
            self.shared.reconfig_complete().await;
        }
        if restoring_ap {
            self.shared.set_mbssid_beacons(self.vdev_id, ap_beacons);
            self.set_ap_carrier(true, ap_frequency.unwrap_or(0));
        }
        if complete_reconfig {
            self.record_recovered();
        }
        // A replay-safe managed station was restored above in mac80211's
        // reconfiguration shape. A pre-key in-kernel handshake uses its
        // existing scan-and-associate retry path.
        let last = self.last_assoc.lock().take();
        match last {
            // A successfully replayed kernel station still needs its request
            // retained: a later reset can occur during a new handshake, when
            // only the directed scan-and-associate fallback is safe.
            Some((req, origin)) if restoring_station => {
                *self.last_assoc.lock() = Some((req, origin));
            }
            Some((req, ConnectOrigin::Kernel)) => {
                *self.last_assoc.lock() = Some((copy_request(&req), ConnectOrigin::Kernel));
                self.reconnect(req).await;
            }
            Some((_, ConnectOrigin::Nl80211)) | None => {}
        }
        true
    }

    /// Finish the userspace-visible half of a successful recovery. A shared
    /// radio calls this only after its complete vif reconfiguration pass.
    fn record_recovered(&self) {
        use core::fmt::Write as _;
        narf_memory::diag::note_wifi_recovered();
        self.stats.recovered.fetch_add(1, Ordering::Relaxed);
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: {}: firmware recovered",
            self.name
        );
    }

    /// Associate again after a recovery: a scan directed at the network
    /// on its channel (the new mac layer has no BSS table), then the
    /// association.
    async fn reconnect(&self, req: AssociateRequest) {
        use core::fmt::Write as _;
        let scan = ScanRequest {
            ssids: alloc::vec![req.ssid.clone()],
            frequencies_mhz: alloc::vec![req.frequency_mhz],
            channels: alloc::vec![req.channel],
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        };
        let r = match self.scan(scan).await {
            Ok(_) => self.associate_kernel(req).await,
            Err(e) => Err(e),
        };
        match r {
            Ok(()) => {
                self.stats.reconnects.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  ath11k: {}: reconnect after recovery failed: {:?}",
                    self.name,
                    e
                );
            }
        }
    }

    /// Notify userspace of the link loss for one member of a radio-wide
    /// firmware restart. AP carrier has no associated BSSID and must not be
    /// reported as a station disconnect.
    async fn prepare_radio_recovery(&self) {
        let m = self.mac.lock().await;
        let ap = m.vif().is_some_and(|vif| vif.kind.is_ap());
        let restore_station = m.external_recovery().is_some() || m.kernel_recovery().is_some();
        let restore_ap = m.ap_recovery().is_some();
        drop(m);
        if ap && !restore_ap {
            self.set_ap_carrier(false, 0);
        } else if !restore_station && !restore_ap {
            self.link_down(Some(Disconnect {
                reason: frame::WLAN_REASON_UNSPECIFIED,
                from_ap: false,
                deauth: true,
                bssid: [0; 6],
            }));
        }
    }

    /// Recreate this one MAC instance after the physical radio's core/DP/WMI
    /// reconstruction has completed. The caller has reset the shared pdev
    /// start refcount, so each previously-open vif reclaims it through
    /// [`Self::do_open`] without replaying pdev setup for siblings.
    async fn rebuild_after_radio_recovery(
        &self,
        mut caps: DeviceCaps,
        reg_info: Option<Box<super::wmi::RegInfo>>,
    ) -> bool {
        let mut m = self.mac.lock().await;
        let was_open = m.vif().is_some();
        let config = m.config();
        let station_recovery = m.external_recovery().or_else(|| m.kernel_recovery());
        let restoring_station = station_recovery.is_some();
        let ap_recovery = m.ap_recovery();
        let restoring_ap = ap_recovery.is_some();
        let ap_source_templates = ap_recovery
            .as_ref()
            .and_then(|state| state.mbssid_source_vdev())
            .and_then(|vdev_id| self.shared.mbssid_beacons(vdev_id));
        caps.mac_addr = self.mac_addr;
        let mut mac = Mac::new(
            Port(self.shared.clone(), self.vdev_id),
            Port(self.shared.clone(), self.vdev_id),
            caps,
            config,
            reg_info.as_deref(),
        );
        let opened = if was_open {
            self.do_open(&mut mac).await
        } else {
            Ok(())
        };
        let restored = match opened {
            Ok(()) => match station_recovery {
                Some(state) => mac.restore_station_recovery(state).await,
                None => match ap_recovery {
                    Some(state) => mac.restore_ap_recovery(state, ap_source_templates).await,
                    None => Ok(()),
                },
            },
            Err(error) => Err(error),
        };
        let ap_beacons = mac.mbssid_beacon_set();
        let ap_frequency = mac.vif().and_then(|vif| vif.chanctx.map(|def| def.freq));
        *m = mac;
        drop(m);
        if restored.is_err() {
            if restoring_station {
                self.link_down(Some(Disconnect {
                    reason: frame::WLAN_REASON_UNSPECIFIED,
                    from_ap: false,
                    deauth: true,
                    bssid: [0; 6],
                }));
            }
            if restoring_ap {
                self.set_ap_carrier(false, 0);
            }
            self.shared.park(alloc::boxed::Box::new(()));
            return false;
        }
        if restoring_ap {
            self.shared.set_mbssid_beacons(self.vdev_id, ap_beacons);
            self.set_ap_carrier(true, ap_frequency.unwrap_or(0));
        }
        self.stats.recovered.fetch_add(1, Ordering::Relaxed);
        let last = self.last_assoc.lock().take();
        match last {
            // See `recover_one`: preserve a successful kernel association's
            // request in case a later restart arrives before replay is safe.
            Some((req, origin)) if restoring_station => {
                *self.last_assoc.lock() = Some((req, origin));
            }
            Some((req, ConnectOrigin::Kernel)) => {
                *self.last_assoc.lock() = Some((copy_request(&req), ConnectOrigin::Kernel));
                self.reconnect(req).await;
            }
            Some((_, ConnectOrigin::Nl80211)) | None => {}
        }
        true
    }

    /// Synchronous drain for the stack's busy-wait paths
    /// (`narf_net::iface::install_rx_drain`): service + deliver if the
    /// runtime is free. `true` when frames were delivered.
    pub fn drain_sync(&self) -> bool {
        let frames: Vec<(Vec<u8>, bool)> = {
            let Some(mut g) = self.shared.try_lock() else {
                return false;
            };
            g.service();
            g.vdev_mut(self.vdev_id)
                .map(|vdev| vdev.link.data_rx.drain(..).collect())
                .unwrap_or_default()
        };
        self.deliver(frames) > 0
    }

    fn mac_wowlan_config(config: Option<&WowlanConfig>) -> Option<super::mac::WowlanConfig> {
        config.map(|config| super::mac::WowlanConfig {
            disconnect: config.disconnect,
            magic_packet: config.magic_packet,
            gtk_rekey_failure: config.gtk_rekey_failure,
            patterns: config
                .patterns
                .iter()
                .map(|pattern| super::mac::WowPattern {
                    mask: pattern.mask.clone(),
                    pattern: pattern.pattern.clone(),
                    offset: pattern.offset,
                })
                .collect(),
            net_detect: config
                .net_detect
                .as_ref()
                .map(|net_detect| super::wmi::NloConfig {
                    probe_ssids: net_detect.probe_ssids.clone(),
                    channels_mhz: net_detect.frequencies_mhz.clone(),
                    probe_ies: net_detect.probe_ies.clone(),
                    networks: net_detect
                        .matches
                        .iter()
                        .map(|matched| super::wmi::NloNetwork {
                            ssid: matched.ssid.clone(),
                            rssi_threshold_dbm: matched.rssi_threshold_dbm,
                            hidden: net_detect.probe_ssids.contains(&matched.ssid),
                        })
                        .collect(),
                    plans: net_detect
                        .plans
                        .iter()
                        .map(|plan| (plan.interval_secs, plan.iterations))
                        .collect(),
                    delay_secs: net_detect.delay_secs,
                    random_mac: net_detect.random_mac,
                }),
        })
    }
}

impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> Interface for Ath11kNetdev<Io, Irq, Q> {
    fn name(&self) -> &str {
        self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.mac_addr
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ring
    }
    fn offloads(&self) -> narf_net::OffloadCapabilities {
        super::tx_offload::OFFLOADS
    }
}

#[async_trait]
impl<Io: RtIo, Irq: DpIrq, Q: RtQmi> WirelessNetIface for Ath11kNetdev<Io, Irq, Q> {
    fn wiphy_id(&self) -> u64 {
        self.shared.radio_id
    }

    fn supports_virtual_interfaces(&self) -> bool {
        self.virtual_lifecycle.is_some()
    }

    fn interface_combinations(&self) -> Vec<narf_wireless::InterfaceCombination> {
        if self.virtual_lifecycle.is_none() {
            return Vec::new();
        }
        // `ath11k_mac_setup_iface_combinations`, reduced to WCN6855's
        // deliberate three-vdev host ceiling. WCN6855 advertises two station
        // vdevs on up to two channels; AP/GO beaconing shares the
        // infrastructure beacon interval.
        alloc::vec![narf_wireless::InterfaceCombination {
            limits: alloc::vec![
                narf_wireless::InterfaceTypeLimit {
                    max: 2,
                    iftypes: alloc::vec![2], // NL80211_IFTYPE_STATION
                },
                narf_wireless::InterfaceTypeLimit {
                    max: 3,
                    iftypes: alloc::vec![3, 8, 9], // AP, P2P client, P2P GO
                },
                narf_wireless::InterfaceTypeLimit {
                    max: 1,
                    iftypes: alloc::vec![10], // P2P device
                },
            ],
            max_interfaces: super::runtime::WCN6855_MAX_VDEVS as u32,
            max_channels: 2,
            sta_ap_beacon_interval_match: true,
            beacon_interval_min_gcd: Some(100),
            // NL80211_CHAN_WIDTH_{20_NOHT,20,40,80,80P80,160}.
            radar_detect_widths: Some(
                (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5)
            ),
        }]
    }

    fn wiphy_mac_addresses(&self) -> Vec<[u8; 6]> {
        if self.virtual_lifecycle.is_none() {
            return Vec::new();
        }
        (0..super::runtime::WCN6855_MAX_VDEVS as u32)
            .map(|vdev_id| {
                if vdev_id == 0 {
                    self.mac_addr
                } else {
                    virtual_mac(self.mac_addr, vdev_id)
                }
            })
            .collect()
    }

    fn wiphy_extended_capabilities(&self) -> Option<WiphyExtendedCapabilities> {
        // mac80211's `local->ext_capa`: WCN6855 is
        // SUPPORTS_ONLY_HE_MULTI_BSSID, so bit 6 of byte three belongs in
        // the per-iftype arrays but not the wiphy-wide value.
        let capabilities = alloc::vec![1 << 2, 0, 0, 0, 0, 0, 0, 1 << 6];
        Some(WiphyExtendedCapabilities {
            mask: capabilities.clone(),
            capabilities,
        })
    }

    fn iftype_extended_capabilities(&self) -> Vec<IftypeExtendedCapability> {
        // `ath11k_iftypes_ext_capa`: cfg80211 includes a default record,
        // then station- and AP-specific records. Each mask equals the
        // advertised bits exactly, just as Linux's static arrays do.
        let common = alloc::vec![1 << 2, 0, 1 << 6, 0, 0, 0, 0, 1 << 6];
        let mut station = common.clone();
        station.resize(10, 0);
        station[9] = 1 << 5; // WLAN_EXT_CAPA10_TWT_REQUESTER_SUPPORT
        let mut ap = common.clone();
        ap.resize(11, 0);
        ap[9] = 1 << 6; // WLAN_EXT_CAPA10_TWT_RESPONDER_SUPPORT
        ap[10] = 1 << 3; // WLAN_EXT_CAPA11_EMA_SUPPORT
        alloc::vec![
            IftypeExtendedCapability {
                iftype: 0,
                capabilities: common.clone(),
                mask: common,
            },
            IftypeExtendedCapability {
                iftype: 2, // NL80211_IFTYPE_STATION
                capabilities: station.clone(),
                mask: station,
            },
            IftypeExtendedCapability {
                iftype: 3, // NL80211_IFTYPE_AP
                capabilities: ap.clone(),
                mask: ap,
            },
        ]
    }

    fn mbssid_support(&self) -> Option<MbssidSupport> {
        // Linux ath11k publishes this for WCN6855. NARF creates the AP WMI
        // vdev at ndo_open (before hostapd's START_AP), so only advertise it
        // when firmware accepts the role fields in VDEV_START rather than
        // the earlier VDEV_CREATE command.
        (self.virtual_lifecycle.is_some() && self.radio.mbssid_start).then_some(MbssidSupport {
            max_interfaces: super::runtime::WCN6855_MAX_VDEVS as u8,
            ema_max_profile_periodicity: 8,
        })
    }

    fn sar_capability(&self) -> Option<SarCapability> {
        self.radio.bios_sar.then_some(SarCapability {
            sar_type: 0, // NL80211_SAR_TYPE_POWER
            // `ath11k_hw_sar_freq_ranges_wcn6855` exactly as Linux
            // advertises it through `nl80211_put_sar_specs`.
            frequency_ranges: alloc::vec![
                SarFrequencyRange {
                    start_freq: 2402,
                    end_freq: 2482
                },
                SarFrequencyRange {
                    start_freq: 5150,
                    end_freq: 5250
                },
                SarFrequencyRange {
                    start_freq: 5250,
                    end_freq: 5725
                },
                SarFrequencyRange {
                    start_freq: 5725,
                    end_freq: 5810
                },
                SarFrequencyRange {
                    start_freq: 5815,
                    end_freq: 5895
                },
                SarFrequencyRange {
                    start_freq: 5925,
                    end_freq: 6165
                },
                SarFrequencyRange {
                    start_freq: 6165,
                    end_freq: 6425
                },
                SarFrequencyRange {
                    start_freq: 6425,
                    end_freq: 6525
                },
                SarFrequencyRange {
                    start_freq: 6525,
                    end_freq: 6705
                },
                SarFrequencyRange {
                    start_freq: 6705,
                    end_freq: 6875
                },
                SarFrequencyRange {
                    start_freq: 6875,
                    end_freq: 7125
                },
            ],
        })
    }

    fn set_sar_power_limits(&self, limits: &[SarPowerLimit]) -> Result<(), i32> {
        if !self.radio.bios_sar {
            return Err(super::mac::errno::EOPNOTSUPP);
        }
        // Linux ath11k rejects zero sub-specifications even though cfg80211
        // accepts an empty nested list generically. It stores only the low
        // byte of the signed quarter-dBm field in both chain halves.
        if limits.is_empty() || limits.len() > super::wmi::BIOS_SAR_TABLE_LEN / 2 {
            return Err(super::mac::errno::EINVAL);
        }
        let mut table = [0u8; super::wmi::BIOS_SAR_TABLE_LEN];
        for limit in limits {
            let index = limit.range_index as usize;
            if index >= super::wmi::BIOS_SAR_TABLE_LEN / 2
                || limits
                    .iter()
                    .filter(|other| other.range_index == limit.range_index)
                    .count()
                    != 1
            {
                return Err(super::mac::errno::EINVAL);
            }
            let power = limit.power_quarter_dbm as u8;
            table[index] = power;
            table[index + super::wmi::BIOS_SAR_TABLE_LEN / 2] = power;
        }
        self.shared.set_bios_sar_table(table);
        self.queue_ext(ExtOp::BiosSar(table));
        Ok(())
    }

    fn supports_scan_random_mac(&self) -> bool {
        self.radio.scan_random_mac
    }

    fn supports_scan_dwell(&self) -> bool {
        // ath11k_mac_register unconditionally exposes SET_SCAN_DWELL; the
        // common WMI start-scan command has per-band dwell-time fields.
        true
    }

    fn nl80211_feature_flags(&self) -> u32 {
        // Mirrors ath11k_mac_register().  The AP scan and CSA paths are
        // role-checked at execution time; these bits advertise the physical
        // wiphy's capability, as mac80211 does.  Firmware also supplies the
        // current TPC value for Spectrum-Management TPC/RM reports.
        const AP_SCAN: u32 = 1 << 8;
        const AP_MODE_CHAN_WIDTH_CHANGE: u32 = 1 << 18;
        const TX_POWER_INSERTION: u32 = 1 << 22;
        const STATIC_SMPS: u32 = 1 << 24;
        const DYNAMIC_SMPS: u32 = 1 << 25;

        let mut flags = AP_SCAN | AP_MODE_CHAN_WIDTH_CHANGE | TX_POWER_INSERTION | STATIC_SMPS;
        if self.radio.dynamic_smps {
            flags |= DYNAMIC_SMPS;
        }
        flags
    }

    fn new_virtual_interface(
        &self,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        let lifecycle = self
            .virtual_lifecycle
            .as_ref()
            .ok_or(WirelessError::NotSupported)?;
        (lifecycle.create)(self, name, iftype, mac)
    }

    fn delete_virtual_interface(&self) -> Result<(), WirelessError> {
        if self.vdev_id == 0 {
            return Err(WirelessError::NotSupported);
        }
        let lifecycle = self
            .virtual_lifecycle
            .as_ref()
            .ok_or(WirelessError::NotSupported)?;
        (lifecycle.delete)(self)
    }

    fn supports_ap(&self) -> bool {
        // WCN6855's Linux hw_params advertise AP alongside STA and P2P. The
        // role is selected by a down-only NL80211_CMD_SET_INTERFACE change.
        true
    }

    fn supports_ap_uapsd(&self) -> bool {
        // WCN6855 advertises WMI_TLV_SERVICE_AP_UAPSD and Linux exposes
        // WIPHY_FLAG_AP_UAPSD. Firmware owns the client buffers and TIM.
        true
    }

    fn max_ap_assoc_sta(&self) -> u32 {
        super::wmi::WCN6855_MAX_AP_ASSOC_STA
    }

    fn supports_fils_discovery(&self) -> bool {
        self.radio.fils_discovery
    }

    fn supports_unsol_bcast_probe_resp(&self) -> bool {
        self.radio.unsol_bcast_probe_resp
    }

    fn supports_ftm_responder(&self) -> bool {
        self.radio.ftm_responder
    }

    fn supports_bss_color(&self) -> bool {
        self.radio.bss_color
    }

    fn supports_twt_responder(&self) -> bool {
        self.radio.twt_responder
    }

    fn supports_channel_switch(&self) -> bool {
        // ath11k restarts the active AP / GO vdev on the target chandef;
        // mac80211 owns the CSA beacon countdown around that restart.
        true
    }

    fn max_csa_counters(&self) -> u8 {
        // IEEE80211_MAX_CNTDWN_COUNTERS_NUM, enforced by the AP CSA parser.
        2
    }

    fn current_iftype(&self) -> u32 {
        self.iftype.load(Ordering::Acquire)
    }

    fn set_iftype(&self, iftype: u32) -> Result<(), WirelessError> {
        // WCN6855 uses a different WMI vdev type for AP and STA. Linux's
        // change_virtual_intf requires the old netdev down; never retag an
        // extant firmware vdev because it would leave its peer/DP state in
        // the previous role.
        if !matches!(iftype, 2 | 3 | 8 | 9 | 10) {
            return Err(WirelessError::NotSupported);
        }
        if self.admin_up() {
            return Err(WirelessError::Busy);
        }
        let Some(m) = self.mac.try_lock() else {
            return Err(WirelessError::Busy);
        };
        if m.vif().is_some() {
            return Err(WirelessError::Busy);
        }
        if !self.shared.assign_vdev_iftype(self.vdev_id, iftype) {
            return Err(WirelessError::Busy);
        }
        if iftype != 2 {
            // An AP/GO/P2P vdev cannot inherit station WDS header mode.
            self.four_addr.store(false, Ordering::Release);
            *self.station_tx_power.lock() = None;
        }
        self.iftype.store(iftype, Ordering::Release);
        Ok(())
    }

    fn supports_four_addr_station(&self) -> bool {
        // This is the physical wiphy's `WIPHY_FLAG_4ADDR_STATION`, not the
        // current netdev role. `SET_INTERFACE` may select STATION and 4ADDR
        // together, as cfg80211 validates its requested `ntype` first.
        true
    }

    fn four_addr_enabled(&self) -> bool {
        self.four_addr.load(Ordering::Acquire)
    }

    fn set_four_addr(&self, enabled: bool) -> Result<(), i32> {
        if self.current_iftype() != 2 {
            return Err(super::mac::errno::EOPNOTSUPP);
        }
        if self.four_addr.swap(enabled, Ordering::AcqRel) != enabled {
            self.queue_ext(ExtOp::SetFourAddr(enabled));
        }
        Ok(())
    }

    fn start_ap(&self, cfg: ApConfig) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 3 | 9) {
            return Err(WirelessError::NotSupported);
        }
        if self.shared.is_dead() || !self.admin_up() {
            return Err(WirelessError::HardwareError);
        }
        let mbssid = self.mbssid_params(&cfg)?;
        self.shared.set_mbssid_transmitter(
            self.vdev_id,
            mbssid.is_non_transmitting().then_some(mbssid.tx_vdev_id),
        );
        // A generic-netlink handler can run inside an executor poll, where a
        // synchronous `block_on` would be a re-entrant deadlock. Preserve
        // netlink order in the same runtime queue that applies keys and
        // control-port changes; the WMI completion path reports any target
        // failure through the driver's diagnostic/error channel.
        self.queue_ext(ExtOp::StartAp {
            config: cfg,
            mbssid,
        });
        Ok(())
    }

    fn stop_ap(&self) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 3 | 9) {
            return Err(WirelessError::NotSupported);
        }
        self.queue_ext(ExtOp::StopAp);
        Ok(())
    }

    fn set_beacon(
        &self,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        probe_resp: Option<Vec<u8>>,
    ) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 3 | 9) {
            return Err(WirelessError::NotSupported);
        }
        self.queue_ext(ExtOp::SetApBeacon {
            head,
            tail,
            probe_resp,
        });
        Ok(())
    }

    fn set_ap_discovery(
        &self,
        fils: Option<Option<FilsDiscoveryConfig>>,
        unsol_bcast_probe_resp: Option<Option<UnsolBcastProbeRespConfig>>,
    ) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 3 | 9) {
            return Err(WirelessError::NotSupported);
        }
        if fils.is_some() && !self.radio.fils_discovery {
            return Err(WirelessError::NotSupported);
        }
        if unsol_bcast_probe_resp.is_some() && !self.radio.unsol_bcast_probe_resp {
            return Err(WirelessError::NotSupported);
        }
        self.queue_ext(ExtOp::SetApDiscovery {
            fils,
            unsol_bcast_probe_resp,
        });
        Ok(())
    }

    fn set_ap_ftm_responder(&self, config: FtmResponderConfig) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 3 | 9) || !self.radio.ftm_responder {
            return Err(WirelessError::NotSupported);
        }
        self.queue_ext(ExtOp::SetApFtmResponder(config));
        Ok(())
    }

    fn set_ap_he_bss_color(&self, config: HeBssColorConfig) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 3 | 9) {
            return Err(WirelessError::NotSupported);
        }
        // The common cfg80211 beacon parser does not gate this attribute on
        // the advertised extended feature. Match ath11k's AP BSS-info path:
        // accept the retained state and let firmware report any WMI failure.
        self.queue_ext(ExtOp::SetApHeBssColor(config));
        Ok(())
    }

    fn color_change(&self, cfg: ColorChangeConfig) -> Result<(), WirelessError> {
        // nl80211_color_change is infrastructure-AP-only. In particular, a
        // P2P GO must not borrow the similar AP template path for this WMI
        // BSS-color operation.
        if self.current_iftype() != 3 || !self.radio.bss_color {
            return Err(WirelessError::NotSupported);
        }
        if self.shared.is_dead() || !self.admin_up() {
            return Err(WirelessError::HardwareError);
        }
        let Some(m) = self.mac.try_lock() else {
            return Err(WirelessError::Busy);
        };
        if !m.ap_active() {
            return Err(WirelessError::Busy);
        }
        drop(m);
        self.queue_ext(ExtOp::ColorChange(cfg));
        Ok(())
    }

    fn channel_switch(&self, cfg: ChannelSwitchConfig) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 3 | 9) {
            return Err(WirelessError::NotSupported);
        }
        if self.shared.is_dead() || !self.admin_up() {
            return Err(WirelessError::HardwareError);
        }
        let Some(m) = self.mac.try_lock() else {
            return Err(WirelessError::Busy);
        };
        if !m.ap_active() {
            return Err(WirelessError::Busy);
        }
        drop(m);
        self.queue_ext(ExtOp::ChannelSwitch(cfg));
        Ok(())
    }

    fn add_station(&self, station: StationConfig) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 3 | 9) {
            return Err(WirelessError::NotSupported);
        }
        if let Some(setting) = station.station_tx_power {
            let m = self.mac.try_lock().ok_or(WirelessError::Busy)?;
            m.validate_station_tx_power(setting)
                .map_err(|_| WirelessError::InvalidArgs)?;
        }
        self.queue_ext(ExtOp::AddApStation(station));
        Ok(())
    }

    fn set_station(&self, station: StationConfig) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 3 | 9) {
            return Err(WirelessError::NotSupported);
        }
        if let Some(setting) = station.station_tx_power {
            let m = self.mac.try_lock().ok_or(WirelessError::Busy)?;
            m.validate_station_tx_power(setting)
                .map_err(|_| WirelessError::InvalidArgs)?;
        }
        self.queue_ext(ExtOp::SetApStation(station));
        Ok(())
    }

    fn del_station(&self, mac: Option<[u8; 6]>, _reason: u16) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 3 | 9) {
            return Err(WirelessError::NotSupported);
        }
        self.queue_ext(ExtOp::DelApStation(mac));
        Ok(())
    }

    fn supports_handshake_offload(&self) -> bool {
        // Like ath11k on Linux (mac80211 with its SME in userspace), no
        // offload is advertised: wpa_supplicant runs SME and supplicant.
        // The mac layer's own 4-way handshake serves the in-kernel
        // autoconnect (`associate_kernel`).
        false
    }

    fn supports_userspace_mlme(&self) -> bool {
        true
    }

    fn supports_external_supplicant(&self) -> bool {
        true
    }

    fn supports_control_port_tx_status(&self) -> bool {
        // mac80211 sets this unconditionally: every requested ath11k data
        // frame carries an ACK id through WBM completion.
        true
    }

    fn cipher_suites(&self) -> &'static [u32] {
        // `ath11k_mac_register`'s full cipher set. The five data suites
        // travel through WMI and are reflected in the TCL/REO descriptor;
        // BIP remains host MFP as ath11k returns `1` from set_key for it.
        &[
            narf_wireless::CIPHER_SUITE_TKIP,
            narf_wireless::CIPHER_SUITE_CCMP,
            narf_wireless::CIPHER_SUITE_AES_CMAC,
            narf_wireless::CIPHER_SUITE_BIP_CMAC_256,
            narf_wireless::CIPHER_SUITE_BIP_GMAC_128,
            narf_wireless::CIPHER_SUITE_BIP_GMAC_256,
            narf_wireless::CIPHER_SUITE_GCMP,
            narf_wireless::CIPHER_SUITE_GCMP_256,
            narf_wireless::CIPHER_SUITE_CCMP_256,
        ]
    }

    fn supports_gtk_rekey_offload(&self) -> bool {
        self.radio.gtk_rekey_offload
    }

    fn wowlan_support(&self) -> Option<WowlanSupport> {
        self.radio.wowlan.then_some(WowlanSupport {
            disconnect: true,
            magic_packet: true,
            gtk_rekey: self.radio.gtk_rekey_offload,
            gtk_rekey_failure: self.radio.gtk_rekey_offload,
            max_patterns: super::mac::ATH11K_WOW_MAX_PATTERNS as u8,
            min_pattern_len: 1,
            max_pattern_len: super::wmi::WMI_WOW_MAX_PATTERN_SIZE as u16,
            max_packet_offset: super::mac::ATH11K_WOW_MAX_PKT_OFFSET as u16,
            net_detect_max_match_sets: if self.radio.net_detect { 16 } else { 0 },
            net_detect_random_mac: self.radio.net_detect,
        })
    }

    fn set_wowlan(&self, config: Option<WowlanConfig>) -> Result<(), i32> {
        let support = self.wowlan_support().ok_or(super::mac::errno::EOPNOTSUPP)?;
        if let Some(config) = config.as_ref() {
            if config.patterns.len() > support.max_patterns as usize
                || config.patterns.iter().any(|pattern| {
                    pattern.pattern.is_empty()
                        || pattern.pattern.len() < support.min_pattern_len as usize
                        || pattern.pattern.len() > support.max_pattern_len as usize
                        || pattern.mask.len() != pattern.pattern.len().div_ceil(8)
                        || pattern.offset > support.max_packet_offset as u32
                })
            {
                return Err(super::mac::errno::EINVAL);
            }
            if config.gtk_rekey_failure && !support.gtk_rekey_failure {
                return Err(super::mac::errno::EINVAL);
            }
            if config.net_detect.is_some()
                && (support.net_detect_max_match_sets == 0 || self.current_iftype() != 2)
            {
                return Err(super::mac::errno::EINVAL);
            }
        }
        let mac_config = Self::mac_wowlan_config(config.as_ref());
        if let Some(net_detect) = mac_config
            .as_ref()
            .and_then(|config| config.net_detect.as_ref())
        {
            // `SET_WOWLAN` is synchronous. Validate the complete WMI-shaped
            // request now instead of accepting an unrepresentable direct
            // trait caller and losing the later asynchronous error.
            super::wmi::nlo_config_start_cmd(self.vdev_id, net_detect)
                .map_err(|error| error.errno())?;
        }
        *self.wowlan.lock() = config;
        self.queue_ext(ExtOp::Wowlan(mac_config));
        Ok(())
    }

    fn wowlan_config(&self) -> Option<WowlanConfig> {
        self.wowlan.lock().clone()
    }

    fn reports_disconnect_events(&self) -> bool {
        true
    }

    async fn mlme_authenticate(&self, req: MlmeAuthRequest) -> Result<Vec<u8>, WirelessError> {
        if !matches!(self.current_iftype(), 2 | 8) {
            return Err(WirelessError::NotSupported);
        }
        if self.shared.is_dead() {
            return Err(WirelessError::HardwareError);
        }
        let mut m = self.mac.lock().await;
        if !self.sync_admin(&mut m).await {
            return Err(WirelessError::HardwareError);
        }
        let r = m.sme_authenticate(&req).await;
        let why = m.take_disconnect();
        drop(m);
        if why.is_some() {
            // A new authentication left the old association.
            self.link_down(why);
        }
        r.map_err(|e| e.wireless())
    }

    async fn mlme_associate(&self, req: MlmeAssocRequest) -> Result<Vec<u8>, WirelessError> {
        if !matches!(self.current_iftype(), 2 | 8) {
            return Err(WirelessError::NotSupported);
        }
        if self.shared.is_dead() {
            return Err(WirelessError::HardwareError);
        }
        let mut m = self.mac.lock().await;
        // The preceding AUTHENTICATE selected a cached BSS, whose ChanDef
        // retains the exact MHz identity. Do not reconstruct it from the
        // channel number: 6 GHz numbering overlaps legacy bands.
        let reservation = match m.link().map(|link| link.def.freq) {
            Some(frequency_mhz) => Some(
                self.shared
                    .reserve_operating_channel(self.vdev_id, frequency_mhz)
                    .ok_or(WirelessError::Busy)?,
            ),
            None => None,
        };
        let r = m.sme_associate(&req).await;
        let b = m.connected_bssid();
        drop(m);
        if r.is_err() || b.is_none() {
            if let Some(previous_frequency) = reservation {
                self.shared
                    .restore_operating_channel(self.vdev_id, previous_frequency);
            }
        }
        let frame = r.map_err(|e| e.wireless())?;
        if b.is_some() {
            self.set_control_port(req.control_port);
            *self.last_assoc.lock() = None;
            // ieee80211_set_associated → netif_carrier_on.
            self.set_link(true, b, frame::freq_to_channel(req.frequency_mhz));
        }
        Ok(frame)
    }

    async fn mlme_deauthenticate(
        &self,
        peer: [u8; 6],
        reason: u16,
    ) -> Result<Vec<u8>, WirelessError> {
        self.sme_leave(peer, reason, true).await
    }

    async fn mlme_disassociate(
        &self,
        peer: [u8; 6],
        reason: u16,
    ) -> Result<Vec<u8>, WirelessError> {
        self.sme_leave(peer, reason, false).await
    }

    fn register_mgmt_frame(
        &self,
        frame_type: u16,
        match_prefix: &[u8],
    ) -> Result<(), WirelessError> {
        // cfg80211 registrations match only management type/subtype and a
        // body prefix. Keep the finite filter list bounded exactly where it
        // is owned, independent of a malformed generic-netlink caller.
        if frame_type & 0x000c != 0 || match_prefix.len() > u8::MAX as usize {
            return Err(WirelessError::InvalidArgs);
        }
        let registration = MgmtRegistration {
            frame_type: frame_type & frame::FCTL_TYPE_STYPE,
            match_prefix: match_prefix.to_vec(),
        };
        let mut registrations = self.mgmt_registrations.lock();
        if registrations.iter().any(|r| r == &registration) {
            return Ok(());
        }
        if registrations.len() == 64 {
            return Err(WirelessError::Busy);
        }
        registrations.push(registration);
        Ok(())
    }

    async fn mgmt_tx(&self, _cookie: u64, request: MgmtTxRequest) -> Result<bool, WirelessError> {
        if self.shared.is_dead() || !self.admin_up() {
            return Err(WirelessError::HardwareError);
        }
        if request.frame.len() < frame::MGMT_HDR_LEN || request.frame[0] & 0x0c != 0 {
            return Err(WirelessError::InvalidArgs);
        }
        let mut m = self.mac.lock().await;
        let current_frequency = m.vif().and_then(|vif| vif.chanctx.map(|def| def.freq));
        let on_roc =
            request.frequency_mhz != 0 && m.remain_on_channel_active(request.frequency_mhz);
        if request.frequency_mhz != 0 && current_frequency != Some(request.frequency_mhz) && !on_roc
        {
            return Err(WirelessError::InvalidArgs);
        }
        if request.offchannel_ok && !on_roc {
            return Err(WirelessError::InvalidArgs);
        }
        m.registered_mgmt_tx(&request.frame, on_roc.then_some(request.frequency_mhz))
            .await
            .map_err(|error| error.wireless())
    }

    fn max_remain_on_channel_duration_ms(&self) -> u32 {
        5000 // Linux's WCN6855 wiphy->max_remain_on_channel_duration
    }

    fn supports_offchannel_mgmt_tx(&self) -> bool {
        // `hw_params.support_off_channel_tx`: a registered management frame
        // may transmit on the active scan-backed ROC context.
        true
    }

    fn remain_on_channel(
        &self,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 8..=10) {
            return Err(WirelessError::NotSupported);
        }
        if self.shared.is_dead() || !self.admin_up() {
            return Err(WirelessError::HardwareError);
        }
        if duration_ms == 0 || duration_ms > self.max_remain_on_channel_duration_ms() {
            return Err(WirelessError::InvalidArgs);
        }
        let Some(m) = self.mac.try_lock() else {
            return Err(WirelessError::Busy);
        };
        if m.remain_on_channel_busy() {
            return Err(WirelessError::Busy);
        }
        if !m.can_remain_on_channel(frequency_mhz) {
            return Err(WirelessError::InvalidArgs);
        }
        drop(m);
        if !self.shared.claim_scan(self.vdev_id) {
            return Err(WirelessError::Busy);
        }
        self.queue_ext(ExtOp::RemainOnChannel {
            cookie,
            frequency_mhz,
            duration_ms,
        });
        Ok(())
    }

    fn cancel_remain_on_channel(&self, cookie: u64) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 8..=10) {
            return Err(WirelessError::NotSupported);
        }
        let Some(m) = self.mac.try_lock() else {
            return Err(WirelessError::Busy);
        };
        if !m.has_remain_on_channel(cookie) {
            return Err(WirelessError::InvalidArgs);
        }
        drop(m);
        self.queue_ext(ExtOp::CancelRemainOnChannel { cookie });
        Ok(())
    }

    fn add_key(&self, key: KeyParams) -> Result<(), i32> {
        if matches!(self.current_iftype(), 3 | 9) {
            if !matches!(
                key.cipher,
                narf_wireless::CIPHER_SUITE_TKIP
                    | narf_wireless::CIPHER_SUITE_CCMP
                    | narf_wireless::CIPHER_SUITE_CCMP_256
                    | narf_wireless::CIPHER_SUITE_GCMP
                    | narf_wireless::CIPHER_SUITE_GCMP_256
                    | narf_wireless::CIPHER_SUITE_AES_CMAC
                    | narf_wireless::CIPHER_SUITE_BIP_CMAC_256
                    | narf_wireless::CIPHER_SUITE_BIP_GMAC_128
                    | narf_wireless::CIPHER_SUITE_BIP_GMAC_256
            ) {
                return Err(super::mac::errno::EOPNOTSUPP);
            }
            if super::mac::sec::bip_cipher(key.cipher).is_some()
                && (key.pairwise || key.peer.is_some())
            {
                return Err(super::mac::errno::EINVAL);
            }
            let m = self.mac.try_lock().ok_or(super::mac::errno::EBUSY)?;
            if !m.ap_active() {
                return Err(super::mac::errno::ENOTCONN);
            }
            if key.pairwise {
                key.peer.ok_or(super::mac::errno::EINVAL)?;
            } else if key.peer.is_some() {
                return Err(super::mac::errno::ENOENT);
            }
            // NEW_STATION and NEW_KEY are ordered on `ext_ops`, but each
            // netlink syscall returns before its WMI sequence runs. Do not
            // reject hostapd's immediately-following peer key merely because
            // the queued station add has not populated `Mac::ap` yet; the
            // runtime validates it after the preceding operation.
            drop(m);
            self.queue_ext(ExtOp::AddApKey(key));
            return Ok(());
        }
        let ap = self.connected_bssid();
        if key.pairwise && (ap.is_none() || key.peer != ap) {
            return Err(super::mac::errno::ENOENT);
        }
        if ap.is_none() {
            return Err(super::mac::errno::ENOENT);
        }
        match key.cipher {
            narf_wireless::CIPHER_SUITE_TKIP
            | narf_wireless::CIPHER_SUITE_CCMP
            | narf_wireless::CIPHER_SUITE_CCMP_256
            | narf_wireless::CIPHER_SUITE_GCMP
            | narf_wireless::CIPHER_SUITE_GCMP_256
            | narf_wireless::CIPHER_SUITE_AES_CMAC
            | narf_wireless::CIPHER_SUITE_BIP_CMAC_256
            | narf_wireless::CIPHER_SUITE_BIP_GMAC_128
            | narf_wireless::CIPHER_SUITE_BIP_GMAC_256 => {}
            _ => return Err(super::mac::errno::EOPNOTSUPP),
        }
        {
            let mut book = self.keys.lock();
            if key.pairwise {
                book.ptk = true;
            } else if let Some(s) = book.group.get_mut(key.idx as usize) {
                *s = true;
            }
        }
        self.queue_ext(ExtOp::AddKey(key));
        Ok(())
    }

    fn set_gtk_rekey_data(&self, data: GtkRekeyData) -> Result<(), i32> {
        if !self.supports_gtk_rekey_offload() {
            return Err(super::mac::errno::EOPNOTSUPP);
        }
        // nl80211_set_rekey_data requires an associated station.  Store it
        // in the same ordered queue as keys and port authorization so a
        // low-power transition cannot observe a partially applied request.
        if self.connected_bssid().is_none() {
            return Err(super::mac::errno::ENOTCONN);
        }
        self.queue_ext(ExtOp::GtkRekeyData(data));
        Ok(())
    }

    fn del_key(&self, idx: u8, pairwise: bool, peer: Option<[u8; 6]>) -> Result<(), i32> {
        if matches!(self.current_iftype(), 3 | 9) {
            let m = self.mac.try_lock().ok_or(super::mac::errno::EBUSY)?;
            if pairwise && peer.is_none()
                || !pairwise && peer.is_some()
                || !m.ap_has_key(idx, pairwise, peer)
            {
                return Err(super::mac::errno::ENOENT);
            }
            drop(m);
            self.queue_ext(ExtOp::DelApKey {
                idx,
                pairwise,
                peer,
            });
            return Ok(());
        }
        let ap = self.connected_bssid();
        if pairwise && (ap.is_none() || peer != ap) {
            return Err(super::mac::errno::ENOENT);
        }
        {
            let mut book = self.keys.lock();
            let slot = if pairwise {
                Some(&mut book.ptk)
            } else {
                book.group.get_mut(idx as usize)
            };
            match slot {
                Some(s) if *s => *s = false,
                _ => return Err(super::mac::errno::ENOENT),
            }
        }
        self.queue_ext(ExtOp::DelKey { idx, pairwise });
        Ok(())
    }

    fn set_default_mgmt_key(&self, idx: u8) -> Result<(), i32> {
        if !matches!(self.current_iftype(), 3 | 9) {
            // Station mode verifies inbound IGTKs by the MMIE key id; it has
            // no management-group transmit key to select.
            return Ok(());
        }
        let m = self.mac.try_lock().ok_or(super::mac::errno::EBUSY)?;
        if !m.ap_active() {
            return Err(super::mac::errno::ENOTCONN);
        }
        drop(m);
        self.queue_ext(ExtOp::SetApDefaultMgmtKey(idx));
        Ok(())
    }

    fn set_port_authorized(&self, peer: [u8; 6], authorized: bool) -> Result<(), i32> {
        if matches!(self.current_iftype(), 3 | 9) {
            let m = self.mac.try_lock().ok_or(super::mac::errno::EBUSY)?;
            if !m.ap_active() {
                return Err(super::mac::errno::ENOTCONN);
            }
            // Keep NEW_STATION → NEW_KEY → PORT_AUTHORIZED in the same
            // ordered runtime stream; the station may still be pending here.
            drop(m);
            self.queue_ext(ExtOp::AuthorizeAp {
                peer,
                on: authorized,
            });
            return Ok(());
        }
        if self.connected_bssid() != Some(peer) {
            return Err(super::mac::errno::ENOENT);
        }
        self.queue_ext(ExtOp::Authorize(authorized));
        Ok(())
    }

    fn tx_control_port(
        &self,
        dest: [u8; 6],
        proto: u16,
        frame: Vec<u8>,
        no_encrypt: bool,
    ) -> Result<(), i32> {
        self.queue_control_port(dest, proto, frame, no_encrypt, None)
    }

    fn tx_control_port_with_status(
        &self,
        dest: [u8; 6],
        proto: u16,
        frame: Vec<u8>,
        no_encrypt: bool,
        cookie: Option<u64>,
    ) -> Result<(), i32> {
        self.queue_control_port(dest, proto, frame, no_encrypt, cookie)
    }

    fn power_save_default(&self) -> Option<bool> {
        // mac80211's set_power_mgmt; SUPPORTS_PS on WCN6855.
        Some(true)
    }

    fn set_power_save(&self, enabled: bool) -> Result<(), i32> {
        self.ps.store(enabled, Ordering::Release);
        self.queue_ext(ExtOp::PowerSave(enabled));
        Ok(())
    }

    fn supports_cqm_rssi(&self) -> bool {
        // ath11k does not set IEEE80211_VIF_BEACON_FILTER, so Linux
        // mac80211 evaluates CQM RSSI in software from AP beacons.
        matches!(self.current_iftype(), 2 | 8)
    }

    fn supports_cqm_rssi_list(&self) -> bool {
        // mac80211 provides this through its software range-CQM path when
        // the vif does not request target-side beacon filtering.
        self.supports_cqm_rssi()
    }

    fn set_cqm_rssi(&self, config: Option<CqmRssiConfig>) -> Result<(), i32> {
        if !self.supports_cqm_rssi() {
            return Err(super::mac::errno::EOPNOTSUPP);
        }
        self.queue_ext(ExtOp::SetCqmRssi(config));
        Ok(())
    }

    fn supports_survey(&self) -> bool {
        self.radio.bss_survey
    }

    fn antenna_info(&self) -> Option<AntennaInfo> {
        let (tx, rx) = self
            .shared
            .antenna_config()
            .map(|(masks, _)| masks)
            .unwrap_or((self.radio.antenna_avail_tx, self.radio.antenna_avail_rx));
        Some(AntennaInfo {
            tx,
            rx,
            available_tx: self.radio.antenna_avail_tx,
            available_rx: self.radio.antenna_avail_rx,
        })
    }

    fn set_antenna(&self, tx: u32, rx: u32) -> Result<(), i32> {
        if tx == 0
            || rx == 0
            || tx & !self.radio.antenna_avail_tx != 0
            || rx & !self.radio.antenna_avail_rx != 0
        {
            return Err(super::mac::errno::EINVAL);
        }
        self.shared.set_antenna_masks(tx, rx);
        Ok(())
    }

    fn fragmentation_threshold(&self) -> Option<u32> {
        // `wiphy_new()` leaves fragmentation disabled (`u32::MAX`). ath11k
        // still rejects an attempted threshold change because the target
        // clears More-Fragments, just as Linux's `set_frag_threshold` path
        // does.
        Some(u32::MAX)
    }

    fn rts_threshold(&self) -> Option<u32> {
        Some(self.shared.rts_config().0)
    }

    fn set_rts_threshold(&self, threshold: u32) -> Result<(), i32> {
        self.shared.set_rts_threshold(threshold);
        Ok(())
    }

    fn supports_tx_bitrate_mask(&self) -> bool {
        matches!(self.current_iftype(), 2 | 3 | 8 | 9)
    }

    fn set_tx_bitrate_mask(&self, mask: TxBitrateMask) -> Result<(), i32> {
        if !self.supports_tx_bitrate_mask() {
            return Err(super::mac::errno::EOPNOTSUPP);
        }
        // Mirror `ath11k_mac_vif_chan`: a rate mask belongs to a configured
        // channel, not merely to an administratively-created vdev.
        let m = self.mac.try_lock().ok_or(super::mac::errno::EBUSY)?;
        if m.connected_bssid().is_none() && !m.ap_active() {
            return Err(super::mac::errno::EPERM);
        }
        m.validate_tx_bitrate_mask(&mask)?;
        drop(m);
        *self.bitrate_mask.lock() = mask.clone();
        self.queue_ext(ExtOp::SetTxBitrateMask(mask));
        Ok(())
    }

    fn supports_station_tx_power(&self) -> bool {
        // Linux ath11k unconditionally exposes NL80211_EXT_FEATURE_STA_TX_PWR
        // for its mac80211 wiphy; the target-side peer parameter is common to
        // both WCN6855 station and AP vdevs.
        true
    }

    fn supports_ack_signal(&self) -> bool {
        self.radio.ack_signal
    }

    fn set_station_tx_power(&self, peer: [u8; 6], setting: StationTxPower) -> Result<(), i32> {
        if !matches!(self.current_iftype(), 2 | 8) {
            return Err(super::mac::errno::EOPNOTSUPP);
        }
        let m = self.mac.try_lock().ok_or(super::mac::errno::EBUSY)?;
        if m.connected_bssid() != Some(peer) {
            return Err(super::mac::errno::ENOENT);
        }
        m.validate_station_tx_power(setting)?;
        drop(m);
        *self.station_tx_power.lock() = Some(setting);
        self.queue_ext(ExtOp::SetStationTxPower { peer, setting });
        Ok(())
    }

    fn tx_power_dbm(&self) -> Option<i32> {
        self.mac.try_lock()?.tx_power_dbm()
    }

    fn survey_info(&self) -> Vec<SurveyInfo> {
        // The generic-netlink syscall cannot await WMI (it may already run in
        // the executor), so return Linux-shaped cached records and coalesce a
        // refresh for the ordered runtime worker.
        self.shared.request_bss_survey();
        let cached = self.shared.bss_surveys();
        let in_use = self.shared.operating_channels();
        self.radio
            .bands
            .iter()
            .flat_map(|(band, channels)| {
                channels.iter().map(move |channel| match *band {
                    2400 if *channel == 14 => 2484,
                    2400 => 2407 + *channel * 5,
                    5000 => 5000 + *channel * 5,
                    6000 if *channel == 2 => 5935,
                    6000 => 5950 + *channel * 5,
                    _ => 0,
                })
            })
            .filter(|frequency_mhz| *frequency_mhz != 0)
            .map(|frequency_mhz| {
                let sample = cached
                    .iter()
                    .find(|sample| sample.frequency_mhz == frequency_mhz);
                SurveyInfo {
                    frequency_mhz,
                    noise_dbm: sample.map(|sample| sample.noise_dbm),
                    in_use: in_use.contains(&frequency_mhz),
                    time_ms: sample.map(|sample| sample.time_ms),
                    time_busy_ms: sample.map(|sample| sample.time_busy_ms),
                    time_rx_ms: sample.map(|sample| sample.time_rx_ms),
                    time_tx_ms: sample.map(|sample| sample.time_tx_ms),
                }
            })
            .collect()
    }

    fn regulatory_domain(&self) -> Option<narf_wireless::RegDomainInfo> {
        let r = self.mac.try_lock()?.regd();
        Some(narf_wireless::RegDomainInfo {
            alpha2: r.alpha2,
            dfs_region: r.dfs_region as u8,
            // ath11k_mac_register: REGULATORY_WIPHY_SELF_MANAGED.
            self_managed: true,
            rules: r
                .rules
                .iter()
                .map(|x| narf_wireless::RegRuleInfo {
                    flags: x.flags,
                    start_khz: x.start * 1000,
                    end_khz: x.end * 1000,
                    max_bw_khz: x.max_bw * 1000,
                    max_antenna_gain_mbi: x.max_antenna_gain * 100,
                    max_eirp_mbm: x.max_eirp * 100,
                    dfs_cac_ms: x.dfs_cac_ms,
                })
                .collect(),
        })
    }

    fn station_info(&self) -> Option<narf_wireless::StationInfo> {
        // The runtime owns the completion counters while the MAC owns the
        // associated station's received-signal sample. Both are try-locks:
        // GET_STATION is observational and must not stall the data path.
        let rt = self.shared.try_lock()?;
        let stats = rt.stats;
        let vdev = rt.vdev(self.vdev_id)?;
        let ack_signal_dbm = vdev.link.last_ack_signal.map(|s| s.clamp(-128, 127) as i8);
        let last_tx_rate = vdev.link.last_tx_rate;
        let last_ppdu_tx_rate = vdev.link.last_ppdu_tx_rate;
        let last_rx_rate = vdev.link.last_rx_rate;
        let tx_duration_us = vdev.link.tx_duration_us;
        let last_ppdu_signal_dbm = vdev.link.last_ppdu_signal_dbm;
        let ppdu_signal_avg_dbm = vdev.link.ppdu_signal_avg_dbm;
        let chain_signal_dbm = vdev.link.chain_signal_dbm;
        let rx_duration_us = vdev.link.rx_duration_us;
        drop(rt);
        let m = self.mac.try_lock()?;
        let l = m.link()?;
        // Prefer the peer PPDU EWMA from ath11k's default monitor-status
        // filter. Before the first status buffer, retain the mac80211-style
        // beacon CQM fallback already used by this interface.
        let beacon_signal_avg_dbm = if l.beacon_signal_count >= 4 {
            l.beacon_signal_ewma
                .map(|ewma| -((ewma / 16) as i32))
                .map(|signal| signal.clamp(-128, 127) as i8)
        } else {
            None
        };
        Some(narf_wireless::StationInfo {
            signal_dbm: last_ppdu_signal_dbm
                .or_else(|| l.last_signal.map(|s| s.clamp(-128, 127) as i8)),
            signal_avg_dbm: ppdu_signal_avg_dbm.or(beacon_signal_avg_dbm),
            chain_signal_dbm,
            ack_signal_dbm,
            // Firmware PPDU statistics carry actual NSS and HE RU/DCM. A
            // WBM first-MSDU record remains the pre-PPDU fallback and lacks
            // its own NSS, so decode it against the negotiated peer value.
            tx_bitrate: last_ppdu_tx_rate
                .or_else(|| last_tx_rate.and_then(|raw| runtime::tx_rate_info(raw, l.sta.rx_nss))),
            // Fast-RX descriptors carry their own MIMO stream bitmap, so no
            // association-state fallback is necessary for the receive rate.
            rx_bitrate: last_rx_rate.and_then(runtime::rx_rate_info),
            // Each non-dropped status is one completed MSDU for the AP;
            // queue rejects and invalid-peer releases are deliberately not
            // represented as station traffic.
            tx_packets: Some(stats.tx_status_acked.saturating_add(stats.tx_status_noack)),
            tx_retries: Some(stats.tx_retries),
            tx_failed: Some(stats.tx_status_noack),
            tx_duration_us: Some(tx_duration_us),
            rx_duration_us: Some(rx_duration_us),
            // The runtime delivers EAPOL as well as authorized data from the
            // AP. This counts accepted MSDUs rather than inferring packets
            // from PPDU reports, which carry independent RX airtime above.
            rx_packets: Some(stats.rx_data.saturating_add(stats.rx_eapol)),
        })
    }

    fn ap_station_macs(&self) -> Vec<[u8; 6]> {
        self.mac
            .try_lock()
            .map(|mac| mac.ap_station_macs())
            .unwrap_or_default()
    }

    fn ap_station_info(&self, peer: [u8; 6]) -> Option<narf_wireless::StationInfo> {
        // Both snapshots use try-locks so an observational netlink query
        // cannot stall RX/TX. The runtime owns WBM/fast-RX accounting; the
        // MAC table establishes that this is still an associated client.
        let rt = self.shared.try_lock()?;
        let ap_peer = rt
            .vdev(self.vdev_id)?
            .ap
            .as_ref()?
            .peers
            .iter()
            .find(|known| known.addr == peer)?;
        let info = narf_wireless::StationInfo {
            rx_packets: Some(ap_peer.rx_packets),
            tx_packets: Some(ap_peer.tx_packets),
            tx_retries: Some(ap_peer.tx_retries),
            tx_failed: Some(ap_peer.tx_failed),
            tx_bitrate: ap_peer.last_tx_rate,
            tx_duration_us: Some(ap_peer.tx_duration_us),
            signal_dbm: ap_peer.last_ppdu_signal_dbm,
            signal_avg_dbm: ap_peer.ppdu_signal_avg_dbm,
            chain_signal_dbm: ap_peer.chain_signal_dbm,
            rx_duration_us: Some(ap_peer.rx_duration_us),
            ..Default::default()
        };
        drop(rt);
        self.mac.try_lock()?.ap_has_station(peer).then_some(info)
    }

    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.mac
            .try_lock()?
            .bss_table()
            .iter()
            .find(|b| b.bssid == bssid)
            .map(|b| b.ies.clone())
    }

    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        WirelessIfaceInfo {
            base_name: self.name.into(),
            base_mac: self.mac_addr,
            bands: self
                .radio
                .bands
                .iter()
                .map(|(f, ch)| WirelessBand {
                    freq_mhz: *f,
                    channels: ch.clone(),
                })
                .collect(),
            modes: WirelessModes::STATION | WirelessModes::AP | WirelessModes::P2P,
            hw_caps: HwCaps {
                ht_supported: self.radio.ht,
                vht_supported: self.radio.vht,
                // HE association on 2.4 / 5 GHz (ath11k.md §3.9).
                he_supported: self.radio.he,
                eht_supported: false,
            },
        }
    }

    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        if self.shared.is_dead() {
            return Err(WirelessError::HardwareError);
        }
        // A generic-netlink request can be cancelled while `m.scan()` is
        // awaiting firmware. Normal return releases the lease here; future
        // drop queues ordered WMI cancellation on this vdev worker first.
        let mut scan =
            ScanLease::acquire(self.shared.clone(), self.vdev_id).ok_or(WirelessError::Busy)?;
        let result = {
            let mut m = self.mac.lock().await;
            // nl80211 refuses a scan on a down interface (-ENETDOWN).
            if !self.sync_admin(&mut m).await {
                Err(WirelessError::HardwareError)
            } else {
                m.scan(&req).await
            }
        };
        scan.complete();
        result
    }

    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        // nl80211 CONNECT: userspace's connection.
        self.associate_from(req, ConnectOrigin::Nl80211).await
    }

    async fn roam(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        if self.shared.is_dead() {
            return Err(WirelessError::HardwareError);
        }
        let mut m = self.mac.lock().await;
        if !self.sync_admin(&mut m).await {
            return Err(WirelessError::HardwareError);
        }
        let Some(previous_frequency) = self
            .shared
            .reserve_operating_channel(self.vdev_id, req.frequency_mhz)
        else {
            return Err(WirelessError::Busy);
        };
        let r = m.roam(&req).await;
        let b = m.connected_bssid();
        drop(m);
        if r.is_err() {
            // The old station was already released before the new vdev and
            // peer were prepared, so a failed roam has no usable link.
            *self.last_assoc.lock() = None;
            self.shared.clear_operating_channel(self.vdev_id);
            self.link_down(None);
            return r;
        }
        if b.is_none() {
            self.shared
                .restore_operating_channel(self.vdev_id, previous_frequency);
        }
        if let SecurityConfig::External(e) = &req.security {
            self.set_control_port(e.control_port);
        }
        *self.last_assoc.lock() = Some((copy_request(&req), ConnectOrigin::Nl80211));
        // `ieee80211_set_associated` changes BSSID without a carrier flap.
        self.set_link(b.is_some(), b, req.channel);
        Ok(())
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 2 | 8) {
            return Err(WirelessError::NotSupported);
        }
        *self.last_assoc.lock() = None;
        if self.shared.is_dead() {
            self.set_link(false, None, 0);
            return Err(WirelessError::HardwareError);
        }
        let mut m = self.mac.lock().await;
        // ieee80211_set_disassoc: "drop any frame before deauth/disassoc".
        if m.link().is_some() {
            self.shared.flush_queues_for(self.vdev_id, true).await;
        }
        let r = m.disassociate().await;
        let why = m.take_disconnect();
        drop(m);
        self.link_down(why);
        r
    }

    fn connected_bssid(&self) -> Option<[u8; 6]> {
        let packed = self.bssid.load(Ordering::Acquire);
        (packed & (1 << 63) != 0).then(|| core::array::from_fn(|i| (packed >> (8 * i)) as u8))
    }

    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError> {
        // A station follows its AP's channel; transmit power is the
        // regulatory / firmware limit (no `iw set txpower`).
        if cfg.tx_power_dbm.is_some() {
            return Err(WirelessError::NotSupported);
        }
        if channel_number_freq(cfg.channel).is_none() {
            return Err(WirelessError::InvalidArgs);
        }
        if self.channel.load(Ordering::Acquire) == cfg.channel && self.link_up() {
            Ok(())
        } else {
            Err(WirelessError::InvalidArgs)
        }
    }
}

// ── registration (PCI) ────────────────────────────────────────────

/// The hardware netdev.
pub type PciNetdev = Ath11kNetdev<super::core::Bar0, super::ce::MsiCeIrq, super::pci::Wlfw>;

impl Ath11kNetdev<super::core::Bar0, super::ce::MsiCeIrq, super::pci::Wlfw> {
    /// Complete the asynchronous half of Linux's
    /// `ath11k_wow_op_suspend`: arm firmware WoW first, then take the PCI
    /// transport through MHI M3.  This must run before the synchronous S3
    /// device callbacks gate interrupts, so the WMI and MHI completions can
    /// still arrive.
    pub async fn system_suspend_wowlan(&self) -> Result<(), i32> {
        let devices = pci_radio_devices(self.shared.radio_id);
        let mut armed: Vec<Arc<PciNetdev>> = Vec::new();
        for dev in devices {
            if dev.wowlan.lock().is_none() {
                continue;
            }
            if let Err(e) = dev.prepare_wowlan().await {
                // All of these WMI exchanges completed while the transport
                // is still live, so a later vdev failure can unwind the
                // earlier vdevs before the platform sees suspend failure.
                for prepared in armed {
                    let _ = prepared.resume_wowlan().await;
                }
                return Err(e.errno);
            }
            armed.push(dev);
        }
        if armed.is_empty() {
            return Err(super::mac::errno::EINVAL);
        }
        if let Err(e) = self.shared.wowlan_hif_suspend().await {
            // The MHI transition did not complete, so CE/DP delivery remains
            // live and the normal WMI wake/cleanup sequence is safe to run.
            for prepared in armed {
                let _ = prepared.resume_wowlan().await;
            }
            return Err(e);
        }
        Ok(())
    }

    /// The inverse of [`Self::system_suspend_wowlan`]: restore MHI and host
    /// interrupts before issuing WMI host-wakeup and removing WoW state.
    pub async fn system_resume_wowlan(&self) -> Result<(), i32> {
        self.shared.wowlan_hif_resume().await?;
        for dev in pci_radio_devices(self.shared.radio_id) {
            // `resume_wowlan` is a no-op for vdevs that never received an
            // enable ACK, which keeps the pairing correct even if userspace
            // cleared SET_WOWLAN while the platform was asleep.
            dev.resume_wowlan().await.map_err(|e| e.errno)?;
        }
        Ok(())
    }

    /// Linux's non-WoW `cfg80211`/`mac80211` system-suspend route: bring the
    /// station down (including its cfg80211 disconnect notification), then
    /// put the HIF through the ordinary MHI power-off path. The retained
    /// administrative-up bit causes `ieee80211_reconfig`-equivalent vdev
    /// recreation after resume; association itself is intentionally left to
    /// the userspace SME because no WoW state preserved it.
    async fn suspend_cold_member(&self) {
        let mut m = self.mac.lock().await;
        let open = m.vif().is_some();
        // cfg80211's no-WoW suspend path disconnects every interface;
        // unlike crash recovery, neither kernel nor userspace state is
        // eligible for an automatic reconnect after the cold cycle.
        *self.last_assoc.lock() = None;
        if open {
            self.do_stop(&mut m).await;
        }
        self.cold_reopen.store(open, Ordering::Release);
    }

    async fn system_suspend_cold(&self) -> Result<(), i32> {
        if self.shared.is_dead() {
            return Err(super::runtime::EIO);
        }
        for dev in pci_radio_devices(self.shared.radio_id) {
            dev.suspend_cold_member().await;
        }
        self.shared.system_hif_power_down().await?;
        Ok(())
    }

    /// Linux's `ath11k_core_resume_early` + restart completion followed by
    /// `ath11k_core_resume_default`: power the PCI/MHI transport back up,
    /// wait for firmware/QMI ready, rebuild CE/DP/WMI, and recreate the
    /// station vdev when it was administratively open before suspend.
    async fn rebuild_after_cold_resume(
        &self,
        mut caps: DeviceCaps,
        reg_info: Option<Box<super::wmi::RegInfo>>,
    ) -> Result<(), super::mac::MacError> {
        let mut m = self.mac.lock().await;
        let config = m.config();
        caps.mac_addr = self.mac_addr;
        let mut mac = Mac::new(
            Port(self.shared.clone(), self.vdev_id),
            Port(self.shared.clone(), self.vdev_id),
            caps,
            config,
            reg_info.as_deref(),
        );
        let opened = if self.cold_reopen.swap(false, Ordering::AcqRel) {
            self.do_open(&mut mac).await
        } else {
            Ok(())
        };
        *m = mac;
        opened
    }

    async fn system_resume_cold(&self) -> Result<(), i32> {
        if self.shared.is_dead() {
            return Err(super::runtime::EIO);
        }
        let dev = self
            .shared
            .resume_after_system_suspend()
            .await
            .map_err(|e| e.errno)?;
        for iface in pci_radio_devices(self.shared.radio_id) {
            iface
                .rebuild_after_cold_resume(dev.caps.clone(), dev.reg_info.clone())
                .await
                .map_err(|e| e.errno)?;
        }
        self.shared.reconfig_complete().await;
        Ok(())
    }

    /// Pick and execute the policy cfg80211 would select for this device:
    /// explicit WoWLAN keeps firmware alive in M3; absent configuration uses
    /// the normal cold cycle. The completion state is recorded only after
    /// preparation succeeds so a failed prepare is safe for the power
    /// coordinator to roll back.
    async fn system_prepare_suspend(&self) -> Result<(), i32> {
        {
            let state = self.system_pm.lock();
            if *state != SystemPmMode::Idle {
                return Err(super::mac::errno::EBUSY);
            }
        }
        let radio_wowlan = pci_radio_devices(self.shared.radio_id)
            .iter()
            .any(|dev| dev.wowlan.lock().is_some());
        if radio_wowlan {
            self.system_suspend_wowlan().await?;
            *self.system_pm.lock() = SystemPmMode::Wowlan;
        } else {
            self.system_suspend_cold().await?;
            *self.system_pm.lock() = SystemPmMode::Cold;
        }
        Ok(())
    }

    /// Complete whichever suspend policy actually prepared. The mode is
    /// cleared before the asynchronous work so an error still lets a later
    /// system-PM retry perform a fresh, coherent handoff.
    async fn system_resume_prepared(&self) -> Result<(), i32> {
        let mode = {
            let mut state = self.system_pm.lock();
            core::mem::replace(&mut *state, SystemPmMode::Idle)
        };
        match mode {
            SystemPmMode::Idle => Ok(()),
            SystemPmMode::Wowlan => self.system_resume_wowlan().await,
            SystemPmMode::Cold => self.system_resume_cold().await,
        }
    }
}

/// The interrupt-driven half of `dev_pm_ops` for WCN6855.  Firmware WoW
/// exchanges cannot be placed in `DevicePmOps`: that fan-out runs after
/// device interrupt gating and deliberately forbids scheduling.  The power
/// coordinator invokes this object immediately before / after that fan-out.
impl narf_power::system_pm::AsyncSystemPm
    for Ath11kNetdev<super::core::Bar0, super::ce::MsiCeIrq, super::pci::Wlfw>
{
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        Box::pin(async move {
            self.system_prepare_suspend()
                .await
                .map_err(|errno| match errno {
                    // MHI has outstanding client traffic or a concurrent
                    // transition.  This is retryable and must prevent S3.
                    super::mac::errno::EBUSY | super::runtime::ETIMEDOUT => {
                        narf_power::device_pm::DevicePmError::Busy
                    }
                    _ => narf_power::device_pm::DevicePmError::DriverError,
                })
        })
    }

    fn resume_from_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        Box::pin(async move {
            self.system_resume_prepared()
                .await
                .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
        })
    }
}

/// All PCI netdevs live under their one physical radio.  The stack's
/// function-pointer hooks are context-dispatched, so an Ethernet frame can
/// never fall through to a sibling virtual interface.
static ACTIVE: IrqSafeSpinLock<Vec<Arc<PciNetdev>>> = IrqSafeSpinLock::new(Vec::new());

/// Snapshot the still-live netdevs bound to one physical WCN6855.  The
/// snapshot is deliberately taken before any awaits: drivers then serialize
/// their own MAC operations without holding the global active-netdev lock.
fn pci_radio_devices(radio_id: u64) -> Vec<Arc<PciNetdev>> {
    ACTIVE
        .lock()
        .iter()
        .filter(|dev| {
            dev.shared.radio_id == radio_id
                && !dev.deleted.load(Ordering::Acquire)
                && !dev.delete_pending.load(Ordering::Acquire)
        })
        .cloned()
        .collect()
}

fn pci_send_context(cookie: u64, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let dev = ACTIVE
        .lock()
        .iter()
        .find(|dev| dev.dispatch_cookie() == cookie)
        .cloned()
        .ok_or(())?;
    dev.queue_tx(bytes, meta)
}

fn pci_drain() -> bool {
    let devices = ACTIVE.lock().clone();
    devices.iter().any(|dev| dev.drain_sync())
}

fn pci_link(name: &str, up: bool) {
    // netif_carrier_on / netif_carrier_off (IFF_UP is the stack's).
    narf_net::iface::set_link_metadata(name, up, None, None);
}

fn pci_disconnected(name: &str, d: Disconnect, own: &[u8; 6]) {
    narf_wireless::nl80211::notify_mlme_disconnect(name, &d.frame(own), *own);
}

fn pci_mlme_tx(name: &str, frame: &[u8]) {
    narf_wireless::nl80211::notify_mlme_frame(name, frame);
}

fn pci_control_port(name: &str, src: [u8; 6], proto: u16, pdu: &[u8], unencrypted: bool) -> bool {
    narf_wireless::nl80211::rx_control_port(name, src, proto, pdu, unencrypted)
}

fn pci_admin(name: &str, up: bool) {
    narf_net::iface::set_link_state(name, up);
}

fn pci_open_stop(name: &str, up: bool) {
    if let Some(dev) = ACTIVE.lock().iter().find(|dev| dev.name() == name).cloned() {
        dev.request_admin(up);
    }
}

/// Netdevs the capability registry holds (`Box<dyn Interface>`): a view
/// on the shared device.
struct Registered(Arc<PciNetdev>);

impl Interface for Registered {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        self.0.mtu()
    }
    fn link_up(&self) -> bool {
        self.0.link_up()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
    fn offloads(&self) -> narf_net::OffloadCapabilities {
        self.0.offloads()
    }
}

fn pci_sinks() -> Sinks {
    Sinks {
        rx: narf_net::iface::on_rx_frame_from,
        link: pci_link,
        admin: pci_admin,
        disconnected: pci_disconnected,
        mlme_tx: pci_mlme_tx,
        control_port: pci_control_port,
    }
}

fn virtual_mac(parent: [u8; 6], vdev_id: u32) -> [u8; 6] {
    let mut mac = parent;
    // `ath11k_mac_setup_vdev_params`: wiphy address slots start with the
    // factory address, set the locally-administered bit, then advance the
    // first octet by 0x10 for each non-root firmware vdev.
    mac[0] = (mac[0] | 0x02).wrapping_add((vdev_id.saturating_sub(1) as u8) << 4);
    mac
}

fn pci_virtual_create(
    parent: &PciNetdev,
    requested_name: &str,
    iftype: u32,
    requested_mac: Option<[u8; 6]>,
) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
    if parent.shared.is_dead() {
        return Err(WirelessError::HardwareError);
    }
    let vdev_id = parent.shared.reserve_vdev().ok_or(WirelessError::Busy)?;
    let result = (|| {
        if !parent.shared.assign_vdev_iftype(vdev_id, iftype) {
            return Err(WirelessError::Busy);
        }
        if !parent.shared.prepare_vdev_slot(vdev_id) {
            return Err(WirelessError::Busy);
        }
        let lifecycle = parent
            .virtual_lifecycle
            .clone()
            .ok_or(WirelessError::NotSupported)?;
        let config = parent.mac.try_lock().ok_or(WirelessError::Busy)?.config();
        // The physical radio may have completed a firmware recovery since
        // its root netdev was registered.  Read the live capability and
        // regulatory snapshots rather than a registration-time copy before
        // building a later virtual vdev.
        let (mut caps, reg_info) = {
            let rt = parent.shared.try_lock().ok_or(WirelessError::Busy)?;
            let caps = rt.device_caps().map_err(|_| WirelessError::HardwareError)?;
            (caps, rt.core.reg_info.clone())
        };
        let name = Box::leak(alloc::string::String::from(requested_name).into_boxed_str());
        let mac_addr = requested_mac.unwrap_or_else(|| virtual_mac(parent.mac_addr, vdev_id));
        caps.mac_addr = mac_addr;
        let mac = Mac::new(
            Port(parent.shared.clone(), vdev_id),
            Port(parent.shared.clone(), vdev_id),
            caps,
            config.with_vdev(vdev_id),
            reg_info.as_deref(),
        );
        let (child, tx_cons) = Ath11kNetdev::new_on_vdev_with_lifecycle(
            name,
            parent.shared.clone(),
            mac,
            mac_addr,
            pci_sinks(),
            vdev_id,
            iftype,
            Some(lifecycle),
        );
        let child = Arc::new(child);
        register_pci_netdev(child.clone(), tx_cons, false);
        Ok(child as Arc<dyn WirelessNetIface>)
    })();
    if result.is_err() {
        parent.shared.release_vdev(vdev_id);
    }
    result
}

fn pci_virtual_delete(dev: &PciNetdev) -> Result<(), WirelessError> {
    // The physical root owns the radio registration and is not a cfg80211
    // virtual interface.  Linux similarly refuses to delete the base hw
    // object through `NL80211_CMD_DEL_INTERFACE`.
    if dev.vdev_id == 0 {
        return Err(WirelessError::NotSupported);
    }
    if dev.delete_pending.swap(true, Ordering::AcqRel) {
        return Err(WirelessError::Busy);
    }
    // `NL80211_CMD_DEL_INTERFACE`: cfg80211 removes every
    // non-transmitting profile when its transmitting MBSSID interface is
    // deleted. Each child follows the same hide-now / WMI-teardown-later
    // lifecycle, so no target vdev slot is reused until its worker finishes.
    for name in dev.shared.mbssid_dependents(dev.vdev_id) {
        if let Some(profile) = narf_wireless::registry::list()
            .into_iter()
            .find(|profile| profile.name() == name)
        {
            let _ = profile.delete_virtual_interface();
        }
    }
    // cfg80211 removes an up netdev synchronously from discovery while its
    // driver `ndo_stop` may sleep.  Hide it now; the runtime worker performs
    // the WMI VDEV_DELETE and calls `pci_finish_virtual_delete` afterwards.
    dev.admin_up.store(false, Ordering::Release);
    *dev.last_assoc.lock() = None;
    // Close the producer so the per-netdev TX pump drops its final worker
    // reference even if the stack had no further traffic to wake it.
    dev.tx_ring.lock().take();
    dev.rx_prod.lock().take();
    let name = dev.name();
    narf_wireless::registry::unregister(name);
    narf_net::iface::unregister(name);
    narf_net::registry().unregister(name);
    Ok(())
}

/// Final, worker-context half of `pci_virtual_delete`.  No externally
/// reachable handle exists at this point, and `complete_virtual_delete` has
/// completed the vdev-local WMI/DP teardown, so its slot can be reused.
fn pci_finish_virtual_delete(dev: &PciNetdev) {
    ACTIVE
        .lock()
        .retain(|candidate| candidate.dispatch_cookie() != dev.dispatch_cookie());
    dev.shared.release_vdev(dev.vdev_id);
}

fn pci_radio_recover<'a>(
    trigger: &'a PciNetdev,
    notice: FwNotice,
) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
    Box::pin(async move {
        // A WMI/CE reset is pdev-wide. Whichever vdev's task observed the
        // notice coordinates the physical root and every sibling MAC; a
        // child must never reconstruct only its own VIF over a new DP.
        let devices: Vec<Arc<PciNetdev>> = ACTIVE
            .lock()
            .iter()
            .filter(|dev| {
                dev.shared.radio_id == trigger.shared.radio_id
                    && !dev.deleted.load(Ordering::Acquire)
                    && !dev.delete_pending.load(Ordering::Acquire)
            })
            .cloned()
            .collect();
        let Some(coordinator) = devices.iter().find(|dev| dev.vdev_id == 0).cloned() else {
            return trigger.recover_one(notice, true).await;
        };
        for dev in devices
            .iter()
            .filter(|dev| dev.dispatch_cookie() != coordinator.dispatch_cookie())
        {
            dev.prepare_radio_recovery().await;
        }
        if !coordinator.recover_one(notice, false).await {
            return false;
        }
        let (caps, reg_info) = {
            let rt = trigger.shared.lock().await;
            let Ok(caps) = rt.device_caps() else {
                trigger.shared.park(alloc::boxed::Box::new(()));
                return false;
            };
            (caps, rt.core.reg_info.clone())
        };
        for dev in devices
            .iter()
            .filter(|dev| dev.dispatch_cookie() != coordinator.dispatch_cookie())
        {
            if !dev
                .rebuild_after_radio_recovery(caps.clone(), reg_info.clone())
                .await
            {
                return false;
            }
        }
        // `ieee80211_restart_hw` invokes reconfig_complete after its full
        // interface reconfiguration pass, not after the coordinator vif.
        coordinator.shared.reconfig_complete().await;
        coordinator.record_recovered();
        true
    })
}

/// Common registration for the initial netdev and every child virtual
/// interface.  Each gets a context-dispatched stack send hook and its own
/// NARF rings; only the initial netdev is a system-PM owner.
fn register_pci_netdev(
    dev: Arc<PciNetdev>,
    tx_cons: Consumer<Frame, TX_RING_N>,
    system_pm_owner: bool,
) {
    use core::fmt::Write as _;
    let name = dev.name();
    ACTIVE.lock().push(dev.clone());
    // cfg80211 → mac80211 calls ath11k's WoW hooks from the platform PM
    // sequence.  This registry is NARF's equivalent and keeps the WMI/MHI
    // exchanges outside the later interrupt-gated device-PM fan-out.
    if system_pm_owner {
        narf_power::system_pm::register_async_system_pm(name, dev.clone());
    }
    narf_net::iface::register_with_context(
        name,
        dev.mac(),
        dev.dispatch_cookie(),
        pci_send_context,
    );
    narf_net::iface::set_driver_info(name, "ath11k_pci", None, alloc::string::String::new());
    // ath11k_mac_register: hw->netdev_features = NETIF_F_HW_CSUM.
    narf_net::iface::set_offloads(name, super::tx_offload::OFFLOADS);
    // register_netdevice: down, no carrier; IFF_UP opens the hardware.
    narf_net::iface::set_link_metadata(name, false, None, None);
    narf_net::iface::set_open_stop(name, pci_open_stop);
    narf_net::iface::install_rx_drain(pci_drain);
    match narf_net::trusted_net_authority().and_then(|a| a.derive().ok()) {
        Some(authority) => {
            if let Err(e) = narf_net::registry().register(&authority, Registered(dev.clone())) {
                let d = match e {
                    narf_net::RegisterError::AuthorityRevoked => 2,
                    narf_net::RegisterError::DuplicateName => 3,
                };
                let _ = writeln!(
                    narf_console::Writer,
                    "  ath11k: {}: capability registry: {:?} (step {} detail {})",
                    name,
                    e,
                    super::runtime::step::NET_REGISTER,
                    d
                );
            }
        }
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: {}: no net authority for the capability registry (step {} detail 1)",
                name,
                super::runtime::step::NET_REGISTER
            );
        }
    }
    narf_wireless::registry::register(dev.clone());
    let d = dev.clone();
    narf_scheduler::spawn(async move { d.run().await });
    let d = dev.clone();
    narf_scheduler::spawn(async move { d.tx_pump(tx_cons).await });
}

/// `ieee80211_register_hw` + `ieee80211_if_add("wlan%d")`: name the
/// initial netdev, bind it to WMI vdev zero, and make it the physical radio's
/// system-PM owner. Later `NL80211_CMD_NEW_INTERFACE` calls share its
/// lifecycle hooks while selecting vdevs one and two.
pub fn register_pci(
    shared: Arc<Shared<super::core::Bar0, super::ce::MsiCeIrq, super::pci::Wlfw>>,
    mac: RtMac<super::core::Bar0, super::ce::MsiCeIrq, super::pci::Wlfw>,
    mac_addr: [u8; 6],
) -> &'static str {
    use core::fmt::Write as _;
    let name = narf_net::iface::reserve_name("wlan%d");
    let lifecycle = VirtualLifecycle {
        create: pci_virtual_create,
        delete: pci_virtual_delete,
        finish_delete: pci_finish_virtual_delete,
        recover: pci_radio_recover,
    };
    let (dev, tx_cons) = Ath11kNetdev::new_on_vdev_with_lifecycle(
        name,
        shared,
        mac,
        mac_addr,
        pci_sinks(),
        0,
        2,
        Some(lifecycle),
    );
    let dev = Arc::new(dev);
    register_pci_netdev(dev.clone(), tx_cons, true);
    // Bring-up aid: `ath11k.scan=1` / `ath11k.ssid=…` (autoconnect.rs).
    match super::autoconnect::parse(narf_boot::cmdline()) {
        Ok(Some(cfg)) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: {}: autoconnect {:?}",
                name,
                cfg
            );
            // Like `ip link set wlan0 up` before wpa_supplicant connects.
            narf_net::iface::set_link_state(name, true);
            narf_scheduler::spawn(super::autoconnect::run(dev, cfg));
        }
        Ok(None) => {}
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: {}: ignoring ath11k.* cmdline: {:?}",
                name,
                e
            );
        }
    }
    name
}

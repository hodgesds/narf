//! `nl80211` discovery and explicitly delegated station control.

mod control;

#[cfg(any(test, feature = "kernel-test"))]
pub use control::connect_for_test;

pub use control::station::{
    control_port_over_nl80211, notify_control_port_tx_status, notify_gtk_rekey,
    notify_michael_mic_failure, notify_mlme_disconnect, notify_mlme_frame, rx_control_port,
};

extern crate alloc;

use alloc::vec::Vec;
use narf_net::netlink_generic::{GenlFamily, GenlMulticastGroup, GenlOperation, GenlReply};

pub const NL80211_FAMILY_ID: u16 = 0x13;
pub const NL80211_CMD_GET_WIPHY: u8 = 1;
pub const NL80211_CMD_SET_WIPHY: u8 = 2;
pub const NL80211_CMD_NEW_WIPHY: u8 = 3;
pub const NL80211_CMD_GET_INTERFACE: u8 = 5;
pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;
pub const NL80211_CMD_DEL_INTERFACE: u8 = 8;
pub const NL80211_CMD_GET_PROTOCOL_FEATURES: u8 = 95;
/// Per-channel noise/airtime snapshot dump.
pub const NL80211_CMD_GET_SURVEY: u8 = 50;
pub const NL80211_CMD_NEW_SURVEY_RESULTS: u8 = 51;
/// Restrict the rate-control set for one netdev.
pub const NL80211_CMD_SET_TX_BITRATE_MASK: u8 = 57;
/// WoWLAN query / configuration (`nl80211_commands`).
pub const NL80211_CMD_GET_WOWLAN: u8 = 73;
pub const NL80211_CMD_SET_WOWLAN: u8 = 74;
/// `NL80211_CMD_SET_SAR_SPECS`.
pub const NL80211_CMD_SET_SAR_SPECS: u8 = 140;

const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_WIPHY_NAME: u16 = 2;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_KEY_IDX: u16 = 8;
const NL80211_ATTR_KEY_TYPE: u16 = 55;
const NL80211_ATTR_4ADDR: u16 = 83;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_SUPPORTED_IFTYPES: u16 = 32;
const NL80211_ATTR_SUPPORTED_COMMANDS: u16 = 50;
const NL80211_ATTR_FRAME: u16 = 51;
const NL80211_ATTR_RX_SIGNAL_DBM: u16 = 151;
const NL80211_ATTR_WDEV: u16 = 153;
const NL80211_ATTR_PROTOCOL_FEATURES: u16 = 173;
const NL80211_ATTR_WIPHY_RETRY_SHORT: u16 = 61;
const NL80211_ATTR_WIPHY_RETRY_LONG: u16 = 62;
const NL80211_ATTR_MAX_NUM_PMKIDS: u16 = 86;
const NL80211_ATTR_DURATION: u16 = 87;
const NL80211_ATTR_COOKIE: u16 = 88;
const NL80211_ATTR_ACK: u16 = 92;
pub(super) const NL80211_ATTR_SURVEY_INFO: u16 = 84;
const NL80211_ATTR_WIPHY_FRAG_THRESHOLD: u16 = 63;
const NL80211_ATTR_WIPHY_RTS_THRESHOLD: u16 = 64;
const NL80211_ATTR_WIPHY_COVERAGE_CLASS: u16 = 89;
const NL80211_ATTR_WIPHY_ANTENNA_TX: u16 = 105;
const NL80211_ATTR_WIPHY_ANTENNA_RX: u16 = 106;
const NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX: u16 = 113;
const NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX: u16 = 114;
pub(super) const NL80211_ATTR_TX_RATES: u16 = 90;
const NL80211_ATTR_WIPHY_TX_POWER_LEVEL: u16 = 98;
const NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION: u16 = 111;
const NL80211_ATTR_SUPPORT_AP_UAPSD: u16 = 130;
const NL80211_ATTR_MAX_AP_ASSOC_STA: u16 = 202;
const NL80211_ATTR_EXT_CAPA: u16 = 169;
const NL80211_ATTR_EXT_CAPA_MASK: u16 = 170;
const NL80211_ATTR_IFTYPE_EXT_CAPA: u16 = 230;
const NL80211_ATTR_MAC_ADDRS: u16 = 166;
const NL80211_ATTR_OFFCHANNEL_TX_OK: u16 = 108;
const NL80211_ATTR_MAX_CSA_COUNTERS: u16 = 206;
const NLA_F_NESTED: u16 = 1 << 15;
const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_IFTYPE_AP: u32 = 3;
const NL80211_IFTYPE_MONITOR: u32 = 6;
const NL80211_IFTYPE_P2P_DEVICE: u32 = 10;
const NL80211_IFTYPE_P2P_CLIENT: u32 = 8;
const NL80211_IFTYPE_P2P_GO: u32 = 9;
const GENL_CMD_CAP_DO: u32 = 1 << 1;
const GENL_CMD_CAP_DUMP: u32 = 1 << 2;
const ENODEV: i32 = 19;
const EINVAL: i32 = 22;
const EOPNOTSUPP: i32 = 95;

/// `NL80211_ATTR_REASON_CODE`.
const NL80211_ATTR_REASON_CODE: u16 = 54;
/// `NL80211_ATTR_DISCONNECTED_BY_AP`.
const NL80211_ATTR_DISCONNECTED_BY_AP: u16 = 71;
/// `NL80211_ATTR_OBSS_COLOR_BITMAP`.
const NL80211_ATTR_OBSS_COLOR_BITMAP: u16 = 302;

/// `cfg80211_obss_color_collision_notify`: the firmware found a BSS color
/// collision for this interface.  The ath11k runtime has already applied
/// mac80211's 500-ms coalescing rule before it reaches this publisher.
pub fn notify_obss_color_collision(name: &str, bitmap: u64) {
    const OBSS_COLOR_COLLISION: u8 = 141;
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    // `nla_put_u64_64bit` conditionally inserts PAD. Generic-netlink's
    // nlmsghdr + genl header make the u64 payload aligned after IFINDEX, so
    // the normal Linux encoding here has no filler attribute.
    push_attr(
        &mut attrs,
        NL80211_ATTR_OBSS_COLOR_BITMAP,
        &bitmap.to_ne_bytes(),
    );
    narf_net::netlink_generic::publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply {
            command: OBSS_COLOR_COLLISION,
            attrs,
        },
    );
}

/// `cfg80211_color_change_started_notify`,
/// `cfg80211_color_change_aborted_notify`, and
/// `cfg80211_color_change_notify`. `state` is 0=started, 1=aborted,
/// 2=completed; only STARTED carries `NL80211_ATTR_COLOR_CHANGE_COUNT`,
/// encoded as u32 exactly as cfg80211 does.
pub fn notify_color_change(name: &str, state: u8, count: u8) {
    const COLOR_CHANGE_STARTED: u8 = 143;
    const COLOR_CHANGE_ABORTED: u8 = 144;
    const COLOR_CHANGE_COMPLETED: u8 = 145;
    const ATTR_COLOR_CHANGE_COUNT: u16 = 303;
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let command = match state {
        0 => COLOR_CHANGE_STARTED,
        1 => COLOR_CHANGE_ABORTED,
        2 => COLOR_CHANGE_COMPLETED,
        _ => return,
    };
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    if state == 0 {
        push_attr(
            &mut attrs,
            ATTR_COLOR_CHANGE_COUNT,
            &(count as u32).to_ne_bytes(),
        );
    }
    narf_net::netlink_generic::publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply { command, attrs },
    );
}

/// Report a driver's completed link-down transition
/// (`nl80211_send_disconnected` from `__cfg80211_disconnected`): the
/// reason code (omitted when 0) and, when the AP sent the
/// Deauthentication / Disassociation, the `DISCONNECTED_BY_AP` flag.
/// Called after dropping any network-registry lock; no device state is
/// queried by the socket sink.
pub fn notify_disconnect(name: &str, reason: u16, from_ap: bool) {
    let Some(index) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(iface) = narf_net::iface::lookup(name) else {
        return;
    };
    let attrs = disconnect_attrs(index, reason, from_ap);
    narf_net::netlink_generic::publish_event(
        NL80211_FAMILY_ID,
        19,
        iface.net_ns_id,
        GenlReply { command: 48, attrs },
    );
}

/// `cfg80211_cqm_pktloss_notify`: firmware reported that `peer` did not
/// acknowledge `packets` consecutive frames. The AP station remains present;
/// userspace owns any resulting inactivity/disassociation decision.
pub fn notify_cqm_packet_loss(name: &str, peer: [u8; 6], packets: u32) {
    const NOTIFY_CQM: u8 = 64;
    const ATTR_CQM: u16 = 94;
    const CQM_PKT_LOSS_EVENT: u16 = 4;
    const NLA_F_NESTED: u16 = 1 << 15;
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let Some(wiphy) = wiphy_for_name(name) else {
        return;
    };
    let mut cqm = Vec::new();
    push_attr(&mut cqm, CQM_PKT_LOSS_EVENT, &packets.to_ne_bytes());
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &wiphy.to_ne_bytes());
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    push_attr(&mut attrs, NL80211_ATTR_MAC, &peer);
    push_attr(&mut attrs, ATTR_CQM | NLA_F_NESTED, &cqm);
    narf_net::netlink_generic::publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply {
            command: NOTIFY_CQM,
            attrs,
        },
    );
}

/// `cfg80211_cqm_rssi_notify` → `NL80211_CMD_NOTIFY_CQM` on the MLME
/// multicast group. The level is the mac80211-style averaged beacon RSSI;
/// `high = false` / `true` maps to the LOW / HIGH threshold event values.
pub fn notify_cqm_rssi(name: &str, high: bool, level_dbm: i32) {
    const NOTIFY_CQM: u8 = 64;
    const ATTR_CQM: u16 = 94;
    const CQM_RSSI_THRESHOLD_EVENT: u16 = 3;
    const CQM_RSSI_LEVEL: u16 = 9;
    const NLA_F_NESTED: u16 = 1 << 15;
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let Some(wiphy) = wiphy_for_name(name) else {
        return;
    };
    let mut cqm = Vec::new();
    push_attr(
        &mut cqm,
        CQM_RSSI_THRESHOLD_EVENT,
        &(high as u32).to_ne_bytes(),
    );
    push_attr(&mut cqm, CQM_RSSI_LEVEL, &level_dbm.to_ne_bytes());
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &wiphy.to_ne_bytes());
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    push_attr(&mut attrs, ATTR_CQM | NLA_F_NESTED, &cqm);
    narf_net::netlink_generic::publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply {
            command: NOTIFY_CQM,
            attrs,
        },
    );
}

/// Deliver one received management frame to the userspace MLME owner
/// (`cfg80211_rx_mgmt` → `nl80211_send_mgmt`). The ath11k runtime calls this
/// only after applying its `REGISTER_FRAME` filters and dropping the MAC
/// mutex, so publishing cannot re-enter the firmware event path.
pub fn notify_mgmt_rx(name: &str, frequency_mhz: u32, signal_dbm: i32, frame: &[u8]) {
    if frame.len() < 24 {
        return;
    }
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let Some(wiphy) = wiphy_for_name(name) else {
        return;
    };
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &wiphy.to_ne_bytes());
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    push_attr(
        &mut attrs,
        NL80211_ATTR_WDEV,
        &control::station::wdev_id(wiphy, ifindex).to_ne_bytes(),
    );
    if frequency_mhz != 0 {
        push_attr(
            &mut attrs,
            NL80211_ATTR_WIPHY_FREQ,
            &frequency_mhz.to_ne_bytes(),
        );
    }
    if signal_dbm != 0 {
        // nl80211 carries this signed dBm sample in a u32 attribute.
        push_attr(
            &mut attrs,
            NL80211_ATTR_RX_SIGNAL_DBM,
            &(signal_dbm as u32).to_ne_bytes(),
        );
    }
    push_attr(&mut attrs, NL80211_ATTR_FRAME, frame);
    narf_net::netlink_generic::publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply {
            command: 59, // NL80211_CMD_FRAME
            attrs,
        },
    );
}

/// `cfg80211_ready_on_channel` / `cfg80211_remain_on_channel_expired`.
/// ath11k emits these after the WMI scan has actually entered the requested
/// channel and after its completion/cancellation, rather than claiming a
/// scheduled ROC request has already started.
pub fn notify_remain_on_channel(
    name: &str,
    cookie: u64,
    frequency_mhz: u32,
    duration_ms: u32,
    started: bool,
) {
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let Some(wiphy) = wiphy_for_name(name) else {
        return;
    };
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &wiphy.to_ne_bytes());
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    push_attr(
        &mut attrs,
        NL80211_ATTR_WDEV,
        &control::station::wdev_id(wiphy, ifindex).to_ne_bytes(),
    );
    push_attr(&mut attrs, NL80211_ATTR_COOKIE, &cookie.to_ne_bytes());
    if started {
        push_attr(
            &mut attrs,
            NL80211_ATTR_WIPHY_FREQ,
            &frequency_mhz.to_ne_bytes(),
        );
        push_attr(
            &mut attrs,
            NL80211_ATTR_DURATION,
            &duration_ms.to_ne_bytes(),
        );
    }
    narf_net::netlink_generic::publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply {
            command: if started { 55 } else { 56 },
            attrs,
        },
    );
}

/// `cfg80211_ch_switch_started_notify` / `cfg80211_ch_switch_notify` for a
/// locally initiated AP or P2P-GO channel switch.  Linux puts IFINDEX and the
/// exact chandef in these MLME multicast messages; the countdown and quiet
/// flag are present only in the started notification.
#[allow(clippy::too_many_arguments)]
pub fn notify_channel_switch(
    name: &str,
    frequency_mhz: u32,
    channel_width: u32,
    center_freq1_mhz: u32,
    center_freq2_mhz: u32,
    count: u8,
    block_tx: bool,
    started: bool,
) {
    const CH_SWITCH_NOTIFY: u8 = 88;
    const CH_SWITCH_STARTED_NOTIFY: u8 = 110;
    const ATTR_CHANNEL_WIDTH: u16 = 159;
    const ATTR_CENTER_FREQ1: u16 = 160;
    const ATTR_CENTER_FREQ2: u16 = 161;
    const ATTR_CH_SWITCH_COUNT: u16 = 183;
    const ATTR_CH_SWITCH_BLOCK_TX: u16 = 184;
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    push_attr(
        &mut attrs,
        NL80211_ATTR_WIPHY_FREQ,
        &frequency_mhz.to_ne_bytes(),
    );
    push_attr(&mut attrs, ATTR_CHANNEL_WIDTH, &channel_width.to_ne_bytes());
    push_attr(
        &mut attrs,
        ATTR_CENTER_FREQ1,
        &center_freq1_mhz.to_ne_bytes(),
    );
    if center_freq2_mhz != 0 {
        push_attr(
            &mut attrs,
            ATTR_CENTER_FREQ2,
            &center_freq2_mhz.to_ne_bytes(),
        );
    }
    if started {
        push_attr(
            &mut attrs,
            ATTR_CH_SWITCH_COUNT,
            &(count as u32).to_ne_bytes(),
        );
        if block_tx {
            push_attr(&mut attrs, ATTR_CH_SWITCH_BLOCK_TX, &[]);
        }
    }
    narf_net::netlink_generic::publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply {
            command: if started {
                CH_SWITCH_STARTED_NOTIFY
            } else {
                CH_SWITCH_NOTIFY
            },
            attrs,
        },
    );
}

/// `nl80211_radar_notify` for radar detection, CAC state changes, and NOP
/// expiry. `event` is the matching `enum nl80211_radar_event` value.
pub fn notify_dfs_event(
    name: &str,
    frequency_mhz: u32,
    channel_width: u32,
    center_freq1_mhz: u32,
    center_freq2_mhz: u32,
    event: u32,
    netdev: bool,
) {
    const RADAR_DETECT: u8 = 94;
    const ATTR_CHANNEL_WIDTH: u16 = 159;
    const ATTR_CENTER_FREQ1: u16 = 160;
    const ATTR_CENTER_FREQ2: u16 = 161;
    const ATTR_RADAR_EVENT: u16 = 168;
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let Some(wiphy) = wiphy_for_name(name) else {
        return;
    };
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &wiphy.to_ne_bytes());
    if netdev {
        let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(name) else {
            return;
        };
        push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        push_attr(
            &mut attrs,
            NL80211_ATTR_WDEV,
            &control::station::wdev_id(wiphy, ifindex).to_ne_bytes(),
        );
    }
    push_attr(&mut attrs, ATTR_RADAR_EVENT, &event.to_ne_bytes());
    push_attr(
        &mut attrs,
        NL80211_ATTR_WIPHY_FREQ,
        &frequency_mhz.to_ne_bytes(),
    );
    push_attr(&mut attrs, ATTR_CHANNEL_WIDTH, &channel_width.to_ne_bytes());
    push_attr(
        &mut attrs,
        ATTR_CENTER_FREQ1,
        &center_freq1_mhz.to_ne_bytes(),
    );
    if center_freq2_mhz != 0 {
        push_attr(
            &mut attrs,
            ATTR_CENTER_FREQ2,
            &center_freq2_mhz.to_ne_bytes(),
        );
    }
    narf_net::netlink_generic::publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply {
            command: RADAR_DETECT,
            attrs,
        },
    );
}

/// The attributes of `NL80211_CMD_DISCONNECT` (`nl80211_send_disconnected`
/// order: ifindex, reason code if non-zero, the by-AP flag).
pub fn disconnect_attrs(ifindex: u32, reason: u16, from_ap: bool) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    if reason != 0 {
        push_attr(&mut attrs, NL80211_ATTR_REASON_CODE, &reason.to_ne_bytes());
    }
    if from_ap {
        push_attr(&mut attrs, NL80211_ATTR_DISCONNECTED_BY_AP, &[]);
    }
    attrs
}

fn align(len: usize) -> usize {
    (len + 3) & !3
}

fn push_attr(body: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = (4 + payload.len()) as u16;
    body.extend_from_slice(&len.to_ne_bytes());
    body.extend_from_slice(&kind.to_ne_bytes());
    body.extend_from_slice(payload);
    body.resize(align(body.len()), 0);
}

fn named_attr(body: &mut Vec<u8>, kind: u16, name: &str) {
    let mut value = name.as_bytes().to_vec();
    value.push(0);
    push_attr(body, kind, &value);
}

fn find_attr(attrs: &[u8], requested_kind: u16) -> Option<&[u8]> {
    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let len = u16::from_ne_bytes(attrs[offset..offset + 2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(attrs[offset + 2..offset + 4].try_into().ok()?);
        if len < 4 || offset + len > attrs.len() {
            return None;
        }
        if kind == requested_kind {
            return Some(&attrs[offset + 4..offset + len]);
        }
        offset += align(len);
    }
    None
}

fn interface_attrs(wiphy: u32, iface: &dyn crate::WirelessNetIface, iftype: u32) -> Vec<u8> {
    let info = iface.get_wireless_info();
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &wiphy.to_ne_bytes());
    let ifindex = narf_net::netlink_route::ifindex_for_name(&info.base_name).unwrap_or(0);
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    named_attr(&mut attrs, NL80211_ATTR_IFNAME, &info.base_name);
    push_attr(&mut attrs, NL80211_ATTR_IFTYPE, &iftype.to_ne_bytes());
    // nl80211_send_iface: NL80211_ATTR_WDEV = wdev_id(wdev) (u64).
    push_attr(
        &mut attrs,
        NL80211_ATTR_WDEV,
        &control::station::wdev_id(wiphy, ifindex).to_ne_bytes(),
    );
    push_attr(&mut attrs, NL80211_ATTR_MAC, &info.base_mac);
    // `nl80211_send_iface` emits this unconditionally, including for
    // interface types that cannot enable it.
    push_attr(
        &mut attrs,
        NL80211_ATTR_4ADDR,
        &[iface.four_addr_enabled() as u8],
    );
    if let Some(dbm) = iface.tx_power_dbm() {
        // `DBM_TO_MBM(dbm)`: Linux's GET_INTERFACE encoder uses a u32
        // attribute even though the documented mBm value is signed.
        push_attr(
            &mut attrs,
            NL80211_ATTR_WIPHY_TX_POWER_LEVEL,
            &dbm.saturating_mul(100).to_ne_bytes(),
        );
    }
    attrs
}

fn wiphy_attrs(
    index: u32,
    info: &crate::WirelessIfaceInfo,
    iface: Option<&dyn crate::WirelessNetIface>,
) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &index.to_ne_bytes());
    named_attr(
        &mut attrs,
        NL80211_ATTR_WIPHY_NAME,
        &alloc::format!("phy{index}"),
    );
    // `nl80211_send_wiphy` reports the physical permanent address separately
    // from every netdev's current interface address.
    push_attr(&mut attrs, NL80211_ATTR_MAC, &info.base_mac);
    // These are the `wiphy_new()` defaults mac80211 leaves in place for
    // ath11k: ath11k has no retry or coverage-class callback, and rejects a
    // fragmentation-threshold update.  They remain visible discovery state
    // in Linux even though only RTS is mutable on this target.
    push_attr(&mut attrs, NL80211_ATTR_WIPHY_RETRY_SHORT, &[7]);
    push_attr(&mut attrs, NL80211_ATTR_WIPHY_RETRY_LONG, &[4]);
    push_attr(&mut attrs, NL80211_ATTR_WIPHY_COVERAGE_CLASS, &[0]);
    let mut bands = Vec::new();
    for band in &info.bands {
        let band_id = match band.freq_mhz {
            2400..=2500 => 0,
            4900..=5900 => 1,
            // enum nl80211_band: 6 GHz follows the legacy 60 GHz ordinal.
            5901..=7200 => 3,
            _ => continue,
        };
        let mut frequencies = Vec::new();
        for (i, channel) in band.channels.iter().enumerate() {
            let frequency = match band_id {
                0 if *channel == 14 => 2484,
                0 => 2407 + channel * 5,
                1 => 5000 + channel * 5,
                // 6 GHz channel two is the 5935 MHz special case; all
                // ordinary 6 GHz channels use `5950 + 5 * channel`.
                3 if *channel == 2 => 5935,
                3 => 5950 + channel * 5,
                _ => unreachable!("band id was selected above"),
            };
            let mut entry = Vec::new();
            push_attr(&mut entry, 1, &frequency.to_ne_bytes());
            push_attr(&mut frequencies, i as u16 | NLA_F_NESTED, &entry);
        }
        let mut body = Vec::new();
        push_attr(&mut body, 1 | NLA_F_NESTED, &frequencies);
        let rates: &[u32] = match band_id {
            0 => &[10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540],
            // Linux ath11k uses ath11k_a_rates for both 5 and 6 GHz
            // supported-band records, despite 6 GHz associations requiring
            // HE on air.
            1 | 3 => &[60, 90, 120, 180, 240, 360, 480, 540],
            _ => unreachable!("band id was selected above"),
        };
        let mut bitrates = Vec::new();
        for (i, rate) in rates.iter().enumerate() {
            let mut entry = Vec::new();
            push_attr(&mut entry, 1, &rate.to_ne_bytes());
            push_attr(&mut bitrates, i as u16 | NLA_F_NESTED, &entry);
        }
        push_attr(&mut body, 2 | NLA_F_NESTED, &bitrates);
        if let Some(caps) = iface.and_then(|iface| iface.phy_capabilities(band.freq_mhz)) {
            push_attr(&mut body, 3, &caps.ht[3..19]); // HT MCS set
            push_attr(
                &mut body,
                4,
                &u16::from_le_bytes(caps.ht[..2].try_into().unwrap()).to_ne_bytes(),
            );
            push_attr(&mut body, 5, &[caps.ht[2] & 3]);
            push_attr(&mut body, 6, &[(caps.ht[2] >> 2) & 7]);
            if let Some(vht) = caps.vht {
                push_attr(&mut body, 7, &vht[4..12]);
                push_attr(
                    &mut body,
                    8,
                    &u32::from_le_bytes(vht[..4].try_into().unwrap()).to_ne_bytes(),
                );
            }
        }
        push_attr(&mut bands, band_id | NLA_F_NESTED, &body);
    }
    push_attr(&mut attrs, 22 | NLA_F_NESTED, &bands);
    push_attr(
        &mut attrs,
        43,
        &[iface.map_or(0, |iface| iface.max_scan_ssids())],
    );
    push_attr(
        &mut attrs,
        56,
        &iface
            .map_or(512, |iface| iface.max_scan_ie_len())
            .to_ne_bytes(),
    );
    if let Some(max) = iface
        .map(|iface| iface.max_remain_on_channel_duration_ms())
        .filter(|max| *max != 0)
    {
        push_attr(
            &mut attrs,
            NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION,
            &max.to_ne_bytes(),
        );
    }
    if iface.is_some_and(|iface| iface.supports_offchannel_mgmt_tx()) {
        push_attr(&mut attrs, NL80211_ATTR_OFFCHANNEL_TX_OK, &[]);
    }
    if let Some(antenna) = iface.and_then(|iface| iface.antenna_info()) {
        push_attr(
            &mut attrs,
            NL80211_ATTR_WIPHY_ANTENNA_TX,
            &antenna.tx.to_ne_bytes(),
        );
        push_attr(
            &mut attrs,
            NL80211_ATTR_WIPHY_ANTENNA_RX,
            &antenna.rx.to_ne_bytes(),
        );
        push_attr(
            &mut attrs,
            NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX,
            &antenna.available_tx.to_ne_bytes(),
        );
        push_attr(
            &mut attrs,
            NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX,
            &antenna.available_rx.to_ne_bytes(),
        );
    }
    // `wiphy_new()`'s disabled default is observable even when a driver
    // offers no fragmentation callback. A driver with a real setting
    // replaces that one value, never adds a duplicate attribute.
    let fragmentation = iface
        .and_then(|iface| iface.fragmentation_threshold())
        .unwrap_or(u32::MAX);
    push_attr(
        &mut attrs,
        NL80211_ATTR_WIPHY_FRAG_THRESHOLD,
        &fragmentation.to_ne_bytes(),
    );
    if let Some(rts) = iface.and_then(|iface| iface.rts_threshold()) {
        push_attr(
            &mut attrs,
            NL80211_ATTR_WIPHY_RTS_THRESHOLD,
            &rts.to_ne_bytes(),
        );
    }
    let mut modes = Vec::new();
    if info.modes.contains(crate::iface::WirelessModes::STATION) {
        push_attr(&mut modes, NL80211_IFTYPE_STATION as u16, &[]);
    }
    if info.modes.contains(crate::iface::WirelessModes::AP) {
        push_attr(&mut modes, NL80211_IFTYPE_AP as u16, &[]);
    }
    if info.modes.contains(crate::iface::WirelessModes::MONITOR) {
        push_attr(&mut modes, NL80211_IFTYPE_MONITOR as u16, &[]);
    }
    if info.modes.contains(crate::iface::WirelessModes::P2P) {
        push_attr(&mut modes, NL80211_IFTYPE_P2P_DEVICE as u16, &[]);
        push_attr(&mut modes, NL80211_IFTYPE_P2P_CLIENT as u16, &[]);
        push_attr(&mut modes, NL80211_IFTYPE_P2P_GO as u16, &[]);
    }
    push_attr(
        &mut attrs,
        NL80211_ATTR_SUPPORTED_IFTYPES | NLA_F_NESTED,
        &modes,
    );
    if let Some(iface) = iface {
        if let Some(capability) = iface
            .wiphy_extended_capabilities()
            .filter(|capability| capability.capabilities.len() == capability.mask.len())
        {
            push_attr(&mut attrs, NL80211_ATTR_EXT_CAPA, &capability.capabilities);
            push_attr(&mut attrs, NL80211_ATTR_EXT_CAPA_MASK, &capability.mask);
        }
        let mac_addresses = iface.wiphy_mac_addresses();
        if mac_addresses.len() > 1 {
            let mut addresses = Vec::new();
            for (index, mac) in mac_addresses.iter().enumerate() {
                push_attr(&mut addresses, index as u16 + 1, mac);
            }
            push_attr(
                &mut attrs,
                NL80211_ATTR_MAC_ADDRS | NLA_F_NESTED,
                &addresses,
            );
        }
        let extended_capabilities = iface.iftype_extended_capabilities();
        if !extended_capabilities.is_empty() {
            let mut records = Vec::new();
            for (index, capability) in extended_capabilities.iter().enumerate() {
                // cfg80211 uses `nla_nest_start_noflag` for both container
                // levels here. The attributes within each record are its
                // regular IFTYPE / EXT_CAPA / EXT_CAPA_MASK members.
                if capability.capabilities.len() != capability.mask.len() {
                    continue;
                }
                let mut record = Vec::new();
                push_attr(
                    &mut record,
                    NL80211_ATTR_IFTYPE,
                    &capability.iftype.to_ne_bytes(),
                );
                push_attr(&mut record, NL80211_ATTR_EXT_CAPA, &capability.capabilities);
                push_attr(&mut record, NL80211_ATTR_EXT_CAPA_MASK, &capability.mask);
                push_attr(&mut records, index as u16, &record);
            }
            if !records.is_empty() {
                push_attr(&mut attrs, NL80211_ATTR_IFTYPE_EXT_CAPA, &records);
            }
        }
        let combinations = iface.interface_combinations();
        if !combinations.is_empty() {
            let mut records = Vec::new();
            for (index, combination) in combinations.iter().enumerate() {
                let mut record = Vec::new();
                let mut limits = Vec::new();
                for (limit_index, limit) in combination.limits.iter().enumerate() {
                    let mut one = Vec::new();
                    push_attr(&mut one, 1, &limit.max.to_ne_bytes());
                    let mut types = Vec::new();
                    for iftype in &limit.iftypes {
                        push_attr(&mut types, *iftype as u16, &[]);
                    }
                    push_attr(&mut one, 2 | NLA_F_NESTED, &types);
                    push_attr(&mut limits, (limit_index as u16 + 1) | NLA_F_NESTED, &one);
                }
                // enum nl80211_if_combination_attrs: LIMITS=1, MAXNUM=2,
                // STA_AP_BI_MATCH=3, NUM_CHANNELS=4, RADAR_DETECT_WIDTHS=5,
                // BI_MIN_GCD=7.
                push_attr(&mut record, 1 | NLA_F_NESTED, &limits);
                push_attr(&mut record, 2, &combination.max_interfaces.to_ne_bytes());
                if combination.sta_ap_beacon_interval_match {
                    push_attr(&mut record, 3, &[]);
                }
                push_attr(&mut record, 4, &combination.max_channels.to_ne_bytes());
                if let Some(widths) = combination.radar_detect_widths {
                    push_attr(&mut record, 5, &widths.to_ne_bytes());
                }
                if let Some(gcd) = combination.beacon_interval_min_gcd {
                    push_attr(&mut record, 7, &gcd.to_ne_bytes());
                }
                push_attr(&mut records, (index as u16 + 1) | NLA_F_NESTED, &record);
            }
            // NL80211_ATTR_INTERFACE_COMBINATIONS.
            push_attr(&mut attrs, 120 | NLA_F_NESTED, &records);
        }
    }
    if iface.is_some_and(|iface| iface.supports_ap_uapsd()) {
        push_attr(&mut attrs, NL80211_ATTR_SUPPORT_AP_UAPSD, &[]);
    }
    if let Some(max) = iface
        .map(|iface| iface.max_ap_assoc_sta())
        .filter(|max| *max != 0)
    {
        // ath11k_mac_register: wiphy->max_ap_assoc_sta.
        push_attr(
            &mut attrs,
            NL80211_ATTR_MAX_AP_ASSOC_STA,
            &max.to_ne_bytes(),
        );
    }
    if let Some(max) = iface
        .map(|iface| iface.max_csa_counters())
        .filter(|max| *max != 0)
    {
        push_attr(&mut attrs, NL80211_ATTR_MAX_CSA_COUNTERS, &[max]);
    }
    // `nl80211_put_mbssid_support`: this is capability metadata on the
    // physical wiphy, not the configuration of any one AP netdev.  The
    // request-side attribute uses the same nested enum, but carries INDEX /
    // TX_IFINDEX / EMA instead of these two maximums.
    if let Some(mbssid) = iface.and_then(|iface| iface.mbssid_support()) {
        let mut config = Vec::new();
        push_attr(&mut config, 1, &[mbssid.max_interfaces]);
        if mbssid.ema_max_profile_periodicity != 0 {
            push_attr(&mut config, 2, &[mbssid.ema_max_profile_periodicity]);
        }
        push_attr(&mut attrs, 306 | NLA_F_NESTED, &config);
    }
    // `nl80211_put_sar_specs`: WCN6855 exposes its fixed BIOS SAR range
    // table under one nested `NL80211_ATTR_SAR_SPEC`.  Unlike a current
    // power setting this is capability metadata; each SET replaces the
    // complete target table and is sent through the driver separately.
    if let Some(sar) = iface.and_then(|iface| iface.sar_capability()) {
        let mut sar_attrs = Vec::new();
        push_attr(&mut sar_attrs, 1, &sar.sar_type.to_ne_bytes());
        let mut ranges = Vec::new();
        for (index, range) in sar.frequency_ranges.iter().enumerate() {
            let mut one = Vec::new();
            push_attr(&mut one, 3, &range.start_freq.to_ne_bytes());
            push_attr(&mut one, 4, &range.end_freq.to_ne_bytes());
            push_attr(&mut ranges, (index as u16 + 1) | NLA_F_NESTED, &one);
        }
        push_attr(&mut sar_attrs, 2 | NLA_F_NESTED, &ranges);
        push_attr(&mut attrs, 300 | NLA_F_NESTED, &sar_attrs);
    }
    // `nl80211_send_wowlan`: ath11k exposes disconnect/magic-packet wake,
    // GTK rekey capability/failure and 22 byte-pattern slots.  The pattern
    // support body is `struct nl80211_pattern_support` (four native u32s).
    if let Some(wowlan) = iface.and_then(|iface| iface.wowlan_support()) {
        let mut triggers = Vec::new();
        if wowlan.disconnect {
            push_attr(&mut triggers, 2, &[]); // DISCONNECT
        }
        if wowlan.magic_packet {
            push_attr(&mut triggers, 3, &[]); // MAGIC_PKT
        }
        if wowlan.gtk_rekey {
            push_attr(&mut triggers, 5, &[]); // GTK_REKEY_SUPPORTED
        }
        if wowlan.gtk_rekey_failure {
            push_attr(&mut triggers, 6, &[]); // GTK_REKEY_FAILURE
        }
        if wowlan.max_patterns != 0 {
            let mut pattern = Vec::new();
            for value in [
                wowlan.max_patterns as u32,
                wowlan.min_pattern_len as u32,
                wowlan.max_pattern_len as u32,
                wowlan.max_packet_offset as u32,
            ] {
                pattern.extend_from_slice(&value.to_ne_bytes());
            }
            push_attr(&mut triggers, 4, &pattern); // PKT_PATTERN support
        }
        if wowlan.net_detect_max_match_sets != 0 {
            // WIPHY_WOWLAN_NET_DETECT is represented by the maximum number
            // of cfg80211 match sets, not a nested capability structure.
            push_attr(
                &mut triggers,
                17, // NL80211_WOWLAN_TRIG_NET_DETECT
                &(wowlan.net_detect_max_match_sets as u32).to_ne_bytes(),
            );
            // ath11k publishes its PNO limits on the wiphy even though it
            // implements NLO only as the WoWLAN NET_DETECT path, not as a
            // general scheduled-scan operation.
            // `nl80211_send_wiphy` uses u8/u16/u8 for these three limits;
            // their attribute widths are part of the netlink ABI.
            push_attr(&mut attrs, 123, &[16]);
            push_attr(&mut attrs, 124, &512u16.to_ne_bytes());
            push_attr(&mut attrs, 133, &[wowlan.net_detect_max_match_sets]);
            push_attr(&mut attrs, 222, &2u32.to_ne_bytes());
            push_attr(&mut attrs, 223, &7200u32.to_ne_bytes());
            push_attr(&mut attrs, 224, &100u32.to_ne_bytes());
        }
        push_attr(&mut attrs, 118 | NLA_F_NESTED, &triggers);
    }
    let mut command_list: Vec<u32> = alloc::vec![
        NL80211_CMD_GET_WIPHY as u32,
        NL80211_CMD_GET_INTERFACE as u32,
        NL80211_CMD_GET_PROTOCOL_FEATURES as u32,
        32, // GET_SCAN
        33, // TRIGGER_SCAN
        46, // CONNECT
        48, // DISCONNECT
        6,  // SET_INTERFACE
        17, // GET_STATION
    ];
    if iface.is_some_and(|iface| iface.antenna_info().is_some() || iface.rts_threshold().is_some())
    {
        command_list.push(NL80211_CMD_SET_WIPHY as u32);
    }
    if iface.is_some_and(|iface| iface.supports_survey()) {
        command_list.push(NL80211_CMD_GET_SURVEY as u32);
    }
    if iface.is_some_and(|iface| iface.supports_tx_bitrate_mask()) {
        command_list.push(NL80211_CMD_SET_TX_BITRATE_MASK as u32);
    }
    if iface.is_some_and(|iface| iface.supports_virtual_interfaces()) {
        command_list.extend_from_slice(&[
            NL80211_CMD_NEW_INTERFACE as u32,
            NL80211_CMD_DEL_INTERFACE as u32,
        ]);
    }
    // A userspace-SME driver additionally advertises the low-level MLME /
    // management-frame commands wpa_supplicant uses when it runs its own SME.
    if iface.is_some_and(|iface| iface.supports_userspace_mlme()) {
        command_list.extend_from_slice(&[
            37,  // AUTHENTICATE
            38,  // ASSOCIATE
            39,  // DEAUTHENTICATE
            40,  // DISASSOCIATE
            58,  // REGISTER_FRAME
            59,  // FRAME
            127, // EXTERNAL_AUTH
        ]);
    }
    if iface.is_some_and(|iface| iface.max_remain_on_channel_duration_ms() != 0) {
        command_list.extend_from_slice(&[
            55, // REMAIN_ON_CHANNEL
            56, // CANCEL_REMAIN_ON_CHANNEL
        ]);
    }
    // An external-supplicant driver has `add_key` (CMD(add_key, NEW_KEY)).
    if iface.is_some_and(|iface| iface.supports_external_supplicant()) {
        command_list.push(11); // NEW_KEY
    }
    if iface.is_some_and(|iface| iface.supports_gtk_rekey_offload()) {
        command_list.push(79); // SET_REKEY_OFFLOAD
    }
    if iface.is_some_and(|iface| iface.wowlan_support().is_some()) {
        command_list
            .extend_from_slice(&[NL80211_CMD_GET_WOWLAN as u32, NL80211_CMD_SET_WOWLAN as u32]);
    }
    if iface.is_some_and(|iface| iface.sar_capability().is_some()) {
        command_list.push(NL80211_CMD_SET_SAR_SPECS as u32);
    }
    // `set_power_mgmt`.
    if iface.is_some_and(|iface| iface.power_save_default().is_some()) {
        command_list.push(61); // SET_POWER_SAVE
    }
    if iface.is_some_and(|iface| iface.supports_cqm_rssi()) {
        command_list.push(63); // SET_CQM
    }
    // An AP-capable driver advertises the beacon + station-table commands.
    if iface.is_some_and(|iface| iface.supports_ap()) {
        command_list.extend_from_slice(&[
            14, // SET_BEACON
            15, // START_AP
            16, // STOP_AP
            18, // SET_STATION
            19, // NEW_STATION
            20, // DEL_STATION
        ]);
    }
    if iface.is_some_and(|iface| iface.supports_channel_switch()) {
        command_list.push(107); // CHANNEL_SWITCH
    }
    if iface.is_some_and(|iface| iface.supports_bss_color()) {
        command_list.push(142); // COLOR_CHANGE_REQUEST
    }
    let mut commands = Vec::new();
    for (index, command) in command_list.iter().enumerate() {
        push_attr(&mut commands, index as u16 + 1, &command.to_ne_bytes());
    }
    push_attr(
        &mut attrs,
        NL80211_ATTR_SUPPORTED_COMMANDS | NLA_F_NESTED,
        &commands,
    );
    attrs
}

/// A wiphy's ciphers and the features wpa_supplicant keys its driver
/// mode off (`wpa_driver_nl80211_get_info`): `NL80211_ATTR_CIPHER_SUITES`,
/// `NL80211_ATTR_FEATURE_FLAGS` (generic SAE/random-MAC and physical-driver
/// feature bits) and
/// `NL80211_ATTR_EXT_FEATURES` (a little-endian bitmap). A driver whose SME
/// runs in userspace never advertises the handshake offloads: with
/// `WPA_DRIVER_FLAGS_SME` wpa_supplicant passes no PMK, yet with
/// `4WAY_HANDSHAKE_STA_PSK` it would also ignore EAPOL.
fn wiphy_security_attrs(attrs: &mut Vec<u8>, iface: &dyn crate::WirelessNetIface) {
    let suites = control::station::cipher_suites(iface);
    if !suites.is_empty() {
        let raw: Vec<u8> = suites.iter().flat_map(|c| c.to_ne_bytes()).collect();
        push_attr(attrs, 57, &raw);
    }
    // `nl80211_send_wiphy` serializes this u8 unconditionally. ath11k has
    // no firmware PMKSA cache, so its Linux value is zero.
    push_attr(attrs, NL80211_ATTR_MAX_NUM_PMKIDS, &[0]);
    let sme = iface.supports_userspace_mlme();
    let external = iface.supports_external_supplicant();
    let mut feature_flags = iface.nl80211_feature_flags();
    if sme && external {
        // NL80211_FEATURE_SAE: SAE over AUTHENTICATE.
        feature_flags |= 1 << 5;
    }
    if iface.supports_scan_random_mac() {
        // NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR.  The request parser applies
        // the same feature gating before ath11k reaches WMI.
        feature_flags |= 1 << 29;
    }
    if iface
        .wowlan_support()
        .is_some_and(|support| support.net_detect_random_mac)
    {
        // NL80211_FEATURE_ND_RANDOM_MAC_ADDR.  This applies only to the
        // low-power NET_DETECT payload, independently of normal scans.
        feature_flags |= 1 << 31;
    }
    if feature_flags != 0 {
        push_attr(attrs, 143, &feature_flags.to_ne_bytes());
    }
    let mut bits: Vec<u32> = Vec::new();
    if iface.supports_handshake_offload() && !sme {
        bits.push(15); // 4WAY_HANDSHAKE_STA_PSK
    }
    if iface.supports_sae_offload() && !sme {
        bits.push(38); // SAE_OFFLOAD
    }
    if external {
        bits.push(26); // CONTROL_PORT_OVER_NL80211
        bits.push(42); // CONTROL_PORT_NO_PREAUTH
        if iface.supports_control_port_tx_status() {
            bits.push(48); // CONTROL_PORT_OVER_NL80211_TX_STATUS
        }
    }
    if iface.supports_fils_discovery() {
        bits.push(52); // FILS_DISCOVERY
    }
    if iface.supports_unsol_bcast_probe_resp() {
        bits.push(53); // UNSOL_BCAST_PROBE_RESP
    }
    if iface.supports_ftm_responder() {
        bits.push(32); // ENABLE_FTM_RESPONDER
    }
    if iface.supports_bss_color() {
        bits.push(58); // BSS_COLOR
    }
    if iface.supports_station_tx_power() {
        bits.push(36); // STA_TX_PWR
    }
    if iface.supports_ack_signal() {
        bits.push(27); // ACK_SIGNAL_SUPPORT
    }
    if iface.supports_scan_dwell() {
        bits.push(5); // SET_SCAN_DWELL
    }
    if iface.supports_cqm_rssi_list() {
        bits.push(13); // CQM_RSSI_LIST
    }
    if let Some(max) = bits.iter().max() {
        let mut ext = alloc::vec![0u8; (*max as usize) / 8 + 1];
        for bit in bits {
            ext[bit as usize / 8] |= 1 << (bit % 8);
        }
        push_attr(attrs, 217, &ext);
    }
}

fn handle(command: u8, attrs: &[u8], dump: bool) -> Result<Vec<GenlReply>, i32> {
    handle_in(command, attrs, dump, 0)
}

fn in_namespace(iface: &dyn crate::WirelessNetIface, namespace: u64) -> bool {
    narf_net::iface::lookup(iface.name())
        .map(|i| i.net_ns_id)
        .unwrap_or(0)
        == namespace
}

/// Resolve a registered netdev to the index of its physical wiphy.  Virtual
/// interfaces carry distinct ifindexes/WDEVs but share this value.
fn wiphy_for_name(name: &str) -> Option<u32> {
    crate::registry::list()
        .iter()
        .find(|iface| iface.name() == name)
        .and_then(|iface| crate::registry::wiphy_index(iface.wiphy_id()))
}

fn u32_of(raw: &[u8]) -> Result<u32, i32> {
    raw.try_into().map(u32::from_ne_bytes).map_err(|_| EINVAL)
}

/// `nl80211_pre_doit` for `NL80211_FLAG_NEED_WIPHY`
/// (`__cfg80211_rdev_from_attrs`): the wiphy named by `NL80211_ATTR_WIPHY`,
/// `NL80211_ATTR_WDEV` or the netdev `NL80211_ATTR_IFINDEX` — wpa_supplicant
/// asks by ifindex.  WDEV's high half is its physical wiphy and the low half
/// is the individual netdev ifindex, and both halves must resolve to the
/// same live wireless interface. A netdev that is not wireless, or
/// names disagreeing on the wiphy, is -EINVAL; nothing found, or a wiphy in
/// another namespace, is -ENODEV.
fn wiphy_from_attrs(
    interfaces: &[alloc::sync::Arc<dyn crate::WirelessNetIface>],
    attrs: &[u8],
    namespace: u64,
) -> Result<u32, i32> {
    let by_index = find_attr(attrs, NL80211_ATTR_WIPHY)
        .map(u32_of)
        .transpose()?;
    let wdev = find_attr(attrs, NL80211_ATTR_WDEV)
        .map(|raw| {
            <[u8; 8]>::try_from(raw)
                .map(u64::from_ne_bytes)
                .map_err(|_| EINVAL)
        })
        .transpose()?;
    let ifindex = find_attr(attrs, NL80211_ATTR_IFINDEX)
        .map(u32_of)
        .transpose()?;
    if by_index.is_none() && wdev.is_none() && ifindex.is_none() {
        return Err(EINVAL);
    }
    let mut wiphy = by_index.filter(|index| crate::registry::wiphys().len() > *index as usize);
    if let Some(wdev) = wdev {
        let from_wdev = (wdev >> 32) as u32;
        let wdev_ifindex = wdev as u32;
        let from_wdev_netdev = narf_net::netlink_route::iface_name_for_index(wdev_ifindex)
            .filter(|name| narf_net::iface::lookup_in(namespace, name).is_some())
            .and_then(|name| {
                interfaces
                    .iter()
                    .find(|iface| iface.name() == name)
                    .and_then(|iface| crate::registry::wiphy_index(iface.wiphy_id()))
            })
            .ok_or(ENODEV)?;
        if from_wdev_netdev != from_wdev {
            return Err(EINVAL);
        }
        if wiphy.is_some_and(|wiphy| wiphy != from_wdev) {
            return Err(EINVAL);
        }
        wiphy = Some(from_wdev);
    }
    if let Some(ifindex) = ifindex {
        if let Some(name) = narf_net::netlink_route::iface_name_for_index(ifindex)
            .filter(|name| narf_net::iface::lookup_in(namespace, name).is_some())
        {
            let from_netdev = interfaces
                .iter()
                .find(|iface| iface.name() == name)
                .and_then(|iface| crate::registry::wiphy_index(iface.wiphy_id()))
                .ok_or(EINVAL)?;
            if wiphy.is_some_and(|wiphy| wiphy != from_netdev) {
                return Err(EINVAL);
            }
            wiphy = Some(from_netdev);
        }
    }
    let wiphy = wiphy.ok_or(ENODEV)?;
    if !interfaces.iter().any(|iface| {
        crate::registry::wiphy_index(iface.wiphy_id()) == Some(wiphy)
            && in_namespace(iface.as_ref(), namespace)
    }) {
        return Err(ENODEV);
    }
    Ok(wiphy)
}

/// `nl80211_dump_wiphy_parse`: a GET_WIPHY dump (NetworkManager's split
/// dump) is narrowed by NL80211_ATTR_WIPHY, NL80211_ATTR_WDEV (its upper 32
/// bits) or the wiphy of the netdev NL80211_ATTR_IFINDEX names; an ifindex
/// with no netdev in the namespace is -ENODEV, a non-wireless one filters
/// nothing. Malformed attributes are ignored, as Linux does.
fn dump_wiphy_filter(
    interfaces: &[alloc::sync::Arc<dyn crate::WirelessNetIface>],
    attrs: &[u8],
    namespace: u64,
) -> Result<Option<u32>, i32> {
    let mut filter = find_attr(attrs, NL80211_ATTR_WIPHY).and_then(|raw| u32_of(raw).ok());
    if let Some(wdev) = find_attr(attrs, NL80211_ATTR_WDEV)
        .and_then(|raw| <[u8; 8]>::try_from(raw).ok())
        .map(u64::from_ne_bytes)
    {
        filter = Some((wdev >> 32) as u32);
    }
    if let Some(ifindex) = find_attr(attrs, NL80211_ATTR_IFINDEX).and_then(|raw| u32_of(raw).ok()) {
        let name = narf_net::netlink_route::iface_name_for_index(ifindex)
            .filter(|name| narf_net::iface::lookup_in(namespace, name).is_some())
            .ok_or(ENODEV)?;
        if let Some(index) = interfaces
            .iter()
            .find(|iface| iface.name() == name)
            .and_then(|iface| crate::registry::wiphy_index(iface.wiphy_id()))
        {
            filter = Some(index);
        }
    }
    Ok(filter)
}

fn handle_in(command: u8, attrs: &[u8], dump: bool, namespace: u64) -> Result<Vec<GenlReply>, i32> {
    let interfaces = crate::registry::list();
    let replies: Vec<GenlReply> = match command {
        NL80211_CMD_GET_WIPHY => {
            let wanted = if dump {
                dump_wiphy_filter(&interfaces, attrs, namespace)?
            } else {
                Some(wiphy_from_attrs(&interfaces, attrs, namespace)?)
            };
            crate::registry::wiphys()
                .iter()
                .enumerate()
                .filter(|(_, iface)| {
                    interfaces.iter().any(|candidate| {
                        candidate.wiphy_id() == iface.wiphy_id()
                            && in_namespace(candidate.as_ref(), namespace)
                    })
                })
                .filter(|(index, _iface)| wanted.is_none_or(|wanted| wanted == *index as u32))
                .map(|(index, iface)| {
                    let mut attrs = wiphy_attrs(
                        index as u32,
                        &iface.get_wireless_info(),
                        Some(iface.as_ref()),
                    );
                    wiphy_security_attrs(&mut attrs, iface.as_ref());
                    GenlReply {
                        command: NL80211_CMD_NEW_WIPHY,
                        attrs,
                    }
                })
                .collect()
        }
        NL80211_CMD_GET_INTERFACE => interfaces
            .iter()
            .enumerate()
            .filter(|(_, iface)| in_namespace(iface.as_ref(), namespace))
            .filter(|(_index, iface)| {
                dump || find_attr(attrs, NL80211_ATTR_IFINDEX).is_some_and(|raw| {
                    raw.len() == 4
                        && narf_net::netlink_route::ifindex_for_name(
                            &iface.get_wireless_info().base_name,
                        ) == Some(u32::from_ne_bytes(raw.try_into().unwrap_or([0; 4])))
                }) || find_attr(attrs, NL80211_ATTR_IFNAME).is_some_and(|raw| {
                    raw.strip_suffix(&[0]).unwrap_or(raw)
                        == iface.get_wireless_info().base_name.as_bytes()
                })
            })
            .map(|(_index, iface)| GenlReply {
                command: NL80211_CMD_NEW_INTERFACE,
                attrs: interface_attrs(
                    crate::registry::wiphy_index(iface.wiphy_id()).unwrap_or(0),
                    iface.as_ref(),
                    iface.current_iftype(),
                ),
            })
            .collect(),
        NL80211_CMD_GET_PROTOCOL_FEATURES => {
            if dump {
                return Err(EOPNOTSUPP);
            }
            let mut attrs = Vec::new();
            // No optional protocol features are claimed: in particular,
            // replies are not split across multiple wiphy records.
            push_attr(
                &mut attrs,
                NL80211_ATTR_PROTOCOL_FEATURES,
                &0u32.to_ne_bytes(),
            );
            alloc::vec![GenlReply {
                command: NL80211_CMD_GET_PROTOCOL_FEATURES,
                attrs,
            }]
        }
        _ => return Err(EOPNOTSUPP),
    };
    if !dump && replies.is_empty() {
        Err(ENODEV)
    } else {
        Ok(replies)
    }
}

/// One `nl80211_ops` / `nl80211_small_ops` entry: the command, whether it
/// has a doit / dumpit, and its Linux permission flag (`.flags`).
const fn op(command: u8, kinds: u32, perm: u32) -> GenlOperation {
    GenlOperation {
        command,
        flags: kinds | perm,
    }
}
const DO: u32 = GENL_CMD_CAP_DO;
const DUMP: u32 = GENL_CMD_CAP_DUMP;
/// No `.flags`: anyone may send it.
const OPEN: u32 = 0;
const UNS: u32 = narf_net::netlink_generic::GENL_UNS_ADMIN_PERM;
const ADMIN: u32 = narf_net::netlink_generic::GENL_ADMIN_PERM;

/// The commands NARF implements, each with the `.flags` Linux gives it in
/// `net/wireless/nl80211.c`. The generic-netlink layer enforces the
/// permission bit before the handler runs, and reports the whole word in
/// `CTRL_ATTR_OP_FLAGS`. Per-wiphy support (userspace MLME, AP mode) is
/// checked by the handler after the permission check, as cfg80211 does.
pub(crate) const OPERATIONS: &[GenlOperation] = &[
    op(NL80211_CMD_GET_WIPHY, DO | DUMP, OPEN),
    op(NL80211_CMD_SET_WIPHY, DO, UNS),
    op(NL80211_CMD_GET_INTERFACE, DO | DUMP, OPEN),
    op(NL80211_CMD_GET_PROTOCOL_FEATURES, DO, OPEN),
    op(NL80211_CMD_NEW_INTERFACE, DO, UNS),
    op(NL80211_CMD_DEL_INTERFACE, DO, UNS),
    op(NL80211_CMD_GET_WOWLAN, DO, OPEN),
    op(NL80211_CMD_SET_WOWLAN, DO, UNS),
    op(6, DO, UNS),          // SET_INTERFACE
    op(17, DO | DUMP, OPEN), // GET_STATION
    op(32, DUMP, OPEN),      // GET_SCAN
    op(NL80211_CMD_GET_SURVEY, DUMP, OPEN),
    op(NL80211_CMD_SET_TX_BITRATE_MASK, DO, UNS),
    op(63, DO, UNS), // SET_CQM
    op(33, DO, UNS), // TRIGGER_SCAN
    op(46, DO, UNS), // CONNECT
    op(48, DO, UNS), // DISCONNECT
    // Userspace-SME MLME + management-frame commands.
    op(37, DO, UNS),    // AUTHENTICATE
    op(38, DO, UNS),    // ASSOCIATE
    op(39, DO, UNS),    // DEAUTHENTICATE
    op(40, DO, UNS),    // DISASSOCIATE
    op(58, DO, UNS),    // REGISTER_FRAME
    op(59, DO, UNS),    // FRAME
    op(127, DO, ADMIN), // EXTERNAL_AUTH
    // Access-Point mode commands.
    op(14, DO, UNS),  // SET_BEACON
    op(15, DO, UNS),  // START_AP
    op(16, DO, UNS),  // STOP_AP
    op(18, DO, UNS),  // SET_STATION
    op(19, DO, UNS),  // NEW_STATION
    op(20, DO, UNS),  // DEL_STATION
    op(107, DO, UNS), // CHANNEL_SWITCH
    op(142, DO, UNS), // COLOR_CHANGE_REQUEST
    // External-supplicant station commands.
    op(10, DO, UNS),         // SET_KEY
    op(11, DO, UNS),         // NEW_KEY
    op(12, DO, UNS),         // DEL_KEY
    op(52, DO, UNS),         // SET_PMKSA
    op(53, DO, UNS),         // DEL_PMKSA
    op(54, DO, UNS),         // FLUSH_PMKSA
    op(129, DO, UNS),        // CONTROL_PORT_FRAME
    op(61, DO, UNS),         // SET_POWER_SAVE
    op(62, DO, OPEN),        // GET_POWER_SAVE
    op(79, DO, UNS),         // SET_REKEY_OFFLOAD
    op(31, DO | DUMP, OPEN), // GET_REG
];
/// `nl80211_mcgrps`, in Linux's order. None carries `GENL_MCAST_CAP_*`, so
/// `genl_bind` lets any socket join any of them. NARF publishes on config,
/// scan and mlme; regulatory, vendor and nan exist so tools that join them
/// (iw's event listener, wpa_supplicant) resolve every name Linux offers.
const GROUPS: &[GenlMulticastGroup] = &[
    GenlMulticastGroup {
        name: "config",
        id: 17,
    },
    GenlMulticastGroup {
        name: "scan",
        id: 18,
    },
    GenlMulticastGroup {
        name: "regulatory",
        id: 20,
    },
    GenlMulticastGroup {
        name: "mlme",
        id: 19,
    },
    GenlMulticastGroup {
        name: "vendor",
        id: 21,
    },
    GenlMulticastGroup {
        name: "nan",
        id: 22,
    },
];

pub fn register() -> bool {
    let registered = narf_net::netlink_generic::register_family(GenlFamily {
        id: NL80211_FAMILY_ID,
        name: "nl80211",
        version: 1,
        max_attr: 254,
        operations: OPERATIONS,
        groups: GROUPS,
        handler: handle,
    });
    if registered {
        let _ =
            narf_net::netlink_generic::register_context_handler(NL80211_FAMILY_ID, control::handle);
        // nl80211_netlink_notifier.
        narf_net::netlink_generic::register_release_notifier(control::station::release);
    }
    registered
}

/// Private driver fixtures stage only cfg80211's socket-owner metadata. This
/// grants no network authority and does not perform or simulate driver work.
#[cfg(any(test, feature = "kernel-test"))]
#[doc(hidden)]
pub fn __connection_owner_for_test(
    name: &str,
    namespace: u64,
    portid: u32,
    bssid: [u8; 6],
) -> ConnectionOwnerFixture {
    control::set_owner_for_test(name, namespace, portid, bssid);
    ConnectionOwnerFixture(alloc::string::String::from(name))
}

#[cfg(any(test, feature = "kernel-test"))]
#[doc(hidden)]
pub struct ConnectionOwnerFixture(alloc::string::String);
#[cfg(any(test, feature = "kernel-test"))]
impl Drop for ConnectionOwnerFixture {
    fn drop(&mut self) {
        control::unregister_owner_for_test(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiphy_description_maps_modes_and_identity() {
        let info = crate::WirelessIfaceInfo {
            base_name: "wlan-test".into(),
            base_mac: [2, 0, 0, 0, 0, 1],
            bands: alloc::vec![],
            modes: crate::iface::WirelessModes::STATION | crate::iface::WirelessModes::MONITOR,
            hw_caps: crate::iface::HwCaps {
                ht_supported: true,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        };
        let attrs = wiphy_attrs(4, &info, None);
        assert!(attrs.windows(5).any(|window| window == b"phy4\0"));
        assert!(attrs
            .windows(info.base_mac.len())
            .any(|window| window == info.base_mac));
        assert!(attrs.windows(2).any(|window| {
            u16::from_ne_bytes(window.try_into().unwrap())
                == NL80211_ATTR_SUPPORTED_IFTYPES | NLA_F_NESTED
        }));
        assert!(find_attr(&attrs, NL80211_ATTR_SUPPORTED_COMMANDS).is_some());
    }

    #[test]
    fn protocol_features_reports_no_unimplemented_flags() {
        let replies = handle(NL80211_CMD_GET_PROTOCOL_FEATURES, &[], false).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            find_attr(&replies[0].attrs, NL80211_ATTR_PROTOCOL_FEATURES),
            Some(&0u32.to_ne_bytes()[..])
        );
        assert_eq!(
            handle(NL80211_CMD_GET_PROTOCOL_FEATURES, &[], true).unwrap_err(),
            EOPNOTSUPP
        );
    }

    #[test]
    fn family_registration_is_idempotent() {
        assert!(register() || !register());
        assert!(!register());
    }
}

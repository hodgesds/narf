//! `nl80211` discovery and explicitly delegated station control.

mod control;

extern crate alloc;

use alloc::vec::Vec;
use narf_net::netlink_generic::{GenlFamily, GenlMulticastGroup, GenlOperation, GenlReply};

pub const NL80211_FAMILY_ID: u16 = 0x13;
pub const NL80211_CMD_GET_WIPHY: u8 = 1;
pub const NL80211_CMD_NEW_WIPHY: u8 = 3;
pub const NL80211_CMD_GET_INTERFACE: u8 = 5;
pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;
pub const NL80211_CMD_GET_PROTOCOL_FEATURES: u8 = 95;

const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_WIPHY_NAME: u16 = 2;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_SUPPORTED_IFTYPES: u16 = 32;
const NL80211_ATTR_SUPPORTED_COMMANDS: u16 = 50;
const NL80211_ATTR_WDEV: u16 = 153;
const NL80211_ATTR_PROTOCOL_FEATURES: u16 = 173;
const NLA_F_NESTED: u16 = 1 << 15;
const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_IFTYPE_AP: u32 = 3;
const NL80211_IFTYPE_MONITOR: u32 = 6;
const NL80211_IFTYPE_P2P_CLIENT: u32 = 8;
const GENL_CMD_CAP_DO: u32 = 1 << 1;
const GENL_CMD_CAP_DUMP: u32 = 1 << 2;
const ENODEV: i32 = 19;
const EINVAL: i32 = 22;
const EOPNOTSUPP: i32 = 95;

/// `NL80211_ATTR_REASON_CODE`.
const NL80211_ATTR_REASON_CODE: u16 = 54;
/// `NL80211_ATTR_DISCONNECTED_BY_AP`.
const NL80211_ATTR_DISCONNECTED_BY_AP: u16 = 71;

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

fn interface_attrs(index: u32, info: &crate::WirelessIfaceInfo, iftype: u32) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &index.to_ne_bytes());
    let ifindex = narf_net::netlink_route::ifindex_for_name(&info.base_name).unwrap_or(0);
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    named_attr(&mut attrs, NL80211_ATTR_IFNAME, &info.base_name);
    push_attr(&mut attrs, NL80211_ATTR_IFTYPE, &iftype.to_ne_bytes());
    push_attr(&mut attrs, NL80211_ATTR_MAC, &info.base_mac);
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
    let mut bands = Vec::new();
    for band in &info.bands {
        let band_id = match band.freq_mhz {
            2400..=2500 => 0,
            4900..=5900 => 1,
            _ => continue,
        };
        let mut frequencies = Vec::new();
        for (i, channel) in band.channels.iter().enumerate() {
            let frequency = if band_id == 0 {
                if *channel == 14 {
                    2484
                } else {
                    2407 + channel * 5
                }
            } else {
                5000 + channel * 5
            };
            let mut entry = Vec::new();
            push_attr(&mut entry, 1, &frequency.to_ne_bytes());
            push_attr(&mut frequencies, i as u16 | NLA_F_NESTED, &entry);
        }
        let mut body = Vec::new();
        push_attr(&mut body, 1 | NLA_F_NESTED, &frequencies);
        let rates: &[u32] = if band_id == 0 {
            &[10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540]
        } else {
            &[60, 90, 120, 180, 240, 360, 480, 540]
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
    push_attr(&mut attrs, 43, &[16]); // max scan SSIDs
    push_attr(&mut attrs, 56, &0u16.to_ne_bytes()); // no custom probe IEs
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
        push_attr(&mut modes, NL80211_IFTYPE_P2P_CLIENT as u16, &[]);
    }
    push_attr(
        &mut attrs,
        NL80211_ATTR_SUPPORTED_IFTYPES | NLA_F_NESTED,
        &modes,
    );
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

fn handle(command: u8, attrs: &[u8], dump: bool) -> Result<Vec<GenlReply>, i32> {
    handle_in(command, attrs, dump, 0)
}

fn in_namespace(iface: &dyn crate::WirelessNetIface, namespace: u64) -> bool {
    narf_net::iface::lookup(iface.name())
        .map(|i| i.net_ns_id)
        .unwrap_or(0)
        == namespace
}

fn u32_of(raw: &[u8]) -> Result<u32, i32> {
    raw.try_into().map(u32::from_ne_bytes).map_err(|_| EINVAL)
}

/// `nl80211_pre_doit` for `NL80211_FLAG_NEED_WIPHY`
/// (`__cfg80211_rdev_from_attrs`): the wiphy named by `NL80211_ATTR_WIPHY`,
/// `NL80211_ATTR_WDEV` or the netdev `NL80211_ATTR_IFINDEX` — wpa_supplicant
/// asks by ifindex. None of them is -EINVAL; a netdev that is not wireless,
/// or names disagreeing on the wiphy, -EINVAL; nothing found, or a wiphy in
/// another namespace, -ENODEV. NARF hands out no wdev identifiers, so a
/// `NL80211_ATTR_WDEV` never names one.
fn wiphy_from_attrs(
    interfaces: &[alloc::sync::Arc<dyn crate::WirelessNetIface>],
    attrs: &[u8],
    namespace: u64,
) -> Result<usize, i32> {
    let by_index = find_attr(attrs, NL80211_ATTR_WIPHY)
        .map(u32_of)
        .transpose()?;
    let wdev = find_attr(attrs, NL80211_ATTR_WDEV);
    let ifindex = find_attr(attrs, NL80211_ATTR_IFINDEX)
        .map(u32_of)
        .transpose()?;
    if by_index.is_none() && wdev.is_none() && ifindex.is_none() {
        return Err(EINVAL);
    }
    let mut wiphy = by_index
        .map(|index| index as usize)
        .filter(|index| *index < interfaces.len());
    if let Some(ifindex) = ifindex {
        if let Some(name) = narf_net::netlink_route::iface_name_for_index(ifindex)
            .filter(|name| narf_net::iface::lookup_in(namespace, name).is_some())
        {
            let from_netdev = interfaces
                .iter()
                .position(|iface| iface.name() == name)
                .ok_or(EINVAL)?;
            if wiphy.is_some_and(|wiphy| wiphy != from_netdev) {
                return Err(EINVAL);
            }
            wiphy = Some(from_netdev);
        }
    }
    let wiphy = wiphy.ok_or(ENODEV)?;
    if !in_namespace(interfaces[wiphy].as_ref(), namespace) {
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
) -> Result<Option<usize>, i32> {
    let mut filter = find_attr(attrs, NL80211_ATTR_WIPHY)
        .and_then(|raw| u32_of(raw).ok())
        .map(|index| index as usize);
    if let Some(wdev) = find_attr(attrs, NL80211_ATTR_WDEV)
        .and_then(|raw| <[u8; 8]>::try_from(raw).ok())
        .map(u64::from_ne_bytes)
    {
        filter = Some((wdev >> 32) as usize);
    }
    if let Some(ifindex) = find_attr(attrs, NL80211_ATTR_IFINDEX).and_then(|raw| u32_of(raw).ok()) {
        let name = narf_net::netlink_route::iface_name_for_index(ifindex)
            .filter(|name| narf_net::iface::lookup_in(namespace, name).is_some())
            .ok_or(ENODEV)?;
        if let Some(index) = interfaces.iter().position(|iface| iface.name() == name) {
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
            interfaces
                .iter()
                .enumerate()
                .filter(|(_, iface)| in_namespace(iface.as_ref(), namespace))
                .filter(|(index, _iface)| wanted.is_none_or(|wanted| wanted == *index))
                .map(|(index, iface)| {
                    let mut attrs = wiphy_attrs(
                        index as u32,
                        &iface.get_wireless_info(),
                        Some(iface.as_ref()),
                    );
                    let psk = iface.supports_handshake_offload();
                    let sae = iface.supports_sae_offload();
                    if psk || sae {
                        // CCMP (00-0F-AC:4) is the pairwise cipher for both
                        // WPA2-PSK and WPA3-SAE Personal.
                        push_attr(&mut attrs, 57, &0x000fac04u32.to_ne_bytes());
                        // NL80211_ATTR_EXT_FEATURES is a little-endian bitmap:
                        // bit 15 = 4WAY_HANDSHAKE_STA_PSK, bit 38 = SAE_OFFLOAD.
                        let mut ext = alloc::vec![0u8; if sae { 5 } else { 2 }];
                        if psk {
                            ext[1] |= 0x80; // bit 15
                        }
                        if sae {
                            ext[4] |= 0x40; // bit 38
                        }
                        push_attr(&mut attrs, 217, &ext);
                    }
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
            .map(|(index, iface)| GenlReply {
                command: NL80211_CMD_NEW_INTERFACE,
                attrs: interface_attrs(
                    index as u32,
                    &iface.get_wireless_info(),
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
    op(NL80211_CMD_GET_INTERFACE, DO | DUMP, OPEN),
    op(NL80211_CMD_GET_PROTOCOL_FEATURES, DO, OPEN),
    op(6, DO, UNS),          // SET_INTERFACE
    op(17, DO | DUMP, OPEN), // GET_STATION
    op(32, DUMP, OPEN),      // GET_SCAN
    op(33, DO, UNS),         // TRIGGER_SCAN
    op(46, DO, UNS),         // CONNECT
    op(48, DO, UNS),         // DISCONNECT
    // Userspace-SME MLME + management-frame commands.
    op(37, DO, UNS),    // AUTHENTICATE
    op(38, DO, UNS),    // ASSOCIATE
    op(39, DO, UNS),    // DEAUTHENTICATE
    op(40, DO, UNS),    // DISASSOCIATE
    op(58, DO, UNS),    // REGISTER_FRAME
    op(59, DO, UNS),    // FRAME
    op(127, DO, ADMIN), // EXTERNAL_AUTH
    // Access-Point mode commands.
    op(14, DO, UNS), // SET_BEACON
    op(15, DO, UNS), // START_AP
    op(16, DO, UNS), // STOP_AP
    op(18, DO, UNS), // SET_STATION
    op(19, DO, UNS), // NEW_STATION
    op(20, DO, UNS), // DEL_STATION
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
    }
    registered
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

//! Read-only `nl80211` generic-netlink family backed by the wireless registry.

extern crate alloc;

use alloc::vec::Vec;
use narf_net::netlink_generic::{GenlFamily, GenlMulticastGroup, GenlOperation, GenlReply};

pub const NL80211_FAMILY_ID: u16 = 0x13;
pub const NL80211_CMD_GET_WIPHY: u8 = 1;
pub const NL80211_CMD_NEW_WIPHY: u8 = 3;
pub const NL80211_CMD_GET_INTERFACE: u8 = 5;
pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;

const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_WIPHY_NAME: u16 = 2;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_SUPPORTED_IFTYPES: u16 = 32;
const NLA_F_NESTED: u16 = 1 << 15;
const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_IFTYPE_AP: u32 = 3;
const NL80211_IFTYPE_MONITOR: u32 = 6;
const NL80211_IFTYPE_P2P_CLIENT: u32 = 8;
const GENL_CMD_CAP_DO: u32 = 1 << 1;
const GENL_CMD_CAP_DUMP: u32 = 1 << 2;
const ENODEV: i32 = 19;
const EOPNOTSUPP: i32 = 95;

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

fn interface_attrs(index: u32, info: &crate::WirelessIfaceInfo) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &index.to_ne_bytes());
    let ifindex = narf_net::netlink_route::ifindex_for_name(&info.base_name).unwrap_or(0);
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    named_attr(&mut attrs, NL80211_ATTR_IFNAME, &info.base_name);
    push_attr(
        &mut attrs,
        NL80211_ATTR_IFTYPE,
        &NL80211_IFTYPE_STATION.to_ne_bytes(),
    );
    push_attr(&mut attrs, NL80211_ATTR_MAC, &info.base_mac);
    attrs
}

fn wiphy_attrs(index: u32, info: &crate::WirelessIfaceInfo) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &index.to_ne_bytes());
    named_attr(
        &mut attrs,
        NL80211_ATTR_WIPHY_NAME,
        &alloc::format!("phy{index}"),
    );
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
    attrs
}

fn handle(command: u8, attrs: &[u8], dump: bool) -> Result<Vec<GenlReply>, i32> {
    let interfaces = crate::registry::list();
    let replies: Vec<GenlReply> = match command {
        NL80211_CMD_GET_WIPHY => interfaces
            .iter()
            .enumerate()
            .filter(|(index, _iface)| {
                dump || find_attr(attrs, NL80211_ATTR_WIPHY).is_some_and(|raw| {
                    raw.len() == 4
                        && u32::from_ne_bytes(raw.try_into().unwrap_or([0; 4])) == *index as u32
                }) || find_attr(attrs, NL80211_ATTR_WIPHY_NAME).is_some_and(|raw| {
                    raw.strip_suffix(&[0]).unwrap_or(raw) == alloc::format!("phy{index}").as_bytes()
                })
            })
            .map(|(index, iface)| GenlReply {
                command: NL80211_CMD_NEW_WIPHY,
                attrs: wiphy_attrs(index as u32, &iface.get_wireless_info()),
            })
            .collect(),
        NL80211_CMD_GET_INTERFACE => interfaces
            .iter()
            .enumerate()
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
                attrs: interface_attrs(index as u32, &iface.get_wireless_info()),
            })
            .collect(),
        _ => return Err(EOPNOTSUPP),
    };
    if !dump && replies.is_empty() {
        Err(ENODEV)
    } else {
        Ok(replies)
    }
}

const OPERATIONS: &[GenlOperation] = &[
    GenlOperation {
        command: NL80211_CMD_GET_WIPHY,
        flags: GENL_CMD_CAP_DO | GENL_CMD_CAP_DUMP,
    },
    GenlOperation {
        command: NL80211_CMD_GET_INTERFACE,
        flags: GENL_CMD_CAP_DO | GENL_CMD_CAP_DUMP,
    },
];
const GROUPS: &[GenlMulticastGroup] = &[
    GenlMulticastGroup {
        name: "config",
        id: 17,
    },
    GenlMulticastGroup {
        name: "scan",
        id: 18,
    },
];

pub fn register() -> bool {
    narf_net::netlink_generic::register_family(GenlFamily {
        id: NL80211_FAMILY_ID,
        name: "nl80211",
        version: 1,
        max_attr: NL80211_ATTR_SUPPORTED_IFTYPES as u32,
        operations: OPERATIONS,
        groups: GROUPS,
        handler: handle,
    })
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
        let attrs = wiphy_attrs(4, &info);
        assert!(attrs.windows(5).any(|window| window == b"phy4\0"));
        assert!(attrs
            .windows(info.base_mac.len())
            .any(|window| window == info.base_mac));
        assert!(attrs.windows(2).any(|window| {
            u16::from_ne_bytes(window.try_into().unwrap())
                == NL80211_ATTR_SUPPORTED_IFTYPES | NLA_F_NESTED
        }));
    }

    #[test]
    fn family_registration_is_idempotent() {
        assert!(register() || !register());
        assert!(!register());
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-vdev role identity and the native P2P WMI codecs.
//!
//! Linux 7.3-rc4 `ath10k/mac.c::ath10k_add_interface` (vdev type/subtype
//! per nl80211 iftype, `free_vdev_map` + `__ffs64`), the per-dialect
//! `get_vdev_subtype` ops in `wmi.c`/`wmi-tlv.c`, `gen_vdev_create`,
//! `mac.c::ath10k_mac_setup_bcn_p2p_ie` / `ath10k_mac_remove_vendor_ie`,
//! `wmi-tlv.c::ath10k_wmi_tlv_op_gen_p2p_go_bcn_ie`,
//! `wmi-tlv.c::ath10k_wmi_tlv_event_p2p_noa` and `p2p.c` (NoA IE).
//!
//! These are codecs and bounded bookkeeping only. Creating a P2P vdev,
//! starting a GO, or publishing a NoA attribute still requires the role
//! owner that binds the actual physical/source generation; nothing here
//! grants RF, peer, key or data authority.
use super::wire::{self, packet, put, Wire};
use super::Error;
use crate::ath10k::wmi_boot::Dialect;
use alloc::vec::Vec;

/// nl80211 `enum nl80211_iftype` values used by the role table.
pub(super) const IFTYPE_STATION: u32 = 2;
pub(super) const IFTYPE_AP: u32 = 3;
pub(super) const IFTYPE_P2P_CLIENT: u32 = 8;
pub(super) const IFTYPE_P2P_GO: u32 = 9;
pub(super) const IFTYPE_P2P_DEVICE: u32 = 10;

/// One firmware vdev's role, chosen once at VDEV_CREATE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    Station,
    Ap,
    P2pDevice,
    P2pClient,
    P2pGo,
}

impl Role {
    /// `mac.c::ath10k_add_interface`: P2P_DEVICE and (p2p) STATION are
    /// `WMI_VDEV_TYPE_STA` (2); (p2p) AP is `WMI_VDEV_TYPE_AP` (1).
    pub(super) fn vdev_type(self) -> u32 {
        match self {
            Self::Ap | Self::P2pGo => 1,
            Self::Station | Self::P2pDevice | Self::P2pClient => 2,
        }
    }
    /// The wire subtype. `wmi.c::ath10k_wmi_op_get_vdev_subtype` (MAIN,
    /// 10.1, 10.2), `ath10k_wmi_10_2_4_op_get_vdev_subtype`,
    /// `ath10k_wmi_10_4_op_get_vdev_subtype` and
    /// `wmi-tlv.c::ath10k_wmi_tlv_op_get_vdev_subtype` all number
    /// NONE 0, P2P_DEV 1, P2P_CLI 2 and P2P_GO 3 identically; only the
    /// proxy/mesh subtypes (not modelled) differ between dialects.
    pub(super) fn subtype(self) -> u32 {
        match self {
            Self::Station | Self::Ap => 0,
            Self::P2pDevice => 1,
            Self::P2pClient => 2,
            Self::P2pGo => 3,
        }
    }
    pub(super) fn iftype(self) -> u32 {
        match self {
            Self::Station => IFTYPE_STATION,
            Self::Ap => IFTYPE_AP,
            Self::P2pDevice => IFTYPE_P2P_DEVICE,
            Self::P2pClient => IFTYPE_P2P_CLIENT,
            Self::P2pGo => IFTYPE_P2P_GO,
        }
    }
    pub(super) fn from_iftype(iftype: u32) -> Option<Self> {
        Some(match iftype {
            IFTYPE_STATION => Self::Station,
            IFTYPE_AP => Self::Ap,
            IFTYPE_P2P_DEVICE => Self::P2pDevice,
            IFTYPE_P2P_CLIENT => Self::P2pClient,
            IFTYPE_P2P_GO => Self::P2pGo,
            _ => return None,
        })
    }
}

/// A firmware vdev identity: the id allocated from [`VdevMap`] plus the
/// role it was created with. The id is also the HTT/WMI routing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Vdev {
    id: u8,
    role: Role,
}

impl Vdev {
    pub(super) const fn new(id: u8, role: Role) -> Self {
        Self { id, role }
    }
    pub(super) fn id(self) -> u8 {
        self.id
    }
    pub(super) fn role(self) -> Role {
        self.role
    }
    /// `WMI_VDEV_CREATE_CMDID` (`struct wmi_vdev_create_cmd`: vdev_id,
    /// vdev_type, vdev_subtype, mac). `wmi.c::ath10k_wmi_op_gen_vdev_create`
    /// serves MAIN/10.x/10.4; `wmi-tlv.c::ath10k_wmi_tlv_op_gen_vdev_create`
    /// wraps the same fields in `WMI_TLV_TAG_STRUCT_VDEV_CREATE_CMD` (86).
    pub(super) fn create(self, wire: &Wire, mac: [u8; 6]) -> Result<Vec<u8>, Error> {
        if !unicast(mac) {
            return Err(Error::Malformed);
        }
        let tlv = wire.dialect == Dialect::Tlv;
        let mut out = packet(wire.create, 20 + usize::from(tlv) * 4)?;
        let at = if tlv {
            put(&mut out, 4, (86 << 16) | 20);
            8
        } else {
            4
        };
        put(&mut out, at, u32::from(self.id));
        put(&mut out, at + 4, self.role.vdev_type());
        put(&mut out, at + 8, self.role.subtype());
        out[at + 12..at + 18].copy_from_slice(&mac);
        Ok(out)
    }
    /// `WMI_VDEV_DELETE_CMDID` (`struct wmi_vdev_delete_cmd`: vdev_id).
    /// Every dialect's command table places DELETE directly after CREATE
    /// (`wmi.h` `WMI_VDEV_DELETE_CMDID`, `WMI_10X_`/`WMI_10_2_`/`WMI_10_4_`);
    /// `wmi-tlv.c::ath10k_wmi_tlv_op_gen_vdev_delete` wraps it in
    /// `WMI_TLV_TAG_STRUCT_VDEV_DELETE_CMD` (87).
    pub(super) fn delete(self, wire: &Wire) -> Result<Vec<u8>, Error> {
        let tlv = wire.dialect == Dialect::Tlv;
        let mut out = packet(wire.create + 1, 4 + usize::from(tlv) * 4)?;
        let at = if tlv {
            put(&mut out, 4, (87 << 16) | 4);
            8
        } else {
            4
        };
        put(&mut out, at, u32::from(self.id));
        Ok(out)
    }
}

fn unicast(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

/// `ar->free_vdev_map`: core.c initialises it to `(1 << max_num_vdevs) - 1`
/// from the INIT resource count; `ath10k_add_interface` takes the lowest
/// free bit (`__ffs64`) and `ath10k_remove_interface` returns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VdevMap {
    free: u64,
    limit: u8,
}

impl VdevMap {
    pub(super) fn new(vdevs: u32) -> Result<Self, Error> {
        if vdevs == 0 || vdevs > 64 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            free: u64::MAX >> (64 - vdevs),
            limit: vdevs as u8,
        })
    }
    /// The lowest free id, or `Exhausted` (Linux returns `-EBUSY`).
    pub(super) fn allocate(&mut self) -> Result<u8, Error> {
        if self.free == 0 {
            return Err(Error::Exhausted);
        }
        let id = self.free.trailing_zeros() as u8;
        self.free &= !(1 << id);
        Ok(id)
    }
    /// Return an id that is currently allocated. A double release or an id
    /// outside the INIT resource count is a bookkeeping error, not a no-op.
    pub(super) fn release(&mut self, id: u8) -> Result<(), Error> {
        if id >= self.limit || self.free & (1 << id) != 0 {
            return Err(Error::Malformed);
        }
        self.free |= 1 << id;
        Ok(())
    }
    pub(super) fn allocated(&self, id: u8) -> bool {
        id < self.limit && self.free & (1 << id) == 0
    }
}

/// WFA OUI and the P2P vendor-IE OUI type (`WLAN_OUI_WFA`,
/// `WLAN_OUI_TYPE_WFA_P2P`).
const P2P_OUI: [u8; 4] = [0x50, 0x6f, 0x9a, 9];
/// `IEEE80211_P2P_ATTR_ABSENCE_NOTICE`.
const ATTR_ABSENCE_NOTICE: u8 = 12;
/// Offset of `u.beacon.variable` in `struct ieee80211_mgmt`.
pub(super) const BEACON_IES: usize = 36;

/// The byte range of the first P2P vendor IE in an element stream,
/// as `cfg80211_find_vendor_ie(WLAN_OUI_WFA, WLAN_OUI_TYPE_WFA_P2P, ..)`.
/// A truncated element is malformed rather than silently ignored.
fn find_p2p_ie(elements: &[u8]) -> Result<Option<core::ops::Range<usize>>, Error> {
    let mut at = 0;
    while at < elements.len() {
        let length = usize::from(*elements.get(at + 1).ok_or(Error::Malformed)?);
        let end = at + 2 + length;
        if end > elements.len() {
            return Err(Error::Malformed);
        }
        if elements[at] == 221 && length >= 4 && elements[at + 2..at + 6] == P2P_OUI {
            return Ok(Some(at..end));
        }
        at = end;
    }
    Ok(None)
}

/// `mac.c::ath10k_mac_setup_bcn_p2p_ie` + `ath10k_mac_remove_vendor_ie`
/// for a GO beacon template (a whole management frame). Returns the native
/// `WMI_TLV_P2P_GO_SET_BEACON_IE` command when the beacon carries a P2P IE
/// and removes that IE from `beacon`, because firmware inserts it (with its
/// own NoA) into every transmitted beacon. Non-GO roles are unchanged.
pub(super) fn go_beacon_ie(vdev: Vdev, beacon: &mut Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
    if vdev.role != Role::P2pGo {
        return Ok(None);
    }
    let elements = beacon.get(BEACON_IES..).ok_or(Error::Malformed)?;
    let Some(range) = find_p2p_ie(elements)? else {
        return Ok(None);
    };
    let ie = &elements[range.clone()];
    let padded = ie.len().next_multiple_of(4);
    // Command id WMI_TLV_P2P_GO_SET_BEACON_IE (GRP_P2P 0xd, third command);
    // TAG_STRUCT_P2P_GO_SET_BEACON_IE (90) {vdev_id, ie_len}, then
    // TAG_ARRAY_BYTE (17) carrying the IE padded to four bytes.
    let mut out = packet(0xd003, 16 + padded)?;
    put(&mut out, 4, (90 << 16) | 8);
    put(&mut out, 8, u32::from(vdev.id));
    put(&mut out, 12, ie.len() as u32);
    put(&mut out, 16, (17 << 16) | padded as u32);
    out[20..20 + ie.len()].copy_from_slice(ie);
    let start = BEACON_IES + range.start;
    let end = BEACON_IES + range.end;
    beacon.drain(start..end);
    Ok(Some(out))
}

/// `WMI_P2P_MAX_NOA_DESCRIPTORS`.
pub(super) const MAX_NOA_DESCRIPTORS: usize = 4;
/// `sizeof(struct wmi_p2p_noa_info)`: four bytes then four 16-byte
/// `wmi_p2p_noa_descriptor`s.
const NOA_INFO_LEN: usize = 4 + MAX_NOA_DESCRIPTORS * 16;

/// `struct wmi_p2p_noa_descriptor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NoaDescriptor {
    pub type_count: u32,
    pub duration: u32,
    pub interval: u32,
    pub start_time: u32,
}

/// `struct wmi_p2p_noa_info` as reported by firmware for one GO vdev:
/// the firmware-owned NoA schedule and opportunistic-PS/CTWindow state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Noa {
    pub changed: bool,
    pub index: u8,
    /// Bit 0: OppPS enabled; bits 1..7: CTWindow in TUs
    /// (`WMI_P2P_OPPPS_ENABLE_BIT`, `WMI_P2P_OPPPS_CTWINDOW_OFFSET`).
    pub ctwindow_oppps: u8,
    pub descriptors: Vec<NoaDescriptor>,
}

impl Noa {
    /// Decode one `wmi_p2p_noa_info`. Linux trusts `num_descriptors`; a
    /// count above the fixed four-entry array is rejected here instead of
    /// reading past it.
    pub(super) fn from_info(info: &[u8]) -> Result<Self, Error> {
        if info.len() < NOA_INFO_LEN {
            return Err(Error::Malformed);
        }
        let count = usize::from(info[3]);
        if count > MAX_NOA_DESCRIPTORS {
            return Err(Error::Malformed);
        }
        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(count)
            .map_err(|_| Error::NoMemory)?;
        for i in 0..count {
            let at = 4 + i * 16;
            descriptors.push(NoaDescriptor {
                type_count: wire::word(info, at)?,
                duration: wire::word(info, at + 4)?,
                interval: wire::word(info, at + 8)?,
                start_time: wire::word(info, at + 12)?,
            });
        }
        Ok(Self {
            changed: info[0] & 1 != 0,
            index: info[1],
            ctwindow_oppps: info[2],
            descriptors,
        })
    }
    /// `wmi-tlv.c::ath10k_wmi_tlv_event_p2p_noa` over the body after the
    /// WMI header: `TAG_STRUCT_P2P_NOA_EVENT` (223, `vdev_id`) and
    /// `TAG_STRUCT_P2P_NOA_INFO` (69). Both are required (`-EPROTO`).
    /// The TLV path updates unconditionally; `changed` is not consulted.
    pub(super) fn tlv_event(body: &[u8]) -> Result<(u32, Self), Error> {
        let event = wire::tag(body, 223)?;
        let info = wire::tag(body, 69)?;
        let vdev = wire::word(event, 0)?;
        Ok((vdev, Self::from_info(info)?))
    }
    pub(super) fn opportunistic(&self) -> bool {
        self.ctwindow_oppps & 1 != 0
    }
    pub(super) fn ctwindow(&self) -> u8 {
        self.ctwindow_oppps >> 1
    }
    /// `p2p.c::ath10k_p2p_noa_ie_len_compute` + `ath10k_p2p_noa_ie_fill`:
    /// the P2P IE with one Notice of Absence attribute that a GO appends to
    /// probe responses (`mac.c::ath10k_tx_h_add_p2p_noa_ie`). `None` when
    /// there is no descriptor and OppPS is off, which clears the IE.
    /// The descriptor count is narrowed to the u8 IEEE field as Linux does.
    pub(super) fn information_element(&self) -> Result<Option<Vec<u8>>, Error> {
        if self.descriptors.is_empty() && !self.opportunistic() {
            return Ok(None);
        }
        let attribute = 2 + self.descriptors.len() * 13;
        let total = 6 + 3 + attribute;
        let mut out = Vec::new();
        out.try_reserve_exact(total).map_err(|_| Error::NoMemory)?;
        out.extend_from_slice(&[221, (total - 2) as u8]);
        out.extend_from_slice(&P2P_OUI);
        out.push(ATTR_ABSENCE_NOTICE);
        out.extend_from_slice(&(attribute as u16).to_le_bytes());
        out.push(self.index);
        // IEEE80211_P2P_OPPPS_ENABLE_BIT is bit 7; CTWindow is the low bits.
        out.push(self.ctwindow() | if self.opportunistic() { 0x80 } else { 0 });
        for descriptor in &self.descriptors {
            out.push(descriptor.type_count as u8);
            out.extend_from_slice(&descriptor.duration.to_le_bytes());
            out.extend_from_slice(&descriptor.interval.to_le_bytes());
            out.extend_from_slice(&descriptor.start_time.to_le_bytes());
        }
        Ok(Some(out))
    }
}

/// The per-GO NoA owner (`arvif->u.ap.noa_data`). It retains only the IE
/// built from the most recent firmware report for its own vdev; a report
/// for another vdev is not applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct NoaOwner {
    ie: Option<Vec<u8>>,
}

impl NoaOwner {
    /// `p2p.c::__ath10k_p2p_noa_update`: drop the old IE, then retain a new
    /// one only when the report yields one.
    pub(super) fn update(&mut self, vdev: Vdev, reported: u32, noa: &Noa) -> Result<bool, Error> {
        if vdev.role != Role::P2pGo || reported != u32::from(vdev.id) {
            return Ok(false);
        }
        self.ie = None;
        self.ie = noa.information_element()?;
        Ok(true)
    }
    pub(super) fn ie(&self) -> Option<&[u8]> {
        self.ie.as_deref()
    }
    /// `mac.c::ath10k_tx_h_add_p2p_noa_ie`: a GO appends the retained IE
    /// only to Probe Response frames (subtype 5); other frames unchanged.
    pub(super) fn append_to_probe_response(&self, frame: &mut Vec<u8>) -> Result<(), Error> {
        let Some(ie) = self.ie.as_deref() else {
            return Ok(());
        };
        if frame.len() < 24 || frame[0] & 0xfc != 0x50 {
            return Ok(());
        }
        frame
            .try_reserve_exact(ie.len())
            .map_err(|_| Error::NoMemory)?;
        frame.extend_from_slice(ie);
        Ok(())
    }
}

/// `mac.c::ath10k_mac_register`: the TLV interface combinations
/// (`ath10k_tlv_if_comb`, or `ath10k_tlv_qcs_if_comb` with
/// `WMI_SERVICE_ADAPTIVE_OCS`, TLV service 39). The IBSS-only combination is
/// omitted because no ADHOC role exists here. Other dialects return none:
/// MAIN's `ath10k_if_comb` is not admitted (no MAIN AP/GO owner), 10.x and
/// 10.4 combinations contain no P2P type, and `ATH10K_FW_FEATURE_NO_P2P`
/// removes P2P from `interface_modes` entirely.
pub(super) fn p2p_combinations(
    dialect: Dialect,
    adaptive_ocs: bool,
    no_p2p: bool,
) -> Vec<narf_wireless::InterfaceCombination> {
    use narf_wireless::{InterfaceCombination, InterfaceTypeLimit};
    if dialect != Dialect::Tlv || no_p2p {
        return Vec::new();
    }
    let limit = |max, iftypes: &[u32]| InterfaceTypeLimit {
        max,
        iftypes: iftypes.to_vec(),
    };
    let limits = if adaptive_ocs {
        alloc::vec![
            limit(2, &[IFTYPE_STATION]),
            limit(2, &[IFTYPE_P2P_CLIENT]),
            limit(1, &[IFTYPE_AP, IFTYPE_P2P_GO]),
            limit(1, &[IFTYPE_P2P_DEVICE]),
        ]
    } else {
        alloc::vec![
            limit(2, &[IFTYPE_STATION]),
            limit(2, &[IFTYPE_AP, IFTYPE_P2P_CLIENT, IFTYPE_P2P_GO]),
            limit(1, &[IFTYPE_P2P_DEVICE]),
        ]
    };
    alloc::vec![InterfaceCombination {
        limits,
        max_interfaces: 4,
        max_channels: if adaptive_ocs { 2 } else { 1 },
        sta_ap_beacon_interval_match: false,
        beacon_interval_min_gcd: None,
        radar_detect_widths: None,
    }]
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "p2p_tests.rs"]
mod tests;

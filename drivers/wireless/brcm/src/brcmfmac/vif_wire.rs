// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared FullMAC virtual-interface wire layer and firmware interface
//! registry (both BCM43602 msgbuf and CYW43439 BCDC use these encodings).
//!
//! This module is a *foundation only*: it grants no interface, role, data or
//! transmit authority and is not consulted by any capability advertisement.
//! A secondary netdev, its per-ifidx transport demux and its role terminal
//! owner are separate, still-missing compositions (`brcmfmac.md` §3
//! "Virtual-interface wire foundation").
//!
//! Linux 7.3-rc4 sources mirrored here:
//! - `feature.c::brcmf_feat_firmware_capabilities` (`brcmf_fwcap_map`:
//!   `mbss`, `mchan`, `p2p`, `rtap`) and `brcmf_feat_attach` (MBSS disabled
//!   on 4330/43362);
//! - `fwil.c::brcmf_create_bsscfg` (`bsscfg:` prefixed iovars);
//! - `cfg80211.c::brcmf_cfg80211_request_{ap,sta}_if`,
//!   `brcmf_set_vif_sta_macaddr`, `brcmf_get_first_free_bsscfgidx` and the
//!   `wl_interface_create_v{1,2,3}` layouts;
//! - `fweh.h` `struct brcmf_if_event` / `BRCMF_E_IF_*`,
//!   `fweh.c::brcmf_fweh_handle_if_event`;
//! - `core.c::brcmf_add_if`, `brcmf_del_if` and `brcmf_get_ifp`
//!   (`iflist[bsscfgidx]`, `if2bss[ifidx]`, `BRCMF_MAX_IFS`).
use crate::cyw43439::runtime::Error;
use alloc::vec::Vec;

/// `core.h` `BRCMF_MAX_IFS`.
pub const MAX_IFS: u8 = 16;
/// `fweh.h` `BRCMF_E_IF`.
pub const E_IF: u32 = 54;
/// `fweh.h` `BRCMF_E_IF_FLAG_NOIF`.
pub const IF_FLAG_NOIF: u8 = 1;
/// `struct brcmf_if_event` is five bytes.
pub const IF_EVENT_LEN: usize = 5;
/// `cfg80211.c` `WL_INTERFACE_MAC_USE`.
pub const INTERFACE_MAC_USE: u32 = 0x2;
/// `brcm_hw_ids.h` chips on which `brcmf_feat_attach` clears MBSS.
const MBSS_BROKEN_CHIPS: [u32; 2] = [0x4330, 43362];
/// `fwil.c::brcmf_create_bsscfg` prefix (copied without its NUL).
const BSSCFG_PREFIX: &[u8] = b"bsscfg:";

/// Firmware-reported interface-composition features. Each bit is only the
/// actual `cap` token Linux maps; none of them is an interface grant.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Features {
    /// `BRCMF_FEAT_MBSS` (`mbss`), after the chip exclusion.
    pub mbss: bool,
    /// `BRCMF_FEAT_MCHAN` (`mchan`).
    pub mchan: bool,
    /// `BRCMF_FEAT_P2P` (`p2p`).
    pub p2p: bool,
    /// `BRCMF_FEAT_MONITOR_FLAG` (`rtap`).
    pub monitor_flag: bool,
}

/// Parse the bounded native `cap` C string exactly as the existing monitor
/// and AP discovery do: an unterminated full-length reply, non-ASCII or
/// non-whitespace control bytes fail closed instead of being guessed.
pub fn features(capabilities: &[u8], maximum: usize, chip: u32) -> Result<Features, Error> {
    let terminator = capabilities.iter().position(|byte| *byte == 0);
    if terminator.is_none() && capabilities.len() >= maximum {
        return Err(Error::Malformed);
    }
    let end = terminator.unwrap_or(capabilities.len());
    let text = core::str::from_utf8(&capabilities[..end]).map_err(|_| Error::Malformed)?;
    if !text.is_ascii()
        || text
            .bytes()
            .any(|byte| byte.is_ascii_control() && !byte.is_ascii_whitespace())
    {
        return Err(Error::Malformed);
    }
    let has = |token: &str| text.split_ascii_whitespace().any(|word| word == token);
    Ok(Features {
        mbss: has("mbss") && !MBSS_BROKEN_CHIPS.contains(&chip),
        mchan: has("mchan"),
        p2p: has("p2p"),
        monitor_flag: has("rtap"),
    })
}

/// `fwil.c::brcmf_create_bsscfg`: bsscfg0 is the ordinary `name\0data`
/// iovar; any other index is `bsscfg:` + `name\0` + le32 index + data.
pub fn bsscfg_iovar(bsscfgidx: u8, name: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    if bsscfgidx >= MAX_IFS
        || name.is_empty()
        || name.contains(&0)
        || name.len() >= super::fwil::IOVAR_NAME_MAX
    {
        return Err(Error::Malformed);
    }
    let prefix = if bsscfgidx == 0 {
        0
    } else {
        BSSCFG_PREFIX.len() + 4
    };
    let total = prefix + name.len() + 1 + data.len();
    if total > super::fwil::BRCMF_DCMD_MAXLEN {
        return Err(Error::Malformed);
    }
    let mut out = Vec::with_capacity(total);
    if bsscfgidx != 0 {
        out.extend_from_slice(BSSCFG_PREFIX);
    }
    out.extend_from_slice(name);
    out.push(0);
    if bsscfgidx != 0 {
        out.extend_from_slice(&u32::from(bsscfgidx).to_le_bytes());
    }
    out.extend_from_slice(data);
    Ok(out)
}

/// `brcmf_set_vif_sta_macaddr`: locally administered address derived from
/// the primary MAC; the alternating index is the caller's retained state.
pub fn vif_mac(primary: [u8; 6], mac_idx: &mut u8) -> [u8; 6] {
    let mut mac = primary;
    mac[0] |= 0x02;
    mac[3] ^= if *mac_idx != 0 { 0xc0 } else { 0xa0 };
    *mac_idx = (*mac_idx + 1) % 2;
    mac
}

/// `WL_INTERFACE_CREATE_STA` / `WL_INTERFACE_CREATE_AP`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateKind {
    Station = 0,
    Ap = 1,
}

/// `struct wl_interface_create_v1` (natural C alignment, 20 bytes). As in
/// `brcmf_cfg80211_request_{ap,sta}_if`, the role is carried in `flags`.
pub fn interface_create_v1(kind: CreateKind, mac: [u8; 6]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0..2].copy_from_slice(&1u16.to_le_bytes());
    out[4..8].copy_from_slice(&(kind as u32 | INTERFACE_MAC_USE).to_le_bytes());
    out[8..14].copy_from_slice(&mac);
    out
}

/// `struct wl_interface_create_v2` (20 bytes); role in `iftype`.
pub fn interface_create_v2(kind: CreateKind, mac: [u8; 6]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0..2].copy_from_slice(&2u16.to_le_bytes());
    out[4..8].copy_from_slice(&INTERFACE_MAC_USE.to_le_bytes());
    out[8..14].copy_from_slice(&mac);
    out[14] = kind as u8;
    out
}

/// `struct wl_interface_create_v3` fixed part (28 bytes). Linux leaves
/// `len`/`fixed_len`/`bssid`/`if_index` zero; so does this encoder. It is
/// only valid after the firmware's bsscfg `interface_create` query
/// reported version 3.
pub fn interface_create_v3(kind: CreateKind, mac: [u8; 6]) -> [u8; 28] {
    let mut out = [0u8; 28];
    out[0..2].copy_from_slice(&3u16.to_le_bytes());
    out[6] = kind as u8;
    out[8..12].copy_from_slice(&INTERFACE_MAC_USE.to_le_bytes());
    out[12..18].copy_from_slice(&mac);
    out
}

/// `struct brcmf_mbss_ssid_le` for the legacy `bsscfg:ssid` AP fallback:
/// `ssid<N>` placeholder exactly as `brcmf_cfg80211_request_ap_if`.
pub fn mbss_ssid(bsscfgidx: u8) -> Result<[u8; 40], Error> {
    if bsscfgidx == 0 || bsscfgidx == 1 || bsscfgidx >= MAX_IFS {
        return Err(Error::Malformed);
    }
    let mut out = [0u8; 40];
    out[0..4].copy_from_slice(&u32::from(bsscfgidx).to_le_bytes());
    let mut name = [0u8; 6];
    name[..4].copy_from_slice(b"ssid");
    let len = if bsscfgidx < 10 {
        name[4] = b'0' + bsscfgidx;
        5
    } else {
        name[4] = b'1';
        name[5] = b'0' + bsscfgidx - 10;
        6
    };
    // Linux hard-codes SSID_len 5 even for a two-digit index; mirror it.
    out[4..8].copy_from_slice(&5u32.to_le_bytes());
    out[8..8 + len].copy_from_slice(&name[..len]);
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IfAction {
    Add,
    Del,
    Change,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IfRole {
    Station,
    Ap,
    Wds,
    P2pGo,
    P2pClient,
}

/// Decoded `struct brcmf_if_event`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IfEvent {
    pub ifidx: u8,
    pub action: IfAction,
    pub flags: u8,
    pub bsscfgidx: u8,
    pub role: IfRole,
}

impl IfEvent {
    /// Strict decode. Linux reads the five bytes unconditionally; NARF
    /// refuses a short declared payload and unknown action/role codes
    /// instead of creating an interface from undefined input.
    pub fn parse(event_code: u32, datalen: u32, payload: &[u8]) -> Result<Self, Error> {
        if event_code != E_IF
            || (datalen as usize) < IF_EVENT_LEN
            || payload.len() < IF_EVENT_LEN
            || payload.len() < datalen as usize
        {
            return Err(Error::Malformed);
        }
        let action = match payload[1] {
            1 => IfAction::Add,
            2 => IfAction::Del,
            3 => IfAction::Change,
            _ => return Err(Error::Malformed),
        };
        let role = match payload[4] {
            0 => IfRole::Station,
            1 => IfRole::Ap,
            2 => IfRole::Wds,
            3 => IfRole::P2pGo,
            4 => IfRole::P2pClient,
            _ => return Err(Error::Malformed),
        };
        Ok(Self {
            ifidx: payload[0],
            action,
            flags: payload[2],
            bsscfgidx: payload[3],
            role,
        })
    }

    /// `brcmf_fweh_handle_if_event` P2P-device classification.
    pub fn is_p2p_device(&self, p2pdev_setup_ongoing: bool) -> bool {
        self.flags & IF_FLAG_NOIF != 0
            && (self.role == IfRole::P2pClient
                || self.role == IfRole::Station && p2pdev_setup_ongoing)
    }
}

/// `brcmf_fweh_handle_if_event` disposition before any registry change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// NOIF without a P2P-device role (e.g. TDLS): ignored.
    Ignore,
    /// Out-of-range ifidx/bsscfgidx: Linux logs and drops it.
    Invalid,
    Apply {
        event: IfEvent,
        p2p_device: bool,
    },
}

pub fn classify(event: IfEvent, p2pdev_setup_ongoing: bool) -> Disposition {
    let p2p_device = event.is_p2p_device(p2pdev_setup_ongoing);
    if !p2p_device && event.flags & IF_FLAG_NOIF != 0 {
        Disposition::Ignore
    } else if event.ifidx >= MAX_IFS || event.bsscfgidx >= MAX_IFS {
        Disposition::Invalid
    } else {
        Disposition::Apply { event, p2p_device }
    }
}

/// One firmware interface known to the host (`iflist[bsscfgidx]`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    pub ifidx: u8,
    pub bsscfgidx: u8,
    pub mac: [u8; 6],
    /// Non-netdev P2P device bsscfg (`!p2p_enable && is_p2pdev`).
    pub p2p_device: bool,
    /// Nonwrapping identity; a replaced or removed entry never revives.
    pub generation: u64,
}

/// Result of applying an actual native IF event to the registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Applied {
    Added(Entry),
    /// `brcmf_add_if` found a stale nonzero-ifidx entry (missed DEL): the
    /// old one is detached and must have its authority retired by its owner.
    Replaced {
        old: Entry,
        new: Entry,
    },
    Changed(Entry),
    Removed(Entry),
    /// ADD over an existing ifidx0 entry, or CHANGE/DEL for an absent
    /// bsscfg: Linux ignores it; nothing changed.
    Ignored,
}

/// Host interface registry: `iflist[bsscfgidx]` + `if2bss[ifidx]`.
#[derive(Debug)]
pub struct Registry {
    iflist: [Option<Entry>; MAX_IFS as usize],
    if2bss: [Option<u8>; MAX_IFS as usize],
    generation: u64,
}

impl Registry {
    /// Primary interface0/bsscfg0 (`brcmf_attach` -> `brcmf_add_if(0, 0)`).
    pub fn new(primary_mac: [u8; 6]) -> Self {
        let mut registry = Self {
            iflist: [None; MAX_IFS as usize],
            if2bss: [None; MAX_IFS as usize],
            generation: 0,
        };
        let _ = registry.add(0, 0, false, primary_mac);
        registry
    }

    fn add(&mut self, bsscfgidx: u8, ifidx: u8, p2p_device: bool, mac: [u8; 6]) -> Applied {
        let old = self.iflist[bsscfgidx as usize];
        if let Some(existing) = old {
            if ifidx == 0 {
                return Applied::Ignored;
            }
            self.detach(existing);
        }
        self.generation = self.generation.saturating_add(1);
        let entry = Entry {
            ifidx,
            bsscfgidx,
            mac,
            p2p_device,
            generation: self.generation,
        };
        // A non-netdev P2P device stores no ifidx mapping (brcmf_add_if).
        if !p2p_device && self.if2bss[ifidx as usize].is_none() {
            self.if2bss[ifidx as usize] = Some(bsscfgidx);
        }
        self.iflist[bsscfgidx as usize] = Some(entry);
        match old {
            Some(old) => Applied::Replaced { old, new: entry },
            None => Applied::Added(entry),
        }
    }

    fn detach(&mut self, entry: Entry) {
        self.iflist[entry.bsscfgidx as usize] = None;
        if self.if2bss[entry.ifidx as usize] == Some(entry.bsscfgidx) {
            self.if2bss[entry.ifidx as usize] = None;
        }
    }

    /// Apply an IF event that passed [`classify`]. `mac` is the event
    /// header source address (`emsg->addr`). Removing bsscfg0 is refused:
    /// the primary interface lifetime belongs to the physical owner.
    pub fn apply(&mut self, event: IfEvent, p2p_device: bool, mac: [u8; 6]) -> Applied {
        if event.ifidx >= MAX_IFS || event.bsscfgidx >= MAX_IFS {
            return Applied::Ignored;
        }
        let current = self.iflist[event.bsscfgidx as usize];
        match event.action {
            IfAction::Add => self.add(event.bsscfgidx, event.ifidx, p2p_device, mac),
            IfAction::Change => current.map_or(Applied::Ignored, Applied::Changed),
            IfAction::Del => match current {
                Some(entry) if entry.bsscfgidx != 0 => {
                    self.detach(entry);
                    Applied::Removed(entry)
                }
                _ => Applied::Ignored,
            },
        }
    }

    /// `brcmf_get_ifp`: receive/event demultiplexing by firmware ifidx.
    pub fn by_ifidx(&self, ifidx: u8) -> Option<Entry> {
        let bsscfgidx = *self.if2bss.get(ifidx as usize)?;
        self.iflist[bsscfgidx? as usize]
    }

    pub fn by_bsscfgidx(&self, bsscfgidx: u8) -> Option<Entry> {
        *self.iflist.get(bsscfgidx as usize)?
    }

    /// `brcmf_get_first_free_bsscfgidx`; bsscfg1 is reserved for P2P.
    pub fn first_free_bsscfgidx(&self) -> Option<u8> {
        (0..MAX_IFS).find(|index| *index != 1 && self.iflist[*index as usize].is_none())
    }
}

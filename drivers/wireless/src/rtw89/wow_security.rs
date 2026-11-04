// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B security CAM for the WoW window only, Linux 7.3-rc4 `cam.c`
//! (`rtw89_cam_sec_key_install`, `rtw89_cam_get_addr_cam_key_idx`,
//! `rtw89_cam_fill_addr_cam_info`) and `wow.c`
//! (`rtw89_wow_construct_key_info`, `rtw89_wow_cfg_wake`).
//!
//! The awake NARF station runs CCMP/BIP on the host: no security CAM entry
//! is attached to its address CAM and `B_AX_{UC,BMC}_MGNT_DEC` stay clear.
//! Only while the WoW image runs (host TRX halted) are the current PTK and
//! GTKs (`station_security::Security::suspend_keys`, never IGTK) written so
//! the firmware can decrypt magic/pattern frames. The address CAM carries
//! them in `SEC_ENT*` with `WOL_MAGIC`/`WOL_PATTERN`; resume restores the
//! plain associated CAM and overwrites every written entry with a zero key
//! before host RX restarts. Host PN/replay state never leaves
//! `station_security`; the firmware must not transmit protected frames.
use super::wow_wire::{self, Alg, KeyInfo};
use alloc::vec::Vec;
use narf_wireless::station_security::{SuspendFloors, SuspendKeys};
use zeroize::Zeroizing;

/// `RTW89_SEC_CAM_IN_ADDR_CAM`.
const SLOTS: usize = 7;
/// `RTW89_ADDR_CAM_SEC_NORMAL` group slots 2..=4 (0..=1 unicast, 5..=6 BIP).
const GROUP_SLOTS: core::ops::RangeInclusive<usize> = 2..=4;
/// `R_AX_SEC_ENG_CTRL` `B_AX_UC_MGNT_DEC | B_AX_BMC_MGNT_DEC`
/// (`mac.c::rtw89_mac_hw_mgnt_sec`, RTL8852B mask).
pub(super) const MGNT_DEC: u32 = 1 << 4 | 1 << 5;

/// One `struct rtw89_sec_cam_entry` as `rtw89_cam_send_sec_key_cmd` writes it.
pub(super) struct Entry {
    pub index: u8,
    pub key: Zeroizing<[u8; 16]>,
}
impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw89SecCamEntry")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}
impl Entry {
    /// `H2C_FUNC_MAC_SEC_UPD` body for this entry.
    pub(super) fn body(&self) -> Zeroizing<[u8; 24]> {
        wow_wire::sec_cam_ccmp(self.index, &self.key)
    }
    /// The same entry with a zero key: the resume overwrite.
    pub(super) fn cleared(&self) -> Zeroizing<[u8; 24]> {
        wow_wire::sec_cam_ccmp(self.index, &[0; 16])
    }
}

/// Security inputs of one WoW window.
#[derive(Debug)]
pub(super) struct Keys {
    pub entries: Vec<Entry>,
    /// Address-CAM security slot -> (key id, security CAM index).
    slots: [Option<(u8, u8)>; SLOTS],
    pub key_info: KeyInfo,
    pub pairwise: Alg,
    pub group: Alg,
}

impl Keys {
    /// Open BSS: nothing written, `ptk_alg`/`gtk_alg` zero.
    pub(super) fn open() -> Self {
        Self {
            entries: Vec::new(),
            slots: [None; SLOTS],
            key_info: KeyInfo::default(),
            pairwise: Alg::None,
            group: Alg::None,
        }
    }
    pub(super) fn secured(&self) -> bool {
        self.pairwise != Alg::None
    }
}

/// `rtw89_cam_sec_key_install` for the snapshot, as the keys reached the
/// hardware at association: the pairwise key at security CAM 0 and address
/// slot 0 (`IEEE80211_KEY_FLAG_PAIRWISE`, key id 0), each group key at the
/// next CAM index and the next free group slot 2..=4 with its key id.
/// `rtw89_wow_get_key_info_iter`: CCMP-128 IVs from the matching floors
/// (`ptk_tx_iv`, `ptk_rx_iv`, `gtk_rx_iv[keyidx]`), `gtk_keyidx` from the
/// last group key, then `RTW89_WOW_VALID_CHECK` and both symbol checks.
pub(super) fn plan(
    keys: Option<&SuspendKeys>,
    floors: Option<&SuspendFloors>,
) -> Result<Keys, wow_wire::Error> {
    let (keys, floors) = match (keys, floors) {
        (None, None) => return Ok(Keys::open()),
        (Some(keys), Some(floors)) => (keys, floors),
        _ => return Err(wow_wire::Error::Invalid),
    };
    // An open controlled port always has a group key; the floors must name
    // exactly the same key set.
    if keys.groups.is_empty()
        || keys.groups.len() > GROUP_SLOTS.count()
        || keys.groups.len() != floors.groups.len()
    {
        return Err(wow_wire::Error::Invalid);
    }
    let mut out = Keys::open();
    out.entries
        .try_reserve_exact(keys.groups.len() + 1)
        .map_err(|_| wow_wire::Error::Invalid)?;
    out.entries.push(Entry {
        index: 0,
        key: Zeroizing::new(*keys.pairwise),
    });
    out.slots[0] = Some((0, 0));
    out.key_info.ptk_tx_iv = wow_wire::ccmp_iv(floors.pairwise_tx, 0);
    out.key_info.ptk_rx_iv = wow_wire::ccmp_iv(floors.pairwise_rx, 0);
    for ((id, key), slot) in keys.groups.iter().zip(GROUP_SLOTS) {
        let floor = floors
            .groups
            .iter()
            .find(|(fid, _)| fid == id)
            .map(|(_, pn)| *pn)
            .ok_or(wow_wire::Error::Invalid)?;
        if *id > 3
            || out.slots[GROUP_SLOTS]
                .iter()
                .flatten()
                .any(|(k, _)| k == id)
        {
            return Err(wow_wire::Error::Invalid);
        }
        let index = out.entries.len() as u8;
        out.entries.push(Entry {
            index,
            key: Zeroizing::new(**key),
        });
        out.slots[slot] = Some((*id, index));
        out.key_info.gtk_rx_iv[usize::from(*id)] = wow_wire::ccmp_iv(floor, *id);
        out.key_info.gtk_keyidx = *id;
    }
    out.key_info.valid_check = wow_wire::VALID_CHECK;
    out.key_info.symbol_check_en = wow_wire::SYMBOL_CHECK_PTK_GTK;
    out.pairwise = Alg::Ccmp;
    out.group = Alg::Ccmp;
    Ok(out)
}

fn word(cam: &[u8; 60], index: usize) -> u32 {
    u32::from_le_bytes([
        cam[index * 4],
        cam[index * 4 + 1],
        cam[index * 4 + 2],
        cam[index * 4 + 3],
    ])
}
fn set_word(cam: &mut [u8; 60], index: usize, value: u32) {
    cam[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
}

/// `rtw89_cam_fill_addr_cam_info` words 9..=11 on the plain associated AX
/// v0 body: `WOL_PATTERN` (bit 12, any pattern), `WOL_MAGIC` (bit 14),
/// `SEC_ENT_MODE` kept (`SEC_NORMAL`), `SEC_ENTn_KEYID` (bits 18 + 2n),
/// `SEC_ENT_VALID` (word 10 bits 7:0) and `SEC_ENTn` (word 10 bytes 1..3,
/// word 11 bytes 0..3). `WOL_UC` stays clear (Linux never sets it).
pub(super) fn wow_cam(base: &[u8; 60], keys: &Keys, pattern: bool, magic: bool) -> [u8; 60] {
    let mut cam = *base;
    let mut w9 = word(&cam, 9) & !(1 << 12 | 1 << 13 | 1 << 14 | 0xfffc_0000);
    w9 |= u32::from(pattern) << 12 | u32::from(magic) << 14;
    let (mut valid, mut w10, mut w11) = (0u32, 0u32, 0u32);
    for (n, slot) in keys.slots.iter().enumerate() {
        let Some((key_id, index)) = slot else {
            continue;
        };
        valid |= 1 << n;
        w9 |= u32::from(key_id & 3) << (18 + 2 * n);
        if n < 3 {
            w10 |= u32::from(*index) << (8 + 8 * n);
        } else {
            w11 |= u32::from(*index) << (8 * (n - 3));
        }
    }
    set_word(&mut cam, 9, w9);
    set_word(&mut cam, 10, valid | w10);
    set_word(&mut cam, 11, w11);
    cam
}

#[cfg(feature = "kernel-test")]
#[path = "wow_security_tests.rs"]
mod tests;

// SPDX-License-Identifier: GPL-2.0-or-later
//! Hardware security CAM for the RTL8822CE WoW window, Linux 7.3-rc4
//! `rtw88/sec.c` (`rtw_sec_write_cam`, `rtw_sec_clear_cam`,
//! `rtw_sec_enable_sec_engine`) and `mac80211.c::rtw_ops_set_key`.
//!
//! The awake NARF station keeps software CCMP: `radio::software_crypto`
//! invalidates all 32 CAM entries, clears `BIT_MAC_SEC_EN` (CR bit 9) and
//! leaves `RTW_SEC_CONFIG` zero, and the station/HT guards re-check that
//! state. Only for the WoW window, with host TRX stopped, are the current
//! PTK/GTK written so the WoW firmware can decrypt magic/pattern frames
//! (AOAC). [`clear`] restores exactly the software-crypto state before host
//! TRX restarts; host PN/replay state never leaves `station_security`.
use super::firmware_transport::Error as NativeError;
use super::wow::{Error, Io, KeyType};
use alloc::vec::Vec;
use narf_wireless::station_security::SuspendKeys;
use zeroize::Zeroizing;

// sec.h
pub(super) const SEC_CMD: u16 = 0x0670;
pub(super) const SEC_WRITE: u16 = 0x0674;
pub(super) const SEC_CONFIG: u16 = 0x0680;
pub(super) const CMD_WRITE_ENABLE: u32 = 1 << 16;
pub(super) const CMD_POLLING: u32 = 1 << 31;
const ENTRY_SHIFT: u32 = 3;
/// `RTW_SEC_DEFAULT_KEY_NUM`: with default key search the first four entries
/// map directly to group key ids.
const DEFAULT_KEY_NUM: u8 = 4;
/// `RTW_MAX_SEC_CAM_NUM`.
const MAX_CAM: u8 = 32;
/// `RTW_SEC_{TX,RX}_UNI_USE_DK | RTW_SEC_{TX,RX}_DEC_EN | RTW_SEC_{TX,RX}_BC_USE_DK`.
pub(super) const CONFIG_WOW: u8 = 0xcf;
/// `RTW_SEC_ENGINE_EN` (REG_CR bit 9) as its byte at `REG_CR + 1`.
pub(super) const CR_HIGH: u16 = 0x0101;
pub(super) const ENGINE_EN: u8 = 1 << 1;

/// One `struct rtw_cam_entry` as `rtw_sec_write_cam` programs it.
pub(super) struct Entry {
    pub index: u8,
    pub key_id: u8,
    pub kind: KeyType,
    pub group: bool,
    pub addr: [u8; 6],
    pub key: Zeroizing<[u8; 16]>,
}
impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88CamEntry")
            .field("index", &self.index)
            .field("key_id", &self.key_id)
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

/// `rtw_ops_set_key` slot choice under `default_key_search` (always set by
/// `rtw_sec_enable_sec_engine`): group keys at their key id, the pairwise
/// key at the first free entry from `RTW_SEC_DEFAULT_KEY_NUM`, i.e. 4.
/// NARF's station security is CCMP-128 only (`RTW_CAM_AES`); the pairwise
/// key id is 0 (no extended key id) and is addressed to the AP
/// (`sta->addr`), group keys to broadcast.
pub(super) fn entries(keys: &SuspendKeys, peer: [u8; 6]) -> Result<Vec<Entry>, Error> {
    let mut out = Vec::with_capacity(keys.groups.len() + 1);
    for (id, key) in &keys.groups {
        if *id >= DEFAULT_KEY_NUM {
            return Err(Error::Invalid);
        }
        out.push(Entry {
            index: *id,
            key_id: *id,
            kind: KeyType::Aes,
            group: true,
            addr: [0xff; 6],
            key: Zeroizing::new(**key),
        });
    }
    if out.is_empty() {
        // An open controlled port always has a group key.
        return Err(Error::Invalid);
    }
    out.push(Entry {
        index: DEFAULT_KEY_NUM,
        key_id: 0,
        kind: KeyType::Aes,
        group: false,
        addr: peer,
        key: Zeroizing::new(*keys.pairwise),
    });
    Ok(out)
}

/// `rtw_sec_write_cam`: eight words, written from word 7 down to word 0
/// (the valid bit lives in word 0, so the entry turns valid last). Returns
/// `(RTW_SEC_CMD_REG value, RTW_SEC_WRITE_REG value)` in write order.
pub(super) fn words(entry: &Entry) -> [(u32, u32); 8] {
    let base = u32::from(entry.index) << ENTRY_SHIFT;
    let a = entry.addr.map(u32::from);
    let k = &entry.key;
    let mut out = [(0, 0); 8];
    for (slot, i) in out.iter_mut().zip((0..8u32).rev()) {
        let content = match i {
            0 => {
                u32::from(entry.key_id & 3)
                    | (entry.kind as u32 & 7) << 2
                    | u32::from(entry.group) << 6
                    | 1 << 15
                    | a[0] << 16
                    | a[1] << 24
            }
            1 => a[2] | a[3] << 8 | a[4] << 16 | a[5] << 24,
            6 | 7 => 0,
            _ => {
                let j = ((i - 2) << 2) as usize;
                u32::from_le_bytes([k[j], k[j + 1], k[j + 2], k[j + 3]])
            }
        };
        *slot = (CMD_WRITE_ENABLE | CMD_POLLING | (base + i), content);
    }
    out
}

/// Linux writes CAM commands back to back; NARF bounds each on the command
/// engine's polling bit like `radio::software_crypto` (10 us x 1000).
async fn command<I: Io>(io: &mut I, cmd: u32, content: u32) -> Result<(), Error> {
    idle(io).await?;
    io.write32(SEC_WRITE, content).await?;
    io.write32(SEC_CMD, cmd).await?;
    idle(io).await
}
async fn idle<I: Io>(io: &mut I) -> Result<(), Error> {
    for _ in 0..1000 {
        let v = io.read32(SEC_CMD).await?;
        if v == u32::MAX {
            return Err(Error::Native(NativeError::Gone));
        }
        if v & CMD_POLLING == 0 {
            return Ok(());
        }
        io.delay_us(10).await;
    }
    Err(Error::Timeout)
}
/// The awake software-crypto state `radio::software_crypto` established and
/// `ht.rs`/`radio8821c.rs` re-check: engine off, `RTW_SEC_CONFIG` clear.
async fn software<I: Io>(io: &mut I) -> Result<bool, Error> {
    Ok(io.read8(CR_HIGH).await? & ENGINE_EN == 0 && io.read8(SEC_CONFIG).await? & CONFIG_WOW == 0)
}

/// Proof that CAM entries are live; only [`clear`] consumes it. Dropping it
/// means the caller must run the cold full restart, which card-offs the MAC.
#[must_use]
#[derive(Debug)]
pub(super) struct Installed {
    indices: Vec<u8>,
}
impl Installed {
    pub(super) fn none() -> Self {
        Self {
            indices: Vec::new(),
        }
    }
}

/// `rtw_ops_set_key(SET_KEY)` for each entry, then
/// `rtw_sec_enable_sec_engine` (default key search). Requires the awake
/// software-crypto state, so no host-visible RX was ever device-decrypted.
/// An empty set (open BSS) programs nothing and leaves the engine off.
pub(super) async fn install<I: Io>(io: &mut I, entries: &[Entry]) -> Result<Installed, Error> {
    if !software(io).await? {
        return Err(Error::Native(NativeError::Prerequisite));
    }
    if entries.is_empty() {
        return Ok(Installed::none());
    }
    if entries.iter().any(|e| e.index >= MAX_CAM) {
        return Err(Error::Invalid);
    }
    for entry in entries {
        for (cmd, content) in words(entry) {
            command(io, cmd, content).await?;
        }
    }
    let cr = io.read8(CR_HIGH).await?;
    io.write8(CR_HIGH, cr | ENGINE_EN).await?;
    let config = io.read8(SEC_CONFIG).await?;
    io.write8(SEC_CONFIG, config | CONFIG_WOW).await?;
    if io.read8(CR_HIGH).await? & ENGINE_EN == 0
        || io.read8(SEC_CONFIG).await? & CONFIG_WOW != CONFIG_WOW
    {
        return Err(Error::Native(NativeError::Prerequisite));
    }
    Ok(Installed {
        indices: entries.iter().map(|e| e.index).collect(),
    })
}

/// `rtw_ops_set_key(DISABLE_KEY)` → `rtw_sec_clear_cam` for each installed
/// entry, then turn the engine back off and prove the software-crypto state
/// again. Linux keeps hardware crypto after resume; NARF's awake path is
/// software CCMP with its own PN/replay windows, which never changed.
pub(super) async fn clear<I: Io>(io: &mut I, installed: Installed) -> Result<(), Error> {
    if installed.indices.is_empty() {
        return if software(io).await? {
            Ok(())
        } else {
            Err(Error::Native(NativeError::Prerequisite))
        };
    }
    let config = io.read8(SEC_CONFIG).await?;
    io.write8(SEC_CONFIG, config & !CONFIG_WOW).await?;
    let cr = io.read8(CR_HIGH).await?;
    io.write8(CR_HIGH, cr & !ENGINE_EN).await?;
    for index in &installed.indices {
        let cmd = CMD_WRITE_ENABLE | CMD_POLLING | u32::from(*index) << ENTRY_SHIFT;
        command(io, cmd, 0).await?;
    }
    if !software(io).await? {
        return Err(Error::Native(NativeError::Prerequisite));
    }
    Ok(())
}

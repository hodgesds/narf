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
#[cfg(feature = "module")]
#[allow(unused_imports)]
use crate::rtw88::platform::narf_wireless;
use alloc::vec::Vec;
use narf_wireless::station_security::SuspendKeys;
use zeroize::Zeroizing;

// sec.h — the register map lives in the shared chip core
// (`narf-drivers-wireless-rtl-chip::security_cam`), single-sourced so the
// builtin driver and the loadable `.ko` program the same CAM.
use narf_drivers_wireless_rtl_chip::security_cam::{
    self as chip_cam, DEFAULT_KEY_NUM, ENTRY_SHIFT, MAX_CAM,
};
pub(super) use narf_drivers_wireless_rtl_chip::security_cam::{
    CMD_POLLING, CMD_WRITE_ENABLE, CONFIG_WOW, CR_HIGH, ENGINE_EN, SEC_CMD, SEC_CONFIG, SEC_WRITE,
};

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
/// The layout lives in the shared chip core; this only lends the entry's
/// key bytes to it.
pub(super) fn words(entry: &Entry) -> [(u32, u32); 8] {
    chip_cam::words(&chip_cam::CamEntry {
        index: entry.index,
        key_id: entry.key_id,
        kind: entry.kind as u8,
        group: entry.group,
        addr: entry.addr,
        key: &entry.key,
    })
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

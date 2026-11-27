// SPDX-License-Identifier: GPL-2.0-or-later
//! Hardware security CAM word layout for the RTL8822CE WoW window, Linux
//! 7.3-rc4 `rtw88/sec.c` (`rtw_sec_write_cam`) and `sec.h`.
//!
//! Only the pure word computation lives here: the eight `(SEC_CMD,
//! SEC_WRITE)` pairs that program one `struct rtw_cam_entry`, written
//! from word 7 down to word 0 (the valid bit lives in word 0, so the
//! entry turns valid last). The poll/install/clear sequences stay in the
//! consuming crate over its `wow::Io`: that trait has no 16-bit access,
//! so it cannot be a `RegIo`, and the key material (`Zeroizing`,
//! `SuspendKeys`) stays there too. This module never owns key bytes: the
//! caller lends them through [`CamEntry::key`].

/// Security CAM command register (`SEC_CMD`).
pub const SEC_CMD: u16 = 0x0670;
/// Security CAM write register (`SEC_WRITE`).
pub const SEC_WRITE: u16 = 0x0674;
/// Security CAM config register (`SEC_CONFIG`).
pub const SEC_CONFIG: u16 = 0x0680;
/// `SEC_CMD` write-enable bit.
pub const CMD_WRITE_ENABLE: u32 = 1 << 16;
/// `SEC_CMD` engine-polling bit.
pub const CMD_POLLING: u32 = 1 << 31;
/// Entry index shift in `SEC_CMD`.
pub const ENTRY_SHIFT: u32 = 3;
/// `RTW_SEC_DEFAULT_KEY_NUM`: with default key search the first four entries
/// map directly to group key ids.
pub const DEFAULT_KEY_NUM: u8 = 4;
/// `RTW_MAX_SEC_CAM_NUM`.
pub const MAX_CAM: u8 = 32;
/// `RTW_SEC_{TX,RX}_UNI_USE_DK | RTW_SEC_{TX,RX}_DEC_EN | RTW_SEC_{TX,RX}_BC_USE_DK`.
pub const CONFIG_WOW: u8 = 0xcf;
/// `RTW_SEC_ENGINE_EN` (REG_CR bit 9) as its byte at `REG_CR + 1`.
pub const CR_HIGH: u16 = 0x0101;
/// `RTW_SEC_ENGINE_EN` within [`CR_HIGH`].
pub const ENGINE_EN: u8 = 1 << 1;
/// CAM key-type field for CCMP-128 (`RTW_CAM_AES`); NARF's station
/// security is CCMP-128 only.
pub const CAM_TYPE_AES: u8 = 4;

/// One `struct rtw_cam_entry` as `rtw_sec_write_cam` programs it. The key
/// is borrowed: the caller keeps the `Zeroizing` owner and lends the bytes
/// for the word computation only. The `Debug` impl deliberately omits the
/// key, as the consuming crate's does.
#[derive(Clone, Copy)]
pub struct CamEntry<'a> {
    pub index: u8,
    pub key_id: u8,
    /// CAM key-type field (3 bits); [`CAM_TYPE_AES`] for CCMP-128.
    pub kind: u8,
    pub group: bool,
    pub addr: [u8; 6],
    pub key: &'a [u8; 16],
}
impl core::fmt::Debug for CamEntry<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88CamEntry")
            .field("index", &self.index)
            .field("key_id", &self.key_id)
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

/// `rtw_sec_write_cam`: eight `(SEC_CMD, SEC_WRITE)` pairs, in write order
/// (word 7 down to word 0; the valid bit lives in word 0, so the entry
/// turns valid last).
pub fn words(entry: &CamEntry<'_>) -> [(u32, u32); 8] {
    let base = u32::from(entry.index) << ENTRY_SHIFT;
    let a = entry.addr.map(u32::from);
    let k = entry.key;
    let mut out = [(0, 0); 8];
    for (slot, i) in out.iter_mut().zip((0..8u32).rev()) {
        let content = match i {
            0 => {
                u32::from(entry.key_id & 3)
                    | u32::from(entry.kind & 7) << 2
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

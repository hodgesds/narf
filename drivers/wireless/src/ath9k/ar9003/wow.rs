// SPDX-License-Identifier: GPL-2.0-or-later
//! Wake-on-Wireless for the AR9003 generation: the `ar9003_wow.c` hardware
//! layer, the `wow.c` trigger mapping and disassociate/deauthenticate
//! patterns, and the `pci.c` AR9462-subsystem WoW table
//! (Linux @ `cbbddb6`, `drivers/net/wireless/ath/ath9k/`).
//!
//! WoW is AR9462-subsystem-only: `ATH9K_PCI_WOW` (`0x0010`) appears on
//! thirteen `0x0034` subsystem entries in `pci.c:330-395` (under
//! `CONFIG_ATH9K_PCOEM`) and on no `0x0032` (AR9485), `0x0033` (AR9580),
//! `0x0036` (AR9565) or `0x0037` (AR1111) entry, which answers the open
//! question from the AR9485 step-1 lane (#1382): the other AR9003 parts
//! have no WoW `driver_data`. The two verified entries the issue names
//! are AZWAVE `0x1a3b:0x2110` and ASUSTEK `0x1043:0x850e`; the remaining
//! subvendor numerics are copied from `pci.c:330-395`, never from memory.
//!
//! Scope: the hardware layer is complete (`apply_pattern`,
//! `wow_enable`, `wow_wakeup`, the keep-alive pattern and the WoW-sleep
//! power mode). What is NOT here: the owner-level suspend/resume wiring
//! (`ath9k_suspend`/`ath9k_resume` in `wow.c` — ANI stop, btcoex stop,
//! interrupt-mask save/restore, the associated-station and single-VIF
//! gates — needs the `ar9300_owner` suspend path to grow a WoW branch),
//! the MCI interaction (`ath9k_hw_mci_is_enabled` is always false until
//! the MCI subsystem of #1912 §1 lands; the `mci_enabled` flag threads
//! the Linux branches so they stay visible), and the
//! `ath9k_hw_configpcipowersave(false)` restore in `wow_wakeup` (the
//! AR9003 SerDes restore is PR #1911, unmerged; `Wakeup` reports it as
//! `restore_pcie_powersave` for the caller instead of calling the AR9002
//! helper). The TSF2 restart in `wow_wakeup` likewise reports
//! `tsf2_restart`: Linux only restarts it when a TSF2 generic timer was
//! enabled (`hw.c::ath9k_hw_gen_timer_start_tsf2`), and this tree has no
//! generic-timer table yet.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::power::MAX_RATE_POWER;
use super::{field as set_field, rmw, Revision};
use crate::ath9k::identity::{BringUpError, RegisterIo};

/// `ath9k.h:955`: the `driver_data` flag marking a WoW-capable PCI entry.
pub(in crate::ath9k) const ATH9K_PCI_WOW: u32 = 0x0010;
/// `pci.c`: the AR9462 device ID carrying every WoW subsystem entry.
pub(in crate::ath9k) const WOW_DEVICE_AR9462: u16 = 0x0034;

/// `pci.c:330-395`: the thirteen AR9462 (`0x0034`) subsystem
/// `(subsystem_vendor, subsystem_device)` entries carrying
/// `ATH9K_PCI_WOW`, in Linux table order. Subvendor numerics are the
/// `PCI_VENDOR_ID_*` values from `include/linux/pci_ids.h` at the same
/// commit, or the raw values `pci.c` spells out (`0x11ad` LITEON,
/// `0x14cd` USI, `0x10cf` Fujitsu).
pub(in crate::ath9k) const WOW_SUBSYSTEMS: &[(u16, u16)] = &[
    (0x168c, 0x3117), // ATHEROS
    (0x17aa, 0x3214), // LENOVO
    (0x1969, 0x0091), // ATTANSIC
    (0x1a3b, 0x2110), // AZWAVE
    (0x1043, 0x850e), // ASUSTEK
    (0x11ad, 0x6631), // LITEON
    (0x11ad, 0x6641), // LITEON
    (0x103c, 0x1864), // HP
    (0x14cd, 0x0063), // USI
    (0x14cd, 0x0064), // USI
    (0x10cf, 0x1783), // Fujitsu
    (0x1028, 0x020b), // DELL
    (0x1028, 0x0300), // DELL
];

/// `pci.c::ath_pci_id_table`: only an AR9462 whose subsystem pair is in
/// `WOW_SUBSYSTEMS` carries WoW `driver_data`. Every other AR9003 device
/// ID — including the AR9485 (`0x0032`), AR9580 (`0x0033`), AR9565
/// (`0x0036`) and AR1111 (`0x0037`) entries — reports no WoW capability.
pub(in crate::ath9k) fn wow_capable(device: u16, subvendor: u16, subdevice: u16) -> bool {
    device == WOW_DEVICE_AR9462 && WOW_SUBSYSTEMS.contains(&(subvendor, subdevice))
}

/// The PCI `driver_data` for a device/subsystem pair: `ATH9K_PCI_WOW`
/// when `wow_capable`, zero otherwise.
pub(in crate::ath9k) fn driver_data(device: u16, subvendor: u16, subdevice: u16) -> u32 {
    if wow_capable(device, subvendor, subdevice) {
        ATH9K_PCI_WOW
    } else {
        0
    }
}

/// `wow.c::ath9k_init_wow`: WoW initialises when the PCI entry carries
/// `ATH9K_PCI_WOW` or WoW is forced.
pub(in crate::ath9k) fn init_capable(driver_data: u32, force_wow: bool) -> bool {
    driver_data & ATH9K_PCI_WOW != 0 || force_wow
}

// `reg_wow.h` register map.
const AR_WOW_PATTERN: u64 = 0x825c;
const AR_WOW_COUNT: u64 = 0x8260;
const AR_WOW_BCN_EN: u64 = 0x8270;
const AR_WOW_BCN_TIMO: u64 = 0x8274;
const AR_WOW_KEEP_ALIVE_TIMO: u64 = 0x8278;
const AR_WOW_KEEP_ALIVE: u64 = 0x827c;
const AR_WOW_KEEP_ALIVE_DELAY: u64 = 0x8288;
const AR_WOW_LENGTH1: u64 = 0x8360;
const AR_WOW_LENGTH2: u64 = 0x8364;
const AR_WOW_LENGTH3: u64 = 0x8380;
const AR_WOW_LENGTH4: u64 = 0x8384;
const AR_WOW_PATTERN_MATCH_LT_256B: u64 = 0x8368;
const AR_MAC_PCU_WOW4: u64 = 0x8370;
/// `reg_wow.h::AR_WOW_KA_DESC_WORD2` / `AR_WOW_TRANSMIT_BUFFER`.
const AR_WOW_TXBUF_BASE: u64 = 0xe000;
/// `reg_wow.h::AR_WOW_TB_PATTERN(i)`.
const fn tb_pattern(pattern: usize) -> u64 {
    0xe100 + ((pattern as u64) << 8)
}
/// `reg_wow.h::AR_WOW_TB_MASK(i)`.
const fn tb_mask(pattern: usize) -> u64 {
    0xec00 + ((pattern as u64) << 5)
}
/// `reg_wow.h::AR_WOW_TXBUF(i)`.
const fn txbuf(word: usize) -> u64 {
    AR_WOW_TXBUF_BASE + ((word as u64) << 2)
}

// `reg_wow.h` pattern/status bits.
const AR_WOW_MAC_INTR_EN: u32 = 0x0004_0000;
const AR_WOW_MAGIC_EN: u32 = 0x0001_0000;
const AR_WOW_PAT_FOUND_SHIFT: u32 = 8;
const AR_WOW_PATTERN_FOUND_MASK: u32 = 0xff << AR_WOW_PAT_FOUND_SHIFT;
const AR_WOW_MAGIC_PAT_FOUND: u32 = 0x0002_0000;
const AR_WOW_KEEP_ALIVE_FAIL: u32 = 0x0010_0000;
const AR_WOW_BEACON_FAIL: u32 = 0x0020_0000;
/// `reg_wow.h::AR_WOW_BACK_OFF_SHIFT(AR_WOW_PAT_BACKOFF)`.
const AR_WOW_BACK_OFF: u32 = (0x4 & 0xf) << 27;
const AR_WOW_AIFS_CNT: u32 = 0x22;
const AR_WOW_SLOT_CNT: u32 = 0x09 << 8;
const AR_WOW_KEEP_ALIVE_CNT: u32 = 0x08 << 16;
const AR_WOW_BEACON_FAIL_EN: u32 = 0x0000_0001;
/// `reg_wow.h::AR_WOW_BEACON_TIMO`.
const AR_WOW_BEACON_TIMO: u32 = 0x4000_0000;
/// `reg.h:2096::AR_WOW_BEACON_TIMO_MAX`.
const AR_WOW_BEACON_TIMO_MAX: u32 = 0xffff_ffff;
const AR_WOW_KEEP_ALIVE_NEVER: u32 = 0xffff_ffff;
const AR_WOW_KEEP_ALIVE_AUTO_DIS: u32 = 0x0000_0001;
const AR_WOW_KEEP_ALIVE_FAIL_DIS: u32 = 0x0000_0002;
const AR_WOW_BMISSTHRESHOLD: u32 = 0x20;
const AR_WOW_PATTERN_SUPPORTED: u32 = 0xffff;
const AR_WOW_LENGTH_MAX: u32 = 0xff;

// `reg.h` registers/bits shared with the WoW layer.
const AR_CR: u64 = 0x0008;
const AR_CR_RXD: u32 = 0x20;
/// `reg.h::AR_CR_RXE(ah)` for `AR_SREV_9300_20_OR_LATER` (every AR9003 part).
const AR_CR_RXE: u32 = 0xc;
const AR_STA_ID1: u64 = 0x8004;
const AR_STA_ID1_PWR_SAV: u32 = 0x0004_0000;
const AR_STA_ID1_PRESERVE_SEQNUM: u32 = 0x2000_0000;
const AR_MAC_PCU_GEN_TIMER_TSF_SEL: u64 = 0x83d8;
const AR_DIRECT_CONNECT: u64 = 0x83a0;
const AR_DC_TSF2_ENABLE: u32 = 0x0000_0001;
const AR_NDP2_TIMER_MODE: u64 = 0x81c0;
const AR_GEN_TIMERS2_MODE_ENABLE_MASK: u32 = 0x0000_00ff;
const AR_RTC_KEEP_AWAKE: u64 = 0x7034;
const AR_RTC_FORCE_WAKE: u64 = 0x704c;
const AR_RTC_FORCE_WAKE_ON_INT: u32 = 2;
const AR_RSSI_THR: u64 = 0x8018;
const AR_RSSI_THR_BM_THR: u32 = 0x0000_ff00;
const AR_RSSI_THR_BM_THR_S: u32 = 8;
/// `hw.h::INIT_RSSI_THR`.
const INIT_RSSI_THR: u32 = 0x0000_0700;
/// `reg.h::AR_PCIE_PM_CTRL(ah)` for a non-AR9340 part.
const AR_PCIE_PM_CTRL: u64 = 0x4014;
const AR_PCIE_PM_CTRL_ENA: u32 = 0x0008_0000;
const AR_PMCTRL_HOST_PME_EN: u32 = 0x0040_0000;
const AR_PMCTRL_PWR_PM_CTRL_ENA: u32 = 0x0000_8000;
const AR_PMCTRL_AUX_PWR_DET: u32 = 0x1000_0000;
const AR_PMCTRL_WOW_PME_CLR: u32 = 0x0020_0000;
const AR_PMCTRL_PWR_STATE_D1D3: u32 = 0x0f00_0000;
/// `reg.h::AR_PMCTRL_PWR_STATE_D1D3_REAL` (same value as `D1D3`).
const AR_PMCTRL_PWR_STATE_D1D3_REAL: u32 = 0x0f00_0000;
/// `reg.h::AR_WA(ah)` for a non-AR9340 part.
const AR_WA: u64 = 0x4004;
const AR_WA_UNTIE_RESET_EN: u32 = 1 << 15;
const AR_WA_RESET_EN: u32 = 1 << 18;
const AR_WA_POR_SHORT: u32 = 1 << 21;
const AR_PCIE_PHY_REG3: u64 = 0x18c08;
const AR_PCU_MISC_MODE3: u64 = 0x83d0;
/// `hw.h::AH_WAIT_TIMEOUT` (µs).
const AH_WAIT_TIMEOUT: u64 = 100_000;

// `hw.h` keep-alive frame facts.
const KAL_FRAME_LEN: u32 = 28;
const KAL_FRAME_TYPE: u32 = 0x2;
const KAL_FRAME_SUB_TYPE: u32 = 0x4;
const KAL_DURATION_ID: u32 = 0x3d;
const KAL_NUM_DATA_WORDS: usize = 6;
const KAL_NUM_DESC_WORDS: usize = 12;
const KAL_TO_DS: u32 = 1;
const KAL_DELAY: u32 = 4;
const KAL_TIMEOUT: u32 = 900;

/// `hw.h::MAX_PATTERN_SIZE`.
pub(in crate::ath9k) const MAX_PATTERN_SIZE: usize = 256;
/// `hw.h::MAX_PATTERN_MASK_SIZE`.
pub(in crate::ath9k) const MAX_PATTERN_MASK_SIZE: usize = 32;
/// `hw.h::MAX_NUM_PATTERN`.
pub(in crate::ath9k) const MAX_NUM_PATTERN: usize = 16;
/// `hw.h::MAX_NUM_PATTERN_LEGACY`.
pub(in crate::ath9k) const MAX_NUM_PATTERN_LEGACY: usize = 8;
/// `hw.h::MAX_NUM_USER_PATTERN` (user patterns after the two
/// disassociate/deauthenticate slots).
pub(in crate::ath9k) const MAX_NUM_USER_PATTERN: usize = 6;

/// `hw.h` WoW trigger flags (`ath9k_wow_map_triggers` output).
pub(in crate::ath9k) const AH_WOW_USER_PATTERN_EN: u32 = 1 << 0;
pub(in crate::ath9k) const AH_WOW_MAGIC_PATTERN_EN: u32 = 1 << 1;
pub(in crate::ath9k) const AH_WOW_LINK_CHANGE: u32 = 1 << 2;
pub(in crate::ath9k) const AH_WOW_BEACON_MISS: u32 = 1 << 3;

/// `reg_wow.h::AR_WOW_LEN1_SHIFT(i)`.
const fn len1_shift(pattern: usize) -> u32 {
    ((0x3 - (pattern & 0x3)) << 0x3) as u32
}
/// `reg_wow.h::AR_WOW_LEN2_SHIFT(i)`.
const fn len2_shift(pattern: usize) -> u32 {
    ((0x7 - (pattern & 0x7)) << 0x3) as u32
}
/// `reg_wow.h::AR_WOW_LEN3_SHIFT(i)`.
const fn len3_shift(pattern: usize) -> u32 {
    ((0xb - (pattern & 0xb)) << 0x3) as u32
}
/// `reg_wow.h::AR_WOW_LEN4_SHIFT(i)`.
const fn len4_shift(pattern: usize) -> u32 {
    ((0xf - (pattern & 0xf)) << 0x3) as u32
}

/// `reg_wow.h::AR_WOW_STATUS(x)`.
const fn wow_status(raw: u32) -> u32 {
    raw & (AR_WOW_PATTERN_FOUND_MASK
        | AR_WOW_MAGIC_PAT_FOUND
        | AR_WOW_KEEP_ALIVE_FAIL
        | AR_WOW_BEACON_FAIL)
}

/// `reg_wow.h::AR_WOW_CLEAR_EVENTS(x)`.
const fn wow_clear_events(raw: u32) -> u32 {
    raw & !(0xff
        | AR_WOW_MAGIC_EN
        | AR_WOW_MAC_INTR_EN
        | AR_WOW_BEACON_FAIL
        | AR_WOW_KEEP_ALIVE_FAIL)
}

/// `reg_wow.h::AR_WOW_STATUS2(x)`.
const fn wow_status2(raw: u32) -> u32 {
    raw & AR_WOW_PATTERN_FOUND_MASK
}

/// `reg_wow.h::AR_WOW_CLEAR_EVENTS2(x)`.
const fn wow_clear_events2(raw: u32) -> u32 {
    raw & !0xff
}

/// The `wow.c` WoW request: which wake triggers the stack asked for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct WowlanRequest {
    /// `cfg80211_wowlan::disconnect`: wake on link change / beacon miss.
    pub disconnect: bool,
    /// `cfg80211_wowlan::magic_pkt`: wake on magic packet.
    pub magic_pkt: bool,
    /// `cfg80211_wowlan::n_patterns`: user patterns to apply.
    pub n_patterns: u8,
}

/// `wow.c::ath9k_wow_map_triggers`.
pub(in crate::ath9k) fn map_triggers(request: &WowlanRequest) -> u32 {
    let mut triggers = 0;
    if request.disconnect {
        triggers |= AH_WOW_LINK_CHANGE | AH_WOW_BEACON_MISS;
    }
    if request.magic_pkt {
        triggers |= AH_WOW_MAGIC_PATTERN_EN;
    }
    if request.n_patterns > 0 {
        triggers |= AH_WOW_USER_PATTERN_EN;
    }
    triggers
}

/// `wow.c`: the `wiphy_wowlan_support` split. AR9462 2.0-or-later and
/// AR9565 1.1-or-later match the full 16 patterns; anything else (AR9485,
/// AR9565 1.0/1.0.1, AR9462 below 2.0 — refused by `Revision::decode`
/// anyway) matches the legacy set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum WowlanSupport {
    /// `ath9k_wowlan_support_legacy`: 6 user patterns.
    Legacy,
    /// `ath9k_wowlan_support`: `MAX_NUM_PATTERN - 2` user patterns.
    Full,
}

impl WowlanSupport {
    /// `wow.c::ath9k_init_wow`.
    pub(in crate::ath9k) fn for_revision(revision: &Revision) -> Self {
        if revision.ar9462_20_or_later() || revision.ar9565_11_or_later() {
            Self::Full
        } else {
            Self::Legacy
        }
    }

    /// `wiphy_wowlan_support::n_patterns`.
    pub(in crate::ath9k) fn n_patterns(self) -> u8 {
        match self {
            Self::Full => (MAX_NUM_PATTERN - 2) as u8,
            Self::Legacy => MAX_NUM_USER_PATTERN as u8,
        }
    }

    /// `wiphy_wowlan_support::pattern_max_len` (`MAX_PATTERN_SIZE`).
    pub(in crate::ath9k) fn pattern_max_len(self) -> usize {
        MAX_PATTERN_SIZE
    }
}

/// A WoW pattern: the 256-byte pattern, the 32-byte mask and the
/// programmed length (`wow.c` builds both in `MAX_PATTERN_SIZE` buffers;
/// the hardware consumes `MAX_PATTERN_MASK_SIZE` mask bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Pattern {
    pub bytes: [u8; MAX_PATTERN_SIZE],
    pub mask: [u8; MAX_PATTERN_MASK_SIZE],
    pub len: u8,
}

/// `wow.c::ath9k_wow_add_disassoc_deauth_pattern`: the disassociate
/// (frame-control first byte `0xA0`) and deauthenticate (`0xC0`)
/// patterns, each 22 bytes — first frame-control byte, then the source
/// MAC and BSSID (both the associated AP's address); destination MAC and
/// duration are masked out. The mask is all `0xff` except bytes 0–2
/// (`0xfe`, `0x03`, `0xc0`).
pub(in crate::ath9k) fn disassoc_deauth_patterns(bssid: &[u8; 6]) -> [Pattern; 2] {
    let mut base = Pattern {
        bytes: [0; MAX_PATTERN_SIZE],
        mask: [0xff; MAX_PATTERN_MASK_SIZE],
        len: 22,
    };
    base.bytes[0] = 0xa0;
    // Skip the second frame-control byte and the duration field (3),
    // then the destination MAC (6): the source MAC lands at byte 10.
    base.bytes[10..16].copy_from_slice(bssid);
    base.bytes[16..22].copy_from_slice(bssid);
    base.mask[0] = 0xfe;
    base.mask[1] = 0x03;
    base.mask[2] = 0xc0;
    let mut deauth = base.clone();
    deauth.bytes[0] = 0xc0;
    [base, deauth]
}

/// The keep-alive frame facts `ath9k_wow_create_keep_alive_pattern` needs:
/// the transmit chainmask, the current band and the station/AP addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct KeepAlive {
    pub tx_chainmask: u8,
    /// `IS_CHAN_2GHZ(ah->curchan)`: CCK 1M below, OFDM 6M above.
    pub is_2ghz: bool,
    pub sta_mac: [u8; 6],
    pub ap_mac: [u8; 6],
}

/// The outcome of `ath9k_hw_wow_wakeup`, plus the two restores Linux
/// performs through helpers this tree does not own yet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct Wakeup {
    /// Decoded wake reason (`AH_WOW_*` trigger bits).
    pub status: u32,
    /// A 9462/9565/9485 part came out of WoW sleep with
    /// `AR_DC_TSF2_ENABLE` clear: the generic-timer owner must restart
    /// TSF2 (`hw.c::ath9k_hw_gen_timer_start_tsf2`, only when a TSF2
    /// timer was enabled).
    pub tsf2_restart: bool,
    /// A PCIe part came out of WoW sleep: the caller must restore PCIe
    /// power-save (`ath9k_hw_configpcipowersave(ah, false)`; the AR9003
    /// SerDes restore is PR #1911, unmerged).
    pub restore_pcie_powersave: bool,
}

/// `hw.h::struct ath9k_hw_wow`: the programmed WoW event masks and the
/// pattern capacity, plus the MCI fact the WoW layer consults. MCI is
/// #1912 §1 and is not implemented: `mci_enabled` is always false until
/// it lands, and the branches below keep Linux's shape so the MCI
/// interaction stays visible instead of silently vanishing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Wow {
    pub event_mask: u32,
    pub event_mask2: u32,
    pub max_patterns: u8,
    pub mci_enabled: bool,
}

impl Wow {
    /// `hw.c::ath9k_hw_fill_cap_info` under `CONFIG_ATH9K_WOW`:
    /// `MAX_NUM_PATTERN` for AR9462 2.0-or-later / AR9565 1.1-or-later,
    /// `MAX_NUM_PATTERN_LEGACY` otherwise.
    pub(in crate::ath9k) fn new(revision: &Revision) -> Self {
        Self {
            event_mask: 0,
            event_mask2: 0,
            max_patterns: if revision.ar9462_20_or_later() || revision.ar9565_11_or_later() {
                MAX_NUM_PATTERN as u8
            } else {
                MAX_NUM_PATTERN_LEGACY as u8
            },
            mci_enabled: false,
        }
    }

    /// `ar9003_wow.c::ath9k_hw_wow_apply_pattern`. `pattern_count >=
    /// max_patterns` is Linux `-ENOSPC`, reported here as `BadState`
    /// (no free pattern slot). Patterns 0–7 program `AR_WOW_PATTERN`
    /// and the first length pair; 8–15 program `AR_MAC_PCU_WOW4` and
    /// the second event mask.
    pub(in crate::ath9k) fn apply_pattern(
        &mut self,
        io: &mut impl RegisterIo,
        pattern: &[u8; MAX_PATTERN_SIZE],
        mask: &[u8; MAX_PATTERN_MASK_SIZE],
        pattern_count: usize,
        pattern_len: u8,
    ) -> Result<(), BringUpError> {
        if pattern_count >= usize::from(self.max_patterns) {
            return Err(BringUpError::BadState);
        }
        if pattern_count < MAX_NUM_PATTERN_LEGACY {
            rmw(io, AR_WOW_PATTERN, 0, 1 << pattern_count)?;
        } else {
            rmw(
                io,
                AR_MAC_PCU_WOW4,
                0,
                1 << (pattern_count - MAX_NUM_PATTERN_LEGACY),
            )?;
        }
        for (i, chunk) in pattern.chunks_exact(4).enumerate() {
            io.write32(
                tb_pattern(pattern_count) + (i as u64) * 4,
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            );
        }
        for (i, chunk) in mask.chunks_exact(4).enumerate() {
            io.write32(
                tb_mask(pattern_count) + (i as u64) * 4,
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            );
        }
        if pattern_count < MAX_NUM_PATTERN_LEGACY {
            self.event_mask |= 1 << (pattern_count + AR_WOW_PAT_FOUND_SHIFT as usize);
        } else {
            self.event_mask2 |=
                1 << ((pattern_count - MAX_NUM_PATTERN_LEGACY) + AR_WOW_PAT_FOUND_SHIFT as usize);
        }
        let set = (u32::from(pattern_len) & AR_WOW_LENGTH_MAX) << len_shift(pattern_count);
        let clear = AR_WOW_LENGTH_MAX << len_shift(pattern_count);
        match pattern_count {
            0..=3 => rmw(io, AR_WOW_LENGTH1, clear, set),
            4..=7 => rmw(io, AR_WOW_LENGTH2, clear, set),
            8..=11 => rmw(io, AR_WOW_LENGTH3, clear, set),
            _ => rmw(io, AR_WOW_LENGTH4, clear, set),
        }
    }

    /// `ar9003_wow.c::ath9k_hw_wow_wakeup`: decode the wake reason from
    /// the WoW status registers (masked to the events this `Wow`
    /// enabled), clear the events, restore the beacon threshold and
    /// drop both event masks. The PCIe power-save restore and the TSF2
    /// restart are reported, not performed (see `Wakeup`).
    pub(in crate::ath9k) fn wakeup(
        &mut self,
        io: &mut impl RegisterIo,
        revision: &Revision,
    ) -> Result<Wakeup, BringUpError> {
        let mut status = 0;
        let raw = io.read32(AR_WOW_PATTERN);
        if raw == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        let mut value = wow_status(raw) & self.event_mask;
        if value != 0 {
            if value & AR_WOW_MAGIC_PAT_FOUND != 0 {
                status |= AH_WOW_MAGIC_PATTERN_EN;
            }
            if value & AR_WOW_PATTERN_FOUND_MASK != 0 {
                status |= AH_WOW_USER_PATTERN_EN;
            }
            if value & AR_WOW_KEEP_ALIVE_FAIL != 0 {
                status |= AH_WOW_LINK_CHANGE;
            }
            if value & AR_WOW_BEACON_FAIL != 0 {
                status |= AH_WOW_BEACON_MISS;
            }
        }
        let raw2 = io.read32(AR_MAC_PCU_WOW4);
        if raw2 == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        value = wow_status2(raw2) & self.event_mask2;
        if value & AR_WOW_PATTERN_FOUND_MASK != 0 {
            status |= AH_WOW_USER_PATTERN_EN;
        }
        // Set and clear `WOW_PME_CLEAR` so the chip can generate the next
        // WoW signal; clear the D1/D3 power-state bits.
        rmw(
            io,
            AR_PCIE_PM_CTRL,
            AR_PMCTRL_PWR_STATE_D1D3,
            AR_PMCTRL_WOW_PME_CLR,
        )?;
        let raw = io.read32(AR_WOW_PATTERN);
        if raw == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        io.write32(AR_WOW_PATTERN, wow_clear_events(raw));
        let raw2 = io.read32(AR_MAC_PCU_WOW4);
        if raw2 == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        io.write32(AR_MAC_PCU_WOW4, wow_clear_events2(raw2));
        io.write32(AR_RSSI_THR, INIT_RSSI_THR);
        let mut tsf2_restart = false;
        if revision.ar9462() || revision.ar9565() || revision.ar9485() {
            let dc = io.read32(AR_DIRECT_CONNECT);
            if dc == u32::MAX {
                return Err(BringUpError::DeviceGone);
            }
            tsf2_restart = dc & AR_DC_TSF2_ENABLE == 0;
        }
        self.event_mask = 0;
        self.event_mask2 = 0;
        Ok(Wakeup {
            status,
            tsf2_restart,
            restore_pcie_powersave: revision.pcie,
        })
    }

    /// `ar9003_wow.c::ath9k_hw_wow_enable`: program the keep-alive,
    /// beacon and magic-packet wake events, arm PME/D1D3 (with the
    /// AR9462 `D1D3_REAL` word that stops the chip waking the host
    /// within 3–4 seconds on some platforms/BIOSes), untie the internal
    /// POR from the PCIe reset, then drop into WoW sleep. The Rx-DMA
    /// stop wait can time out (`Timeout`); the caller aborts the sleep
    /// then, as Linux does.
    pub(in crate::ath9k) fn enable(
        &mut self,
        io: &mut impl RegisterIo,
        revision: &Revision,
        triggers: u32,
        keep_alive: &KeepAlive,
    ) -> Result<(), BringUpError> {
        let mut wow_event_mask = self.event_mask;
        rmw(
            io,
            AR_PCIE_PM_CTRL,
            0,
            AR_PMCTRL_HOST_PME_EN
                | AR_PMCTRL_PWR_PM_CTRL_ENA
                | AR_PMCTRL_AUX_PWR_DET
                | AR_PMCTRL_WOW_PME_CLR,
        )?;
        rmw(io, AR_PCIE_PM_CTRL, AR_PMCTRL_WOW_PME_CLR, 0)?;
        // Random backoff: `AR_WOW_PAT_BACKOFF` bits of the contention window.
        rmw(io, AR_WOW_PATTERN, 0, AR_WOW_BACK_OFF)?;
        rmw(
            io,
            AR_WOW_COUNT,
            0,
            AR_WOW_AIFS_CNT | AR_WOW_SLOT_CNT | AR_WOW_KEEP_ALIVE_CNT,
        )?;
        if triggers & AH_WOW_BEACON_MISS != 0 {
            io.write32(AR_WOW_BCN_TIMO, AR_WOW_BEACON_TIMO);
        } else {
            io.write32(AR_WOW_BCN_TIMO, AR_WOW_BEACON_TIMO_MAX);
        }
        if triggers == 0 {
            io.write32(AR_WOW_KEEP_ALIVE_TIMO, AR_WOW_KEEP_ALIVE_NEVER);
        } else {
            io.write32(AR_WOW_KEEP_ALIVE_TIMO, KAL_TIMEOUT * 32);
        }
        io.write32(AR_WOW_KEEP_ALIVE_DELAY, KAL_DELAY * 1000);
        keep_alive_pattern(io, revision, keep_alive);
        let mut keep_alive_reg = io.read32(AR_WOW_KEEP_ALIVE);
        if keep_alive_reg == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        // Send keep-alive timeouts anyway.
        keep_alive_reg &= !AR_WOW_KEEP_ALIVE_AUTO_DIS;
        if triggers & AH_WOW_LINK_CHANGE != 0 {
            keep_alive_reg &= !AR_WOW_KEEP_ALIVE_FAIL_DIS;
            wow_event_mask |= AR_WOW_KEEP_ALIVE_FAIL;
        } else {
            keep_alive_reg |= AR_WOW_KEEP_ALIVE_FAIL_DIS;
        }
        io.write32(AR_WOW_KEEP_ALIVE, keep_alive_reg);
        // Rely on a beacon-miss failure: enough threshold to prevent
        // false positives.
        set_field(
            io,
            AR_RSSI_THR,
            AR_RSSI_THR_BM_THR,
            AR_RSSI_THR_BM_THR_S,
            AR_WOW_BMISSTHRESHOLD,
        )?;
        if triggers & AH_WOW_BEACON_MISS != 0 {
            wow_event_mask |= AR_WOW_BEACON_FAIL;
            rmw(io, AR_WOW_BCN_EN, 0, AR_WOW_BEACON_FAIL_EN)?;
        } else {
            rmw(io, AR_WOW_BCN_EN, AR_WOW_BEACON_FAIL_EN, 0)?;
        }
        let mut magic_pattern = io.read32(AR_WOW_PATTERN);
        if magic_pattern == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        magic_pattern |= AR_WOW_MAC_INTR_EN;
        if triggers & AH_WOW_MAGIC_PATTERN_EN != 0 {
            magic_pattern |= AR_WOW_MAGIC_EN;
            wow_event_mask |= AR_WOW_MAGIC_PAT_FOUND;
        } else {
            magic_pattern &= !AR_WOW_MAGIC_EN;
        }
        io.write32(AR_WOW_PATTERN, magic_pattern);
        io.write32(AR_WOW_PATTERN_MATCH_LT_256B, AR_WOW_PATTERN_SUPPORTED);
        let mut host_pm_ctrl = io.read32(AR_PCIE_PM_CTRL);
        if host_pm_ctrl == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        host_pm_ctrl |=
            AR_PMCTRL_PWR_STATE_D1D3 | AR_PMCTRL_HOST_PME_EN | AR_PMCTRL_PWR_PM_CTRL_ENA;
        host_pm_ctrl &= !AR_PCIE_PM_CTRL_ENA;
        if revision.ar9462() {
            host_pm_ctrl &= !AR_PMCTRL_PWR_STATE_D1D3;
            host_pm_ctrl |= AR_PMCTRL_PWR_STATE_D1D3_REAL;
        }
        io.write32(AR_PCIE_PM_CTRL, host_pm_ctrl);
        rmw(io, AR_STA_ID1, AR_STA_ID1_PRESERVE_SEQNUM, 0)?;
        // Bring down the WoW power low margin.
        rmw(io, AR_PCIE_PHY_REG3, 0, 1 << 13)?;
        set_arwr_reg(io, revision.pcie)?;
        if self.mci_enabled {
            io.write32(AR_RTC_KEEP_AWAKE, 0x2);
        }
        // Hardware WoW.
        rmw(io, AR_PCU_MISC_MODE3, 1 << 5, 0)?;
        set_powermode_wow_sleep(io, revision, self.mci_enabled)?;
        self.event_mask = wow_event_mask;
        Ok(())
    }
}

/// `reg_wow.h::AR_WOW_LEN*_SHIFT(i)` for `pattern_count`.
fn len_shift(pattern_count: usize) -> u32 {
    match pattern_count {
        0..=3 => len1_shift(pattern_count),
        4..=7 => len2_shift(pattern_count),
        8..=11 => len3_shift(pattern_count),
        _ => len4_shift(pattern_count),
    }
}

/// `ar9003_wow.c::ath9k_hw_wow_set_arwr_reg`: untie the internal POR
/// from the external PCIe reset and tie the PCIe PHY reset to the PCIe
/// reset. PCIe only.
fn set_arwr_reg(io: &mut impl RegisterIo, pcie: bool) -> Result<(), BringUpError> {
    if !pcie {
        return Ok(());
    }
    let mut wa = io.read32(AR_WA);
    if wa == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    wa &= !AR_WA_UNTIE_RESET_EN;
    wa |= AR_WA_RESET_EN | AR_WA_POR_SHORT;
    io.write32(AR_WA, wa);
    Ok(())
}

/// `ar9003_wow.c::ath9k_wow_create_keep_alive_pattern`: the null-data
/// keep-alive frame (station MAC, AP BSSID) in the WoW transmit buffer,
/// with the 12 descriptor words. AR9462 2.0-or-later and AR9565 have an
/// extra descriptor word (time-based discard), so their frame starts at
/// transmit-buffer word 13 instead of 12.
fn keep_alive_pattern(io: &mut impl RegisterIo, revision: &Revision, params: &KeepAlive) {
    let mut ctl = [0u32; 13];
    ctl[0] = KAL_FRAME_LEN | (u32::from(MAX_RATE_POWER) << 16);
    ctl[2] = 0xf << 16; // tx_tries 0
    ctl[3] = if params.is_2ghz { 0x1b } else { 0xb }; // CCK_1M / OFDM_6M
    ctl[7] = u32::from(params.tx_chainmask) << 2;
    for (i, word) in ctl.iter().take(KAL_NUM_DESC_WORDS).enumerate() {
        io.write32(txbuf(i), *word);
    }
    let sta = params.sta_mac;
    let ap = params.ap_mac;
    let data_word = [
        (KAL_FRAME_TYPE << 2)
            | (KAL_FRAME_SUB_TYPE << 4)
            | (KAL_TO_DS << 8)
            | (KAL_DURATION_ID << 16),
        (u32::from(ap[3]) << 24)
            | (u32::from(ap[2]) << 16)
            | (u32::from(ap[1]) << 8)
            | u32::from(ap[0]),
        (u32::from(sta[1]) << 24)
            | (u32::from(sta[0]) << 16)
            | (u32::from(ap[5]) << 8)
            | u32::from(ap[4]),
        (u32::from(sta[5]) << 24)
            | (u32::from(sta[4]) << 16)
            | (u32::from(sta[3]) << 8)
            | u32::from(sta[2]),
        (u32::from(ap[3]) << 24)
            | (u32::from(ap[2]) << 16)
            | (u32::from(ap[1]) << 8)
            | u32::from(ap[0]),
        (u32::from(ap[5]) << 8) | u32::from(ap[4]),
    ];
    let base = if revision.ar9462_20_or_later() || revision.ar9565() {
        io.write32(txbuf(KAL_NUM_DESC_WORDS), 0);
        13
    } else {
        12
    };
    for (i, word) in data_word.iter().take(KAL_NUM_DATA_WORDS).enumerate() {
        io.write32(txbuf(base + i), *word);
    }
}

/// `ar9003_wow.c::ath9k_hw_set_powermode_wow_sleep`: station powersave,
/// stop Rx DMA (a missed 10 ms stop aborts the sleep with `Timeout`),
/// clear `AR_DC_TSF2_ENABLE` when no TSF2 timer is armed, then force
/// wake on interrupt. With MCI enabled Linux sets `PWR_SAV` only when
/// the MCI WLAN power-save state is disabled; that state does not exist
/// here yet, so `mci_enabled` conservatively skips the set (see #1912 §1).
fn set_powermode_wow_sleep(
    io: &mut impl RegisterIo,
    revision: &Revision,
    mci_enabled: bool,
) -> Result<(), BringUpError> {
    if !mci_enabled {
        rmw(io, AR_STA_ID1, 0, AR_STA_ID1_PWR_SAV)?;
    }
    io.write32(AR_CR, AR_CR_RXD);
    io.wait_us(AR_CR, AR_CR_RXE, 0, AH_WAIT_TIMEOUT)?;
    if revision.ar9462() || revision.ar9565() {
        if io.read32(AR_MAC_PCU_GEN_TIMER_TSF_SEL) == 0 {
            rmw(io, AR_DIRECT_CONNECT, AR_DC_TSF2_ENABLE, 0)?;
        }
    } else if revision.ar9485()
        && io.read32(AR_NDP2_TIMER_MODE) & AR_GEN_TIMERS2_MODE_ENABLE_MASK == 0
    {
        rmw(io, AR_DIRECT_CONNECT, AR_DC_TSF2_ENABLE, 0)?;
    }
    if mci_enabled {
        io.write32(AR_RTC_KEEP_AWAKE, 0x2);
    }
    io.write32(AR_RTC_FORCE_WAKE, AR_RTC_FORCE_WAKE_ON_INT);
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests;

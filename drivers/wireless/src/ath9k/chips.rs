// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-chip ath9k PCI profiles: silicon revision decode
//! (`hw.c::ath9k_hw_read_revisions`, `ath9k_hw_init`'s accepted versions),
//! PCI device inventory (`hw.h` / `pci.c::ath_pci_id_table`) and the factory
//! EEPROM map each family reads (`eeprom_4k.c`, `eeprom_9287.c`,
//! `eeprom_def.c`).
//!
//! A profile only describes facts. Probe admission is separate: a chip
//! without a complete native station path is never matched by `register()`,
//! so the non-AR9285 profiles are exercised only by kernel tests until then.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

/// `reg.h::AR_SREV` macro versions of the PCI AR5008/AR9001/AR9002 parts.
pub(super) const AR_SREV_VERSION_5416_PCI: u32 = 0xd;
pub(super) const AR_SREV_VERSION_5416_PCIE: u32 = 0xc;
pub(super) const AR_SREV_VERSION_9160: u32 = 0x40;
pub(super) const AR_SREV_VERSION_9280: u32 = 0x80;
pub(super) const AR_SREV_VERSION_9285: u32 = 0xc0;
pub(super) const AR_SREV_VERSION_9287: u32 = 0x180;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Chip {
    /// AR5416 PCI (`0x0023`) / AR5418 PCIe (`0x0024`): AR5008 PHY.
    Ar5416,
    /// AR9160 PCI (`0x0027`): AR9001 (AR5008 PHY ops).
    Ar9160,
    /// AR9280 PCI/PCIe (`0x0029`/`0x002a`): AR9002 dual-band.
    Ar9280,
    /// AR9285 (`0x002b`) and AR2427 (`0x002c`): AR9002, one chain.
    Ar9285,
    /// AR9287 PCI/PCIe (`0x002d`/`0x002e`): AR9002, two chains, 2.4 GHz.
    Ar9287,
}

/// The decoded `AR_SREV` facts (`ah->hw_version.macVersion/macRev`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Revision {
    pub chip: Chip,
    pub mac_version: u32,
    pub mac_rev: u8,
}

impl Revision {
    /// `hw.c::ath9k_hw_read_revisions` for PCI parts (no AR9100/SoC device
    /// IDs). The `AR_SREV_ID == 0xff` format carries
    /// `(srev & AR_SREV_VERSION2) >> AR_SREV_TYPE2_S` (Linux's shift of 12,
    /// not `AR_SREV_VERSION2_S`) and `AR_SREV_REVISION2`; the legacy format
    /// carries `MS(srev, AR_SREV_VERSION)` and `AR_SREV_REVISION`. Versions
    /// outside `ath9k_hw_init`'s accepted AR5008/AR9001/AR9002 PCI set (and
    /// the AR9003 EDMA parts this driver does not implement) are refused.
    pub fn decode(srev: u32) -> Option<Self> {
        if srev == u32::MAX {
            return None;
        }
        let (mac_version, mac_rev) = if srev & 0xff == 0xff {
            ((srev & 0xfffc_0000) >> 12, ((srev >> 8) & 0xf) as u8)
        } else {
            ((srev & 0xf0) >> 4, (srev & 0x7) as u8)
        };
        let chip = match mac_version {
            AR_SREV_VERSION_5416_PCI | AR_SREV_VERSION_5416_PCIE => Chip::Ar5416,
            AR_SREV_VERSION_9160 => Chip::Ar9160,
            AR_SREV_VERSION_9280 => Chip::Ar9280,
            AR_SREV_VERSION_9285 => Chip::Ar9285,
            AR_SREV_VERSION_9287 => Chip::Ar9287,
            _ => return None,
        };
        Some(Self {
            chip,
            mac_version,
            mac_rev,
        })
    }

    /// `AR_SREV_9287_13_OR_LATER`: async FIFO, 117 MHz MAC clock
    /// (`hw.c::ath9k_hw_set_clockrate`, `ath9k_hw_init_global_settings`).
    pub fn ar9287_async_fifo(&self) -> bool {
        self.chip == Chip::Ar9287 && self.mac_rev >= 3
    }
}

impl Chip {
    /// `hw.h` PCI device IDs (`pci.c::ath_pci_id_table`) for these families.
    pub fn for_device(device: u16) -> Option<Self> {
        Some(match device {
            0x0023 | 0x0024 => Self::Ar5416,
            0x0027 => Self::Ar9160,
            0x0029 | 0x002a => Self::Ar9280,
            0x002b | 0x002c => Self::Ar9285,
            0x002d | 0x002e => Self::Ar9287,
            _ => return None,
        })
    }

    pub fn eeprom_map(self) -> &'static EepromMap {
        match self {
            Self::Ar9285 => &MAP_4K,
            Self::Ar9287 => &MAP_9287,
            Self::Ar5416 | Self::Ar9160 | Self::Ar9280 => &MAP_DEF,
        }
    }

    /// Hardware RX/TX chains: AR5416/AR9160 three (`AR5416_MAX_CHAINS`),
    /// AR9280/AR9287 two (`AR9287_MAX_CHAINS`), AR9285 one.
    pub fn max_chains(self) -> u8 {
        match self {
            Self::Ar5416 | Self::Ar9160 => 3,
            Self::Ar9280 | Self::Ar9287 => 2,
            Self::Ar9285 => 1,
        }
    }
}

/// The factory map a family reads through the `AR5416_EEPROM_OFFSET`
/// window (`pci.c::ath_pci_eeprom_read`), in 16-bit words.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct EepromMap {
    /// First word (`AR5416_EEP_START_LOC` / `AR9287_EEP_START_LOC`).
    pub start_word: usize,
    /// Words read (`SIZE_EEPROM_*` = `sizeof(map) / sizeof(u16)`).
    pub words: usize,
    /// Chains whose bits may appear in `rxMask`/`txMask`.
    pub chains: u8,
    /// Linux `ath9k_hw_4k_check_eeprom` clamps the checksum span, but this
    /// tree's AR9285 path has always rejected odd or oversized lengths; keep
    /// that policy byte-identical for the 4k map only.
    pub strict_length: bool,
}

impl EepromMap {
    pub const fn bytes(&self) -> usize {
        self.words * 2
    }
    /// Words covered by the header-length checksum, or `None` for an
    /// unusable length. Non-4k maps follow `ath9k_hw_{ar9287,def}_check_eeprom`:
    /// `min(length / 2, SIZE_EEPROM)`. Every map refuses a header shorter
    /// than the 32-byte base identity it must cover.
    pub fn checksum_words(&self, length: usize) -> Option<usize> {
        if length < 32 {
            return None;
        }
        if self.strict_length {
            return (length <= self.bytes() && length & 1 == 0).then_some(length / 2);
        }
        Some((length / 2).min(self.words))
    }
    pub fn chainmask_valid(&self, mask: u8) -> bool {
        mask != 0 && u16::from(mask) < 1u16 << self.chains
    }
}

/// `struct ar5416_eeprom_4k` at word 64 (376 bytes, one chain).
pub(super) const MAP_4K: EepromMap = EepromMap {
    start_word: 64,
    words: 188,
    chains: 1,
    strict_length: true,
};
/// `struct ar9287_eeprom` at `AR9287_EEP_START_LOC` 128: 727 packed bytes,
/// of which `SIZE_EEPROM_AR9287` = 363 words are read (the trailing pad byte
/// is not).
pub(super) const MAP_9287: EepromMap = EepromMap {
    start_word: 128,
    words: 363,
    chains: 2,
    strict_length: false,
};
/// `struct ar5416_eeprom_def` at word 64 (3256 bytes, three chains).
pub(super) const MAP_DEF: EepromMap = EepromMap {
    start_word: 64,
    words: 1628,
    chains: 3,
    strict_length: false,
};

//! ixgbe VLAN filtering — VFTA / VLNCTRL / RXDCTL.VME.
//!
//! Grounding: Intel 82599 Datasheet rev. 2.0 §8.2.3.7.11 (VFTA at
//! 0x0A000 + 4*n, n = 0..127; bit i of register n passes VLAN tag
//! 32*n+i), §8.2.3.7.2 (VLNCTRL at 0x05088: VET bits 15:0 default
//! 0x8100, CFI bit 28, CFIEN bit 29, VFE bit 30), §8.2.3.8.6
//! (RXDCTL VME bit 30: strip the VLAN tag on received 802.1Q
//! packets for that queue). No Linux ixgbe source consulted.
//!
//! Semantics: with VFE set, a tagged frame passes only if its VID
//! bit is set in the VFTA (and, when CFIEN is set, its CFI bit
//! equals VLNCTRL.CFI); untagged frames are unaffected by the
//! table. VME is per-queue: a stripped frame's tag lands in the
//! RX descriptor's VLAN field (advanced descriptors; the legacy
//! descriptors this driver uses report it in `special` — see the
//! remainder note in the spec). This module programs the filter;
//! per-queue strip selection is exposed so a later advanced-
//! descriptor migration can consume the tag.

use alloc::vec::Vec;

use super::queues::RegBank;

/// VLAN filter table base (datasheet §8.2.3.7.11).
pub const REG_VFTA_BASE: u64 = 0x0A000;
/// VLAN filter table register count (4096 VIDs).
pub const VFTA_REGS: usize = 128;
/// VLAN control register (datasheet §8.2.3.7.2).
pub const REG_VLNCTRL: u64 = 0x05088;
/// VLNCTRL bits.
pub const VLNCTRL_VET_8021Q: u32 = 0x8100;
pub const VLNCTRL_CFI: u32 = 1 << 28;
pub const VLNCTRL_CFIEN: u32 = 1 << 29;
pub const VLNCTRL_VFE: u32 = 1 << 30;
/// RXDCTL VLAN-mode-enable (strip) bit (datasheet §8.2.3.8.6).
pub const RXDCTL_VME: u32 = 1 << 30;

/// VFTA register index + bit for a VLAN ID (0..=4095).
pub const fn vfta_slot(vid: u16) -> (usize, u32) {
    let vid = vid as usize & 0xFFF;
    (vid / 32, 1u32 << (vid % 32))
}

/// Build the 128-word VFTA from an allowed-VID list. Out-of-range
/// VIDs (> 4095) are ignored; duplicates collapse.
pub fn vfta_words(vids: &[u16]) -> [u32; VFTA_REGS] {
    let mut words = [0u32; VFTA_REGS];
    for &vid in vids {
        if vid > 4095 {
            continue;
        }
        let (reg, bit) = vfta_slot(vid);
        words[reg] |= bit;
    }
    words
}

/// Build the VLNCTRL word: TPID 0x8100 (the datasheet warns
/// software must not change the default), VFE set, CFI handling
/// only when the caller asks for it.
pub const fn vlnctrl_word(cfi_match: Option<bool>) -> u32 {
    let mut w = VLNCTRL_VET_8021Q | VLNCTRL_VFE;
    if let Some(cfi) = cfi_match {
        w |= VLNCTRL_CFIEN;
        if cfi {
            w |= VLNCTRL_CFI;
        }
    }
    w
}

/// VLAN filter programming: allowed VIDs + optional CFI match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VlanFilter {
    /// Allowed VIDs (each 0..=4095).
    pub vids: Vec<u16>,
    /// `Some(cfi)` enables CFI comparison against `cfi`.
    pub cfi_match: Option<bool>,
}

impl VlanFilter {
    /// Program VFTA + VLNCTRL into `bank`. Callers must have RX
    /// disabled (RXCTRL.RXEN = 0) while reprogramming filters.
    pub fn apply(&self, bank: &mut impl RegBank) {
        for (n, w) in vfta_words(&self.vids).iter().enumerate() {
            bank.write32(REG_VFTA_BASE + 4 * n as u64, *w);
        }
        bank.write32(REG_VLNCTRL, vlnctrl_word(self.cfi_match));
    }

    /// Disable filtering again: clear the table and clear VFE
    /// (leaving VET at its 0x8100 default).
    pub fn clear(bank: &mut impl RegBank) {
        for n in 0..VFTA_REGS {
            bank.write32(REG_VFTA_BASE + 4 * n as u64, 0);
        }
        bank.write32(REG_VLNCTRL, VLNCTRL_VET_8021Q);
    }
}

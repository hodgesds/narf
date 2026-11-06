//! Wake-on-LAN for the Atheros/Attansic `atl1c` family (issue #792).
//!
//! Linux reference: `drivers/net/ethernet/atheros/atl1c/atl1c_ethtool.c`
//! (`atl1c_get_wol` / `atl1c_set_wol`), `atl1c_hw.c`
//! (`atl1c_power_saving`, `atl1c_phy_to_ps_link`,
//! `atl1c_restart_autoneg`) and `atl1c_hw.h` (register + bit
//! definitions), plus `include/uapi/linux/ethtool.h` (`WAKE_*`) and
//! `include/uapi/linux/mii.h` (MII registers, LPA / ADVERTISE bits).
//!
//! The only wake filters this family can arm are magic-packet and
//! link-change: `atl1c_set_wol` rejects `WAKE_ARP`,
//! `WAKE_MAGICSECURE`, `WAKE_UCAST`, `WAKE_BCAST` and `WAKE_MCAST`
//! with `-EOPNOTSUPP`, and `atl1c_power_saving` only consumes the
//! `AT_WUFC_MAG` / `AT_WUFC_LNKC` bits of the WUFC word. The
//! `AT_WUFC_EX` / `AT_WUFC_MC` / `AT_WUFC_BC` bits exist in the
//! header but no set path can ever turn them on, so they are not
//! modeled here.
//!
//! The register program is a pure transcription of
//! `atl1c_power_saving`: given the live `MASTER_CTRL` / `MAC_CTRL` /
//! `GPHY_CTRL` words, the WUFC word, the last-known link speed /
//! duplex and the L2CB-revision quirk flag, it computes the four
//! words the suspend path writes. The PHY side effects (the
//! `MII_IER` write for link-change wake, the `MII_ISR` read that
//! clears a pending PHY interrupt) are separate calls the live
//! suspend path performs in Linux's order — PHY ops first, then
//! the four MMIO writes — and are covered by
//! [`phy_wake_setup`].
//!
//! The L2CB pattern quirk: on the AR8161 (`PCI_DEVICE_ID_ATHEROS_L2C_B`
//! `0x2060`, `atl1c_hw.h:59`) at revision `0xc1` (`L2CB_V11`,
//! `atl1c_hw.h:64`), a magic-packet arm also enables the pattern
//! matcher (`WOL_PATTERN_EN | WOL_PATTERN_PME_EN`), because that
//! silicon revision cannot wake on the magic pattern alone. The
//! live driver keys the quirk off the PCI device id + revision id
//! read at bring-up, exactly as Linux keys it off
//! `hw->nic_type == athr_l2c_b && hw->revision_id == L2CB_V11`.

use narf_driver_runtime::MmioRegion;

// ── ethtool WAKE_* (include/uapi/linux/ethtool.h) ───────────────────

/// Wake on PHY activity (link change).
pub const WAKE_PHY: u32 = 1 << 0;
/// Wake on unicast — rejected by this family.
pub const WAKE_UCAST: u32 = 1 << 1;
/// Wake on multicast — rejected by this family.
pub const WAKE_MCAST: u32 = 1 << 2;
/// Wake on broadcast — rejected by this family.
pub const WAKE_BCAST: u32 = 1 << 3;
/// Wake on ARP — rejected by this family.
pub const WAKE_ARP: u32 = 1 << 4;
/// Wake on magic packet.
pub const WAKE_MAGIC: u32 = 1 << 5;
/// Wake on magic packet with SecureOn password — rejected.
pub const WAKE_MAGICSECURE: u32 = 1 << 6;

// ── Registers (atl1c_hw.h) ──────────────────────────────────────────

/// `REG_MASTER_CTRL`.
pub const REG_MASTER_CTRL: u64 = 0x1400;
/// `REG_GPHY_CTRL`.
pub const REG_GPHY_CTRL: u64 = 0x140c;
/// `REG_MAC_CTRL`.
pub const REG_MAC_CTRL: u64 = 0x1480;
/// `REG_WOL_CTRL`.
pub const REG_WOL_CTRL: u64 = 0x14a0;

// ── MASTER_CTRL bits ────────────────────────────────────────────────

/// `MASTER_CTRL_CLK_SEL_DIS` — bit 12.
pub const MASTER_CTRL_CLK_SEL_DIS: u32 = 1 << 12;

// ── GPHY_CTRL bits ──────────────────────────────────────────────────

/// `GPHY_CTRL_EXT_RESET` — bit 0.
pub const GPHY_CTRL_EXT_RESET: u32 = 1 << 0;
/// `GPHY_CTRL_PHY_IDDQ` — bit 7.
pub const GPHY_CTRL_PHY_IDDQ: u32 = 1 << 7;
/// `GPHY_CTRL_HIB_EN` — bit 10.
pub const GPHY_CTRL_HIB_EN: u32 = 1 << 10;
/// `GPHY_CTRL_HIB_PULSE` — bit 11.
pub const GPHY_CTRL_HIB_PULSE: u32 = 1 << 11;
/// `GPHY_CTRL_SEL_ANA_RST` — bit 12.
pub const GPHY_CTRL_SEL_ANA_RST: u32 = 1 << 12;
/// `GPHY_CTRL_PHY_PLL_ON` — bit 13.
pub const GPHY_CTRL_PHY_PLL_ON: u32 = 1 << 13;
/// `GPHY_CTRL_PWDOWN_HW` — bit 14.
pub const GPHY_CTRL_PWDOWN_HW: u32 = 1 << 14;
/// `GPHY_CTRL_LED_MODE` — bit 2.
pub const GPHY_CTRL_LED_MODE: u32 = 1 << 2;
/// `GPHY_CTRL_100AB_EN` — bit 17.
pub const GPHY_CTRL_100AB_EN: u32 = 1 << 17;
/// `GPHY_CTRL_CLS` — `LED_MODE | 100AB_EN | PHY_PLL_ON`.
pub const GPHY_CTRL_CLS: u32 = GPHY_CTRL_LED_MODE | GPHY_CTRL_100AB_EN | GPHY_CTRL_PHY_PLL_ON;

// ── MAC_CTRL bits (field values mirrored in `atheros.rs`) ───────────

/// MAC_CTRL speed field mask, bits[21:20].
pub const MAC_CTRL_SPEED_MASK: u32 = 0b11 << 20;
/// MAC_CTRL speed field, 1000 Mbit.
pub const MAC_CTRL_SPEED_1000: u32 = 0b10 << 20;
/// MAC_CTRL speed field, 10/100 Mbit.
pub const MAC_CTRL_SPEED_10_100: u32 = 0b01 << 20;
/// `MAC_CTRL_TX_EN` — bit 0.
pub const MAC_CTRL_TX_EN: u32 = 1 << 0;
/// `MAC_CTRL_RX_EN` — bit 1.
pub const MAC_CTRL_RX_EN: u32 = 1 << 1;
/// `MAC_CTRL_DUPLX` — bit 5.
pub const MAC_CTRL_DUPLX: u32 = 1 << 5;
/// `MAC_CTRL_BC_EN` — bit 26.
pub const MAC_CTRL_BC_EN: u32 = 1 << 26;

// ── WOL_CTRL bits ───────────────────────────────────────────────────

/// `WOL_PATTERN_EN` — bit 0.
pub const WOL_PATTERN_EN: u32 = 1 << 0;
/// `WOL_PATTERN_PME_EN` — bit 1.
pub const WOL_PATTERN_PME_EN: u32 = 1 << 1;
/// `WOL_MAGIC_EN` — bit 2.
pub const WOL_MAGIC_EN: u32 = 1 << 2;
/// `WOL_MAGIC_PME_EN` — bit 3.
pub const WOL_MAGIC_PME_EN: u32 = 1 << 3;
/// `WOL_LINK_CHG_EN` — bit 4.
pub const WOL_LINK_CHG_EN: u32 = 1 << 4;
/// `WOL_LINK_CHG_PME_EN` — bit 5.
pub const WOL_LINK_CHG_PME_EN: u32 = 1 << 5;
/// `WOL_PATTERN_ST` — bit 8 (status: a pattern filter fired).
pub const WOL_PATTERN_ST: u32 = 1 << 8;
/// `WOL_MAGIC_ST` — bit 9 (status: a magic packet fired).
pub const WOL_MAGIC_ST: u32 = 1 << 9;
/// `WOL_LNKCHG_ST` — bit 10 (status: a link change fired).
pub const WOL_LNKCHG_ST: u32 = 1 << 10;

// ── WUFC bits (atl1c.h) ─────────────────────────────────────────────

/// `AT_WUFC_LNKC` — link change.
pub const AT_WUFC_LNKC: u32 = 0x1;
/// `AT_WUFC_MAG` — magic packet.
pub const AT_WUFC_MAG: u32 = 0x2;
/// `AT_WUFC_EX` — exact (unicast) match. Never armed: no set path.
pub const AT_WUFC_EX: u32 = 0x4;
/// `AT_WUFC_MC` — multicast match. Never armed: no set path.
pub const AT_WUFC_MC: u32 = 0x8;
/// `AT_WUFC_BC` — broadcast match. Never armed: no set path.
pub const AT_WUFC_BC: u32 = 0x10;

// ── L2CB quirk ──────────────────────────────────────────────────────

/// `L2CB_V11` revision id (`atl1c_hw.h:64`).
pub const L2CB_V11_REV: u8 = 0xc1;

// ── MII registers / bits (include/uapi/linux/mii.h, atl1c_hw.h) ─────

/// `MII_IER` — interrupt enable register (`atl1c_hw.h:835`).
pub const MII_IER: u8 = 0x12;
/// `IER_LINK_UP` — link-up interrupt enable (`atl1c_hw.h:836`).
pub const IER_LINK_UP: u16 = 0x0400;
/// `MII_ISR` — interrupt status register (`atl1c_hw.h:840`).
pub const MII_ISR: u8 = 0x13;
/// `MII_LPA` — link partner ability.
pub const MII_LPA: u8 = 0x05;
/// `MII_ADVERTISE` — autoneg advertisement.
pub const MII_ADVERTISE: u8 = 0x04;
/// `LPA_10HALF` / `ADVERTISE_10HALF`.
pub const LPA_10HALF: u16 = 0x0020;
/// `LPA_10FULL` / `ADVERTISE_10FULL`.
pub const LPA_10FULL: u16 = 0x0040;
/// `LPA_100HALF` / `ADVERTISE_100HALF`.
pub const LPA_100HALF: u16 = 0x0080;
/// `LPA_100FULL` / `ADVERTISE_100FULL`.
pub const LPA_100FULL: u16 = 0x0100;
/// `BMCR_RESET`.
pub const BMCR_RESET: u16 = 0x8000;
/// `BMCR_ANENABLE`.
pub const BMCR_ANENABLE: u16 = 0x1000;
/// `BMCR_ANRESTART`.
pub const BMCR_ANRESTART: u16 = 0x0200;

// ── Register-bank abstraction (fixture + live share the program) ────

/// Minimal 32-bit register bank, mirroring ixgbe's `queues::RegBank`.
/// Fixtures drive it with an in-memory bank; the live path adapts
/// the driver's `MmioRegion` through [`MmioRegBank`].
pub trait RegBank {
    fn read32(&self, offset: u64) -> u32;
    fn write32(&mut self, offset: u64, value: u32);
}

/// Live `RegBank` over an `MmioRegion`.
pub struct MmioRegBank<'a>(pub &'a MmioRegion);

impl RegBank for MmioRegBank<'_> {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: the caller owns the BAR0 mapping behind this bank.
        unsafe { self.0.read32(offset) }
    }
    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: same.
        unsafe { self.0.write32(offset, value) }
    }
}

// ── WoL filter set ──────────────────────────────────────────────────

/// The wake filters this family can arm. Only these two bits of the
/// WUFC word are reachable: every other `AT_WUFC_*` bit is rejected
/// at the set entry point (Linux `atl1c_set_wol`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WolFilters {
    /// Magic packet (`AT_WUFC_MAG`).
    pub magic: bool,
    /// Link change (`AT_WUFC_LNKC`).
    pub link_change: bool,
}

impl WolFilters {
    /// Magic-packet only.
    pub const fn magic_only() -> Self {
        Self {
            magic: true,
            link_change: false,
        }
    }

    /// Encode as a WUFC word.
    pub const fn to_wufc(self) -> u32 {
        (if self.magic { AT_WUFC_MAG } else { 0 })
            | (if self.link_change { AT_WUFC_LNKC } else { 0 })
    }

    /// Decode a WUFC word, dropping bits this family never arms.
    pub const fn from_wufc(wufc: u32) -> Self {
        Self {
            magic: wufc & AT_WUFC_MAG != 0,
            link_change: wufc & AT_WUFC_LNKC != 0,
        }
    }
}

/// The `ethtool` `supported` mask for this family: magic + PHY only
/// (Linux `atl1c_get_wol`: `WAKE_MAGIC | WAKE_PHY`).
pub const fn wol_supported_opts() -> u32 {
    WAKE_MAGIC | WAKE_PHY
}

/// Map a filter set to `ethtool` `wolopts`.
pub const fn wol_opts(filters: WolFilters) -> u32 {
    (if filters.magic { WAKE_MAGIC } else { 0 }) | (if filters.link_change { WAKE_PHY } else { 0 })
}

/// Set-side validation failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WolError {
    /// The request asked for a filter this family cannot arm.
    Unsupported,
}

/// Validate an `ethtool` `wolopts` word the way Linux
/// `atl1c_set_wol` does: the five unsupported kinds
/// (`WAKE_ARP | WAKE_MAGICSECURE | WAKE_UCAST | WAKE_BCAST |
/// `WAKE_MCAST`) are rejected; `WAKE_MAGIC` maps to the magic
/// filter and `WAKE_PHY` to link-change. Unknown high bits are
/// ignored, exactly as Linux's explicit-reject list ignores them.
pub const fn wol_filters_from_opts(wolopts: u32) -> Result<WolFilters, WolError> {
    if wolopts & (WAKE_ARP | WAKE_MAGICSECURE | WAKE_UCAST | WAKE_BCAST | WAKE_MCAST) != 0 {
        return Err(WolError::Unsupported);
    }
    Ok(WolFilters {
        magic: wolopts & WAKE_MAGIC != 0,
        link_change: wolopts & WAKE_PHY != 0,
    })
}

// ── Power-saving program (atl1c_power_saving, pure) ─────────────────

/// The four MMIO words `atl1c_power_saving` writes, in Linux's
/// write order: MASTER, MAC, GPHY, WOL_CTRL.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PowerSavingProgram {
    pub master: u32,
    pub mac: u32,
    pub gphy: u32,
    pub wol: u32,
}

/// Transcribe `atl1c_power_saving` without its PHY side effects.
///
/// Inputs are the live register words plus the last-known link
/// speed / duplex and the L2CB-revision quirk flag. The PHY
/// operations (`MII_IER` write for link-change wake, `MII_ISR`
/// read to clear a pending PHY interrupt) are the caller's job —
/// see [`phy_wake_setup`] — because they are MDIO transactions,
/// not MMIO words.
///
/// Shape of the transcription:
/// - MASTER always loses `CLK_SEL_DIS`; it regains it only on the
///   no-WoL branch, where the PHY also gains `PHY_IDDQ |
///   PWDOWN_HW` and WOL_CTRL goes to 0.
/// - MAC always takes the speed field from the link speed, drops
///   `DUPLX | RX_EN | TX_EN`, and regains `DUPLX` when full-duplex.
/// - GPHY always drops `EXT_RESET | CLS` and gains
///   `SEL_ANA_RST | HIB_PULSE | HIB_EN`; the WoL branch additionally
///   sets `EXT_RESET`.
/// - Magic adds `RX_EN | BC_EN` to MAC and `MAGIC_EN |
///   MAGIC_PME_EN` to WOL_CTRL (+ the pattern bits on L2CB v1.1).
/// - Link-change adds `LINK_CHG_EN | LINK_CHG_PME_EN` to WOL_CTRL.
pub const fn power_saving_program(
    master: u32,
    mac: u32,
    gphy: u32,
    wufc: u32,
    speed_1000: bool,
    duplex_full: bool,
    l2cb_v11: bool,
) -> PowerSavingProgram {
    let mut master = master & !MASTER_CTRL_CLK_SEL_DIS;
    let mut mac = (mac & !MAC_CTRL_SPEED_MASK)
        | if speed_1000 {
            MAC_CTRL_SPEED_1000
        } else {
            MAC_CTRL_SPEED_10_100
        };
    mac &= !(MAC_CTRL_DUPLX | MAC_CTRL_RX_EN | MAC_CTRL_TX_EN);
    if duplex_full {
        mac |= MAC_CTRL_DUPLX;
    }
    let mut gphy = gphy & !(GPHY_CTRL_EXT_RESET | GPHY_CTRL_CLS);
    gphy |= GPHY_CTRL_SEL_ANA_RST | GPHY_CTRL_HIB_PULSE | GPHY_CTRL_HIB_EN;
    let mut wol: u32 = 0;
    if wufc == 0 {
        master |= MASTER_CTRL_CLK_SEL_DIS;
        gphy |= GPHY_CTRL_PHY_IDDQ | GPHY_CTRL_PWDOWN_HW;
        return PowerSavingProgram {
            master,
            mac,
            gphy,
            wol,
        };
    }
    gphy |= GPHY_CTRL_EXT_RESET;
    if wufc & AT_WUFC_MAG != 0 {
        mac |= MAC_CTRL_RX_EN | MAC_CTRL_BC_EN;
        wol |= WOL_MAGIC_EN | WOL_MAGIC_PME_EN;
        if l2cb_v11 {
            wol |= WOL_PATTERN_EN | WOL_PATTERN_PME_EN;
        }
    }
    if wufc & AT_WUFC_LNKC != 0 {
        wol |= WOL_LINK_CHG_EN | WOL_LINK_CHG_PME_EN;
    }
    PowerSavingProgram {
        master,
        mac,
        gphy,
        wol,
    }
}

/// Write a computed program in Linux's order (MASTER, MAC, GPHY,
/// WOL_CTRL).
pub fn apply_power_saving(bank: &mut impl RegBank, program: &PowerSavingProgram) {
    bank.write32(REG_MASTER_CTRL, program.master);
    bank.write32(REG_MAC_CTRL, program.mac);
    bank.write32(REG_GPHY_CTRL, program.gphy);
    bank.write32(REG_WOL_CTRL, program.wol);
}

/// Whether the WUFC word needs the PHY-side wake setup: link-change
/// wake programs `MII_IER = IER_LINK_UP` and then reads `MII_ISR` to
/// clear any pending PHY interrupt. The `MII_ISR` read runs whenever
/// WoL is armed at all (`atl1c_power_saving` does it after the
/// `LNKC` block, still inside the `wufc != 0` branch); the
/// `MII_IER` write runs only for link-change.
pub const fn phy_wake_setup(wufc: u32) -> bool {
    wufc & AT_WUFC_LNKC != 0
}

// ── Power-saving link selection (atl1c_phy_to_ps_link, pure) ─────────

/// What `atl1c_phy_to_ps_link` decides from the link-partner
/// abilities: the autoneg advertisement to restart with, and the
/// speed / duplex the WoL program uses. The advertisement is the
/// *lowest* mode the partner claims, in Linux's check order:
/// 10FULL, then 10HALF, then 100HALF, then 100FULL (note the
/// half-before-full order at 100 Mbit — that is Linux's order, not
/// a typo). No LPA bits at all falls back to 10HALF, the value
/// Linux initialises `autoneg_advertised` to. A link that is down
/// when suspend starts needs no renegotiation: 10 Mbit half-duplex,
/// no advertisement write.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PsLinkTarget {
    /// `MII_ADVERTISE` word to write before the autoneg restart, or
    /// `None` when the link is down and no restart happens.
    pub advertise: Option<u16>,
    /// Speed the WoL program should encode.
    pub speed_1000: bool,
    /// Duplex the WoL program should encode.
    pub duplex_full: bool,
}

pub const fn ps_link_target(link_up: bool, lpa: u16) -> PsLinkTarget {
    if !link_up {
        return PsLinkTarget {
            advertise: None,
            speed_1000: false,
            duplex_full: false,
        };
    }
    if lpa & LPA_10FULL != 0 {
        PsLinkTarget {
            advertise: Some(0x0040),
            speed_1000: false,
            duplex_full: true,
        }
    } else if lpa & LPA_10HALF != 0 {
        PsLinkTarget {
            advertise: Some(0x0020),
            speed_1000: false,
            duplex_full: false,
        }
    } else if lpa & LPA_100HALF != 0 {
        PsLinkTarget {
            advertise: Some(0x0080),
            speed_1000: false,
            duplex_full: false,
        }
    } else if lpa & LPA_100FULL != 0 {
        PsLinkTarget {
            advertise: Some(0x0100),
            speed_1000: false,
            duplex_full: true,
        }
    } else {
        PsLinkTarget {
            advertise: Some(0x0020),
            speed_1000: false,
            duplex_full: false,
        }
    }
}

// ── Wake status decode ──────────────────────────────────────────────

/// Decoded `REG_WOL_CTRL` status bits. The status bits are read
/// live (the register is read-clear on this family), so a snapshot
/// is only meaningful immediately after a wake.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WakeStatus {
    pub raw: u32,
}

impl WakeStatus {
    /// A magic packet fired (`WOL_MAGIC_ST`).
    pub const fn magic(self) -> bool {
        self.raw & WOL_MAGIC_ST != 0
    }
    /// A link change fired (`WOL_LNKCHG_ST`).
    pub const fn link_change(self) -> bool {
        self.raw & WOL_LNKCHG_ST != 0
    }
    /// A pattern filter fired (`WOL_PATTERN_ST`).
    pub const fn pattern(self) -> bool {
        self.raw & WOL_PATTERN_ST != 0
    }
    /// Pattern slot `n` (0..=7) matched (`WOL_PT{n}_MATCH`,
    /// bits 24..31).
    pub const fn pattern_match(self, n: u8) -> bool {
        if n > 7 {
            return false;
        }
        self.raw & (1 << (24 + n)) != 0
    }
}

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct FakeBank {
        regs: alloc::vec::Vec<u32>,
    }

    impl FakeBank {
        fn new() -> Self {
            Self {
                regs: alloc::vec![0u32; 0x2000 / 4],
            }
        }
    }

    impl RegBank for FakeBank {
        fn read32(&self, offset: u64) -> u32 {
            if offset % 4 != 0 {
                return 0;
            }
            self.regs.get((offset / 4) as usize).copied().unwrap_or(0)
        }
        fn write32(&mut self, offset: u64, value: u32) {
            if offset % 4 != 0 {
                return;
            }
            if let Some(slot) = self.regs.get_mut((offset / 4) as usize) {
                *slot = value;
            }
        }
    }

    fn smoke_atheros_wol_set_validation() -> TestResult {
        // Magic-only and PHY-only map to their filters.
        match wol_filters_from_opts(WAKE_MAGIC) {
            Ok(f) if f == WolFilters::magic_only() => {}
            _ => return TestResult::Fail("WAKE_MAGIC did not map to magic-only"),
        }
        match wol_filters_from_opts(WAKE_PHY) {
            Ok(f) if f.magic == false && f.link_change => {}
            _ => return TestResult::Fail("WAKE_PHY did not map to link-change-only"),
        }
        match wol_filters_from_opts(WAKE_MAGIC | WAKE_PHY) {
            Ok(f) if f.magic && f.link_change => {}
            _ => return TestResult::Fail("MAGIC|PHY did not map to both filters"),
        }
        if wol_filters_from_opts(0).map(|f| f.to_wufc()) != Ok(0) {
            return TestResult::Fail("zero wolopts did not map to empty filters");
        }
        // Each rejected kind fails, alone and combined with magic.
        for bad in [
            WAKE_ARP,
            WAKE_MAGICSECURE,
            WAKE_UCAST,
            WAKE_BCAST,
            WAKE_MCAST,
        ] {
            if wol_filters_from_opts(bad) != Err(WolError::Unsupported) {
                return TestResult::Fail("unsupported wolopt was not rejected");
            }
            if wol_filters_from_opts(WAKE_MAGIC | bad) != Err(WolError::Unsupported) {
                return TestResult::Fail("magic+unsupported wolopt was not rejected");
            }
        }
        // Supported mask and get mapping.
        if wol_supported_opts() != 0x21 {
            return TestResult::Fail("supported mask is not WAKE_MAGIC|WAKE_PHY (0x21)");
        }
        if wol_opts(WolFilters::magic_only()) != WAKE_MAGIC {
            return TestResult::Fail("magic-only wolopts wrong");
        }
        if wol_opts(WolFilters {
            magic: false,
            link_change: true,
        }) != WAKE_PHY
        {
            return TestResult::Fail("link-change-only wolopts wrong");
        }
        if WolFilters::magic_only().to_wufc() != 0x2 {
            return TestResult::Fail("magic-only WUFC word wrong");
        }
        if (WolFilters {
            magic: true,
            link_change: true,
        })
        .to_wufc()
            != 0x3
        {
            return TestResult::Fail("magic+link-change WUFC word wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/atheros", smoke_atheros_wol_set_validation);

    fn smoke_atheros_wol_power_saving() -> TestResult {
        // Bring-up MAC word, MASTER with CLK_SEL_DIS set, GPHY zero.
        let mac_bringup: u32 = 0x0620_00e3;
        let master_bringup: u32 = 0x0000_1000;
        // Magic-only, 1000/FD, not the L2CB quirk part.
        let p = power_saving_program(
            master_bringup,
            mac_bringup,
            0,
            AT_WUFC_MAG,
            true,
            true,
            false,
        );
        if p.wol != 0xC {
            return TestResult::Fail("magic-only WOL_CTRL is not MAGIC_EN|MAGIC_PME_EN (0xC)");
        }
        if p.master & MASTER_CTRL_CLK_SEL_DIS != 0 {
            return TestResult::Fail("CLK_SEL_DIS not cleared on the WoL branch");
        }
        if p.mac & MAC_CTRL_SPEED_MASK != MAC_CTRL_SPEED_1000 {
            return TestResult::Fail("MAC speed field is not 1000 on a 1000 link");
        }
        if p.mac & MAC_CTRL_TX_EN != 0 {
            return TestResult::Fail("MAC TX_EN not dropped by the power-saving program");
        }
        if p.mac & MAC_CTRL_RX_EN == 0 || p.mac & MAC_CTRL_BC_EN == 0 {
            return TestResult::Fail("magic arm did not set MAC RX_EN|BC_EN");
        }
        if p.mac & MAC_CTRL_DUPLX == 0 {
            return TestResult::Fail("full-duplex did not restore MAC DUPLX");
        }
        if p.gphy & (GPHY_CTRL_SEL_ANA_RST | GPHY_CTRL_HIB_PULSE | GPHY_CTRL_HIB_EN)
            != (GPHY_CTRL_SEL_ANA_RST | GPHY_CTRL_HIB_PULSE | GPHY_CTRL_HIB_EN)
        {
            return TestResult::Fail("GPHY hibernate bits missing on the WoL branch");
        }
        if p.gphy & GPHY_CTRL_EXT_RESET == 0 {
            return TestResult::Fail("GPHY EXT_RESET not set on the WoL branch");
        }
        if p.gphy & GPHY_CTRL_PWDOWN_HW != 0 || p.gphy & GPHY_CTRL_PHY_IDDQ != 0 {
            return TestResult::Fail("WoL branch must not power down the PHY");
        }
        // L2CB v1.1 quirk: pattern bits join the magic arm.
        let q = power_saving_program(
            master_bringup,
            mac_bringup,
            0,
            AT_WUFC_MAG,
            true,
            true,
            true,
        );
        if q.wol != 0xF {
            return TestResult::Fail("L2CB quirk arm is not 0xF (magic + pattern)");
        }
        // Link-change only: no MAC RX_EN, WOL_CTRL is the link pair.
        let l = power_saving_program(
            master_bringup,
            mac_bringup,
            0,
            AT_WUFC_LNKC,
            false,
            false,
            false,
        );
        if l.wol != 0x30 {
            return TestResult::Fail("link-change-only WOL_CTRL is not 0x30");
        }
        if l.mac & MAC_CTRL_RX_EN != 0 {
            return TestResult::Fail("link-change arm must not set MAC RX_EN");
        }
        if l.mac & MAC_CTRL_SPEED_MASK != MAC_CTRL_SPEED_10_100 {
            return TestResult::Fail("MAC speed field is not 10/100 on a 100 link");
        }
        if l.mac & MAC_CTRL_DUPLX != 0 {
            return TestResult::Fail("half-duplex set MAC DUPLX");
        }
        // No WoL: clock-select disabled, PHY powered down, WOL_CTRL 0.
        let n = power_saving_program(master_bringup, mac_bringup, 0, 0, true, true, false);
        if n.wol != 0 {
            return TestResult::Fail("no-WoL program left WOL_CTRL armed");
        }
        if n.master & MASTER_CTRL_CLK_SEL_DIS == 0 {
            return TestResult::Fail("no-WoL program did not set CLK_SEL_DIS");
        }
        if n.gphy & (GPHY_CTRL_PHY_IDDQ | GPHY_CTRL_PWDOWN_HW)
            != (GPHY_CTRL_PHY_IDDQ | GPHY_CTRL_PWDOWN_HW)
        {
            return TestResult::Fail("no-WoL program did not power down the PHY");
        }
        if n.mac & MAC_CTRL_RX_EN != 0 {
            return TestResult::Fail("no-WoL program left MAC RX_EN set");
        }
        // The register conversation: the four words land in Linux's order.
        let mut bank = FakeBank::new();
        bank.write32(REG_MASTER_CTRL, master_bringup);
        bank.write32(REG_MAC_CTRL, mac_bringup);
        bank.write32(REG_GPHY_CTRL, 0);
        bank.write32(REG_WOL_CTRL, 0xFFFF_FFFF);
        let program = power_saving_program(
            bank.read32(REG_MASTER_CTRL),
            bank.read32(REG_MAC_CTRL),
            bank.read32(REG_GPHY_CTRL),
            AT_WUFC_MAG,
            true,
            true,
            false,
        );
        apply_power_saving(&mut bank, &program);
        if bank.read32(REG_WOL_CTRL) != 0xC {
            return TestResult::Fail("apply did not land WOL_CTRL 0xC");
        }
        if bank.read32(REG_MASTER_CTRL) & MASTER_CTRL_CLK_SEL_DIS != 0 {
            return TestResult::Fail("apply left CLK_SEL_DIS set");
        }
        if bank.read32(REG_MAC_CTRL) & MAC_CTRL_RX_EN == 0 {
            return TestResult::Fail("apply did not set MAC RX_EN");
        }
        if bank.read32(REG_GPHY_CTRL) & GPHY_CTRL_EXT_RESET == 0 {
            return TestResult::Fail("apply did not set GPHY EXT_RESET");
        }
        // PHY-side setup: only link-change needs the MII_IER write.
        if !phy_wake_setup(AT_WUFC_LNKC) || phy_wake_setup(AT_WUFC_MAG) {
            return TestResult::Fail("phy_wake_setup is not exactly the LNKC bit");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/atheros", smoke_atheros_wol_power_saving);

    fn smoke_atheros_wol_ps_link() -> TestResult {
        let down = ps_link_target(false, 0);
        if down.advertise.is_some() || down.speed_1000 || down.duplex_full {
            return TestResult::Fail("link-down target is not 10/HD with no restart");
        }
        let t = ps_link_target(true, LPA_10FULL);
        if t.advertise != Some(0x0040) || t.speed_1000 || !t.duplex_full {
            return TestResult::Fail("LPA 10FULL target wrong");
        }
        let t = ps_link_target(true, LPA_10HALF);
        if t.advertise != Some(0x0020) || t.speed_1000 || t.duplex_full {
            return TestResult::Fail("LPA 10HALF target wrong");
        }
        // Linux checks 100HALF before 100FULL.
        let t = ps_link_target(true, LPA_100HALF | LPA_100FULL);
        if t.advertise != Some(0x0080) || t.speed_1000 || t.duplex_full {
            return TestResult::Fail("LPA 100HALF must win over 100FULL");
        }
        let t = ps_link_target(true, LPA_100FULL);
        if t.advertise != Some(0x0100) || t.speed_1000 || !t.duplex_full {
            return TestResult::Fail("LPA 100FULL target wrong");
        }
        let t = ps_link_target(true, 0);
        if t.advertise != Some(0x0020) || t.speed_1000 || t.duplex_full {
            return TestResult::Fail("empty LPA must fall back to 10HALF");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/atheros", smoke_atheros_wol_ps_link);

    fn smoke_atheros_wol_status() -> TestResult {
        let st = WakeStatus {
            raw: WOL_MAGIC_ST | WOL_LNKCHG_ST | (1 << (24 + 2)),
        };
        if !st.magic() || !st.link_change() || st.pattern() {
            return TestResult::Fail("WakeStatus magic/link-change decode wrong");
        }
        if !st.pattern_match(2) || st.pattern_match(3) || st.pattern_match(8) {
            return TestResult::Fail("WakeStatus pattern-slot decode wrong");
        }
        let st = WakeStatus {
            raw: WOL_PATTERN_ST,
        };
        if !st.pattern() || st.magic() {
            return TestResult::Fail("WakeStatus pattern decode wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/atheros", smoke_atheros_wol_status);
}

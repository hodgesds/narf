//! EEE (Energy Efficient Ethernet, IEEE 802.3az) advertisement +
//! ethtool get/set for the igb copper parts (82576, I350, I210/I211
//! copper). Fiber/SerDes/SGMII parts have no copper PHY to negotiate
//! EEE on and report not-capable (see [`eee_capable_device`]).
//!
//! Grounding — every register and bit below comes from an in-tree
//! source, never from memory:
//!
//! * Clause 45 MMD device 7 (PCS) registers 60/61/62/63 and the
//!   MMDAC (13) / MMDAAD (14) Clause 22 window, with the data-phase
//!   `dev | 0x4000` step: exactly igc's `mmd()` in
//!   `drivers/net/igc/src/hardware.rs`, which Linux's `igc_setup_link`
//!   / `igc_ethtool_get_eee` use for the same registers.
//! * The MMD 7/60 bit map (bit 1 = 100BASE-TX EEE, bit 2 =
//!   1000BASE-T EEE; 7/62 bit 0 = 2.5GBASE-T EEE) and the
//!   `narf_net::nic::EeeStatus` advertisement encoding (8 = 100M,
//!   16 = 1G, 32 = 2.5G): igc's `modes()` closure.
//! * IPCNFG (0x0E38) EEE-advertise bits 12 (100M) and 14 (1G) and
//!   EEER (0x0E30) LPI bits 16/17/18: Linux `defines.h`
//!   (`E1000_IPCNFG_EEE_*_AN`, `E1000_EEER_*`), as already cited
//!   in-tree by `drivers/net/e1000/src/e1000.rs` for the same
//!   e1000-generation MAC register map. NOTE the generation split:
//!   igc's I225 writes IPCNFG bits 2–4 for the same logical field —
//!   this module uses the e1000-generation bits 12/14, which are
//!   the ones the 82576/I350/I210 MAC implements.
//! * MDIC opcodes (write `0b01 << 26`, read `0b10 << 26`), READY
//!   bit 28 and ERROR bit 30: the e1000 crate's MDIC block (Linux
//!   `E1000_MDIC_*`) and igc's `mdio()`.
//! * Set shape (MMD advertisement, then IPCNFG, then EEER, then a
//!   BMCR autoneg restart so the new advertisement goes on the
//!   wire): igc's `setup_link` EEE block. The restart is required —
//!   an advertisement change only takes effect at the next autoneg.
//!
//! Live-link caveat (stated plainly, not hidden): igb forces 1 GbE
//! full-duplex at the MAC (`CTRL_FRCSPD`/`FRCDPLX`, autoneg
//! reported off), so a programmed EEE advertisement is negotiated
//! by the PHY autoneg the BMCR restart kicks, while the MAC side
//! stays forced. `eee_status` therefore reports the programmed
//! advertisement and the partner set it can observe; `active` is
//! the negotiated intersection (advertised ∩ partner, link up),
//! exactly the derivation ixgbe's FW-PHY path uses. If the link
//! policy later gains autoneg, no EEE change is needed — the same
//! registers drive the negotiation.
//!
//! Register access is injected through [`EeeRegs`] (the igc
//! `Registers` pattern) so the whole register conversation is
//! fixture-testable: the fake in `tests` scripts the MMD map and
//! the MAC registers and observes every write. The real impl
//! ([`MmioEeeRegs`]) is a thin wrapper over `MmioRegion`.

use narf_net::nic::EeeStatus;

use super::{
    IgbError, MDIC_ERROR, MDIC_OP_READ, MDIC_OP_WRITE, MDIC_PHY_ADDR, MDIC_READY, PHY_BMCR,
    PHY_BMCR_ANENABLE, PHY_BMCR_ANRESTART, REG_MDIC, REG_STATUS,
};

/// STATUS link-up bit (bit 1) — `Igb::link_up` reads the same bit.
pub const STATUS_LU: u32 = 1 << 1;

/// IPCNFG — In-band Configuration (e1000-generation MAC map).
pub const REG_IPCNFG: u64 = 0x0E38;
/// IPCNFG EEE 1000BASE-T advertise bit (Linux `E1000_IPCNFG_EEE_1G_AN`).
pub const IPCNFG_EEE_1G_AN: u32 = 1 << 14;
/// IPCNFG EEE 100BASE-TX advertise bit (Linux `E1000_IPCNFG_EEE_100M_AN`).
pub const IPCNFG_EEE_100M_AN: u32 = 1 << 12;
/// IPCNFG EEE-advertise mask (both speeds).
pub const IPCNFG_EEE_AN_MASK: u32 = IPCNFG_EEE_1G_AN | IPCNFG_EEE_100M_AN;

/// EEER — Energy Efficient Ethernet Register (e1000-generation MAC map).
pub const REG_EEER: u64 = 0x0E30;
/// EEER TX LPI enable (Linux `E1000_EEER_TX_LPI_EN`).
pub const EEER_TX_LPI_EN: u32 = 1 << 16;
/// EEER RX LPI enable (Linux `E1000_EEER_RX_LPI_EN`).
pub const EEER_RX_LPI_EN: u32 = 1 << 17;
/// EEER LPI frame counter (Linux `E1000_EEER_LPI_FC`).
pub const EEER_LPI_FC: u32 = 1 << 18;
/// EEER LPI mask (TX + RX LPI enable + frame counter).
pub const EEER_LPI_MASK: u32 = EEER_TX_LPI_EN | EEER_RX_LPI_EN | EEER_LPI_FC;

/// Clause 45 MMD device 7 (PCS) — the EEE register device.
pub const EEE_MMD_DEV: u16 = 7;
/// MMD EEE advertisement register.
pub const EEE_MMD_ADV: u16 = 60;
/// MMD link-partner EEE advertisement register.
pub const EEE_MMD_LP_ADV: u16 = 61;
/// MMD EEE advertisement-2 register (2.5GBASE-T).
pub const EEE_MMD_ADV2: u16 = 62;
/// MMD link-partner EEE advertisement-2 register.
pub const EEE_MMD_LP_ADV2: u16 = 63;
/// Clause 22 MMD access-control register (MMDAC).
pub const PHY_MMDAC: u8 = 13;
/// Clause 22 MMD access address/data register (MMDAAD).
pub const PHY_MMDAAD: u8 = 14;
/// MMDAC function field for the data phase (bit 14: data access,
/// no address post-increment) — igc's `mmd()` writes `dev | 0x4000`.
pub const MMDAC_FUN_DATA: u16 = 0x4000;

/// `EeeStatus` advertised/partner bit: 100BASE-TX EEE.
pub const EEE_ADV_100M: u32 = 1 << 3;
/// `EeeStatus` advertised/partner bit: 1000BASE-T EEE.
pub const EEE_ADV_1G: u32 = 1 << 4;
/// `EeeStatus` advertised/partner bit: 2.5GBASE-T EEE.
pub const EEE_ADV_2_5G: u32 = 1 << 5;
/// Speeds an igb copper part can advertise EEE on (100M + 1G only —
/// every igb part is 1 GbE max; there is no 2.5G mode to advertise).
pub const EEE_SUPPORTED: u32 = EEE_ADV_100M | EEE_ADV_1G;

/// `true` iff `did` is an igb copper part with a PHY that can
/// negotiate EEE. Fiber/SerDes/SGMII parts have no copper PHY and
/// are not capable — EEE is a copper autonegotiation feature.
pub fn eee_capable_device(did: u16) -> bool {
    matches!(
        did,
        super::IGB_I210_COPPER
            | super::IGB_I210_COPPER_FLASHLESS
            | super::IGB_I211_COPPER
            | super::IGB_82576
            | super::IGB_82576_NS
            | super::IGB_I350_COPPER
    )
}

/// Register access for the EEE conversation, injected so tests can
/// script the PHY/MAC state (the igc `Registers` pattern). The
/// real impl is [`MmioEeeRegs`]; the fake lives in `tests`.
pub trait EeeRegs {
    fn read32(&self, reg: u64) -> u32;
    fn write32(&self, reg: u64, value: u32);
    fn wait(&self, us: u64, ready: impl FnMut() -> bool) -> bool;
}

/// [`EeeRegs`] over a live BAR0 mapping.
#[derive(Debug)]
pub struct MmioEeeRegs<'a>(pub &'a narf_bus::MmioRegion);

impl EeeRegs for MmioEeeRegs<'_> {
    fn read32(&self, reg: u64) -> u32 {
        // SAFETY: mapped MMIO; the caller owns BAR0.
        unsafe { self.0.read32(reg) }
    }

    fn write32(&self, reg: u64, value: u32) {
        // SAFETY: mapped MMIO; the caller owns BAR0.
        unsafe { self.0.write32(reg, value) }
    }

    fn wait(&self, us: u64, ready: impl FnMut() -> bool) -> bool {
        narf_scheduler::responsive_spin_until(ready, narf_time::Deadline::after_us(us))
    }
}

/// Decode an EEE advertisement pair (MMD 7/60 + 7/62) into the
/// `EeeStatus` bit encoding — the shared decode
/// ([`crate::phy::eee_modes_from_mmd`]); this keeps the name
/// the existing call sites and smokes use.
pub fn eee_modes(local: u16, local2: u16) -> u32 {
    crate::phy::eee_modes_from_mmd(local, local2)
}

/// MMD advertisement words (7/60, 7/62) for an advertised set:
/// the shared encode ([`crate::phy::eee_mmd_adv_words`]),
/// the inverse of [`eee_modes`] (igc's `setup_link` writes the
/// same words).
pub fn eee_mmd_adv(advertised: u32) -> (u16, u16) {
    crate::phy::eee_mmd_adv_words(advertised)
}

/// Next IPCNFG word for an advertised set: rewrite only the
/// e1000-generation EEE-advertise bits (1G bit 14, 100M bit 12)
/// and preserve every other field. A 2.5G request bit has no
/// IPCNFG bit on these parts and is dropped, never programmed.
pub fn eee_ipcnfg_next(current: u32, advertised: u32) -> u32 {
    (current & !IPCNFG_EEE_AN_MASK)
        | (if advertised & EEE_ADV_100M != 0 {
            IPCNFG_EEE_100M_AN
        } else {
            0
        })
        | (if advertised & EEE_ADV_1G != 0 {
            IPCNFG_EEE_1G_AN
        } else {
            0
        })
}

/// Next EEER word for an enable/disable: rewrite only the LPI
/// mask (bits 16/17/18) and preserve every other field.
pub fn eee_eeer_next(current: u32, enable: bool) -> u32 {
    (current & !EEER_LPI_MASK) | (if enable { EEER_LPI_MASK } else { 0 })
}

/// EEE status from scripted state. Active is the negotiated
/// intersection — advertised ∩ partner, gated on live link-up —
/// the same derivation ixgbe's FW-PHY path uses; `tx_lpi` is
/// EEER TX-LPI-EN as read.
pub fn eee_status_from(advertised: u32, partner: u32, link_up: bool, tx_lpi: bool) -> EeeStatus {
    EeeStatus {
        advertised,
        partner,
        active: link_up && (advertised & partner) != 0,
        tx_lpi,
    }
}

/// One MDIO transaction (Clause 22 register `reg`): write the
/// command word, poll READY, check the ERROR bit and the register
/// echo — exactly igc's `mdio()` (same opcodes, same 30 ms bound).
fn mdio(r: &impl EeeRegs, reg: u8, value: Option<u16>) -> Result<u16, IgbError> {
    let command = (u32::from(reg) << 16)
        | MDIC_PHY_ADDR
        | value.map_or(MDIC_OP_READ, |v| MDIC_OP_WRITE | u32::from(v));
    r.write32(REG_MDIC, command);
    if !r.wait(30_000, || r.read32(REG_MDIC) & MDIC_READY != 0) {
        return Err(IgbError::Other("eee mdic timeout"));
    }
    let result = r.read32(REG_MDIC);
    if result & MDIC_ERROR != 0 || (result >> 16) & 31 != u32::from(reg) {
        return Err(IgbError::Other("eee mdic completion error"));
    }
    Ok(result as u16)
}

/// One Clause 45 MMD access (device `dev`, register `reg`) through
/// the Clause 22 MMDAC/MMDAAD window — exactly igc's `mmd()`.
/// A cleanup failure (restoring MMDAC to 0) is an error too.
fn mmd(r: &impl EeeRegs, dev: u16, reg: u16, value: Option<u16>) -> Result<u16, IgbError> {
    mdio(r, PHY_MMDAC, Some(dev))?;
    mdio(r, PHY_MMDAAD, Some(reg))?;
    mdio(r, PHY_MMDAC, Some(dev | MMDAC_FUN_DATA))?;
    let result = mdio(r, PHY_MMDAAD, value);
    let cleanup = mdio(r, PHY_MMDAC, Some(0));
    cleanup?;
    result
}

/// EEE status from live registers: advertised from MMD 7/60+62,
/// link-partner from MMD 7/61+63, TX-LPI from EEER bit 16,
/// link-up from live STATUS.LU — the igc `eee_status` shape.
pub fn eee_status(r: &impl EeeRegs) -> Result<EeeStatus, IgbError> {
    let local = mmd(r, EEE_MMD_DEV, EEE_MMD_ADV, None)?;
    let local2 = mmd(r, EEE_MMD_DEV, EEE_MMD_ADV2, None)?;
    let partner = mmd(r, EEE_MMD_DEV, EEE_MMD_LP_ADV, None)?;
    let partner2 = mmd(r, EEE_MMD_DEV, EEE_MMD_LP_ADV2, None)?;
    let advertised = eee_modes(local, local2);
    let partner_modes = eee_modes(partner, partner2);
    let link_up = r.read32(REG_STATUS) & STATUS_LU != 0;
    let tx_lpi = r.read32(REG_EEER) & EEER_TX_LPI_EN != 0;
    Ok(eee_status_from(advertised, partner_modes, link_up, tx_lpi))
}

/// Enable or disable EEE advertisement (igc `setup_link`'s EEE
/// block shape): MMD 7/60+62 advertisement, IPCNFG advertise
/// bits, EEER LPI bits, then a BMCR autoneg restart so the new
/// advertisement goes on the wire. Already-in-state still
/// rewrites the words and restarts autoneg — the caller owns the
/// no-op decision (unlike e1000's `set_eee`, which early-outs):
/// igb's bring-up forces the MAC link, so a set that skips the
/// restart could leave the PHY advertising a stale set with no
/// later trigger to renegotiate.
pub fn set_eee(r: &impl EeeRegs, enable: bool) -> Result<(), IgbError> {
    let advertised = if enable { EEE_SUPPORTED } else { 0 };
    let (adv60, adv62) = eee_mmd_adv(advertised);
    mmd(r, EEE_MMD_DEV, EEE_MMD_ADV, Some(adv60))?;
    mmd(r, EEE_MMD_DEV, EEE_MMD_ADV2, Some(adv62))?;
    r.write32(
        REG_IPCNFG,
        eee_ipcnfg_next(r.read32(REG_IPCNFG), advertised),
    );
    r.write32(REG_EEER, eee_eeer_next(r.read32(REG_EEER), enable));
    let bmcr = mdio(r, PHY_BMCR as u8, None)?;
    mdio(
        r,
        PHY_BMCR as u8,
        Some(bmcr | PHY_BMCR_ANENABLE | PHY_BMCR_ANRESTART),
    )?;
    Ok(())
}

#[cfg(any(test, feature = "builtin"))]
mod tests {
    use alloc::collections::BTreeMap;
    use core::cell::RefCell;

    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::*;

    /// Scripted register file for the EEE conversation, modeled on
    /// igc's `Model` fake: MAC registers in `regs`, Clause 22 PHY
    /// registers in `phy`, Clause 45 MMD cells in `mmd`. MDIC
    /// completion is modeled — a read command returns READY plus
    /// the scripted data, a write lands it — so `mdio`/`mmd`
    /// run the real transaction sequence against scripted state.
    struct FakeRegs {
        regs: RefCell<BTreeMap<u64, u32>>,
        phy: RefCell<BTreeMap<u8, u16>>,
        mmd: RefCell<BTreeMap<(u16, u16), u16>>,
        mmd_dev: RefCell<u16>,
        mmd_reg: RefCell<u16>,
    }

    impl FakeRegs {
        fn new() -> Self {
            Self {
                regs: RefCell::new(BTreeMap::new()),
                phy: RefCell::new(BTreeMap::new()),
                mmd: RefCell::new(BTreeMap::new()),
                mmd_dev: RefCell::new(0),
                mmd_reg: RefCell::new(0),
            }
        }

        fn value(&self, reg: u64) -> u32 {
            *self.regs.borrow().get(&reg).unwrap_or(&0)
        }

        fn phy_value(&self, reg: u8) -> u16 {
            if reg == PHY_MMDAAD && *self.mmd_dev.borrow() & 0x4000 != 0 {
                *self
                    .mmd
                    .borrow()
                    .get(&(*self.mmd_dev.borrow() & 31, *self.mmd_reg.borrow()))
                    .unwrap_or(&0)
            } else {
                *self.phy.borrow().get(&reg).unwrap_or(&0)
            }
        }
    }

    impl EeeRegs for FakeRegs {
        fn read32(&self, reg: u64) -> u32 {
            self.value(reg)
        }

        fn write32(&self, reg: u64, mut value: u32) {
            if reg == REG_MDIC {
                let index = ((value >> 16) & 31) as u8;
                if value & MDIC_OP_WRITE != 0 {
                    let data = value as u16;
                    if index == PHY_MMDAC {
                        *self.mmd_dev.borrow_mut() = data;
                    } else if index == PHY_MMDAAD {
                        if *self.mmd_dev.borrow() & 0x4000 == 0 {
                            *self.mmd_reg.borrow_mut() = data;
                        } else {
                            self.mmd.borrow_mut().insert(
                                (*self.mmd_dev.borrow() & 31, *self.mmd_reg.borrow()),
                                data,
                            );
                        }
                    } else {
                        self.phy.borrow_mut().insert(index, data);
                    }
                } else {
                    value = (value & !0xffff) | u32::from(self.phy_value(index));
                }
                value |= MDIC_READY;
            }
            self.regs.borrow_mut().insert(reg, value);
        }

        fn wait(&self, _: u64, mut ready: impl FnMut() -> bool) -> bool {
            // Bounded deterministic model steps, never a hardware poll.
            for _ in 0..32 {
                if ready() {
                    return true;
                }
            }
            false
        }
    }

    fn smoke_igb_eee_mmd_words() -> TestResult {
        // Supported set (100M + 1G) → 7/60 = 0b110, 7/62 = 0.
        if eee_mmd_adv(EEE_SUPPORTED) != (6, 0) {
            return TestResult::Fail("igb EEE MMD advertisement words wrong for 100M+1G");
        }
        if eee_mmd_adv(0) != (0, 0) || eee_mmd_adv(EEE_ADV_2_5G) != (0, 1) {
            return TestResult::Fail("igb EEE MMD advertisement words wrong for off/2.5G");
        }
        // Round-trip through the decode, including 2.5G.
        if eee_modes(6, 1) != 0x38 || eee_modes(0x2, 0x0) != EEE_ADV_100M {
            return TestResult::Fail("igb EEE MMD mode decode wrong");
        }
        if eee_modes(0xFFF9, 0xFFFE) != 0 {
            return TestResult::Fail("igb EEE MMD mode decode leaked non-EEE bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_eee_mmd_words);

    fn smoke_igb_eee_mac_words() -> TestResult {
        // e1000-generation IPCNFG bits: 100M → bit 12, 1G → bit 14.
        if eee_ipcnfg_next(0, EEE_SUPPORTED) != 0x5000 {
            return TestResult::Fail("igb EEE IPCNFG word wrong for the supported set");
        }
        if eee_ipcnfg_next(0, 0) != 0 || eee_ipcnfg_next(0xFFFF_FFFF, EEE_ADV_2_5G) != 0xFFFF_AFFF {
            return TestResult::Fail("igb EEE IPCNFG word wrong for off/2.5G-only");
        }
        if eee_ipcnfg_next(0x0000_0001, EEE_ADV_100M) != 0x0000_1001 {
            return TestResult::Fail("igb EEE IPCNFG word did not preserve other bits");
        }
        if eee_eeer_next(0, true) != 0x70000 || eee_eeer_next(0x70000, false) != 0 {
            return TestResult::Fail("igb EEE EEER word wrong for enable/disable");
        }
        if eee_eeer_next(0x8000_0001, true) != 0x8007_0001 {
            return TestResult::Fail("igb EEE EEER word did not preserve other bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_eee_mac_words);

    fn smoke_igb_eee_capability_gate() -> TestResult {
        for did in [
            super::super::IGB_I210_COPPER,
            super::super::IGB_I210_COPPER_FLASHLESS,
            super::super::IGB_I211_COPPER,
            super::super::IGB_82576,
            super::super::IGB_82576_NS,
            super::super::IGB_I350_COPPER,
        ] {
            if !eee_capable_device(did) {
                return TestResult::Fail("igb copper part reported not EEE-capable");
            }
        }
        for did in [
            super::super::IGB_I210_FIBER,
            super::super::IGB_I210_SERDES,
            super::super::IGB_I210_SGMII,
            super::super::IGB_I210_SERDES_FLASHLESS,
            0xFFFF,
        ] {
            if eee_capable_device(did) {
                return TestResult::Fail("igb fiber/serdes/unknown part reported EEE-capable");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_eee_capability_gate);

    fn smoke_igb_eee_set_then_status() -> TestResult {
        // End-to-end register conversation against scripted state:
        // link up, LPI off, no advertisement programmed yet.
        let fake = FakeRegs::new();
        fake.regs.borrow_mut().insert(REG_STATUS, STATUS_LU);
        fake.regs.borrow_mut().insert(REG_EEER, 0);
        fake.regs.borrow_mut().insert(REG_IPCNFG, 0);
        fake.phy.borrow_mut().insert(PHY_BMCR as u8, 0x1140);

        if set_eee(&fake, true).is_err() {
            return TestResult::Fail("igb set_eee(true) failed on scripted regs");
        }
        if fake.mmd.borrow().get(&(7, 60)) != Some(&6)
            || fake.mmd.borrow().get(&(7, 62)) != Some(&0)
        {
            return TestResult::Fail("igb EEE set did not program the MMD advertisement");
        }
        if fake.value(REG_IPCNFG) != 0x5000 || fake.value(REG_EEER) != 0x70000 {
            return TestResult::Fail("igb EEE set did not program IPCNFG/EEER");
        }
        if fake.phy.borrow().get(&(PHY_BMCR as u8)) != Some(&0x1340) {
            return TestResult::Fail("igb EEE set did not restart autoneg (BMCR 0x1200)");
        }

        // Partner advertises the same set: negotiated, active, LPI on.
        fake.mmd.borrow_mut().insert((7, 61), 6);
        fake.mmd.borrow_mut().insert((7, 63), 0);
        let status = match eee_status(&fake) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("igb eee_status failed on scripted regs"),
        };
        if !status.active || status.advertised != 0x18 || status.partner != 0x18 || !status.tx_lpi {
            return TestResult::Fail("igb EEE status wrong for negotiated link");
        }

        // Disable: advertisement cleared everywhere, status inactive.
        if set_eee(&fake, false).is_err() {
            return TestResult::Fail("igb set_eee(false) failed on scripted regs");
        }
        if fake.mmd.borrow().get(&(7, 60)) != Some(&0)
            || fake.value(REG_IPCNFG) != 0
            || fake.value(REG_EEER) != 0
        {
            return TestResult::Fail("igb EEE disable did not clear the advertisement");
        }
        let off = match eee_status(&fake) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("igb eee_status failed after disable"),
        };
        if off.active || off.advertised != 0 {
            return TestResult::Fail("igb EEE status active after disable");
        }

        // Link down → not active even with matching advertisements.
        fake.mmd.borrow_mut().insert((7, 60), 6);
        fake.mmd.borrow_mut().insert((7, 61), 6);
        fake.regs.borrow_mut().insert(REG_STATUS, 0);
        fake.regs.borrow_mut().insert(REG_EEER, EEER_TX_LPI_EN);
        let down = match eee_status(&fake) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("igb eee_status failed link-down"),
        };
        if down.active || !down.tx_lpi {
            return TestResult::Fail("igb EEE status active without link / tx_lpi lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_eee_set_then_status);
}

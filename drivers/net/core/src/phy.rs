//! Shared PHY/MDIO abstraction for NARF NIC drivers (issue #790).
//!
//! Every wired driver used to hand-roll PHY access: Realtek went
//! through the OCP/PHYAR windows (`drivers/net/realtek`), Intel
//! through MDIC (`e1000` / `igb` / `igc`), and each re-declared the
//! Clause-22 register map. This module is the one shared surface:
//! a [`Phy`] trait over Clause-22 register access, with the
//! negotiated-link decode every driver needs on top.
//!
//! ## References (public-only)
//!
//! - IEEE 802.3 Clause 22 — MII management registers (BMCR 0x00,
//!   BMSR 0x01, PHYSID1/2 0x02/0x03, ADVERTISE 0x04, LPA 0x05,
//!   GBCR 0x09, GBSR 0x0A) and Clause 45 access via the Clause-22
//!   indirection registers (MMD access control 0x0D, MMD access
//!   data 0x0E).
//! - Linux `include/uapi/linux/mdio.h` — `MDIO_MMD_AN` 7,
//!   `MDIO_AN_10GBT_CTRL` 32 / `MDIO_AN_10GBT_STAT` 33,
//!   `MDIO_AN_EEE_ADV` 60 / `MDIO_AN_EEE_LPABLE` 61 /
//!   `MDIO_AN_EEE_ADV2` 62 / `MDIO_AN_EEE_LPABLE2` 63.
//! - Linux `include/uapi/linux/mii.h` — `BMSR_LSTATUS` 0x0004,
//!   `BMSR_ANEGCOMPLETE` 0x0020, `LPA_10HALF` 0x0020 /
//!   `LPA_10FULL` 0x0040 / `LPA_100HALF` 0x0080 / `LPA_100FULL`
//!   0x0100, `LPA_1000HALF` 0x0400 / `LPA_1000FULL` 0x0800
//!   (1000BASE-T status register 0x0A), and the `mii_nway_result`
//!   priority order (1000FD > 1000HD > 100FD > 100HD > 10FD >
//!   10HD, 100BASE-T4 aside).
//! - Linux `drivers/net/phy/realtek.c` (`rtlgen_read_status` +
//!   `rtlgen_decode_speed`, v6.12) — the Realtek internal NBase-T
//!   PHYs (RTL8125 / RTL8126 / RTL8127-internal) report the
//!   negotiated rate in paged register 0xa43 / 0x12 under mask
//!   `RTLGEN_SPEED_MASK` 0x0630: 0x0000 → 10, 0x0010 → 100,
//!   0x0020 → 1000, 0x0200 → 10000, 0x0210 → 2500, 0x0220 →
//!   5000. The Realtek override lives in
//!   `narf-drivers-net-realtek` (`phy_access.rs`), not here: this
//!   module only knows the standard registers.
//! - Linux `drivers/net/phy/phy.c` (`genphy_read_status`) — the
//!   Clause-22 status algorithm this trait's default
//!   [`read_status_c22`] mirrors: BMSR read twice (the link bit
//!   is latch-low, IEEE 802.3 §22.2.4.2), autonegotiation-complete
//!   gates the LPA/GBSR resolution, and a disabled autonegotiation
//!   falls back to the BMCR speed/duplex bits.
//!
//! ## Transport contract
//!
//! `read_reg` / `write_reg` access the PHY register file at the
//! currently-selected page. Page 0 is the steady state: every
//! paged access restores it, and [`read_status_c22`] selects page
//! 0 before reading. Transports whose register window encodes
//! the page in the *address* rather than in a PHY page register
//! (Realtek OCP) MUST override [`Phy::read_paged`] /
//! [`Phy::write_paged`] with address arithmetic — the default
//! assumes a Clause-22 page register at 0x1F and would read the
//! wrong page through such a window.
//!
//! ## EEE rides here later (issue #794)
//!
//! This trait deliberately exposes the Clause-45 MMD accessors
//! ([`Phy::read_mmd`] / [`Phy::write_mmd`]) that the EEE surface
//! needs (AN MMD 7.60 / 7.62 advertisement, 7.61 / 7.63 link
//! partner). No EEE policy lives here — #794 builds on these
//! accessors; this lane only proves the transport.

use narf_net::iface::LinkDuplex;

use crate::publish::LinkSample;
use crate::rtl_phy::{
    MII_ADVERTISE, MII_BMCR, MII_BMSR, MII_GBCR, MII_GBSR, MII_LPA, MII_PHYSID1, MII_PHYSID2,
};

// ── Clause-22 register map (re-exported from `rtl_phy`) ─────────────
// The addresses live in `rtl_phy` (the low-level codec); the bit
// positions below are the ones `read_status_c22` decodes.

// MII page-select register (Clause 22 register 0x1F).
pub const MII_PAGE_SELECT: u8 = 0x1F;

// BMSR bits (Linux `include/uapi/linux/mii.h`: `BMSR_LSTATUS`
// 0x0004, `BMSR_ANEGCOMPLETE` 0x0020).
pub const BMSR_LINK_UP: u16 = 1 << 2;
pub const BMSR_ANEG_COMPLETE: u16 = 1 << 5;

// LPA bits (register 0x05; same positions as ANAR).
pub const LPA_10HALF: u16 = 0x0020;
pub const LPA_10FULL: u16 = 0x0040;
pub const LPA_100HALF: u16 = 0x0080;
pub const LPA_100FULL: u16 = 0x0100;

// 1000BASE-T status bits (register 0x0A, `MII_STAT1000`).
pub const GBSR_1000HALF: u16 = 0x0400;
pub const GBSR_1000FULL: u16 = 0x0800;

// BMCR bits (`rtl_phy` already names these; repeated here so the
// forced-link decode reads without cross-module hunting).
pub const BMCR_SPEED100: u16 = 1 << 13;
pub const BMCR_SPEED1000: u16 = 1 << 6;
pub const BMCR_FULL_DUPLEX: u16 = 1 << 8;

// 1000BASE-T control bits (register 0x09, GBCR; Linux
// `include/uapi/linux/mii.h` — not BMCR's speed bits, which sit
// at different positions).
pub const GBCR_1000HALF: u16 = 1 << 8;
pub const GBCR_1000FULL: u16 = 1 << 9;

// MMD indirection registers (Clause 22 0x0D / 0x0E) and the
// control-word modes (IEEE 802.3 Clause 45 over Clause 22).
pub const MII_MMD_CTRL: u8 = 0x0D;
pub const MII_MMD_DATA: u8 = 0x0E;
/// MMD control word: address phase (device + register follow).
pub const MMD_CTRL_ADDRESS: u16 = 0x0000;
/// MMD control word: data phase (reads/writes the selected register).
pub const MMD_CTRL_DATA: u16 = 0x4000;

// ── Negotiated link ─────────────────────────────────────────────────

/// The PHY's negotiated link state, as [`Phy::read_status`]
/// reports it. `speed_mbps` / `duplex` are `None` exactly when
/// the PHY cannot prove them (link down, or an unrecognised
/// speed encoding) — never a guessed rate.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PhyLink {
    /// BMSR link-status bit (read twice: latch-low).
    pub link_up: bool,
    /// Negotiated rate in Mbit/s, when the PHY proves it.
    pub speed_mbps: Option<u32>,
    /// Negotiated duplex, when the PHY proves it.
    pub duplex: Option<LinkDuplex>,
}

impl PhyLink {
    /// A link-down sample (speed/duplex unknown by definition).
    pub const DOWN: PhyLink = PhyLink {
        link_up: false,
        speed_mbps: None,
        duplex: None,
    };

    /// A carrier-up sample with the negotiated speed/duplex,
    /// either of which may be unknown.
    pub const fn up(speed_mbps: Option<u32>, duplex: Option<LinkDuplex>) -> Self {
        PhyLink {
            link_up: true,
            speed_mbps,
            duplex,
        }
    }

    /// Publish this state through the iface metadata path
    /// (`narf_net::iface::set_link_metadata`, via
    /// [`LinkSample`]). A down link publishes `LinkSample::DOWN`,
    /// matching Linux's speed `-1` / duplex `unknown` on a down
    /// link.
    pub const fn to_link_sample(self) -> LinkSample {
        if !self.link_up {
            return LinkSample::DOWN;
        }
        LinkSample::up(self.speed_mbps, self.duplex)
    }
}

/// Merge a PHY-derived [`PhyLink`] into an in-band
/// [`LinkSample`] (e.g. a MAC PHYStatus byte that only proves a
/// lower bound). A PHY field wins only when it is `Some`; a
/// `None` PHY field keeps the in-band value, so a PHY read that
/// proves carrier but not the rate never downgrades a known
/// lower bound to unknown. A down PHY link always wins: the
/// merged sample is `LinkSample::DOWN`.
pub fn merge_phy_sample(base: LinkSample, phy: PhyLink) -> LinkSample {
    if !phy.link_up {
        return LinkSample::DOWN;
    }
    LinkSample {
        carrier: true,
        speed_mbps: phy.speed_mbps.or(base.speed_mbps),
        duplex: phy.duplex.or(base.duplex),
        // Media state comes from the in-band side, never the PHY
        // read — preserve the base sample's media fields.
        media_available: base.media_available,
        phy_type: base.phy_type,
        phy_type_name: base.phy_type_name,
    }
}

// ── Pure Clause-22 decodes ──────────────────────────────────────────

/// Resolve the negotiated mode from the autonegotiation words:
/// our advertisement (ANAR 0x04 / GBCR 0x09 as read back from
/// the PHY) against the partner's (LPA 0x05 / GBSR 0x0A).
///
/// Priority is `mii_nway_result` order, 1000BASE-T first:
/// 1000FD > 1000HD > 100FD > 100HD > 10FD > 10HD. `None`
/// means no common mode — the partner has not answered yet, or
/// the advertisements are disjoint. This is the same order
/// `e1000::resolve_negotiated_mode` uses; the two are
/// cross-checked by fixture.
pub const fn resolve_aneg(
    our_anar: u16,
    our_gbcr: u16,
    lp_lpa: u16,
    lp_gbsr: u16,
) -> (Option<u32>, Option<LinkDuplex>) {
    if our_gbcr & GBCR_1000FULL != 0 && lp_gbsr & GBSR_1000FULL != 0 {
        (Some(1000), Some(LinkDuplex::Full))
    } else if our_gbcr & GBCR_1000HALF != 0 && lp_gbsr & GBSR_1000HALF != 0 {
        (Some(1000), Some(LinkDuplex::Half))
    } else if our_anar & LPA_100FULL != 0 && lp_lpa & LPA_100FULL != 0 {
        (Some(100), Some(LinkDuplex::Full))
    } else if our_anar & LPA_100HALF != 0 && lp_lpa & LPA_100HALF != 0 {
        (Some(100), Some(LinkDuplex::Half))
    } else if our_anar & LPA_10FULL != 0 && lp_lpa & LPA_10FULL != 0 {
        (Some(10), Some(LinkDuplex::Full))
    } else if our_anar & LPA_10HALF != 0 && lp_lpa & LPA_10HALF != 0 {
        (Some(10), Some(LinkDuplex::Half))
    } else {
        (None, None)
    }
}

/// Forced (autonegotiation-disabled) link from BMCR: speed bits
/// 13 (100) / 6 (1000), anything else 10; duplex bit 8.
pub const fn forced_link(bmcr: u16) -> (Option<u32>, Option<LinkDuplex>) {
    let speed = if bmcr & BMCR_SPEED1000 != 0 {
        1000
    } else if bmcr & BMCR_SPEED100 != 0 {
        100
    } else {
        10
    };
    let duplex = if bmcr & BMCR_FULL_DUPLEX != 0 {
        LinkDuplex::Full
    } else {
        LinkDuplex::Half
    };
    (Some(speed), Some(duplex))
}

/// `true` unless a PHY ID read is the no-device signature:
/// all-ones (MDIO pull-ups, nothing answering) or all-zeros.
pub const fn phy_id_valid(id: u32) -> bool {
    id != 0 && id != 0xFFFF_FFFF
}

/// Clause-22 status algorithm, factored out of the [`Phy`]
/// trait so overrides (Realtek's `rtlgen` path) can reuse it
/// instead of duplicating it: BMSR read twice, link gates
/// everything, autonegotiation-complete selects the LPA/GBSR
/// resolution, and a disabled autonegotiation falls back to
/// the BMCR bits. Page 0 is selected first (see the transport
/// contract in the module docs).
pub fn read_status_c22<P: Phy + ?Sized>(phy: &P) -> Result<PhyLink, P::Error> {
    // Select page 0: a previous paged access must never leak
    // into this read.
    phy.write_reg(MII_PAGE_SELECT, 0)?;
    // The BMSR link bit is latch-low (IEEE 802.3 §22.2.4.2):
    // the first read re-arms it, the second reports live state.
    let _ = phy.read_reg(MII_BMSR)?;
    let bmsr = phy.read_reg(MII_BMSR)?;
    if bmsr & BMSR_LINK_UP == 0 {
        return Ok(PhyLink::DOWN);
    }
    if bmsr & BMSR_ANEG_COMPLETE != 0 {
        let our_anar = phy.read_reg(MII_ADVERTISE)?;
        let our_gbcr = phy.read_reg(MII_GBCR)?;
        let lp_lpa = phy.read_reg(MII_LPA)?;
        let lp_gbsr = phy.read_reg(MII_GBSR)?;
        let (speed_mbps, duplex) = resolve_aneg(our_anar, our_gbcr, lp_lpa, lp_gbsr);
        Ok(PhyLink {
            link_up: true,
            speed_mbps,
            duplex,
        })
    } else {
        let bmcr = phy.read_reg(MII_BMCR)?;
        let (speed_mbps, duplex) = forced_link(bmcr);
        Ok(PhyLink {
            link_up: true,
            speed_mbps,
            duplex,
        })
    }
}

// ── The trait ───────────────────────────────────────────────────────

/// Shared PHY access: one Clause-22 register surface every
/// wired driver implements instead of hand-rolling MDIO.
///
/// The only required methods are the two register primitives;
/// everything else is provided: paged access (with page
/// restore), Clause-45 MMD access via the Clause-22
/// indirection registers, PHY identification, link sampling,
/// and the negotiated-status decode. A transport overrides a
/// provided method only when its hardware disagrees with the
/// standard sequence — Realtek's OCP window overrides the
/// paged accessors (address arithmetic, no page register) and
/// `read_status` (the `rtlgen` multigig override); a plain
/// MDIC transport (e1000) implements just the primitives.
///
/// Implementations may carry call-context constraints (e.g.
/// e1000's MDIC access must not run during bring-up, when the
/// firmware semaphore is already held) — those are documented
/// on the implementation, not the trait.
pub trait Phy {
    /// Transport error (per-driver: `PhyError`, `E1000Error`, …).
    type Error: core::fmt::Debug;

    /// Read one Clause-22 register (`reg` 0..=31) at the
    /// currently-selected page.
    fn read_reg(&self, reg: u8) -> Result<u16, Self::Error>;
    /// Write one Clause-22 register at the currently-selected page.
    fn write_reg(&self, reg: u8, val: u16) -> Result<(), Self::Error>;

    /// Read register `reg` on page `page` (select via register
    /// 0x1F, read, restore page 0 — the Linux
    /// `phy_read_paged` / `phy_restore_page` discipline). The
    /// restore runs even when the read fails.
    fn read_paged(&self, page: u16, reg: u8) -> Result<u16, Self::Error> {
        self.write_reg(MII_PAGE_SELECT, page)?;
        let result = self.read_reg(reg);
        let _ = self.write_reg(MII_PAGE_SELECT, 0);
        result
    }

    /// Write register `reg` on page `page` (select, write,
    /// restore page 0).
    fn write_paged(&self, page: u16, reg: u8, val: u16) -> Result<(), Self::Error> {
        self.write_reg(MII_PAGE_SELECT, page)?;
        let result = self.write_reg(reg, val);
        let _ = self.write_reg(MII_PAGE_SELECT, 0);
        result
    }

    /// Read a Clause-45 MMD register via the Clause-22
    /// indirection sequence (IEEE 802.3 Clause 45 over Clause
    /// 22): write the device to 0x0D, the register to 0x0E,
    /// `0x4000 | device` to 0x0D (data phase), then read 0x0E.
    /// This is the transport the #794 EEE surface will ride
    /// (AN MMD 7.60 / 7.62).
    fn read_mmd(&self, dev: u8, reg: u16) -> Result<u16, Self::Error> {
        self.write_reg(MII_MMD_CTRL, u16::from(dev) | MMD_CTRL_ADDRESS)?;
        self.write_reg(MII_MMD_DATA, reg)?;
        self.write_reg(MII_MMD_CTRL, u16::from(dev) | MMD_CTRL_DATA)?;
        self.read_reg(MII_MMD_DATA)
    }

    /// Write a Clause-45 MMD register via the same indirection
    /// sequence, ending with the data write to 0x0E.
    fn write_mmd(&self, dev: u8, reg: u16, val: u16) -> Result<(), Self::Error> {
        self.write_reg(MII_MMD_CTRL, u16::from(dev) | MMD_CTRL_ADDRESS)?;
        self.write_reg(MII_MMD_DATA, reg)?;
        self.write_reg(MII_MMD_CTRL, u16::from(dev) | MMD_CTRL_DATA)?;
        self.write_reg(MII_MMD_DATA, val)
    }

    /// Read the PHY identifier (PHYSID1 0x02 / PHYSID2 0x03,
    /// ID1 in the high half — Linux `e1000_get_phy_id` shape).
    /// No validity judgement: use [`phy_id_valid`].
    fn read_phy_id(&self) -> Result<u32, Self::Error> {
        let id1 = self.read_reg(MII_PHYSID1)?;
        let id2 = self.read_reg(MII_PHYSID2)?;
        Ok(((u32::from(id1)) << 16) | u32::from(id2))
    }

    /// PHY link status via BMSR. Two consecutive reads: the
    /// first re-arms the latch-low link bit, the second reports
    /// live state. This is the PHY-side signal; a MAC-side
    /// `STATUS.LU` sample is a separate path.
    fn link_up(&self) -> Result<bool, Self::Error> {
        let _ = self.read_reg(MII_BMSR)?;
        let bmsr = self.read_reg(MII_BMSR)?;
        Ok(bmsr & BMSR_LINK_UP != 0)
    }

    /// Auto-negotiation complete sample: two consecutive BMSR
    /// reads (latch-low), trust the second.
    fn autoneg_complete(&self) -> Result<bool, Self::Error> {
        let _ = self.read_reg(MII_BMSR)?;
        let bmsr = self.read_reg(MII_BMSR)?;
        Ok(bmsr & BMSR_ANEG_COMPLETE != 0)
    }

    /// Negotiated link state: the standard Clause-22 algorithm
    /// ([`read_status_c22`]). Transports whose PHY reports the
    /// rate in a vendor register override this and apply their
    /// decode on top of [`read_status_c22`].
    fn read_status(&self) -> Result<PhyLink, Self::Error> {
        read_status_c22(self)
    }
}

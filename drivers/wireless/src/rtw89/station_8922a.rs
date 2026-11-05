// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A station owner + admission (chip-row step 2).
//!
//! This is the owner the EHT step-2 lane's `EhtStation` facet was
//! written for (`eht.rs`: "the facet the future 8922A station owner
//! composes once admission exists"). It admits one EHT station at a
//! time against the chip container's static caps and produces the
//! firmware artifacts admission programs: the G7 default CMAC table
//! (`cctl_g7::build_default`), the G7 association CMAC table
//! (`cctl_g7::build_assoc`, Linux `fw.c`
//! `rtw89_fw_h2c_assoc_cmac_tbl_g7`), the BA-CAM v1 slot map
//! (`bacam_v1::BaCam`, 24 slots / 8 dynamic), and the TXWD_INFO
//! EHT fields from the facet (`txrx_be::eht_info_fields`).
//!
//! Fail-closed by construction: every check that can refuse does
//! so with a named [`Error`] before any artifact is built, and no
//! artifact is produced for a refused request. The caller owns
//! transport: this module builds H2C bodies but never sends them
//! (BE DMA ring programming + H2C transport integration are the
//! chip row's remaining transport lane), and the caller publishes
//! MACID ownership by holding the admitted [`Station`] and
//! releasing its MACID back to the [`MacIdPool`] on disconnect.
//!
//! Deliberate narrowings (all stated, none silent):
//! - EHT stations only. Legacy/HE/VHT/HT-only admission needs
//!   its own RA/CCTL paths and is a remainder; this owner takes
//!   an `EhtStation` facet as a required input.
//! - Single-link. MLO multi-link (chip supports 2 links) is a
//!   remainder; admission carries one link's parameters.
//! - 2.4/5 GHz only. 6 GHz is refused (`SixGhzPowerMissing`)
//!   until the 6 GHz TX-power program (TPE) lands — transmitting
//!   on 6 GHz with unprogrammed power would be wrong, so the
//!   refusal is explicit, not a silent 5 GHz fallback.
//! - 320 MHz refused (`WidthNotAdvertised`): the width is
//!   programmed by the EHT lane but deliberately NOT advertised
//!   (chip bandwidths top at 160 MHz, `rtw8922a.c:3263..3266`).
//! - The primary channel is checked nonzero only. Exact channel
//!   legality lives with the channel/regulatory plan, not here.
//! - Assoc PPE pads are caller-supplied (2 bits per width).
//!   Parsing them from peer EHT/HE IEs is a remainder; zero pads
//!   mean the peer advertised neither EHT nor HE caps (Linux
//!   memsets the pads and only fills them from EHT/HE caps).
//! - The RA v1 command is NOT built here: its mask needs the
//!   peer's negotiated MCS map + RSSI, which admission does not
//!   have. `ra_v1::build_ra_v1` is the builder the RA lane fills
//!   once those inputs exist; the station record carries the
//!   structural inputs (MACID, band, width, NSS) that lane needs.

use super::{
    bacam_v1::{self, BaCam},
    cctl_g7::{self, DefaultCmac},
    chip_8922a,
    efuse_be::BeFactory,
    eht::EhtStation,
};

/// Operating band of the admitted link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Band {
    /// 2.4 GHz.
    Ghz2,
    /// 5 GHz.
    Ghz5,
    /// 6 GHz (refused until the 6 GHz power program lands).
    Ghz6,
}

/// One admission request: the peer, the link, and the
/// caller-supplied station parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Request {
    /// Peer MAC address.
    pub(super) peer: [u8; 6],
    /// Operating band.
    pub(super) band: Band,
    /// Operating width in MHz (20/40/80/160).
    pub(super) width_mhz: u32,
    /// Primary channel number (nonzero; legality is the
    /// channel plan's job, not admission's).
    pub(super) primary: u8,
    /// Spatial streams (1..=2, the chip's TX/RX NSS).
    pub(super) nss: u8,
    /// Association ID (12 bits, CCTL w6).
    pub(super) aid: u16,
    /// Multi-port id (3 bits, CCTL w4).
    pub(super) port: u8,
    /// AP-mode vif (CCTL w4 DATA_DCM mask arm).
    pub(super) ap_mode: bool,
    /// Station-mode vif (CCTL w6 ULDL bit).
    pub(super) station_mode: bool,
    /// BSS EHT support (CCTL w4 subchannel arm).
    pub(super) eht_support: bool,
    /// Punctured-subchannel bitmap (only read when
    /// `eht_support`; written inverted into w4).
    pub(super) punctured: u16,
    /// Nominal packet padding per width, 20/40/80/160/320
    /// order, 2 bits each (see module docs).
    pub(super) pads: [u8; 5],
    /// Peer HE support (CCTL w8 BSR format bit).
    pub(super) has_he: bool,
    /// MGQ report enable (default CCTL w0).
    pub(super) mgq_rpt_en: bool,
    /// P2P vif (assoc lowest-rate arm is always OFDM6).
    pub(super) p2p: bool,
}

/// Admission failures. Every variant is a refusal, never a
/// fallback: a refused request produces no station and no
/// partially-programmed artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// 6 GHz requested before the 6 GHz power program exists.
    SixGhzPowerMissing,
    /// Width outside 20/40/80/160 (includes 320 MHz).
    WidthNotAdvertised,
    /// NSS zero or above the chip's 2-stream cap.
    NssOutOfRange,
    /// MACID pool exhausted (32 stations admitted).
    NoMacId,
    /// AID above the 12-bit CCTL field.
    AidOutOfRange,
    /// Port above the 3-bit CCTL field.
    PortOutOfRange,
    /// A PPE pad above its 2-bit field.
    PadsOutOfRange,
    /// Primary channel zero.
    BadPrimary,
    /// CMAC builder rejection (MACID/field overflow).
    Cctl(cctl_g7::Error),
    /// BA-CAM map rejection (cannot happen for 24 slots).
    BaCam(bacam_v1::Error),
}

/// MACID allocator over the chip's station slots
/// (`SUPPORT_MACID_NUM` = 32). Lowest free slot first,
/// matching the BA-CAM map's lowest-free discipline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MacIdPool {
    used: [bool; chip_8922a::SUPPORT_MACID_NUM],
}

impl MacIdPool {
    /// Empty pool: no MACID admitted.
    pub(super) fn new() -> Self {
        Self {
            used: [false; chip_8922a::SUPPORT_MACID_NUM],
        }
    }

    /// Allocate the lowest free MACID, or refuse when full.
    pub(super) fn alloc(&mut self) -> Result<u8, Error> {
        for (idx, slot) in self.used.iter_mut().enumerate() {
            if !*slot {
                *slot = true;
                return Ok(idx as u8);
            }
        }
        Err(Error::NoMacId)
    }

    /// Release `macid`. Total and idempotent: releasing an
    /// unallocated or out-of-range id is a no-op, so a
    /// double disconnect cannot corrupt the pool.
    pub(super) fn free(&mut self, macid: u8) {
        if let Some(slot) = self.used.get_mut(macid as usize) {
            *slot = false;
        }
    }

    /// True when `macid` is currently admitted.
    pub(super) fn is_used(&self, macid: u8) -> bool {
        self.used.get(macid as usize).copied().unwrap_or(false)
    }
}

/// An admitted 8922A station: its identity, its link, and the
/// firmware artifacts admission programmed for it. The caller
/// sends the CCTL bodies over H2C and owns the BA-CAM map for
/// the station's lifetime (TID/SSN/buffer-size inputs arrive
/// with traffic, so BA-CAM H2C bodies are built on demand via
/// [`Station::ba_h2c`], not here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Station {
    /// Own MAC, from the BE factory identity.
    pub(super) own: [u8; 6],
    /// Peer MAC.
    pub(super) peer: [u8; 6],
    /// Allocated MACID (released via [`MacIdPool::free`]).
    pub(super) macid: u8,
    /// Operating band.
    pub(super) band: Band,
    /// Operating width in MHz.
    pub(super) width_mhz: u32,
    /// Primary channel number.
    pub(super) primary: u8,
    /// Spatial streams.
    pub(super) nss: u8,
    /// Association ID.
    pub(super) aid: u16,
    /// EHT facet (advertised cap + TXWD EHT overrides).
    pub(super) facet: EhtStation,
    /// BA-CAM v1 slot map (24 slots; entry index written to
    /// firmware is the bitmap index + 8 dynamic slots).
    pub(super) bacam: BaCam,
    /// G7 default CMAC table for this MACID.
    pub(super) default_cctl: DefaultCmac,
    /// G7 association CMAC table for this station.
    pub(super) assoc_cctl: DefaultCmac,
}

impl Station {
    /// EHT contribution to the BE TXWD_INFO block for this
    /// station: (info4 bits, info7 bits) from the facet.
    /// `None` only on an out-of-range NLTF value, which
    /// fail-closed facet construction never produces.
    pub(super) fn txwd_info_eht(&self) -> Option<(u32, u32)> {
        self.facet.txwd_info_eht()
    }

    /// Build a BA-CAM v1 H2C body for one of this station's
    /// BlockAck sessions. Single-link pass-1: MLD off,
    /// MAC-index 0, so band-select is clear. `bitmap_idx`
    /// must come from [`BaCam::acquire`] on [`Self::bacam`].
    pub(super) fn ba_h2c(
        &self,
        tid: u32,
        bmap_size: u32,
        ssn: u32,
        bitmap_idx: u32,
    ) -> Result<bacam_v1::BaCamH2c, Error> {
        bacam_v1::build_h2c(
            true,
            self.macid as u32,
            tid,
            bmap_size,
            ssn,
            bitmap_idx,
            chip_8922a::BACAM_DYNAMIC_NUM as u32,
            false,
            false,
        )
        .map_err(Error::BaCam)
    }

    /// Release this station's MACID back to the pool.
    /// The station record itself is then dead; the caller
    /// must not send further H2C for it.
    pub(super) fn release_macid(&self, pool: &mut MacIdPool) {
        pool.free(self.macid);
    }
}

/// Admit one EHT station. Checks run in a fixed order so a
/// request failing several checks always reports the same
/// refusal; no MACID is consumed by a refused request (the
/// pool allocation happens only after every other check).
pub(super) fn admit(
    factory: &BeFactory,
    facet: EhtStation,
    pool: &mut MacIdPool,
    req: &Request,
) -> Result<Station, Error> {
    if req.band == Band::Ghz6 {
        return Err(Error::SixGhzPowerMissing);
    }
    if !chip_8922a::SUPPORT_BANDWIDTHS_MHZ.contains(&req.width_mhz) {
        return Err(Error::WidthNotAdvertised);
    }
    if req.nss == 0 || req.nss as usize > chip_8922a::TX_NSS {
        return Err(Error::NssOutOfRange);
    }
    if req.primary == 0 {
        return Err(Error::BadPrimary);
    }
    if req.aid > 0xFFF {
        return Err(Error::AidOutOfRange);
    }
    if req.port > 7 {
        return Err(Error::PortOutOfRange);
    }
    if req.pads.iter().any(|p| *p > 3) {
        return Err(Error::PadsOutOfRange);
    }
    let macid = pool.alloc()?;
    let default_cctl = cctl_g7::build_default(macid as u32, req.mgq_rpt_en).map_err(Error::Cctl)?;
    let assoc_cctl = cctl_g7::build_assoc(
        macid as u32,
        req.band == Band::Ghz2,
        req.p2p,
        req.port as u32,
        req.ap_mode,
        req.eht_support,
        req.punctured,
        req.pads,
        req.aid,
        req.station_mode,
        req.has_he,
    )
    .map_err(Error::Cctl)?;
    let bacam = BaCam::new(chip_8922a::BACAM_NUM).map_err(Error::BaCam)?;
    Ok(Station {
        own: factory.mac,
        peer: req.peer,
        macid,
        band: req.band,
        width_mhz: req.width_mhz,
        primary: req.primary,
        nss: req.nss,
        aid: req.aid,
        facet,
        bacam,
        default_cctl,
        assoc_cctl,
    })
}

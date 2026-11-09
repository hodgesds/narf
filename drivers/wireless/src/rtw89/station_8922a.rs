// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A station owner + admission (chip-row step 2).
//!
//! This is the owner the EHT step-2 lane's `EhtStation` facet was
//! written for (`eht.rs`: "the facet the future 8922A station owner
//! composes once admission exists"). It admits one station at a
//! time against the chip container's static caps and produces the
//! firmware artifacts admission programs: the G7 default CMAC table
//! (`cctl_g7::build_default`), the G7 association CMAC table
//! (`cctl_g7::build_assoc`, Linux `fw.c`
//! `rtw89_fw_h2c_assoc_cmac_tbl_g7`), the BA-CAM v1 slot map
//! (`bacam_v1::BaCam`, 24 slots / 8 dynamic), and — for EHT
//! stations — the TXWD_INFO EHT fields from the facet
//! (`txrx_be::eht_info_fields`).
//!
//! Two admission paths share one [`MacIdPool`], so EHT and
//! legacy-mode stations coexist: EHT stations admit via [`admit`]
//! with an `EhtStation` facet; legacy-mode stations (legacy-only,
//! HT, VHT, HE — everything non-EHT) admit via [`admit_legacy`]
//! with a [`LegacyCaps`] facet carrying the peer's negotiated
//! rates and caps. The legacy record builds its RA v1 command on
//! demand from those caps ([`LegacyStation::ra_h2c`], via
//! `ra_mask::build`, Linux `phy.c` `rtw89_phy_ra_sta_update`);
//! the EHT record does not (see below).
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
//! - Legacy-mode admission is the non-EHT path: a legacy
//!   request carrying EHT support is refused
//!   (`EhtInLegacyRequest`) instead of being silently
//!   downgraded — an EHT peer belongs on [`admit`]. The
//!   legacy facet carries no EHT caps by construction, so a
//!   legacy record can never program EHT RA or TXWD fields.
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
//! - Assoc PPE pads are parsed from the peer's association IEs
//!   (`ppe::parse_assoc_ppe`, issue #1882) at admission, EHT
//!   first then HE, and stored on the station record; zero pads
//!   still mean the peer advertised neither EHT nor HE caps
//!   (Linux memsets the pads and only fills them from EHT/HE
//!   caps). The G7 assoc builder still takes raw pads and
//!   validates their 2-bit range — the parse output is always
//!   in range by construction.
//! - The RA v1 command is NOT built for EHT stations here:
//!   its mask needs the peer's negotiated MCS map + RSSI,
//!   which the EHT facet does not carry. `ra_v1::build_ra_v1`
//!   is the builder the RA lane fills once those inputs exist;
//!   the EHT station record carries the structural inputs
//!   (MACID, band, width, NSS) that lane needs. The legacy
//!   record is the exception: admission stores the negotiated
//!   caps, so [`LegacyStation::ra_h2c`] builds the command on
//!   demand via `ra_mask::build`.
//! - 6 GHz legacy admission stays refused
//!   (`SixGhzPowerMissing`): the 6 GHz power program is the
//!   separate 6 GHz lane's work, and composing it into the
//!   legacy path (HE20 6 GHz stations) is a follow-up once
//!   that program exists, not part of this remainder.

use super::{
    bacam_v1::{self, BaCam},
    cctl_g7::{self, DefaultCmac},
    chip_8922a,
    efuse_be::BeFactory,
    eht::EhtStation,
    ppe,
    ra_mask::{self, HeCaps, HtCaps, VhtCaps},
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
pub(super) struct Request<'a> {
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
    /// The peer's association IEs: concatenated `[id, len, ...]`
    /// elements starting at the first IE (see `ppe`). Admission
    /// parses the Assoc PPE pads from them; there is no separate
    /// pad input anymore.
    pub(super) peer_ies: &'a [u8],
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
    /// Primary channel zero.
    BadPrimary,
    /// CMAC builder rejection (MACID/field overflow).
    Cctl(cctl_g7::Error),
    /// BA-CAM map rejection (cannot happen for 24 slots).
    BaCam(bacam_v1::Error),
    /// A legacy-mode request carrying EHT support: an EHT
    /// peer belongs on [`admit`], not [`admit_legacy`].
    EhtInLegacyRequest,
    /// Legacy caps with an empty supported-rates bitmap:
    /// Linux's RA update never sees one (an associated
    /// station's supported-rates IE is non-empty by
    /// construction), and admitting it would program a zero
    /// RA mask.
    NoSupportedRates,
    /// RA command build rejection for a legacy station.
    Ra(ra_mask::Error),
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
    /// Assoc PPE pads parsed from the peer's association IEs
    /// (20/40/80/160/320 MHz order, 2 bits each), the values
    /// programmed into the assoc CCTL w5. Zero means the peer
    /// advertised neither EHT nor HE caps. The EHT station
    /// owner gates PPE-dependent behavior on these, not on
    /// caller-supplied values.
    pub(super) pads: [u8; 5],
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
    // Pads come from the peer's IEs, never from the caller: the
    // parse output is always five 2-bit values, so no
    // PadsOutOfRange refusal exists anymore (the assoc builder
    // still validates its own input).
    let pads = ppe::parse_assoc_ppe(req.peer_ies, req.nss);
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
        pads,
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
        pads,
        bacam,
        default_cctl,
        assoc_cctl,
    })
}

// ── Legacy-mode admission ──────────────────────────────────────────────
//
// Everything non-EHT: legacy-only (CCK/OFDM), HT, VHT, and HE
// peers. The CCTL composition is the same G7 builders the EHT
// path uses, with EHT support off: the assoc table's lowest
// rate arm is CCK1 on 2.4 GHz (non-P2P) and OFDM6 otherwise
// (`cctl_g7::build_assoc`), the punctured-subchannel arm stays
// unprogrammed, the BSR format bit follows the peer's HE
// support, and the PPE pads are caller-supplied (zero when the
// peer has neither EHT nor HE caps — Linux memsets the pads
// and only fills them from EHT/HE caps). RA is computed from
// the negotiated caps stored here, mirroring Linux `phy.c`
// `rtw89_phy_ra_sta_update` via `ra_mask::build`.
//
// The validation checks run in the same order as [`admit`]
// (band, EHT-exclusion, rates, width, NSS, primary, AID,
// port, pads) so a request failing several checks always
// reports the same refusal on either path; no MACID is
// consumed by a refused request. The two check sequences are
// deliberately duplicated rather than factored into a shared
// helper: the 6 GHz lane is reworking `admit`'s opening
// checks on its own branch, and a shared helper would collide
// with it. Factor them once that lane lands.

/// Highest non-EHT mode a legacy station negotiated, in
/// Linux's `rtw89_phy_ra_sta_update` else-if priority
/// (HE beats VHT beats HT beats legacy-only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LegacyMode {
    /// CCK/OFDM only: no HT/VHT/HE caps.
    Legacy,
    /// HT caps, no VHT/HE caps.
    Ht,
    /// VHT caps, no HE caps.
    Vht,
    /// HE caps.
    He,
}

/// The peer's negotiated legacy-mode capabilities: the
/// inputs `ra_mask::compute` needs beyond the link
/// parameters [`Request`] already carries. This is the
/// legacy analogue of the [`EhtStation`] facet: it holds
/// what the peer advertised, not what the chip supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LegacyCaps {
    /// Legacy supported-rates bitmap, in Linux's
    /// convention: on 2.4 GHz the bits ARE the mask bits
    /// (CCK 0..3, OFDM 4..11); on 5/6 GHz the bitmap is
    /// shifted left by 4, so bit 0 lands on OFDM bit 4.
    /// Must be nonzero (see [`Error::NoSupportedRates`]).
    pub(super) supp_rates: u16,
    /// HT caps, if the peer advertises HT.
    pub(super) ht: Option<HtCaps>,
    /// VHT caps, if the peer advertises VHT.
    pub(super) vht: Option<VhtCaps>,
    /// HE caps, if the peer advertises HE.
    pub(super) he: Option<HeCaps>,
    /// Average RSSI (raw units; Linux halves it).
    pub(super) rssi: u8,
    /// ER capability from the station link.
    pub(super) er_cap: bool,
}

/// An admitted 8922A legacy-mode station: its identity, its
/// link, the peer's negotiated caps, and the firmware
/// artifacts admission programmed for it. The caller sends
/// the CCTL bodies over H2C and owns the BA-CAM map for the
/// station's lifetime, exactly as for [`Station`]; the two
/// record types share the [`MacIdPool`], so EHT and legacy
/// stations coexist with distinct MACIDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LegacyStation {
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
    /// Peer's negotiated legacy-mode caps (RA inputs).
    pub(super) caps: LegacyCaps,
    /// BA-CAM v1 slot map (24 slots; entry index written to
    /// firmware is the bitmap index + 8 dynamic slots).
    pub(super) bacam: BaCam,
    /// G7 default CMAC table for this MACID.
    pub(super) default_cctl: DefaultCmac,
    /// G7 association CMAC table for this station.
    pub(super) assoc_cctl: DefaultCmac,
}

impl LegacyStation {
    /// Highest non-EHT mode this station negotiated, in
    /// Linux's else-if priority.
    pub(super) fn mode(&self) -> LegacyMode {
        if self.caps.he.is_some() {
            LegacyMode::He
        } else if self.caps.vht.is_some() {
            LegacyMode::Vht
        } else if self.caps.ht.is_some() {
            LegacyMode::Ht
        } else {
            LegacyMode::Legacy
        }
    }

    /// EHT contribution to the BE TXWD_INFO block for this
    /// station: always (0, 0). A legacy station programs no
    /// EHT TXWD override — the facet carries no EHT state —
    /// so the transport ORs in nothing for it.
    pub(super) fn txwd_info_eht(&self) -> Option<(u32, u32)> {
        Some((0, 0))
    }

    /// Build the BE RA v1 H2C command for this station from
    /// the negotiated caps admission stored, via
    /// `ra_mask::build` (Linux `phy.c`
    /// `rtw89_phy_ra_sta_update`). `phy_idx` is the PHY
    /// index Linux reports as `band_num`; `upd_mask` /
    /// `upd_bw_nss` are the caller's change flags — a fresh
    /// station update passes both false.
    pub(super) fn ra_h2c(
        &self,
        phy_idx: u8,
        upd_mask: bool,
        upd_bw_nss: bool,
    ) -> Result<[u32; 6], Error> {
        let caps = ra_mask::StationCaps {
            band: self.band,
            width_mhz: self.width_mhz,
            supp_rates: self.caps.supp_rates,
            ht: self.caps.ht,
            vht: self.caps.vht,
            he: self.caps.he,
            eht: None,
            rx_nss: self.nss,
            tx_nss: chip_8922a::TX_NSS as u8,
            rssi: self.caps.rssi,
            // 8922AE variant: `rtw8922ae_vs_variant
            // .no_mcs_12_13` (see `eht::EHT_CAP_8922AE_INPUTS`
            // and `ra_mask` docs).
            no_mcs_12_13: true,
            er_cap: self.caps.er_cap,
        };
        ra_mask::build(&caps, self.macid, phy_idx, upd_mask, upd_bw_nss).map_err(Error::Ra)
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

/// Admit one legacy-mode station. `req` is the shared
/// admission request; `req.eht_support` must be false and
/// `req.punctured` is not consumed (Linux reads the
/// puncturing bitmap only when EHT is supported).
/// `req.has_he` must agree with the facet's HE caps — the
/// caller supplies both, as with the PPE pads — and drives
/// the assoc table's BSR format bit.
pub(super) fn admit_legacy(
    factory: &BeFactory,
    caps: &LegacyCaps,
    pool: &mut MacIdPool,
    req: &Request,
) -> Result<LegacyStation, Error> {
    if req.band == Band::Ghz6 {
        return Err(Error::SixGhzPowerMissing);
    }
    if req.eht_support {
        return Err(Error::EhtInLegacyRequest);
    }
    if caps.supp_rates == 0 {
        return Err(Error::NoSupportedRates);
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
        false,
        0,
        req.pads,
        req.aid,
        req.station_mode,
        req.has_he,
    )
    .map_err(Error::Cctl)?;
    let bacam = BaCam::new(chip_8922a::BACAM_NUM).map_err(Error::BaCam)?;
    Ok(LegacyStation {
        own: factory.mac,
        peer: req.peer,
        macid,
        band: req.band,
        width_mhz: req.width_mhz,
        primary: req.primary,
        nss: req.nss,
        aid: req.aid,
        caps: *caps,
        bacam,
        default_cctl,
        assoc_cctl,
    })
}

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
//! - Multi-link (MLO) is admitted by [`admit_mld`] as an
//!   [`MldStation`]: one MLD address, one shared AID and port,
//!   up to `SUPPORT_LINK_NUM` (2) links, each with its own
//!   link address, channel, per-link MACID, per-link G7
//!   default + assoc CCTL, and per-link BA-CAM map. The
//!   per-link MACIDs are strided off one pool base
//!   (`base + index * MLD_MACID_STRIDE`, stride 16), the
//!   BA-CAM H2C is built from the designated link (first
//!   link added) with MLD_EN set and BAND_SEL from that
//!   link's MAC index, and links can be added
//!   ([`MldStation::add_link`]) or removed one at a time
//!   ([`MldStation::remove_link`]) with the MLD surviving
//!   on the remaining link. See the "MLO model" section
//!   below for the Linux grounding and the deliberate
//!   differences from it.
//! - 2.4/5 GHz only, plus 6 GHz at 20 MHz with a 6 GHz power
//!   program. A 6 GHz request must carry [`SixGhzAdmission`]
//!   (the AP's client power type + the regd.c TPE constraint from
//!   [`tpe`]); without it admission is refused
//!   (`SixGhzPowerMissing`), so 6 GHz is never transmitted with
//!   unprogrammed power. The TPE is the primary-20 MHz
//!   subchannel constraint only, so wider 6 GHz widths are
//!   refused (`SixGhzWidthUnsupported`): a wide station would
//!   need the full-width EIRP/PSD rearrange (a follow-up), and
//!   admitting it on the primary subchannel's constraint alone
//!   could over-permit power on the other subchannels.
//!   The admitted [`Station`] records the program as
//!   [`SixGhzProgram`], including the phy.c TPE constraint in
//!   MAC units the future `rtw8922a_set_txpwr` limit program
//!   consumes. The register-level program itself (by-rate /
//!   limit / limit-RU pages on BE registers, shape, diff, ref,
//!   SAR-diff) is a follow-up: it needs the firmware TXPWR
//!   elements container this owner does not hold. The program
//!   applies per link: each link of an MLD request carries its
//!   own admission, validated by [`validate`].
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
//! - 6 GHz legacy admission (HE20) composes the same 6 GHz
//!   power program as the EHT path
//!   ([`SixGhzProgram::from_admission`]): a legacy 6 GHz
//!   request must carry [`SixGhzAdmission`]
//!   (`SixGhzPowerMissing` without it), is 20 MHz only
//!   (`SixGhzWidthUnsupported`), and the admitted
//!   [`LegacyStation`] records the program (see
//!   [`LegacyStation::six_ghz`]).
//! ## MLO model (Linux grounding)
//!
//! Grounded in torvalds/linux master `7475ea8b`
//! (`drivers/net/wireless/realtek/rtw89`), same tree the
//! single-link owner cites at `05441d6` for the builders:
//!
//! - Chip caps: `support_macid_num` = 32, `support_link_num`
//!   = 2 (`rtw8922a.c:3256..3257`), `support_chanctx_num` =
//!   2 (`rtw8922a.c:3258`), `__RTW89_MLD_MAX_LINK_NUM` = 2
//!   (`core.h:904`); 802.11 link IDs are 0..=14
//!   (`IEEE80211_MLD_MAX_NUM_LINKS` = 15,
//!   `include/linux/ieee80211-eht.h:462`).
//! - MACIDs: `rtw89_acquire_mac_id` (`core.c:6771`) searches
//!   only `support_macid_num / support_link_num` base slots
//!   when MLO is on, and `rtw89_init_sta` (`core.c:6830`)
//!   gives link instance `index` the MACID
//!   `base + index * support_mld_num`, where
//!   `support_mld_num = support_macid_num / support_link_num`
//!   = 16. Each link instance also gets
//!   `mac_idx = RTW89_MAC_0 + index` (`core.c:6822`) and all
//!   links share one port ("multi-link use the same port id
//!   on different HW bands", `core.c:6825`).
//! - Link identity: `rtw89_sta_set_link` (`core.c:6909`)
//!   assigns the lowest free *instance* index (admission
//!   order, not the 802.11 link ID); the designated link is
//!   the first entry of the link pool (`rtw89_get_designated_link`,
//!   `core.h:8000`) — i.e. the first link added.
//! - Assoc is per link: `__rtw89_ops_sta_assoc`
//!   (`mac80211.c`) iterates every link and calls
//!   `rtw89_core_sta_link_assoc` per link, which sends one
//!   assoc CMAC table per link
//!   (`rtw89_fw_h2c_assoc_cmac_tbl_g7`, `fw.c:4431`) keyed by
//!   that link's MACID, band, and per-link EHT/HE pads —
//!   while the AID is `vif->cfg.aid`, one AID shared by all
//!   links. The G7 assoc table has no MLD-specific field.
//! - BA-CAM is MLD-aware: `rtw89_fw_h2c_ba_cam_v1`
//!   (`fw.c:2922`) builds from the *designated* link
//!   (`macid = rtwsta_link->mac_id`), sets MLD_EN when the
//!   VIF is MLD (`ieee80211_vif_is_mld`), and sets BAND_SEL
//!   from the designated link's `mac_idx != 0`.
//! - Link add/remove: `__rtw89_ops_set_sta_links`
//!   (`mac80211.c:1809`) does set-link, link-add, then
//!   link-assoc per added link; `__rtw89_ops_clr_sta_links`
//!   (`mac80211.c:1786`) does disassoc, disconnect, remove,
//!   then unset-link per removed link. The H2C bodies those
//!   steps send are built by [`super::link_h2c_8922a`]
//!   (issue #1918) from the links admitted here.
//! - MLO itself is gated in Linux on the firmware
//!   `NOTIFY_AP_INFO` feature (`core.c:7691`, present for
//!   RTL8922A at `fw.c:1010`); this owner cannot see
//!   firmware features, so that gate is a caller/platform
//!   precondition, not a check here.
//!
//! Deliberate differences from Linux (same spirit as the
//! single-link owner):
//! - The pool keeps the full 32-slot range for single-link
//!   admission; an MLD base is admitted only when both of
//!   its strided slots (`base`, `base + 16`) are free, so a
//!   single-link station can never collide with an MLD link.
//!   (Linux searches only the 16 base slots while MLO is on.)
//! - BA-CAM slot maps are per link (each link `Station`
//!   owns its own `BaCam`); Linux allocates BA-CAM entries
//!   from one device-global map with per-sta tracking
//!   (`core.c:5597`). The H2C still comes from the
//!   designated link's map, as in Linux.
//! - This owner has no VIF concept, so the station-mode rule
//!   that a peer station takes the VIF's main MACID instead
//!   of a pool MACID (`mac80211.c`, `rtw89_vif_get_main_macid`)
//!   is not modeled here; MLD links take pool MACIDs exactly like
//!   the single-link owner does. VIF composition lives on the
//!   Prepared owner (`prepared_8922a::Prepared8922a`): it holds
//!   the VIF record and admits the TDLS peer at the VIF's main
//!   MACID via [`admit_with_macid`], and it admits MLDs via
//!   [`admit_mld`].
//! - Role-maintain / DMAC / join-info / CAM H2Cs that Linux
//!   sends around link add/assoc/disconnect are built by
//!   [`super::link_h2c_8922a`] (issue #1918), not here: like
//!   the single-link owner, this module builds CCTL + BA-CAM
//!   bodies only and never sends them; the lifecycle module
//!   composes the per-link transition bodies from the records
//!   admitted here plus the caller's VIF-link context.

use super::{
    bacam_v1::{self, BaCam},
    cctl_g7::{self, DefaultCmac},
    chip_8922a,
    efuse_be::BeFactory,
    eht::EhtStation,
    ppe,
    ra_mask::{self, HeCaps, HtCaps, VhtCaps},
    radio_power_c::tpe_mac,
};
use narf_wireless::association::six_ghz::SixGhzChannel;
use narf_wireless::reg::PowerType6Ghz;

/// Stride between an MLD link's MACIDs: one base MACID per
/// MLD station, link instance `index` takes
/// `base + index * MLD_MACID_STRIDE` (Linux `core.c`
/// `rtw89_acquire_mac_id` / `rtw89_init_sta`:
/// `support_mld_num = support_macid_num / support_link_num`).
pub(super) const MLD_MACID_STRIDE: usize =
    chip_8922a::SUPPORT_MACID_NUM / chip_8922a::SUPPORT_LINK_NUM;

/// Maximum 802.11 link ID (`IEEE80211_MLD_MAX_NUM_LINKS` =
/// 15, `include/linux/ieee80211-eht.h:462`): link IDs are
/// 0..=14.
pub(super) const MAX_LINK_ID: u8 = 14;

/// Operating band of the admitted link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Band {
    /// 2.4 GHz.
    Ghz2,
    /// 5 GHz.
    Ghz5,
    /// 6 GHz (admitted only with a [`SixGhzAdmission`] power
    /// program; 20 MHz only, see the module docs).
    Ghz6,
}

/// The caller-supplied 6 GHz power program for one admission
/// request: the AP's client power type (cfg80211
/// `cfg80211_6ghz_power_type`, from the AP's HE 6 GHz
/// Operation regulatory info via
/// `six_ghz::He6GhzOperation::power_type`) and, for Standard
/// Power only, the regd.c TPE constraint in dBm from [`tpe`].
/// A 6 GHz request without this context is refused
/// (`Error::SixGhzPowerMissing`); a non-6 GHz request
/// carrying one is refused (`Error::SixGhzContextUnexpected`).
///
/// Country policy (a 6 GHz-blocked country, the VLP block
/// for US/CA) is NOT checked here: it lives with the REGD
/// element owner (`radio_power_c::SixGhzPower::new`, which
/// needs the container's REGD map and the host regulatory
/// country — neither of which this owner holds), and the
/// future `rtw8922a_set_txpwr` program refuses a context
/// that policy does not admit. Admission records the
/// AP-advertised power type as-is; it programs no power.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SixGhzAdmission {
    /// AP client power type (VLP/LPI/SP).
    pub(super) power: PowerType6Ghz,
    /// regd.c intersected TPE constraint (dBm), Standard
    /// Power only; `None` means the AP advertised no usable
    /// default-category TPE (no TPE constraint applies).
    pub(super) tpe_dbm: Option<i8>,
}

/// The 6 GHz power program recorded on an admitted station:
/// the validated admission context plus the phy.c TPE
/// constraint in MAC units that the TX-power limit program
/// consumes (`rtw89_phy_get_tpe_constraint`, via
/// `radio_power_c::tpe_mac`): 63 when no TPE constrains the
/// link, so the limit pages are capped by the regulatory
/// tables alone. This is the program's admission-level
/// artifact; the register writes are the follow-up
/// `rtw8922a_set_txpwr` lane's (Linux `rtw8922a.c`
/// `rtw8922a_set_txpwr`: generic
/// `rtw89_phy_set_txpwr_{byrate,offset,limit,limit_ru}` plus
/// the 8922A `set_tx_shape` / `set_txpwr_diff` /
/// `set_txpwr_ref` / `set_txpwr_sar_diff` steps).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SixGhzProgram {
    /// AP client power type (VLP/LPI/SP).
    pub(super) power: PowerType6Ghz,
    /// regd.c intersected TPE constraint (dBm), STD only.
    pub(super) tpe_dbm: Option<i8>,
    /// phy.c `rtw89_phy_get_tpe_constraint` in MAC units
    /// (63 = no TPE constraint).
    pub(super) tpe_mac: i8,
}

impl SixGhzProgram {
    /// Validate `admission` into a program. Fail-closed:
    /// a TPE is meaningful only for Standard Power
    /// (`radio_power_c::Plan::from_elements_6ghz` refuses a
    /// TPE under any other `reg_6ghz_power`), and a TPE
    /// constraint below `RTW89_MIN_VALID_POWER_CONSTRAINT`
    /// (-10 dBm) is `-EINVAL` in regd.c
    /// (`rtw89_reg_6ghz_tpe_recalc`).
    fn from_admission(admission: SixGhzAdmission) -> Result<Self, Error> {
        if admission.tpe_dbm.is_some() && admission.power != PowerType6Ghz::Sp {
            return Err(Error::SixGhzTpeNotStandard);
        }
        if admission.tpe_dbm.is_some_and(|c| c < -10) {
            return Err(Error::SixGhzTpeBelowMinimum);
        }
        Ok(Self {
            power: admission.power,
            tpe_dbm: admission.tpe_dbm,
            tpe_mac: tpe_mac(admission.tpe_dbm),
        })
    }

    /// `enum rtw89_reg_6ghz_power` of this program
    /// (VLP 0 = DFLT, LPI 1, STD 2), as regd.c
    /// `rtw89_reg_6ghz_power_recalc` maps the client power
    /// type (see `radio_power_c::SixGhzPower`).
    pub(super) fn reg_6ghz_power(self) -> u8 {
        match self.power {
            PowerType6Ghz::Vlp => 0,
            PowerType6Ghz::Lpi => 1,
            PowerType6Ghz::Sp => 2,
        }
    }
}

/// The 8922A 6 GHz TPE entry point: the regd.c
/// `rtw89_calculate_tpe` constraint (dBm) for a 20 MHz
/// station on the primary inside the AP's HE 6 GHz channel
/// `ap`, from the AP's Transmit Power Envelope elements in
/// `ies`. It is the shared mac80211/regd.c parse
/// (`station_six_ghz::tpe`, the 8852C template: validate,
/// parse, rearrange to the used 20 MHz chandef, intersect
/// the local and regulatory-client EIRP/PSD limits); the
/// 8922A owner adds the admission rules around its result
/// ([`SixGhzProgram::from_admission`]) rather than a second
/// copy of the parse. `Ok(None)`: no valid default-category
/// TPE. `Err`: an 80+80 MHz AP channel or a primary outside
/// `ap` — the caller refuses the join.
pub(super) fn tpe(ies: &[u8], ap: &SixGhzChannel) -> Result<Option<i8>, ()> {
    super::station::six::tpe(ies, ap)
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
    /// 6 GHz power program (required for `Band::Ghz6`,
    /// refused on any other band).
    pub(super) six_ghz: Option<SixGhzAdmission>,
}

/// Admission failures. Every variant is a refusal, never a
/// fallback: a refused request produces no station and no
/// partially-programmed artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// 6 GHz requested without a 6 GHz power program
    /// (`SixGhzAdmission` absent).
    SixGhzPowerMissing,
    /// A 6 GHz power program supplied for a non-6 GHz band.
    SixGhzContextUnexpected,
    /// A TPE constraint supplied for a non-Standard-Power
    /// 6 GHz program (a TPE constrains STD only).
    SixGhzTpeNotStandard,
    /// A Standard-Power TPE constraint below -10 dBm
    /// (`RTW89_MIN_VALID_POWER_CONSTRAINT`, regd.c `-EINVAL`).
    SixGhzTpeBelowMinimum,
    /// A 6 GHz width above 20 MHz (the TPE rearrange is
    /// validated for the primary 20 MHz subchannel only).
    SixGhzWidthUnsupported,
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
    /// MLD admission with zero link requests.
    NoLinks,
    /// More link requests than the chip's link count (2).
    TooManyLinks,
    /// A link ID above 14 (`IEEE80211_MLD_MAX_NUM_LINKS` - 1).
    LinkIdOutOfRange,
    /// Two links share one 802.11 link ID.
    DuplicateLinkId,
    /// Two links share one peer link address.
    DuplicateLinkAddr,
    /// Two links share one (band, primary channel): each
    /// link needs its own channel context (the chip has 2).
    DuplicateChannel,
    /// Link requests disagree on the AID: Linux programs
    /// the one `vif->cfg.aid` into every link's assoc CCTL.
    AidMismatch,
    /// Link requests disagree on the port: Linux uses one
    /// port id for all of an MLD's links ("multi-link use
    /// the same port id on different HW bands").
    PortMismatch,
    /// No admitted link has this 802.11 link ID.
    LinkNotFound,
    /// A link with this 802.11 link ID is already admitted.
    LinkAlreadyActive,
    /// Admission at a caller-owned MACID outside the chip's
    /// 32-slot range (`admit_with_macid`).
    MacIdOutOfRange,
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

    /// Claim one specific MACID (an MLD re-adding a link at
    /// a slot it returned). Refuses with [`Error::NoMacId`]
    /// when the slot is taken or out of range.
    pub(super) fn claim(&mut self, macid: u8) -> Result<(), Error> {
        match self.used.get_mut(macid as usize) {
            Some(slot) if !*slot => {
                *slot = true;
                Ok(())
            }
            _ => Err(Error::NoMacId),
        }
    }

    /// Allocate an MLD base MACID: the lowest base `b` in
    /// `0..MLD_MACID_STRIDE` whose whole strided pair
    /// (`b`, `b + MLD_MACID_STRIDE`) is free. Both slots are
    /// marked used, reserving the second link's MACID even
    /// when the MLD is admitted with one link (Linux
    /// precomputes both instances' MACIDs in
    /// `rtw89_init_sta`). A later [`Self::free`] of one
    /// slot frees only that link; the base slot stays held
    /// until its own link is removed. Refuses with
    /// [`Error::NoMacId`] when no pair is free.
    pub(super) fn alloc_mld_base(&mut self) -> Result<u8, Error> {
        for base in 0..MLD_MACID_STRIDE {
            let second = base + MLD_MACID_STRIDE;
            if !self.used[base] && !self.used[second] {
                self.used[base] = true;
                self.used[second] = true;
                return Ok(base as u8);
            }
        }
        Err(Error::NoMacId)
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
    /// 6 GHz power program (`Some` exactly when
    /// `band == Band::Ghz6`).
    pub(super) six_ghz: Option<SixGhzProgram>,
}

impl Station {
    /// The 6 GHz power program of this station, if it is a
    /// 6 GHz station: the client power type, the TPE
    /// constraint (dBm, STD only) and its MAC-unit form.
    pub(super) fn six_ghz(&self) -> Option<SixGhzProgram> {
        self.six_ghz
    }

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

/// Validate one link's admission request. Checks run in a
/// fixed order so a request failing several checks always
/// reports the same refusal. Does not touch the pool: a
/// refused request consumes no MACID. Returns the 6 GHz
/// power program for an admitted 6 GHz link (`None` on
/// 2.4/5 GHz): a 6 GHz request without an admission is
/// refused (`SixGhzPowerMissing`), as is a non-6 GHz
/// request carrying one (`SixGhzContextUnexpected`).
fn validate(req: &Request) -> Result<Option<SixGhzProgram>, Error> {
    let six_ghz = match (req.band, req.six_ghz) {
        (Band::Ghz6, None) => return Err(Error::SixGhzPowerMissing),
        (Band::Ghz6, Some(admission)) => Some(SixGhzProgram::from_admission(admission)?),
        (_, Some(_)) => return Err(Error::SixGhzContextUnexpected),
        (_, None) => None,
    };
    if !chip_8922a::SUPPORT_BANDWIDTHS_MHZ.contains(&req.width_mhz) {
        return Err(Error::WidthNotAdvertised);
    }
    if req.band == Band::Ghz6 && req.width_mhz != 20 {
        return Err(Error::SixGhzWidthUnsupported);
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
    Ok(six_ghz)
}

/// Build one link's station record for an already-allocated
/// `macid`: the G7 default + assoc CCTL tables and the
/// BA-CAM map. Pure: no pool interaction.
fn build_station(
    factory: &BeFactory,
    facet: EhtStation,
    req: &Request,
    macid: u8,
    six_ghz: Option<SixGhzProgram>,
) -> Result<Station, Error> {
    // Pads come from the peer's IEs, never from the caller: the
    // parse output is always five 2-bit values, so no
    // PadsOutOfRange refusal exists anymore (the assoc builder
    // still validates its own input).
    let pads = ppe::parse_assoc_ppe(req.peer_ies, req.nss);
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
        six_ghz,
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
    /// 6 GHz power program (`Some` exactly when
    /// `band == Band::Ghz6`).
    pub(super) six_ghz: Option<SixGhzProgram>,
}

impl LegacyStation {
    /// The 6 GHz power program of this station, if it is a
    /// 6 GHz station: the client power type, the TPE
    /// constraint (dBm, STD only) and its MAC-unit form.
    pub(super) fn six_ghz(&self) -> Option<SixGhzProgram> {
        self.six_ghz
    }

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
/// caller supplies both — and drives the assoc table's BSR
/// format bit. PPE pads are parsed from `req.peer_ies`.
/// A 6 GHz request must carry a [`SixGhzAdmission`]
/// (20 MHz only); the program is recorded on the admitted
/// station (see [`LegacyStation::six_ghz`]).
pub(super) fn admit_legacy(
    factory: &BeFactory,
    caps: &LegacyCaps,
    pool: &mut MacIdPool,
    req: &Request,
) -> Result<LegacyStation, Error> {
    // 6 GHz composes the same power program as the EHT path
    // (`validate`): a 6 GHz request without an admission is
    // refused, a non-6 GHz request carrying one is refused,
    // and a TPE is validated the same way. The 20 MHz-only
    // width rule is checked with the width below, in the
    // same relative order as `validate`.
    let six_ghz = match (req.band, req.six_ghz) {
        (Band::Ghz6, None) => return Err(Error::SixGhzPowerMissing),
        (Band::Ghz6, Some(admission)) => Some(SixGhzProgram::from_admission(admission)?),
        (_, Some(_)) => return Err(Error::SixGhzContextUnexpected),
        (_, None) => None,
    };
    if req.eht_support {
        return Err(Error::EhtInLegacyRequest);
    }
    if caps.supp_rates == 0 {
        return Err(Error::NoSupportedRates);
    }
    if !chip_8922a::SUPPORT_BANDWIDTHS_MHZ.contains(&req.width_mhz) {
        return Err(Error::WidthNotAdvertised);
    }
    if req.band == Band::Ghz6 && req.width_mhz != 20 {
        return Err(Error::SixGhzWidthUnsupported);
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
    let pads = ppe::parse_assoc_ppe(req.peer_ies, req.nss);
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
        pads,
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
        six_ghz,
    })
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
    let six_ghz = validate(req)?;
    let macid = pool.alloc()?;
    build_station(factory, facet, req, macid, six_ghz)
}

/// Admit one EHT station at a caller-owned MACID. The
/// Prepared owner uses this for the station-mode rule
/// (Linux `mac80211.c` `__rtw89_ops_sta_add`: a TDLS peer
/// on a station-mode VIF takes the VIF's main MACID,
/// `rtw89_vif_get_main_macid`, instead of a pool MACID).
/// The MACID is NOT allocated from any pool here: the
/// caller owns it already (the VIF's base slot is marked
/// used in the shared pool), and the caller releases it by
/// dropping the VIF, never by freeing this station's
/// MACID. The request is validated exactly as in
/// [`admit`]; a refused request consumes nothing.
pub(super) fn admit_with_macid(
    factory: &BeFactory,
    facet: EhtStation,
    req: &Request,
    macid: u8,
) -> Result<Station, Error> {
    let six_ghz = validate(req)?;
    if macid as usize >= chip_8922a::SUPPORT_MACID_NUM {
        return Err(Error::MacIdOutOfRange);
    }
    build_station(factory, facet, req, macid, six_ghz)
}

/// One MLD link request: the 802.11 link ID plus the
/// single-link admission request for that link's channel.
/// The link ID is the peer's advertised link ID (0..=14),
/// distinct from the instance index (admission order),
/// exactly as Linux keeps `links[link_id]` separate from
/// `links_inst[index]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LinkRequest<'a> {
    /// 802.11 link ID (0..=14).
    pub(super) link_id: u8,
    /// This link's admission request (peer link address,
    /// band, width, channel, NSS, and the shared AID/port).
    pub(super) req: Request<'a>,
}

/// One admitted MLD link: its 802.11 link ID, its instance
/// index, and its single-link station record. The instance
/// index is the admission order (lowest free slot, Linux
/// `rtw89_sta_set_link`); the link's MAC index is the
/// instance index (`RTW89_MAC_0 + index`) and its MACID is
/// `base + index * MLD_MACID_STRIDE` (Linux
/// `rtw89_init_sta`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MldLink {
    /// 802.11 link ID (0..=14).
    pub(super) link_id: u8,
    /// Instance index (0 or 1): admission order.
    pub(super) index: usize,
    /// This link's station record (per-link MACID, CCTLs,
    /// BA-CAM map).
    pub(super) station: Station,
}

impl MldLink {
    /// This link's MACID (`station.macid`).
    pub(super) fn macid(&self) -> u8 {
        self.station.macid
    }

    /// This link's MAC index (`RTW89_MAC_0 + index`).
    pub(super) fn mac_idx(&self) -> u8 {
        self.index as u8
    }
}

/// An admitted 8922A MLD station: one peer MLD, up to two
/// links. The MLD address is the shared identity; each link
/// carries its own link address, channel, MACID, CCTLs, and
/// BA-CAM map. AID and port are shared across links (Linux
/// programs the one `vif->cfg.aid` and the one port id into
/// every link's assoc CCTL). Links live in instance-index
/// slots: the designated link — the one BA-CAM H2C is built
/// from — is the first present link in index order (Linux
/// `rtw89_get_designated_link`: first link added).
///
/// The caller owns transport, as for [`Station`]: it sends
/// each link's CCTL bodies over H2C. Removing the last link
/// leaves an empty MLD; the caller then drops it (its
/// [`MldStation::release_all`] is a no-op once empty, and
/// every removed link already freed its own MACID). A
/// one-link MLD's [`MldStation::release_all`] also returns
/// the reserved second-link MACID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MldStation {
    /// Peer MLD address (shared by all links).
    pub(super) mld_addr: [u8; 6],
    /// Pool base MACID: link `index` owns
    /// `base_macid + index * MLD_MACID_STRIDE`.
    pub(super) base_macid: u8,
    /// Association ID, shared by all links.
    pub(super) aid: u16,
    /// Multi-port id, shared by all links.
    pub(super) port: u8,
    /// Admitted links by instance index; `None` = free.
    pub(super) links: [Option<MldLink>; chip_8922a::SUPPORT_LINK_NUM],
    /// Instance slots whose pool MACID this MLD still holds.
    /// [`MacIdPool::alloc_mld_base`] reserves both strided
    /// slots, so a one-link MLD holds the second link's MACID
    /// without a link in it; [`Self::remove_link`] returns a
    /// slot and [`Self::add_link`] re-claims it.
    pub(super) held: [bool; chip_8922a::SUPPORT_LINK_NUM],
}

impl MldStation {
    /// Number of admitted links.
    pub(super) fn link_count(&self) -> usize {
        self.links.iter().filter(|link| link.is_some()).count()
    }

    /// True when no link is admitted.
    pub(super) fn is_empty(&self) -> bool {
        self.link_count() == 0
    }

    /// The designated link (first present link in instance
    /// index order), or `None` when empty. Linux builds the
    /// BA-CAM H2C from this link.
    pub(super) fn designated_link(&self) -> Option<&MldLink> {
        self.links.iter().flatten().next()
    }

    /// Mutable access to the designated link, for BA-CAM
    /// slot acquisition.
    fn designated_link_mut(&mut self) -> Option<&mut MldLink> {
        self.links.iter_mut().flatten().next()
    }

    /// Admitted link by 802.11 link ID, if any.
    pub(super) fn link(&self, link_id: u8) -> Option<&MldLink> {
        self.links
            .iter()
            .flatten()
            .find(|link| link.link_id == link_id)
    }

    /// EHT contribution to the BE TXWD_INFO block for one
    /// admitted link: (info4 bits, info7 bits) from that
    /// link's facet. `None` when the link ID is not
    /// admitted or the facet cannot encode its NLTF value.
    pub(super) fn txwd_info_eht(&self, link_id: u8) -> Option<(u32, u32)> {
        self.link(link_id)?.station.txwd_info_eht()
    }

    /// Acquire a BA-CAM bitmap slot for a BlockAck session
    /// on the designated link. The index feeds
    /// [`Self::ba_h2c`]; it is only meaningful while the
    /// designated link stays admitted — release it before
    /// removing that link.
    pub(super) fn acquire_bacam(&mut self, tid: u8) -> Result<usize, Error> {
        let link = self.designated_link_mut().ok_or(Error::LinkNotFound)?;
        link.station.bacam.acquire(tid).map_err(Error::BaCam)
    }

    /// Build a BA-CAM v1 H2C body for one of the designated
    /// link's BlockAck sessions. MLD on, band-select from
    /// the designated link's MAC index (Linux
    /// `rtw89_fw_h2c_ba_cam_v1`: MLD_EN when the VIF is MLD,
    /// BAND_SEL = `mac_idx != 0`). `bitmap_idx` must come
    /// from [`Self::acquire_bacam`].
    pub(super) fn ba_h2c(
        &self,
        tid: u32,
        bmap_size: u32,
        ssn: u32,
        bitmap_idx: u32,
    ) -> Result<bacam_v1::BaCamH2c, Error> {
        let link = self.designated_link().ok_or(Error::LinkNotFound)?;
        bacam_v1::build_h2c(
            true,
            link.macid() as u32,
            tid,
            bmap_size,
            ssn,
            bitmap_idx,
            chip_8922a::BACAM_DYNAMIC_NUM as u32,
            true,
            link.mac_idx() != 0,
        )
        .map_err(Error::BaCam)
    }

    /// Release a BA-CAM bitmap slot acquired via
    /// [`Self::acquire_bacam`] on the designated link.
    pub(super) fn release_bacam(&mut self, idx: usize) -> Result<(), Error> {
        let link = self.designated_link_mut().ok_or(Error::LinkNotFound)?;
        link.station.bacam.release(idx).map_err(Error::BaCam)
    }

    /// Admit one more link to this MLD (Linux
    /// `__rtw89_ops_set_sta_links`: set-link, link-add,
    /// link-assoc). The new link takes the lowest free
    /// instance index, whose MACID slot was already
    /// reserved by the MLD base allocation, so no pool
    /// allocation happens here. Returns the new link's
    /// MACID. A refused request leaves the existing links
    /// untouched.
    pub(super) fn add_link(
        &mut self,
        factory: &BeFactory,
        facet: EhtStation,
        pool: &mut MacIdPool,
        link: &LinkRequest<'_>,
    ) -> Result<u8, Error> {
        if link.link_id > MAX_LINK_ID {
            return Err(Error::LinkIdOutOfRange);
        }
        let six_ghz = validate(&link.req)?;
        if self.link(link.link_id).is_some() {
            return Err(Error::LinkAlreadyActive);
        }
        if link.req.aid != self.aid {
            return Err(Error::AidMismatch);
        }
        if link.req.port != self.port {
            return Err(Error::PortMismatch);
        }
        for other in self.links.iter().flatten() {
            if other.station.peer == link.req.peer {
                return Err(Error::DuplicateLinkAddr);
            }
            if other.station.band == link.req.band && other.station.primary == link.req.primary {
                return Err(Error::DuplicateChannel);
            }
        }
        let index = self
            .links
            .iter()
            .position(|slot| slot.is_none())
            .ok_or(Error::TooManyLinks)?;
        let macid = self.base_macid + (index * MLD_MACID_STRIDE) as u8;
        let station = build_station(factory, facet, &link.req, macid, six_ghz)?;
        if !self.held[index] {
            pool.claim(macid)?;
            self.held[index] = true;
        }
        self.links[index] = Some(MldLink {
            link_id: link.link_id,
            index,
            station,
        });
        Ok(macid)
    }

    /// Remove one link (Linux `__rtw89_ops_clr_sta_links`:
    /// disassoc, disconnect, remove, unset-link). The
    /// removed link's MACID returns to the pool and its
    /// record is returned; the MLD survives on the
    /// remaining link, whose designated-link status follows
    /// automatically (first present link in index order).
    /// Removing the last link leaves an empty MLD for the
    /// caller to drop. Release the link's BA-CAM slots
    /// before removing it when it is the designated link:
    /// its map goes away with it.
    pub(super) fn remove_link(
        &mut self,
        pool: &mut MacIdPool,
        link_id: u8,
    ) -> Result<MldLink, Error> {
        let index = self
            .links
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|link| link.link_id == link_id))
            .ok_or(Error::LinkNotFound)?;
        let link = self.links[index].take().expect("slot held a link");
        pool.free(link.macid());
        self.held[index] = false;
        Ok(link)
    }

    /// Release every remaining link's MACID back to the
    /// pool (dissolve the whole MLD at once). The MLD
    /// record itself is then dead; the caller must not send
    /// further H2C for it. A no-op when already empty.
    pub(super) fn release_all(&self, pool: &mut MacIdPool) {
        for (index, held) in self.held.iter().enumerate() {
            if *held {
                pool.free(self.base_macid + (index * MLD_MACID_STRIDE) as u8);
            }
        }
    }
}

/// Admit one EHT MLD station with 1..=2 links. Cross-link
/// checks (distinct link IDs, link addresses, and channels;
/// one shared AID and port) run before any pool allocation,
/// and each link's own request is validated by
/// [`validate`], so a refused request consumes no MACID and
/// produces no station. The base MACID comes from
/// [`MacIdPool::alloc_mld_base`]; link instance `index`
/// takes `base + index * MLD_MACID_STRIDE`, and each link's
/// station record is built with that MACID (per-link G7
/// default + assoc CCTL, per-link BA-CAM map).
pub(super) fn admit_mld(
    factory: &BeFactory,
    facet: EhtStation,
    pool: &mut MacIdPool,
    mld_addr: [u8; 6],
    links: &[LinkRequest<'_>],
) -> Result<MldStation, Error> {
    if links.is_empty() {
        return Err(Error::NoLinks);
    }
    if links.len() > chip_8922a::SUPPORT_LINK_NUM {
        return Err(Error::TooManyLinks);
    }
    let mut programs: [Option<SixGhzProgram>; chip_8922a::SUPPORT_LINK_NUM] = [None, None];
    for (i, link) in links.iter().enumerate() {
        if link.link_id > MAX_LINK_ID {
            return Err(Error::LinkIdOutOfRange);
        }
        programs[i] = validate(&link.req)?;
    }
    for (i, a) in links.iter().enumerate() {
        for b in &links[i + 1..] {
            if a.link_id == b.link_id {
                return Err(Error::DuplicateLinkId);
            }
            if a.req.peer == b.req.peer {
                return Err(Error::DuplicateLinkAddr);
            }
            if a.req.band == b.req.band && a.req.primary == b.req.primary {
                return Err(Error::DuplicateChannel);
            }
        }
    }
    let aid = links[0].req.aid;
    let port = links[0].req.port;
    if links.iter().any(|link| link.req.aid != aid) {
        return Err(Error::AidMismatch);
    }
    if links.iter().any(|link| link.req.port != port) {
        return Err(Error::PortMismatch);
    }
    let base_macid = pool.alloc_mld_base()?;
    let mut slots: [Option<MldLink>; chip_8922a::SUPPORT_LINK_NUM] = [None, None];
    for (index, link) in links.iter().enumerate() {
        let macid = base_macid + (index * MLD_MACID_STRIDE) as u8;
        match build_station(factory, facet, &link.req, macid, programs[index]) {
            Ok(station) => {
                slots[index] = Some(MldLink {
                    link_id: link.link_id,
                    index,
                    station,
                });
            }
            // Unreachable after validation (CCTL/BA-CAM only
            // fail on field overflow), but a refused request
            // must never leak its base pair.
            Err(error) => {
                pool.free(base_macid);
                pool.free(base_macid + MLD_MACID_STRIDE as u8);
                return Err(error);
            }
        }
    }
    Ok(MldStation {
        mld_addr,
        base_macid,
        aid,
        port,
        links: slots,
        held: [true; chip_8922a::SUPPORT_LINK_NUM],
    })
}

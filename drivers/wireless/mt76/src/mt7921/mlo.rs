//! MT7925 multi-link operation (MLO): the MLD station lifecycle on
//! top of the UNI TLV layer (`crate::mt7925::mcu`).
//!
//! Slice (6) delivered the TLV encoders (`MldLinks`,
//! `encode_sta_rec_mld_tlv` / `encode_sta_rec_eht_mld_tlv`, the
//! per-link BA builders, per-link BSS info with `UNI_BSS_MLD`,
//! `build_uni_sta_update_req` with `mld`, `build_uni_sta_remove_req`
//! with `STA_REC_MLD_OFF`); slice (7) delivered the EHT capability
//! values. This module owns what was left: the station lifecycle
//! that drives those builders (add/assoc per link, primary first;
//! per-link BA setup per TID; teardown with per-link remove +
//! `MLD_OFF`; secondary-link join/leave), the MLD capability this
//! driver advertises, and the EML capability source.
//!
//! ## Upstream shape (torvalds/linux `4dce97c6c26`, `mt7925/mcu.c`)
//!
//! - One station-update message per active link, primary first
//!   (`mt7925_mcu_sta_cmd`, `:2159-2246`; the per-link loop shape
//!   is `mt7925_mcu_uni_tx_ba` / `mt7925_mcu_uni_rx_ba`, `:761-824`).
//!   The MLD TLV always lists the primary (deflink) first, then at
//!   most one secondary (`mt7925_mcu_sta_mld_tlv`, `:2066-2140`,
//!   `mld->link[2]`).
//! - The station update emits `sta_rec_eht` + `sta_rec_mld` +
//!   `sta_rec_eht_mld` together (`:2182-2202`); the MLD pair only
//!   when the state is not NONE and the vif is an MLD vif.
//! - Removal is `STA_REC_REMOVE` + bare `STA_REC_MLD_OFF`
//!   (`:2237-2244`).
//! - BSS info is one message per link
//!   (`mt7925_mcu_add_bss_info_sta`, `:3102-3142`), always carrying
//!   the MLD TLV (`mt7925_mcu_bss_mld_tlv`, `:2912-2929`).
//!
//! ## What NARF does not have (and does not invent)
//!
//! - No wiphy: the MLD capability advertisement is a fixed claim,
//!   `MldCapability::advertised()` — max simultaneous links 2
//!   (upstream `mld->link[2]`; the wiphy
//!   `mld_capa_and_ops & MAX_SIMUL_LINKS` gate at `mcu.c:1488` is
//!   an ROC-path check with no NARF counterpart). 320 MHz stays
//!   refused: the lifecycle rejects an RLM bandwidth of
//!   `RLM_BW_320` (the 7925 is a 160 MHz part;
//!   `is_320mhz_supported` is 7927-only).
//! - No second-link SME trigger: NARF has one station vif and one
//!   association plan, so no live code can join a secondary link
//!   yet. The lifecycle is the pure, fixture-tested orchestration
//!   the session will drive once the SME learns a second link; the
//!   single-link UNI dispatch in `station_join.rs` is the live
//!   part of this slice (it drives `peer_record_uni_on` /
//!   `sta_remove_uni_on` / the UNI key records for a 7925 radio).
//! - No live ADDBA/DELBA engine integration: the lifecycle's
//!   `tx_ba` / `rx_ba` build the per-link BA messages, but the
//!   live BA owners (`tx_ba_station.rs`, `rx_ba_station.rs`)
//!   still program CONNAC2 BA records. Wiring them to the UNI
//!   per-link builders (per-link BA state lives in the session's
//!   `MldStation`) is a follow-up, not this slice.
//! - No WTBL programming: the UNI station update has no WTBL TLVs
//!   (see `peer_record_uni_on`); WTBL programming on 7925 is a
//!   separate WTBL-update path, also a follow-up.
//!
//! ## EML capability source
//!
//! Upstream (`mt7925_mcu_sta_eht_mld_tlv`, `mcu.c:2028-2062`)
//! computes
//! `eml_cap = (vif->cfg.eml_cap & (EMLSR_SUPP |
//! TRANSITION_TIMEOUT)) | (ext_capa->eml_capabilities &
//! (PADDING_DELAY | TRANSITION_DELAY))` — both inputs are
//! *local* state (the vif's configured EML cap, the wiphy's
//! iftype ext-capa EML capabilities), not the peer's negotiated
//! EHT caps. NARF models neither input (no vif cfg, no wiphy
//! iftype ext capa; the EHT Capabilities element carries no EML
//! bits), so the NARF-side source is the fail-closed constant
//! `EmlCaps::advertised()`: no EMLSR, `eml_cap = 0`, and the
//! EHT MLD TLV carries the fallback `str_cap[0] = BIT(1)`.
//! When the SME one day advertises EMLSR (Extended Capabilities
//! EML field + vif cfg), that is where the value comes from —
//! never from the negotiated EHT caps.

use super::association::{JoinPlan, Security, TxPermission};
use super::firmware_transport::{Error, RadioInfo, ScanBss};
use super::vif_slots::{Link, Vif};
use crate::mt7925::mcu::{
    build_uni_rx_ba_req, build_uni_tx_ba_req, MldLink, MldLinks, UniBssHe, UniBssMld, UniBssRlm,
    UniBssSec, RLM_BAND_2G, RLM_BAND_5G, RLM_BAND_6G, RLM_BW_320,
};
use alloc::vec::Vec;

/// The MLD capability this driver advertises for an MT7925
/// station: at most two simultaneous links — the primary plus one
/// secondary (`MldLinks` carries exactly that shape; upstream
/// `mld->link[2]`). NARF has no wiphy, so this is a fixed claim,
/// not a negotiated value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MldCapability {
    /// Maximum simultaneous links: always 2.
    pub max_simultaneous_links: u8,
    /// The station's EML capabilities (see [`EmlCaps`]).
    pub eml: EmlCaps,
}

impl MldCapability {
    /// Maximum simultaneous links an MT7925 MLD station claims.
    pub const MAX_SIMULTANEOUS_LINKS: u8 = 2;

    /// The driver's advertised MLD capability.
    pub const fn advertised() -> Self {
        Self {
            max_simultaneous_links: Self::MAX_SIMULTANEOUS_LINKS,
            eml: EmlCaps::advertised(),
        }
    }
}

/// EML capabilities of this station, for the EHT MLD TLV
/// (`sta_rec_eht_mld`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EmlCaps {
    /// `true` when EMLSR is supported (selects the `eml_cap`
    /// bytes in the TLV; otherwise `str_cap[0] = BIT(1)`).
    pub emlsr: bool,
    /// Masked EML capabilities (see the module docs for the
    /// upstream formula and the NARF-side source).
    pub eml_cap: u16,
}

impl EmlCaps {
    /// No EMLSR: `emlsr = false`, `eml_cap = 0`.
    pub const NONE: Self = Self {
        emlsr: false,
        eml_cap: 0,
    };

    /// The driver's local EML advertisement: [`Self::NONE`].
    /// Fail-closed by construction — see the module docs. NARF
    /// advertises no EMLSR (the local EHT MAC caps carry no EMLSR
    /// bit and no Extended Capabilities EML field is emitted), so
    /// a peer never sees EMLSR from this station and the EHT MLD
    /// TLV always takes the `str_cap[0] = BIT(1)` fallback.
    pub const fn advertised() -> Self {
        Self::NONE
    }
}

/// `true` when `info` is an MT7925 radio: the UNI (CONNAC3)
/// station path applies instead of the CONNAC2 one. Keyed on
/// `RadioInfo.chip_id == 0x7925` — the same value
/// `mt7921::eht::qualified` gates EHT on. This is the dispatch
/// the single-link join/teardown uses; it is reachable in
/// fixtures (where `RadioInfo` is constructed with `0x7925`)
/// and on hardware only once Q1 opens (the probe gate at
/// `pci.rs:441` and `chip_id()` in `firmware_transport_hw.rs`
/// still reject 7925 today).
pub(crate) fn is_connac3(info: RadioInfo) -> bool {
    info.chip_id == 0x7925
}

/// BSS slot time in µs for a UNI BSS record (upstream
/// `phy->slottime`): 20 (long slot) on 2.4 GHz, 9 (short slot) on
/// 5/6 GHz. NARF does not model short-slot negotiation, so the
/// long-slot default is used on 2.4 GHz and the 9 µs slot
/// elsewhere.
pub(crate) const fn slot_time_us(channel: u8) -> u16 {
    if channel <= 14 {
        20
    } else {
        9
    }
}

/// Per-link MLD identity for one UNI BSS record
/// (`UniBssMld`, `mt7925/mcu.c:2912-2929`): `link_id` is this
/// record's link, `primary_bss_idx` the primary link's BSS
/// index. `eml_enable` follows the station's EMLSR support
/// (always false while `EmlCaps::advertised()` is [`EmlCaps::NONE`]).
pub(crate) fn uni_bss_mld(
    link: Link,
    own_mac: [u8; 6],
    is_mld: bool,
    primary_bss_idx: u8,
    eml_enable: bool,
) -> UniBssMld {
    UniBssMld {
        is_mld,
        link_id: link.bss(),
        primary_bss_idx,
        own_mac,
        eml_enable,
    }
}

/// RLM (channel) parameters for one link's UNI BSS record, from
/// the link's regulatory grant: control channel, center channel,
/// native width, stream counts, band. `center_chan2` is 0 — no
/// 80P80, and 320 MHz stays refused (a 320 MHz grant fails
/// closed in the caller, never here). `bw` is the grant's native
/// width, which shares the `RLM_BW_*` numbering
/// (`IEEE80211_STA_RX_BW_*`).
pub(crate) fn uni_rlm(
    bss: &ScanBss,
    permission: TxPermission,
    streams: u8,
) -> Result<UniBssRlm, Error> {
    let band = match permission.band() {
        Some(super::channel::Band::Ghz2) => RLM_BAND_2G,
        Some(super::channel::Band::Ghz5) => RLM_BAND_5G,
        Some(super::channel::Band::Ghz6) => RLM_BAND_6G,
        None => return Err(Error::Bounds),
    };
    Ok(UniBssRlm {
        control_channel: bss.channel,
        center_chan: permission.center_channel(),
        center_chan2: 0,
        bw: permission.native_width(),
        tx_streams: streams,
        rx_streams: streams,
        band,
    })
}

/// One link's UNI BSS record for the station join, assembled from
/// the plan + grant (the single-link dispatch helper).
/// `connected = false` is the pre-auth record: no HE/RLM — the
/// builder only emits RLM + MBSSID when enabling, and the
/// pre-auth channel context rides the earlier channel-switch
/// command. `connected = true` is the assoc-time record (HE +
/// RLM). `#[inline(never)]` keeps the join future's frame small:
/// the record assembly (HE params, RLM, SEC, MLD identity)
/// stays out of `associate_station_as`.
#[inline(never)]
pub(crate) fn uni_bss_record(
    plan: &JoinPlan,
    link: Link,
    bss: &ScanBss,
    security: Security,
    connected: bool,
    permission: TxPermission,
    info: RadioInfo,
) -> Result<Vec<u8>, Error> {
    let he = if connected {
        plan.he().map(|he| he.uni_bss_he(true))
    } else {
        None
    };
    let rlm = if connected {
        Some(uni_rlm(
            bss,
            permission,
            info.capabilities.phy.spatial_streams.min(2),
        )?)
    } else {
        None
    };
    super::association::bss_record_uni_on(
        link,
        bss,
        connected,
        super::association::uni_bss_sec_for(security),
        uni_bss_mld(link, info.capabilities.mac, false, link.bss(), false),
        he,
        rlm,
        slot_time_us(bss.channel),
    )
    // The BSS builder reports the plan's error type; the session
    // reports the native one (the same mapping `station_join.rs`
    // applies to every plan call).
    .map_err(|_| Error::Bounds)
}

/// One link's UNI BSS disable record for teardown (the
/// single-link dispatch helper). `he` is the assoc-time HE
/// params with the color cleared (`uni_bss_he(false)`), or
/// `None` when the BSS never negotiated HE. `is_mld` /
/// `primary_bss_idx` describe the station at teardown time (see
/// [`MldStation::teardown`]).
pub(crate) fn uni_bss_disable(
    link: Link,
    bss: &ScanBss,
    sec: UniBssSec,
    he: Option<UniBssHe>,
    own_mac: [u8; 6],
    is_mld: bool,
    primary_bss_idx: u8,
) -> Result<Vec<u8>, Error> {
    super::association::bss_record_uni_on(
        link,
        bss,
        false,
        sec,
        uni_bss_mld(link, own_mac, is_mld, primary_bss_idx, false),
        he,
        None,
        slot_time_us(bss.channel),
    )
    .map_err(|_| Error::Bounds)
}

/// Which UNI command a lifecycle message is sent with.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MloCommand {
    /// `MCU_UNI_CMD(BSS_INFO_UPDATE)`.
    BssInfo,
    /// `MCU_UNI_CMD(STA_REC_UPDATE)`.
    StaUpdate,
}

impl MloCommand {
    /// The `Command::Unified { id }` this message is exchanged
    /// with (`mt7925/mcu.c`: BSS = 2, STA = 3).
    pub const fn unified_id(self) -> u16 {
        match self {
            Self::BssInfo => 2,
            Self::StaUpdate => 3,
        }
    }
}

/// One firmware message the lifecycle produces, in send order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MloMessage {
    /// Which UNI command carries the body.
    pub command: MloCommand,
    /// The command body (`bss_req_hdr` / `sta_req_hdr` + TLVs).
    pub body: Vec<u8>,
}

/// Firmware-record state of one MLD link.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// No BSS/STA record programmed for this link.
    Idle,
    /// BSS + pre-association STA record programmed.
    Added,
    /// Associated STA record programmed.
    Associated,
}

/// One link of an MLD station: its `Link` geometry and its
/// firmware-record state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct MldLinkState {
    link: Link,
    state: LinkState,
}

/// An MLD station: the primary link plus at most one secondary
/// link, and the EML capabilities its EHT MLD TLV carries.
///
/// The station starts single-link (`links()` is `None`: it is
/// not an MLD vif, so no MLD TLVs are emitted — upstream emits
/// them only for an MLD vif). It becomes an MLD station when a
/// secondary link joins (`links()` is `Some` with both links).
/// Every method builds its messages first and commits state
/// only on success, so a failed build never claims a link the
/// firmware was not programmed with.
#[derive(Clone, Debug)]
pub struct MldStation {
    own_mac: [u8; 6],
    primary: MldLinkState,
    secondary: Option<MldLinkState>,
    eml: EmlCaps,
}

impl MldStation {
    /// A single-link station on `primary` (`Link::HOME` for the
    /// retained station vif). The secondary slot is empty until
    /// [`Self::join_secondary`] fills it.
    pub(crate) fn new(primary: Link, own_mac: [u8; 6]) -> Self {
        Self {
            own_mac,
            primary: MldLinkState {
                link: primary,
                state: LinkState::Idle,
            },
            secondary: None,
            eml: EmlCaps::advertised(),
        }
    }

    /// A secondary-link `Link` on vif `vif_index` with peer WCID
    /// `peer_wcid` (allocated from the shared WTBL map by the
    /// caller). Each MLO link is its own vif: BSS/OMAC/WMM follow
    /// the vif index, exactly as `Link::HOME` is BSS0.
    pub(crate) fn new_secondary_link(vif_index: u8, peer_wcid: u8) -> Result<Link, Error> {
        Link::new(Vif::new(vif_index)?, peer_wcid)
    }

    /// The station's `MldLinks` for a station update: `None`
    /// while single-link (not an MLD vif — no MLD TLVs),
    /// `Some` with both links once a secondary is active.
    pub(crate) fn links(&self) -> Option<MldLinks> {
        let secondary = self.secondary.filter(|s| s.state != LinkState::Idle)?;
        Some(MldLinks {
            own_mac: self.own_mac,
            primary: MldLink {
                wcid_idx: u16::from(self.primary.link.peer()),
                bss_idx: self.primary.link.bss(),
            },
            secondary: Some(MldLink {
                wcid_idx: u16::from(secondary.link.peer()),
                bss_idx: secondary.link.bss(),
            }),
            eml_cap: self.eml.eml_cap,
            emlsr: self.eml.emlsr,
        })
    }

    /// `true` once a secondary link is active.
    pub(crate) fn is_mld(&self) -> bool {
        self.links().is_some()
    }

    /// The primary link's record state.
    pub(crate) fn primary_state(&self) -> LinkState {
        self.primary.state
    }

    /// The secondary link's record state, if a secondary exists.
    pub(crate) fn secondary_state(&self) -> Option<LinkState> {
        self.secondary.map(|s| s.state)
    }

    /// The primary link.
    pub(crate) fn primary_link(&self) -> Link {
        self.primary.link
    }

    /// The secondary link, if one exists.
    pub(crate) fn secondary_link(&self) -> Option<Link> {
        self.secondary.map(|s| s.link)
    }

    /// The per-link MLD identity for `link`'s BSS record.
    fn bss_mld(&self, link: Link, was_mld: bool) -> UniBssMld {
        uni_bss_mld(
            link,
            self.own_mac,
            was_mld,
            self.primary.link.bss(),
            self.eml.emlsr,
        )
    }

    /// Build (without committing) the BSS + STA-update messages
    /// for adding `link` with `links` as the MLD set the update
    /// carries. 320 MHz is refused here: an RLM bandwidth of
    /// `RLM_BW_320` fails closed (`UnsupportedFirmware`).
    // Wide record ABI: the per-link BSS/STA inputs are the
    // parameters (same shape as the `build_uni_*_req` builders).
    #[allow(clippy::too_many_arguments)]
    fn build_add(
        &self,
        plan: &JoinPlan,
        link: Link,
        aid: u16,
        associated: bool,
        bss: &ScanBss,
        sec: UniBssSec,
        he: Option<UniBssHe>,
        rlm: Option<UniBssRlm>,
        links: Option<MldLinks>,
    ) -> Result<Vec<MloMessage>, Error> {
        if rlm.is_some_and(|rlm| rlm.bw == RLM_BW_320) {
            return Err(Error::UnsupportedFirmware);
        }
        let bss_record = super::association::bss_record_uni_on(
            link,
            bss,
            associated,
            sec,
            self.bss_mld(link, links.is_some()),
            he,
            rlm,
            slot_time_us(bss.channel),
        )
        .map_err(|_| Error::Bounds)?;
        let sta_record = plan
            .peer_record_uni_on(link, aid, associated, links)
            .map_err(|_| Error::Bounds)?;
        Ok(alloc::vec![
            MloMessage {
                command: MloCommand::BssInfo,
                body: bss_record,
            },
            MloMessage {
                command: MloCommand::StaUpdate,
                body: sta_record,
            },
        ])
    }

    /// Add or re-add `link`: its BSS record, then its station
    /// update — primary first, one message per active link.
    /// `link` must be the primary link or the secondary link (a
    /// new secondary is accepted here too, with its own vif).
    /// Adding a new secondary also refreshes the primary's
    /// station update with the two-link MLD set (its earlier
    /// record carried `link_num = 1` and would otherwise go
    /// stale); the refresh is idempotent. State commits only
    /// once every message builds.
    // Wide record ABI: the per-link BSS/STA inputs are the
    // parameters (same shape as the `build_uni_*_req` builders).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_link(
        &mut self,
        plan: &JoinPlan,
        link: Link,
        aid: u16,
        associated: bool,
        bss: &ScanBss,
        sec: UniBssSec,
        he: Option<UniBssHe>,
        rlm: Option<UniBssRlm>,
    ) -> Result<Vec<MloMessage>, Error> {
        let new_secondary = link != self.primary.link
            && self
                .secondary
                .is_none_or(|secondary| secondary.link != link);
        if new_secondary && link.bss() == self.primary.link.bss() {
            // A second station record on the primary vif is not a
            // second link: each MLO link is its own vif.
            return Err(Error::Busy);
        }
        if new_secondary && self.secondary.is_some() {
            return Err(Error::Busy);
        }
        let target_state = if link == self.primary.link {
            self.primary.state
        } else {
            self.secondary.map_or(LinkState::Idle, |s| s.state)
        };
        if target_state == LinkState::Associated && !associated {
            // An associated link is not downgraded to a
            // pre-association add.
            return Err(Error::Busy);
        }
        let links = if new_secondary {
            Some(MldLinks {
                own_mac: self.own_mac,
                primary: MldLink {
                    wcid_idx: u16::from(self.primary.link.peer()),
                    bss_idx: self.primary.link.bss(),
                },
                secondary: Some(MldLink {
                    wcid_idx: u16::from(link.peer()),
                    bss_idx: link.bss(),
                }),
                eml_cap: self.eml.eml_cap,
                emlsr: self.eml.emlsr,
            })
        } else {
            self.links()
        };
        let mut messages = self.build_add(plan, link, aid, associated, bss, sec, he, rlm, links)?;
        if new_secondary {
            // Refresh the primary's station update with the
            // two-link set, primary first among STA updates.
            let refresh = plan
                .peer_record_uni_on(self.primary.link, aid, true, links)
                .map_err(|_| Error::Bounds)?;
            messages.insert(
                1,
                MloMessage {
                    command: MloCommand::StaUpdate,
                    body: refresh,
                },
            );
        }
        let state = if associated {
            LinkState::Associated
        } else {
            LinkState::Added
        };
        if link == self.primary.link {
            self.primary.state = state;
        } else if let Some(secondary) = &mut self.secondary {
            secondary.state = state;
        } else {
            self.secondary = Some(MldLinkState { link, state });
        }
        Ok(messages)
    }

    /// Join a secondary link: the primary must already be
    /// associated, the secondary slot must be free, and the link
    /// must be its own vif. Emits the secondary's BSS record,
    /// then the primary's refreshed station update, then the
    /// secondary's station update (primary first among STA
    /// updates, both carrying the two-link MLD set).
    // Wide record ABI: the per-link BSS/STA inputs are the
    // parameters (same shape as the `build_uni_*_req` builders).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn join_secondary(
        &mut self,
        plan: &JoinPlan,
        link: Link,
        aid: u16,
        bss: &ScanBss,
        sec: UniBssSec,
        he: Option<UniBssHe>,
        rlm: Option<UniBssRlm>,
    ) -> Result<Vec<MloMessage>, Error> {
        if self.primary.state != LinkState::Associated {
            return Err(Error::Busy);
        }
        if self.secondary.is_some() || link == self.primary.link {
            return Err(Error::Busy);
        }
        self.add_link(plan, link, aid, true, bss, sec, he, rlm)
    }

    /// Leave the secondary link: its station remove
    /// (`STA_REC_REMOVE` + `STA_REC_MLD_OFF`), then its BSS
    /// disable. A station with no secondary leaves with no
    /// messages and no error. State clears only once both
    /// messages build.
    pub(crate) fn leave_secondary(
        &mut self,
        bss: &ScanBss,
        sec: UniBssSec,
    ) -> Result<Vec<MloMessage>, Error> {
        let Some(secondary) = self.secondary.filter(|s| s.state != LinkState::Idle) else {
            return Ok(Vec::new());
        };
        let messages = alloc::vec![
            MloMessage {
                command: MloCommand::StaUpdate,
                body: self.sta_remove_for(secondary.link),
            },
            MloMessage {
                command: MloCommand::BssInfo,
                body: super::association::bss_record_uni_on(
                    secondary.link,
                    bss,
                    false,
                    sec,
                    self.bss_mld(secondary.link, true),
                    None,
                    None,
                    slot_time_us(bss.channel),
                )
                .map_err(|_| Error::Bounds)?,
            },
        ];
        self.secondary = None;
        Ok(messages)
    }

    /// The station-remove message for `link` (no plan needed:
    /// removal is valid from any phase, and carries no capability
    /// TLVs — only `STA_REC_REMOVE` + `STA_REC_MLD_OFF`).
    fn sta_remove_for(&self, link: Link) -> Vec<u8> {
        crate::mt7925::mcu::build_uni_sta_remove_req(
            link.bss(),
            u16::from(link.peer()),
            link.omac(),
        )
    }

    /// Tear the station down: secondary first (remove + BSS
    /// disable), then primary (remove + BSS disable). A station
    /// with nothing active tears down with no messages. State
    /// clears only once every message builds.
    pub(crate) fn teardown(
        &mut self,
        bss: &ScanBss,
        sec: UniBssSec,
    ) -> Result<Vec<MloMessage>, Error> {
        let was_mld = self.is_mld();
        let mut messages = Vec::new();
        if let Some(secondary) = self.secondary.filter(|s| s.state != LinkState::Idle) {
            messages.push(MloMessage {
                command: MloCommand::StaUpdate,
                body: self.sta_remove_for(secondary.link),
            });
            messages.push(MloMessage {
                command: MloCommand::BssInfo,
                body: super::association::bss_record_uni_on(
                    secondary.link,
                    bss,
                    false,
                    sec,
                    self.bss_mld(secondary.link, true),
                    None,
                    None,
                    slot_time_us(bss.channel),
                )
                .map_err(|_| Error::Bounds)?,
            });
        }
        if self.primary.state != LinkState::Idle {
            messages.push(MloMessage {
                command: MloCommand::StaUpdate,
                body: self.sta_remove_for(self.primary.link),
            });
            messages.push(MloMessage {
                command: MloCommand::BssInfo,
                body: super::association::bss_record_uni_on(
                    self.primary.link,
                    bss,
                    false,
                    sec,
                    self.bss_mld(self.primary.link, was_mld),
                    None,
                    None,
                    slot_time_us(bss.channel),
                )
                .map_err(|_| Error::Bounds)?,
            });
        }
        self.secondary = None;
        self.primary.state = LinkState::Idle;
        Ok(messages)
    }

    /// Per-link BA setup for one TID: one `STA_REC_UPDATE`
    /// carrying a single `STA_REC_BA` TLV for `link`
    /// (`mt7925_mcu_uni_tx_ba`, `mt7925/mcu.c:761-793`). The link
    /// must be associated; `tid` must be < 8 (the TLV's `ba_en`
    /// is one octet, `enable << tid`) and the window within the
    /// driver's 256-frame cap.
    pub(crate) fn tx_ba(
        &self,
        link: Link,
        tid: u8,
        amsdu: bool,
        enable: bool,
        ssn: u16,
        winsize: u16,
    ) -> Result<MloMessage, Error> {
        self.ba(link, tid, true, amsdu, enable, ssn, winsize)
    }

    /// Per-link BA setup for one TID, recipient side
    /// (`mt7925_mcu_uni_rx_ba`, `mt7925/mcu.c:795-824`).
    pub(crate) fn rx_ba(
        &self,
        link: Link,
        tid: u8,
        amsdu: bool,
        enable: bool,
        ssn: u16,
        winsize: u16,
    ) -> Result<MloMessage, Error> {
        self.ba(link, tid, false, amsdu, enable, ssn, winsize)
    }

    // Wide record ABI: the per-link BA inputs are the parameters
    // (same shape as the `build_uni_*_ba_req` builders).
    #[allow(clippy::too_many_arguments)]
    fn ba(
        &self,
        link: Link,
        tid: u8,
        tx: bool,
        amsdu: bool,
        enable: bool,
        ssn: u16,
        winsize: u16,
    ) -> Result<MloMessage, Error> {
        let state = if link == self.primary.link {
            self.primary.state
        } else if self.secondary.is_some_and(|s| s.link == link) {
            self.secondary.map_or(LinkState::Idle, |s| s.state)
        } else {
            return Err(Error::Busy);
        };
        if state != LinkState::Associated || tid >= 8 || winsize == 0 || winsize > 256 {
            return Err(if state != LinkState::Associated {
                Error::Busy
            } else {
                Error::Bounds
            });
        }
        let body = if tx {
            build_uni_tx_ba_req(
                link.bss(),
                u16::from(link.peer()),
                link.omac(),
                tid,
                amsdu,
                enable,
                ssn,
                winsize,
            )
        } else {
            build_uni_rx_ba_req(
                link.bss(),
                u16::from(link.peer()),
                link.omac(),
                tid,
                amsdu,
                enable,
                ssn,
                winsize,
            )
        }
        .ok_or(Error::Bounds)?;
        Ok(MloMessage {
            command: MloCommand::StaUpdate,
            body,
        })
    }
}

#[cfg(any(test, feature = "builtin"))]
#[path = "mlo_tests.rs"]
mod tests;

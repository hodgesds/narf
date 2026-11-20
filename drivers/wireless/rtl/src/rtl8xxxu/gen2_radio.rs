// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained gen2 radio owner shared by RTL8192EU and RTL8723BU stations.
//!
//! Linux `rtl8xxxu/core.c`: `rtl8xxxu_start` (`enable_rf`, RX URBs, RX
//! filter maps, IGI), `rtl8xxxu_add_interface`/`rtl8xxxu_set_bssid`,
//! `rtl8xxxu_rx_complete` → `rtl8xxxu_parse_rxdesc24` (MPDUs and gen2 C2H),
//! `rtl8xxxu_c2hcmd_callback` (RA reports, 8723B BT info),
//! `rtl8xxxu_bss_info_changed` ASSOC (`ra_connect_8192e`), the 2 s
//! `rtl8xxxu_ra_iter` watchdog and `rtl8xxxu_stop` (`disable_rf`). The
//! admitted signed permission (`N92P`/`N8BP`) is the only channel/rate
//! authority. Other channels are reached only with
//! a grant minted from the same signed record and authenticated domain
//! (`Authority::grant`): on a receiving unbound radio through a live
//! retune (`tune_8192e`/`tune_8723b` TX power + channel on the running
//! radio, Linux `rtl8xxxu_config`); on a stopped radio through a cold
//! `retune` (`rtl8xxxu_stop`, the chip power-off and a fresh
//! `rtl8xxxu_init_device` lifecycle, then `rtl8xxxu_start` on the new
//! channel). A 40 MHz operating channel is
//! reached only with a wide grant minted from the same record and domain
//! (`Authority::grant_wide`) and activated by `Radio::widen` after a
//! Forty negotiation; the initial grant never widens itself. QoS DATA needs the programmed
//! EDCA rows; HT20 MCS reception, firmware-RA HT masks and A-MPDU fields
//! need a negotiated HT association (`associate(.., ht = true)`) whose
//! local capability is `ht_local` (the signed admitted MCS set).
//! The HT40 variant lives in `ht40_capability`: it adds
//! SUP_WIDTH_20_40, SGI_40 and MCS32 (RX-only), and is offered only to
//! a station holding a wide grant.
use super::{
    btcoex::Coex,
    firmware_transport::{ControlIo, Error as ControlError, Owner as Firmware, Stage},
    packet_codec::{Kind, Mpdu},
    packet_transport::{self, Delivered, Io as PacketIo, Owner as Packets},
    rate_adaptation::Rssi,
    regs::ChipFamily,
    rtl8192e_packet::{self, C2h, Record, TxControl},
    rtl8192e_ra::{Peer, Ra},
};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use narf_wireless::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Control(ControlError),
    Packet(packet_transport::Error),
    State,
    Profile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Fresh or restarted owner at `RadioReady`; `start` is permitted.
    Prepared,
    Receiving,
    Stopped,
    Parked,
    Failed,
}

/// The chip's signed admission for one operating channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    Rtl8192e(super::rtl8192e_policy::Permission),
    Rtl8723b(super::rtl8723b_policy::Permission),
}
impl Grant {
    pub fn primary(&self) -> u8 {
        match self {
            Self::Rtl8192e(p) => p.primary(),
            Self::Rtl8723b(p) => p.primary(),
        }
    }
    /// The admitted `DESC_RATE` mask `Ra::new` takes.
    pub fn admitted(&self) -> u32 {
        match self {
            Self::Rtl8192e(p) => p.admitted(),
            Self::Rtl8723b(p) => p.admitted(),
        }
    }
    /// The operating width this grant qualifies: `Ht20` for the initial
    /// grant, `Ht40Above`/`Ht40Below` for a wide grant.
    pub fn width(&self) -> super::rtl8192e_radio::Width {
        match self {
            Self::Rtl8192e(p) => p.width(),
            Self::Rtl8723b(p) => p.width(),
        }
    }
    fn chip(&self) -> ChipFamily {
        match self {
            Self::Rtl8192e(_) => ChipFamily::Rtl8192eu,
            Self::Rtl8723b(_) => ChipFamily::Rtl8723bu,
        }
    }
}

/// The admitted signed record and authenticated regulatory domain, the only
/// source of further channel grants. Each `grant` re-invokes the record's
/// current firmware capability and intersects that channel's occupied
/// 20 MHz band with every rule (`Calibration::permission`); a missing
/// measured row or unsupported rule flag refuses the channel.
pub enum Authority {
    Rtl8192e {
        record: super::rtl8192e_policy::Calibration,
        domain: narf_wireless::reg::RegulatoryDomain,
    },
    Rtl8723b {
        record: super::rtl8723b_policy::Calibration,
        domain: narf_wireless::reg::RegulatoryDomain,
    },
}
impl core::fmt::Debug for Authority {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rtl8192e { record, .. } => record.fmt(f),
            Self::Rtl8723b { record, .. } => record.fmt(f),
        }
    }
}
impl Authority {
    pub fn from_8192e(admitted: super::rtl8192e_admission::Admitted) -> (Self, Grant) {
        let grant = Grant::Rtl8192e(admitted.permission);
        (
            Self::Rtl8192e {
                record: admitted.record,
                domain: admitted.domain,
            },
            grant,
        )
    }
    pub fn from_8723b(admitted: super::rtl8723b_admission::Admitted) -> (Self, Grant) {
        let grant = Grant::Rtl8723b(admitted.permission);
        (
            Self::Rtl8723b {
                record: admitted.record,
                domain: admitted.domain,
            },
            grant,
        )
    }
    /// The legacy 20 MHz grant for `primary` (the width the initial
    /// admission uses), or `Profile`.
    pub fn grant(&self, primary: u8) -> Result<Grant, Error> {
        match self {
            Self::Rtl8192e { record, domain } => record
                .permission(domain, primary, super::rtl8192e_admission::INITIAL_WIDTH)
                .map(Grant::Rtl8192e)
                .map_err(|_| Error::Profile),
            Self::Rtl8723b { record, domain } => record
                .permission(domain, primary, super::rtl8723b_admission::INITIAL_WIDTH)
                .map(Grant::Rtl8723b)
                .map_err(|_| Error::Profile),
        }
    }
    /// A 40 MHz grant for `primary` at `width` (secondary above or below),
    /// minted from the same signed record and domain: the record must
    /// carry a measured row for that primary/width and the domain must
    /// allow the full 40 MHz span. Refusal leaves the caller at 20 MHz;
    /// it is never a fallback to a narrower grant.
    pub fn grant_wide(
        &self,
        primary: u8,
        width: super::rtl8192e_radio::Width,
    ) -> Result<Grant, Error> {
        match self {
            Self::Rtl8192e { record, domain } => record
                .permission(domain, primary, width)
                .map(Grant::Rtl8192e)
                .map_err(|_| Error::Profile),
            Self::Rtl8723b { record, domain } => record
                .permission(domain, primary, width)
                .map(Grant::Rtl8723b)
                .map_err(|_| Error::Profile),
        }
    }
    /// Channels 1..=13 this record and domain currently grant.
    pub fn channels(&self) -> Vec<u8> {
        (1..=13).filter(|c| self.grant(*c).is_ok()).collect()
    }
}

/// `RTL8XXXU_RA_WATCHDOG` (`schedule_delayed_work(&priv->ra_watchdog, 2 * HZ)`).
pub const WATCHDOG_MS: u64 = 2000;
/// Bound on queued `C2H_8723B_BT_INFO` records awaiting the async path.
const BT_QUEUE: usize = 8;

const REG_TXPAUSE: u16 = 0x522;
const REG_ACM_HW_CTRL: u16 = 0x5c0;
const REG_RXFLTMAP0: u16 = 0x6a0;
/// Control-frame RX filter map. Written `0xffff` at `start` (the rtw88
/// retained value after mac_init + MAC table, same Realtek filter block):
/// BlockAckReq reaches the host, where only peer-bound BARs advance a
/// recipient session and every other control frame is dropped by the
/// station gate. No narrower PS-Poll|BAR value is groundable in-tree —
/// no RXFLTMAP1 subtype-bit table exists for rtl8xxxu — so the retained
/// all-control value is used rather than a fabricated bit.
const REG_RXFLTMAP1: u16 = 0x6a2;
const REG_RXFLTMAP2: u16 = 0x6a4;
const REG_OFDM0_XA_AGC_CORE1: u16 = 0xc50;
const REG_MSR: u16 = 0x102;
const REG_FWHW_TXQ_CTRL: u16 = 0x420;
const REG_TBTT_PROHIBIT: u16 = 0x540;
const REG_SLOT: u16 = 0x51b;
const REG_BEACON_CTRL: u16 = 0x550;
const REG_MACID: u16 = 0x610;
const REG_BSSID: u16 = 0x618;
const REG_AGGLEN_LMT: u16 = 0x458;
const REG_AMPDU_MIN_SPACE: u16 = 0x45c;
/// `DESC_RATE_MCS0`.
const MCS0: u8 = 12;
const BEACON_ATIM: u8 = 1 << 0;
const BEACON_FUNCTION_ENABLE: u8 = 1 << 3;
const BEACON_DISABLE_TSF_UPDATE: u8 = 1 << 4;
const MSR_LINKTYPE_STATION: u8 = 2;

/// A gen2 rxdesc24 MPDU admitted by `admit` in the shared
/// management/security frame type. No rxdesc16 word or HT40 seal is
/// carried (`Mpdu::admitted` is never the gen2 gate; `station_admitted`
/// is); `ba` carries the descriptor's A-MPDU (`paggr`) bit, which `admit`
/// passed only on a TID with an accepted recipient session.
pub(super) fn mpdu(frame: rtl8192e_packet::Frame) -> Mpdu {
    Mpdu {
        ht: frame.ht(),
        bytes: frame.bytes,
        phy: frame.phy,
        rate: frame.rate,
        bandwidth40: frame.bandwidth40,
        tid: frame.tid,
        decrypted: frame.decrypted,
        timestamp: frame.timestamp,
        native: None,
        wide: None,
        ba: frame.paggr,
    }
}

/// Gen2 station RX admission of one rxdesc24 MPDU (`rtl8xxxu_parse_rxdesc24`
/// facts, checked before any crypto): legacy 20 MHz plaintext always; with
/// a negotiated HT association (`ht`) also HT MCS within the advertised
/// RX streams at 20 MHz, or at 40 MHz once `ht40` (a widened Forty
/// association) is active (`Frame::admitted(ht, ht40, ba)`), A-MPDU
/// members only on a TID in `rx_ba` (accepted recipient sessions), and a
/// standalone A-MSDU whose descriptor and QoS-header A-MSDU bits agree,
/// never inside an A-MPDU (the ADDBA response clears A-MSDU permission:
/// rtl8xxxu lacks `SUPPORTS_AMSDU_IN_AMPDU`).
pub(super) fn admit(
    frame: &rtl8192e_packet::Frame,
    ht: bool,
    ht40: bool,
    rx_ba: u8,
    streams: u8,
) -> bool {
    if frame.ht() && (!ht || frame.rate >= MCS0 + 8 * streams.clamp(1, 2)) {
        return false;
    }
    let ba = ht && frame.qos && frame.tid < 8 && rx_ba & (1 << frame.tid) != 0;
    if !frame.amsdu {
        return frame.admitted(ht, ht40, ba);
    }
    let b = &frame.bytes;
    ht && frame.ht()
        && frame.qos
        && !frame.paggr
        && !frame.decrypted
        && !frame.more_frag
        && !frame.ldpc
        && !frame.stbc
        && (!frame.bandwidth40 || ht40)
        && b.len() >= 26
        && b[0] == 0x88
        && b[1] & 4 == 0
        && b[22] & 15 == 0
        && b[24] & 0x80 != 0
        && b[24] & 0x70 == 0
        && b[24] & 15 == frame.tid
        && b[25] == 0
}

/// The station-level gate for a gen2 `Mpdu` (descriptor facts already
/// checked by `admit`): plaintext, legacy rates, or HT MCS0..15 only
/// under a negotiated HT association, at 20 MHz or at 40 MHz once `ht40`
/// (a widened Forty association) is active.
pub(super) fn station_admitted(frame: &Mpdu, ht: bool, ht40: bool) -> bool {
    !frame.decrypted
        && (!frame.bandwidth40 || ht40)
        && frame.native.is_none()
        && frame.wide.is_none()
        && if frame.ht {
            ht && (MCS0..MCS0 + 16).contains(&frame.rate)
        } else {
            frame.rate < MCS0 && !frame.ba
        }
}

/// `rtl8xxxu_probe` HT capability (core.c `sband->ht_cap`) for HT20:
/// `IEEE80211_HT_MAX_AMPDU_64K` (3), `IEEE80211_HT_MPDU_DENSITY_16` (7),
/// `IEEE80211_HT_CAP_SGI_20`, `rx_mask[0] = 0xff` and, for a second path,
/// `rx_mask[1] = 0xff`, `IEEE80211_HT_MCS_TX_DEFINED`. Two streams require a
/// 2T board whose signed record admits MCS8..15 (a 1T2R RTL8191EU or a 2T
/// record without 2SS rows advertises one stream). TX selection is the
/// signed admitted MCS set; a record admitting no MCS keeps the legacy
/// station. Without a wide grant the station advertises HT20 only: no
/// SUP_WIDTH_20_40, no SGI_40, no MCS32 (`rx_mask[4]`, an HT40-only
/// duplicate); see `ht40_capability` for the granted variant.
pub(super) fn ht_local(admitted: u32, tx_paths: u8) -> Option<LocalPhy> {
    LocalPhy::ht20(ht_capability(admitted, tx_paths)?).ok()
}

/// `rtl8xxxu_probe` HT capability (core.c `sband->ht_cap`) for HT40:
/// the HT20 capability plus `SUP_WIDTH_20_40`, `SGI_40` in both
/// directions and MCS32 (`rx_mask[4]` bit 0, the 40 MHz duplicate,
/// RX-only: the TX mask and TX selection never carry it, since the
/// station never transmits the duplicate mode). Only a station holding
/// a wide grant for its primary offers this; the grant, not the
/// capability computation, is the authority.
pub(super) fn ht40_capability(admitted: u32, tx_paths: u8) -> Option<LocalHt> {
    let one = (admitted >> 12) as u8;
    let two = (admitted >> 20) as u8;
    let two_ss = tx_paths == 2 && two != 0;
    if one == 0 && !two_ss {
        return None;
    }
    let mut rx = [0u8; 10];
    rx[0] = 0xff;
    rx[1] = if two_ss { 0xff } else { 0 };
    rx[4] = 1;
    let mut tx = [0u8; 10];
    tx[0] = 0xff;
    tx[1] = if two_ss { 0xff } else { 0 };
    let mut selection = [0u8; 10];
    selection[0] = one;
    selection[1] = if two_ss { two } else { 0 };
    let gi = HtGi {
        rx20: true,
        tx20: true,
        rx40: true,
        tx40: true,
    };
    LocalHt::new(rx, tx, HtWidth::TwentyForty, gi, 3, 7)
        .ok()?
        .with_tx_selection(selection)
        .ok()
}

/// The HT40 local capability, offered only to a station holding a wide
/// grant for its primary.
pub(super) fn ht40_local(admitted: u32, tx_paths: u8) -> Option<LocalPhy> {
    LocalPhy::ht40(ht40_capability(admitted, tx_paths)?).ok()
}
pub(super) fn ht_capability(admitted: u32, tx_paths: u8) -> Option<LocalHt> {
    let one = (admitted >> 12) as u8;
    let two = (admitted >> 20) as u8;
    let two_ss = tx_paths == 2 && two != 0;
    if one == 0 && !two_ss {
        return None;
    }
    let mut mask = [0u8; 10];
    mask[0] = 0xff;
    mask[1] = if two_ss { 0xff } else { 0 };
    let mut selection = [0u8; 10];
    selection[0] = one;
    selection[1] = if two_ss { two } else { 0 };
    let gi = HtGi {
        rx20: true,
        tx20: true,
        rx40: false,
        tx40: false,
    };
    LocalHt::new(mask, mask, HtWidth::Twenty, gi, 3, 7)
        .ok()?
        .with_tx_selection(selection)
        .ok()
}

/// `rtl8xxxu_rx_addr_match` for the EWMA: bound-BSS frames to us or beacons.
pub(super) fn rssi_match(bytes: &[u8], local: [u8; 6], peer: [u8; 6]) -> bool {
    bytes.len() >= 24 && bytes[10..16] == peer && (bytes[4..10] == local || bytes[0] == 0x80)
}

/// What one parsed C2H record asks of the station (`rtl8xxxu_c2hcmd_callback`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum C2hRoute {
    /// `rtl8xxxu_update_ra_report` (`Ra::report`).
    Ra(rtl8192e_packet::RaReport),
    /// `C2H_8723B_BT_INFO` for `Owner::c2h_bt_8723b` (RTL8723BU only).
    Bt(C2h),
    Ignore,
}
pub(super) fn route_c2h(chip: ChipFamily, record: C2h) -> C2hRoute {
    match &record {
        C2h::RaReport(report) => C2hRoute::Ra(*report),
        C2h::Other { id, payload, .. }
            if chip == ChipFamily::Rtl8723bu && super::btcoex::bt_info(*id, payload).is_some() =>
        {
            C2hRoute::Bt(record)
        }
        C2h::Other { .. } => C2hRoute::Ignore,
    }
}

struct Attempt<C: ControlIo> {
    firmware: Arc<Firmware<C>>,
    armed: bool,
}
impl<C: ControlIo> Drop for Attempt<C> {
    fn drop(&mut self) {
        if self.armed {
            self.firmware.runtime_failed(ControlError::Cancelled);
        }
    }
}

pub struct Radio<C: ControlIo, B: PacketIo> {
    firmware: Arc<Firmware<C>>,
    packets: Packets<B>,
    grant: Grant,
    phase: Phase,
    claimed: bool,
    local: [u8; 6],
    tx_paths: u8,
    /// `priv->cck_agc_report_type` (RTL8192EU signal decode).
    cck_agc_report_type: bool,
    peer: Option<[u8; 6]>,
    /// `priv->ra_info` for the port-0 AP entry while associated.
    ra: Option<Ra>,
    rssi: Rssi,
    next_watchdog: u64,
    /// `priv->bt_coex` (RTL8723BU only).
    coex: Option<Coex>,
    bt: VecDeque<C2h>,
    /// Physical receive generation: advanced by every completed retune,
    /// cold or live, so an observation names the channel epoch that
    /// copied it (a live retune keeps the transfer posted but the
    /// channel — and therefore every observation's meaning — changes).
    generation: u64,
    /// Negotiated HT20 association: HT RX admission and HT TX fields.
    ht: bool,
    /// TIDs with an accepted recipient BA session (A-MPDU RX admission).
    rx_ba: u8,
    /// Offered-but-unactivated 40 MHz grant for the current primary
    /// (minted at connect when the BSS operates at 40 MHz and the
    /// signed record admits it; activated by `widen` only on a Forty
    /// negotiation, retained across stops for `rejoin`, cleared by
    /// `offer_wide(None)` at the next connect).
    wide: Option<Grant>,
    /// `widen` has programmed the 40 MHz channel and no stop has
    /// since cleared it: RX admission and firmware RA use 40 MHz.
    wide_active: bool,
}
impl<C: ControlIo, B: PacketIo> core::fmt::Debug for Radio<C, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8xxxuGen2Radio")
            .field("chip", &self.grant.chip())
            .field("phase", &self.phase)
            .field("channel", &self.grant.primary())
            .finish_non_exhaustive()
    }
}

/// How `retune` moves an unbound radio to a new grant. Pure dispatch,
/// pinned by `gen2_radio_tests`: a receiving radio retunes live, a
/// stopped radio pays the cold lifecycle, a never-started radio only
/// relabels; a bound radio (peer or RA state) or a failed/parked one
/// refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RetunePath {
    Live,
    Cold,
    Relabel,
}
/// `retune` dispatch, as a free function so pure tests need no firmware
/// fixture: the live/cold/relabel decision depends only on the phase
/// and the bound flag.
pub(super) fn retune_path(phase: Phase, bound: bool) -> Option<RetunePath> {
    if bound {
        return None;
    }
    match phase {
        Phase::Receiving => Some(RetunePath::Live),
        Phase::Stopped => Some(RetunePath::Cold),
        Phase::Prepared => Some(RetunePath::Relabel),
        _ => None,
    }
}

impl<C: ControlIo, B: PacketIo> Radio<C, B> {
    /// The owner must be at `RadioReady` for the grant's chip with its
    /// factory, queue map and post-calibration state retained.
    pub fn new(firmware: Arc<Firmware<C>>, io: B, grant: Grant) -> Result<Self, Error> {
        if firmware.status().stage != Stage::RadioReady || firmware.chip() != grant.chip() {
            return Err(Error::State);
        }
        let endpoints = firmware.endpoints().ok_or(Error::State)?;
        let (local, tx_paths, cck_agc_report_type, queues, coex) = match grant {
            Grant::Rtl8192e(_) => {
                let factory = firmware.factory_8192e().ok_or(Error::State)?;
                let radio = firmware.radio_8192e().ok_or(Error::State)?;
                (
                    factory.mac,
                    factory.identity.tx_paths,
                    radio.post.cck_agc_report_type,
                    firmware.queues_8192e().ok_or(Error::State)?,
                    None,
                )
            }
            Grant::Rtl8723b(_) => {
                let factory = firmware.factory_8723b().ok_or(Error::State)?;
                firmware.radio_8723b().ok_or(Error::State)?;
                (
                    factory.mac,
                    1,
                    false,
                    firmware.queues_8723b().ok_or(Error::State)?,
                    Some(Coex::default()),
                )
            }
        };
        if local == [0; 6] || local[0] & 1 != 0 {
            return Err(Error::Profile);
        }
        let packets =
            Packets::new_8192e(io, endpoints, queues, grant.primary()).map_err(Error::Packet)?;
        Ok(Self {
            firmware,
            packets,
            grant,
            phase: Phase::Prepared,
            claimed: false,
            local,
            tx_paths,
            cck_agc_report_type,
            peer: None,
            ra: None,
            rssi: Rssi::default(),
            next_watchdog: 0,
            coex,
            bt: VecDeque::new(),
            generation: 1,
            ht: false,
            rx_ba: 0,
            wide: None,
            wide_active: false,
        })
    }
    pub fn phase(&self) -> Phase {
        if self.firmware.status().stage == Stage::Failed {
            Phase::Failed
        } else {
            self.phase
        }
    }
    pub fn chip(&self) -> ChipFamily {
        self.grant.chip()
    }
    pub fn local(&self) -> [u8; 6] {
        self.local
    }
    pub fn channel(&self) -> u8 {
        self.grant.primary()
    }
    pub fn tx_paths(&self) -> u8 {
        self.tx_paths
    }
    pub fn grant(&self) -> Grant {
        self.grant
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// The local HT capability this board's signed record supports:
    /// HT40 when a wide grant is held for the current primary, else
    /// HT20.
    pub(super) fn ht_local(&self) -> Option<LocalPhy> {
        if self.wide.is_some() {
            ht40_local(self.grant.admitted(), self.tx_paths)
        } else {
            ht_local(self.grant.admitted(), self.tx_paths)
        }
    }
    /// Offer a 40 MHz grant for the current primary, or clear any
    /// offered grant. The grant must be for this radio's chip and
    /// primary at a Forty width; anything else is a programming error
    /// and refuses, leaving the previous offer untouched. Offering
    /// clears any prior activation: a new offer must be widened anew.
    pub(super) fn offer_wide(&mut self, wide: Option<Grant>) -> Result<(), Error> {
        if let Some(grant) = &wide {
            if grant.chip() != self.chip()
                || grant.primary() != self.grant.primary()
                || !matches!(
                    grant.width(),
                    super::rtl8192e_radio::Width::Ht40Above
                        | super::rtl8192e_radio::Width::Ht40Below
                )
            {
                return Err(Error::State);
            }
        }
        self.wide = wide;
        self.wide_active = false;
        Ok(())
    }
    /// The offered wide grant's width, if one is held.
    pub(super) fn wide_width(&self) -> Option<super::rtl8192e_radio::Width> {
        self.wide.as_ref().map(Grant::width)
    }
    /// A `widen` is in effect: RX admission and firmware RA use 40 MHz.
    pub(super) fn wide_active(&self) -> bool {
        self.wide_active
    }
    /// Program the offered 40 MHz channel (`set_tx_power` with the
    /// wide flag, then `config_channel` at the wide width) on a
    /// receiving, unassociated radio, and mark 40 MHz active. The
    /// initial grant stays the admission anchor; only the programmed
    /// channel and the active flag change. Permission refusal (a
    /// mismatched record or domain) fails before any transfer; a
    /// mid-tune device error fails the radio terminally through the
    /// attempt guard, as every other radio operation.
    pub(super) async fn widen(&mut self) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving || self.peer.is_none() || self.ra.is_some() {
            return Err(Error::State);
        }
        let Some(wide) = self.wide else {
            return Err(Error::State);
        };
        if wide.primary() != self.grant.primary() {
            return Err(Error::State);
        }
        match &wide {
            Grant::Rtl8192e(permission) => {
                self.firmware
                    .tune_8192e(permission, wide.primary(), wide.width())
                    .await
                    .map_err(Error::Control)?;
            }
            Grant::Rtl8723b(permission) => {
                self.firmware
                    .tune_8723b(permission, wide.primary(), wide.width())
                    .await
                    .map_err(Error::Control)?;
            }
        }
        self.wide_active = true;
        Ok(())
    }
    /// The HT Capabilities IE body (26 bytes) this board's signed record
    /// supports, for active-scan probes (gen2 F10): the same admitted MCS
    /// set the association offers, not the probe constructor's SISO body.
    /// `None` on a legacy-only board, whose probes carry no HT caps.
    pub(super) fn ht_caps(&self) -> Option<[u8; 26]> {
        ht_capability(self.grant.admitted(), self.tx_paths).map(|ht| ht.capability_body())
    }
    /// Advertised RX spatial streams (`rx_mask[1]` present).
    fn streams(&self) -> u8 {
        if self.tx_paths == 2 && self.grant.admitted() >> 20 & 0xff != 0 {
            2
        } else {
            1
        }
    }
    pub(super) fn bound(&self) -> bool {
        self.peer.is_some()
    }
    pub(super) fn ra(&self) -> Option<&Ra> {
        self.ra.as_ref()
    }
    pub(super) fn coex(&self) -> Option<&Coex> {
        self.coex.as_ref()
    }
    pub(super) fn associated(&self) -> bool {
        self.ra.is_some()
    }
    fn current(&self) -> Result<(), Error> {
        self.firmware
            .executable()
            .ok_or(Error::State)?
            .invoke(|| ())
            .map_err(Error::Control)
    }
    fn attempt(&self) -> Attempt<C> {
        Attempt {
            firmware: self.firmware.clone(),
            armed: true,
        }
    }
    pub(super) fn fail_terminal(&mut self) {
        self.ra = None;
        self.bt.clear();
        self.phase = Phase::Failed;
        self.packets.fail();
        self.firmware.runtime_failed(ControlError::RuntimeState);
    }
    /// `rtl8xxxu_start`: `enable_rf` plus the admitted initial channel
    /// (`start_8192e`/`start_8723b`), the persistent RX transfer, then
    /// `REG_RXFLTMAP2`/`REG_RXFLTMAP1`/`REG_RXFLTMAP0 = 0xffff` and IGI
    /// `0x1e`.
    pub async fn start(&mut self) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Prepared || self.firmware.status().stage != Stage::RadioReady {
            return Err(Error::State);
        }
        let mut attempt = self.attempt();
        let result = async {
            let admitted = match &self.grant {
                Grant::Rtl8192e(p) => self.firmware.start_8192e(p).await,
                Grant::Rtl8723b(p) => self.firmware.start_8723b(p).await,
            }
            .map_err(Error::Control)?;
            if admitted != self.grant.admitted() {
                return Err(Error::Profile);
            }
            if !self.claimed {
                self.firmware.claim_receive().map_err(Error::Control)?;
                self.claimed = true;
            }
            self.packets.start().map_err(Error::Packet)?;
            for reg in [REG_RXFLTMAP2, REG_RXFLTMAP1, REG_RXFLTMAP0] {
                self.firmware
                    .write16(reg, 0xffff)
                    .await
                    .map_err(Error::Control)?;
            }
            let agc = self
                .firmware
                .read32(REG_OFDM0_XA_AGC_CORE1)
                .await
                .map_err(Error::Control)?;
            self.firmware
                .write32(REG_OFDM0_XA_AGC_CORE1, (agc & !0x7f) | 0x1e)
                .await
                .map_err(Error::Control)
        }
        .await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.phase = Phase::Receiving;
                self.firmware.receiving();
                Ok(())
            }
            Err(error) => {
                self.fail_terminal();
                Err(error)
            }
        }
    }
    /// One completed bulk-IN transfer: admitted legacy plaintext MPDUs, the
    /// bound-BSS RSSI EWMA, RA reports folded into `priv->ra_report` and
    /// BT-info records queued for the async coexistence path.
    pub fn poll(&mut self) -> Result<Option<Vec<Mpdu>>, Error> {
        self.current()?;
        if self.phase() != Phase::Receiving {
            return Err(Error::State);
        }
        let records = match self.packets.poll_receive_8192e() {
            Ok(None) | Err(packet_transport::Error::Halted) => return Ok(None),
            Ok(Some(records)) => records,
            Err(error) => {
                self.fail_terminal();
                return Err(Error::Packet(error));
            }
        };
        let chip = self.chip();
        let streams = self.streams();
        let mut frames = Vec::new();
        for record in records {
            match record {
                Record::Frame(frame) => {
                    if let Some(peer) = self.peer {
                        if rssi_match(&frame.bytes, self.local, peer) {
                            let signal = match chip {
                                ChipFamily::Rtl8723bu => {
                                    super::rtl8723b_packet::signal(&frame.phy, frame.rate)
                                }
                                _ => rtl8192e_packet::signal(
                                    &frame.phy,
                                    frame.rate,
                                    self.cck_agc_report_type,
                                ),
                            };
                            self.rssi.add(signal.unwrap_or(0));
                        }
                    }
                    if admit(&frame, self.ht, self.wide_active, self.rx_ba, streams) {
                        frames.push(mpdu(frame));
                    }
                }
                Record::C2h(c2h) => match route_c2h(chip, c2h) {
                    C2hRoute::Ra(report) => {
                        if let Some(ra) = &mut self.ra {
                            ra.report(&report);
                        }
                    }
                    C2hRoute::Bt(record) => {
                        if self.bt.len() >= BT_QUEUE {
                            self.bt.pop_front();
                        }
                        self.bt.push_back(record);
                    }
                    C2hRoute::Ignore => {}
                },
            }
        }
        Ok(Some(frames))
    }
    pub fn recovery_pending(&self) -> bool {
        self.packets.is_halted()
    }
    pub(super) async fn recover(&mut self) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving {
            return Err(Error::State);
        }
        let mut attempt = self.attempt();
        let result = self.packets.recover().await;
        attempt.armed = false;
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                self.fail_terminal();
                Err(Error::Packet(error))
            }
        }
    }
    fn control(&self) -> TxControl {
        // Long preamble, no RTS/CTS protection: this station never adopts
        // `bss_conf.use_short_preamble`/`use_cts_prot` from the ERP element.
        TxControl {
            macid: 0,
            ..TxControl::default()
        }
    }
    fn submit(&mut self, kind: Kind, frame: &[u8]) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving {
            return Err(Error::State);
        }
        let control = self.control();
        self.packets
            .submit_8192e(kind, frame, control)
            .map_err(|error| {
                if self.packets.is_failed() {
                    self.fail_terminal();
                }
                Error::Packet(error)
            })
    }
    pub fn submit_management(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.submit(Kind::Management, frame)
    }
    pub fn submit_data(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.submit(Kind::Data, frame)
    }
    pub fn poll_delivery(&mut self) -> Result<Option<Delivered>, Error> {
        match self.packets.poll_transmit() {
            Ok(delivered) => Ok(delivered),
            Err(packet_transport::Error::Halted) => Ok(None),
            Err(error) => {
                self.fail_terminal();
                Err(Error::Packet(error))
            }
        }
    }
    /// `rtl8xxxu_add_interface(STATION, port 0)`: `rtl8xxxu_stop_tx_beacon`,
    /// `BEACON_ATIM | BEACON_FUNCTION_ENABLE | BEACON_DISABLE_TSF_UPDATE`,
    /// `rtl8xxxu_set_linktype(STATION)`, `rtl8xxxu_set_mac`; then
    /// `rtl8xxxu_set_bssid` and the `BSS_CHANGED_ERP_SLOT` slot time. TSF
    /// updates stay disabled until `ra_connect_8192e`'s association step
    /// (Linux re-enables them in `rtl8xxxu_sw_scan_complete`).
    pub async fn prepare_station(&mut self, peer: [u8; 6], short_slot: bool) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving
            || self.peer.is_some()
            || peer == [0; 6]
            || peer[0] & 1 != 0
            || peer == self.local
        {
            return Err(Error::State);
        }
        let mut attempt = self.attempt();
        let result = async {
            let f = &self.firmware;
            let txq = f.read8(REG_FWHW_TXQ_CTRL + 2).await? & !(1 << 6);
            f.write8(REG_FWHW_TXQ_CTRL + 2, txq).await?;
            f.write8(REG_TBTT_PROHIBIT + 1, 0x64).await?;
            let tbtt = f.read8(REG_TBTT_PROHIBIT + 2).await? & !1;
            f.write8(REG_TBTT_PROHIBIT + 2, tbtt).await?;
            let beacon = f.read8(REG_BEACON_CTRL).await?
                | BEACON_ATIM
                | BEACON_FUNCTION_ENABLE
                | BEACON_DISABLE_TSF_UPDATE;
            f.write8(REG_BEACON_CTRL, beacon).await?;
            let msr = (f.read8(REG_MSR).await? & 0x0c) | MSR_LINKTYPE_STATION;
            f.write8(REG_MSR, msr).await?;
            for (i, byte) in self.local.iter().enumerate() {
                f.write8(REG_MACID + i as u16, *byte).await?;
            }
            for (i, byte) in peer.iter().enumerate() {
                f.write8(REG_BSSID + i as u16, *byte).await?;
            }
            f.write8(REG_SLOT, if short_slot { 9 } else { 20 }).await?;
            let beacon = f.read8(REG_BEACON_CTRL).await? & !BEACON_DISABLE_TSF_UPDATE;
            f.write8(REG_BEACON_CTRL, beacon).await
        }
        .await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.peer = Some(peer);
                Ok(())
            }
            Err(error) => {
                self.fail_terminal();
                Err(Error::Control(error))
            }
        }
    }
    /// `BSS_CHANGED_ASSOC` with association: `Ra::new` over the admitted mask
    /// (refused, never narrowed), then `ra_connect_8192e` (both gen2 chips
    /// share `rtl8xxxu_gen2_update_rate_mask`/`gen2_report_connect`). An HT
    /// peer (`peer.ht`) needs the programmed EDCA rows (HT implies WMM) and a
    /// local HT capability; it then admits HT RX and HT TX fields.
    pub async fn associate(&mut self, aid: u16, peer: Peer, now: u64) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving || self.peer.is_none() || self.ra.is_some() {
            return Err(Error::State);
        }
        if peer.ht && (!self.packets.qos || self.ht_local().is_none()) {
            return Err(Error::Profile);
        }
        let mut ra = Ra::new(peer, self.grant.admitted(), self.tx_paths, self.wide_active)
            .map_err(|_| Error::Profile)?;
        let mut attempt = self.attempt();
        let result = self.firmware.ra_connect_8192e(&mut ra, aid).await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.ra = Some(ra);
                self.ht = peer.ht;
                self.packets.ht = peer.ht;
                self.rssi = Rssi::default();
                self.next_watchdog = now.saturating_add(WATCHDOG_MS);
                Ok(())
            }
            Err(error) => {
                self.fail_terminal();
                Err(Error::Control(error))
            }
        }
    }
    pub(super) fn maintenance_pending(&self) -> bool {
        self.recovery_pending() || !self.bt.is_empty()
    }
    /// `rtl8xxxu_watchdog_callback` → `rtl8xxxu_ra_iter` while associated:
    /// `ra_watchdog_8192e`/`ra_watchdog_8723b` with `-ewma_rssi_read`. The
    /// device's watchdog work calls it every `WATCHDOG_MS`; the period gate
    /// makes any extra call within a period a no-op. Failure is terminal.
    pub async fn ra_watchdog(&mut self, now: u64) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving || self.ra.is_none() || now < self.next_watchdog {
            return Ok(());
        }
        let mut attempt = self.attempt();
        let signal = self.rssi.signal();
        let result = match (&mut self.ra, &self.grant) {
            (Some(ra), Grant::Rtl8192e(_)) => self.firmware.ra_watchdog_8192e(ra, signal).await,
            (Some(ra), Grant::Rtl8723b(_)) => self.firmware.ra_watchdog_8723b(ra, signal).await,
            (None, _) => Ok(()),
        };
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.next_watchdog = now.saturating_add(WATCHDOG_MS);
                Ok(())
            }
            Err(error) => {
                self.fail_terminal();
                Err(Error::Control(error))
            }
        }
    }
    /// The async half of `poll`: recovery and queued `C2H_8723B_BT_INFO`
    /// records through `c2h_bt_8723b` with `rtl8xxxu_is_assoc`.
    pub async fn maintain(&mut self) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving {
            return Err(Error::State);
        }
        if self.recovery_pending() {
            self.recover().await?;
        }
        let mut attempt = self.attempt();
        let result = async {
            let assoc = self.ra.is_some();
            while let Some(record) = self.bt.pop_front() {
                if let Some(coex) = &mut self.coex {
                    self.firmware.c2h_bt_8723b(coex, &record, assoc).await?;
                }
            }
            Ok(())
        }
        .await;
        attempt.armed = false;
        result.map_err(|error| {
            self.fail_terminal();
            Error::Control(error)
        })
    }
    /// Idle BT-info drain: the `rtl8xxxu_c2hcmd_callback` half of
    /// `maintain` for a radio with no station serviced — the scan/listen
    /// path, where `poll` queues `C2H_8723B_BT_INFO` records but no
    /// station `maintain` runs. `assoc` is the caller's association
    /// state, not `self.ra`: `false` for an unbound radio, `true` for a
    /// station's off-channel visit (Linux `rtl8xxxu_is_assoc` stays true
    /// through a scan, while NARF's `leave` takes `ra`, so the radio
    /// alone cannot answer it). No RA watchdog, no recovery: the caller
    /// owns those, exactly as `listen` already runs `maintain` for
    /// recovery before polling.
    pub async fn drain_bt(&mut self, assoc: bool) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving {
            return Err(Error::State);
        }
        let mut attempt = self.attempt();
        let result = async {
            while let Some(record) = self.bt.pop_front() {
                if let Some(coex) = &mut self.coex {
                    self.firmware.c2h_bt_8723b(coex, &record, assoc).await?;
                }
            }
            Ok(())
        }
        .await;
        attempt.armed = false;
        result.map_err(|error| {
            self.fail_terminal();
            Error::Control(error)
        })
    }
    /// `BSS_CHANGED_ASSOC` without association (`ra_disconnect_8192e`), then
    /// `rtl8xxxu_stop`: `REG_TXPAUSE = 0xff`, RX filter maps cleared, the
    /// host transfers retired, `REG_TXPAUSE = 0xff`, `disable_rf`.
    pub async fn stop(&mut self) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving {
            return Err(Error::State);
        }
        let mut attempt = self.attempt();
        let result = async {
            if self.ra.take().is_some() {
                self.firmware
                    .ra_disconnect_8192e()
                    .await
                    .map_err(Error::Control)?;
            }
            self.peer = None;
            self.bt.clear();
            self.ht = false;
            self.rx_ba = 0;
            self.wide_active = false;
            self.packets.ht = false;
            self.packets.ampdu = None;
            let f = &self.firmware;
            f.write8(REG_TXPAUSE, 0xff).await.map_err(Error::Control)?;
            for reg in [REG_RXFLTMAP0, REG_RXFLTMAP1, REG_RXFLTMAP2] {
                f.write16(reg, 0).await.map_err(Error::Control)?;
            }
            self.packets.stop().await.map_err(Error::Packet)?;
            let f = &self.firmware;
            f.write8(REG_TXPAUSE, 0xff).await.map_err(Error::Control)?;
            match self.grant {
                Grant::Rtl8192e(_) => super::rtl8192e_power::disable_rf(f).await,
                Grant::Rtl8723b(_) => super::rtl8723b_power::disable_rf(f).await,
            }
            .map_err(Error::Control)
        }
        .await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.phase = Phase::Stopped;
                self.firmware.receive_stopped();
                Ok(())
            }
            Err(error) => {
                self.fail_terminal();
                Err(error)
            }
        }
    }
    /// `rtl8192eu_power_off`/`rtl8723bu_power_off` of a stopped radio.
    pub async fn park(&mut self) -> Result<(), Error> {
        if self.phase() != Phase::Stopped {
            return Err(Error::State);
        }
        match self.firmware.park_stopped().await {
            Ok(()) => {
                self.phase = Phase::Parked;
                Ok(())
            }
            Err(error) => {
                self.phase = Phase::Failed;
                Err(Error::Control(error))
            }
        }
    }
    /// A fresh owner lifecycle after park: the full `rtl8xxxu_init_device`
    /// against the retained identity, back to `RadioReady`; `start` follows.
    pub async fn restart_parked(&mut self) -> Result<(), Error> {
        if self.phase() != Phase::Parked {
            return Err(Error::State);
        }
        match self.firmware.restart_parked().await {
            Ok(()) => {
                if self.firmware.status().stage != Stage::RadioReady {
                    self.fail_terminal();
                    return Err(Error::State);
                }
                self.coex = self.coex.map(|_| Coex::default());
                self.rssi = Rssi::default();
                self.generation = self.generation.saturating_add(1);
                self.phase = Phase::Prepared;
                Ok(())
            }
            Err(error) => {
                self.phase = Phase::Failed;
                Err(Error::Control(error))
            }
        }
    }
    /// Administrative IFF_DOWN park (mac80211 `drv_stop` → `rtl8xxxu_stop`,
    /// then the chip power-off) from any unbound phase. A radio at
    /// `RadioReady` that never started is started first, so its receive
    /// claim and the Linux stop sequence retire exactly as for a running
    /// radio (the owner parks only from `ReceiveStopped`). Parked is a no-op.
    pub(super) async fn park_idle(&mut self) -> Result<(), Error> {
        if self.phase() == Phase::Parked {
            return Ok(());
        }
        self.current()?;
        if self.peer.is_some() || self.ra.is_some() {
            return Err(Error::State);
        }
        if self.phase() == Phase::Prepared {
            self.start().await?;
        }
        if self.phase() == Phase::Receiving {
            self.stop().await?;
        }
        match self.phase() {
            Phase::Stopped => self.park().await,
            Phase::Parked => Ok(()),
            _ => Err(Error::State),
        }
    }
    /// Channel change of an unbound radio under a new grant from the same
    /// record and domain. The path follows `retune_path`:
    ///
    /// - Live (receiving): Linux `rtl8xxxu_config` — `tune_8192e`/
    ///   `tune_8723b` (TX power + channel) on the running radio. The RX
    ///   transfer stays posted, the RX filter maps and IGI stay
    ///   programmed, and no firmware lifecycle runs. No TX may be
    ///   outstanding (callers guarantee it: probe visits await delivery,
    ///   idle/set_config radios submit nothing); the packet channel
    ///   label moves with the grant, and the observation generation
    ///   advances, since a channel change redefines every observation
    ///   even though the transfer continues. The tune writes, the
    ///   relabel, the grant swap and the generation advance run without
    ///   an await between them, so no poll can tag a frame with a
    ///   half-moved channel.
    /// - Cold (stopped): `stop` already ran, so the chip power-off and a
    ///   fresh `rtl8xxxu_init_device` lifecycle, so no device-FIFO byte
    ///   from the old channel survives into the new stream; then the new
    ///   grant's channel label and `rtl8xxxu_start` when the radio was
    ///   receiving. This is also what the associated-scan return pays:
    ///   `leave` stops the radio, so `rejoin`'s retune stays cold until
    ///   a later lane makes leave itself live.
    /// - Relabel (never started): only the grant label moves.
    ///
    /// Any failure is terminal.
    pub async fn retune(&mut self, grant: Grant) -> Result<(), Error> {
        self.current()?;
        if grant.chip() != self.chip() {
            return Err(Error::State);
        }
        let bound = self.peer.is_some() || self.ra.is_some();
        match retune_path(self.phase(), bound) {
            Some(RetunePath::Live) => {
                if self.packets.transmit_pending() {
                    return Err(Error::State);
                }
                let admitted = match &grant {
                    Grant::Rtl8192e(p) => self.firmware.tune_8192e(p, p.primary(), p.width()).await,
                    Grant::Rtl8723b(p) => self.firmware.tune_8723b(p, p.primary(), p.width()).await,
                }
                .map_err(Error::Control)?;
                if admitted != grant.admitted() {
                    self.fail_terminal();
                    return Err(Error::Profile);
                }
                if let Err(error) = self.packets.retarget_live(grant.primary()) {
                    self.fail_terminal();
                    return Err(Error::Packet(error));
                }
                self.grant = grant;
                self.generation = self.generation.saturating_add(1);
                Ok(())
            }
            Some(RetunePath::Cold) => {
                // Entered only from Stopped (Receiving takes the live
                // path): the cold lifecycle, then receiving resumes.
                self.park().await?;
                self.restart_parked().await?;
                if let Err(error) = self.packets.retarget_stopped(grant.primary()) {
                    self.fail_terminal();
                    return Err(Error::Packet(error));
                }
                self.grant = grant;
                self.start().await?;
                Ok(())
            }
            Some(RetunePath::Relabel) => {
                self.grant = grant;
                Ok(())
            }
            None => Err(Error::State),
        }
    }
    /// Host BA facts, no device access: the HT peer's MPDU density with the
    /// operational originator TIDs (`priv->tid_tx_operational`) for the
    /// txdesc40 A-MPDU fields, and the recipient-session TIDs whose A-MPDU
    /// members `poll` admits. Both are empty without an HT association.
    pub(super) fn set_ba(&mut self, tx: Option<(u8, u8)>, rx: u8) {
        self.packets.ampdu = tx.filter(|_| self.ht);
        self.rx_ba = if self.ht { rx } else { 0 };
    }
    /// `rtl8xxxu_set_ampdu_factor` + `rtl8xxxu_set_ampdu_min_space`, issued
    /// by `rtl8xxxu_ampdu_action` TX_START (peer factor/density) and every
    /// TX_STOP (both 0): `REG_AGGLEN_LMT` 0x458..0x45b from
    /// `{0x41, 0xa8, 0x72, 0xb9}` clamped to `1 << (factor + 2)` (max 0xf),
    /// then the low three bits of `REG_AMPDU_MIN_SPACE` 0x45c. Each write
    /// has an exact readback; failure is terminal.
    pub(super) async fn configure_ampdu(&mut self, factor: u8, density: u8) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving || !self.ht || factor > 3 || density > 7 {
            return Err(Error::State);
        }
        let limit = (1u8 << (factor + 2)).min(0xf);
        let values = [0x41u8, 0xa8, 0x72, 0xb9].map(|mut v| {
            if v & 0xf0 > limit << 4 {
                v = (v & 0x0f) | limit << 4;
            }
            if v & 0x0f > limit {
                v = (v & 0xf0) | limit;
            }
            v
        });
        let mut attempt = self.attempt();
        let result = async {
            let f = &self.firmware;
            for (i, value) in values.into_iter().enumerate() {
                let reg = REG_AGGLEN_LMT + i as u16;
                f.write8(reg, value).await.map_err(Error::Control)?;
                if f.read8(reg).await.map_err(Error::Control)? != value {
                    return Err(Error::State);
                }
            }
            let space =
                (f.read8(REG_AMPDU_MIN_SPACE).await.map_err(Error::Control)? & 0xf8) | density;
            f.write8(REG_AMPDU_MIN_SPACE, space)
                .await
                .map_err(Error::Control)?;
            if f.read8(REG_AMPDU_MIN_SPACE).await.map_err(Error::Control)? != space {
                return Err(Error::State);
            }
            Ok(())
        }
        .await;
        attempt.armed = false;
        result.inspect_err(|_| self.fail_terminal())
    }
    /// `rtl8xxxu_conf_tx` for BE/BK/VI/VO (`REG_EDCA_*_PARAM` 0x508/0x50c/
    /// 0x504/0x500 with `rtl8xxxu_set_aifs` SIFS 10 (legacy 2.4 GHz; 16 for
    /// an HT peer, `WIRELESS_MODE_N_24G`) plus AIFSN slots, via
    /// `wmm_runtime::words_profile`), each with an exact
    /// readback, then `REG_ACM_HW_CTRL` mirroring each AC's ACM. Rows this
    /// profile cannot program (BE ACM, ECW/AIFSN geometry, 8-bit AIFS) are
    /// refused before any write. Only afterwards may QoS DATA (txdesc40 AC
    /// queue/pipe per `rtl8xxxu_queue_select`) be submitted.
    pub(super) async fn configure_edca(
        &mut self,
        p: narf_wireless::wmm::Parameters,
        short_slot: bool,
        ht: bool,
    ) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving || self.peer.is_none() {
            return Err(Error::State);
        }
        let values =
            super::wmm_runtime::words_profile(p, short_slot, ht).map_err(|_| Error::Profile)?;
        let mut attempt = self.attempt();
        let result = async {
            let f = &self.firmware;
            for (reg, value) in [0x508u16, 0x50c, 0x504, 0x500].into_iter().zip(values) {
                f.write32(reg, value).await.map_err(Error::Control)?;
                if f.read32(reg).await.map_err(Error::Control)? != value {
                    return Err(Error::State);
                }
            }
            let acm = (f.read8(REG_ACM_HW_CTRL).await.map_err(Error::Control)? & !0x0f)
                | super::wmm_runtime::acm_bits(p);
            f.write8(REG_ACM_HW_CTRL, acm)
                .await
                .map_err(Error::Control)?;
            if f.read8(REG_ACM_HW_CTRL).await.map_err(Error::Control)? != acm {
                return Err(Error::State);
            }
            Ok(())
        }
        .await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.packets.qos = true;
                Ok(())
            }
            Err(error) => {
                self.fail_terminal();
                Err(error)
            }
        }
    }
    /// The prepared broadcast Probe Request on the management pipe of an
    /// unbound receiving radio (`probe_runtime::Prepared` is the only
    /// broadcast management constructor; ordinary submission stays unicast).
    /// An HT-capable board's probe carries its HT caps (`ht_caps`); a
    /// legacy-only board's probe carries none — the prepared frame's HT
    /// flag must match the board capability, not a constant.
    pub(super) fn submit_probe(
        &mut self,
        probe: &super::probe_runtime::Prepared,
    ) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving
            || self.peer.is_some()
            || !probe.matches(
                self.local,
                self.grant.primary(),
                self.ht_caps().is_some(),
                false,
            )
        {
            return Err(Error::State);
        }
        self.packets.submit_probe_8192e(probe).map_err(|error| {
            if self.packets.is_failed() {
                self.fail_terminal();
            }
            Error::Packet(error)
        })
    }
    /// The station's plaintext (QoS) Null to the bound AP.
    pub(super) fn submit_null(&mut self, null: &super::ps_null::Prepared) -> Result<(), Error> {
        self.current()?;
        let Some(peer) = self.peer else {
            return Err(Error::State);
        };
        if self.phase() != Phase::Receiving || !null.matches(self.local, peer, null.qos()) {
            return Err(Error::State);
        }
        self.packets.submit_null_8192e(null).map_err(|error| {
            if self.packets.is_failed() {
                self.fail_terminal();
            }
            Error::Packet(error)
        })
    }
}
impl<C: ControlIo, B: PacketIo> Drop for Radio<C, B> {
    fn drop(&mut self) {
        // As `receive_runtime::Receiver`: no I/O on drop; a claimed radio
        // cannot be restarted by a new software owner.
        if self.claimed && self.firmware.status().stage != Stage::Failed {
            self.firmware.runtime_failed(ControlError::Cancelled);
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "gen2_radio_tests.rs"]
mod tests;

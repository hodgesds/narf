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
//! authority; nothing here widens it. Other channels are reached only with
//! a grant minted from the same signed record and authenticated domain
//! (`Authority::grant`), through a cold `retune` (`rtl8xxxu_stop`, the
//! chip power-off and a fresh `rtl8xxxu_init_device` lifecycle, then
//! `rtl8xxxu_start` on the new channel). The packet owner never sets
//! QoS/HT, so this station is a legacy 20 MHz non-QoS station.
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
const REG_RXFLTMAP2: u16 = 0x6a4;
const REG_OFDM0_XA_AGC_CORE1: u16 = 0xc50;
const REG_MSR: u16 = 0x102;
const REG_FWHW_TXQ_CTRL: u16 = 0x420;
const REG_TBTT_PROHIBIT: u16 = 0x540;
const REG_SLOT: u16 = 0x51b;
const REG_BEACON_CTRL: u16 = 0x550;
const REG_MACID: u16 = 0x610;
const REG_BSSID: u16 = 0x618;
const BEACON_ATIM: u8 = 1 << 0;
const BEACON_FUNCTION_ENABLE: u8 = 1 << 3;
const BEACON_DISABLE_TSF_UPDATE: u8 = 1 << 4;
const MSR_LINKTYPE_STATION: u8 = 2;

/// A gen2 rxdesc24 MPDU in the shared management/security frame type. Only
/// legacy 20 MHz plaintext MPDUs reach this (`Frame::admitted(false, ..)`),
/// so no rxdesc16 word or HT40 seal is carried.
pub(super) fn mpdu(frame: rtl8192e_packet::Frame) -> Mpdu {
    Mpdu {
        bytes: frame.bytes,
        phy: frame.phy,
        rate: frame.rate,
        ht: false,
        bandwidth40: frame.bandwidth40,
        tid: frame.tid,
        decrypted: frame.decrypted,
        timestamp: frame.timestamp,
        native: None,
        wide: None,
        ba: false,
    }
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
    /// Physical receive-stream generation: advanced by every completed cold
    /// restart, so an observation names the stream that copied it.
    generation: u64,
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
    /// `REG_RXFLTMAP2`/`REG_RXFLTMAP0 = 0xffff` and IGI `0x1e`.
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
            for reg in [REG_RXFLTMAP2, REG_RXFLTMAP0] {
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
                    if frame.admitted(false, false, false) {
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
    /// share `rtl8xxxu_gen2_update_rate_mask`/`gen2_report_connect`).
    pub async fn associate(&mut self, aid: u16, peer: Peer, now: u64) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving || self.peer.is_none() || self.ra.is_some() {
            return Err(Error::State);
        }
        let mut ra = Ra::new(peer, self.grant.admitted(), self.tx_paths, false)
            .map_err(|_| Error::Profile)?;
        let mut attempt = self.attempt();
        let result = self.firmware.ra_connect_8192e(&mut ra, aid).await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.ra = Some(ra);
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
    pub(super) fn maintenance_pending(&self, now: u64) -> bool {
        self.recovery_pending()
            || !self.bt.is_empty()
            || self.ra.is_some() && now >= self.next_watchdog
    }
    /// The async half: `rtl8xxxu_ra_iter` every 2 s while associated
    /// (`ra_watchdog_8192e`/`ra_watchdog_8723b` with `-ewma_rssi_read`) and
    /// queued `C2H_8723B_BT_INFO` records through `c2h_bt_8723b` with
    /// `rtl8xxxu_is_assoc`.
    pub async fn maintain(&mut self, now: u64) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving {
            return Err(Error::State);
        }
        if self.recovery_pending() {
            self.recover().await?;
        }
        let mut attempt = self.attempt();
        let result = async {
            if let Some(ra) = &mut self.ra {
                if now >= self.next_watchdog {
                    let signal = self.rssi.signal();
                    match self.grant {
                        Grant::Rtl8192e(_) => self.firmware.ra_watchdog_8192e(ra, signal).await?,
                        Grant::Rtl8723b(_) => self.firmware.ra_watchdog_8723b(ra, signal).await?,
                    }
                    self.next_watchdog = now.saturating_add(WATCHDOG_MS);
                }
            }
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
            let f = &self.firmware;
            f.write8(REG_TXPAUSE, 0xff).await.map_err(Error::Control)?;
            for reg in [REG_RXFLTMAP0, REG_RXFLTMAP2] {
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
    /// Cold channel change of an unbound radio: `stop` (MAC TX/RX and RX
    /// filter maps closed, host transfers retired by USB Stop/SetDeq,
    /// `disable_rf`), the chip power-off and a fresh `rtl8xxxu_init_device`
    /// lifecycle, so no device-FIFO byte from the old channel survives into
    /// the new stream; then the new grant's channel label and, when the radio
    /// was receiving, `rtl8xxxu_start` (`tune_8192e`/`tune_8723b` revalidate
    /// the grant against the retained identity before any channel write).
    /// A never-started radio only relabels. Any failure is terminal.
    pub async fn retune(&mut self, grant: Grant) -> Result<(), Error> {
        self.current()?;
        if grant.chip() != self.chip() || self.peer.is_some() || self.ra.is_some() {
            return Err(Error::State);
        }
        let resume = match self.phase() {
            Phase::Prepared => false,
            Phase::Receiving | Phase::Stopped => true,
            _ => return Err(Error::State),
        };
        if self.phase() == Phase::Receiving {
            self.stop().await?;
        }
        if self.phase() == Phase::Stopped {
            self.park().await?;
            self.restart_parked().await?;
        }
        if let Err(error) = self.packets.retarget_stopped(grant.primary()) {
            self.fail_terminal();
            return Err(Error::Packet(error));
        }
        self.grant = grant;
        if resume {
            self.start().await?;
        }
        Ok(())
    }
    /// `rtl8xxxu_conf_tx` for BE/BK/VI/VO (`REG_EDCA_*_PARAM` 0x508/0x50c/
    /// 0x504/0x500 with `rtl8xxxu_set_aifs` SIFS 10 (legacy 2.4 GHz) plus
    /// AIFSN slots, via `wmm_runtime::words_profile`), each with an exact
    /// readback, then `REG_ACM_HW_CTRL` mirroring each AC's ACM. Rows this
    /// profile cannot program (BE ACM, ECW/AIFSN geometry, 8-bit AIFS) are
    /// refused before any write. Only afterwards may QoS DATA (txdesc40 AC
    /// queue/pipe per `rtl8xxxu_queue_select`) be submitted.
    pub(super) async fn configure_edca(
        &mut self,
        p: narf_wireless::wmm::Parameters,
        short_slot: bool,
    ) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving || self.peer.is_none() {
            return Err(Error::State);
        }
        let values =
            super::wmm_runtime::words_profile(p, short_slot, false).map_err(|_| Error::Profile)?;
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
    pub(super) fn submit_probe(
        &mut self,
        probe: &super::probe_runtime::Prepared,
    ) -> Result<(), Error> {
        self.current()?;
        if self.phase() != Phase::Receiving
            || self.peer.is_some()
            || !probe.matches(self.local, self.grant.primary(), false, false)
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

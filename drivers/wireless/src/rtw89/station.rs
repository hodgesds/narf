// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8852B 2.4GHz/20MHz host station state (channel1 initially;
//! signed noninitial primaries 2..=13 through the native retune owner). The exact firmware Owner
//! keeps its native backend; this state never owns or reconstructs hardware.
use super::command_native::OperatingChannel;
use super::{
    packet_core::{self as packet, Frame as Mpdu, Receipt},
    power,
    station_control::Admission,
};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec, vec::Vec};
use narf_wireless::reg::witness::{self, BeaconWitness, ScanGeneration};
use narf_wireless::reg::RegulatoryDomain;
use narf_wireless::{
    association::{self, AkmSet, JoinOptions, JoinPlan, ObservedBss, Pmf, SecurityMode},
    station_security::{self, RawFrame, Security},
};
use zeroize::Zeroizing;
#[path = "station_fragment.rs"]
mod fragment;
#[path = "station_six_ghz.rs"]
pub(super) mod six;
#[path = "station_tx_amsdu.rs"]
mod tx_amsdu;

/// Same retained cold/firmware/radio owner. Implementations must invoke
/// current device and exact ordinary RF/response authority at publication;
/// calibration-only qualification cannot satisfy this interface.
///
/// # Safety
/// Every operation borrows the same exclusive retained native owner. All
/// packet mappings remain owned across cancellation and ambiguous failure;
/// current capability and qualified ordinary RF/response checks enclose
/// actual hardware publication, including after an asynchronous wait.
#[async_trait::async_trait]
pub(super) unsafe trait Io: Send {
    fn monitor_capable(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    fn monitor_active(&self) -> bool {
        false
    }
    // Default-unsupported receive-only owner. These methods never construct
    // an ordinary packet Core or permit injection/autonomous responses.
    async fn monitor_start(
        &mut self,
        _: Arc<super::monitor::Desired>,
        _: Admission,
    ) -> Result<super::monitor::Source, power::Error> {
        Err(power::Error::Unsupported)
    }
    fn monitor_poll(&mut self) -> Result<Vec<Vec<u8>>, power::Error> {
        Err(power::Error::Unsupported)
    }
    fn monitor_stop(&mut self) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn station_allowed(&mut self) -> Result<(), power::Error>;
    fn station_own(&mut self) -> Result<[u8; 6], power::Error>;
    fn station_wmm_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    /// Signed firmware rate-adaptation program (`Program::FirmwareRa`).
    fn station_firmware_ra_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    /// Program firmware RA for the WMM-configured peer.
    async fn station_configure_ra(
        &mut self,
        _: u16,
        _: Option<super::station_control::HtRa>,
        _: Option<super::station_control::HeRa>,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// [`Self::station_configure_ra`] on an admitted 40/80MHz channel.
    async fn station_configure_ra_wide(
        &mut self,
        _: u16,
        _: super::station_control::HtRa,
        _: Option<super::station_control::HeRa>,
        _: super::station_control::WideRa,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// `rtw89_fw_h2c_ba_cam` for a recipient session start/stop.
    async fn station_configure_ba(
        &mut self,
        _: bool,
        _: u8,
        _: u16,
        _: u16,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Signed HT20 program (`Program::Ht`).
    fn station_ht_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    /// Distinct current expanded full-radio A-MSDU companion, not the old
    /// A-MPDU flag or HT enumeration. Optional prior profiles keep false.
    fn station_amsdu_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    /// Signed originator BA / TX A-MPDU program (`Program::Ampdu`).
    fn station_ampdu_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    /// `IEEE80211_AMPDU_TX_OPERATIONAL`/`TX_STOP_*` device half on RTL8852B:
    /// `rtw89_phy_ra_recalc_agg_limit` with the minimum operational
    /// `agg_num` (`None`: no TX session).
    async fn station_configure_agg_limit(
        &mut self,
        _: Option<u16>,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Room for one more aggregated data frame (`Core::ready_aggregate`).
    fn packet_ready_aggregate(&self) -> bool {
        false
    }
    /// `Core::submit_agg` for one aggregated QoS DATA MPDU.
    fn packet_submit_agg(
        &mut self,
        _: &[u8],
        _: bool,
        _: u8,
        _: super::packet_format::Agg,
    ) -> Result<u64, packet::Error> {
        Err(packet::Error::State)
    }
    /// Track-work register read (`track::REGISTERS` only). `Unsupported`
    /// disables tracking, as `disabled_dm_bitmap` does.
    /// Native opt-in comes only from the actual signed expanded LPS program.
    fn station_sleep_capable(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    /// True includes an interrupted/uncertain transition; synchronous drain
    /// may not read ordinary RX/BB until the retained async owner restores it.
    fn station_sleep_blocked(&self) -> bool {
        false
    }
    async fn station_sleep_service(
        &mut self,
        _: Option<narf_net::native_emission::Lifetime>,
        _: bool,
        _: bool,
        _: bool,
        _: &Admission,
    ) -> Result<(bool, bool), power::Error> {
        Ok((false, false))
    }
    /// RTL8852B WoW (`rtw89_wow_suspend`) is possible on this owner.
    fn station_wow_capable(&mut self) -> bool {
        false
    }
    /// `rtw89_wow_suspend` with the validated configuration and the
    /// station's key snapshot; any error leaves the owner for the cold path.
    async fn station_wow_suspend(
        &mut self,
        _: &narf_wireless::WowlanConfig,
        _: Option<&station_security::SuspendKeys>,
        _: Option<&station_security::SuspendFloors>,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// `rtw89_wow_resume`: the wake report (even on failure) and whether the
    /// awake station was restored.
    async fn station_wow_resume(
        &mut self,
        _: &Admission,
    ) -> (
        Option<super::wow_wire::WakeReport>,
        Result<(), power::Error>,
    ) {
        (None, Err(power::Error::Unsupported))
    }
    /// One periodic RF tracking step (`rtw89_track_work` ->
    /// `rtw89_chip_rfk_track`); never called while scanning.
    async fn station_rf_tracking(&mut self, _: &Admission) -> Result<(), power::Error> {
        Ok(())
    }
    fn station_track_read(&mut self, _: u32) -> Result<u32, power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Track-work register write (`track::REGISTERS` only).
    fn station_track_write(&mut self, _: u32, _: u32) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Prepared operating-PHY facts (`track::Profile`).
    fn station_track_profile(&mut self) -> Result<super::track::Profile, power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Track-work chip register layout and 5 GHz operating band.
    fn station_track_layout(&mut self) -> Result<(super::track::Layout, bool), power::Error> {
        Ok((super::track::LAYOUT_B, false))
    }
    /// CFO crystal-capacitor write through XTAL SI; returns the SC_XI readback.
    async fn station_track_crystal(&mut self, _: u8) -> Result<u8, power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Signed HE20 program (`Program::He`).
    fn station_he_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    /// One RF path (RTL8851B `rx_nss` = `tx_nss` = 1): the station offers
    /// the NSS1 VHT/HE capability bodies.
    fn station_single_stream(&mut self) -> bool {
        false
    }
    /// Retune the Ready radio to `primary` (2.4GHz or 5GHz 20MHz, signed
    /// N52C record required except channel1) and return the new retune epoch. `Busy` is a
    /// proven-unpublished refusal while TX/RX work is still pending.
    async fn station_retune(&mut self, _: u8, _: &Admission) -> Result<u32, power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Signed-admitted RTL8852B 40/80MHz operating channels
    /// (`Native::admitted_wide`). Default: none, so the station stays 20MHz.
    fn station_wide_channels(
        &mut self,
    ) -> Result<alloc::vec::Vec<super::operating_channel::Profile>, power::Error> {
        Ok(alloc::vec::Vec::new())
    }
    /// Retune the Ready unassociated radio to one admitted 40/80MHz
    /// `profile` (`Native::retune_full_radio_to`), same refusal contract as
    /// [`Self::station_retune`].
    async fn station_retune_wide(
        &mut self,
        _: super::operating_channel::Profile,
        _: &Admission,
    ) -> Result<u32, power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Associated channel switch (CSA): retune the Ready radio to `primary`
    /// keeping the installed peer, same admission/record rules as
    /// [`Self::station_retune`]. `Busy` is a proven-unpublished refusal.
    async fn station_switch_channel(&mut self, _: u8, _: &Admission) -> Result<u32, power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Associated wide channel switch (CSA on a wide link): retune the
    /// Ready radio to `profile` keeping the installed peer, same
    /// admission/record rules as [`Self::station_switch_channel`].
    /// `Busy` is a proven-unpublished refusal.
    async fn station_switch_wide_channel(
        &mut self,
        _: super::operating_channel::Profile,
        _: &Admission,
    ) -> Result<u32, power::Error> {
        Err(power::Error::Unsupported)
    }
    /// RTL8852C 6GHz 20MHz channels with a current signed record under a
    /// regd.c power context the host rule admits (`Native::admitted_six_ghz`).
    /// Default: none, so no 6GHz scan, join or band advertisement exists.
    fn station_six_ghz_channels(
        &mut self,
    ) -> Result<Vec<super::command_native::SixGhzChannel>, power::Error> {
        Ok(Vec::new())
    }
    /// The host policy the 6GHz records are admitted under
    /// (`Native::six_ghz_regulatory`); the 6GHz join takes its rule.
    fn station_six_ghz_regulatory(
        &mut self,
    ) -> Result<Option<Arc<RegulatoryDomain>>, power::Error> {
        Ok(None)
    }
    /// Retune the Ready radio to one admitted 6GHz 20MHz channel under its
    /// power context and the regd.c TPE constraint (`tpe`, dBm, STD only)
    /// (`Startup::retune_channel_c` with `Some((six, tpe))`). `linked` keeps
    /// the installed peer (TPE update / channel switch). Same refusal
    /// contract as [`Self::station_retune`].
    async fn station_retune_6ghz(
        &mut self,
        _: super::command_native::SixGhzChannel,
        _: Option<i8>,
        _: bool,
        _: &Admission,
    ) -> Result<u32, power::Error> {
        Err(power::Error::Unsupported)
    }
    /// `operating_channel::slot` mask (2.4GHz primary n = bit n, 5GHz from
    /// bit 16) of primaries with a current signed full program (channel1 is
    /// the base record). Default: channel1 only.
    fn station_channels(&mut self) -> Result<u64, power::Error> {
        Ok(1 << 1)
    }
    /// The host policy snapshot the native envelope checks run against,
    /// classifying passive-only (DFS / NO_IR) primaries and scoping the
    /// station's beacon witnesses. `None` (default): the native side admits
    /// no passive-only primary, so every admitted primary is active.
    fn station_regulatory(&mut self) -> Result<Option<Arc<RegulatoryDomain>>, power::Error> {
        Ok(None)
    }
    /// Grant (`Some((primary, policy))`) or withdraw (`None`) native frame
    /// TX on a passive-only primary the station admitted under a witness.
    fn station_passive_tx(
        &mut self,
        _: Option<(u8, Arc<RegulatoryDomain>)>,
    ) -> Result<(), power::Error> {
        Ok(())
    }
    /// `rtw89_core_scan_start`/`_complete` address CAM update: a random scan
    /// SMA, or `None` to restore the own address.
    async fn station_scan_address(
        &mut self,
        _: Option<[u8; 6]>,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Mirror the scan source address in the packet owner.
    fn packet_scan_address(&mut self, _: Option<[u8; 6]>) -> Result<(), packet::Error> {
        Err(packet::Error::State)
    }
    /// Signed all-AC/TID QoS program (`radio_policy::Program::QosAll`).
    fn station_qos_all_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    async fn station_configure_wmm(
        &mut self,
        _: narf_wireless::wmm::Parameters,
        _: bool,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Reprogram EDCA for an already admitted QoS peer.
    async fn station_update_wmm(
        &mut self,
        _: narf_wireless::wmm::Parameters,
        _: bool,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn station_prepare_initial(
        &mut self,
        own: [u8; 6],
        admission: &Admission,
    ) -> Result<(), power::Error>;
    async fn station_prepare_peer(
        &mut self,
        peer: [u8; 6],
        admission: &Admission,
    ) -> Result<(), power::Error>;
    async fn station_commit_peer(
        &mut self,
        peer: [u8; 6],
        aid: u16,
        short_slot: bool,
        admission: &Admission,
    ) -> Result<(), power::Error>;
    async fn station_disconnect(
        &mut self,
        peer: [u8; 6],
        admission: &Admission,
    ) -> Result<(), power::Error>;
    fn station_fragments_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    fn packet_fragment_binding(
        &mut self,
        _: &Admission,
    ) -> Result<super::command_native::FragmentBinding, power::Error> {
        Err(power::Error::Unsupported)
    }
    fn packet_submit_fragment(
        &mut self,
        _: &super::command_native::FragmentPart,
        _: bool,
    ) -> Result<u64, packet::Error> {
        Err(packet::Error::State)
    }
    // AP role (`startup_ap.rs`): exclusive with the station owner. Default
    // unsupported; no AP capability follows from these alone.
    fn ap_allowed(&mut self) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Signed AP channel admission and retune (before `ap_prepare`).
    async fn ap_channel(&mut self, _: u8, _: &Admission) -> Result<u32, power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn ap_prepare(&mut self, _: [u8; 6], _: &Admission) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn ap_start(
        &mut self,
        _: super::ap_control::PortConfig,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn ap_publish_beacon(
        &mut self,
        _: &[u8],
        _: usize,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn ap_add_peer(&mut self, _: [u8; 6], _: &Admission) -> Result<u8, power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn ap_associate_peer(
        &mut self,
        _: [u8; 6],
        _: u16,
        _: [u8; 16],
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn ap_remove_peer(&mut self, _: [u8; 6], _: &Admission) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn ap_stop(&mut self, _: &Admission) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn ap_packet_ready(&self) -> bool {
        false
    }
    fn ap_lowest_rate(&mut self) -> Result<u8, power::Error> {
        Err(power::Error::Unsupported)
    }
    /// One AP frame (`after_dtim`: CH9 HIQ); the native owner resolves the
    /// peer MACID and refuses unbound unicast data.
    fn packet_submit_ap(
        &mut self,
        _: &[u8],
        _: bool,
        _: bool,
        _: u8,
    ) -> Result<u64, packet::Error> {
        Err(packet::Error::State)
    }
    fn packet_prepare(&mut self, own: [u8; 6], macid: u8) -> Result<(), packet::Error>;
    fn packet_start(&mut self) -> Result<(), packet::Error>;
    fn packet_ready(&self) -> bool;
    fn packet_submit(&mut self, bytes: &[u8], report: bool) -> Result<u64, packet::Error>;
    fn packet_submit_rate(
        &mut self,
        bytes: &[u8],
        report: bool,
        rate: u8,
    ) -> Result<u64, packet::Error> {
        if rate == 0 {
            self.packet_submit(bytes, report)
        } else {
            Err(packet::Error::Packet)
        }
    }
    fn packet_poll(&mut self) -> Result<packet::Step, packet::Error>;
    fn packet_stop(&mut self) -> Result<(), packet::Error>;
    /// After `packet_stop`: prove every HCI DMA engine idle with bus
    /// mastering off and free all published storage. True only when nothing
    /// remains pinned; owners without a proof keep everything (false).
    fn retire_dma(&mut self) -> bool {
        false
    }
    /// Bind interrupt delivery to `line` once packets are started. Owners
    /// without an MSI path stay in polled mode.
    fn irq_start(&mut self, _line: &Arc<super::irq::Line>) -> Result<u8, power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Mask, recognize and acknowledge pending interrupt sources.
    fn irq_service(&mut self) -> Result<super::irq::Events, power::Error> {
        Ok(super::irq::Events::default())
    }
    /// Re-enable the interrupt mask after the rings were drained.
    fn irq_rearm(&mut self) -> Result<(), power::Error> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    State,
    Busy,
    Profile,
    Entropy,
    Timeout,
    PeerLost,
    Transport(packet::Error),
    Native(power::Error),
    Management(association::Error),
    Security(station_security::Error),
    /// Firmware halt (SER) or watchdog interrupt from the device.
    Halted,
}
impl From<packet::Error> for Error {
    fn from(error: packet::Error) -> Self {
        Self::Transport(error)
    }
}
impl From<power::Error> for Error {
    fn from(error: power::Error) -> Self {
        Self::Native(error)
    }
}
impl From<association::Error> for Error {
    fn from(error: association::Error) -> Self {
        Self::Management(error)
    }
}
impl From<station_security::Error> for Error {
    fn from(error: station_security::Error) -> Self {
        Self::Security(error)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Prepared,
    Passive,
    Authentication,
    Association,
    FourWay,
    Open,
    Failed,
    Stopped,
}
#[async_trait::async_trait]
pub(super) trait Environment: Send + Sync {
    fn now_ms(&self) -> u64;
    fn nonce(&self) -> Option<[u8; 32]>;
    async fn pause(&self);
}
pub(super) struct NativeEnvironment;
#[async_trait::async_trait]
impl Environment for NativeEnvironment {
    fn now_ms(&self) -> u64 {
        narf_time::monotonic_ns() / 1_000_000
    }
    fn nonce(&self) -> Option<[u8; 32]> {
        let mut bytes = [0; 32];
        narf_crypto::try_fill_random_bytes(&mut bytes).ok()?;
        Some(bytes)
    }
    async fn pause(&self) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Authentication,
    Association,
    Security,
    Data,
    /// Block Ack action frames: like data, a missing ACK is not fatal.
    Action,
    /// Broadcast probe request (never acknowledged).
    Probe,
}
/// Association credential, mapped from `SecurityConfig` by the interface.
pub(super) enum Credential {
    Open,
    /// WPA2-PSK PMK; PMF is negotiated (`ieee80211w=1`) from the AP RSNE.
    Psk(Zeroizing<[u8; 32]>),
    /// WPA3-Personal SAE password (`sae_pwe=2`, PMF required).
    Sae(Zeroizing<Vec<u8>>),
}
/// mac80211 `ieee80211_process_sa_query_req`: an SA Query Request (category
/// 8, action 0) from the bound AP to this station is answered with the same
/// transaction identifier (`IEEE80211_MIN_ACTION_SIZE + sizeof(sa_query)`).
pub(super) fn sa_query_response(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() < 28
        || frame[0] != 0xd0
        || frame[1] & 0x40 != 0
        || frame[4..10] != own
        || frame[10..16] != peer
        || frame[16..22] != peer
        || frame[24..26] != [8, 0]
    {
        return None;
    }
    let mut response = vec![0xd0, 0, 0, 0];
    response.extend_from_slice(&peer);
    response.extend_from_slice(&own);
    response.extend_from_slice(&peer);
    response.extend_from_slice(&[0, 0, 8, 1, frame[26], frame[27]]);
    Some(response)
}
/// Active-scan probe content: SSIDs (empty = wildcard) and caller IEs.
pub(super) struct Probe {
    pub(super) ssids: Vec<Vec<u8>>,
    pub(super) ies: Vec<u8>,
    /// Random scan source address (`NL80211_SCAN_FLAG_RANDOM_ADDR`).
    pub(super) address: Option<[u8; 6]>,
    /// `NL80211_SCAN_FLAG_RANDOM_SN`: every probe request carries a random
    /// sequence number and leaves the station counter untouched
    /// (`IEEE80211_TX_CTRL_NO_SEQNO`).
    pub(super) random_sn: bool,
}
/// mac80211 `ieee80211_build_probe_req` (`ieee80211_build_preq_ies_band`)
/// for this 20MHz profile. 2.4GHz: SSID, Supported Rates
/// (1,2,5.5,11,6,9,12,18), Extended Supported Rates (24,36,48,54), DS
/// Parameter Set (the retained radio's actual primary). 5GHz: SSID and the
/// eight OFDM Supported Rates (6..54) only; no Extended Supported Rates
/// (nothing left over) and no DS Parameter Set (2.4GHz only). Then the
/// caller's extra IEs.
pub(super) fn probe_request(own: [u8; 6], ssid: &[u8], ies: &[u8], channel: u8) -> Vec<u8> {
    let mut frame = vec![0x40, 0, 0, 0];
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&own);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0, ssid.len() as u8]);
    frame.extend_from_slice(ssid);
    if ghz5(channel) {
        frame.extend_from_slice(&[1, 8, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]);
    } else {
        frame.extend_from_slice(&[1, 8, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24]);
        frame.extend_from_slice(&[50, 4, 0x30, 0x48, 0x60, 0x6c]);
        frame.extend_from_slice(&[3, 1, channel]);
    }
    frame.extend_from_slice(ies);
    frame
}
/// A typed 5GHz primary (`operating_channel::GHZ5`).
pub(super) fn ghz5(primary: u8) -> bool {
    super::operating_channel::GHZ5.contains(&primary)
}
/// cfg80211 centre frequency of a typed primary (20 MHz witness key).
fn center(primary: u8) -> u16 {
    super::monitor_wire::frequency(primary) as u16
}
/// The primary is passive-only (cfg80211 RADAR / NO_IR) under `policy`.
pub(super) fn passive_only(policy: Option<&Arc<RegulatoryDomain>>, primary: u8) -> bool {
    policy.is_some_and(|p| witness::passive_only(p, center(primary)))
}
/// A typed 20MHz primary this station may tune: 2.4GHz 1..=13 or 5GHz.
fn typed(primary: u8) -> bool {
    (1..=13).contains(&primary) || ghz5(primary)
}
/// `primary` is set in an `operating_channel::slot` admission mask.
pub(super) fn channel_admitted(mask: u64, primary: u8) -> bool {
    typed(primary)
        && super::operating_channel::slot(primary).is_some_and(|bit| mask & (1u64 << bit) != 0)
}
/// The station's own fixed management rate on `primary` (core.c
/// `rtw89_core_get_mgmt_rate` band floor) must be a BSS basic rate:
/// 1Mbps on 2.4GHz, 6Mbps on 5GHz, where no CCK rate may be basic.
fn basic_ok(ofdm_only: bool, basic: u16) -> bool {
    if ofdm_only {
        basic & 0x10 != 0 && basic & 0xf == 0
    } else {
        basic & 1 != 0
    }
}
enum BaOp {
    Start(super::block_ack::Request, u16),
    Stop(u8),
    /// Originator `TX_OPERATIONAL` for a TID.
    TxOperational(u8),
    /// Originator `TX_STOP_*`: recompute the RA aggregation limit.
    TxLimit,
}
struct Pending {
    id: u64,
    bytes: Vec<u8>,
    kind: Kind,
    /// Published with TXWD AGG_EN.
    agg: bool,
}
struct Entry {
    candidate: ObservedBss,
    seen: u64,
}
struct Attempt {
    admission: Admission,
    armed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.armed {
            self.admission.close();
        }
    }
}
pub(super) struct State {
    environment: Arc<dyn Environment>,
    own: [u8; 6],
    phase: Phase,
    admission: Admission,
    prepared: bool,
    peer_commit: Option<(u16, bool)>,
    cache: Vec<Entry>,
    peer: Option<ObservedBss>,
    plan: Option<JoinPlan>,
    security: Option<Security>,
    /// SAE exchange in progress (password element, scalars), boxed.
    sae: Option<Box<narf_wireless::sae::SaeSession>>,
    incoming: VecDeque<Mpdu>,
    received: VecDeque<Vec<u8>>,
    /// Frames in flight, oldest first. More than one only for aggregated
    /// QoS DATA on an operational originator session.
    pending: VecDeque<Pending>,
    fragment_tx: Option<Box<fragment::Flight>>,
    fragment_wait: Option<Box<fragment::Deferred>>,
    fragment_policy: Option<Arc<super::monitor::Desired>>,
    fragment_plain: Option<Box<super::fragment_rx::Plain>>,
    fragment_rx_pending: bool,
    delivered_reply: Option<Pending>,
    initial_nonce: Option<[u8; 32]>,
    sequence: u16,
    established: bool,
    wmm: Option<narf_wireless::wmm::Parameters>,
    /// Newer AP EDCA set observed in a peer beacon, awaiting reprogramming.
    edca_pending: Option<narf_wireless::wmm::Parameters>,
    short_slot: bool,
    /// All-AC/TID QoS routing is active for this association.
    qos_all: bool,
    /// Firmware rate adaptation owns DATA rates for this association.
    firmware_ra: bool,
    /// HT20 was negotiated for this association.
    ht: bool,
    /// HE20 was negotiated for this association.
    he: bool,
    /// A current MACID0 RA report has ruled out legacy fallback.
    htc_rate: bool,
    /// Latest matching native RC body ceiling; None is Linux's initial no clamp.
    amsdu_rc: Option<usize>,
    /// Actual RX prefix was drained to idle by the last retained worker pass.
    rx_idle: bool,
    /// Data TXWD `DATA_ER` (Linux `er_cap`: HE operation allows ER SU).
    er: bool,
    /// Random scan address live in the address CAM during an active scan.
    scan: Option<[u8; 6]>,
    /// Recipient Block Ack sessions per TID.
    ba: [Option<super::block_ack::Session<Mpdu>>; 8],
    /// Originator (TX) Block Ack sessions under the signed aggregate program.
    originator: Box<super::block_ack::Originator>,
    /// `Program::Ampdu` granted and HT negotiated for this association.
    ampdu: bool,
    /// Peer HT minimum MPDU start spacing (TXWD AMPDU_DENSITY).
    density: u8,
    /// BA CAM programming awaiting the async owner.
    ba_ops: VecDeque<BaOp>,
    /// Queued ADDBA responses / DELBAs.
    mgmt_out: VecDeque<Vec<u8>>,
    deadline: u64,
    last_peer: u64,
    last_now: u64,
    /// `rtw89_track_work` RSSI statistics and dynamic EDCCA.
    track: super::track::Tracker,
    scanning: bool,
    /// cfg80211 `beacon_found` per 20MHz primary in its latest covering scan
    /// (shared `reg::witness`): admits association / CSA onto a passive-only
    /// (DFS / NO_IR) primary.
    witness: BeaconWitness,
    /// Witness generation of the dwell in progress, if any.
    witness_scan: Option<ScanGeneration>,
    /// Band-qualified actual channel of the retained radio (native retune
    /// epoch below); 2.4/5GHz legacy numbering until a 6GHz retune exists.
    channel: OperatingChannel,
    /// The admitted 40/80MHz operating channel the radio is tuned to around
    /// `channel`, if any (`None`: the 20MHz profile of `channel`).
    wide: Option<super::operating_channel::Profile>,
    /// RTL8852C 6GHz tuning: the admitted channel/power context and the
    /// regd.c TPE constraint it was programmed with (`None` off 6GHz).
    six: Option<(super::command_native::SixGhzChannel, Option<i8>)>,
    /// Native retune epoch this state's channel-bound work was built for.
    epoch: Option<u32>,
    /// Accepted AP channel switch (mac80211 `link->csa`), if any.
    csa: Option<Switch>,
}
/// mac80211 station CSA state for one link: target primary, switch time
/// (`csa_time_tu` after the announcing beacon), `csa.blocked_tx` and
/// `csa.waiting_bcn` once the radio is on the target. `wide` is the
/// target wide chandef for a wide link (the Wide Bandwidth element, or
/// the current width/center at the new primary); `None` on a wide link
/// means the link cannot follow and fails instead of narrowing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Switch {
    pub primary: u8,
    pub at_ms: u64,
    pub block_tx: bool,
    pub switched: bool,
    pub wide: Option<super::operating_channel::Profile>,
}
/// Parsed CSA/ECSA element of a beacon (`ieee80211_parse_ch_switch_ie`):
/// ECSA (60) takes precedence over CSA (37) when its operating class is
/// understood (`ieee80211_operating_class_to_band`: 81..=84 2.4GHz, 112 and
/// 115..=130 5GHz, 131..=135/137 6GHz, 180 60GHz); otherwise the CSA element
/// is used in the current band. `None` primary is a target this 20MHz
/// station has no typed channel for (another band, channel 14, or a channel
/// outside the band's primaries).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Announcement {
    pub mode: bool,
    pub primary: Option<u8>,
    pub count: u8,
}
pub(super) fn channel_switch(ies: &[u8], current: u8) -> Option<Announcement> {
    let mut csa = None;
    let mut ecsa = None;
    let mut rest = ies;
    while let [id, len, tail @ ..] = rest {
        let len = usize::from(*len);
        let Some(body) = tail.get(..len) else {
            break;
        };
        match (*id, body) {
            (37, [mode, channel, count]) if csa.is_none() => csa = Some((*mode, *channel, *count)),
            (60, [mode, class, channel, count]) if ecsa.is_none() => {
                ecsa = Some((*mode, Some(*class), *channel, *count))
            }
            _ => {}
        }
        rest = &tail[len..];
    }
    // 0: 2.4GHz, 1: 5GHz, 2: a band without typed channels here.
    let class_band = |class: u8| match class {
        81..=84 => Some(0),
        112 | 115..=130 => Some(1),
        131..=135 | 137 | 180 => Some(2),
        _ => None,
    };
    let current_band = u8::from(ghz5(current));
    let (mode, band, channel, count) = match ecsa {
        Some((mode, Some(class), channel, count)) if class_band(class).is_some() => {
            (mode, class_band(class)?, channel, count)
        }
        _ => {
            let (mode, channel, count) = csa?;
            (mode, current_band, channel, count)
        }
    };
    let primary = match band {
        0 => (1..=13).contains(&channel),
        1 => ghz5(channel),
        _ => false,
    };
    Some(Announcement {
        mode: mode == 1,
        primary: primary.then_some(channel),
        count,
    })
}
/// Wide Bandwidth Channel Switch element (194) of a beacon, if any:
/// (new channel width, center segment 0, center segment 1), first
/// element wins like CSA/ECSA above. The width byte mirrors the VHT
/// operation element (0 = 20/40, 1 = 80, 2 = 160, 3 = 80+80).
pub(super) fn wide_bandwidth_switch(ies: &[u8]) -> Option<(u8, u8, u8)> {
    let mut rest = ies;
    while let [id, len, tail @ ..] = rest {
        let len = usize::from(*len);
        let Some(body) = tail.get(..len) else {
            break;
        };
        if let (194, [width, seg0, seg1]) = (*id, body) {
            return Some((*width, *seg0, *seg1));
        }
        rest = &tail[len..];
    }
    None
}
/// Target wide profile for a CSA on a wide link, or `None` when the
/// link cannot follow (`ieee80211_sta_process_chanswitch` drops the
/// connection on an unusable target). Without a Wide Bandwidth element
/// the target keeps the current width and center at the new primary;
/// with one, width 1 is 80MHz and width 2 is 160MHz at the announced
/// segment 0 (segment 1 must be 0: 80+80 is never offered). Width 0
/// (20/40, whose new secondary side is unknowable from the
/// announcement) and width 3 (80+80) are unusable, as is any target
/// outside the admitted wide profiles or with a passive-only
/// subchannel (association's wide rule: every subchannel must be
/// active, with no beacon-witness exception).
pub(super) fn wide_target(
    ies: &[u8],
    primary: u8,
    current: super::operating_channel::Profile,
    admitted: &[super::operating_channel::Profile],
    policy: Option<&Arc<RegulatoryDomain>>,
) -> Option<super::operating_channel::Profile> {
    use super::operating_channel::{Profile, Width};
    let target = match wide_bandwidth_switch(ies) {
        Some((1, seg0, 0)) => {
            let profile = Profile::new_5ghz(primary, Width::Mhz80)?;
            (profile.center() == seg0).then_some(profile)?
        }
        Some((2, seg0, 0)) => {
            let profile = Profile::new_5ghz_160(primary)?;
            (profile.center() == seg0).then_some(profile)?
        }
        Some(_) => return None,
        None => {
            let profile = match current.width() {
                Width::Mhz160 => Profile::new_5ghz_160(primary)?,
                width => Profile::new_wide(primary, width, current.center() > primary)?,
            };
            (profile.center() == current.center()).then_some(profile)?
        }
    };
    if !admitted.contains(&target) {
        return None;
    }
    if !target.subchannels().all(|ch| !passive_only(policy, ch)) {
        return None;
    }
    Some(target)
}
impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8852bStation")
            .field("phase", &self.phase)
            .field("established", &self.established)
            .finish_non_exhaustive()
    }
}
impl State {
    pub(super) fn new(
        own: [u8; 6],
        environment: Arc<dyn Environment>,
        admission: Admission,
    ) -> Self {
        Self {
            environment,
            own,
            phase: Phase::Prepared,
            admission,
            prepared: false,
            peer_commit: None,
            cache: Vec::new(),
            peer: None,
            plan: None,
            security: None,
            sae: None,
            incoming: VecDeque::new(),
            received: VecDeque::new(),
            pending: VecDeque::new(),
            fragment_tx: None,
            fragment_wait: None,
            fragment_policy: None,
            fragment_plain: None,
            fragment_rx_pending: false,
            delivered_reply: None,
            initial_nonce: None,
            sequence: 1,
            established: false,
            wmm: None,
            edca_pending: None,
            short_slot: false,
            qos_all: false,
            firmware_ra: false,
            ht: false,
            he: false,
            htc_rate: false,
            amsdu_rc: None,
            rx_idle: false,
            er: false,
            scan: None,
            ba: core::array::from_fn(|_| None),
            originator: Box::default(),
            ampdu: false,
            density: 0,
            ba_ops: VecDeque::new(),
            mgmt_out: VecDeque::new(),
            deadline: 0,
            last_peer: 0,
            last_now: 0,
            track: super::track::Tracker::default(),
            scanning: false,
            witness: BeaconWitness::new(),
            witness_scan: None,
            channel: OperatingChannel::legacy(1),
            wide: None,
            six: None,
            epoch: None,
            csa: None,
        }
    }
    pub(super) fn admission(&self) -> Admission {
        self.admission.clone()
    }
    pub(super) fn local(&self) -> [u8; 6] {
        self.own
    }
    pub(super) fn phase(&self) -> Phase {
        if self.admission.closed() && self.phase != Phase::Stopped {
            Phase::Failed
        } else {
            self.phase
        }
    }
    pub(super) fn peer(&self) -> Option<[u8; 6]> {
        if self.established && !self.admission.closed() {
            self.peer.as_ref().map(|peer| peer.bss.bssid)
        } else {
            None
        }
    }
    pub(super) fn sleep_idle(&self) -> bool {
        self.phase == Phase::Open
            && self.ready()
            && self.pending.is_empty()
            && self.fragment_tx.is_none()
            && self.fragment_wait.is_none()
            && !self.fragment_rx_pending
            && self.delivered_reply.is_none()
            && self.incoming.is_empty()
            && self.received.is_empty()
            && self.mgmt_out.is_empty()
            && self.ba_ops.is_empty()
            && self.edca_pending.is_none()
            && self.csa.is_none()
            && !self.scanning
            && self.scan.is_none()
            && self.rx_idle
            && self
                .ba
                .iter()
                .flatten()
                .all(|session| session.reorder.buffered() == 0)
            && (0..8).all(|tid| !self.originator.holding(tid))
            && !self.sleep_timer_due()
            && self.security.as_ref().is_none_or(|s| !s.handshake_active())
            && !self.track.due(self.environment.now_ms())
    }
    /// `rtw89_wow_suspend` inputs from the associated, settled station
    /// (no handshake, CSA, scan or management/packet work in flight): the
    /// current temporal keys and their PN floors, both `None` for an open
    /// BSS. Reading them consumes no PN or replay state.
    pub(super) fn wow_snapshot(
        &self,
    ) -> Result<
        (
            Option<station_security::SuspendKeys>,
            Option<station_security::SuspendFloors>,
        ),
        Error,
    > {
        if self.phase != Phase::Open
            || self.peer().is_none()
            || !self.ready()
            || !self.pending.is_empty()
            || self.csa.is_some()
            || self.scanning
            || self.scan.is_some()
            || !self.mgmt_out.is_empty()
            || !self.ba_ops.is_empty()
            || self.edca_pending.is_some()
        {
            return Err(Error::State);
        }
        match self.security.as_ref() {
            None => Ok((None, None)),
            Some(security) => {
                let keys = security.suspend_keys().ok_or(Error::State)?;
                let floors = security.suspend_floors().ok_or(Error::State)?;
                Ok((Some(keys), Some(floors)))
            }
        }
    }
    /// The link survived the WoW window (`rtw89_wow_resume` kept the
    /// association): the AP was heard by the WoW firmware until now.
    pub(super) fn wow_resumed(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Open || self.peer().is_none() {
            return Err(Error::State);
        }
        self.last_peer = self.now()?;
        Ok(())
    }
    pub(super) fn sleep_restored(&mut self) {
        self.track.restored();
    }
    pub(super) fn ready(&self) -> bool {
        self.peer().is_some()
            && !self.csa_blocks_tx()
            && self.fragment_tx.is_none()
            && self.fragment_wait.is_none()
            && self.pending.iter().all(|pending| pending.agg)
            && self.delivered_reply.is_none()
            && self.security.as_ref().is_none_or(Security::port_open)
    }
    pub(super) async fn start(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if self.phase() != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let mut attempt = Attempt {
            admission: self.admission.clone(),
            armed: true,
        };
        io.station_prepare_initial(self.own, &self.admission)
            .await?;
        self.admission
            .run(|| Ok(io.packet_prepare(self.own, 0)))??;
        self.prepared = true;
        let started = self
            .admission
            .run(|| Ok(io.packet_start()))
            .map_err(Error::Native)
            .and_then(|result| result.map_err(Error::Transport));
        if let Err(error) = started {
            self.fail(io);
            return Err(error);
        }
        self.last_now = self.environment.now_ms();
        self.phase = Phase::Passive;
        attempt.armed = false;
        Ok(())
    }
    pub(super) fn stop(&mut self, io: &mut impl Io) -> Result<(), Error> {
        self.sae = None;
        self.fragment_tx = None;
        self.fragment_wait = None;
        self.fragment_plain = None;
        self.fragment_rx_pending = false;
        self.wmm = None;

        self.edca_pending = None;
        self.csa = None;
        self.qos_all = false;
        self.firmware_ra = false;
        self.ht = false;
        self.he = false;
        self.htc_rate = false;
        self.amsdu_rc = None;
        self.rx_idle = false;
        self.er = false;
        self.scan = None;
        self.witness.clear();
        self.witness_scan = None;
        let _ = io.station_passive_tx(None);
        self.clear_block_ack();
        self.admission.close();
        self.established = false;
        self.phase = Phase::Stopped;
        if let Some(security) = &mut self.security {
            security.fail();
        }
        self.incoming.clear();
        self.received.clear();
        self.peer_commit = None;
        // Controller initialization can already own live CH12/RX DMA before
        // the ordinary packet core exists. The adapter closes that same
        // Native even when preparation was cancelled before Core::prepare.
        io.packet_stop()?;
        Ok(())
    }
    fn fail(&mut self, io: &mut impl Io) {
        let _ = self.stop(io);
        self.phase = Phase::Failed;
    }
    pub(super) async fn disconnect(&mut self, io: &mut impl Io) -> Result<(), Error> {
        // Public Device reserves before waiting for this owner's mutex.
        // Direct private callers need the same cancellation/worker ordering.
        let reservation = if self.admission.teardown_pending() {
            None
        } else {
            Some(self.admission.begin_disconnect()?)
        };
        self.admission.close();
        self.fragment_tx = None;
        self.fragment_wait = None;
        self.fragment_plain = None;
        self.fragment_rx_pending = false;
        self.established = false;
        self.wmm = None;
        self.edca_pending = None;
        self.csa = None;
        self.qos_all = false;
        self.firmware_ra = false;
        self.ht = false;
        self.he = false;
        self.htc_rate = false;
        self.amsdu_rc = None;
        self.rx_idle = false;
        self.er = false;
        self.scan = None;
        self.clear_block_ack();
        if let Some(security) = &mut self.security {
            security.fail();
        }
        let mut attempt = Attempt {
            admission: self.admission.clone(),
            armed: true,
        };
        let control = if let Some(peer) = &self.peer {
            io.station_disconnect(peer.bss.bssid, &self.admission).await
        } else {
            Ok(())
        };
        let stopped = self.stop(io);
        attempt.armed = false;
        drop(reservation);
        control?;
        stopped
    }
    fn now(&mut self) -> Result<u64, Error> {
        let now = self.environment.now_ms();
        if now < self.last_now {
            return Err(Error::State);
        }
        self.last_now = now;
        Ok(now)
    }
    /// `total_sta_assoc > 0`: the associated AP, as `rtw89_track_work` sees it.
    /// mac80211 adds the station at association (`total_sta_assoc`), so the
    /// four-way handshake already counts as linked.
    fn linked(&self) -> Option<[u8; 6]> {
        matches!(self.phase, Phase::FourWay | Phase::Open)
            .then(|| self.peer.as_ref().map(|peer| peer.bss.bssid))
            .flatten()
    }
    /// `rtw89_track_work` (and the enhanced CFO timer) when due (`track.rs`).
    async fn track(&mut self, io: &mut impl Io) -> Result<(), Error> {
        struct Hw<'a, I>(&'a mut I, &'a Admission);
        impl<I: Io> super::track::Hw for Hw<'_, I> {
            async fn rfk(&mut self) -> Result<(), power::Error> {
                self.0.station_rf_tracking(self.1).await
            }
            fn read(&mut self, address: u32) -> Result<u32, power::Error> {
                self.0.station_track_read(address)
            }
            fn write(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
                self.0.station_track_write(address, value)
            }
            fn profile(&mut self) -> Result<super::track::Profile, power::Error> {
                self.0.station_track_profile()
            }
            fn layout(&mut self) -> Result<(super::track::Layout, bool), power::Error> {
                self.0.station_track_layout()
            }
            async fn crystal(&mut self, cap: u8) -> Result<u8, power::Error> {
                self.0.station_track_crystal(cap).await
            }
        }
        let now = self.now()?;
        let (peer, scanning) = (self.linked(), self.scanning);
        match self
            .track
            .run(&mut Hw(io, &self.admission), now, peer, scanning)
            .await
        {
            Ok(()) => Ok(()),
            Err(power::Error::Unsupported) => {
                self.track.disable();
                Ok(())
            }
            Err(error) => Err(Error::Native(error)),
        }
    }
    pub(super) fn candidates(&self) -> Vec<ObservedBss> {
        let now = self.environment.now_ms();
        self.cache
            .iter()
            .filter(|entry| now >= entry.seen && now - entry.seen < 10_000)
            .map(|entry| entry.candidate.clone())
            .collect()
    }
    pub(super) fn information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.candidates()
            .into_iter()
            .find(|candidate| candidate.bss.bssid == bssid)
            .map(|candidate| candidate.bss.information_elements)
    }
    /// Exact station admission, shared by pre-crypto and final native send.
    /// The peer BA window can be smaller than the packet core's global limit.
    fn transmit_room(&self, kind: Kind, agg: Option<super::packet_format::Agg>) -> bool {
        let joins = agg.is_some_and(|agg| {
            kind == Kind::Data
                && self.pending.iter().all(|pending| pending.agg)
                && self.pending.len() < (usize::from(agg.num) + 1).min(packet::AGG_WINDOW)
        });
        self.fragment_tx.is_none()
            && self.fragment_wait.is_none()
            && (self.pending.is_empty() || joins)
            && self.delivered_reply.is_none()
    }
    fn transmit(&mut self, io: &mut impl Io, bytes: Vec<u8>, kind: Kind) -> Result<(), Error> {
        self.transmit_with(io, bytes, kind, true, None)
    }
    /// `assign` false is mac80211 `IEEE80211_TX_CTRL_NO_SEQNO`: the caller
    /// already wrote the sequence number (random-SN probe requests).
    fn transmit_with(
        &mut self,
        io: &mut impl Io,
        mut bytes: Vec<u8>,
        kind: Kind,
        assign: bool,
        agg: Option<super::packet_format::Agg>,
    ) -> Result<(), Error> {
        // Caller holds publication; this helper never awaits or re-enters it.
        if self.admission.closed() {
            return Err(Error::State);
        }
        if !self.transmit_room(kind, agg) {
            return Err(Error::Busy);
        }
        if self.fragment_management(io, &bytes, kind, assign)? {
            return Ok(());
        }
        if assign && !matches!(kind, Kind::Security | Kind::Data) {
            bytes[22..24].copy_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
        }
        // PMF: robust Action frames (Block Ack, SA Query) to the AP are
        // host-CCMP protected once the port is open (RTL8852B has no
        // `hw_mgmt_tx_encrypt`; mac80211 `ieee80211_tx_h_encrypt`).
        if kind == Kind::Action {
            if let Some(security) = self.security.as_mut().filter(|s| s.pmf() && s.port_open()) {
                bytes = security.protect_management(&bytes)?;
            }
        }
        let rate = if kind == Kind::Data && self.wmm.is_some() && self.firmware_ra {
            // rtw89_core_get_data_rate: lowest negotiated rate bounds retries.
            let rates = self.plan.as_ref().ok_or(Error::State)?.legacy_rates().0 & 0xfff;
            if rates == 0 {
                return Err(Error::Profile);
            }
            let er = if self.er {
                super::packet_format::DATA_ER
            } else {
                0
            };
            super::packet_format::FIRMWARE_RA | er | rates.trailing_zeros() as u8
        } else if kind == Kind::Data && self.wmm.is_some() {
            let rates = self.plan.as_ref().ok_or(Error::State)?.legacy_rates().0;
            [11, 10, 9, 8, 7, 6, 3, 5, 4, 2, 1, 0]
                .into_iter()
                .find(|rate| rates & (1 << rate) != 0)
                .ok_or(Error::Profile)?
        } else {
            // rtw89_core_get_mgmt_rate: CCK1 on 2.4GHz, OFDM6 on 5GHz.
            if self.channel.ofdm_only() {
                super::packet_format::OFDM6
            } else {
                0
            }
        };
        let id = match agg {
            Some(agg) => io.packet_submit_agg(&bytes, false, rate, agg)?,
            None => io.packet_submit_rate(&bytes, kind != Kind::Data, rate)?,
        };
        // rtw89_core_txq_check_agg: an EAPOL frame stops (and forbids for
        // RTW89_FORBID_BA_TIMER) the originator session of its TID.
        if kind == Kind::Security {
            if let Some(tid) = super::packet_format::qos_tid(&bytes).map(|t| t & 7) {
                if self.originator.stop(tid) {
                    self.stop_originator(tid, true);
                }
                let until = self.last_now.saturating_add(super::block_ack::FORBID_MS);
                self.originator.forbid(tid, until);
            }
        }
        self.pending.push_back(Pending {
            id,
            bytes,
            kind,
            agg: agg.is_some(),
        });
        Ok(())
    }
    fn cache(&mut self, frame: &Mpdu, now: u64) {
        // This native profile exposes no calibrated per-frame dBm estimate.
        let signal = None;
        let own = self.scan.unwrap_or(self.own);
        let observed = self.observe_tuned(frame, own, signal);
        let Ok(candidate) = observed else {
            return;
        };
        // cfg80211 `beacon_found` for this dwell's witness: an actual Beacon
        // (not a probe response) observed on the tuned primary.
        if let Some(generation) = self.witness_scan.filter(|_| self.scanning) {
            if frame.bytes().first() == Some(&0x80)
                && candidate.bss.channel == self.channel.primary()
                && candidate.bss.beacon_interval != 0
            {
                let _ = self
                    .witness
                    .beacon_found(generation, center(self.channel.primary()));
            }
        }
        if !basic_ok(self.channel.ofdm_only(), candidate.basic_rates) {
            return;
        }
        if self
            .peer
            .as_ref()
            .is_some_and(|peer| peer.bss.bssid == candidate.bss.bssid)
        {
            self.last_peer = now;
        }
        if let Some(entry) = self
            .cache
            .iter_mut()
            .find(|entry| entry.candidate.bss.bssid == candidate.bss.bssid)
        {
            *entry = Entry {
                candidate,
                seen: now,
            };
        } else {
            if self.cache.len() == 32 {
                let oldest = self
                    .cache
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.seen)
                    .map(|(index, _)| index)
                    .unwrap_or(0);
                self.cache.swap_remove(oldest);
            }
            self.cache.push(Entry {
                candidate,
                seen: now,
            });
        }
    }
    fn lost(&self, frame: &Mpdu) -> bool {
        let Some(peer) = &self.peer else {
            return false;
        };
        let bytes = frame.bytes();
        bytes.len() >= 26
            && matches!(bytes[0], 0xa0 | 0xc0)
            && bytes[1] & 0xc7 == 0
            && bytes[22] & 15 == 0
            && bytes[10..16] == peer.bss.bssid
            && bytes[16..22] == peer.bss.bssid
            && (bytes[4..10] == self.own || bytes[4..10] == [255; 6])
    }
    /// mac80211 `ieee80211_sta_wmm_params` on a bound peer beacon/probe
    /// response. An unchanged parameter-set count (and U-APSD bit) is
    /// ignored, and so is a beacon without a valid WMM Parameter element
    /// (`_ieee80211_sta_wmm_params` returns before touching the set). A new
    /// count on an established peer queues an EDCA update that the async
    /// owner applies; an inadmissible set or a change before the link is
    /// open still closes the station.
    /// `association::observe` on the tuned channel, band-qualified: a 6GHz
    /// tuning observes with `band = Ghz6` (`observe_6ghz`).
    fn observe_tuned(
        &self,
        frame: &Mpdu,
        own: [u8; 6],
        signal: Option<i8>,
    ) -> Result<ObservedBss, association::Error> {
        if self.channel.band() == super::operating_channel_c::Band::Ghz6 {
            association::observe_6ghz(frame, self.channel.primary(), own, signal)
        } else {
            association::observe(frame, self.channel.primary(), own, signal)
        }
    }
    fn observe_wmm(&mut self, frame: &Mpdu) -> Result<(), Error> {
        let (Some(current), Some(peer)) = (self.wmm, &self.peer) else {
            return Ok(());
        };
        let Some(candidate) = self
            .observe_tuned(frame, self.own, None)
            .ok()
            .filter(|candidate| candidate.bss.bssid == peer.bss.bssid)
        else {
            return Ok(());
        };
        let offered = narf_wireless::wmm::Parameters::parse(&candidate.bss.information_elements)
            .ok()
            .flatten();
        // `_ieee80211_sta_wmm_params` (mac80211 mlme.c): a beacon without a
        // (valid) WMM Parameter element leaves the current EDCA set as is.
        let Some(offered) = offered else {
            return Ok(());
        };
        let base = self.edca_pending.unwrap_or(current);
        if offered == base
            || (offered.parameter_set_count == base.parameter_set_count
                && offered.uapsd == base.uapsd)
        {
            return Ok(());
        }
        if self.phase != Phase::Open
            || offered.uapsd != current.uapsd
            || super::station_control::wmm_admit(offered, self.short_slot, self.channel.ofdm_only())
                .is_err()
        {
            return Err(Error::PeerLost);
        }
        self.edca_pending = Some(offered);
        Ok(())
    }
    /// mac80211 `ieee80211_sta_process_chanswitch` for a bound peer beacon
    /// on the current primary (source BEACON). While a switch is active: the
    /// first beacon after the switch ends it (`ieee80211_chswitch_post_beacon`,
    /// TX unblocked) and is then treated as a fresh beacon; a beacon without
    /// CSA before the switch aborts it (`ieee80211_sta_abort_chanswitch`);
    /// otherwise it is disregarded. A new announcement to another band or an
    /// unadmitted primary drops the connection ("switches to unsupported
    /// channel"); one to the current primary is ignored. The 20MHz link
    /// keeps 20MHz on the target (CSA chandef downgraded to the link's
    /// connection mode), so secondary/wide-bandwidth elements are not used.
    /// A wide link follows to the target wide chandef (`Switch.wide`):
    /// the Wide Bandwidth element, or the current width/center at the
    /// new primary; an unusable wide target drops the connection.
    fn observe_csa(&mut self, io: &mut impl Io, frame: &Mpdu, now: u64) -> Result<(), Error> {
        if self.phase != Phase::Open || frame.bytes().first() != Some(&0x80) {
            return Ok(());
        }
        let Some(peer) = self.peer.as_ref().map(|peer| peer.bss.bssid) else {
            return Ok(());
        };
        let six_ghz = self.channel.band() == super::operating_channel_c::Band::Ghz6;
        let observed = self.observe_tuned(frame, self.own, None);
        let Some(candidate) = observed
            .ok()
            .filter(|candidate| candidate.bss.bssid == peer)
        else {
            return Ok(());
        };
        // No native 6GHz channel-switch owner: like a wide link that cannot
        // follow (`ieee80211_sta_process_chanswitch` -> connection loss), a
        // 6GHz link drops on any switch announcement.
        if six_ghz {
            return match channel_switch(&candidate.bss.information_elements, 0) {
                Some(_) => Err(Error::PeerLost),
                None => Ok(()),
            };
        }
        let announced = channel_switch(&candidate.bss.information_elements, self.channel.primary());
        if let Some(active) = self.csa {
            if active.switched {
                self.csa = None;
            } else {
                if announced.is_none() {
                    self.csa = None;
                }
                return Ok(());
            }
        }
        let Some(announced) = announced else {
            return Ok(());
        };
        let Some(primary) = announced.primary else {
            return Err(Error::PeerLost);
        };
        if primary == self.channel.primary() {
            return Ok(());
        }
        if !channel_admitted(io.station_channels()?, primary) {
            return Err(Error::PeerLost);
        }
        let policy = io.station_regulatory()?;
        // A wide link follows to the target wide chandef; an unusable
        // target drops the connection, as for a 20MHz link.
        let wide = match self.wide {
            Some(current) => Some(
                wide_target(
                    &candidate.bss.information_elements,
                    primary,
                    current,
                    &io.station_wide_channels()?,
                    policy.as_ref(),
                )
                .ok_or(Error::PeerLost)?,
            ),
            None => None,
        };
        // mac80211 `ieee80211_sta_process_chanswitch` drops the connection
        // on an unusable target. A passive-only (RADAR / NO_IR) target is
        // usable here only under a current beacon witness for it. A wide
        // target already passed its stricter rule (every subchannel
        // active), so it needs no witness check.
        if wide.is_none() {
            if let Some(policy) = &policy {
                if !self.witness.may_associate(policy, &[center(primary)]) {
                    return Err(Error::PeerLost);
                }
            }
        }
        // csa_time_tu = (max(count, 1) - 1) * beacon_int.
        let tu = u64::from(announced.count.max(1) - 1) * u64::from(candidate.bss.beacon_interval);
        self.csa = Some(Switch {
            primary,
            at_ms: now.saturating_add((tu * 1024).div_ceil(1000)),
            block_tx: announced.mode,
            switched: false,
            wide,
        });
        Ok(())
    }
    /// `csa.blocked_tx`, or the switch time has come (queues stopped for
    /// `ieee80211_csa_switch_work`'s flush/retune).
    fn csa_blocks_tx(&self) -> bool {
        self.csa.is_some_and(|csa| {
            csa.block_tx || !csa.switched && self.environment.now_ms() >= csa.at_ms
        })
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn channel_switch(&self) -> Option<Switch> {
        self.csa
    }
    fn channel_switch_due(&self) -> bool {
        self.phase == Phase::Open
            && self
                .csa
                .is_some_and(|csa| !csa.switched && self.environment.now_ms() >= csa.at_ms)
    }
    /// `ieee80211_csa_switch_work` -> rtw89 chanctx switch (`Io::station_switch_channel`,
    /// or `Io::station_switch_wide_channel` for a wide link) once every TX
    /// in flight retired; the installed peer stays. A `Busy` native
    /// refusal or TX still in flight retries on a later worker pass
    /// within one second of the switch time, then the link fails like a
    /// mac80211 switch failure. Afterwards the beacon monitor restarts
    /// (`ieee80211_sta_reset_beacon_monitor`) and TX stays blocked (if
    /// requested) until the first beacon on the target.
    pub(super) async fn switch_channel(&mut self, io: &mut impl Io) -> Result<(), Error> {
        let Some(csa) = self.csa.filter(|csa| !csa.switched) else {
            return Ok(());
        };
        if self.phase != Phase::Open || !typed(csa.primary) {
            return Err(Error::State);
        }
        // A wide link follows to the target chandef recorded at
        // announcement time; without one (defensive: announcement time
        // already failed it) the link fails instead of narrowing
        // silently, like a mac80211 switch failure.
        let wide = match self.wide {
            Some(_) => Some(match csa.wide {
                Some(target) => target,
                None => {
                    if !self.admission.teardown_pending() {
                        self.fail(io);
                    }
                    return Err(Error::PeerLost);
                }
            }),
            None => None,
        };
        let now = self.now()?;
        let quiet = self.pending.is_empty()
            && self.fragment_tx.is_none()
            && self.fragment_wait.is_none()
            && self.delivered_reply.is_none();
        // Re-check the witness at the switch: the target's passive TX grant
        // follows only a still-current witness under the current policy.
        let policy = io.station_regulatory()?;
        let grant = match &policy {
            Some(policy) if passive_only(Some(policy), csa.primary) => {
                if !self.witness.may_associate(policy, &[center(csa.primary)]) {
                    if !self.admission.teardown_pending() {
                        self.fail(io);
                    }
                    return Err(Error::PeerLost);
                }
                Some((csa.primary, policy.clone()))
            }
            _ => None,
        };
        // Re-check wide subchannels at the switch: the policy may have
        // changed since announcement, and a wide target needs every
        // subchannel active (a passive primary grant cannot cover it).
        if let Some(target) = wide {
            if !target
                .subchannels()
                .all(|ch| !passive_only(policy.as_ref(), ch))
            {
                if !self.admission.teardown_pending() {
                    self.fail(io);
                }
                return Err(Error::PeerLost);
            }
        }
        let result = if quiet {
            match wide {
                Some(target) => {
                    io.station_switch_wide_channel(target, &self.admission)
                        .await
                }
                None => {
                    io.station_switch_channel(csa.primary, &self.admission)
                        .await
                }
            }
        } else {
            Err(power::Error::Busy)
        };
        let result = match result {
            Ok(epoch) if grant.is_some() => io.station_passive_tx(grant).map(|()| epoch),
            other => other,
        };
        match result {
            Ok(epoch) => {
                self.channel = OperatingChannel::legacy(csa.primary);
                self.wide = wide;
                self.epoch = Some(epoch);
                if let Some(peer) = self.peer.as_mut() {
                    // An ECSA may move the link to the other band.
                    peer.bss.channel = csa.primary;
                    peer.bss.band = association::channel::band(csa.primary);
                }
                // rtw89_track_work statistics belong to the old primary.
                self.track = super::track::Tracker::default();
                self.last_peer = now;
                self.csa = Some(Switch {
                    switched: true,
                    ..csa
                });
                Ok(())
            }
            Err(power::Error::Busy) if now < csa.at_ms.saturating_add(1000) => Ok(()),
            Err(error) => {
                if !self.admission.teardown_pending() {
                    self.fail(io);
                }
                Err(match error {
                    power::Error::Busy => Error::State,
                    error => Error::Native(error),
                })
            }
        }
    }
    /// After `Originator::stop`: `TX_STOP_*` reaches the driver (RA limit),
    /// and a locally requested stop (`AGG_STOP_LOCAL_REQUEST`) sends DELBA
    /// as initiator with `WLAN_REASON_QSTA_NOT_USE` (`ieee80211_stop_tx_ba_cb`).
    fn stop_originator(&mut self, tid: u8, local: bool) {
        self.ba_ops.push_back(BaOp::TxLimit);
        if local {
            if let Some(peer) = self.peer.as_ref().map(|p| p.bss.bssid) {
                self.mgmt_out.push_back(super::block_ack::delba_initiator(
                    self.own,
                    peer,
                    tid,
                    super::block_ack::REASON_NOT_USE,
                ));
            }
        }
    }
    /// Operational originator sessions (bitmap by TID).
    pub(super) fn tx_block_ack_sessions(&self) -> u8 {
        (0..8u8).fold(0, |m, tid| {
            if self.originator.aggregating(tid).is_some() {
                m | 1 << tid
            } else {
                m
            }
        })
    }
    fn clear_block_ack(&mut self) {
        // Drop discards ownership only (shared Reorder contract). Station
        // teardown is AGG_STOP_DESTROY_STA: no DELBA.
        self.originator = Box::default();
        self.ampdu = false;
        self.ba = core::array::from_fn(|_| None);
        self.ba_ops.clear();
        self.mgmt_out.clear();
    }
    fn queue_incoming(&mut self, frames: Vec<Mpdu>) -> Result<(), Error> {
        for frame in frames {
            if self.incoming.len() == 64 {
                return Err(Error::State);
            }
            self.incoming.push_back(frame);
        }
        Ok(())
    }
    /// mac80211 Block Ack receive steps for an open link: ADDBA/DELBA
    /// actions, BlockAckReq and reorder admission of QoS DATA on a live
    /// session. Returns the frame when it continues the ordinary path.
    fn block_ack_rx(&mut self, frame: Mpdu, now: u64) -> Result<Option<Mpdu>, Error> {
        use super::block_ack as ba;
        let control = frame.bytes().first().is_some_and(|fc| fc & 0x0c == 0x04);
        let Some(peer) = self.peer.as_ref().map(|p| p.bss.bssid) else {
            return Ok((!control).then_some(frame));
        };
        if self.phase != Phase::Open {
            return Ok((!control).then_some(frame));
        }
        let now_ns = now.saturating_mul(1_000_000);
        if let Some(action) = ba::parse_action(frame.bytes(), self.own, peer) {
            match action {
                ba::Action::AddbaRequest(request) => {
                    let (status, buf) = ba::decide(&request, self.ht);
                    if status == ba::STATUS_SUCCESS {
                        let tid = usize::from(request.tid);
                        if self.ba[tid].take().is_some() {
                            self.ba_ops.push_back(BaOp::Stop(request.tid));
                        }
                        self.ba_ops.push_back(BaOp::Start(request, buf));
                    } else {
                        self.mgmt_out.push_back(ba::addba_response(
                            self.own,
                            peer,
                            &request,
                            status,
                            request.buf_size,
                        ));
                    }
                }
                ba::Action::AddbaResponse {
                    token,
                    status,
                    tid,
                    buf_size,
                    amsdu,
                } => {
                    // Sticky directional peer denial also constrains a
                    // separately qualified expanded A-MSDU emitter.
                    if self.ampdu {
                        let requested = matches!(
                            self.originator.tids.get(usize::from(tid)).copied().flatten(),
                            Some(ba::TxState::Requested { token: t, .. }) if t == token
                        );
                        if self
                            .originator
                            .response(token, status, tid, buf_size, amsdu)
                            .is_some()
                        {
                            self.ba_ops.push_back(BaOp::TxOperational(tid));
                        } else if requested {
                            // AGG_STOP_DECLINED: TX_STOP, no DELBA.
                            self.ba_ops.push_back(BaOp::TxLimit);
                        }
                    }
                }
                ba::Action::Delba {
                    tid,
                    initiator: false,
                    ..
                } => {
                    // ieee80211_process_delba from the recipient:
                    // AGG_STOP_PEER_REQUEST, no DELBA back.
                    if self.originator.stop(tid) {
                        self.stop_originator(tid, false);
                    }
                }
                ba::Action::Delba {
                    tid,
                    initiator: true,
                    ..
                } => {
                    if self
                        .ba
                        .get_mut(usize::from(tid))
                        .and_then(Option::take)
                        .is_some()
                    {
                        self.ba_ops.push_back(BaOp::Stop(tid));
                    }
                }
                _ => {}
            }
            return Ok(None);
        }
        if let Some((tid, ssn)) = ba::bar(frame.bytes(), self.own, peer) {
            if let Some(session) = self.ba.get_mut(usize::from(tid)).and_then(Option::as_mut) {
                session.last_ms = now;
                let released = session.reorder.advance(ssn, now_ns).unwrap_or_default();
                self.queue_incoming(released)?;
            }
            return Ok(None);
        }
        if control {
            // Only BlockAckReq is consumed; other control frames carry no
            // host state for this station.
            return Ok(None);
        }
        if frame.bytes().get(10..16) == Some(&peer[..]) {
            if let Some((tid, sequence)) = ba::qos_sequence(frame.bytes()) {
                if let Some(session) = self.ba.get_mut(usize::from(tid)).and_then(Option::as_mut) {
                    session.last_ms = now;
                    // Old/duplicate sequence numbers are dropped (mac80211
                    // ieee80211_sta_manage_reorder_buf).
                    let released = session
                        .reorder
                        .push(sequence, now_ns, frame)
                        .unwrap_or_default();
                    self.queue_incoming(released)?;
                    return Ok(None);
                }
            }
        }
        Ok(Some(frame))
    }
    /// Reorder release timer and session inactivity timeout
    /// (`sta_rx_agg_reorder_timer_expired`, `sta_rx_agg_session_timer_expired`).
    fn block_ack_tick(&mut self, now: u64) -> Result<(), Error> {
        let now_ns = now.saturating_mul(1_000_000);
        let peer = self.peer.as_ref().map(|p| p.bss.bssid);
        // sta_addba_resp_timer_expired -> ieee80211_stop_tx_ba_session.
        let expired: Vec<u8> = self.originator.expired(now).collect();
        for tid in expired {
            self.originator.stop(tid);
            self.stop_originator(tid, true);
        }
        for tid in 0..8u8 {
            let Some(session) = self.ba[usize::from(tid)].as_mut() else {
                continue;
            };
            let released = session.reorder.expire(now_ns).unwrap_or_default();
            let idle_ms = (u64::from(session.timeout_tu) * 1024).div_ceil(1000);
            let expired = session.timeout_tu != 0 && now.saturating_sub(session.last_ms) > idle_ms;
            self.queue_incoming(released)?;
            if expired {
                self.ba[usize::from(tid)] = None;
                self.ba_ops.push_back(BaOp::Stop(tid));
                if let Some(peer) = peer {
                    self.mgmt_out.push_back(super::block_ack::delba(
                        self.own,
                        peer,
                        tid,
                        super::block_ack::REASON_TIMEOUT,
                    ));
                }
            }
        }
        Ok(())
    }
    /// Live Block Ack sessions (bitmap by TID).
    pub(super) fn block_ack_sessions(&self) -> u8 {
        self.ba
            .iter()
            .enumerate()
            .fold(0, |m, (tid, s)| if s.is_some() { m | 1 << tid } else { m })
    }
    /// Work that needs awaited firmware receipts (EDCA, BA CAM).
    fn sleep_timer_due(&self) -> bool {
        let now = self.environment.now_ms();
        self.originator.expired(now).next().is_some()
            || self.ba.iter().flatten().any(|session| {
                session.timeout_tu != 0
                    && now.saturating_sub(session.last_ms)
                        > (u64::from(session.timeout_tu) * 1024).div_ceil(1000)
            })
    }
    pub(super) fn async_pending(&self) -> bool {
        self.edca_pending()
            || self.channel_switch_due()
            || self.sleep_timer_due()
            || self.phase == Phase::Open && !self.ba_ops.is_empty()
            || !matches!(self.phase, Phase::Prepared | Phase::Failed | Phase::Stopped)
                && self.track.due(self.environment.now_ms())
    }
    pub(super) async fn apply_async(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if self.edca_pending() {
            self.apply_edca(io).await?;
        }
        if self.channel_switch_due() {
            self.switch_channel(io).await?;
        }
        if !matches!(self.phase, Phase::Prepared | Phase::Failed | Phase::Stopped) {
            self.track(io).await?;
        }
        while let Some(op) = self.ba_ops.pop_front() {
            if self.phase != Phase::Open {
                return Err(Error::State);
            }
            let result = match op {
                BaOp::Start(request, buf) => {
                    let result = io
                        .station_configure_ba(true, request.tid, buf, request.ssn, &self.admission)
                        .await;
                    if result.is_ok() {
                        let mut reorder = narf_wireless::reorder::Reorder::new(
                            buf as u8,
                            super::block_ack::REORDER_TIMEOUT_NS,
                        )
                        .map_err(|_| Error::State)?;
                        // mac80211 head_seq_num = start_seq_num.
                        let now = self.now()?;
                        let _ = reorder.advance(request.ssn, now.saturating_mul(1_000_000));
                        self.ba[usize::from(request.tid)] = Some(super::block_ack::Session {
                            reorder,
                            timeout_tu: request.timeout,
                            last_ms: now,
                            ssn: request.ssn,
                        });
                        let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                        self.mgmt_out.push_back(super::block_ack::addba_response(
                            self.own,
                            peer,
                            &request,
                            super::block_ack::STATUS_SUCCESS,
                            buf,
                        ));
                    }
                    result
                }
                BaOp::Stop(tid) => {
                    io.station_configure_ba(false, tid, 0, 0, &self.admission)
                        .await
                }
                BaOp::TxOperational(tid) => {
                    match self.originator.responded(tid) {
                        Some(buf) => {
                            let limit = self.originator.min_agg().map_or(buf, |m| m.min(buf));
                            let result = io
                                .station_configure_agg_limit(Some(limit), &self.admission)
                                .await;
                            if result.is_ok() {
                                self.originator.operational(tid);
                            }
                            result
                        }
                        // Stopped while the programming was queued.
                        None => Ok(()),
                    }
                }
                BaOp::TxLimit => {
                    io.station_configure_agg_limit(self.originator.min_agg(), &self.admission)
                        .await
                }
            };
            if let Err(error) = result {
                if !self.admission.teardown_pending() {
                    self.fail(io);
                }
                return Err(Error::Native(error));
            }
        }
        Ok(())
    }
    pub(super) fn ht(&self) -> bool {
        self.ht
    }
    pub(super) fn he(&self) -> bool {
        self.he
    }
    pub(super) fn qos_all(&self) -> bool {
        self.qos_all && self.wmm.is_some()
    }
    /// 802.1d TID for an outgoing Ethernet frame: classified and ACM
    /// downgraded with the all-AC program, otherwise the BE/TID0 recipe.
    fn tid(&self, frame: &[u8]) -> u8 {
        match self.wmm {
            Some(p) if self.qos_all => {
                super::qos::tid_for(frame, p.ac.map(|ac| ac.admission_control))
            }
            _ => 0,
        }
    }
    pub(super) fn edca_pending(&self) -> bool {
        self.edca_pending.is_some() && self.phase == Phase::Open
    }
    /// Apply a queued live EDCA change through the source H2C path.
    pub(super) async fn apply_edca(&mut self, io: &mut impl Io) -> Result<(), Error> {
        let Some(next) = self.edca_pending else {
            return Ok(());
        };
        if self.phase != Phase::Open || self.wmm.is_none() {
            return Err(Error::State);
        }
        let result = io
            .station_update_wmm(next, self.short_slot, &self.admission)
            .await;
        match result {
            Ok(()) => {
                self.wmm = Some(next);
                if self.edca_pending == Some(next) {
                    self.edca_pending = None;
                }
                Ok(())
            }
            Err(error) => {
                if !self.admission.teardown_pending() {
                    self.fail(io);
                }
                Err(Error::Native(error))
            }
        }
    }
    fn delivery(&mut self, delivery: Receipt) -> Result<(), Error> {
        let index = self
            .pending
            .iter()
            .position(|pending| pending.id == delivery.id)
            .ok_or(Error::State)?;
        self.fragment_delivered(delivery.id)?;
        let pending = self.pending.remove(index).ok_or(Error::State)?;
        if pending.id != delivery.id || pending.bytes != delivery.bytes {
            return Err(Error::State);
        }
        if !delivery.radio_acknowledged
            && !matches!(pending.kind, Kind::Data | Kind::Action | Kind::Probe)
        {
            return Err(Error::State);
        }
        if pending.kind == Kind::Security {
            self.delivered_reply = Some(pending);
        }
        Ok(())
    }
    pub(super) fn poll(&mut self, io: &mut impl Io) -> Result<Vec<Vec<u8>>, Error> {
        let admission = self.admission.clone();
        let result = admission
            .run(|| Ok(self.progress(io)))
            .map_err(Error::Native)
            .and_then(|result| result);
        if result.is_err() && !self.admission.teardown_pending() {
            self.fail(io);
        }
        result
    }
    fn progress(&mut self, io: &mut impl Io) -> Result<Vec<Vec<u8>>, Error> {
        if self.admission.closed()
            || matches!(self.phase, Phase::Prepared | Phase::Failed | Phase::Stopped)
        {
            return Err(Error::State);
        }
        io.station_allowed()?;
        let now = self.now()?;
        let mut idle = false;
        self.rx_idle = false;
        for _ in 0..32 {
            let step = io.packet_poll()?;
            if self.phase == Phase::Open {
                if let Some(allowed) = step.c2h.as_deref().and_then(super::he_htc::rate_allows) {
                    self.htc_rate = allowed;
                }
                if let Some(limit) = step
                    .c2h
                    .as_deref()
                    .and_then(|bytes| super::tx_amsdu::rate_limit(bytes, self.he))
                {
                    self.amsdu_rc = Some(limit);
                }
            }
            if let Some(rssi) = step.rssi {
                self.track.sample(self.linked(), rssi);
            }
            if let Some(cfo) = step.cfo {
                self.track.sample_cfo(self.linked(), cfo);
            }
            if let Some(receipt) = step.receipt {
                self.delivery(receipt)?;
            }
            if !step.consumed_rx {
                idle = true;
                break;
            }
            if let Some(frame) = step.frame {
                let Some(frame) = self.admit_management(frame)? else {
                    continue;
                };
                if self.phase == Phase::Open && self.mgmt_out.len() < 8 {
                    let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                    if let Some(response) = sa_query_response(frame.bytes(), self.own, peer) {
                        self.mgmt_out.push_back(response);
                        continue;
                    }
                }
                self.observe_wmm(&frame)?;
                self.observe_csa(io, &frame, now)?;
                if self.lost(&frame) {
                    return Err(Error::PeerLost);
                }
                // Every fragment retains its original header until Security
                // authenticates it. Never collapse equal-SN fragments in BA
                // reorder/duplicate machinery before defragmentation.
                let fragment = super::fragment_rx::fragmented(frame.bytes());
                if fragment
                    && super::packet_format::qos_tid(frame.bytes())
                        .is_some_and(|tid| self.ba[usize::from(tid & 7)].is_some())
                {
                    continue;
                }
                let frame = match if fragment {
                    Ok(Some(frame))
                } else {
                    self.block_ack_rx(frame, now)
                }? {
                    Some(frame) => frame,
                    None => continue,
                };
                self.cache(&frame, now);
                if self.phase != Phase::Passive {
                    if self.incoming.len() == 64 {
                        return Err(Error::State);
                    }
                    self.incoming.push_back(frame);
                }
            }
        }
        self.rx_idle = idle;
        // A CRC/report descriptor is consumed input, never an RX-idle fence.
        // Inspect all queued peer loss before committing an exact M4 receipt.
        if idle {
            if let Some(receipt) = self.delivered_reply.take() {
                let security = self.security.as_mut().ok_or(Error::State)?;
                if security.pending_frame() != Some(receipt.bytes.as_slice()) {
                    return Err(Error::State);
                }
                security.reply_delivered(receipt.bytes.len())?;
            }
        }
        for _ in 0..64 {
            if !self.pending.is_empty()
                || self.fragment_blocks_incoming()
                || self.delivered_reply.is_some()
                || self.peer_commit.is_some()
                || self
                    .security
                    .as_ref()
                    .is_some_and(|s| s.pending_frame().is_some())
            {
                break;
            }
            let Some(frame) = self.incoming.pop_front() else {
                break;
            };
            match self.phase {
                Phase::Authentication if self.sae.is_some() => {
                    use narf_wireless::association::SaeStep;
                    let plan = self.plan.as_mut().ok_or(Error::State)?;
                    let session = self.sae.as_mut().ok_or(Error::State)?;
                    let next = match plan.sae_authentication_response(frame.bytes(), session)? {
                        SaeStep::Ignored => None,
                        SaeStep::Transmit(bytes) => Some((false, bytes.to_vec())),
                        SaeStep::Associate(bytes) => Some((true, bytes.to_vec())),
                    };
                    match next {
                        None => {}
                        Some((false, commit)) => self.transmit(io, commit, Kind::Authentication)?,
                        Some((true, mut association)) => {
                            self.start_sae_security()?;
                            if self.wmm.is_some() {
                                association.extend_from_slice(&narf_wireless::wmm::INFORMATION);
                            }
                            self.phase = Phase::Association;
                            self.transmit(io, association, Kind::Association)?;
                        }
                    }
                }
                Phase::Authentication => {
                    if let Some(mut association) = self
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .authentication_response(frame.bytes())?
                        .map(|bytes| bytes.to_vec())
                    {
                        if self.wmm.is_some() {
                            association.extend_from_slice(&narf_wireless::wmm::INFORMATION);
                        }
                        self.phase = Phase::Association;
                        self.transmit(io, association, Kind::Association)?;
                    }
                }
                Phase::Association => {
                    if let Some(aid) = self
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .association_response(frame.bytes())?
                    {
                        let peer = self.peer.as_ref().ok_or(Error::State)?;
                        let response_cap =
                            u16::from_le_bytes([frame.bytes()[24], frame.bytes()[25]]);
                        // mac80211: 5GHz always uses the short slot time.
                        let short = self.channel.ofdm_only()
                            || peer.bss.capability & response_cap & 0x400 != 0;
                        if self.wmm.is_some() {
                            let p = narf_wireless::wmm::Parameters::parse(
                                frame.bytes().get(30..).ok_or(Error::Profile)?,
                            )
                            .map_err(|_| Error::Profile)?
                            .ok_or(Error::Profile)?;
                            super::station_control::wmm_admit(p, short, self.channel.ofdm_only())?;
                            self.wmm = Some(p);
                        }
                        self.peer_commit = Some((aid, short));
                        self.last_peer = now;
                        // Firmware peer commit is an awaited continuation in associate().
                    }
                }
                Phase::FourWay | Phase::Open => {
                    if let Some(security) = &mut self.security {
                        let handshake_active = security.handshake_active();
                        let environment = &self.environment;
                        let initial = &mut self.initial_nonce;
                        let nonce = || initial.take().or_else(|| environment.nonce());
                        let result = if super::fragment_rx::fragmented(frame.bytes()) {
                            security.receive_fragment_with_nonce(&frame, now, nonce)
                        } else {
                            security.receive_with_nonce(&frame, nonce)
                        }?;
                        match result {
                            station_security::Rx::Data(bytes) => {
                                if let Some(bytes) = ethernet(
                                    &bytes,
                                    self.own,
                                    self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                                ) {
                                    self.last_peer = now;
                                    if self.received.len() == 64 {
                                        return Err(Error::State);
                                    }
                                    self.received.push_back(bytes);
                                }
                            }
                            station_security::Rx::ReplyReady => {
                                if self.established && !handshake_active {
                                    self.deadline = now.saturating_add(5000);
                                }
                            }
                            station_security::Rx::Ignored => {}
                        }
                    } else {
                        let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                        let bytes = if super::fragment_rx::fragmented(frame.bytes()) {
                            self.fragment_plain
                                .get_or_insert_with(super::fragment_rx::Plain::boxed)
                                .push(frame.bytes(), self.own, peer, now)
                        } else {
                            Some(frame.bytes().to_vec())
                        };
                        if let Some(bytes) =
                            bytes.as_deref().and_then(|b| ethernet(b, self.own, peer))
                        {
                            self.last_peer = now;
                            if self.received.len() == 64 {
                                return Err(Error::State);
                            }
                            self.received.push_back(bytes);
                        }
                    }
                }
                _ => {}
            }
        }
        self.fragment_rx_pending = self
            .security
            .as_mut()
            .is_some_and(|s| s.fragment_pending(now))
            || self
                .fragment_plain
                .as_mut()
                .is_some_and(|cache| cache.pending(now));
        self.block_ack_tick(now)?;
        self.progress_fragments(io)?;
        if self.fragment_tx.is_none()
            && self.fragment_wait.is_none()
            && self.pending.is_empty()
            && self.delivered_reply.is_none()
            && self.phase == Phase::Open
            && self
                .security
                .as_ref()
                .is_none_or(|s| s.pending_frame().is_none())
        {
            if let Some(frame) = self.mgmt_out.pop_front() {
                self.transmit(io, frame, Kind::Action)?;
            } else if self.ampdu {
                if let Some((tid, token)) = self.originator.next_request(now) {
                    // ieee80211_tx_ba_session_handle_start: SSN is the next
                    // QoS SN of the TID, sampled with nothing in flight.
                    let ssn = match &self.security {
                        Some(security) => security.next_qos_sequence(tid)?,
                        // Open QoS data shares the station counter, and this
                        // request takes the current value.
                        None => (self.sequence + 1) & 4095,
                    };
                    let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                    let request =
                        super::block_ack::addba_request(self.own, peer, token, tid, ssn, self.he);
                    self.transmit(io, request, Kind::Action)?;
                }
            }
        }
        if self.fragment_tx.is_none()
            && self.fragment_wait.is_none()
            && self.pending.is_empty()
            && self.delivered_reply.is_none()
        {
            if let Some(reply) = self
                .security
                .as_ref()
                .and_then(Security::pending_frame)
                .map(|bytes| bytes.to_vec())
            {
                self.transmit(io, reply, Kind::Security)?;
            }
        }
        if idle
            && self.incoming.is_empty()
            && self.pending.is_empty()
            && self.delivered_reply.is_none()
            && self.phase == Phase::FourWay
            && self.security.as_ref().is_none_or(Security::port_open)
        {
            self.established = true;
            self.phase = Phase::Open;
            self.last_peer = now;
        }
        if self.phase != Phase::Passive {
            let expired = if self.established {
                now.saturating_sub(self.last_peer) >= 5000
                    || now >= self.deadline
                        && self
                            .security
                            .as_ref()
                            .is_some_and(Security::handshake_active)
            } else {
                now >= self.deadline
            };
            if expired {
                return Err(Error::Timeout);
            }
        }
        if idle && self.established && self.security.as_ref().is_none_or(Security::port_open) {
            Ok(self.received.drain(..).collect())
        } else {
            Ok(Vec::new())
        }
    }
    /// PMF management admission before any MLME/BA consumer (mac80211
    /// `ieee80211_drop_unencrypted_mgmt`, host `ieee80211_crypto_ccmp_decrypt`
    /// and `ieee80211_crypto_aes_cmac_decrypt`). Frames from other BSSs and
    /// non-PMF associations pass unchanged; `None` drops the frame.
    fn admit_management(&mut self, frame: Mpdu) -> Result<Option<Mpdu>, Error> {
        let Some(peer) = self.peer.as_ref().map(|p| p.bss.bssid) else {
            return Ok(Some(frame));
        };
        let bytes = frame.bytes();
        if bytes.first().is_none_or(|fc| fc & 0x0c != 0) || bytes.get(10..16) != Some(&peer[..]) {
            return Ok(Some(frame));
        }
        if super::fragment_rx::fragmented(bytes) {
            return Ok(match self.security.as_mut() {
                Some(security) => {
                    match security.receive_management_fragment(&frame, self.last_now)? {
                        station_security::MgmtRx::Ignored => None,
                        station_security::MgmtRx::Frame(bytes) => Some(Mpdu::new(bytes)),
                    }
                }
                None => self
                    .fragment_plain
                    .get_or_insert_with(super::fragment_rx::Plain::boxed)
                    .push(bytes, self.own, peer, self.last_now)
                    .map(Mpdu::new),
            });
        }
        let Some(security) = self.security.as_mut().filter(|s| s.pmf()) else {
            return Ok(Some(frame));
        };
        Ok(match security.receive_management(&frame)? {
            station_security::MgmtRx::Ignored => None,
            station_security::MgmtRx::Frame(bytes) => Some(Mpdu::new(bytes)),
        })
    }
    /// The accepted SAE's PMK becomes the WPA3 key owner (`Security::new_sae`)
    /// before the association request; the SAE session is dropped here.
    fn start_sae_security(&mut self) -> Result<(), Error> {
        let session = self.sae.take().ok_or(Error::State)?;
        let pmk = Zeroizing::new(*session.pmk().ok_or(Error::Profile)?);
        drop(session);
        let plan = self.plan.as_ref().ok_or(Error::State)?;
        let peer = self.peer.as_ref().ok_or(Error::State)?;
        let station_rsne = plan.rsn_body().ok_or(Error::Profile)?;
        let station_rsnxe = plan.sae().and_then(|sae| sae.station_rsnxe());
        self.fragment_plain = None;
        self.security = Some(Security::new_sae(
            self.own,
            peer.bss.bssid,
            &pmk,
            &station_rsne,
            station_rsnxe.as_deref(),
            peer.ap_rsne.as_deref().ok_or(Error::Profile)?,
            peer.ap_rsnxe.as_deref(),
            3,
        )?);
        self.initial_nonce = Some(self.environment.nonce().ok_or(Error::Entropy)?);
        Ok(())
    }
    pub(super) async fn scan_for(
        &mut self,
        io: &mut impl Io,
        dwell_ms: u64,
    ) -> Result<Vec<ObservedBss>, Error> {
        self.scan_with(io, dwell_ms, None).await
    }
    /// Scan the current primary for `dwell_ms`. An active scan first transmits one
    /// probe request per SSID (wildcard when none) like mac80211's software
    /// scan, then listens for the dwell.
    pub(super) async fn scan_with(
        &mut self,
        io: &mut impl Io,
        dwell_ms: u64,
        probe: Option<Probe>,
    ) -> Result<Vec<ObservedBss>, Error> {
        if !(1..=1024).contains(&dwell_ms) {
            return Err(Error::Profile);
        }
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        // mac80211 `ieee80211_scan_state_decision`: a RADAR / NO_IR channel
        // is dwelt passively; no probe request (nor random scan address).
        let six_ghz = self.channel.band() == super::operating_channel_c::Band::Ghz6;
        // 6GHz: the admitted record's own active/passive classification
        // (no beacon witness: RTL8852C grants no passive-only TX).
        let policy = io.station_regulatory()?.filter(|_| !six_ghz);
        let probe = probe.filter(|_| match self.six {
            Some((channel, _)) if six_ghz => channel.active,
            _ => !passive_only(policy.as_ref(), self.channel.primary()),
        });
        // ieee80211_send_scan_probe_req: one get_random_u16() per probe,
        // drawn before any address CAM or RF activity so missing entropy
        // fails the scan without a transmission.
        let random_sn = match &probe {
            Some(p) if p.random_sn => {
                if p.ssids.len() > 8 {
                    return Err(Error::Profile);
                }
                Some(self.environment.nonce().ok_or(Error::Entropy)?)
            }
            _ => None,
        };
        let until = self.now()?.saturating_add(dwell_ms);
        let address = probe.as_ref().and_then(|p| p.address);
        if let Some(address) = address {
            if address[0] & 1 != 0 || address == [0; 6] || address == self.own {
                return Err(Error::Profile);
            }
            // rtw89_core_scan_start: the address CAM SMA follows the random
            // scan address before the first probe request.
            io.station_scan_address(Some(address), &self.admission)
                .await?;
            let admission = self.admission.clone();
            admission.run(|| Ok(io.packet_scan_address(Some(address))))??;
            self.scan = Some(address);
        }
        // A new covering scan retracts this primary's earlier witness.
        self.witness_scan = policy.as_ref().map(|policy| {
            self.witness
                .begin_scan(policy, &[center(self.channel.primary())])
        });
        self.scanning = true;
        let result = self.scan_dwell(io, until, probe, random_sn).await;
        self.scanning = false;
        self.witness_scan = None;
        // A failed dwell is terminal: the interface stops the station.
        if address.is_some() && result.is_ok() {
            // rtw89_core_scan_complete: restore the own address once the last
            // probe request has retired. A failure closes the station.
            let deadline = until.saturating_add(1000);
            while !self.pending.is_empty() {
                self.poll(io)?;
                if !self.pending.is_empty() {
                    if self.now()? >= deadline {
                        return Err(Error::State);
                    }
                    self.environment.pause().await;
                }
            }
            let admission = self.admission.clone();
            admission.run(|| Ok(io.packet_scan_address(None)))??;
            self.scan = None;
            io.station_scan_address(None, &self.admission).await?;
        }
        result
    }
    /// Actual primary of the retained radio.
    pub(super) fn channel(&self) -> u8 {
        self.channel.primary()
    }
    /// Retune the unassociated station to `primary` through the native
    /// owner (`Io::station_retune`). Like mac80211 `ieee80211_offchannel_stop_vifs`
    /// plus `drv_flush`, every pending TX retires first; a `Busy` native
    /// refusal (RX/H2C backlog) is retried after polling, bounded. Cached
    /// candidates keep their own observed channel.
    pub(super) async fn retune(&mut self, io: &mut impl Io, primary: u8) -> Result<(), Error> {
        if !typed(primary) {
            return Err(Error::Profile);
        }
        if self.phase() != Phase::Passive || self.scan.is_some() || self.scanning {
            return Err(Error::State);
        }
        if OperatingChannel::legacy(primary) == self.channel && self.wide.is_none() {
            return Ok(());
        }
        let deadline = self.now()?.saturating_add(1000);
        loop {
            self.poll(io)?;
            if self.pending.is_empty() {
                match io.station_retune(primary, &self.admission).await {
                    Ok(epoch) => {
                        self.channel = OperatingChannel::legacy(primary);
                        self.wide = None;
                        self.six = None;
                        self.epoch = Some(epoch);
                        // rtw89_track_work statistics belong to the old primary.
                        self.track = super::track::Tracker::default();
                        return Ok(());
                    }
                    Err(power::Error::Busy) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if self.now()? >= deadline {
                return Err(Error::State);
            }
            self.environment.pause().await;
        }
    }
    /// [`Self::retune`] to one admitted 40/80MHz operating channel
    /// (`Io::station_retune_wide`): mac80211 `ieee80211_prep_channel` with
    /// the AP chandef the local capability selects (`wide_phy`).
    async fn retune_wide(
        &mut self,
        io: &mut impl Io,
        profile: super::operating_channel::Profile,
    ) -> Result<(), Error> {
        if self.phase() != Phase::Passive || self.scan.is_some() || self.scanning {
            return Err(Error::State);
        }
        if self.wide == Some(profile) {
            return Ok(());
        }
        let deadline = self.now()?.saturating_add(1000);
        loop {
            self.poll(io)?;
            if self.pending.is_empty() {
                match io.station_retune_wide(profile, &self.admission).await {
                    Ok(epoch) => {
                        self.channel = OperatingChannel::legacy(profile.primary());
                        self.wide = Some(profile);
                        self.six = None;
                        self.epoch = Some(epoch);
                        self.track = super::track::Tracker::default();
                        return Ok(());
                    }
                    Err(power::Error::Busy) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if self.now()? >= deadline {
                return Err(Error::State);
            }
            self.environment.pause().await;
        }
    }
    /// [`Self::retune`] to one admitted RTL8852C 6GHz 20MHz channel under
    /// its regd.c power context and TPE constraint (`Io::station_retune_6ghz`).
    /// A changed context or TPE is reprogrammed even on the same primary
    /// (regd.c `rtw89_reg_6ghz_recalc` -> `rtw89_core_set_chip_txpwr`).
    async fn retune_6ghz(
        &mut self,
        io: &mut impl Io,
        channel: super::command_native::SixGhzChannel,
        tpe: Option<i8>,
    ) -> Result<(), Error> {
        if self.phase() != Phase::Passive || self.scan.is_some() || self.scanning {
            return Err(Error::State);
        }
        if self.six == Some((channel, tpe)) {
            return Ok(());
        }
        let deadline = self.now()?.saturating_add(1000);
        loop {
            self.poll(io)?;
            if self.pending.is_empty() {
                match io
                    .station_retune_6ghz(channel, tpe, false, &self.admission)
                    .await
                {
                    Ok(epoch) => {
                        self.channel = OperatingChannel::new(
                            super::operating_channel_c::Band::Ghz6,
                            channel.primary,
                        );
                        self.wide = None;
                        self.six = Some((channel, tpe));
                        self.epoch = Some(epoch);
                        self.track = super::track::Tracker::default();
                        return Ok(());
                    }
                    Err(power::Error::Busy) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if self.now()? >= deadline {
                return Err(Error::State);
            }
            self.environment.pause().await;
        }
    }
    /// The 6GHz part of a cfg80211 scan (`cfg80211_scan_6ghz` as planned by
    /// `narf_wireless::scan::plan_6ghz_scan`) over admitted RTL8852C 6GHz
    /// channels, in order: each is tuned TPE-free under its own power
    /// context and dwelt; a probe follows only on an active record (a
    /// passive-only DFS/NO_IR span is listened to). Results accumulate in
    /// the shared candidate cache with `band = Ghz6`.
    pub(super) async fn scan_six_ghz(
        &mut self,
        io: &mut impl Io,
        channels: &[super::command_native::SixGhzChannel],
        dwell_ms: u64,
        probe: impl Fn(&super::command_native::SixGhzChannel) -> Option<Probe>,
    ) -> Result<Vec<ObservedBss>, Error> {
        if channels.is_empty() || channels.len() > 59 * 3 {
            return Err(Error::Profile);
        }
        for channel in channels {
            self.retune_6ghz(io, *channel, None).await?;
            self.scan_with(io, dwell_ms, probe(channel)).await?;
        }
        Ok(self.candidates())
    }
    /// mac80211 software scan (`ieee80211_scan_state_set_channel`,
    /// `ieee80211_scan_state_send_probe`, then the dwell) over each listed
    /// 2.4GHz or 5GHz primary in order (probe content per band), each retuned by the native owner. Results
    /// from every channel accumulate in the shared candidate cache.
    pub(super) async fn scan_channels(
        &mut self,
        io: &mut impl Io,
        channels: &[u8],
        dwell_ms: u64,
        probe: impl Fn() -> Option<Probe>,
    ) -> Result<Vec<ObservedBss>, Error> {
        if channels.is_empty()
            || channels.len() > 13 + super::operating_channel::GHZ5.len()
            || channels.iter().any(|channel| !typed(*channel))
        {
            return Err(Error::Profile);
        }
        for &channel in channels {
            self.retune(io, channel).await?;
            self.scan_with(io, dwell_ms, probe()).await?;
        }
        Ok(self.candidates())
    }
    async fn scan_dwell(
        &mut self,
        io: &mut impl Io,
        until: u64,
        probe: Option<Probe>,
        random_sn: Option<[u8; 32]>,
    ) -> Result<Vec<ObservedBss>, Error> {
        if let Some(probe) = probe {
            let source = probe.address.unwrap_or(self.own);
            let ssids = if probe.ssids.is_empty() {
                vec![Vec::new()]
            } else {
                probe.ssids
            };
            for (index, ssid) in ssids.into_iter().enumerate() {
                while !self.pending.is_empty() {
                    self.poll(io)?;
                    if self.pending.is_empty() {
                        break;
                    }
                    if self.now()? >= until {
                        return Ok(self.candidates());
                    }
                    self.environment.pause().await;
                }
                let mut frame = if self.channel.band() == super::operating_channel_c::Band::Ghz6 {
                    six::probe_request(source, &ssid, &probe.ies).ok_or(Error::Profile)?
                } else {
                    probe_request(source, &ssid, &probe.ies, self.channel.primary())
                };
                let assign = match random_sn {
                    Some(random) => {
                        // IEEE80211_SN_TO_SEQ(get_random_u16()).
                        let sn = u16::from_le_bytes([random[2 * index], random[2 * index + 1]]);
                        frame[22..24].copy_from_slice(&((sn & 0x0fff) << 4).to_le_bytes());
                        false
                    }
                    None => true,
                };
                let admission = self.admission.clone();
                admission
                    .run(|| Ok(self.transmit_with(io, frame, Kind::Probe, assign, None)))??;
            }
        }
        loop {
            self.poll(io)?;
            if self.now()? >= until {
                return Ok(self.candidates());
            }
            self.environment.pause().await;
        }
    }
    pub(super) async fn associate(
        &mut self,
        io: &mut impl Io,
        bssid: [u8; 6],
        ssid: &[u8],
        credential: Credential,
        ies: &[u8],
    ) -> Result<(), Error> {
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        let candidate = self
            .candidates()
            .into_iter()
            .find(|c| c.bss.bssid == bssid)
            .ok_or(Error::Profile)?;
        let six_ghz = candidate.bss.band == Some(association::channel::Band::Ghz6);
        if !(six_ghz || typed(candidate.bss.channel))
            || !basic_ok(
                six_ghz || ghz5(candidate.bss.channel),
                candidate.basic_rates,
            )
        {
            return Err(Error::Profile);
        }
        let mut plan = if six_ghz {
            // RTL8852C 6GHz: plan first (the admitted power context follows
            // the AP's power type), then tune under it and the AP's TPE.
            let (plan, channel, tpe) = self.six_ghz_join(io, &candidate, ssid, &credential)?;
            self.retune_6ghz(io, channel, tpe).await?;
            plan
        } else {
            // A passive-only (RADAR / NO_IR) primary is joined only under its
            // beacon witness from the latest scan of it (cfg80211 `beacon_found`).
            let policy = io.station_regulatory()?;
            let grant = match &policy {
                Some(policy) => {
                    if !self
                        .witness
                        .may_associate(policy, &[center(candidate.bss.channel)])
                    {
                        return Err(Error::Profile);
                    }
                    passive_only(Some(policy), candidate.bss.channel)
                        .then(|| (candidate.bss.channel, policy.clone()))
                }
                None => None,
            };
            // HT is offered only with an AP WMM element and the signed HT20
            // program (which itself requires WMM and firmware RA).
            let ap_wmm = narf_wireless::wmm::Parameters::parse(&candidate.bss.information_elements)
                .ok()
                .flatten()
                .is_some();
            let ht_allowed = ap_wmm && io.station_wmm_allowed()? && io.station_ht_allowed()?;
            let he_allowed = ht_allowed && io.station_he_allowed()?;
            // A 40/80MHz join needs an admitted wide record for exactly the
            // chandef the AP and local capability select, wholly active (no
            // passive-only subchannel: no beacon witness covers a wide span).
            let one_stream = io.station_single_stream();
            let wide = if ht_allowed {
                let admitted = io.station_wide_channels()?;
                super::station_control::wide_phy(
                    &candidate.bss.information_elements,
                    candidate.bss.channel,
                    he_allowed,
                    one_stream,
                    &admitted,
                )
                .filter(|(_, profile)| {
                    profile
                        .subchannels()
                        .all(|ch| !passive_only(policy.as_ref(), ch))
                })
            } else {
                None
            };
            // mac80211 ieee80211_prep_channel: the station joins on the BSS's
            // own primary (or the selected wide chandef around it); the native
            // owner retunes (signed record required).
            match wide {
                Some((_, profile)) => self.retune_wide(io, profile).await?,
                None => self.retune(io, candidate.bss.channel).await?,
            }
            if grant.is_some() {
                io.station_passive_tx(grant)?;
            }
            // rtw89 sets MFP_CAPABLE: WPA2 offers MFPC (`ieee80211w=1`, PMF and
            // PSK-SHA256 admitted) to an AP that advertises MFPC; otherwise the
            // legacy RSNE is kept. WPA3 is SAE with PMF required.
            let ap_mfpc = candidate
                .ap_rsne
                .as_deref()
                .and_then(narf_wireless::rsn::RsnIe::decode_body)
                .is_some_and(|rsn| {
                    rsn.rsn_capabilities & narf_wireless::rsn::RSN_CAP_MFP_CAPABLE != 0
                });
            let (mode, options) = match &credential {
                Credential::Open => (SecurityMode::Open, JoinOptions::default()),
                Credential::Psk(_) => (
                    SecurityMode::Wpa2Psk,
                    if ap_mfpc {
                        JoinOptions::default()
                            .with_akms(AkmSet::PSK.with(AkmSet::PSK_SHA256))
                            .with_pmf(Pmf::Optional)
                    } else {
                        JoinOptions::default()
                    },
                ),
                Credential::Sae(_) => (
                    SecurityMode::Wpa3Sae {
                        pwe: narf_wireless::association::SaePwe::Both,
                    },
                    JoinOptions::default().with_akms(AkmSet::SAE),
                ),
            };
            let plan = if ht_allowed {
                let local = match wide {
                    Some((local, _)) => local,
                    None => {
                        let mut local = narf_wireless::association::phy::LocalPhy::ht20(
                            super::station_control::local_ht(),
                        )
                        .map_err(|_| Error::Profile)?;
                        // HE is offered only under the signed HE20 program
                        // (which itself requires HT20).
                        if he_allowed {
                            let he = if one_stream {
                                super::station_control::local_he_1ss()
                            } else {
                                super::station_control::local_he()
                            }
                            .ok_or(Error::Profile)?;
                            local = local.with_he(he).map_err(|_| Error::Profile)?;
                        }
                        local
                    }
                };
                JoinPlan::prepare_with_options(
                    &candidate.bss,
                    self.own,
                    ssid,
                    mode,
                    Some(local),
                    options,
                )?
            } else {
                JoinPlan::prepare_with_options(&candidate.bss, self.own, ssid, mode, None, options)?
            };
            // The plan's own selection must be the chandef the radio was tuned to.
            if let Some((_, profile)) = wide {
                let offer = plan.offered_phy().ok_or(Error::Profile)?;
                if offer.center_channel() != profile.center()
                    || offer.occupied_channels().len() != 1 << profile.width() as usize
                {
                    return Err(Error::Profile);
                }
            }
            plan
        };
        plan.append_sme_ies(ies)?;
        if let Credential::Sae(password) = &credential {
            use narf_wireless::sae::{SaeError, SaeSession};
            let join = plan.sae().ok_or(Error::Profile)?;
            let mut session = if join.h2e() {
                SaeSession::new_h2e_bytes(ssid, password, self.own, bssid)
            } else {
                SaeSession::new_hunt_and_peck(password, self.own, bssid)
            };
            if let Some(selector) = join.akm_suite_selector() {
                session = session
                    .with_akm_suite_selector(selector)
                    .map_err(|_| Error::Profile)?;
            }
            let mut session = Box::new(session);
            let environment = self.environment.clone();
            session
                .try_build_commit_with_entropy(|out| {
                    for chunk in out.chunks_mut(32) {
                        let random = environment.nonce().ok_or(SaeError::EntropyUnavailable)?;
                        chunk.copy_from_slice(&random[..chunk.len()]);
                    }
                    Ok(())
                })
                .map_err(|_| Error::Entropy)?;
            self.sae = Some(session);
        }
        if let Credential::Psk(pmk) = credential {
            let nonce = self.environment.nonce().ok_or(Error::Entropy)?;
            let station_rsne = plan.rsn_body().ok_or(Error::Profile)?;
            self.fragment_plain = None;
            self.fragment_rx_pending = false;
            self.security = Some(Security::new(
                self.own,
                bssid,
                &pmk,
                &station_rsne,
                candidate.ap_rsne.as_deref().ok_or(Error::Profile)?,
                candidate.ap_rsnxe.as_deref(),
                3,
            )?);
            self.initial_nonce = Some(nonce);
        }
        let mut attempt = Attempt {
            admission: self.admission.clone(),
            armed: true,
        };
        let offered = narf_wireless::wmm::Parameters::parse(&candidate.bss.information_elements)
            .map_err(|_| Error::Profile)?;
        self.wmm = if io.station_wmm_allowed()? {
            offered
        } else {
            None
        };
        if let Some(p) = self.wmm {
            let band5 = six_ghz || ghz5(candidate.bss.channel);
            super::station_control::wmm_admit(
                p,
                band5 || candidate.bss.capability & 0x400 != 0,
                band5,
            )?;
        }
        self.qos_all = self.wmm.is_some() && io.station_qos_all_allowed()?;
        self.firmware_ra = self.wmm.is_some() && io.station_firmware_ra_allowed()?;
        io.station_prepare_peer(bssid, &self.admission).await?;
        self.csa = None;
        self.peer = Some(candidate);
        self.deadline = self.now()?.saturating_add(5000);
        self.last_peer = self.last_now;
        let auth = match self.sae.as_deref() {
            Some(session) => plan.start_sae_authentication(session)?.to_vec(),
            None => plan.start_authentication()?.to_vec(),
        };

        self.plan = Some(plan);
        self.phase = Phase::Authentication;
        let admission = self.admission.clone();
        admission.run(|| Ok(self.transmit(io, auth, Kind::Authentication)))??;
        loop {
            self.poll(io)?;
            if let Some((aid, short)) = self.peer_commit {
                io.station_commit_peer(bssid, aid, short, &self.admission)
                    .await?;
                self.short_slot = short;
                if let Some(p) = self.wmm {
                    io.station_configure_wmm(p, short, &self.admission).await?;
                    if self.firmware_ra {
                        let plan = self.plan.as_ref().ok_or(Error::State)?;
                        // phy.c rtw89_phy_ra_sta_update: a 5GHz peer's
                        // supp_rates[5GHz] << 4 is OFDM-only (no RA CCK mode).
                        let rates = plan.legacy_rates().0
                            & if self.channel.ofdm_only() {
                                0xff0
                            } else {
                                0xfff
                            };
                        let ht = plan.negotiated_phy().map(|phy| {
                            let ht = phy.ht();
                            let m = ht.peer_rx_mcs();
                            super::station_control::HtRa {
                                peer_rx_mcs: [m[0], m[1], m[2], m[3]],
                                sgi20: ht.tx_sgi20(),
                                ldpc: ht.tx_ldpc(),
                            }
                        });
                        // 6GHz: the HE negotiation of the 6GHz plan (no
                        // HT/VHT; `rtw89_phy_ra_sta_update` HE branch on
                        // RTW89_BAND_6G, `station_control::codec::ra_he6`).
                        let he = plan
                            .negotiated_phy()
                            .and_then(|phy| phy.he())
                            .or_else(|| plan.six_ghz().map(|six| six.he()))
                            .map(|he| {
                                let peer = he.peer_capability().phy_capability();
                                (
                                    super::station_control::HeRa {
                                        peer_rx_mcs: he.tx_mcs_map(),
                                        ldpc: he.tx_ldpc(),
                                        dcm: peer[3] & 0x18 != 0,
                                    },
                                    !he.operation().er_su_disabled(),
                                )
                            });
                        self.ht = ht.is_some();
                        self.he = he.is_some();
                        self.density = plan
                            .negotiated_phy()
                            .map_or(0, |phy| phy.ht().peer_mpdu_density());
                        // HE-only (6GHz) aggregates too: negotiated HT is
                        // absent on 6GHz, but HE BA sessions carry TX
                        // A-MPDU (density 0: Linux's zeroed 6GHz ht_cap).
                        self.ampdu = (self.ht || self.he) && io.station_ampdu_allowed()?;
                        self.er = he.is_some_and(|(_, er)| er);
                        let he = he.map(|(he, _)| he);
                        match self.wide {
                            // rtw89_phy_ra_sta_update on the tuned wide
                            // chandef: bw_cap, bandwidth SGI, VHT branch
                            // (160MHz: RTL8852C only, `admitted_wide`).
                            Some(profile) => {
                                let phy = plan.negotiated_phy().ok_or(Error::Profile)?;
                                let bw = match phy.width() {
                                    association::phy::Width::Forty => 1,
                                    association::phy::Width::Eighty => 2,
                                    association::phy::Width::OneSixty if !phy.discontiguous() => 3,
                                    _ => return Err(Error::Profile),
                                };
                                // IEEE80211_STA_RX_BW_160 needs the HE
                                // width (when HE) at 160MHz too.
                                if bw != profile.width() as u8
                                    || phy.center_channel() != profile.center()
                                    || bw == 3
                                        && phy.he().is_some_and(|he| {
                                            he.width() != association::phy::Width::OneSixty
                                        })
                                {
                                    return Err(Error::Profile);
                                }
                                let vht = phy.vht().map(|vht| super::station_control::VhtRa {
                                    peer_rx_mcs: vht.tx_mcs_map(),
                                    ldpc: vht.tx_ldpc(),
                                });
                                // phy.c rtw89_phy_ra_gi_ltf: RTL8852C at
                                // RTW89_CHANNEL_WIDTH_160 fixes SGI_4XHE08
                                // for a SU/MU 4xLTF+0.8us peer, else 2XHE08.
                                let fix_giltf = (bw == 3).then(|| phy.he()).flatten().map(|he| {
                                    if he.peer_capability().phy_capability()[7] & 0x04 != 0 {
                                        1
                                    } else {
                                        3
                                    }
                                });
                                let wide = super::station_control::WideRa {
                                    bw,
                                    sgi: match bw {
                                        3 => phy.vht().is_some_and(|vht| vht.tx_sgi160()),
                                        2 => phy.vht().is_some_and(|vht| vht.tx_sgi80()),
                                        _ => phy.ht().tx_sgi40(),
                                    },
                                    vht,
                                    fix_giltf,
                                };
                                io.station_configure_ra_wide(
                                    rates,
                                    ht.ok_or(Error::Profile)?,
                                    he,
                                    wide,
                                    &self.admission,
                                )
                                .await?;
                            }
                            None => {
                                io.station_configure_ra(rates, ht, he, &self.admission)
                                    .await?
                            }
                        }
                    }
                }
                self.admission.run(|| {
                    self.peer_commit = None;
                    self.phase = Phase::FourWay;
                    Ok(())
                })?;
            }
            if self.established {
                attempt.armed = false;
                return Ok(());
            }
            self.environment.pause().await;
        }
    }
    /// mac80211 `ieee80211_determine_chan_mode` + `ieee80211_prep_channel`
    /// for an RTL8852C 6GHz BSS: SAE (H2E) with the HE20 profile under the
    /// signed WMM/HT/HE programs; `six_ghz::admit_with_rule` against the rule
    /// covering the primary in the host policy the records were admitted
    /// under; `JoinPlan::prepare_6ghz` capped at 20MHz (the admitted 6GHz
    /// records here are 20MHz); the admitted *active* channel record whose
    /// client power type is the AP's (cfg80211 refuses a passive-only 6GHz
    /// join without a TX grant, which RTL8852C has none of); and the regd.c
    /// TPE constraint of the AP's elements (STD power only,
    /// `rtw89_reg_6ghz_tpe_recalc`; below `RTW89_MIN_VALID_POWER_CONSTRAINT`
    /// is refused here, as that recalculation fails with `-EINVAL`).
    fn six_ghz_join(
        &mut self,
        io: &mut impl Io,
        candidate: &ObservedBss,
        ssid: &[u8],
        credential: &Credential,
    ) -> Result<(JoinPlan, super::command_native::SixGhzChannel, Option<i8>), Error> {
        use narf_wireless::association::six_ghz;
        if !matches!(credential, Credential::Sae(_)) {
            return Err(Error::Profile);
        }
        let ies = &candidate.bss.information_elements;
        let ap_wmm = narf_wireless::wmm::Parameters::parse(ies)
            .ok()
            .flatten()
            .is_some();
        if !(ap_wmm
            && io.station_wmm_allowed()?
            && io.station_ht_allowed()?
            && io.station_he_allowed()?)
        {
            return Err(Error::Profile);
        }
        let primary = candidate.bss.channel;
        let mhz = association::channel::frequency_in(association::channel::Band::Ghz6, primary)
            .ok_or(Error::Profile)?;
        let policy = io.station_six_ghz_regulatory()?.ok_or(Error::Profile)?;
        let rule = policy.rule_for(mhz).ok_or(Error::Profile)?.clone();
        let bss = six_ghz::admit_with_rule(ies, primary, &rule).map_err(|_| Error::Profile)?;
        let power = bss.power_type.ok_or(Error::Profile)?;
        let channel = io
            .station_six_ghz_channels()?
            .into_iter()
            .find(|c| c.primary == primary && c.power == power && c.active)
            .ok_or(Error::Profile)?;
        let he = super::station_control::local_he().ok_or(Error::Profile)?;
        let local = six_ghz::SixGhzLocal::new(he, six::capability(), rule)
            .map_err(|_| Error::Profile)?
            .with_max_width(six_ghz::SixGhzWidth::Twenty);
        let plan = JoinPlan::prepare_6ghz(
            &candidate.bss,
            self.own,
            ssid,
            SecurityMode::Wpa3Sae {
                pwe: narf_wireless::association::SaePwe::HashToElement,
            },
            &local,
            JoinOptions::default().with_akms(AkmSet::SAE),
        )?;
        let selected = plan.six_ghz().ok_or(Error::Profile)?;
        if selected.width() != six_ghz::SixGhzWidth::Twenty
            || selected.channel().primary != primary
            || selected.power_type() != power
        {
            return Err(Error::Profile);
        }
        let tpe = if channel.six.power() == 2 {
            // The 8852C station is HE20-only: the used chandef
            // is always 20 MHz, so the 20 MHz rearrange stands
            // even on a wider AP channel.
            six::tpe(ies, &bss.channel, association::phy::Width::Twenty)
                .map_err(|()| Error::Profile)?
        } else {
            None
        };
        if tpe.is_some_and(|c| c < -10) {
            return Err(Error::Profile);
        }
        Ok((plan, channel, tpe))
    }
    pub(super) fn send(&mut self, io: &mut impl Io, frame: &[u8]) -> Result<(), Error> {
        let admission = self.admission.clone();
        let result = admission
            .run(|| Ok(self.send_inner(io, frame)))
            .map_err(Error::Native)
            .and_then(|result| result);
        // Closure happens after run releases the publication lock; stopping
        // inside it would re-enter that lock. Fatal native/key errors cannot
        // leave established metadata visible until an unrelated later poll.
        if !self.admission.teardown_pending()
            && result.as_ref().is_err_and(|error| {
                !matches!(
                    error,
                    Error::Busy | Error::Profile | Error::Transport(packet::Error::Busy)
                )
            })
        {
            self.fail(io);
        }
        // __rtw89_traffic_stats_accu: unicast data only (Ethernet bytes here).
        if result.is_ok() && frame.first().is_some_and(|byte| byte & 1 == 0) {
            self.track.transmitted(frame.len());
        }
        result
    }
    /// The originals remain in the host queue until one actual MPDU was
    /// published. A refusal/Busy never consumes a later prefix member.
    pub(super) fn send_prefix(
        &mut self,
        io: &mut impl Io,
        frames: &[&[u8]],
    ) -> Result<usize, Error> {
        let first = *frames.first().ok_or(Error::Profile)?;
        let admission = self.admission.clone();
        let result = admission
            .run(|| Ok(self.send_amsdu_inner(io, frames)))
            .map_err(Error::Native)
            .and_then(|result| result);
        match result {
            Ok(Some(count)) => {
                for frame in &frames[..count] {
                    if frame[0] & 1 == 0 {
                        self.track.transmitted(frame.len());
                    }
                }
                Ok(count)
            }
            Ok(None) => self.send(io, first).map(|()| 1),
            Err(error) => {
                if !self.admission.teardown_pending()
                    && !matches!(
                        error,
                        Error::Busy | Error::Profile | Error::Transport(packet::Error::Busy)
                    )
                {
                    self.fail(io);
                }
                Err(error)
            }
        }
    }
    fn send_inner(&mut self, io: &mut impl Io, frame: &[u8]) -> Result<(), Error> {
        if !self.ready() {
            return Err(Error::Busy);
        }

        if !admitted(frame, self.own) {
            return Err(Error::Profile);
        }
        let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
        let tid = self.tid(frame);
        // Originator BA (rtw89_core_txq_check_agg): frames of a TID whose
        // session is being set up wait like mac80211's tid_tx->pending;
        // an operational session carries TXWD AGG_EN.
        let agg = if self.ampdu && self.wmm.is_some() {
            if self.originator.holding(tid) {
                return Err(Error::Busy);
            }
            self.originator
                .aggregating(tid)
                .map(|buf| super::packet_format::Agg {
                    num: (buf - 1) as u8,
                    density: self.density,
                })
        } else {
            None
        };
        if !self.transmit_room(Kind::Data, agg)
            || agg.is_some() && !io.packet_ready_aggregate()
            || agg.is_none() && !io.packet_ready()
        {
            return Err(Error::Busy);
        }
        if self.fragment_data(io, frame, tid, agg)? {
            return Ok(());
        }
        let htc = self.he && self.htc_rate && super::he_htc::packet_allows(frame);
        let native = if let Some(security) = &mut self.security {
            if self.wmm.is_some() {
                if htc {
                    security.transmit_ethernet_qos_htc(frame, tid, super::he_htc::CONTROL)?
                } else {
                    security.transmit_ethernet_qos(frame, tid)?
                }
            } else {
                security.transmit_ethernet(frame)?
            }
        } else {
            if !admitted(frame, self.own) {
                return Err(Error::Profile);
            }
            let mut bytes = vec![if self.wmm.is_some() { 0x88 } else { 8 }, 1, 0, 0];
            bytes.extend_from_slice(&peer);
            bytes.extend_from_slice(&self.own);
            bytes.extend_from_slice(&frame[..6]);
            bytes.extend_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
            if self.wmm.is_some() {
                bytes.extend_from_slice(&[tid | if htc { 0x10 } else { 0 }, 0]);
            }
            if htc {
                bytes[1] |= 0x80;
                bytes.extend_from_slice(&super::he_htc::CONTROL);
            }
            bytes.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            bytes.extend_from_slice(&frame[12..]);
            bytes
        };
        self.transmit_with(io, native, Kind::Data, true, agg)?;
        if agg.is_none() && self.ampdu && self.wmm.is_some() {
            // The triggering frame goes out unaggregated; ba_work then
            // starts the session (ieee80211_start_tx_ba_session).
            let now = self.last_now;
            self.originator.want(tid, now);
        }
        Ok(())
    }
}
pub(super) fn admitted(frame: &[u8], own: [u8; 6]) -> bool {
    (14..=1514).contains(&frame.len())
        && frame[6..12] == own
        && frame[..6] != [0; 6]
        && u16::from_be_bytes([frame[12], frame[13]]) >= 0x600
        && !matches!(
            u16::from_be_bytes([frame[12], frame[13]]),
            0x888e | 0x80f3 | 0x8137
        )
}
fn ethernet(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> Option<Vec<u8>> {
    if !(32..=1538).contains(&frame.len())
        || !matches!(frame[0], 8 | 0x88)
        || frame[1] & 0x47 != 2
        || frame[1] & 0x80 != 0 && frame[0] != 0x88
        || frame[22] & 15 != 0
        || frame[10..16] != peer
        || (frame[4..10] != own && frame[4] & 1 == 0)
        || frame[16] & 1 != 0
        || frame[16..22] == [0; 6]
    {
        return None;
    }
    let offset = if frame[0] == 0x88 {
        let qos = frame.get(24..26)?;
        if qos[0] & 0xe0 != 0 || qos[1] != 0 {
            return None;
        }
        26 + if frame[1] & 0x80 != 0 { 4 } else { 0 }
    } else {
        24
    };
    let snap = frame.get(offset..offset + 8)?;
    if snap[..6] != [0xaa, 0xaa, 3, 0, 0, 0] || frame.len() + 6 - offset > 1514 {
        return None;
    }
    let proto = u16::from_be_bytes([snap[6], snap[7]]);
    if proto < 0x600 || matches!(proto, 0x888e | 0x80f3 | 0x8137) {
        return None;
    }
    let mut bytes = Vec::with_capacity(frame.len() - 18);
    bytes.extend_from_slice(&frame[4..10]);
    bytes.extend_from_slice(&frame[16..22]);
    bytes.extend_from_slice(&frame[offset + 6..]);
    Some(bytes)
}

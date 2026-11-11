// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RAW-mode station packets. Firmware receipts, RSNA and packet keys
//! have separate ownership; an associated peer alone never admits Ethernet.
use super::hw_keys;
use super::*;
use crate::ath10k::regulatory::Permission;
use narf_wireless::packet_key::AmsduAdmission;
use narf_wireless::station_security::{KeyInstall, MgmtRx, RawFrame, Rx, Security};
const RECEIVED_FRAMES: usize = 256;
const INCOMING_FRAMES: usize = 1024;
#[path = "rx_ba.rs"]
mod rx_ba;
#[path = "tx_pipeline.rs"]
mod tx_pipeline;
#[path = "tx_qos.rs"]
mod tx_qos;
pub use tx_pipeline::TidCounters;
use tx_pipeline::{Completion, Outcome, Pipeline, Role};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub bssid: [u8; 6],
    pub frequency: u16,
    pub protected: bool,
}
/// An original native MPDU; `.1` marks one the firmware decrypted with a
/// host-installed key (Protected and CCMP header kept, MIC/FCS removed).
#[derive(Debug)]
struct Native(Vec<u8>, bool);
#[derive(Clone, Copy)]
struct Addresses {
    own: [u8; 6],
    bssid: [u8; 6],
}
#[derive(Debug)]
struct Incoming {
    frame: Native,
    peer: u16,
    data_admitted: bool,
}
enum NativeEvent {
    Data(Native),
    Bar { tid: u8, sequence: u16 },
}
impl RawFrame for Native {
    fn bytes(&self) -> &[u8] {
        &self.0
    }
    fn unmodified(&self) -> bool {
        true
    }
}
#[derive(Debug)]
pub(super) struct State {
    security: Option<Security>,
    /// Every outstanding native HTT ID, keyed by MSDU ID (heap-owned).
    pending: Pipeline,
    incoming: VecDeque<Incoming>,
    rx_ba: rx_ba::Owner,
    #[cfg(any(test, feature = "kernel-test"))]
    receive_time: Option<u64>,
    received: VecDeque<Vec<u8>>,
    /// Open-path 802.11 sequence counters per TID (non-QoS uses slot 0,
    /// as before; mac80211 keeps `sta->tid_seq` per TID).
    sequence: [u16; 8],
    qos: bool,
    /// WMM ACM per canonical ACI (BE, BK, VI, VO) for queue downgrade.
    acm: [bool; 4],
    failed: bool,
    authorized: bool,
    last_peer: narf_time::Deadline,
    /// Newer AP WMM parameter set from a beacon, awaiting `ath10k_conf_tx`.
    wmm_update: Option<narf_wireless::wmm::Parameters>,
    /// Changed beacon ERP `use_cts_prot`, awaiting `BSS_CHANGED_ERP_CTS_PROT`.
    protection_update: Option<bool>,
    /// A CCMP-protected SA Query Response awaiting the native management
    /// path (one outstanding; a second request before it is sent is
    /// dropped, as mac80211 answers each request independently).
    management: Option<Vec<u8>>,
    /// Committed keys awaiting `WMI_VDEV_INSTALL_KEY` (hardware-key profile).
    keys: VecDeque<KeyInstall>,
    /// The one install awaiting its HTT security indication.
    key_in_flight: Option<hw_keys::InFlight>,
    /// Native-WiFi decap (`nwifi.rs`): TX native-WiFi frames under firmware
    /// crypto, RX rebuilt to the RAW-equivalent original MPDU.
    native_wifi: bool,
    /// Native-WiFi MSDUs of the A-MSDU being received (first..last).
    amsdu: Vec<htt::rx::Msdu>,
}
/// htt_rx.c `ath10k_htt_rx_h_undecap`: native-WiFi MSDUs are grouped
/// first..last and rebuilt (`nwifi::undecap`); a RAW-decapped MSDU (control
/// frames, or a frame the firmware could not decrypt) passes unchanged and
/// abandons any partial group. RAW decap passes everything unchanged.
fn native_wifi_msdu(
    native_wifi: bool,
    group: &mut Vec<htt::rx::Msdu>,
    msdu: htt::rx::Msdu,
) -> Result<Option<htt::rx::Msdu>, Error> {
    if !native_wifi || msdu.offload.is_some() || nwifi::decap_format(&msdu.descriptor) != 1 {
        group.clear();
        return Ok(Some(msdu));
    }
    if group.len() == 31 {
        group.clear();
        return Ok(None);
    }
    let last = nwifi::last_msdu(&msdu.descriptor);
    group.try_reserve(1).map_err(|_| Error::NoMemory)?;
    group.push(msdu);
    if !last {
        return Ok(None);
    }
    let rebuilt = nwifi::undecap(group);
    group.clear();
    Ok(rebuilt)
}
impl State {
    fn host_idle(&self) -> bool {
        self.roc_quiescent()
            && self.incoming.is_empty()
            && self.received.is_empty()
            && self.wmm_update.is_none()
            && self.protection_update.is_none()
            && self.keys.is_empty()
            && self.key_in_flight.is_none()
            && self.rx_ba.host_idle()
    }
    pub(super) fn protection_allowed(&self) -> bool {
        self.open()
            && !self.pending.reply_in_flight()
            && self.security.as_ref().is_none_or(|s| !s.handshake_active())
    }
    pub(super) fn roc_quiescent(&self) -> bool {
        self.protection_allowed() && self.pending.is_empty() && self.management.is_none()
    }
    pub(super) fn retire_roc_receive(&mut self) {
        self.rx_ba.discard_ppdu();
        self.incoming.clear();
        self.received.clear();
    }
    /// Whether MSDU `id` is in this data owner's TX pipeline.
    /// Every native MSDU id still awaiting its terminal TX indication.
    pub(super) fn pending_ids(&self) -> Vec<u16> {
        self.pending.ids()
    }
    pub(super) fn owns_msdu(&self, id: u16) -> bool {
        self.pending.owns(id)
    }
    pub(super) fn protection_idle(&self) -> bool {
        self.pending.is_empty()
    }
    /// Protection programming drains data IDs; a reply cannot be in flight
    /// (protection_allowed), so meeting one here is an ownership violation.
    pub(super) fn protection_receipt(&mut self, receipt: htt::TxReceipt) -> Result<(), Error> {
        match self.pending.complete(receipt) {
            Completion::Reply { .. } => Err(Error::Failed),
            Completion::Foreign | Completion::Data { .. } => Ok(()),
        }
    }
    pub(super) fn fail(&mut self) {
        self.failed = true;
        self.incoming.clear();
        self.received.clear();
        self.rx_ba.clear();
        if let Some(security) = &mut self.security {
            security.fail();
        }
        // A failed/cancelled HTT operation retains its payload/fragment owner.
        // Do not release or pretend to complete the outstanding native ID.
    }
    fn open(&self) -> bool {
        !self.failed && self.authorized && self.security.as_ref().is_none_or(Security::port_open)
    }
    fn now(&self) -> u64 {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(now) = self.receive_time {
            return now;
        }
        narf_time::wall::monotonic_ns()
    }
    fn queue_ready(&mut self, frames: Vec<Incoming>) -> Result<(), Error> {
        if self.incoming.len().saturating_add(frames.len()) > INCOMING_FRAMES {
            return Err(Error::Exhausted);
        }
        self.incoming
            .try_reserve(frames.len())
            .map_err(|_| Error::NoMemory)?;
        self.incoming.extend(frames);
        Ok(())
    }
    fn receive_native(
        &mut self,
        frame: htt::rx::Msdu,
        status: u8,
        peer: u16,
        tid: u8,
        addresses: Addresses,
        now: u64,
    ) -> Result<(), Error> {
        let Some(frame) = native_wifi_msdu(self.native_wifi, &mut self.amsdu, frame)? else {
            return Ok(());
        };
        let data_admitted = self.open();
        let hardware = self.security.as_ref().is_some_and(Security::hardware_keys);
        match raw_frame(
            frame,
            status,
            peer,
            tid,
            addresses,
            &mut self.rx_ba,
            now,
            hardware,
        )? {
            Some(NativeEvent::Data(frame)) => {
                if !data_admitted && !plaintext_eapol(&frame, addresses) {
                    // Even a valid original FIRST was not admitted in this
                    // controlled-port epoch. Its PHY context cannot authorize
                    // a later MIDDLE/LAST after a delayed reply receipt.
                    self.rx_ba.discard_ppdu();
                    return Ok(());
                }
                let ready = self.rx_ba.push(
                    Incoming {
                        frame,
                        peer,
                        data_admitted,
                    },
                    now,
                )?;
                self.queue_ready(ready)?;
            }
            Some(NativeEvent::Bar { tid, sequence }) => {
                let ready = self.rx_ba.bar(peer, tid, sequence, now)?;
                self.queue_ready(ready)?;
            }
            None => {}
        }
        Ok(())
    }
}
fn plaintext_eapol(frame: &Native, addresses: Addresses) -> bool {
    let b = &frame.0;
    let at = if b[0] == 0x88 { 26 } else { 24 };
    if b[1] & 0x40 != 0
        || b[4..10] != addresses.own
        || b[16..22] != addresses.bssid
        || b[0] == 0x88 && b[24] & 0x80 != 0
        || b.get(at..at + 8) != Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e])
    {
        return false;
    }
    let pdu = &b[at + 8..];
    pdu.len() >= 4
        && (1..=3).contains(&pdu[0])
        && pdu[1] == 3
        && usize::from(u16::from_be_bytes([pdu[2], pdu[3]])) + 4 == pdu.len()
}
fn security_error(_: narf_wireless::station_security::Error) -> Error {
    Error::Malformed
}
/// Linux with a hardware CCMP key on a `peer_flags->pmf` peer: mac80211
/// writes only the CCMP header (`IEEE80211_KEY_FLAG_GENERATE_IV_MGMT`) and
/// wmi.c `ath10k_wmi_op_gen_mgmt_tx` reserves the MIC the firmware writes.
/// Without the PMF peer flag, or before the firmware confirmed the current
/// PTK, the host protects the frame completely as in the software profile.
fn protect_management(
    security: &mut Security,
    frame: &[u8],
    pmf_offload: bool,
) -> Result<Vec<u8>, Error> {
    if pmf_offload && security.pairwise_offloaded() {
        let mut out = security
            .protect_management_offload(frame)
            .map_err(security_error)?;
        out.resize(out.len() + hw_keys::MIC_LEN, 0);
        return Ok(out);
    }
    security.protect_management(frame).map_err(security_error)
}
fn element(ies: &[u8], wanted: u8) -> Result<Option<&[u8]>, Error> {
    let mut rest = ies;
    let mut found = None;
    while !rest.is_empty() {
        let head = rest.get(..2).ok_or(Error::Malformed)?;
        let length = usize::from(head[1]);
        let body = rest.get(2..2 + length).ok_or(Error::Malformed)?;
        if head[0] == wanted {
            if found.is_some() {
                return Err(Error::Malformed);
            }
            found = Some(body);
        }
        rest = &rest[2 + length..];
    }
    Ok(found)
}
fn ethernet(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() < 32
        || !matches!(frame[0], 8 | 0x88)
        || frame[1] & 0xc7 != 2
        || frame[22] & 15 != 0
        || frame[10..16] != peer
        || frame[4..10] != own && frame[4] & 1 == 0
        || frame[16..22] == [0; 6]
        || frame[16] & 1 != 0
    {
        return None;
    }
    let header = if frame[0] == 0x88 { 26 } else { 24 };
    if header == 26 && frame.get(24).is_none_or(|qos| qos & 0x80 != 0) {
        return None;
    }
    let snap = frame.get(header..header + 8)?;
    let protocol = u16::from_be_bytes([snap[6], snap[7]]);
    if snap[..6] != [0xaa, 0xaa, 3, 0, 0, 0]
        || protocol < 0x600
        || matches!(protocol, 0x888e | 0x80f3 | 0x8137)
        || frame.len() - header + 6 > 1514
    {
        return None;
    }
    let mut out = frame[4..10].to_vec();
    out.extend_from_slice(&frame[16..22]);
    out.extend_from_slice(&frame[header + 6..]);
    Some(out)
}

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    /// mac80211 `ieee80211_set_disassoc` sends Deauthentication (reason 3,
    /// DEAUTH_LEAVING) on a local disconnect; under PMF it must be
    /// CCMP-protected with the PTK before the keys are retired.
    pub(super) fn pmf_deauthentication(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let own = self.station_own()?;
        let bssid = self.station.peer.as_ref().ok_or(Error::Failed)?.bssid;
        let Some(security) = self
            .station
            .data
            .as_mut()
            .filter(|d| !d.failed)
            .and_then(|d| d.security.as_mut())
            .filter(|s| s.pmf() && s.port_open())
        else {
            return Ok(None);
        };
        let mut frame = alloc::vec![0xc0, 0, 0, 0];
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&own);
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&[0, 0, 3, 0]);
        protect_management(security, &frame, self.station.peer_pmf_offload).map(Some)
    }
    /// Program committed keys one at a time (Linux mac.c
    /// `ath10k_install_key` under `conf_mutex`): `WMI_VDEV_INSTALL_KEY`, then
    /// the HTT security indication confirms it in `data_event_inner`. No
    /// indication within Linux's 3 s leaves that slot software-only, as
    /// mac80211 keeps a key in software when `drv_set_key` fails.
    async fn send_station_keys(&mut self) -> Result<bool, Error> {
        let (vdev, bssid) = self
            .station
            .peer
            .as_ref()
            .map(|p| (p.vdev, p.bssid))
            .ok_or(Error::Failed)?;
        let dialect = self.wire.dialect;
        let Some(data) = self.station.data.as_mut() else {
            return Ok(false);
        };
        if let Some(flight) = data.key_in_flight {
            if !flight.deadline.expired() {
                return Ok(false);
            }
            data.key_in_flight = None;
            if let Some(security) = data.security.as_mut() {
                security.key_install_failed(flight.token);
            }
        }
        let Some(key) = data.keys.pop_front() else {
            return Ok(false);
        };
        let command = zeroize::Zeroizing::new(hw_keys::install(dialect, vdev, bssid, &key)?);
        data.key_in_flight = Some(hw_keys::InFlight {
            token: key.token,
            pairwise: key.pairwise,
            deadline: narf_time::Deadline::after_ms(hw_keys::INSTALL_TIMEOUT_MS),
        });
        drop(key);
        self.htt
            .wmi
            .htc
            .send_wmi(&command)
            .await
            .map_err(htt::Error::from)?;
        Ok(true)
    }
    /// Publish a queued protected SA Query Response on the native
    /// management path (the synchronous receive drain cannot await WMI).
    async fn send_station_management(&mut self) -> Result<bool, Error> {
        let Some(frame) = self.station.data.as_mut().and_then(|d| d.management.take()) else {
            return Ok(false);
        };
        let own = self.station_own()?;
        let bssid = self.station.peer.as_ref().ok_or(Error::Failed)?.bssid;
        super::management::validate(&frame, own, bssid)?;
        self.send_management_frame(&frame).await?;
        Ok(true)
    }
    /// ath10k_conf_tx for each AC of a beacon's newer WMM parameter set;
    /// peer state and ACM downgrade follow only after the WMI send.
    async fn send_station_wmm(
        &mut self,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<bool, Error> {
        let Some(update) = self.station.data.as_mut().and_then(|d| d.wmm_update.take()) else {
            return Ok(false);
        };
        let command = super::wmm::command(self.wire.dialect, update)?;
        self.send_station_command(&command, validate).await?;
        self.station.peer.as_mut().ok_or(Error::Failed)?.wmm = Some(update);
        self.station.data.as_mut().ok_or(Error::Failed)?.acm = tx_qos::admission(&update);
        Ok(true)
    }
    /// The Device service worker's await point for queued robust
    /// management (Linux transmits the mac80211 SA Query response from its
    /// TX path) and beacon WMM reprogramming; the policy is rechecked before
    /// publication.
    pub(in crate::ath10k) async fn flush_station_management(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<bool, Error> {
        if self.roc_active() {
            return Ok(false);
        }
        let coexistence = self.service_coexistence(domain).await?;
        if self.failed
            || self.station_link().is_none()
            || self.station.data.as_ref().is_none_or(|d| {
                d.management.is_none()
                    && d.wmm_update.is_none()
                    && d.protection_update.is_none()
                    && d.keys.is_empty()
            })
        {
            return Ok(coexistence);
        }
        self.check_data_policy(domain)?;
        // ath10k_bss_info_changed(BSS_CHANGED_ERP_CTS_PROT): recalc RTS/CTS
        // and set use_cts_prot, keeping the configured RTS threshold. It waits
        // for an open, reply-free data path rather than failing the owner.
        if let Some(cts_protection) = self
            .station
            .data
            .as_ref()
            .filter(|d| d.protection_allowed())
            .and_then(|d| d.protection_update)
        {
            let request = super::protection::Request {
                rts_threshold: self.station.protection.and_then(|r| r.rts_threshold),
                cts_protection,
            };
            self.set_station_protection(request, || Ok(domain.clone()))
                .await?;
            if let Some(data) = self.station.data.as_mut() {
                data.protection_update = None;
            }
        }
        self.failed = true;
        // A key committed by a reply the synchronous drain completed (the
        // group-key handshake after association) is programmed here, as
        // mac80211's set_key runs from process context after the reply
        // (mac.c ath10k_set_key -> ath10k_install_key).
        let keys = self.send_station_keys().await?;
        let sent = self.send_station_management().await?;
        let wmm = self.send_station_wmm(&|| Ok(())).await?;
        self.failed = false;
        Ok(coexistence || keys || sent || wmm)
    }
    pub fn has_station_data(&self) -> bool {
        self.station.data.is_some()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn expire_data_for_test(&mut self) {
        if let Some(data) = &mut self.station.data {
            data.last_peer = narf_time::Deadline::after_ms(0);
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn receive_time_for_test(&mut self, now: u64) {
        if let Some(data) = &mut self.station.data {
            data.receive_time = Some(now);
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn receive_ba_for_test(
        &self,
        tid: u8,
    ) -> Option<(u16, u8, usize, Option<u16>)> {
        self.station.data.as_ref()?.rx_ba.state(tid)
    }
    /// Native WiFi has no software-crypto data path (core.c: `cryptmode=1`
    /// requires RAW), so it needs the hardware-key profile.
    pub fn data_supported(&self) -> bool {
        self.htt.data_profile() && (self.htt.wmi.raw_mode() || self.hardware_keys)
    }
    pub fn station_publishable(&self) -> Result<[u8; 6], Error> {
        self.htt
            .wmi
            .htc
            .transport
            .check_current()
            .map_err(crate::ath10k::control::Error::from)
            .map_err(htt::Error::from)?;
        if !self.data_supported() {
            return Err(Error::Unsupported);
        }
        if self.failed || self.station.peer.is_some() || self.station.data.is_some() {
            return Err(Error::Failed);
        }
        self.station_own()
    }
    pub fn fail_station_data(&mut self) {
        self.beacon_hints.retire();
        self.failed = true;
        if let Some(data) = &mut self.station.data {
            data.fail();
        }
    }
    /// Host closure retires receive ownership without failing a still-owned
    /// native TX operation or preventing the subsequent DOWN/DELETE sequence.
    pub(in crate::ath10k) fn retire_station_receive(&mut self) {
        if let Some(data) = &mut self.station.data {
            data.incoming.clear();
            data.received.clear();
            data.rx_ba.clear();
        }
    }
    pub fn station_link(&self) -> Option<Link> {
        if self.coexistence_blocked() {
            return None;
        }
        if !self.station.data.as_ref()?.open() {
            return None;
        }
        let associated = self.associated_station()?;
        Some(Link {
            bssid: associated.bssid,
            frequency: associated.frequency,
            protected: associated.protected,
        })
    }
    /// Native HTT data/reply IDs awaiting their terminal TX indication.
    pub fn tx_in_flight(&self) -> usize {
        self.station.data.as_ref().map_or(0, |d| d.pending.len())
    }
    /// Terminal HTT TX outcomes for one TID (16 = non-QoS).
    pub fn tx_counters(&self, tid: u8) -> TidCounters {
        self.station
            .data
            .as_ref()
            .map_or(TidCounters::default(), |d| d.pending.counters(tid))
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn tx_in_flight_ids(&self) -> Vec<u16> {
        self.station
            .data
            .as_ref()
            .map_or(Vec::new(), |d| d.pending.ids())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn expire_pending_tx_for_test(&mut self) {
        if let Some(data) = &mut self.station.data {
            data.pending.expire_for_test();
        }
    }
    pub(in crate::ath10k) fn data_permission(&self) -> Option<Permission> {
        self.station_link()?;
        Some(self.station.peer.as_ref()?.permission.clone())
    }
    pub(in crate::ath10k) fn check_data_policy(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), Error> {
        if self.roc_active() {
            return Err(Error::Unsupported);
        }
        self.check_dwell_scan(domain)?;
        self.htt
            .wmi
            .htc
            .transport
            .check_current()
            .map_err(crate::ath10k::control::Error::from)
            .map_err(htt::Error::from)?;
        let peer = self.station.peer.as_ref().ok_or(Error::Failed)?;
        peer.permission.check(domain)
    }
    /// Start the packet owner only after native association. Software CCMP is
    /// selected at WMI INIT, never retrofitted onto a native-WiFi/decapped RX
    /// image. PFC additionally requires the real coherent queue-state owner.
    pub async fn start_station_data(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        pmk: Option<&[u8; 32]>,
    ) -> Result<Link, Error> {
        self.start_data_with_nonce(domain, pmk, || {
            let mut nonce = [0; 32];
            narf_crypto::try_fill_random_bytes(&mut nonce)
                .ok()
                .map(|()| nonce)
        })
        .await
    }
    pub(in crate::ath10k) async fn start_data_with_nonce(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        pmk: Option<&[u8; 32]>,
        nonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<Link, Error> {
        self.start_data_with_nonce_checked(domain, pmk, nonce, &|| Ok(()))
            .await
    }
    pub(in crate::ath10k) async fn start_data_with_nonce_checked(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        pmk: Option<&[u8; 32]>,
        mut nonce: impl FnMut() -> Option<[u8; 32]>,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<Link, Error> {
        validate()?;
        let associated = self.associated_station().ok_or(Error::Failed)?;
        if self.station.data.is_some() || !self.data_supported() {
            return Err(Error::Unsupported);
        }
        let native_wifi = !self.htt.wmi.raw_mode();
        let rsn = self.station.peer.as_ref().and_then(|p| p.rsn.as_deref());
        let sae = rsn.is_some_and(|r| r.sae_pmk.is_some());
        // SAE derives its own PMK; a caller PMK is then refused.
        if associated.protected != (pmk.is_some() || sae) || sae && pmk.is_some() {
            return Err(Error::Unsupported);
        }
        self.check_data_policy(domain)?;
        if self
            .station
            .peer
            .as_ref()
            .and_then(|p| p.ht)
            .is_some_and(|h| h.secondary.is_some())
        {
            self.set_station_protection(super::protection::Request::HT40, || {
                validate()?;
                Ok(domain.clone())
            })
            .await?;
        }
        let own = self.station_own()?;
        let cached = self
            .scan_cache
            .iter()
            .find(|b| b.bssid == associated.bssid && b.frequency == associated.frequency)
            .ok_or(Error::Failed)?;
        let security = if associated.protected {
            // The station RSNE/RSNXE are the association's own (plan
            // `rsn_body`, SAE `station_rsnxe`): WPA2, WPA2-PMF or SAE.
            let rsn = self
                .station
                .peer
                .as_ref()
                .and_then(|p| p.rsn.as_deref())
                .ok_or(Error::Unsupported)?;
            let ap_rsne = element(&cached.information_elements, 48)?.ok_or(Error::Unsupported)?;
            let ap_rsnxe = element(&cached.information_elements, 244)?;
            Some(
                match (&rsn.sae_pmk, pmk) {
                    (Some(sae), None) => Security::new_sae(
                        own,
                        associated.bssid,
                        sae,
                        &rsn.rsne,
                        rsn.rsnxe.as_deref(),
                        ap_rsne,
                        ap_rsnxe,
                        2,
                    ),
                    (None, Some(pmk)) => {
                        Security::new(own, associated.bssid, pmk, &rsn.rsne, ap_rsne, ap_rsnxe, 2)
                    }
                    _ => return Err(Error::Unsupported),
                }
                .and_then(|security| {
                    if self.hardware_keys {
                        security.with_hardware_keys()
                    } else {
                        Ok(security)
                    }
                })
                .map_err(security_error)?,
            )
        } else {
            None
        };
        self.failed = true;
        // Events a sibling slot parked for this one (its own early EAPOL or
        // PEER_MAP polled while the sibling owned the radio) precede the
        // radio queue.
        let mut retained = VecDeque::new();
        while let Some(event) = self.station.inbox.pop_front() {
            retained.push_back(self.slot_event(event)?);
        }
        retained.extend(core::mem::take(&mut self.pending));
        let primary = self.primary.id();
        let mut incoming = VecDeque::new();
        // An AP may send M1 before PEER_ASSOC/UP's receive drain ends. Retain
        // only exact descriptor-bound, unprotected unicast EAPOL for the new
        // supplicant. Association-era IP can never become authorized later.
        let peer = self.station.peer.as_ref().ok_or(Error::Failed)?;
        let mut rx_ba = rx_ba::Owner::new(peer.ht)?;
        let addresses = Addresses {
            own,
            bssid: associated.bssid,
        };
        let mut group = Vec::new();
        for event in retained {
            let frames = match event {
                htt::Event::Rx(batch) if security.is_some() && peer.owns(batch.peer) => batch
                    .frames
                    .into_iter()
                    .map(|(status, frame)| (status, batch.peer, batch.tid, frame))
                    .collect::<Vec<_>>(),
                htt::Event::InOrder(i, frames)
                    if security.is_some()
                        && peer.owns(i.peer)
                        && i.vdev == peer.vdev
                        && !i.offload
                        && !i.fragment =>
                {
                    frames
                        .into_iter()
                        .map(|frame| (1, i.peer, i.tid, frame))
                        .collect()
                }
                // Another slot's RX is that slot's (`htt_rx.c` by peer/vdev),
                // never this owner's to discard.
                rx @ (htt::Event::Rx(_) | htt::Event::InOrder(_, _)) => {
                    if let Some(sibling) = self
                        .p2p_client
                        .as_deref_mut()
                        .filter(|s| s.claims(&rx, primary, None))
                    {
                        sibling.park(rx);
                    }
                    Vec::new()
                }
                other => {
                    self.pending.push_back(other);
                    Vec::new()
                }
            };
            for (status, id, tid, frame) in frames {
                let Some(frame) = native_wifi_msdu(native_wifi, &mut group, frame)? else {
                    continue;
                };
                if let Some(NativeEvent::Data(frame)) = raw_frame(
                    frame,
                    status,
                    id,
                    tid,
                    addresses,
                    &mut rx_ba,
                    narf_time::wall::monotonic_ns(),
                    false,
                )? {
                    if plaintext_eapol(&frame, addresses) {
                        if incoming.len() == 64 {
                            return Err(Error::Exhausted);
                        }
                        incoming.push_back(Incoming {
                            frame,
                            peer: id,
                            data_admitted: false,
                        });
                    }
                }
            }
        }
        while self.take_station_receipt().is_some() {}
        self.station.data = Some(State {
            security,
            pending: Pipeline::new()?,
            incoming,
            rx_ba,
            #[cfg(any(test, feature = "kernel-test"))]
            receive_time: None,
            received: VecDeque::new(),
            sequence: [2; 8],
            qos: self
                .station
                .peer
                .as_ref()
                .ok_or(Error::Failed)?
                .wmm
                .is_some(),
            acm: self
                .station
                .peer
                .as_ref()
                .ok_or(Error::Failed)?
                .wmm
                .as_ref()
                .map_or([false; 4], tx_qos::admission),
            failed: false,
            authorized: !associated.protected,
            last_peer: narf_time::Deadline::after_ms(5000),
            wmm_update: None,
            protection_update: None,
            management: None,
            keys: VecDeque::new(),
            key_in_flight: None,
            native_wifi,
            amsdu: Vec::new(),
        });
        self.failed = true;
        let deadline = narf_time::Deadline::after_ms(5000);
        for _ in 0..65536 {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let idle = self.data_step(&mut nonce, validate).await?;
            if idle && self.station.data.as_ref().is_some_and(State::open) {
                self.failed = false;
                return self.station_link().ok_or(Error::Failed);
            }
            narf_scheduler::yield_now().await;
        }
        Err(Error::Timeout)
    }
    /// Publish one Ethernet packet to native HTT. The returned ID describes
    /// publication, not delivery; no second packet/reply overwrites that slot.
    pub async fn transmit_ethernet(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        bytes: &[u8],
    ) -> Result<u16, Error> {
        let (frame, parameters) = self.ethernet_frame(domain, bytes)?;
        self.failed = true;
        let id = self.send_data(&frame, false, parameters).await?;
        self.failed = false;
        Ok(id)
    }
    /// The MSDU and its HTT descriptor parameters. RAW sends the full
    /// 802.11 frame; native WiFi (`nwifi.rs`) the frame without QoS
    /// Control, firmware-encrypted under the confirmed PTK, with the TID
    /// taken before QoS Control is removed (htt_tx.c `ath10k_htt_tx_get_tid`).
    fn ethernet_frame(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        bytes: &[u8],
    ) -> Result<(Vec<u8>, htt::tx::Parameters), Error> {
        let link = self.station_link().ok_or(Error::Failed)?;
        self.check_data_policy(domain)?;
        let own = self.station_own()?;
        let vdev = self.station_vdev();
        let data = self.station.data.as_mut().ok_or(Error::Failed)?;
        if !data.pending.data_admissible() || data.security.as_ref().is_some_and(|s| !s.port_open())
        {
            return Err(Error::Htt(htt::Error::Busy));
        }
        // ieee80211_select_queue + ieee80211_downgrade_queue (tx_qos.rs).
        let tid = if data.qos {
            tx_qos::priority(bytes, data.acm)
        } else {
            0
        };
        let mut hardware = false;
        let frame = if let Some(security) = &mut data.security {
            if data.native_wifi {
                // No software-crypto data path exists in this decap; until
                // the PTK is confirmed in the firmware, data waits.
                if !security.pairwise_offloaded() {
                    return Err(Error::Htt(htt::Error::Busy));
                }
                hardware = true;
                security
                    .transmit_ethernet_device(bytes, data.qos.then_some(tid))
                    .map_err(security_error)?
            } else if security.pairwise_offloaded() {
                // mac80211 GENERATE_IV with a hardware key: the CCMP header
                // only; htt_tx.c RAW protected adds the MIC tail the
                // firmware fills (`skb_put(IEEE80211_CCMP_MIC_LEN)`).
                hardware = true;
                let mut frame = security
                    .transmit_ethernet_offload(bytes, data.qos.then_some(tid))
                    .map_err(security_error)?;
                frame.resize(frame.len() + hw_keys::MIC_LEN, 0);
                frame
            } else if data.qos {
                security
                    .transmit_ethernet_qos(bytes, tid)
                    .map_err(security_error)?
            } else {
                security.transmit_ethernet(bytes).map_err(security_error)?
            }
        } else {
            if !(14..=1514).contains(&bytes.len())
                || bytes[6..12] != own
                || bytes[..6] == [0; 6]
                || u16::from_be_bytes([bytes[12], bytes[13]]) < 0x600
                || matches!(
                    u16::from_be_bytes([bytes[12], bytes[13]]),
                    0x888e | 0x80f3 | 0x8137
                )
            {
                return Err(Error::Unsupported);
            }
            let mut frame = alloc::vec![if data.qos { 0x88 } else { 8 }, 1, 0, 0];
            frame.extend_from_slice(&link.bssid);
            frame.extend_from_slice(&own);
            frame.extend_from_slice(&bytes[..6]);
            let sequence = &mut data.sequence[usize::from(tid)];
            frame.extend_from_slice(&(*sequence << 4).to_le_bytes());
            *sequence = (*sequence + 1) & 4095;
            if data.qos {
                frame.extend_from_slice(&[tid, 0]);
            }
            frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            frame.extend_from_slice(&bytes[12..]);
            frame
        };
        let parameters = htt::tx::Parameters {
            kind: htt::tx::Kind::Raw,
            vdev,
            tid: tx_qos::descriptor_tid(&frame),
            hardware_crypto: hardware,
        };
        if data.native_wifi {
            let frame = nwifi::transmit(frame).ok_or(Error::Unsupported)?;
            return Ok((
                frame,
                htt::tx::Parameters {
                    kind: htt::tx::Kind::Native,
                    ..parameters
                },
            ));
        }
        Ok((frame, parameters))
    }
    pub fn begin_ethernet(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        bytes: &[u8],
    ) -> Result<u16, Error> {
        if self.station_link().is_none() {
            return Err(Error::Failed);
        }
        if !self.htt.source_ready()? {
            return Err(Error::Htt(htt::Error::Busy));
        }
        let (frame, parameters) = self.ethernet_frame(domain, bytes)?;
        self.failed = true;
        let id = self.htt.begin_transmit(parameters, &frame)?;
        self.station
            .data
            .as_mut()
            .ok_or(Error::Failed)?
            .pending
            .push(
                id,
                Role::Data {
                    tid: parameters.tid,
                },
                frame.len(),
            )?;
        self.failed = false;
        Ok(id)
    }
    pub fn poll_ethernet_now(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if self.failed || self.associated_station().is_none() || self.station.data.is_none() {
            return Err(Error::Failed);
        }
        self.check_data_policy(domain)?;
        self.failed = true;
        for _ in 0..64 {
            self.data_check()?;
            let parked = match self.station.inbox.pop_front() {
                Some(e) => Some(self.slot_event(e)?),
                None => None,
            };
            let event = match parked.or_else(|| self.pending.pop_front()) {
                Some(e) => e,
                None => {
                    // This optional host-vote hint is narrower than DATA
                    // admission: retain every buffered BA/key/control/native
                    // original, scan/ROC and copy owner on the full poll path.
                    let eligible = self.scan_pending.is_none()
                        && self.scan_dwell.is_none()
                        && self.roc.is_none()
                        && self.management_done.is_empty()
                        && self.management_received.is_empty()
                        && self.management_completed.is_none()
                        && self
                            .station
                            .coexistence
                            .as_ref()
                            .is_none_or(|state| !state.blocked())
                        && self.station.data.as_ref().is_some_and(State::host_idle);
                    self.htt.wmi.htc.transport.runtime_idle(eligible);
                    let event = self.htt.poll_now()?;
                    if self.htt.take_idle_deferred() {
                        // No actual empty native prefix was read. Do not run
                        // data_event(Idle), expiry/publication or M4 commit.
                        self.failed = false;
                        return Ok(Vec::new());
                    }
                    self.station_event(event)?
                }
            };
            let (idle, reply) = self.data_event(event, &mut || {
                let mut nonce = [0; 32];
                narf_crypto::try_fill_random_bytes(&mut nonce)
                    .ok()
                    .map(|()| nonce)
            })?;
            if let Some(reply) = reply {
                if self.htt.source_ready()? {
                    let parameters = self.reply_parameters(&reply)?;
                    let id = self.htt.begin_transmit(parameters, &reply)?;
                    self.station
                        .data
                        .as_mut()
                        .ok_or(Error::Failed)?
                        .pending
                        .push(id, Role::Reply, reply.len())?;
                }
            }
            self.service_station_pfc()?;
            if idle {
                let data = self.station.data.as_mut().ok_or(Error::Failed)?;
                if !data.open()
                    || self
                        .station
                        .coexistence
                        .as_ref()
                        .is_some_and(|s| s.blocked())
                {
                    data.received.clear();
                }
                let frames = data.received.drain(..).collect();
                self.failed = false;
                return Ok(frames);
            }
        }
        // Bounded synchronous work preserves buffered RX until a later empty
        // receive poll fences same-batch UNMAP/deauthentication before delivery.
        self.failed = false;
        Ok(Vec::new())
    }
    /// `hardware` clears `HTT_DATA_TX_DESC_FLAGS0_NO_ENCRYPT` for a
    /// header-only MPDU under the firmware's current PTK; software-protected
    /// data and every EAPOL reply keep it (Linux `ATH10K_SKB_F_NO_HWCRYPT`).
    async fn send_data(
        &mut self,
        frame: &[u8],
        reply: bool,
        parameters: htt::tx::Parameters,
    ) -> Result<u16, Error> {
        let id = self.htt.transmit(parameters, frame).await?;
        let role = if reply {
            Role::Reply
        } else {
            Role::Data {
                tid: parameters.tid,
            }
        };
        self.station
            .data
            .as_mut()
            .ok_or(Error::Failed)?
            .pending
            .push(id, role, frame.len())?;
        Ok(id)
    }
    /// An EAPOL reply is non-QoS (`HTT_DATA_TX_EXT_TID_NON_QOS_MCAST_BCAST`
    /// 16). RAW sends the software form with `NO_ENCRYPT`; native WiFi sends
    /// `pending_frame_device`, firmware-encrypted exactly when Protected
    /// (`ath10k_tx_h_use_hwcrypto`).
    fn reply_parameters(&self, reply: &[u8]) -> Result<htt::tx::Parameters, Error> {
        let native_wifi = self.station.data.as_ref().ok_or(Error::Failed)?.native_wifi;
        Ok(htt::tx::Parameters {
            kind: if native_wifi {
                htt::tx::Kind::Native
            } else {
                htt::tx::Kind::Raw
            },
            vdev: self.station_vdev(),
            tid: 16,
            hardware_crypto: native_wifi && reply.get(1).is_some_and(|fc| fc & 0x40 != 0),
        })
    }
    /// Consume the same retained HTC/HTT owner used for join/teardown. Receive
    /// quiescence and a still-owned peer precede exposing any Ethernet batch.
    pub async fn poll_ethernet(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if self.failed || self.associated_station().is_none() || self.station.data.is_none() {
            return Err(Error::Failed);
        }
        self.check_data_policy(domain)?;
        self.failed = true;
        for _ in 0..256 {
            let idle = self
                .data_step(
                    &mut || {
                        let mut nonce = [0; 32];
                        narf_crypto::try_fill_random_bytes(&mut nonce)
                            .ok()
                            .map(|()| nonce)
                    },
                    &|| Ok(()),
                )
                .await?;
            if idle {
                let data = self.station.data.as_mut().ok_or(Error::Failed)?;
                if !data.open() {
                    data.received.clear();
                }
                let frames = data.received.drain(..).collect();
                self.failed = false;
                return Ok(frames);
            }
            narf_scheduler::yield_now().await;
        }
        Err(Error::Exhausted)
    }
    async fn data_step(
        &mut self,
        nonce: &mut impl FnMut() -> Option<[u8; 32]>,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<bool, Error> {
        validate()?;
        self.data_check()?;
        // A sibling slot's parked events first (`htt_rx.c` delivers by
        // `peer->vdev_id`), then the radio's queue, then a fresh poll.
        let event = match self.station.inbox.pop_front() {
            Some(e) => self.slot_event(e)?,
            None => match self.pending.pop_front() {
                Some(e) => e,
                None => checked_policy(self.station_progress(), validate).await?,
            },
        };
        let (idle, reply) = self.data_event(event, nonce)?;
        if let Some(reply) = reply {
            let parameters = self.reply_parameters(&reply)?;
            checked_policy(self.send_data(&reply, true, parameters), validate).await?;
        }
        checked_policy(self.send_station_keys(), validate).await?;
        checked_policy(self.send_station_management(), validate).await?;
        self.send_station_wmm(validate).await?;
        validate()?;
        self.service_station_pfc()?;
        Ok(idle)
    }
    fn service_station_pfc(&mut self) -> Result<(), Error> {
        if !self.htt.pfc_active() {
            return Ok(());
        }
        self.data_check()?;
        let data = self.station.data.as_ref().ok_or(Error::Failed)?;
        if data.failed {
            return Err(Error::Failed);
        }
        // Ordinary queued DATA needs its still-open original key/port. The
        // sole pending key reply instead has the exact Pipeline Reply owner;
        // reply_admissible already drained all earlier DATA native terminals.
        if !data.open() && !data.pending.reply_in_flight() {
            return Ok(());
        }
        let peer = self.station.peer.as_ref().ok_or(Error::Failed)?;
        self.htt.service_pfc(peer.bssid, peer.pfc_ids())?;
        Ok(())
    }
    fn data_check(&mut self) -> Result<(), Error> {
        if self
            .station
            .peer
            .as_ref()
            .and_then(|p| p.associated)
            .is_none()
            || self
                .station
                .peer
                .as_ref()
                .and_then(station::Peer::mapped)
                .is_none()
        {
            if let Some(data) = &mut self.station.data {
                data.fail();
            }
            return Err(Error::Failed);
        }
        if self
            .station
            .data
            .as_ref()
            .is_some_and(|d| d.pending.expired())
        {
            if let Some(data) = &mut self.station.data {
                data.fail();
            }
            return Err(Error::Timeout);
        }
        if self
            .station
            .data
            .as_ref()
            .is_some_and(|d| d.last_peer.expired())
        {
            if let Some(data) = &mut self.station.data {
                data.fail();
            }
            return Err(Error::Timeout);
        }
        Ok(())
    }
    fn data_event(
        &mut self,
        event: htt::Event,
        nonce: &mut impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<(bool, Option<Vec<u8>>), Error> {
        let source = self.htt.wmi.htc.transport.current_sources();
        let result = crate::ath10k::firmware_source::invoke(source.as_ref(), || {
            self.data_event_inner(event, nonce)
        })
        .map_err(|_| Error::Failed)
        .and_then(core::convert::identity);
        if result.is_err() {
            if let Some(data) = &mut self.station.data {
                data.fail();
            }
        }
        result
    }
    fn data_event_inner(
        &mut self,
        event: htt::Event,
        nonce: &mut impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<(bool, Option<Vec<u8>>), Error> {
        let idle = matches!(event, htt::Event::Idle);
        if self
            .station
            .peer
            .as_ref()
            .is_none_or(|peer| peer.associated.is_none() || peer.mapped().is_none())
        {
            if let Some(data) = &mut self.station.data {
                data.fail();
            }
            return Err(Error::Failed);
        }
        let peer = self.station.peer.as_ref().ok_or(Error::Failed)?;
        if peer.associated.is_none() || peer.mapped().is_none() {
            return Err(Error::Failed);
        }
        let own = self.station_own()?;
        let bssid = peer.bssid;
        let data = self.station.data.as_mut().ok_or(Error::Failed)?;
        let addresses = Addresses { own, bssid };
        let now = data.now();
        data.rx_ba.retain(|id| peer.owns(id));
        let expired = data.rx_ba.expire(now)?;
        data.queue_ready(expired)?;
        match event {
            htt::Event::Rx(batch) => {
                if peer.owns(batch.peer) {
                    for (status, frame) in batch.frames {
                        data.receive_native(frame, status, batch.peer, batch.tid, addresses, now)?;
                    }
                } else {
                    data.rx_ba.discard_ppdu();
                    // htt_rx.c ath10k_htt_rx_h_ppdu: the peer id selects
                    // `peer->vif`; another slot's peer gets its own batch.
                    if let Some(sibling) = self
                        .p2p_client
                        .as_deref_mut()
                        .filter(|s| s.owns_peer(batch.peer))
                    {
                        sibling.park(htt::Event::Rx(batch));
                    }
                }
            }
            htt::Event::InOrder(indication, frames) => {
                if !indication.offload
                    && !indication.fragment
                    && indication.vdev == peer.vdev
                    && peer.owns(indication.peer)
                {
                    for frame in frames {
                        data.receive_native(
                            frame,
                            1,
                            indication.peer,
                            indication.tid,
                            addresses,
                            now,
                        )?;
                    }
                } else {
                    data.rx_ba.discard_ppdu();
                    // htt_rx.c ath10k_htt_rx_h_rx_offload / in-order: the
                    // indication's vdev and peer select the sibling slot.
                    let primary = self.primary.id();
                    if let Some(sibling) = self.p2p_client.as_deref_mut().filter(|s| {
                        !indication.offload
                            && !indication.fragment
                            && indication.vdev == s.vdev.unwrap_or(primary)
                            && s.owns_peer(indication.peer)
                    }) {
                        sibling.park(htt::Event::InOrder(indication, frames));
                    }
                }
            }
            htt::Event::Wmi(bytes)
                if wire::word(&bytes, 0)? & 0xffffff == self.wire.management_event =>
            {
                let management = self.wire.management(&bytes[4..], self.features)?;
                let f = &management.frame;
                // A sibling station's BSS management (A2 or A3 its BSSID)
                // is its own: wmi.c ath10k_wmi_event_mgmt_rx hands it to
                // mac80211, which matches the frame to that vif.
                // A frame of this slot's own BSS stays here, so a parked
                // copy is never handed back.
                let primary = self.primary.id();
                let mine = f.len() >= 22 && (f[10..16] == bssid || f[16..22] == bssid);
                if let Some(sibling) = self
                    .p2p_client
                    .as_deref_mut()
                    .filter(|s| !mine && s.claims(&htt::Event::Wmi(Vec::new()), primary, Some(f)))
                {
                    sibling.park(htt::Event::Wmi(bytes.clone()));
                }
                if management.status & !0x40 == 0
                    && wire::channel_to_frequency(management.channel)
                        == Some(peer.permission.frequency)
                    && peer.ht.is_some()
                {
                    if let Some((tid, sequence)) = bar(f, addresses) {
                        let ready = data.rx_ba.station_bar(tid, sequence, now)?;
                        data.queue_ready(ready)?;
                    }
                }
                if let Some(beacon) = super::beacon(&management, &[peer.permission.frequency])? {
                    if beacon.bssid == bssid
                        && self
                            .scan_cache
                            .iter()
                            .any(|b| b.bssid == bssid && b.ssid == beacon.ssid)
                    {
                        if !self
                            .station
                            .coexistence
                            .as_ref()
                            .is_some_and(|s| s.blocked())
                            && peer
                                .ht
                                .is_some_and(|h| !h.matches_beacon(&beacon.information_elements))
                        {
                            return Err(Error::Unsupported);
                        }
                        data.last_peer = narf_time::Deadline::after_ms(5000);
                        // mac80211 ieee80211_handle_bss_capability (2.4 GHz):
                        // use_cts_prot = ERP present && Use_Protection; a
                        // change raises BSS_CHANGED_ERP_CTS_PROT.
                        if peer.permission.frequency < 3000 {
                            let erp = element(&beacon.information_elements, 42)?;
                            let wanted = erp.and_then(|b| b.first()).is_some_and(|v| v & 2 != 0);
                            let programmed =
                                self.station.protection.is_some_and(|r| r.cts_protection);
                            data.protection_update = (wanted != programmed).then_some(wanted);
                        }
                        // mac80211 ieee80211_sta_wmm_params: a changed
                        // Parameter Set Count reprograms every AC.
                        if let Some(current) = peer.wmm {
                            if let Some(update) =
                                super::wmm::beacon(current, &beacon.information_elements)?
                            {
                                data.wmm_update = Some(update);
                            }
                        }
                    }
                }
                let current = management.status & !0x40 == 0
                    && wire::channel_to_frequency(management.channel)
                        == Some(peer.permission.frequency);
                if let Some(security) = data.security.as_mut().filter(|s| s.pmf()) {
                    // mac80211 ieee80211_drop_unencrypted_mgmt: robust
                    // frames from the AP pass only CCMP (unicast) or BIP
                    // (group) admission once keys are in.
                    if current && f.len() >= 24 && matches!(f[0], 0xa0 | 0xc0 | 0xd0) {
                        // wmi.c ath10k_wmi_rx_is_decrypted: on a
                        // `peer_flags->pmf` peer the firmware decrypts a
                        // protected unicast deauth/disassoc/action with the
                        // installed PTK and keeps Protected, the CCMP header
                        // and the MIC, which mac80211 trims before its PN
                        // check. Before that PTK is confirmed (or without
                        // the flag) the host keeps full software CCMP.
                        let offloaded = self.station.peer_pmf_offload
                            && security.pairwise_offloaded()
                            && f[1] & 0x40 != 0
                            && f[4] & 1 == 0
                            && f.len() >= 24 + 8 + hw_keys::MIC_LEN;
                        let admitted = if offloaded {
                            security.receive_management_decrypted(&Native(
                                f[..f.len() - hw_keys::MIC_LEN].to_vec(),
                                true,
                            ))
                        } else {
                            security.receive_management(&Native(f.clone(), false))
                        };
                        if let MgmtRx::Frame(plain) = admitted.map_err(security_error)? {
                            if matches!(plain[0], 0xa0 | 0xc0) && plain.len() == 26 {
                                return Err(Error::Failed);
                            }
                            if let Some(response) = sa_query_response(&plain, own, bssid) {
                                if security.port_open() && data.management.is_none() {
                                    data.management = Some(protect_management(
                                        security,
                                        &response,
                                        self.station.peer_pmf_offload,
                                    )?);
                                }
                            }
                        }
                    }
                } else if current
                    && f.len() >= 26
                    && matches!(f[0], 0xa0 | 0xc0)
                    && f[1] & 0xc7 == 0
                    && f[22] & 15 == 0
                    && (f[4..10] == own || f[4..10] == [0xff; 6])
                    && f[10..16] == bssid
                    && f[16..22] == bssid
                {
                    return Err(Error::Failed);
                }
            }
            htt::Event::Message(bytes)
                if bytes.first() == Some(&hw_keys::SECURITY_INDICATION)
                    && data.security.as_ref().is_some_and(Security::hardware_keys) =>
            {
                // htt_rx.c HTT_T2H_MSG_TYPE_SEC_IND completes
                // install_key_done. Only the outstanding install's own
                // peer and key kind confirm it; a late or foreign indication
                // confirms nothing, so that slot stays software-only.
                if let (Some(flight), Some((id, unicast))) =
                    (data.key_in_flight, hw_keys::security_indication(&bytes))
                {
                    if peer.owns(id) && unicast == flight.pairwise {
                        data.key_in_flight = None;
                        data.security
                            .as_mut()
                            .ok_or(Error::Failed)?
                            .key_installed(flight.token);
                    }
                }
            }
            htt::Event::Message(bytes) if !matches!(bytes.first(), Some(3 | 4)) => {
                // An ADDBA/DELBA note names its peer id (`htt_rx.c`
                // ath10k_htt_rx_addba/delba); the sibling's goes to it alone,
                // so a parked note is never handed back.
                // Peer ids are unique, so a claimed note is never this slot's.
                let primary = self.primary.id();
                let event = htt::Event::Message(bytes);
                match self
                    .p2p_client
                    .as_deref_mut()
                    .filter(|s| s.claims(&event, primary, None))
                {
                    Some(sibling) => sibling.park(event),
                    None => {
                        let htt::Event::Message(bytes) = event else {
                            return Err(Error::Failed);
                        };
                        let ba = data.rx_ba.note(&bytes, |id| peer.owns(id))?;
                        // Fragment/PFC and their additional ownership remain separate.
                        if !ba
                            && matches!(bytes.first(), Some(0xb | 0xc | 0xd | 0x16 | 0x17 | 0x18))
                        {
                            return Err(Error::Unsupported);
                        }
                    }
                }
            }
            _ => {}
        }
        // Linux ath10k_htt_rx_tx_compl_ind -> ath10k_txrx_tx_unref: each ID
        // in a (possibly multi-MSDU) indication retires independently.
        // txrx.c ath10k_txrx_tx_unref: the msdu id names its skb and vif,
        // so a sibling slot's id is handed to that slot.
        while let Some(receipt) = self
            .station
            .receipts
            .pop_front()
            .or_else(|| self.htt.take_tx_receipt())
        {
            match data.pending.complete(receipt) {
                Completion::Foreign => {
                    // The GO session's own msdu id completes there.
                    let go = self
                        .ap
                        .as_deref_mut()
                        .is_some_and(|ap| ap.go_receipt(receipt));
                    if let Some(sibling) = self
                        .p2p_client
                        .as_deref_mut()
                        .filter(|s| !go && s.owns_msdu(receipt.id))
                    {
                        sibling.receipts.push_back(receipt);
                    }
                }
                Completion::Data { .. } => {}
                Completion::Reply { outcome, .. } if outcome != Outcome::Ack => {
                    return Err(Error::Firmware(u32::from(receipt.status)));
                }
                Completion::Reply { length, .. } => {
                    // Native reply completion is a receive-admission epoch
                    // boundary. Firmware BA agreements persist across rekey,
                    // but no retained PPDU PHY proof crosses this boundary.
                    data.rx_ba.discard_ppdu();
                    let security = data.security.as_mut().ok_or(Error::Failed)?;
                    if data.native_wifi {
                        security.reply_delivered_device(length)
                    } else {
                        security.reply_delivered(length)
                    }
                    .map_err(security_error)?;
                    // mac80211 set_key after the committing reply (PTK
                    // before GTK); programmed from the async data step.
                    data.keys.extend(security.take_key_installs());
                    if data.security.as_ref().is_some_and(Security::port_open) {
                        data.authorized = true;
                    }
                }
            }
        }
        // Keep the old current port/key while prior host entries await real
        // fetch publication. Otherwise accepting M3/group1 could close that
        // port before its queued originals drain. Native loss/UNMAP/beacon/
        // management handling above is never deferred. The existing Pipeline
        // then requires every old DATA air terminal before publishing M4.
        while !self.htt.pfc_queued()
            && !data.pending.reply_in_flight()
            && data
                .security
                .as_ref()
                .and_then(Security::pending_frame)
                .is_none()
        {
            let Some(incoming) = data.incoming.pop_front() else {
                break;
            };
            if !peer.owns(incoming.peer) {
                continue;
            }
            let frame = incoming.frame;
            if !incoming.data_admitted && !plaintext_eapol(&frame, addresses) {
                continue;
            }
            if !data.open() && !plaintext_eapol(&frame, addresses) {
                continue;
            }
            if frame.0[0] == 0x88 && frame.0[24] & 0x80 != 0 {
                // Native peer/PHY/TID admission precedes this path. Authenticate
                // the original aggregate once; splitting before MIC/replay
                // validation would assign authority to unauthenticated bytes.
                let frames = if let Some(security) = &mut data.security {
                    if frame.1 {
                        security
                            .receive_amsdu_decrypted_with(&frame, AmsduAdmission::new())
                            .map_err(security_error)?
                            .map(|r| r.frames)
                    } else {
                        security.receive_amsdu(&frame).map_err(security_error)?
                    }
                } else if frame.0[1] & 0x40 == 0 {
                    narf_wireless::amsdu::decode(
                        &frame.0[26..],
                        own,
                        frame.0[4..10].try_into().unwrap(),
                    )
                    .ok()
                } else {
                    None
                };
                if let Some(frames) = frames {
                    if data.received.len().saturating_add(frames.len()) > RECEIVED_FRAMES {
                        return Err(Error::Exhausted);
                    }
                    data.last_peer = narf_time::Deadline::after_ms(5000);
                    data.received.extend(frames);
                }
                continue;
            }
            let normalized = if let Some(security) = &mut data.security {
                let received = if frame.1 {
                    security.receive_decrypted_with_nonce(&frame, &mut *nonce)
                } else {
                    security.receive_with_nonce(&frame, &mut *nonce)
                };
                match received.map_err(security_error)? {
                    Rx::Ignored => None,
                    Rx::Data(frame) => {
                        data.last_peer = narf_time::Deadline::after_ms(5000);
                        Some(frame)
                    }
                    Rx::ReplyReady => {
                        // A reply fences a new receive admission/key epoch.
                        // Never allow a late native TX receipt to authorize
                        // data observed while the earlier port was closed.
                        data.received.clear();
                        data.rx_ba.flush();
                        data.incoming
                            .retain(|incoming| plaintext_eapol(&incoming.frame, addresses));
                        data.last_peer = narf_time::Deadline::after_ms(5000);
                        break;
                    }
                }
            } else {
                Some(frame.0)
            };
            if let Some(frame) = normalized.and_then(|f| ethernet(&f, own, bssid)) {
                data.last_peer = narf_time::Deadline::after_ms(5000);
                if data.received.len() == RECEIVED_FRAMES {
                    return Err(Error::Exhausted);
                }
                data.received.push_back(frame);
            }
        }
        // Key-reply fence: the reply waits for every earlier data ID.
        let reply = if data.pending.reply_admissible() {
            data.security
                .as_ref()
                .and_then(|security| {
                    if data.native_wifi {
                        security.pending_frame_device()
                    } else {
                        security.pending_frame()
                    }
                })
                .map(wire::owned)
                .transpose()?
        } else {
            None
        };
        Ok((idle, reply))
    }
}

/// mac80211 `ieee80211_process_sa_query_req`: a unicast SA Query Request
/// (category8, action0, 2-byte transaction id) from the bound AP is
/// answered with a Response carrying the same id, to be CCMP-protected.
fn sa_query_response(frame: &[u8], own: [u8; 6], bssid: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() != 28
        || frame[0] != 0xd0
        || frame[4..10] != own
        || frame[10..16] != bssid
        || frame[16..22] != bssid
        || frame[24..26] != [8, 0]
    {
        return None;
    }
    let mut out = alloc::vec![0xd0, 0, 0, 0];
    out.extend_from_slice(&bssid);
    out.extend_from_slice(&own);
    out.extend_from_slice(&bssid);
    out.extend_from_slice(&[0, 0, 8, 1, frame[26], frame[27]]);
    Some(out)
}

/// Linux htt_rx.c::ath10k_htt_rx_h_undecap_raw strips only FCS for software
/// crypto. Admit a single, complete, original native MPDU and bind both the
/// indication and descriptor to an owned sparse peer/TID before shared RSNA.
/// With `hardware` keys an MPDU the firmware decrypted (`is_decrypted`:
/// AES-CCM, no FCS/decrypt/peer-index error) also loses its MIC, keeping
/// Protected and the CCMP header for the host PN check (`fill_crypt_header`).
#[allow(clippy::too_many_arguments)]
fn raw_frame(
    mut msdu: htt::rx::Msdu,
    status: u8,
    peer: u16,
    tid: u8,
    addresses: Addresses,
    ba: &mut rx_ba::Owner,
    now: u64,
    hardware: bool,
) -> Result<Option<NativeEvent>, Error> {
    let result = raw_frame_inner(&mut msdu, status, peer, tid, addresses, ba, now, hardware);
    if !matches!(&result, Ok(Some(_))) {
        // No malformed header/foreign indication may seed or bridge a PPDU.
        ba.discard_ppdu();
    }
    result
}
#[allow(clippy::too_many_arguments)]
fn raw_frame_inner(
    msdu: &mut htt::rx::Msdu,
    status: u8,
    peer: u16,
    tid: u8,
    Addresses { own, bssid }: Addresses,
    ba: &mut rx_ba::Owner,
    now: u64,
    hardware: bool,
) -> Result<Option<NativeEvent>, Error> {
    if msdu.offload.is_some() || !matches!(status, 1 | 6 | 10) || msdu.descriptor.len() < 116 {
        return Ok(None);
    }
    let descriptor = &msdu.descriptor;
    let word = |at: usize| u32::from_le_bytes(descriptor[at..at + 4].try_into().unwrap());
    let attention = word(4);
    let errors = (1 << 3)
        | (1 << 4)
        | (1 << 7)
        | (1 << 8)
        | (1 << 13)
        | (1 << 16)
        | (1 << 17)
        | (1 << 27)
        | (1 << 28)
        | (1 << 30);
    let start = word(12);
    if attention & (1 << 31) == 0
        || attention & errors != 0
        || word(32) & 0x300 != 0
        || word(56) & 0xc000 != 0xc000
        || (word(24) & 0x3fff) as usize != msdu.payload.len()
        || start & 0x7ff != u32::from(peer)
        || word(20) >> 28 != u32::from(if tid == 16 { 0 } else { tid })
        || !(24..=4096).contains(&msdu.payload.len())
    {
        return Ok(None);
    }
    // A no-key RAW profile may report DECRYPT_ERR; it must never hand already
    // decrypted ciphertext to software CCMP. NONE or an actual failed CCMP
    // decrypt preserves the wire MPDU. The software MIC remains authoritative.
    let encrypted = msdu.payload[1] & 0x40 != 0;
    let enctype = start >> 28;
    // htt_rx.c ath10k_htt_rx_h_mpdu `is_decrypted`: AES_CCM_WPA2 (6) without
    // DECRYPT_ERR (FCS/peer-index errors were refused above). Only the
    // hardware-key profile installs keys, so only it may see one.
    let decrypted = hardware
        && status == 1
        && encrypted
        && enctype == 6
        && attention & (1 << 29) == 0
        && msdu.payload.len() >= 24 + 8 + hw_keys::MIC_LEN + 4;
    if status == 10 && !encrypted
        || encrypted && !decrypted && !(enctype == 7 || enctype == 6 && attention & (1 << 29) != 0)
        || !encrypted && enctype != 7
    {
        return Ok(None);
    }
    msdu.payload.truncate(msdu.payload.len() - 4); // native RAW carries FCS
    if decrypted {
        // RX_FLAG_MIC_STRIPPED | RX_FLAG_ICV_STRIPPED (CCMP has no ICV).
        msdu.payload.truncate(msdu.payload.len() - hw_keys::MIC_LEN);
    }
    let frame = &msdu.payload;
    if let Some((bar_tid, sequence)) = bar(frame, Addresses { own, bssid }) {
        // BAR is a non-QoS control MPDU, with neither DS bit set. Firmware
        // descriptor TID is the non-QoS sentinel, not BAR control's TID.
        if status == 1
            && tid == 16
            && start & 0x1800 == 0
            && attention & (1 << 9) != 0
            && attention & 3 == 3
            && ba.ht()
            && ba.phy(peer, tid, descriptor, false, frame.len() + 4, now)
        {
            return Ok(Some(NativeEvent::Bar {
                tid: bar_tid,
                sequence,
            }));
        }
        return Ok(None);
    }
    if frame.len() < 24
        || !matches!(frame[0], 8 | 0x88)
        || frame[1] & 0x87 != 2
        || start & 0x1800 != 0x800
        || attention & (1 << 9) != 0
        || u32::from(u16::from_le_bytes([frame[22], frame[23]]) >> 4) != (start >> 16) & 0xfff
        || frame[22] & 15 != 0
        || frame[10..16] != bssid
        || frame[4..10] != own && frame[4] & 1 == 0
        || frame[16..22] == [0; 6]
        || frame[16] & 1 != 0
    {
        return Ok(None);
    }
    let qos = frame[0] == 0x88;
    if qos && (frame.len() < 26 || frame[24] & 15 != tid || frame[24] & 0x80 != 0 && !ba.ht())
        || !qos && tid != 16
    {
        return Ok(None);
    }
    if qos && frame[24] & 0x80 != 0 && (frame[24] & 0xf0 != 0x80 || frame[25] != 0) {
        return Ok(None);
    }
    if status == 6 {
        let at = if qos { 26 } else { 24 };
        if encrypted || frame.get(at..at + 8) != Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]) {
            return Ok(None);
        }
    }
    // The PPDU length proof uses the original on-air MPDU length.
    let air = frame.len() + 4 + if decrypted { hw_keys::MIC_LEN } else { 0 };
    if !ba.phy(peer, tid, descriptor, qos && frame[4] & 1 == 0, air, now) {
        return Ok(None);
    }
    Ok(Some(NativeEvent::Data(Native(
        core::mem::take(&mut msdu.payload),
        decrypted,
    ))))
}

/// IEEE compressed, single-TID BAR. RA/TA bind the control to the current
/// association; only an existing native peer/TID BA owner may advance it.
fn bar(frame: &[u8], addresses: Addresses) -> Option<(u8, u16)> {
    if frame.len() != 20
        || frame[..2] != [0x84, 0]
        || frame[4..10] != addresses.own
        || frame[10..16] != addresses.bssid
    {
        return None;
    }
    let control = u16::from_le_bytes([frame[16], frame[17]]);
    let sequence = u16::from_le_bytes([frame[18], frame[19]]);
    if control & 0x0fff != 4 || sequence & 15 != 0 {
        return None;
    }
    Some(((control >> 12) as u8, sequence >> 4))
}

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(super) fn coexistence_ready(&self) -> bool {
        self.station
            .data
            .as_ref()
            .is_some_and(State::protection_allowed)
            && !self.scan_in_progress()
    }
    pub(super) fn coexistence_receipt(&mut self, receipt: htt::TxReceipt) -> Result<(), Error> {
        self.station
            .data
            .as_mut()
            .ok_or(Error::Failed)?
            .protection_receipt(receipt)
    }
    pub(super) fn narrow_coexistence_receive(&mut self, primary: u16) -> Result<(), Error> {
        let data = self.station.data.as_mut().ok_or(Error::Failed)?;
        if !data.protection_allowed() {
            return Err(Error::Failed);
        }
        // The receive owner caches its own original PHY profile. Rebind it
        // only with the terminal-proven narrowed peer, retaining key/PN and
        // BA session ownership while discarding the old PPDU/reorder epoch.
        data.rx_ba.narrow_coexistence(primary)
    }
    pub(super) fn discard_coexistence_receive(&mut self) -> Result<(), Error> {
        let data = self.station.data.as_mut().ok_or(Error::Failed)?;
        if !data.protection_allowed() {
            return Err(Error::Failed);
        }
        data.incoming.clear();
        data.received.clear();
        data.rx_ba.flush();
        self.pending.clear();
        Ok(())
    }
}

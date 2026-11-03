// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained ath10k WMI vdev/passive-scan owner over the real HTC/HTT runtime.
//! Creating a scan vdev does not authorize station traffic or a controlled port.
use crate::ath10k::{
    control::Hif,
    htt_runtime::{self as htt, HttMemory},
    wmi_boot::{self, Dialect, HostMemory},
};
use alloc::{collections::VecDeque, vec::Vec};
#[path = "wmi_runtime/management.rs"]
pub(super) mod management;
#[path = "wmi_runtime/wire.rs"]
mod wire;
pub use management::{
    Completion as ManagementCompletion, Receipt as ManagementReceipt, Token as ManagementToken,
};
mod active_scan;
pub(in crate::ath10k) mod ap;
mod ap_beacon;
mod ap_control;
mod ap_key;
mod ap_keys;
mod ap_native;
mod ap_packet;
mod ap_staging;
mod ap_stop;
mod ap_tx;
mod ap_wire;
mod associated_scan;
mod dwell_scan;
pub(in crate::ath10k) use active_scan::checked as checked_policy;
pub(in crate::ath10k) use associated_scan::receive_permission;
pub(in crate::ath10k) use dwell_scan::ScanPolicy;
#[path = "wmi_runtime/beacon_hints.rs"]
pub(in crate::ath10k) mod beacon_hints;
mod chains;
mod coexistence;
mod data;
mod host_power;
mod ht;
mod hw_keys;
mod mlme;
mod nwifi;
pub(in crate::ath10k) mod offchannel;
// The P2P client netdev role (iftype 8) binds the vdev owner next.
#[allow(dead_code)]
mod p2p_client;
mod p2p_device;
// Role owners (P2P device/client/GO) bind these codecs in later steps.
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
mod p2p;
mod power_save;
mod protection;
pub use protection::Request as StationProtection;
mod wmm;
pub mod wow;
pub use data::Link as StationLink;
pub use mlme::Associated as StationAssociated;
pub use station::Disconnected as StationDisconnected;
pub(in crate::ath10k) use wire::validate_probe_ies;
pub(crate) use wire::{MAX_SCAN_IE_LEN, MAX_SCAN_SSIDS};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Htt(htt::Error),
    Wmi(wmi_boot::Error),
    Malformed,
    Failed,
    NoMemory,
    Unsupported,
    Timeout,
    Exhausted,
    Firmware(u32),
}
impl From<htt::Error> for Error {
    fn from(e: htt::Error) -> Self {
        Self::Htt(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ScanEvent {
    kind: u32,
    reason: u32,
    frequency: u32,
    request: u32,
    sequence: u32,
    vdev: u32,
}
#[derive(Debug)]
pub(super) struct Management {
    pub channel: u32,
    pub snr: u32,
    pub status: u32,
    pub frame: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct ScanBss {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub frequency: u16,
    pub snr: u32,
    pub capability: u16,
    pub beacon_interval: u16,
    pub information_elements: Vec<u8>,
}
#[derive(Debug)]
pub struct ScanReport {
    pub bss: Vec<ScanBss>,
    pub received: u32,
    pub ignored: u32,
    pub truncated: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanReady {
    pub mac: [u8; 6],
    pub channels: u8,
}
/// One station owner (Linux `struct ath10k_vif` station state for one
/// `arvif->vdev_id`): its BSS peer, data path, power save, protection,
/// 20/40 coexistence and PMF offload. `Radio` keeps the home slot on the
/// managed vdev; a P2P client role owns a second slot on its own vdev.
#[derive(Debug)]
pub(super) struct StationSlot {
    peer: Option<station::Peer>,
    data: Option<data::State>,
    /// The current PEER_ASSOC carried `peer_flags->pmf`: firmware decrypts
    /// this peer's robust management (`hw_keys::management_offload`).
    peer_pmf_offload: bool,
    power_save: Option<bool>,
    protection: Option<StationProtection>,
    coexistence: Option<alloc::boxed::Box<coexistence::State>>,
    /// The vdev this slot's BSS peer, data and management use; `None` is
    /// the managed vdev (`Radio::primary`), so the home slot follows an AP
    /// that replaced and restored it on the same id.
    vdev: Option<u8>,
    /// The slot's own (A2) address; `None` is the INIT address.
    own: Option<[u8; 6]>,
    /// HTT events another slot's data step polled but this slot's peer or
    /// vdev owns (`htt_rx.c`: RX is delivered to `peer->vdev_id`'s vif).
    inbox: VecDeque<htt::Event>,
    /// TX completions for this slot's MSDU ids taken by another slot
    /// (`txrx.c::ath10k_txrx_tx_unref`: msdu_id -> skb -> its vif).
    receipts: VecDeque<htt::TxReceipt>,
}
/// Bound on HTT events parked for an idle sibling slot; overflow fails
/// that slot's data owner rather than growing without limit.
const SLOT_INBOX: usize = 256;
/// Bound on the radio's BSS table (a scan report holds at most 64).
const SCAN_CACHE: usize = 64;
impl StationSlot {
    const fn new() -> Self {
        Self {
            peer: None,
            data: None,
            peer_pmf_offload: false,
            power_save: None,
            protection: None,
            coexistence: None,
            vdev: None,
            own: None,
            inbox: VecDeque::new(),
            receipts: VecDeque::new(),
        }
    }
    /// A P2P client slot on its own STA/P2P_CLI vdev and address.
    // Bound by the P2P client netdev role (iftype 8) in a later step.
    #[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
    pub(super) const fn client(vdev: u8, own: [u8; 6]) -> Self {
        let mut slot = Self::new();
        slot.vdev = Some(vdev);
        slot.own = Some(own);
        slot
    }
    /// Park an HTT event for this slot. Every slot filters by its own peer
    /// ids, vdev and BSSID, so a copy it does not own is ignored there.
    fn park(&mut self, event: htt::Event) {
        if self.inbox.len() >= SLOT_INBOX {
            if let Some(data) = &mut self.data {
                data.fail();
            }
            return;
        }
        self.inbox.push_back(event);
    }
    /// Whether this slot's BSS peer owns HTT peer id `id`.
    fn owns_peer(&self, id: u16) -> bool {
        self.peer.as_ref().is_some_and(|p| p.owns(id))
    }
    /// Whether this slot's data owner has MSDU `id` in flight.
    fn owns_msdu(&self, id: u16) -> bool {
        self.data.as_ref().is_some_and(|d| d.owns_msdu(id))
    }
    /// Whether this slot owns an HTT event, wherever it was polled.
    /// `htt_rx.c` delivers a legacy RX batch by its peer id
    /// (`ath10k_htt_rx_h_ppdu` -> `peer->vif`), an in-order indication by
    /// its vdev and peer, and an ADDBA/DELBA note names a peer id
    /// (`ath10k_htt_rx_addba`/`ath10k_htt_rx_delba`, info `>> 4`);
    /// mac80211 hands WMI management RX (`frame`, already decoded) to the
    /// vif whose BSSID is its A2 or A3. Every other event is radio-level or
    /// filtered by each owner itself.
    pub(super) fn claims(&self, event: &htt::Event, primary: u8, frame: Option<&[u8]>) -> bool {
        match event {
            htt::Event::Rx(batch) => self.owns_peer(batch.peer),
            htt::Event::InOrder(i, _) => {
                !i.offload
                    && !i.fragment
                    && i.vdev == self.vdev.unwrap_or(primary)
                    && self.owns_peer(i.peer)
            }
            htt::Event::Message(b) if b.len() == 4 && matches!(b[0], 5 | 6) => {
                self.owns_peer(u16::from_le_bytes([b[2], b[3]]) >> 4)
            }
            htt::Event::Wmi(_) => match (frame, &self.peer) {
                (Some(f), Some(p)) => {
                    f.len() >= 22 && (f[10..16] == p.bssid || f[16..22] == p.bssid)
                }
                _ => false,
            },
            _ => false,
        }
    }
}
/// Runs the radio's station paths on the P2P client slot: the slots are
/// exchanged for the guard's lifetime and restored on drop, including when
/// an async step holding it is cancelled.
pub(super) struct ClientScope<'a, T: Hif + HostMemory + HttMemory> {
    radio: &'a mut Radio<T>,
}
impl<T: Hif + HostMemory + HttMemory> core::ops::Deref for ClientScope<'_, T> {
    type Target = Radio<T>;
    fn deref(&self) -> &Radio<T> {
        self.radio
    }
}
impl<T: Hif + HostMemory + HttMemory> core::ops::DerefMut for ClientScope<'_, T> {
    fn deref_mut(&mut self) -> &mut Radio<T> {
        self.radio
    }
}
impl<T: Hif + HostMemory + HttMemory> Drop for ClientScope<'_, T> {
    fn drop(&mut self) {
        self.radio.exchange_client();
    }
}
/// One netdev's owner of the radio mutex: the home netdev runs on the home
/// slot; the P2P client netdev holds the slots exchanged (a `ClientScope`
/// that owns the guard) for as long as it holds the radio, so every station
/// path it calls runs on the client vdev and nothing else observes the
/// exchanged state.
pub(in crate::ath10k) struct StationGuard<'a, T: Hif + HostMemory + HttMemory> {
    guard: narf_lib::mutex::MutexGuard<'a, Radio<T>>,
    client: bool,
}
impl<'a, T: Hif + HostMemory + HttMemory> StationGuard<'a, T> {
    /// `None` for a client owner whose slot does not exist (not yet
    /// created, or already deleted).
    pub(in crate::ath10k) fn new(
        mut guard: narf_lib::mutex::MutexGuard<'a, Radio<T>>,
        client: bool,
    ) -> Option<Self> {
        if client {
            if guard.in_client_scope || guard.p2p_client.is_none() {
                return None;
            }
            guard.exchange_client();
        }
        Some(Self { guard, client })
    }
}
impl<T: Hif + HostMemory + HttMemory> core::ops::Deref for StationGuard<'_, T> {
    type Target = Radio<T>;
    fn deref(&self) -> &Radio<T> {
        &self.guard
    }
}
impl<T: Hif + HostMemory + HttMemory> core::ops::DerefMut for StationGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Radio<T> {
        &mut self.guard
    }
}
impl<T: Hif + HostMemory + HttMemory> Drop for StationGuard<'_, T> {
    fn drop(&mut self) {
        if self.client {
            self.guard.exchange_client();
        }
    }
}
#[derive(Debug)]
pub(super) struct Radio<T> {
    scan_cache: Vec<ScanBss>,
    beacon_hints: beacon_hints::Owner,
    hint_scan: Option<beacon_hints::Scan>,
    management_done: VecDeque<ManagementCompletion>,
    /// The managed netdev's station owner on `primary` (Linux's home
    /// `arvif`); the P2P client slot is a second, independent owner.
    station: StationSlot,
    /// The P2P client's station slot while one exists (outside a
    /// `ClientScope`; inside one it holds the home slot).
    p2p_client: Option<alloc::boxed::Box<StationSlot>>,
    /// A `ClientScope` holds the slots exchanged.
    in_client_scope: bool,
    ap: Option<alloc::boxed::Box<ap::Session>>,
    ap_staging: Option<alloc::boxed::Box<ap::Staging>>,
    ap_history: Option<alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<ap_key::History>>>,
    ap_sequence: u32,
    ap_dirty_wmm: bool,
    pub htt: htt::Runtime<T>,
    wire: wire::Wire,
    /// `ar->free_vdev_map` from the real INIT resource count; set by
    /// `start`, which allocates the managed role's vdev first.
    vdev_map: Option<p2p::VdevMap>,
    /// The managed netdev's vdev (station discovery, or the AP that replaced
    /// it on the same id). Station peer/data and AP owners route by its id;
    /// additional P2P role vdevs are allocated from `vdev_map` beside it.
    primary: p2p::Vdev,
    /// The control-only P2P_DEVICE vdev (`p2p_device.rs`), if created.
    p2p_device: Option<p2p::Vdev>,
    /// The P2P_DEVICE wdev address the vdev was created with (its frames'
    /// A2/A3 and the directed-RX filter on that vdev).
    p2p_device_mac: [u8; 6],
    features: u64,
    /// Linux `cryptmode=0` beside the RAW decap: station PTK/GTK go to the
    /// firmware key cache (`hw_keys`), software CCMP stays the fallback.
    hardware_keys: bool,
    pub ready: Option<ScanReady>,
    channels: Vec<u16>,
    sequence: u16,
    // Set before any scan setup publication, cleared only after a matched
    // terminal plus successful restore. A dropped public future leaves this
    // retained for the registered worker's STOP/vdev cleanup.
    scan_pending: Option<u16>,
    /// The vdev `scan_pending` runs on (`ar->scan.vdev_id`): its events and
    /// a retained STOP's terminal must carry it.
    scan_vdev: u32,
    scan_terminal: Option<u16>,
    scan_dwell: Option<dwell_scan::Work>,
    roc: Option<alloc::boxed::Box<offchannel::Work>>,
    pending: VecDeque<htt::Event>,
    failed: bool,
    /// WOW_ENABLE was acknowledged; only `wow::wow_resume` may follow.
    wow_armed: bool,
    chains: Option<chains::Chains>,
    management_subscriptions: Option<alloc::sync::Arc<offchannel::Subscriptions>>,
    management_received: VecDeque<offchannel::Captured>,
    management_completed: Option<offchannel::Completed>,
    coexistence_epoch: alloc::sync::Arc<core::sync::atomic::AtomicU64>,
    /// `ath10k_wmi_adaptive_qcs(ar, true)` was sent at start (TLV service
    /// ADAPTIVE_OCS): firmware schedules two channels across vdevs.
    adaptive_qcs: bool,
}
impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) fn configured_channels(&self) -> &[u16] {
        &self.channels
    }
    pub fn information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.scan_cache
            .iter()
            .find(|b| b.bssid == bssid)
            .map(|b| b.information_elements.clone())
    }
    pub fn new(htt: htt::Runtime<T>, dialect: Dialect, features: u64) -> Self {
        Self {
            station: StationSlot::new(),
            p2p_client: None,
            in_client_scope: false,
            ap: None,
            ap_staging: None,
            ap_history: None,
            ap_sequence: 0,
            ap_dirty_wmm: false,
            htt,
            wire: wire::Wire::new(dialect),
            vdev_map: None,
            primary: p2p::Vdev::new(0, p2p::Role::Station),
            p2p_device: None,
            p2p_device_mac: [0; 6],
            features,
            hardware_keys: false,
            ready: None,
            scan_cache: Vec::new(),
            beacon_hints: beacon_hints::Owner::new(),
            hint_scan: None,
            management_done: VecDeque::new(),
            channels: Vec::new(),
            sequence: 0,
            scan_pending: None,
            scan_vdev: 0,
            scan_terminal: None,
            scan_dwell: None,
            roc: None,
            pending: VecDeque::new(),
            failed: false,
            wow_armed: false,
            chains: None,
            management_subscriptions: None,
            management_received: VecDeque::new(),
            management_completed: None,
            coexistence_epoch: alloc::sync::Arc::new(core::sync::atomic::AtomicU64::new(0)),
            adaptive_qcs: false,
        }
    }
    /// Select station hardware key offload (Linux `cryptmode=0`) before the
    /// first association. Software crypto remains the per-frame fallback.
    pub fn with_hardware_keys(mut self, enabled: bool) -> Self {
        self.hardware_keys = enabled;
        self
    }
    /// No country policy is inferred here: these are receive-only IEEE
    /// channels intersected with the target's actual SERVICE_READY limits.
    pub async fn start_from_hardware(&mut self) -> Result<ScanReady, Error> {
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?;
        let mut channels = Vec::new();
        channels
            .try_reserve_exact(64)
            .map_err(|_| Error::NoMemory)?;
        for frequency in (2412..=2472)
            .step_by(5)
            .chain(core::iter::once(2484))
            .chain((5180..=5320).step_by(20))
            .chain((5500..=5720).step_by(20))
            .chain((5745..=5825).step_by(20))
        {
            if wire::supported(caps, frequency) {
                channels.push(frequency);
            }
        }
        self.start(&channels).await
    }
    pub async fn start(&mut self, channels: &[u16]) -> Result<ScanReady, Error> {
        if self.failed || self.ready.is_some() || self.htt.ready.is_none() {
            return Err(Error::Failed);
        }
        wire::validate_channels(channels)?;
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?;
        if channels.iter().any(|f| !wire::supported(caps, *f)) {
            return Err(Error::Unsupported);
        }
        let mac = self.htt.wmi.ready.ok_or(Error::Failed)?.mac;
        // `mac.c::ath10k_add_interface`: the first interface takes the
        // lowest free id of `(1 << max_num_vdevs) - 1`, i.e. vdev 0.
        let (vdevs, _) = self.htt.wmi.ap_resources().ok_or(Error::Failed)?;
        let mut vdev_map = p2p::VdevMap::new(vdevs)?;
        let primary = p2p::Vdev::new(vdev_map.allocate()?, p2p::Role::Station);
        let create = primary.create(&self.wire, mac)?;
        let configured = self.wire.channels(channels)?;
        let chains =
            chains::Chains::new(self.htt.wmi.initialized_chain_mask.ok_or(Error::Failed)?)?;
        let chain_commands = chains.commands(self.wire.dialect)?;
        // `mac.c::ath10k_start`: with `WMI_SERVICE_ADAPTIVE_OCS` enable
        // adaptive QCS before any interface is added (failure aborts start).
        let qcs = (self.wire.dialect == Dialect::Tlv
            && caps.service(Dialect::Tlv, p2p::SERVICE_ADAPTIVE_OCS))
        .then(|| p2p::adaptive_qcs(Dialect::Tlv, true))
        .transpose()?;
        let vdev_nss = chains.vdev_nss_for(self.wire.dialect, primary.id())?;
        self.channels
            .try_reserve_exact(channels.len())
            .map_err(|_| Error::NoMemory)?;
        // No await can expose a reusable vdev/command owner after an
        // ambiguous publication. DMA remains in the nested mission owner.
        self.failed = true;
        for command in chain_commands {
            self.htt
                .wmi
                .htc
                .transport
                .check_current()
                .map_err(crate::ath10k::control::Error::from)
                .map_err(htt::Error::from)?;
            self.htt
                .wmi
                .htc
                .send_wmi(&command)
                .await
                .map_err(htt::Error::from)?;
        }
        if let Some(qcs) = &qcs {
            self.htt
                .wmi
                .htc
                .send_wmi(qcs)
                .await
                .map_err(htt::Error::from)?;
        }
        self.htt
            .wmi
            .htc
            .send_wmi(&create)
            .await
            .map_err(htt::Error::from)?;
        self.htt
            .wmi
            .htc
            .send_wmi(&vdev_nss)
            .await
            .map_err(htt::Error::from)?;
        self.htt
            .wmi
            .htc
            .send_wmi(&configured)
            .await
            .map_err(htt::Error::from)?;
        self.channels.extend_from_slice(channels);
        let ready = ScanReady {
            mac,
            channels: channels.len() as u8,
        };
        self.htt
            .wmi
            .htc
            .transport
            .check_current()
            .map_err(crate::ath10k::control::Error::from)
            .map_err(htt::Error::from)?;
        self.chains = Some(chains);
        self.vdev_map = Some(vdev_map);
        self.primary = primary;
        self.adaptive_qcs = qcs.is_some();
        self.ready = Some(ready);
        self.failed = false;
        Ok(ready)
    }
    /// Scan IDs never wrap within this firmware owner's lifetime. A timeout,
    /// failed scan or dropped future leaves the owner closed until reset.
    pub async fn passive_scan(&mut self, channels: &[u16]) -> Result<ScanReport, Error> {
        self.scan_run(channels, (&[], &[]), &[], None, || Ok(()))
            .await
    }
    async fn scan_run(
        &mut self,
        channels: &[u16],
        probes: (&[Vec<u8>], &[u8]),
        setup: &[Vec<u8>],
        restore: Option<&[u8]>,
        validate: impl Fn() -> Result<(), Error>,
    ) -> Result<ScanReport, Error> {
        self.scan_run_on(None, channels, probes, setup, restore, validate)
            .await
    }
    /// `p2p_device`: run on the P2P_DEVICE vdev (`ath10k_hw_scan` with
    /// `ar->scan.vdev_id = arvif->vdev_id`) instead of the managed role's
    /// vdev. Its discoveries are merged into the shared BSS table
    /// (`publish_scan_cache`), as cfg80211's per-wiphy table.
    async fn scan_run_on(
        &mut self,
        p2p_device: Option<u8>,
        channels: &[u16],
        probes: (&[Vec<u8>], &[u8]),
        setup: &[Vec<u8>],
        restore: Option<&[u8]>,
        validate: impl Fn() -> Result<(), Error>,
    ) -> Result<ScanReport, Error> {
        if self.failed
            || self.ready.is_none()
            || self.station.peer.is_some()
            || self.scan_pending.is_some()
        {
            return Err(Error::Failed);
        }
        if p2p_device.is_some_and(|vdev| self.p2p_device_vdev() != Some(vdev) || self.roc.is_some())
        {
            return Err(Error::Unsupported);
        }
        // Inside a `ClientScope` the scan runs on the P2P client vdev
        // (`ath10k_hw_scan` on that vif). The firmware's single scan engine
        // and this owner's unassociated scan loop do not service the home
        // slot's data, so the home station must have no peer.
        let client = p2p_device.is_none() && self.in_client_scope;
        if client
            && self
                .p2p_client
                .as_deref()
                .is_some_and(|home| home.peer.is_some())
        {
            return Err(Error::Unsupported);
        }
        let scan_vdev = match p2p_device {
            Some(vdev) => u32::from(vdev),
            None if client => u32::from(self.station_vdev()),
            None => self.primary_vdev(),
        };
        wire::validate_channels(channels)?;
        if channels.iter().any(|f| !self.channels.contains(f)) {
            return Err(Error::Unsupported);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .filter(|n| *n <= 4095)
            .ok_or(Error::Exhausted)?;
        let (ssids, extra_ies) = probes;
        let command = if let Some(vdev) = p2p_device {
            self.wire
                .p2p_device_scan(vdev, sequence, channels, ssids, extra_ies)?
        } else if client {
            self.wire
                .scan_on_vdev(self.station_vdev(), sequence, channels, ssids, extra_ies)?
        } else if ssids.is_empty() {
            self.wire.scan(sequence, channels)?
        } else {
            self.wire
                .active_scan(sequence, channels, ssids, extra_ies)?
        };
        let mut report = ScanReport {
            bss: Vec::new(),
            received: 0,
            ignored: 0,
            truncated: false,
        };
        report
            .bss
            .try_reserve_exact(64)
            .map_err(|_| Error::NoMemory)?;
        self.sequence = sequence;
        self.failed = true;
        self.scan_pending = Some(sequence);
        self.scan_vdev = scan_vdev;
        self.begin_beacon_hint_scan(sequence, channels);
        self.scan_terminal = None;
        let retained = self.htt.wmi.htc.transport.nonblocking_wmi();
        for packet in setup
            .iter()
            .map(Vec::as_slice)
            .chain(core::iter::once(command.as_slice()))
        {
            if retained {
                self.send_scan_command(packet, &validate).await?;
            } else {
                active_scan::checked(
                    async {
                        self.htt
                            .wmi
                            .htc
                            .send_wmi(packet)
                            .await
                            .map_err(htt::Error::from)
                            .map_err(Error::from)
                    },
                    &validate,
                )
                .await?;
            }
        }
        let deadline = narf_time::Deadline::after_ms(25_000);
        loop {
            narf_scheduler::yield_now().await;
            validate()?;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = if retained {
                self.htt.poll_now()?
            } else {
                active_scan::checked(
                    async { self.htt.poll().await.map_err(Error::from) },
                    &validate,
                )
                .await?
            };
            self.observe_beacon_hint_event(&event)?;
            match event {
                htt::Event::Wmi(bytes) => {
                    let id = wire::word(&bytes, 0)? & 0xffffff;
                    if id == self.wire.scan_event {
                        let event = self.wire.scan_event(&bytes[4..])?;
                        if event.sequence != 0xa000 | u32::from(sequence)
                            || event.request != 0xa001
                            || event.vdev != scan_vdev
                        {
                            report.ignored = report.ignored.saturating_add(1);
                            continue;
                        }
                        if matches!(event.kind, 2 | 64) {
                            self.scan_terminal = Some(sequence);
                        }
                        match event.kind {
                            2 if event.reason == 0 => {
                                if let Some(packet) = restore {
                                    if retained {
                                        self.send_scan_command(packet, &validate).await?;
                                    } else {
                                        active_scan::checked(
                                            async {
                                                self.htt
                                                    .wmi
                                                    .htc
                                                    .send_wmi(packet)
                                                    .await
                                                    .map_err(htt::Error::from)
                                                    .map_err(Error::from)
                                            },
                                            &validate,
                                        )
                                        .await?;
                                    }
                                }
                                validate()?;
                                self.publish_scan_cache(
                                    &report.bss,
                                    None,
                                    p2p_device.is_some() || client,
                                )?;
                                self.scan_pending = None;
                                self.failed = false;
                                return Ok(report);
                            }
                            2 | 64 => return Err(Error::Firmware(event.reason)),
                            _ => {}
                        }
                    } else if id == self.wire.management_event {
                        let management = self.wire.management(&bytes[4..], self.features)?;
                        report.received = report.received.saturating_add(1);
                        if let Some(bss) = discovered(&management, channels, p2p_device.is_some())?
                        {
                            if let Some(previous) = report
                                .bss
                                .iter_mut()
                                .find(|b| b.bssid == bss.bssid && b.frequency == bss.frequency)
                            {
                                *previous = bss;
                            } else if report.bss.len() < 64 {
                                report.bss.push(bss);
                            } else {
                                report.truncated = true;
                            }
                        } else {
                            report.ignored = report.ignored.saturating_add(1);
                        }
                    } else {
                        self.queue(htt::Event::Wmi(bytes))?;
                    }
                }
                htt::Event::Idle | htt::Event::Progress => narf_scheduler::yield_now().await,
                // Keep peer/BA/packet events for the future station worker.
                // No event can raise a link or open the controlled port here.
                event => self.queue(event)?,
            }
        }
    }
    /// Hand an event the sibling station slot owns (and the current slot
    /// does not) to that slot's inbox, so no wait loop of this owner queues
    /// or consumes it; return every other event unchanged. With no P2P
    /// client slot this is the identity.
    pub(super) fn route_sibling(&mut self, event: htt::Event) -> Option<htt::Event> {
        if self.p2p_client.is_none() && !self.ap_is_go() {
            return Some(event);
        }
        let frame = self.management_frame(&event);
        let primary = self.primary.id();
        if self.station.claims(&event, primary, frame.as_deref()) {
            return Some(event);
        }
        // A GO beside the station slots consumes what it owns.
        let event = self.route_go(event, frame.as_deref())?;
        match self
            .p2p_client
            .as_deref_mut()
            .filter(|s| s.claims(&event, primary, frame.as_deref()))
        {
            Some(sibling) => {
                sibling.park(event);
                None
            }
            None => Some(event),
        }
    }
    /// Publish a scan's BSS table (at most `SCAN_CACHE` entries). cfg80211
    /// keeps one BSS table per wiphy (`net/wireless/scan.c`
    /// `cfg80211_bss_update`), so a P2P_DEVICE scan (`merge`) updates
    /// entries beside the netdev's instead of hiding them, and its GO is
    /// then visible to the P2P client's station prepare. Every scan keeps
    /// each station slot's associated BSS (and `keep`) when the scan did
    /// not observe it.
    pub(super) fn publish_scan_cache(
        &mut self,
        fresh: &[ScanBss],
        keep: Option<([u8; 6], u16)>,
        merge: bool,
    ) -> Result<(), Error> {
        let bound = |slot: &StationSlot| {
            slot.peer
                .as_ref()
                .map(|p| (p.bssid, p.permission.frequency))
        };
        let kept = [
            keep,
            bound(&self.station),
            self.p2p_client.as_deref().and_then(bound),
        ];
        let same = |b: &ScanBss, c: &ScanBss| b.bssid == c.bssid && b.frequency == c.frequency;
        let mut cache: Vec<ScanBss> = Vec::new();
        cache
            .try_reserve_exact(SCAN_CACHE)
            .map_err(|_| Error::NoMemory)?;
        for (bssid, frequency) in kept.into_iter().flatten() {
            if fresh
                .iter()
                .any(|b| b.bssid == bssid && b.frequency == frequency)
                || cache
                    .iter()
                    .any(|b| b.bssid == bssid && b.frequency == frequency)
            {
                continue;
            }
            if let Some(b) = self
                .scan_cache
                .iter()
                .find(|b| b.bssid == bssid && b.frequency == frequency)
            {
                cache.push(b.copy_owned()?);
            }
        }
        for b in fresh {
            if cache.len() < SCAN_CACHE && !cache.iter().any(|c| same(b, c)) {
                cache.push(b.copy_owned()?);
            }
        }
        if merge {
            for b in &self.scan_cache {
                if cache.len() < SCAN_CACHE && !cache.iter().any(|c| same(b, c)) {
                    cache.push(b.copy_owned()?);
                }
            }
        }
        self.scan_cache = cache;
        Ok(())
    }
    /// Retain an event for a later step. A sibling slot's event goes to that
    /// slot's inbox (bounded there), never to this owner's queue.
    fn queue(&mut self, event: htt::Event) -> Result<(), Error> {
        let Some(event) = self.route_sibling(event) else {
            return Ok(());
        };
        if self.pending.len() == 64 {
            return Err(Error::Malformed);
        }
        self.pending.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.pending.push_back(event);
        Ok(())
    }
    pub fn take_event(&mut self) -> Option<htt::Event> {
        self.pending.pop_front()
    }
    /// The managed role's firmware vdev id (WMI `vdev_id`, HTT routing key).
    pub(in crate::ath10k) fn primary_vdev(&self) -> u32 {
        u32::from(self.primary.id())
    }
    /// The vdev the current station slot uses.
    pub(super) fn station_vdev(&self) -> u8 {
        self.station.vdev.unwrap_or(self.primary.id())
    }
    /// The current station slot's own address.
    pub(super) fn station_own(&self) -> Result<[u8; 6], Error> {
        match self.station.own {
            Some(own) => Ok(own),
            None => Ok(self.ready.ok_or(Error::Failed)?.mac),
        }
    }
    fn exchange_client(&mut self) {
        if let Some(client) = self.p2p_client.as_deref_mut() {
            core::mem::swap(&mut self.station, client);
            self.in_client_scope = !self.in_client_scope;
        }
    }
    /// Enter the P2P client slot, if one exists. The client slot must not be
    /// removed while the scope is held (it then holds the home slot).
    // Bound by the P2P client netdev role (iftype 8) in a later step.
    #[allow(dead_code)]
    pub(super) fn client_scope(&mut self) -> Option<ClientScope<'_, T>> {
        if self.in_client_scope {
            return None;
        }
        self.p2p_client.as_ref()?;
        self.exchange_client();
        Some(ClientScope { radio: self })
    }
    /// The pending scan or ROC runs on the sibling slot's vdev; its
    /// retained cleanup belongs to that slot's netdev, not this one.
    pub(in crate::ath10k) fn scan_on_sibling(&self) -> bool {
        self.scan_pending.is_some()
            && self
                .p2p_client
                .as_deref()
                .is_some_and(|s| u32::from(s.vdev.unwrap_or(self.primary.id())) == self.scan_vdev)
    }
    /// The next TX completion for the current slot: one a sibling handed
    /// over, else the HTT queue, passing a sibling-owned id to that slot
    /// (`txrx.c::ath10k_txrx_tx_unref` resolves msdu_id to its vif).
    pub(super) fn take_station_receipt(&mut self) -> Option<htt::TxReceipt> {
        if let Some(receipt) = self.station.receipts.pop_front() {
            return Some(receipt);
        }
        loop {
            let receipt = self.htt.take_tx_receipt()?;
            if !self.station.owns_msdu(receipt.id) && self.route_go_receipt(receipt) {
                continue;
            }
            if !self.station.owns_msdu(receipt.id) {
                if let Some(sibling) = self
                    .p2p_client
                    .as_deref_mut()
                    .filter(|s| s.owns_msdu(receipt.id))
                {
                    sibling.receipts.push_back(receipt);
                    continue;
                }
            }
            return Some(receipt);
        }
    }
}
fn beacon(event: &Management, channels: &[u16]) -> Result<Option<ScanBss>, Error> {
    discovered(event, channels, false)
}
/// A Beacon or Probe Response for the scan cache. On the P2P_DEVICE vdev a
/// P2P Device in Listen state also answers: its Probe Response is neither
/// ESS nor IBSS (P2P spec 3.1.2.1.2; BSSID = P2P Device Address) and is
/// accepted only when it carries the WFA P2P IE (50:6f:9a:09).
fn discovered(event: &Management, channels: &[u16], p2p: bool) -> Result<Option<ScanBss>, Error> {
    if event.status & !0x40 != 0 {
        return Ok(None);
    }
    let Some(frequency) = wire::channel_to_frequency(event.channel) else {
        return Ok(None);
    };
    if !channels.contains(&frequency) {
        return Ok(None);
    }
    let frame = &event.frame;
    let Some(fixed) = frame.get(..36) else {
        return Ok(None);
    };
    let fc = u16::from_le_bytes([fixed[0], fixed[1]]);
    if !matches!(fc & 0x00ff, 0x0080 | 0x0050)
        || fc & 0xc700 != 0
        || fixed[22] & 15 != 0
        || fixed[16] & 1 != 0
        || fixed[16..22] == [0; 6]
        || fixed[10..16] != fixed[16..22]
    {
        return Ok(None);
    }
    let capability = u16::from_le_bytes([fixed[34], fixed[35]]);
    let listen = p2p && capability & 3 == 0 && fc & 0x00ff == 0x0050;
    if capability & 3 != 1 && !listen {
        return Ok(None);
    }
    let mut ssid = None;
    let mut ds = None;
    let mut ht = None;
    let mut p2p_ie = false;
    let mut ies = &frame[36..];
    while !ies.is_empty() {
        let Some(header) = ies.get(..2) else {
            return Ok(None);
        };
        let length = usize::from(header[1]);
        let Some(body) = ies.get(2..2 + length) else {
            return Ok(None);
        };
        match header[0] {
            0 => {
                if length > 32 || ssid.replace(body).is_some() {
                    return Ok(None);
                }
            }
            3 => {
                if length != 1 || ds.replace(body[0]).is_some() {
                    return Ok(None);
                }
            }
            61 => {
                if length != 22 || ht.replace(body[0]).is_some() {
                    return Ok(None);
                }
            }
            221 if body.starts_with(&[0x50, 0x6f, 0x9a, 0x09]) => p2p_ie = true,
            _ => {}
        }
        ies = &ies[2 + length..];
    }
    if listen && !p2p_ie {
        return Ok(None);
    }
    if ds.is_some_and(|c| u32::from(c) != event.channel)
        || ht.is_some_and(|c| u32::from(c) != event.channel)
    {
        return Ok(None);
    }
    let Some(ssid) = ssid else {
        return Ok(None);
    };
    Ok(Some(ScanBss {
        bssid: fixed[16..22].try_into().unwrap(),
        ssid: wire::owned(ssid)?,
        frequency,
        snr: event.snr,
        capability,
        beacon_interval: u16::from_le_bytes([fixed[32], fixed[33]]),
        information_elements: wire::owned(&frame[36..])?,
    }))
}

impl ScanBss {
    fn copy_owned(&self) -> Result<Self, Error> {
        Ok(Self {
            bssid: self.bssid,
            ssid: wire::owned(&self.ssid)?,
            frequency: self.frequency,
            snr: self.snr,
            capability: self.capability,
            beacon_interval: self.beacon_interval,
            information_elements: wire::owned(&self.information_elements)?,
        })
    }
}
#[path = "wmi_runtime/station.rs"]
mod station;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerPrepared {
    pub bssid: [u8; 6],
    pub frequency: u16,
    pub center_frequency: u16,
    pub second_center_frequency: Option<u16>,
    pub bandwidth_mhz: u8,
    /// Sparse firmware ID, not an index bounded by resource peer count.
    pub peer_id: u16,
    pub maximum_power_dbm: u8,
}

// SPDX-License-Identifier: GPL-2.0-or-later
//! Gen2 (RTL8192EU / RTL8723BU) station netdev publication over one
//! retained native USB owner, after `wait_admit` qualified this exact
//! device (signed `N92P`/`N8BP` record, signed regulatory policy, network
//! authority). Unprovisioned devices never reach `attach`.
//!
//! One owner serves idle channel changes (live retune), passive and active
//! scans over the channels the signed record and domain grant, scans
//! while associated (PM1 Null, cold away visit, cold return with the same
//! station/key owners, PM0 Null), one station at a time, and the
//! Linux-shaped teardown: `rtl8xxxu_stop`, the chip's power-off
//! (`restart_parked` path) and a fresh `rtl8xxxu_init_device` lifecycle
//! before the next join.
use super::{
    firmware_transport::{ControlIo, Owner as Firmware, UsbControl},
    gen2_radio::{self, Authority, Grant, Radio},
    gen2_station::{self, Station},
    management_runtime::{Candidate, SecurityMode},
    packet_transport::{Io as PacketIo, UsbIo},
};
use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use narf_ipc::{Consumer, Producer};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessConfig, WirelessError,
    WirelessNetIface,
};
use zeroize::Zeroizing;

#[path = "gen2_interface_power.rs"]
mod gen2_interface_power;

/// Bound on retained scan candidates.
const CANDIDATES: usize = 32;
/// Candidate lifetime (as the RTL8188EU service cache).
const CANDIDATE_MS: u64 = 10_000;
/// A connect after a cold transition waits this long for a fresh beacon.
const FRESH_MS: u64 = 2_000;
/// Host TX receipt bound for scan probes.
const PROBE_TX_MS: u64 = 1_000;
/// mac80211 `scan.c`: away dwell cap HZ/8 while associated, HZ/10 after the
/// PM1 Null (rtl8xxxu has no `.flush`) and HZ/5 on home return.
const AWAY_MS: u64 = 125;
const PM1_GRACE_MS: u64 = 100;
const HOME_GRACE_MS: u64 = 200;

fn now_ms() -> u64 {
    narf_time::wall::monotonic_ns() / 1_000_000
}
async fn pause() {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
}
fn nonce() -> Option<[u8; 32]> {
    let mut nonce = [0; 32];
    narf_crypto::try_fill_random_bytes(&mut nonce).ok()?;
    Some(nonce)
}

enum Slot<C: ControlIo, B: PacketIo> {
    Idle(Box<Radio<C, B>>),
    Station(Box<Station<C, B>>),
    Failed,
}

/// A copied observation, with the physical receive generation that held it.
#[derive(Clone)]
struct Entry {
    candidate: Candidate,
    seen: u64,
    generation: u64,
}

/// What an active visit emits: the one directed SSID (or wildcard) and the
/// checked extra IEs (`max_scan_ssids = 1` in `rtl8xxxu_probe`).
#[derive(Clone, Copy)]
struct Probe<'a> {
    ssid: &'a [u8],
    extra: &'a [u8],
    /// `(pre, post)` listening windows from `probe_runtime::Prepared::timing`.
    timing: (u64, u64),
}

struct State<C: ControlIo, B: PacketIo> {
    slot: Slot<C, B>,
    authority: Authority,
    cache: Vec<Entry>,
    /// Software SN for idle-scan probes (no station owns a sequence space).
    probe_sequence: u16,
    rx: Producer<Frame, RX_RING_N>,
    tx: Consumer<Frame, TX_RING_N>,
}

fn remember(cache: &mut Vec<Entry>, candidate: Candidate, seen: u64, generation: u64) {
    let entry = Entry {
        candidate,
        seen,
        generation,
    };
    if let Some(old) = cache
        .iter_mut()
        .find(|old| old.candidate.bssid() == entry.candidate.bssid())
    {
        *old = entry;
        return;
    }
    if cache.len() == CANDIDATES {
        if let Some(oldest) = cache
            .iter()
            .enumerate()
            .min_by_key(|(_, old)| old.seen)
            .map(|(i, _)| i)
        {
            cache.swap_remove(oldest);
        }
    }
    cache.push(entry);
}

/// Poll one receiving radio for `ms`: every admitted beacon/probe response
/// becomes a cached observation of this physical stream. No MPDU reaches a
/// station, key or replay owner from here. Queued BT-info records drain
/// through `Radio::drain_bt` every iteration — `assoc` is the caller's
/// association state (`false` for an unbound radio, `true` for a
/// station's off-channel visit) — so BT info is programmed while idle,
/// not only while a station is serviced.
async fn listen<C: ControlIo, B: PacketIo>(
    radio: &mut Radio<C, B>,
    cache: &mut Vec<Entry>,
    ms: u64,
    assoc: bool,
) -> Result<(), gen2_radio::Error> {
    let deadline = now_ms().saturating_add(ms);
    while now_ms() < deadline {
        if radio.recovery_pending() {
            radio.maintain().await?;
        }
        match radio.poll()? {
            Some(frames) => {
                for frame in frames {
                    if let Ok(bss) = Candidate::from_receive_with_phy(
                        &frame,
                        radio.channel(),
                        radio.local(),
                        radio.ht_local().as_ref(),
                    ) {
                        remember(cache, bss, now_ms(), radio.generation());
                    }
                }
            }
            None => pause().await,
        }
        radio.drain_bt(assoc).await?;
    }
    Ok(())
}

/// One active visit on the current (unbound, receiving) radio: the source
/// pre-probe delay, the native broadcast Probe Request on the management
/// pipe, its exact host USB receipt, then the response window. `assoc`
/// is the caller's association state, forwarded to `listen` and to the
/// transmit-wait drain below.
async fn probe_visit<C: ControlIo, B: PacketIo>(
    radio: &mut Radio<C, B>,
    cache: &mut Vec<Entry>,
    probe: Probe<'_>,
    sequence: u16,
    assoc: bool,
) -> Result<(), gen2_radio::Error> {
    listen(radio, cache, probe.timing.0, assoc).await?;
    // An HT-capable board's probe carries its own HT caps (gen2 F10);
    // a legacy-only board's probe carries none.
    let prepared = match radio.ht_caps() {
        Some(caps) => super::probe_runtime::Prepared::new_with_ht(
            radio.local(),
            radio.channel(),
            probe.ssid,
            sequence,
            &caps,
            probe.extra,
        ),
        None => super::probe_runtime::Prepared::new(
            radio.local(),
            radio.channel(),
            probe.ssid,
            sequence,
            false,
            probe.extra,
        ),
    }
    .map_err(|_| gen2_radio::Error::Profile)?;
    radio.submit_probe(&prepared)?;
    let deadline = now_ms().saturating_add(PROBE_TX_MS);
    loop {
        if radio.poll_delivery()?.is_some() {
            break;
        }
        if now_ms() >= deadline {
            radio.fail_terminal();
            return Err(gen2_radio::Error::State);
        }
        if let Some(frames) = radio.poll()? {
            for frame in frames {
                if let Ok(bss) = Candidate::from_receive_with_phy(
                    &frame,
                    radio.channel(),
                    radio.local(),
                    radio.ht_local().as_ref(),
                ) {
                    remember(cache, bss, now_ms(), radio.generation());
                }
            }
        } else {
            pause().await;
        }
        radio.drain_bt(assoc).await?;
    }
    listen(radio, cache, probe.timing.1, assoc).await
}

impl<C: ControlIo, B: PacketIo> State<C, B> {
    /// Cache entries younger than `CANDIDATE_MS` on a still-granted channel.
    fn candidates(&self) -> Vec<Candidate> {
        let now = now_ms();
        self.cache
            .iter()
            .filter(|e| {
                now >= e.seen
                    && now - e.seen < CANDIDATE_MS
                    && self.authority.grant(e.candidate.channel()).is_ok()
            })
            .map(|e| e.candidate.clone())
            .collect()
    }
    fn next_probe_sequence(&mut self) -> u16 {
        let sequence = self.probe_sequence;
        self.probe_sequence = (sequence + 1) & 4095;
        sequence
    }
    /// Idle scan: every channel's grant precedes the first transition; each
    /// visit is a live retune (skipped for the current receiving channel),
    /// then passive dwell or one probe visit; the home channel is restored.
    async fn idle_scan(
        &mut self,
        grants: &[Grant],
        dwell: u64,
        probe: Option<Probe<'_>>,
    ) -> Result<(), gen2_radio::Error> {
        let home = {
            let radio = self
                .idle_receiving()
                .await
                .map_err(|_| gen2_radio::Error::State)?;
            radio.grant()
        };
        for grant in grants {
            let sequence = self.next_probe_sequence();
            let Slot::Idle(radio) = &mut self.slot else {
                return Err(gen2_radio::Error::State);
            };
            if radio.grant() != *grant {
                radio.retune(*grant).await?;
            }
            match probe {
                Some(probe) => probe_visit(radio, &mut self.cache, probe, sequence, false).await?,
                None => listen(radio, &mut self.cache, dwell, false).await?,
            }
        }
        let Slot::Idle(radio) = &mut self.slot else {
            return Err(gen2_radio::Error::State);
        };
        if radio.grant() != home {
            radio.retune(home).await?;
        }
        Ok(())
    }
    fn station(&mut self) -> Result<&mut Station<C, B>, gen2_station::Error> {
        match &mut self.slot {
            Slot::Station(station) => Ok(station),
            _ => Err(gen2_station::Error::State),
        }
    }
    /// Normal home service for `ms` (station progress, one Ethernet frame
    /// per step), until both the window elapsed and no receipt is pending.
    async fn home_listen(&mut self, ms: u64) -> Result<(), gen2_station::Error> {
        let deadline = now_ms().saturating_add(ms);
        loop {
            self.service().await?;
            if now_ms() >= deadline && self.station()?.quiescent() {
                return Ok(());
            }
            pause().await;
        }
    }
    /// Associated scan (`ieee80211_scan_state_*` + `offchannel`): a passive
    /// visit to the home channel listens there in normal service; every
    /// other visit (and every active visit) sends PM1, waits the no-flush
    /// grace, leaves through `rtl8xxxu_stop`, cold-retunes to the visited
    /// channel, listens (or probes from the unbound radio), cold-returns to
    /// home with the same AID/rates, sends PM0 and serves home for HZ/5.
    async fn associated_scan(
        &mut self,
        grants: &[Grant],
        dwell: u64,
        probe: Option<Probe<'_>>,
    ) -> Result<(), gen2_station::Error> {
        let home = self.station()?.radio().grant();
        self.station()?.observe(true);
        for grant in grants {
            if probe.is_none() && *grant == home {
                self.home_listen(dwell).await?;
                continue;
            }
            self.home_listen(0).await?;
            self.station()?.send_null(true, now_ms())?;
            self.home_listen(PM1_GRACE_MS).await?;
            let sequence = match probe {
                Some(_) => Some(self.station()?.reserve_sequence()?),
                None => None,
            };
            let station = self.station()?;
            station.leave().await?;
            let Slot::Station(station) = &mut self.slot else {
                return Err(gen2_station::Error::State);
            };
            let radio = station.radio_mut();
            let visit = async {
                radio.retune(*grant).await?;
                match (probe, sequence) {
                    (Some(probe), Some(sequence)) => {
                        probe_visit(radio, &mut self.cache, probe, sequence, true).await
                    }
                    _ => listen(radio, &mut self.cache, dwell, true).await,
                }
            }
            .await;
            if let Err(error) = visit {
                radio.fail_terminal();
                return Err(gen2_station::Error::Radio(error));
            }
            station.rejoin(home, now_ms()).await?;
            station.send_null(false, now_ms())?;
            self.home_listen(HOME_GRACE_MS).await?;
        }
        for (candidate, seen, generation) in self.station()?.observe(false) {
            remember(&mut self.cache, candidate, seen, generation);
        }
        Ok(())
    }
    fn clear_transmit(&mut self) {
        for _ in 0..TX_RING_N {
            if !matches!(self.tx.try_recv(), Ok(Some(_))) {
                break;
            }
        }
    }
    fn connected(&self) -> Option<[u8; 6]> {
        match &self.slot {
            Slot::Station(s) if s.carrier_up() => Some(s.peer()),
            _ => None,
        }
    }
    /// The idle radio, receiving on the admitted channel.
    async fn idle_receiving(&mut self) -> Result<&mut Radio<C, B>, WirelessError> {
        let Slot::Idle(radio) = &mut self.slot else {
            return Err(WirelessError::Busy);
        };
        if radio.phase() == gen2_radio::Phase::Prepared {
            radio.start().await.map_err(radio_error)?;
        }
        if radio.phase() != gen2_radio::Phase::Receiving {
            return Err(WirelessError::HardwareError);
        }
        Ok(&mut **radio)
    }
    /// Worker step: station service, then one queued Ethernet frame.
    async fn service(&mut self) -> Result<(), gen2_station::Error> {
        let Slot::Station(station) = &mut self.slot else {
            return Ok(());
        };
        if !matches!(
            station.phase(),
            gen2_station::Phase::Authentication
                | gen2_station::Phase::Association
                | gen2_station::Phase::FourWay
                | gen2_station::Phase::Open
        ) {
            return Ok(());
        }
        station.step(now_ms(), nonce).await?;
        if !station.controlled_port_open() {
            self.clear_transmit();
            return Ok(());
        }
        if station.transmit_ready() {
            if let Ok(Some(frame)) = self.tx.try_recv() {
                if transmit_admitted(frame.payload(), station.local())
                    && offloads_admitted(frame.tx_meta())
                {
                    station.send_ethernet(frame.payload(), now_ms())?;
                }
            }
        }
        Ok(())
    }
}

pub struct Device<C: ControlIo, B: PacketIo> {
    state: Mutex<State<C, B>>,
    name: String,
    mac: [u8; 6],
    /// The current home channel (initial grant, `set_config` or a join).
    channel: AtomicU8,
    /// Channels the signed record and domain granted at attach (advertised;
    /// every use mints and rechecks its own grant).
    channels: Vec<u8>,
    up: AtomicBool,
    bssid: AtomicU64,
    failed: AtomicBool,
    /// Administratively DOWN (or a transition in flight): no control
    /// operation, worker step or carrier publication.
    closed: AtomicBool,
    admin: IrqSafeSpinLock<gen2_interface_power::Admin>,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
impl<C: ControlIo, B: PacketIo> core::fmt::Debug for Device<C, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8xxxuGen2Device")
            .field("name", &self.name)
            .field("mac", &self.mac)
            .finish_non_exhaustive()
    }
}

impl<C: ControlIo, B: PacketIo> Device<C, B> {
    pub(super) fn new(name: &str, radio: Radio<C, B>, authority: Authority) -> Self {
        let (rx, rx_consumer) = narf_ipc::channel();
        let (tx_producer, tx) = narf_ipc::channel();
        let mac = radio.local();
        let channel = radio.channel();
        let channels = authority.channels();
        let parked = radio.phase() == gen2_radio::Phase::Parked;
        Self {
            state: Mutex::new(State {
                slot: Slot::Idle(Box::new(radio)),
                authority,
                cache: Vec::new(),
                probe_sequence: 0,
                rx,
                tx,
            }),
            name: name.into(),
            mac,
            channel: AtomicU8::new(channel),
            channels,
            up: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            failed: AtomicBool::new(false),
            closed: AtomicBool::new(parked),
            admin: IrqSafeSpinLock::new(gen2_interface_power::Admin::new()),
            rx: IrqSafeSpinLock::new(Some(rx_consumer)),
            tx: IrqSafeSpinLock::new(Some(tx_producer)),
        }
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.failed.store(true, Ordering::Release);
        *self.rx.lock() = None;
        self.link(None);
    }
    fn link(&self, peer: Option<[u8; 6]>) {
        let peer = peer.filter(|_| {
            !self.closed.load(Ordering::Acquire) && !self.failed.load(Ordering::Acquire)
        });
        let mut packed = [0; 8];
        if let Some(peer) = peer {
            packed[..6].copy_from_slice(&peer);
            packed[7] = 1;
        }
        self.bssid
            .store(u64::from_le_bytes(packed), Ordering::Release);
        let up = peer.is_some();
        let was_up = self.up.swap(up, Ordering::AcqRel);
        // Physical carrier is link metadata on the bound registration; it
        // never changes the operator's administrative IFF_UP.
        let published = self.publish_carrier(up);
        if was_up && !up && published {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }
    fn fail(&self, state: &mut State<C, B>) {
        state.clear_transmit();
        if let Slot::Station(station) = core::mem::replace(&mut state.slot, Slot::Failed) {
            drop(station);
        }
        self.failed.store(true, Ordering::Release);
        *self.rx.lock() = None;
        self.link(None);
    }
    /// Worker-only: station progress under the owner lock, link publication.
    pub(super) async fn maintain(&self) {
        if self.failed.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return;
        }
        let Some(mut state) = self.state.try_lock() else {
            return;
        };
        match state.service().await {
            Ok(()) => {
                let peer = state.connected();
                self.link(peer);
            }
            Err(_) => self.fail(&mut state),
        }
    }
    /// `priv->ra_watchdog` (`rtl8xxxu_watchdog_callback`): the RA iteration
    /// for the associated station, under the owner lock. Run from the
    /// device's watchdog work every `WATCHDOG_MS`.
    pub(super) async fn watchdog(&self) {
        if self.failed.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return;
        }
        let mut state = self.state.lock().await;
        let Slot::Station(station) = &mut state.slot else {
            return;
        };
        if station.watchdog(now_ms()).await.is_err() {
            self.fail(&mut state);
        }
    }
    /// Network-stack drain: delivered Ethernet frames, with no lock held
    /// across the stack callback.
    pub(super) fn drain(&self) -> bool {
        let mut frames = Vec::new();
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        {
            let Some(mut state) = self.state.try_lock() else {
                return false;
            };
            if let Slot::Station(station) = &mut state.slot {
                for _ in 0..16 {
                    let Some(frame) = station.pop_received() else {
                        break;
                    };
                    frames.push(frame);
                }
            }
            for bytes in &frames {
                if let Ok(buffer) =
                    narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                {
                    let mut frame = Frame::new(buffer, bytes.len() as u32);
                    frame.payload_mut().copy_from_slice(bytes);
                    let _ = state.rx.try_send(frame);
                }
            }
        }
        let progress = !frames.is_empty();
        for mut frame in frames {
            if self.failed.load(Ordering::Acquire) {
                break;
            }
            narf_net::iface::on_rx_frame_from(&self.name, &mut frame);
        }
        progress
    }
    pub(super) fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if !self.up.load(Ordering::Acquire)
            || self.failed.load(Ordering::Acquire)
            || !transmit_admitted(bytes, self.mac)
            || !offloads_admitted(meta)
        {
            return Err(());
        }
        let buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        frame.set_tx_meta(meta);
        self.tx
            .lock()
            .as_mut()
            .ok_or(())?
            .try_send(frame)
            .map_err(|_| ())
    }
}

trait Endpoint: Send + Sync {
    fn send(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()>;
    fn drain(&self) -> bool;
}
impl<C: ControlIo + 'static, B: PacketIo + 'static> Endpoint for Device<C, B> {
    fn send(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        self.enqueue(bytes, meta)
    }
    fn drain(&self) -> bool {
        Device::drain(self)
    }
}
/// `narf_net::iface::SendFn` carries no interface identity, so the gen2
/// publication is one netdev per boot (as the RTL8188EU one).
static ACTIVE: IrqSafeSpinLock<Option<Arc<dyn Endpoint>>> = IrqSafeSpinLock::new(None);
static CLAIMED: AtomicBool = AtomicBool::new(false);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let active = ACTIVE.lock().clone().ok_or(())?;
    active.send(bytes, meta)
}
fn drain() -> bool {
    let active = ACTIVE.lock().clone();
    active.is_some_and(|owner| owner.drain())
}

/// Publish the admitted gen2 radio as `wlan%d`. The radio stays at
/// `RadioReady` (no RX transfer, RX filter maps closed) until a scan or
/// association starts it.
pub async fn attach(
    firmware: Arc<Firmware<UsbControl>>,
    channels: Authority,
    grant: Grant,
) -> Result<Arc<Device<UsbControl, UsbIo>>, gen2_radio::Error> {
    let authority = narf_net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(gen2_radio::Error::Profile)?;
    let usb = firmware.usb_device();
    CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| gen2_radio::Error::State)?;
    let mut radio = Radio::new(firmware, UsbIo::new(usb), grant)?;
    // register_netdevice starts IFF_DOWN: finish the actual USB/MAC/chip
    // park before publication rather than leave a powered radio under DOWN.
    radio.park_idle().await?;
    let name = narf_net::iface::reserve_name("wlan%d");
    let device = Arc::new(Device::new(name, radio, channels));
    narf_net::registry()
        .register(&authority, Registered(device.clone()))
        .map_err(|_| gen2_radio::Error::Profile)?;
    *ACTIVE.lock() = Some(device.clone());
    narf_net::iface::register(name, device.mac, send);
    narf_net::iface::set_link_state(name, false);
    let registration = narf_net::iface::lookup(name).ok_or(gen2_radio::Error::State)?;
    device.bind_admin(registration)?;
    narf_net::iface::install_rx_drain(drain);
    narf_wireless::registry::register(device.clone());
    crate::watchdog_work::start(&device, gen2_radio::WATCHDOG_MS);
    let worker = device.clone();
    narf_scheduler::spawn(async move {
        loop {
            worker.maintain().await;
            worker.drain();
            pause().await;
        }
    });
    Ok(device)
}

/// `priv->ra_watchdog`; a failed device is terminal and stops it.
impl<C: ControlIo + 'static, B: PacketIo + 'static> crate::watchdog_work::Watchdog for Device<C, B>
where
    Self: Send + Sync,
{
    fn watchdog_stopped(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
    fn watchdog_step(
        self: Arc<Self>,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = ()> + Send>> {
        Box::pin(async move { self.watchdog().await })
    }
}
impl<C: ControlIo + 'static, B: PacketIo + 'static> Interface for Device<C, B> {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}

#[async_trait::async_trait]
impl<C: ControlIo + 'static, B: PacketIo + 'static> WirelessNetIface for Device<C, B> {
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }
    fn supports_scan_dwell(&self) -> bool {
        true
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        let packed = self.bssid.load(Ordering::Acquire).to_le_bytes();
        (packed[7] != 0).then(|| packed[..6].try_into().unwrap())
    }
    fn cipher_suites(&self) -> &'static [u32] {
        &[0x000fac04]
    }
    fn max_scan_ssids(&self) -> u8 {
        1
    }
    fn max_scan_ie_len(&self) -> u16 {
        super::probe_runtime::MAX_IE as u16
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.state
            .try_lock()?
            .candidates()
            .into_iter()
            .find(|b| b.bssid() == bssid)
            .map(|b| b.information_elements().to_vec())
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac,
            bands: vec![WirelessBand {
                freq_mhz: 2400,
                channels: self.channels.iter().map(|c| u32::from(*c)).collect(),
            }],
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    /// Passive or active scan over the requested (or every granted)
    /// channel. All grants, the probe frame and its timing are admitted
    /// before the first hardware transition; idle scans live-retune per
    /// channel and restore home, associated scans visit as `associated_scan`.
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let (mut channels, dwell) = validate_scan(&request)?;
        if self.failed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let mut state = self.control_state(false).await?;
        if channels.is_empty() {
            channels = state.authority.channels();
        }
        let mut grants = Vec::new();
        for channel in &channels {
            grants.push(
                state
                    .authority
                    .grant(*channel)
                    .map_err(|_| WirelessError::NotSupported)?,
            );
        }
        if grants.is_empty() {
            return Err(WirelessError::NotSupported);
        }
        let associated = matches!(state.slot, Slot::Station(_));
        if associated {
            let Slot::Station(station) = &state.slot else {
                return Err(WirelessError::Busy);
            };
            if !station.scan_admissible() {
                return Err(WirelessError::Busy);
            }
            if request.duration_mandatory && dwell > AWAY_MS {
                return Err(WirelessError::InvalidArgs);
            }
        } else if !matches!(state.slot, Slot::Idle(_)) {
            return Err(WirelessError::HardwareError);
        }
        let ssid = request.ssids.first().map_or(&[][..], Vec::as_slice);
        let probe = if request.active {
            // The longest frame any visit emits bounds the source timing.
            // The preflight mirrors the visit probes' HT caps (gen2 F10)
            // so the timing bound covers the 28-byte caps element.
            let caps = match &state.slot {
                Slot::Idle(radio) => radio.ht_caps(),
                Slot::Station(station) => station.radio().ht_caps(),
                Slot::Failed => return Err(WirelessError::HardwareError),
            };
            let prepared = match caps {
                Some(caps) => super::probe_runtime::Prepared::new_with_ht(
                    self.mac,
                    1,
                    ssid,
                    0,
                    &caps,
                    &request.extra_ies,
                ),
                None => super::probe_runtime::Prepared::new(
                    self.mac,
                    1,
                    ssid,
                    0,
                    false,
                    &request.extra_ies,
                ),
            }
            .map_err(|_| WirelessError::InvalidArgs)?;
            let timing = prepared
                .timing(dwell, request.duration_mandatory)
                .map_err(|_| WirelessError::InvalidArgs)?;
            let timing = if associated {
                if request.duration_mandatory && timing.0 + timing.1 > AWAY_MS {
                    return Err(WirelessError::InvalidArgs);
                }
                (timing.0, timing.1.min(AWAY_MS - timing.0))
            } else {
                timing
            };
            Some(Probe {
                ssid,
                extra: &request.extra_ies,
                timing,
            })
        } else {
            None
        };
        let result = if associated {
            state
                .associated_scan(&grants, dwell.min(AWAY_MS), probe)
                .await
                .map_err(station_error)
        } else {
            state
                .idle_scan(&grants, dwell, probe)
                .await
                .map_err(radio_error)
        };
        if let Err(error) = result {
            // Any failure after the first transition is terminal.
            self.fail(&mut state);
            return Err(match error {
                WirelessError::Busy | WirelessError::InvalidArgs => WirelessError::HardwareError,
                other => other,
            });
        }
        Ok(state
            .candidates()
            .into_iter()
            .filter(|b| {
                channels.contains(&b.channel())
                    && (request.ssids.is_empty()
                        || request
                            .ssids
                            .iter()
                            .any(|ssid| ssid.is_empty() || ssid == b.ssid()))
            })
            .map(bss_info)
            .collect())
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if !(1..=13).contains(&request.channel)
            || request.frequency_mhz != 2407 + request.channel * 5
        {
            return Err(WirelessError::NotSupported);
        }
        let (mode, pmk) = match request.security {
            SecurityConfig::Open => (SecurityMode::Open, None),
            SecurityConfig::Wpa2 { psk } => (SecurityMode::Wpa2Psk, Some(Zeroizing::new(psk))),
            _ => return Err(WirelessError::NotSupported),
        };
        let mut state = self.control_state(false).await?;
        let Some(mut candidate) = state.candidates().into_iter().find(|b| {
            b.bssid() == request.bssid
                && b.ssid() == request.ssid
                && u32::from(b.channel()) == request.channel
        }) else {
            return Err(WirelessError::InvalidArgs);
        };
        if !matches!(state.slot, Slot::Idle(_)) {
            return Err(WirelessError::Busy);
        }
        // Pure request admission before any hardware transition.
        let grant = state
            .authority
            .grant(candidate.channel())
            .map_err(|_| WirelessError::NotSupported)?;
        let mut preflight = super::management_runtime::Join::prepare(
            candidate.clone(),
            self.mac,
            &request.ssid,
            mode,
        )
        .map_err(|_| WirelessError::InvalidArgs)?;
        preflight
            .append_sme_ies(&request.ie)
            .map_err(|_| WirelessError::InvalidArgs)?;
        // A retune starts a new observation generation (cold or live):
        // CONNECT then needs a fresh copy of this BSS from it (a hidden
        // SSID found by a directed response is probed again), never an
        // old cache entry's age.
        let fresh = async {
            let sequence = state.next_probe_sequence();
            let State { slot, cache, .. } = &mut *state;
            let Slot::Idle(radio) = slot else {
                return Err(gen2_radio::Error::State);
            };
            if radio.grant() != grant {
                radio.retune(grant).await?;
            }
            if radio.phase() == gen2_radio::Phase::Prepared {
                radio.start().await?;
            }
            let current = |cache: &Vec<Entry>, generation| {
                cache
                    .iter()
                    .find(|e| {
                        e.candidate.bssid() == request.bssid
                            && e.candidate.ssid() == request.ssid
                            && e.generation == generation
                    })
                    .map(|e| e.candidate.clone())
            };
            if let Some(entry) = current(cache, radio.generation()) {
                return Ok(Some(entry));
            }
            if candidate.probe_response() {
                // Timing only: the transmitted probe is built by
                // `probe_visit` with the board's HT caps (gen2 F10);
                // mirror them here so the bound covers the caps element.
                let prepared = match radio.ht_caps() {
                    Some(caps) => super::probe_runtime::Prepared::new_with_ht(
                        radio.local(),
                        radio.channel(),
                        &request.ssid,
                        0,
                        &caps,
                        &[],
                    ),
                    None => super::probe_runtime::Prepared::new(
                        radio.local(),
                        radio.channel(),
                        &request.ssid,
                        0,
                        false,
                        &[],
                    ),
                }
                .map_err(|_| gen2_radio::Error::Profile)?;
                let timing = prepared
                    .timing(0, false)
                    .map_err(|_| gen2_radio::Error::Profile)?;
                let probe = Probe {
                    ssid: &request.ssid,
                    extra: &[],
                    timing,
                };
                probe_visit(radio, cache, probe, sequence, false).await?;
            }
            let deadline = now_ms().saturating_add(FRESH_MS);
            loop {
                if let Some(entry) = current(cache, radio.generation()) {
                    return Ok(Some(entry));
                }
                if now_ms() >= deadline {
                    return Ok(None);
                }
                listen(radio, cache, 10, false).await?;
            }
        }
        .await;
        match fresh {
            Ok(Some(entry)) => candidate = entry,
            Ok(None) => return Err(WirelessError::Timeout),
            Err(error) => {
                self.fail(&mut state);
                return Err(match radio_error(error) {
                    WirelessError::Busy | WirelessError::InvalidArgs => {
                        WirelessError::HardwareError
                    }
                    other => other,
                });
            }
        }
        self.channel.store(candidate.channel(), Ordering::Release);
        // Refuse an unsupported BSS before the radio is handed to a station.
        super::management_runtime::Join::prepare(candidate.clone(), self.mac, &request.ssid, mode)
            .map_err(|_| WirelessError::InvalidArgs)?;
        // A 40 MHz BSS earns a wide grant only when the signed record and
        // domain admit the secondary channel: any failure here is a
        // silent Twenty fallback, not a connect error — the station
        // offers HT20 and the Forty negotiation simply never happens.
        let wide = candidate.ht_secondary().and_then(|secondary| {
            let width = if secondary > candidate.channel() {
                super::rtl8192e_radio::Width::Ht40Above
            } else {
                super::rtl8192e_radio::Width::Ht40Below
            };
            state.authority.grant_wide(candidate.channel(), width).ok()
        });
        state.clear_transmit();
        let Slot::Idle(radio) = core::mem::replace(&mut state.slot, Slot::Failed) else {
            return Err(WirelessError::Busy);
        };
        let mut station = match Station::new(*radio, candidate, &request.ssid, mode, pmk, wide) {
            Ok(station) => Box::new(station),
            Err(error) => {
                self.fail(&mut state);
                return Err(station_error(error));
            }
        };
        let result = async {
            if !request.ie.is_empty() {
                station.append_sme_ies(&request.ie)?;
            }
            station.begin(now_ms()).await?;
            while station.phase() != gen2_station::Phase::Open {
                station.step(now_ms(), nonce).await?;
                pause().await;
            }
            Ok(())
        }
        .await;
        state.slot = Slot::Station(station);
        match result {
            Ok(()) => {
                let peer = state.connected();
                self.link(peer);
                Ok(())
            }
            Err(error) => {
                // A refused/failed join is terminal for this owner, as the
                // RTL8188EU attempt is; nothing replays its keys or radio.
                self.fail(&mut state);
                Err(station_error(error))
            }
        }
    }
    /// `rtl8xxxu_stop` + chip power-off, then a fresh `rtl8xxxu_init_device`
    /// lifecycle (`restart_parked`) so the next join starts from RadioReady.
    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.link(None);
        let mut state = self.control_state(true).await?;
        state.clear_transmit();
        let radio = match core::mem::replace(&mut state.slot, Slot::Failed) {
            Slot::Station(mut station) => {
                if station.disconnect().await.is_err() {
                    self.fail(&mut state);
                    return Err(WirelessError::HardwareError);
                }
                station.into_radio()
            }
            Slot::Idle(radio) if radio.phase() == gen2_radio::Phase::Parked => {
                // Administratively DOWN: nothing is associated or running.
                state.slot = Slot::Idle(radio);
                return Ok(());
            }
            Slot::Idle(radio) => *radio,
            Slot::Failed => return Err(WirelessError::HardwareError),
        };
        let mut radio = radio;
        let result = async {
            if radio.phase() == gen2_radio::Phase::Receiving {
                radio.stop().await?;
            }
            if radio.phase() == gen2_radio::Phase::Stopped {
                radio.park().await?;
                radio.restart_parked().await?;
            }
            Ok::<(), gen2_radio::Error>(())
        }
        .await;
        match result {
            Ok(()) if radio.phase() == gen2_radio::Phase::Prepared => {
                state.slot = Slot::Idle(Box::new(radio));
                Ok(())
            }
            _ => {
                self.fail(&mut state);
                Err(WirelessError::HardwareError)
            }
        }
    }
    /// Qualified idle channel change (`rtl8xxxu_config` CHANGE_CHANNEL as a
    /// live retune under the channel's own grant). No TX power override; a
    /// station keeps its channel.
    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError> {
        if cfg.tx_power_dbm.is_some() || !(1..=13).contains(&cfg.channel) {
            return Err(WirelessError::NotSupported);
        }
        if self.failed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let channel = cfg.channel as u8;
        let mut state = self.control_state(false).await?;
        let grant = state
            .authority
            .grant(channel)
            .map_err(|_| WirelessError::NotSupported)?;
        let Slot::Idle(radio) = &mut state.slot else {
            return if self.channel.load(Ordering::Acquire) == channel {
                Ok(())
            } else {
                Err(WirelessError::Busy)
            };
        };
        if radio.grant() == grant {
            return Ok(());
        }
        match radio.retune(grant).await {
            Ok(()) => {
                self.channel.store(channel, Ordering::Release);
                Ok(())
            }
            Err(_) => {
                self.fail(&mut state);
                Err(WirelessError::HardwareError)
            }
        }
    }
}

/// Bounded explicit channel/frequency lists (1..=13; empty = every granted
/// channel), at most one SSID for an active request, extra IEs only with
/// probes, no random address or 6 GHz.
fn validate_scan(request: &ScanRequest) -> Result<(Vec<u8>, u64), WirelessError> {
    if request.random_mac.is_some()
        || request.colocated_6ghz
        || !request.active && !request.extra_ies.is_empty()
        || request.active && request.ssids.len() > 1
        || request.extra_ies.len() > super::probe_runtime::MAX_IE
        || request.ssids.iter().any(|s| s.len() > 32)
        || request.ssids.len() > 32
    {
        return Err(WirelessError::NotSupported);
    }
    let mut channels = Vec::<u8>::new();
    if request.frequencies_mhz.is_empty() {
        for channel in &request.channels {
            if !(1..=13).contains(channel) {
                return Err(WirelessError::NotSupported);
            }
            let channel = *channel as u8;
            if !channels.contains(&channel) {
                channels.push(channel);
            }
        }
    } else {
        for frequency in &request.frequencies_mhz {
            if !(2412..=2472).contains(frequency) || (*frequency - 2407) % 5 != 0 {
                return Err(WirelessError::NotSupported);
            }
            let channel = ((*frequency - 2407) / 5) as u8;
            if !channels.contains(&channel) {
                channels.push(channel);
            }
        }
    }
    let dwell = match request.duration_tu {
        Some(duration @ 1..=1000) => (u64::from(duration) * 1024).div_ceil(1000),
        Some(_) => return Err(WirelessError::InvalidArgs),
        None if request.duration_mandatory => return Err(WirelessError::InvalidArgs),
        None => 200,
    };
    Ok((channels, dwell))
}
fn bss_info(b: Candidate) -> BssInfo {
    let security = if b.ap_rsne().is_some() {
        narf_wireless::scan::BssSecurity::Wpa2
    } else if b.capability() & 0x10 != 0 {
        narf_wireless::scan::BssSecurity::Wep
    } else {
        narf_wireless::scan::BssSecurity::Open
    };
    BssInfo {
        bssid: b.bssid(),
        ssid: b.ssid().to_vec(),
        frequency_mhz: 2407 + u32::from(b.channel()) * 5,
        channel: u32::from(b.channel()),
        rssi: i8::MIN,
        security,
    }
}
fn offloads_admitted(meta: narf_net::TxMeta) -> bool {
    meta.csum_l4.is_none() && meta.tso_mss.is_none() && meta.vlan_tag.is_none()
}
fn transmit_admitted(bytes: &[u8], own: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[6..12] == own
        && bytes[..6] != [0; 6]
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && !matches!(&bytes[12..14], [0x88, 0x8e] | [0x80, 0xf3] | [0x81, 0x37])
}
fn radio_error(error: gen2_radio::Error) -> WirelessError {
    match error {
        gen2_radio::Error::State => WirelessError::Busy,
        gen2_radio::Error::Profile => WirelessError::InvalidArgs,
        _ => WirelessError::HardwareError,
    }
}
fn station_error(error: gen2_station::Error) -> WirelessError {
    match error {
        gen2_station::Error::State => WirelessError::Busy,
        gen2_station::Error::Profile | gen2_station::Error::Management(_) => {
            WirelessError::InvalidArgs
        }
        gen2_station::Error::Timeout | gen2_station::Error::PeerLost => WirelessError::Timeout,
        _ => WirelessError::HardwareError,
    }
}

struct Registered<C: ControlIo, B: PacketIo>(Arc<Device<C, B>>);
impl<C: ControlIo + 'static, B: PacketIo + 'static> Interface for Registered<C, B> {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.0.link_up()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}

#[cfg(feature = "kernel-test")]
#[path = "gen2_interface_tests.rs"]
mod tests;

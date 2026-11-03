// SPDX-License-Identifier: GPL-2.0-or-later
//! Gen2 (RTL8192EU / RTL8723BU) station netdev publication over one
//! retained native USB owner, after `wait_admit` qualified this exact
//! device (signed `N92P`/`N8BP` record, signed regulatory policy, network
//! authority). Unprovisioned devices never reach `attach`.
//!
//! One owner serves passive scans on the admitted initial channel, one
//! station at a time, and the Linux-shaped teardown: `rtl8xxxu_stop`, the
//! chip's power-off (`restart_parked` path) and a fresh `rtl8xxxu_init_device`
//! lifecycle before the next join.
use super::{
    firmware_transport::{ControlIo, Owner as Firmware, UsbControl},
    gen2_radio::{self, Grant, Radio},
    gen2_station::{self, Station},
    management_runtime::{Candidate, SecurityMode},
    packet_transport::{Io as PacketIo, UsbIo},
};
use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_ipc::{Consumer, Producer};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessConfig, WirelessError,
    WirelessNetIface,
};
use zeroize::Zeroizing;

/// Bound on retained scan candidates.
const CANDIDATES: usize = 32;

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

struct State<C: ControlIo, B: PacketIo> {
    slot: Slot<C, B>,
    candidates: Vec<Candidate>,
    rx: Producer<Frame, RX_RING_N>,
    tx: Consumer<Frame, TX_RING_N>,
}
impl<C: ControlIo, B: PacketIo> State<C, B> {
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
    channel: u8,
    up: AtomicBool,
    bssid: AtomicU64,
    failed: AtomicBool,
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
    pub(super) fn new(name: &str, radio: Radio<C, B>) -> Self {
        let (rx, rx_consumer) = narf_ipc::channel();
        let (tx_producer, tx) = narf_ipc::channel();
        let mac = radio.local();
        let channel = radio.channel();
        Self {
            state: Mutex::new(State {
                slot: Slot::Idle(Box::new(radio)),
                candidates: Vec::new(),
                rx,
                tx,
            }),
            name: name.into(),
            mac,
            channel,
            up: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            failed: AtomicBool::new(false),
            rx: IrqSafeSpinLock::new(Some(rx_consumer)),
            tx: IrqSafeSpinLock::new(Some(tx_producer)),
        }
    }
    fn link(&self, peer: Option<[u8; 6]>) {
        let peer = peer.filter(|_| !self.failed.load(Ordering::Acquire));
        let mut packed = [0; 8];
        if let Some(peer) = peer {
            packed[..6].copy_from_slice(&peer);
            packed[7] = 1;
        }
        self.bssid
            .store(u64::from_le_bytes(packed), Ordering::Release);
        let up = peer.is_some();
        let was_up = self.up.swap(up, Ordering::AcqRel);
        if was_up != up {
            narf_net::iface::set_link_state(&self.name, up);
        }
        if was_up && !up {
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
        if self.failed.load(Ordering::Acquire) {
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
    /// Network-stack drain: delivered Ethernet frames, with no lock held
    /// across the stack callback.
    pub(super) fn drain(&self) -> bool {
        let mut frames = Vec::new();
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
    grant: Grant,
) -> Result<Arc<Device<UsbControl, UsbIo>>, gen2_radio::Error> {
    let authority = narf_net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(gen2_radio::Error::Profile)?;
    let usb = firmware.usb_device();
    CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| gen2_radio::Error::State)?;
    let radio = Radio::new(firmware, UsbIo::new(usb), grant)?;
    let name = narf_net::iface::reserve_name("wlan%d");
    let device = Arc::new(Device::new(name, radio));
    narf_net::registry()
        .register(&authority, Registered(device.clone()))
        .map_err(|_| gen2_radio::Error::Profile)?;
    *ACTIVE.lock() = Some(device.clone());
    narf_net::iface::register(name, device.mac, send);
    narf_net::iface::set_link_state(name, false);
    narf_net::iface::install_rx_drain(drain);
    narf_wireless::registry::register(device.clone());
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
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.state
            .try_lock()?
            .candidates
            .iter()
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
                channels: vec![u32::from(self.channel)],
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
    /// Passive dwell on the admitted channel (the only signed permission
    /// this owner holds); other channels and active probes are refused.
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let dwell = validate_scan(&request, self.channel)?;
        if self.failed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let mut state = self.state.lock().await;
        let mut found: Vec<Candidate> = Vec::new();
        let result = async {
            let radio = state.idle_receiving().await?;
            let deadline = now_ms().saturating_add(dwell);
            while now_ms() < deadline {
                if radio.recovery_pending() {
                    radio.maintain(now_ms()).await.map_err(radio_error)?;
                }
                match radio.poll().map_err(radio_error)? {
                    Some(frames) => {
                        for frame in frames {
                            let Ok(bss) =
                                Candidate::from_receive(&frame, radio.channel(), radio.local())
                            else {
                                continue;
                            };
                            found.retain(|b| b.bssid() != bss.bssid());
                            if found.len() < CANDIDATES {
                                found.push(bss);
                            }
                        }
                    }
                    None => pause().await,
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            if error == WirelessError::HardwareError {
                self.fail(&mut state);
            }
            return Err(error);
        }
        state.candidates = found.clone();
        Ok(found
            .into_iter()
            .filter(|b| {
                request.ssids.is_empty()
                    || request
                        .ssids
                        .iter()
                        .any(|ssid| ssid.is_empty() || ssid == b.ssid())
            })
            .map(bss_info)
            .collect())
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if request.channel != u32::from(self.channel)
            || request.frequency_mhz != 2407 + request.channel * 5
        {
            return Err(WirelessError::NotSupported);
        }
        let (mode, pmk) = match request.security {
            SecurityConfig::Open => (SecurityMode::Open, None),
            SecurityConfig::Wpa2 { psk } => (SecurityMode::Wpa2Psk, Some(Zeroizing::new(psk))),
            _ => return Err(WirelessError::NotSupported),
        };
        let mut state = self.state.lock().await;
        let Some(candidate) = state
            .candidates
            .iter()
            .find(|b| b.bssid() == request.bssid && b.ssid() == request.ssid)
            .cloned()
        else {
            return Err(WirelessError::InvalidArgs);
        };
        if !matches!(state.slot, Slot::Idle(_)) {
            return Err(WirelessError::Busy);
        }
        // Refuse an unsupported BSS before the radio is handed to a station.
        super::management_runtime::Join::prepare(candidate.clone(), self.mac, &request.ssid, mode)
            .map_err(|_| WirelessError::InvalidArgs)?;
        state.clear_transmit();
        let Slot::Idle(radio) = core::mem::replace(&mut state.slot, Slot::Failed) else {
            return Err(WirelessError::Busy);
        };
        let mut station = match Station::new(*radio, candidate, &request.ssid, mode, pmk) {
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
        let mut state = self.state.lock().await;
        state.clear_transmit();
        let radio = match core::mem::replace(&mut state.slot, Slot::Failed) {
            Slot::Station(mut station) => {
                if station.disconnect().await.is_err() {
                    self.fail(&mut state);
                    return Err(WirelessError::HardwareError);
                }
                station.into_radio()
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
    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError> {
        // Only the admitted channel exists; no TX power override.
        if cfg.tx_power_dbm.is_some() || cfg.channel != u32::from(self.channel) {
            return Err(WirelessError::NotSupported);
        }
        Ok(())
    }
}

fn validate_scan(request: &ScanRequest, channel: u8) -> Result<u64, WirelessError> {
    if request.random_mac.is_some()
        || request.colocated_6ghz
        || request.active
        || !request.extra_ies.is_empty()
        || request.ssids.iter().any(|s| s.len() > 32)
        || request.ssids.len() > 32
        || request.channels.iter().any(|c| *c != u32::from(channel))
        || request
            .frequencies_mhz
            .iter()
            .any(|f| *f != 2407 + u32::from(channel) * 5)
    {
        return Err(WirelessError::NotSupported);
    }
    match request.duration_tu {
        Some(duration @ 1..=1000) => Ok((u64::from(duration) * 1024).div_ceil(1000)),
        Some(_) => Err(WirelessError::InvalidArgs),
        None if request.duration_mandatory => Err(WirelessError::InvalidArgs),
        None => Ok(200),
    }
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

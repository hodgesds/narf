// SPDX-License-Identifier: GPL-2.0-or-later
//! One shared native EE view for async wireless control and synchronous stack
//! drains. No executor task is needed to complete DHCP/native packet receipts.
use super::{
    efuse::Factory,
    prepare::{
        packet::Port,
        station::{self, Environment},
        Memory, Phase, Prepared,
    },
};
use crate::platform::lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use crate::platform::net::{Frame, Interface, RX_RING_N, TX_RING_N};
use crate::platform::wireless::WirelessNetIface;
use alloc::{
    boxed::Box,
    string::String,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessConfig, WirelessError,
};
use zeroize::Zeroizing;
#[path = "rtl8723ae/native_activation.rs"]
mod ae_activation;
#[path = "rtl8723be/tracking_native.rs"]
mod be_thermal;
#[path = "channel_runtime.rs"]
mod channel_runtime;
#[path = "endpoint_routes.rs"]
mod endpoint_routes;
#[path = "lifecycle.rs"]
mod lifecycle;
#[path = "rebuild_native.rs"]
mod rebuild_native;
#[path = "recovery.rs"]
pub(crate) mod recovery;
#[path = "scan_runtime.rs"]
mod scan_runtime;
#[path = "supervisor.rs"]
pub(crate) mod supervisor;
#[path = "system_sleep.rs"]
mod system_sleep;
type Error = station::Error;
struct EndpointState {
    rx: crate::platform::ipc::Producer<Frame, RX_RING_N>,
    tx: crate::platform::ipc::Consumer<Frame, TX_RING_N>,
    pending: Option<Frame>,
    /// Receipt belongs to this one retained pending frame, never a packet class.
    special_notified: bool,
    epoch: u64,
}
struct Received {
    bytes: Vec<u8>,
    publication: Arc<station::Publication>,
    generation: u64,
}
impl EndpointState {
    fn clear(&mut self) {
        self.pending = None;
        self.special_notified = false;
        for _ in 0..TX_RING_N {
            if !matches!(self.tx.try_recv(), Ok(Some(_))) {
                break;
            }
        }
    }
}
pub(crate) struct Device<I: Port<Buffer = M>, M: Memory, E: Environment> {
    pub(super) prepared: Arc<Mutex<Option<Prepared<I, M>>>>,
    state: Mutex<EndpointState>,
    factory: Arc<Factory>,
    environment: E,
    name: String,
    published: AtomicBool,
    route: AtomicU64,
    admission: Arc<station::Admission>,
    up: AtomicBool,
    bssid: AtomicU64,
    ht: AtomicBool,
    ht40: AtomicBool,
    ae_ht20: AtomicBool,
    /// RTL8821AE per-band host capability (`rtl8821ae::vht::HOST_*`).
    rtl8821ae_caps: AtomicU8,
    /// Exact installed N21C channel, or zero for the ordinary NAPC profile.
    /// This display/control preflight cache grants no RF authority.
    coex_channel: AtomicU8,
    /// RTL8192EE `rtl8192ee::ht::host_capabilities` bits (0 otherwise).
    rtl8192ee_caps: AtomicU8,
    /// RTL8192CE / 8188CE `rtl8192ce::ht::host_capabilities` bits (0
    /// otherwise).
    rtl8192ce_caps: AtomicU8,
    /// RTL8192DE `rtl8192de::ht::host_capabilities` bits (0 otherwise).
    rtl8192de_caps: AtomicU8,
    /// RTL8723BE `rtl8723be::ht::host_capabilities` bits (0 otherwise).
    rtl8723be_caps: AtomicU8,
    rts_threshold: AtomicU32,
    rx: Arc<IrqSafeSpinLock<Option<crate::platform::ipc::Consumer<Frame, RX_RING_N>>>>,
    tx: IrqSafeSpinLock<Option<crate::platform::ipc::Producer<Frame, TX_RING_N>>>,
    leisure: IrqSafeSpinLock<Leisure>,
    lifecycle: lifecycle::Lifecycle,
    work: Mutex<Option<supervisor::Work>>,
    scan_request: Mutex<()>,
    scan_cache: IrqSafeSpinLock<Vec<scan_runtime::Observation>>,
    /// `rtl_pci_remove` ran: the publisher worker exits.
    removed: AtomicBool,
}
/// Linux `rtl_watchdog_wq_callback` LPS bookkeeping (`link_info`
/// num_rx/tx_inperiod, `mac->cnt_after_linked`) plus a pending
/// `rtl_lps_leave` request raised by the data path.
#[derive(Default)]
struct Leisure {
    rx: u32,
    tx: u32,
    last_ms: Option<u64>,
    linked: u8,
    leave: bool,
}
/// `RTL_WATCH_DOG_TIME` (base.h): the 2 s watchdog period (LPS decision,
/// `dm_watchdog`).
const WATCHDOG_MS: u64 = 2_000;
/// Linux `rtl88ee_mod_params.fwctrl_lps` (module parameter `fwlps`),
/// default off exactly like the upstream RTL8188EE driver.
static FW_LPS: AtomicBool = AtomicBool::new(false);
static INACTIVE_PS: AtomicBool = AtomicBool::new(true);
static PCIE_ASPM: AtomicBool = AtomicBool::new(true);
/// Linux's default-on `aspm` preparation policy. Changes apply at the next
/// cold preparation; they do not claim completion of a live PCI transition.
pub fn set_pcie_aspm(enabled: bool) {
    PCIE_ASPM.store(enabled, Ordering::Release);
}
/// Equivalent to Linux rtl8188ee's default-on `ips` parameter.
pub fn set_inactive_power_save(enabled: bool) {
    INACTIVE_PS.store(enabled, Ordering::Release);
}
/// Module-parameter equivalent of `rtl8188ee fwlps=`.
pub fn set_leisure_power_save(enabled: bool) {
    FW_LPS.store(enabled, Ordering::Release);
}
/// Linux `rtl_watchdog_wq_callback`/`_rtl_pci_rx_interrupt` busy test:
/// `num_rx + num_tx > 8 || num_rx > 2` leaves LPS.
fn busy(rx: u32, tx: u32) -> bool {
    rx + tx > 8 || rx > 2
}
/// Linux `rtl_is_special_data` (TX) class: EAPOL, ARP and DHCP (UDP 67/68).
fn special_class(frame: &[u8]) -> Option<super::btcoex::btc::Packet> {
    use super::btcoex::btc::Packet;
    match frame.get(12..14) {
        Some([0x88, 0x8e]) => Some(Packet::Eapol),
        Some([0x08, 0x06]) => Some(Packet::Arp),
        Some([0x08, 0x00]) => {
            let &version = frame.get(14)?;
            let ihl = usize::from(version & 15) * 4;
            if version >> 4 != 4 || ihl < 20 || frame.get(23) != Some(&17) {
                return None;
            }
            let at = 14 + ihl;
            match (frame.get(at..at + 2), frame.get(at + 2..at + 4)) {
                (Some(src), Some(dst)) => {
                    let src = u16::from_be_bytes([src[0], src[1]]);
                    let dst = u16::from_be_bytes([dst[0], dst[1]]);
                    matches!((src, dst), (68, 67) | (67, 68)).then_some(Packet::Dhcp)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Linux `rtl_is_special_data` (TX): EAPOL, ARP and DHCP (UDP 67/68)
/// leave LPS before transmission.
fn special(frame: &[u8]) -> bool {
    special_class(frame).is_some()
}
impl<I: Port<Buffer = M>, M: Memory, E: Environment> core::fmt::Debug for Device<I, M, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188eeDevice")
            .field("name", &self.name)
            .field("up", &self.up)
            .finish_non_exhaustive()
    }
}
struct Attempt<'a> {
    device: &'a dyn Close,
    owner: Option<Arc<AtomicBool>>,
    generation: u64,
    armed: bool,
}
trait Close: Sync {
    fn close(&self);
    fn request_abort(&self);
    fn abort_generation(&self, expected: u64);
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.armed {
            if let Some(owner) = &self.owner {
                owner.store(true, Ordering::Release);
            }
            self.device.abort_generation(self.generation);
        }
    }
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Close
    for Device<I, M, E>
{
    fn close(&self) {
        self.commit_close(self.admission.publication.lock());
    }
    fn request_abort(&self) {
        self.admission.abort.store(true, Ordering::Release);
        self.close();
    }
    fn abort_generation(&self, expected: u64) {
        let publication = self.admission.publication.lock();
        if self.lifecycle.generation() == expected {
            self.admission.abort.store(true, Ordering::Release);
            self.commit_close(publication);
        }
    }
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Device<I, M, E> {
    /// The RTL8821AE envelope publishes HT on some band.
    fn rtl8821ae_host_ht(&self) -> bool {
        use super::rtl8821ae::vht::{HOST_HT_2G, HOST_HT_5G};
        self.rtl8821ae_caps.load(Ordering::Acquire) & (HOST_HT_2G | HOST_HT_5G) != 0
    }
    /// The RTL8192EE envelope publishes 2.4 GHz HT.
    fn rtl8192ee_host_ht(&self) -> bool {
        self.rtl8192ee_caps.load(Ordering::Acquire) & super::rtl8192ee::ht::HOST_HT_2G != 0
    }
    /// The RTL8192CE / 8188CE envelope publishes 2.4 GHz HT.
    fn rtl8192ce_host_ht(&self) -> bool {
        self.rtl8192ce_caps.load(Ordering::Acquire) & super::rtl8192ce::ht::HOST_HT_2G != 0
    }
    /// The RTL8192DE envelope publishes HT on 2.4 GHz and 5 GHz.
    fn rtl8192de_host_ht(&self) -> bool {
        self.rtl8192de_caps.load(Ordering::Acquire)
            & (super::rtl8192de::ht::HOST_HT_2G | super::rtl8192de::ht::HOST_HT_5G)
            != 0
    }
    /// The RTL8723BE envelope publishes 2.4 GHz HT.
    fn rtl8723be_host_ht(&self) -> bool {
        self.rtl8723be_caps.load(Ordering::Acquire) & super::rtl8723be::ht::HOST_HT_2G != 0
    }
    pub(crate) fn configured_rts_threshold(&self) -> Option<u16> {
        u16::try_from(self.rts_threshold.load(Ordering::Acquire)).ok()
    }
    fn commit_close(&self, _publication: crate::platform::lib::sync::IrqSafeSpinLockGuard<'_, ()>) {
        self.admission.closed.store(true, Ordering::Release);
        self.ht.store(false, Ordering::Release);
        self.ht40.store(false, Ordering::Release);
        self.ae_ht20.store(false, Ordering::Release);
        self.rtl8821ae_caps.store(0, Ordering::Release);
        self.coex_channel.store(0, Ordering::Release);
        self.rtl8192ee_caps.store(0, Ordering::Release);
        self.rtl8192ce_caps.store(0, Ordering::Release);
        self.rtl8192de_caps.store(0, Ordering::Release);
        self.rtl8723be_caps.store(0, Ordering::Release);
        *self.rx.lock() = None;
        self.update_link(None);
    }
    pub(super) fn new(
        name: &str,
        prepared: Arc<Mutex<Option<Prepared<I, M>>>>,
        factory: Arc<Factory>,
        environment: E,
        initial_channel: u8,
    ) -> Self {
        let admission = environment
            .admission()
            .cloned()
            .unwrap_or_else(|| Arc::new(station::Admission::new()));
        let (rx, consumer) = crate::platform::ipc::channel();
        let (producer, tx) = crate::platform::ipc::channel();
        Self {
            prepared,
            state: Mutex::new(EndpointState {
                rx,
                tx,
                pending: None,
                special_notified: false,
                epoch: 0,
            }),
            factory,
            environment,
            name: name.into(),
            published: AtomicBool::new(false),
            route: AtomicU64::new(0),
            admission,
            up: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            ht: AtomicBool::new(false),
            ht40: AtomicBool::new(false),
            ae_ht20: AtomicBool::new(false),
            rtl8821ae_caps: AtomicU8::new(0),
            coex_channel: AtomicU8::new(0),
            rtl8192ee_caps: AtomicU8::new(0),
            rtl8192ce_caps: AtomicU8::new(0),
            rtl8192de_caps: AtomicU8::new(0),
            rtl8723be_caps: AtomicU8::new(0),
            rts_threshold: AtomicU32::new(u32::MAX),
            rx: Arc::new(IrqSafeSpinLock::new(Some(consumer))),
            tx: IrqSafeSpinLock::new(Some(producer)),
            leisure: IrqSafeSpinLock::new(Leisure::default()),
            lifecycle: lifecycle::Lifecycle::with_channel(initial_channel),
            work: Mutex::new(None),
            scan_request: Mutex::new(()),
            scan_cache: IrqSafeSpinLock::new(Vec::new()),
            removed: AtomicBool::new(false),
        }
    }
    fn update_link(&self, peer: Option<[u8; 6]>) {
        let mut packed = [0; 8];
        if let Some(peer) = peer {
            packed[..6].copy_from_slice(&peer);
            packed[7] = 1;
        }
        self.bssid
            .store(u64::from_le_bytes(packed), Ordering::Release);
        let up = peer.is_some();
        let was = self.up.swap(up, Ordering::AcqRel);
        // Physical carrier preserves operator-controlled IFF_UP and never
        // invokes an administrative open/stop hook under retained locks.
        crate::platform::net::iface::set_link_metadata(&self.name, up, None, None);
        if was && !up {
            crate::platform::wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }
    fn link(&self, peer: Option<[u8; 6]>) {
        let _publication = self.admission.publication.lock();
        self.update_link(peer.filter(|_| !self.admission.closed.load(Ordering::Acquire)));
    }
    async fn ready(&self, owner: &mut Prepared<I, M>) -> Result<(), Error> {
        if self.admission.closed.load(Ordering::Acquire) || !self.published.load(Ordering::Acquire)
        {
            return Err(Error::State);
        }
        if owner.chip() == super::prepare::Chip::Rtl8723ae {
            owner.rtl8723ae_ready(
                &self.factory,
                self.lifecycle.channel.load(Ordering::Acquire),
                &self.environment.domain()?,
            )?;
        } else if owner.chip() == super::prepare::Chip::Rtl8821ae {
            if matches!(
                owner.phase(),
                Phase::RadioConfigured | Phase::ChannelConfigured | Phase::MacConfigured
            ) && !owner.station_calibration_present()
            {
                let domain = self.environment.domain()?;
                let channel = self.lifecycle.channel.load(Ordering::Acquire);
                crate::future_heap::build(|| {
                    super::prepare_native::admit_rtl8821ae(owner, &self.factory, &domain, channel)
                })
                .await?;
            }
        } else if owner.chip() == super::prepare::Chip::Rtl8192ee {
            if matches!(
                owner.phase(),
                Phase::RadioConfigured | Phase::ChannelConfigured | Phase::MacConfigured
            ) && !owner.station_calibration_present()
            {
                let domain = self.environment.domain()?;
                let channel = self.lifecycle.channel.load(Ordering::Acquire);
                crate::future_heap::build(|| {
                    super::prepare_native::admit_rtl8192ee(owner, &self.factory, &domain, channel)
                })
                .await?;
            }
        } else if owner.chip() == super::prepare::Chip::Rtl8192ce {
            if matches!(
                owner.phase(),
                Phase::RadioConfigured | Phase::ChannelConfigured | Phase::MacConfigured
            ) && !owner.station_calibration_present()
            {
                let domain = self.environment.domain()?;
                let channel = self.lifecycle.channel.load(Ordering::Acquire);
                crate::future_heap::build(|| {
                    super::prepare_native::admit_rtl8192ce(owner, &self.factory, &domain, channel)
                })
                .await?;
            }
        } else if owner.chip() == super::prepare::Chip::Rtl8723be {
            if matches!(
                owner.phase(),
                Phase::RadioConfigured | Phase::ChannelConfigured | Phase::MacConfigured
            ) && !owner.station_calibration_present()
            {
                let domain = self.environment.domain()?;
                let channel = self.lifecycle.channel.load(Ordering::Acquire);
                crate::future_heap::build(|| {
                    super::prepare_native::admit_rtl8723be(owner, &self.factory, &domain, channel)
                })
                .await?;
            }
        } else if owner.chip() == super::prepare::Chip::Rtl8192de {
            if matches!(
                owner.phase(),
                Phase::RadioConfigured | Phase::ChannelConfigured | Phase::MacConfigured
            ) && !owner.station_calibration_present()
            {
                let domain = self.environment.domain()?;
                let channel = self.lifecycle.channel.load(Ordering::Acquire);
                crate::future_heap::build(|| {
                    super::prepare_native::admit_rtl8192de(owner, &self.factory, &domain, channel)
                })
                .await?;
            }
        } else if matches!(
            owner.phase(),
            Phase::RadioConfigured | Phase::ChannelConfigured
        ) {
            let calibration = super::channel_power::Calibration::load_registered(&self.factory)
                .map_err(|_| Error::Profile)?;
            let domain = self.environment.domain()?;
            let permission = calibration
                .permission(&domain, self.lifecycle.channel.load(Ordering::Acquire))
                .map_err(|_| Error::Profile)?;
            owner.configure_channel(permission).await?;
            owner.configure_mac(&self.factory)?;
            owner.stage_station_calibration(calibration, &domain)?;
        }
        if owner.phase() == Phase::MacConfigured && !owner.station_calibration_present() {
            if matches!(
                owner.chip(),
                super::prepare::Chip::Rtl8821ae
                    | super::prepare::Chip::Rtl8192ee
                    | super::prepare::Chip::Rtl8192ce
                    | super::prepare::Chip::Rtl8723be
                    | super::prepare::Chip::Rtl8192de
            ) {
                return Err(Error::Profile);
            }
            let calibration = super::channel_power::Calibration::load_registered(&self.factory)
                .map_err(|_| Error::Profile)?;
            owner.stage_station_calibration(calibration, &self.environment.domain()?)?;
        }
        if owner.station_phase() == station::Phase::Dormant && owner.phase() == Phase::MacConfigured
        {
            if let Err(error) =
                crate::future_heap::build(|| owner.prepare_station_bus_power(&self.environment))
                    .await
            {
                self.close();
                return Err(error);
            }
        }
        if owner.station_phase() == station::Phase::Dormant {
            let rx = self.rx.clone();
            owner.station_receive_retirement(Arc::new(move || {
                *rx.lock() = None;
            }));
            if let Err(e) = owner.prepare_station_ht(&self.environment) {
                if owner.phase() == Phase::Failed || owner.station_ht_capability().is_some() {
                    owner.abort_station();
                    self.close();
                }
                return Err(e);
            }
            // Starting the original station can install its separately
            // qualified N21C20MHz base. Publish capabilities only after that
            // continuation succeeds, so old NAPC width/VHT bits cannot escape.
            crate::future_heap::build(|| owner.start_station_service(&self.environment)).await?;
            self.ae_ht20.store(owner.rtl8723ae_ht(), Ordering::Release);
            self.coex_channel.store(
                if owner.station_full_coex() {
                    owner.station_grant().ok_or(Error::State)?.channel()
                } else {
                    0
                },
                Ordering::Release,
            );
            self.ht
                .store(owner.station_ht_capability().is_some(), Ordering::Release);
            self.ht40
                .store(owner.station_ht40_supported(), Ordering::Release);
            self.rtl8821ae_caps.store(
                owner.station_rtl8821ae_host_caps(&self.environment),
                Ordering::Release,
            );
            self.rtl8192ee_caps.store(
                owner.station_rtl8192ee_host_caps(&self.environment),
                Ordering::Release,
            );
            self.rtl8192ce_caps.store(
                owner.station_rtl8192ce_host_caps(&self.environment),
                Ordering::Release,
            );
            self.rtl8192de_caps.store(
                owner.station_rtl8192de_host_caps(&self.environment),
                Ordering::Release,
            );
            self.rtl8723be_caps.store(
                owner.station_rtl8723be_host_caps(&self.environment),
                Ordering::Release,
            );
        }
        if owner.station_phase() == station::Phase::Failed {
            return Err(Error::State);
        }
        Ok(())
    }
    pub(super) fn enqueue(
        &self,
        bytes: &[u8],
        meta: crate::platform::net::TxMeta,
    ) -> Result<(), ()> {
        if self.admission.closed.load(Ordering::Acquire)
            || !self.up.load(Ordering::Acquire)
            || !admitted(bytes, self.factory.mac)
            || !offloads(meta)
        {
            return Err(());
        }
        let (publication, generation) = {
            let owner = self.prepared.try_lock().ok_or(())?;
            let owner = owner.as_ref().ok_or(())?;
            if owner.station_peer().is_none() {
                return Err(());
            }
            let publication = owner
                .station_publication_token(&self.environment)
                .map_err(|_| {
                    self.request_abort();
                })?;
            (publication, self.lifecycle.generation())
        };
        let buffer = crate::platform::io::alloc_coherent(
            bytes.len(),
            crate::platform::lib::id::DomainId::DRIVER_0,
        )
        .map_err(|_| ())?;
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        frame.set_tx_meta(meta);
        let _lease = self
            .lifecycle
            .lease(&self.admission, generation)
            .ok_or(())?;
        let result = self.environment.domain().and_then(|domain| {
            publication.invoke(&domain, || {
                Ok(self
                    .tx
                    .lock()
                    .as_mut()
                    .ok_or(())
                    .and_then(|tx| tx.try_send(frame).map_err(|_| ())))
            })
        });
        if let Some(signal) = self.environment.interrupt() {
            // Interrupt-driven service sleeps until a vector fires; stack
            // TX is the other wake source.
            signal.raise();
        }
        match result {
            Ok(Some(result)) => result,
            Ok(None) => Err(()),
            Err(_) => {
                self.abort_generation(generation);
                Err(())
            }
        }
    }
    /// Async preflight for the exact retained handshake reply and then the
    /// exact queued Ethernet frame. Prepared -> endpoint lock order matches
    /// synchronous progress; both are async-safe Mutex guards. No later stack
    /// drain can move this frame while coexistence waits on its H2C receipt.
    async fn coex_flush_special(&self) -> Result<(), Error> {
        let mut storage = self.prepared.lock().await;
        let Some(owner) = storage.as_mut() else {
            return Ok(());
        };
        if owner.chip() != super::prepare::Chip::Rtl8723be && !owner.station_full_coex() {
            return Ok(());
        }
        if owner.phase() != super::prepare::Phase::Running {
            return Ok(());
        }
        if self.admission.closed.load(Ordering::Acquire)
            || self.lifecycle.rebuilding.load(Ordering::Acquire)
            || self.lifecycle.suspended.load(Ordering::Acquire)
            || self.lifecycle.inactive.load(Ordering::Acquire)
        {
            return Ok(());
        }
        owner
            .station_coex_service(&self.environment)
            .await
            .map_err(|_| Error::State)?;
        if !owner.transmit_ready() {
            return Ok(());
        }
        owner
            .flush_station_eapol(&self.environment)
            .await
            .map_err(|_| Error::State)?;
        let mut state = self.state.lock().await;
        if state.special_notified {
            return Ok(());
        }
        let Some(packet) = state
            .pending
            .as_ref()
            .and_then(|frame| special_class(frame.payload()))
        else {
            return Ok(());
        };
        let generation = self.lifecycle.generation();
        owner
            .station_special_packet(packet, &self.environment)
            .await
            .map_err(|_| Error::State)?;
        if self.admission.closed.load(Ordering::Acquire)
            || self.lifecycle.generation() != generation
            || self.lifecycle.suspended.load(Ordering::Acquire)
            || self.lifecycle.inactive.load(Ordering::Acquire)
        {
            state.clear();
            owner.abort_station();
            return Err(Error::State);
        }
        owner.station_publication(&self.environment, || Ok(()))?;
        state.special_notified = true;
        Ok(())
    }
    fn progress(&self) -> Vec<Received> {
        if self.lifecycle.rebuilding.load(Ordering::Acquire)
            || self.lifecycle.suspended.load(Ordering::Acquire)
            || self.lifecycle.inactive.load(Ordering::Acquire)
        {
            return Vec::new();
        }
        let Some(mut storage) = self.prepared.try_lock() else {
            return Vec::new();
        };
        let Some(owner) = storage.as_mut() else {
            return Vec::new();
        };
        let Some(mut state) = self.state.try_lock() else {
            return Vec::new();
        };
        let generation = self.lifecycle.generation();
        if self.admission.closed.load(Ordering::Acquire) {
            state.clear();
            self.withdraw_interrupts(owner);
            if self.admission.abort.load(Ordering::Acquire)
                || owner.station_phase() == station::Phase::Failed
            {
                owner.abort_station();
            }
            return Vec::new();
        }
        if !matches!(
            owner.station_phase(),
            station::Phase::Passive | station::Phase::Open | station::Phase::Failed
        ) {
            return Vec::new();
        }
        let result: Result<Vec<Received>, Error> = (|| {
            self.service_interrupts(owner)?;
            let frames = owner.progress_station(&self.environment)?;
            owner.station_publication(&self.environment, || {
                self.link(owner.station_peer());
                Ok(())
            })?;
            let (_, epoch) = owner.station_receive_epoch();
            if state.epoch != epoch {
                let (producer, consumer) = crate::platform::ipc::channel();
                state.rx = producer;
                *self.rx.lock() = Some(consumer);
                state.epoch = epoch;
            }
            if self.admission.closed.load(Ordering::Acquire) {
                state.clear();
                return Ok(Vec::new());
            }
            if owner.station_peer().is_none() {
                state.clear();
                return Ok(Vec::new());
            }
            if state.pending.is_none() {
                for _ in 0..16 {
                    let Ok(Some(frame)) = state.tx.try_recv() else {
                        break;
                    };
                    if admitted(frame.payload(), self.factory.mac) && offloads(frame.tx_meta()) {
                        state.special_notified = false;
                        state.pending = Some(frame);
                        break;
                    }
                }
            }
            let mut sent = 0;
            if owner.station_transmit_ready() && !self.admission.closed.load(Ordering::Acquire) {
                if let Some(frame) = state.pending.take() {
                    if (owner.chip() == super::prepare::Chip::Rtl8723be
                        || owner.station_full_coex())
                        && special(frame.payload())
                        && !state.special_notified
                    {
                        // The worker must complete the exact frame's async
                        // coexistence preflight before any descriptor emission.
                        state.pending = Some(frame);
                    } else if owner.leisure() && special(frame.payload()) {
                        // rtl_is_special_data: wake before EAPOL/ARP/DHCP.
                        state.pending = Some(frame);
                        self.request_leave();
                    } else {
                        owner.send_station_ethernet(frame.payload(), &self.environment)?;
                        state.special_notified = false;
                        sent = 1;
                    }
                }
            }
            let busy = {
                let mut leisure = self.leisure.lock();
                leisure.rx = leisure.rx.saturating_add(frames.len() as u32);
                leisure.tx = leisure.tx.saturating_add(sent);
                busy(leisure.rx, leisure.tx)
            };
            if busy && owner.leisure() {
                self.request_leave();
            }
            if self.admission.closed.load(Ordering::Acquire) {
                state.clear();
                return Ok(Vec::new());
            }
            let publication = Arc::new(owner.station_publication_token(&self.environment)?);
            if !owner.station_receive_open() {
                return Ok(Vec::new());
            }
            for bytes in &frames {
                if let Ok(buffer) = crate::platform::io::alloc_coherent(
                    bytes.len(),
                    crate::platform::lib::id::DomainId::DRIVER_0,
                ) {
                    let mut frame = Frame::new(buffer, bytes.len() as u32);
                    frame.payload_mut().copy_from_slice(bytes);
                    publication.invoke(&self.environment.domain()?, || {
                        let _ = state.rx.try_send(frame);
                        Ok(())
                    })?;
                }
            }
            Ok(frames
                .into_iter()
                .map(|bytes| Received {
                    bytes,
                    publication: publication.clone(),
                    generation,
                })
                .collect())
        })();
        match result {
            Ok(frames) => frames,
            Err(_) => {
                self.withdraw_interrupts(owner);
                owner.abort_station();
                state.clear();
                self.close();
                Vec::new()
            }
        }
    }
    fn request_leave(&self) {
        self.leisure.lock().leave = true;
        if let Some(signal) = self.environment.interrupt() {
            signal.raise();
        }
    }
    /// One Linux LPS decision step (`rtl_watchdog_wq_callback` →
    /// `rtl_lps_enter`/`rtl_lps_leave`, plus data-path leave requests).
    /// Enter requires the `rtl_lps_enter_core` gates: fwctrl_lps, linked
    /// for at least 5 watchdog periods, RSNA port open, and an idle
    /// period. Any failed H2C/RPWM step leaves the owner Failed; the next
    /// service pass aborts it like every other terminal hardware error.
    pub(super) async fn power_save(&self, enabled: bool) {
        let mut storage = self.prepared.lock().await;
        let Some(owner) = storage.as_mut() else {
            return;
        };
        if owner.chip() == super::prepare::Chip::Rtl8723ae {
            return;
        }
        if self.admission.closed.load(Ordering::Acquire) {
            // disconnect_station_peer leaves PS itself before the report.
            return;
        }
        let now = self.environment.now_ms();
        let (leave, sample) = {
            let mut leisure = self.leisure.lock();
            let leave = core::mem::take(&mut leisure.leave);
            let due = leisure
                .last_ms
                .is_none_or(|last| now.saturating_sub(last) >= WATCHDOG_MS);
            let sample = due.then(|| {
                leisure.last_ms = Some(now);
                (
                    core::mem::take(&mut leisure.rx),
                    core::mem::take(&mut leisure.tx),
                )
            });
            (leave, sample)
        };
        let linked = owner.phase() == Phase::Running && owner.station_linked();
        if owner.leisure() && (leave || !enabled || !linked) {
            if !self.be_tracked_lps(owner, false).await {
                let _ = owner.leave_leisure().await;
            }
            return;
        }
        let Some((rx, tx)) = sample else {
            return;
        };
        let periods = {
            let mut leisure = self.leisure.lock();
            leisure.linked = if linked {
                leisure.linked.saturating_add(1).min(20)
            } else {
                0
            };
            leisure.linked
        };
        if !enabled || !linked {
            return;
        }
        if busy(rx, tx) {
            if owner.leisure() && !self.be_tracked_lps(owner, false).await {
                let _ = owner.leave_leisure().await;
            }
        } else if periods >= 5
            && !owner.leisure()
            && owner.transmit_ready()
            && !self.be_tracked_lps(owner, true).await
        {
            let _ = owner.enter_leisure().await;
        }
    }
    /// The prompt half of [`Self::power_save`]: a pending data-path leave
    /// request, LPS disabled or the link gone leaves LPS now rather than at
    /// the next watchdog period (Linux `rtl_lps_leave` from the TX/RX paths
    /// and `lps_change_work`). The period's traffic sample is untouched.
    pub(super) async fn lps_leave(&self, enabled: bool) {
        let leave = core::mem::take(&mut self.leisure.lock().leave);
        let mut storage = self.prepared.lock().await;
        let Some(owner) = storage.as_mut() else {
            return;
        };
        if self.admission.closed.load(Ordering::Acquire) || !owner.leisure() {
            return;
        }
        let linked = owner.phase() == Phase::Running && owner.station_linked();
        if (leave || !enabled || !linked) && !self.be_tracked_lps(owner, false).await {
            let _ = owner.leave_leisure().await;
        }
    }
    /// `rtl_watchdog_wq_callback`: one `RTL_WATCH_DOG_TIME` period of the
    /// LPS decision and `dm_watchdog` (thermal tracking, antenna diversity,
    /// rate-adaptive mask), run from the device's watchdog work.
    pub(super) async fn watchdog(&self) {
        self.gain_tracking().await;
        self.antenna_diversity().await;
        self.power_save(FW_LPS.load(Ordering::Acquire)).await;
        self.rate_adaptive().await;
    }
    /// Linux `rtl_pci_remove` for the native owner. `ieee80211_unregister_hw`
    /// closes every control/packet path and withdraws the netdev, wireless
    /// and stack registrations; `rtl_op_stop` → `rtl_pci_stop` masks the chip
    /// (`disable_interrupt`) before `rtl_pci_deinit` releases the MSI vector;
    /// a linked station first sends its JOINBSSRPT disconnect. The retained
    /// owner is then stopped and must pass the card-disable quiescence proof
    /// (`Prepared::quiesce`) before it is dropped and its rings released.
    /// Returns whether the DMA mappings were reclaimed; otherwise they stay
    /// pinned for the kernel's lifetime. Idempotent.
    pub(super) async fn remove(self: &Arc<Self>) -> bool {
        self.removed.store(true, Ordering::Release);
        self.close();
        if let Some(signal) = self.environment.interrupt() {
            signal.raise();
        }
        self.withdraw();
        let _control = self.lifecycle.control.lock().await;
        let mut storage = self.prepared.lock().await;
        self.state.lock().await.clear();
        let Some(owner) = storage.as_mut() else {
            return true;
        };
        self.withdraw_interrupts(owner);
        if owner.station_peer().is_some() {
            // Report the disconnect, then stop and prove the engines idle.
            let _ = owner.disconnect_station_peer().await;
        }
        let reclaimed = owner.retire().await;
        let publishers_retired = self.lifecycle.drain_publications().await.is_ok();
        if reclaimed {
            // Proven idle (or never published): Drop releases every ring.
            storage.take();
        }
        reclaimed && publishers_retired
    }
    /// Withdraw this device from every registry `publish` entered.
    fn withdraw(self: &Arc<Self>) {
        if !self.published.swap(false, Ordering::AcqRel) {
            return;
        }
        let cookie = self.route.swap(0, Ordering::AcqRel);
        ROUTES.lock().remove(cookie, Arc::as_ptr(self) as *const ());
        #[cfg(feature = "builtin")]
        {
            narf_wireless::registry::unregister(&self.name);
            crate::platform::net::registry().unregister(&self.name);
            crate::platform::net::iface::unregister(&self.name);
        }
        #[cfg(feature = "module")]
        crate::module_netdev::withdraw();
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn removed_for_test(&self) -> bool {
        self.removed.load(Ordering::Acquire)
    }
    /// Thermal source watchdog; an unavailable/revoked qualification never
    /// substitutes a default gain curve and a failed transition closes carrier.
    pub(super) async fn gain_tracking(&self) {
        let mut storage = self.prepared.lock().await;
        let Some(owner) = storage.as_mut() else {
            return;
        };
        if owner.chip() == super::prepare::Chip::Rtl8723be {
            return;
        }
        if self.admission.closed.load(Ordering::Acquire) {
            return;
        }
        if owner.track_station_gain(&self.environment).await.is_err() {
            owner.abort_station();
            self.close();
        }
    }
    pub(super) async fn antenna_diversity(&self) {
        let mut storage = self.prepared.lock().await;
        let Some(owner) = storage.as_mut() else {
            return;
        };
        if self.admission.closed.load(Ordering::Acquire) {
            return;
        }
        if owner
            .progress_station_antenna(&self.environment)
            .await
            .is_err()
        {
            owner.abort_station();
            self.close();
        }
    }
    pub(crate) fn antenna_diversity_request(
        &self,
        firmware: super::firmware_transport::Identity,
    ) -> Result<super::AntennaDiversityRequest, Error> {
        let storage = self.prepared.try_lock().ok_or(Error::Busy)?;
        storage
            .as_ref()
            .ok_or(Error::State)?
            .station_antenna_request(firmware, &self.environment)
    }
    /// Historical original-owner metadata, including an absent signed N21C
    /// asset. No source recheck, inquiry or qualification attempt is made.
    pub(crate) fn rtl8821ae_coexistence_request(
        &self,
    ) -> Result<Option<super::rtl8821ae::coex_program::Request>, Error> {
        let storage = self.prepared.try_lock().ok_or(Error::Busy)?;
        Ok(storage
            .as_ref()
            .ok_or(Error::State)?
            .rtl8821ae_coex_request())
    }
    pub(crate) fn thermal_tracking_request(
        &self,
        firmware: super::firmware_transport::Identity,
    ) -> Result<super::ThermalTrackingRequest, Error> {
        let storage = self.prepared.try_lock().ok_or(Error::Busy)?;
        storage
            .as_ref()
            .ok_or(Error::State)?
            .station_tracking_request(firmware, &self.environment)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn factory_for_test(&self) -> &Factory {
        &self.factory
    }
    /// `rtl88e_dm_watchdog` RA step: refresh the firmware rate mask from
    /// the smoothed RX PWDB. A failed H2C aborts the station (the next
    /// service pass reports it like every other terminal hardware error).
    pub(super) async fn rate_adaptive(&self) {
        let mut storage = self.prepared.lock().await;
        let Some(owner) = storage.as_mut() else {
            return;
        };
        if self.admission.closed.load(Ordering::Acquire) {
            return;
        }
        let _ = owner.refresh_station_rate_mask(&self.environment).await;
    }
    /// Bind the running owner to its vector on first service, then run one
    /// Linux `_rtl_pci_interrupt` recognition pass per wake. A failed bind
    /// withdraws the vector and leaves the masks clear (polling fallback).
    fn service_interrupts(&self, owner: &mut Prepared<I, M>) -> Result<(), Error> {
        if !owner.interrupts_enabled()
            && owner.phase() == Phase::Running
            && self.environment.interrupt().is_some()
        {
            if owner.enable_interrupts().is_err() {
                // A readback/authority failure is terminal for the owner.
                self.environment.deliver(false);
                return Err(Error::State);
            }
            if !self.environment.deliver(true) {
                owner.disable_interrupts().map_err(|_| Error::State)?;
            }
        }
        if owner.interrupts_enabled() {
            owner.recognize_interrupts().map_err(|_| Error::State)?;
        }
        Ok(())
    }
    /// Mask the chip before releasing the vector (Linux `rtl_pci_stop`
    /// disable_interrupt, then `rtl_pci_deinit` free_irq/pci_disable_msi).
    fn withdraw_interrupts(&self, owner: &mut Prepared<I, M>) {
        if owner.interrupts_enabled() {
            let _ = owner.disable_interrupts();
        }
        if self.environment.interrupt().is_some() {
            self.environment.deliver(false);
        }
    }
    pub(super) fn drain(&self) -> bool {
        // Every owner/state guard has dropped before stack dispatch; ARP/ND
        // can synchronously re-enter this device's enqueue callback.
        let frames = self.progress();
        let progressed = !frames.is_empty();
        for frame in frames {
            if self.admission.closed.load(Ordering::Acquire) || !frame.publication.current() {
                break;
            }
            // The retained owner proves the current controlled port; only an
            // owned epoch/source/PCI token survives into the unlocked callback.
            let allowed = {
                let Some(storage) = self.prepared.try_lock() else {
                    break;
                };
                storage.as_ref().is_some_and(|owner| {
                    owner.station_receive_open() && frame.publication.current()
                })
            };
            if !allowed {
                break;
            }
            let Some(_lease) = self.lifecycle.lease(&self.admission, frame.generation) else {
                break;
            };
            let mut bytes = frame.bytes;
            let result = self.environment.domain().and_then(|domain| {
                frame.publication.invoke(&domain, || {
                    if !self.admission.closed.load(Ordering::Acquire) {
                        crate::platform::net::iface::on_rx_frame_from(&self.name, &mut bytes);
                    }
                    Ok(())
                })
            });
            if result.is_err() {
                self.abort_generation(frame.generation);
                break;
            }
        }
        progressed
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn fallback_for_test(&self) -> Option<bool> {
        self.prepared
            .try_lock()
            .map(|storage| storage.as_ref().is_some_and(|o| o.station_fallback()))
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn pending_for_test(&self) -> Option<bool> {
        self.state.try_lock().map(|state| state.pending.is_some())
    }
    fn attach_route(self: &Arc<Self>) -> Result<u64, Error> {
        if self.removed.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        let cookie = ROUTES.lock().insert(self.clone())?;
        if self
            .route
            .compare_exchange(0, cookie, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            ROUTES.lock().remove(cookie, Arc::as_ptr(self) as *const ());
            return Err(Error::State);
        }
        Ok(cookie)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn attach_stack_for_test(self: &Arc<Self>) -> Result<(), Error> {
        let cookie = self.attach_route()?;
        crate::platform::net::iface::register_with_context(
            &self.name,
            self.factory.mac,
            cookie,
            send,
        );
        crate::platform::net::iface::install_rx_drain(drain);
        self.published.store(true, Ordering::Release);
        Ok(())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn withdraw_stack_for_test(self: &Arc<Self>) {
        self.request_abort();
        self.withdraw();
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn admit_for_test(&self) {
        self.published.store(true, Ordering::Release);
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn fail_for_test(&self) {
        self.request_abort();
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn generation_for_test(&self) -> u64 {
        self.lifecycle.generation()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn environment_for_test(&self) -> &E {
        &self.environment
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn channel_for_test(&self) -> u8 {
        self.lifecycle.channel.load(Ordering::Acquire)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn power_flags_for_test(&self) -> (bool, bool, bool) {
        (
            self.lifecycle.suspended.load(Ordering::Acquire),
            self.lifecycle.inactive.load(Ordering::Acquire),
            self.lifecycle.sleep_complete.load(Ordering::Acquire),
        )
    }
}
fn admitted(bytes: &[u8], own: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[6..12] == own
        && bytes[..6] != [0; 6]
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && !matches!(&bytes[12..14], [0x88, 0x8e] | [0x80, 0xf3] | [0x81, 0x37])
}
fn offloads(meta: crate::platform::net::TxMeta) -> bool {
    meta.csum_l4.is_none() && meta.tso_mss.is_none() && meta.vlan_tag.is_none()
}
fn error(error: Error) -> WirelessError {
    match error {
        Error::Busy | Error::State => WirelessError::Busy,
        Error::Profile | Error::Management(_) => WirelessError::InvalidArgs,
        Error::Timeout => WirelessError::Timeout,
        Error::Entropy => WirelessError::NotSupported,
        _ => WirelessError::HardwareError,
    }
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Interface
    for Device<I, M, E>
{
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.factory.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        !self.admission.closed.load(Ordering::Acquire) && self.up.load(Ordering::Acquire)
    }
    fn rx_ring(
        &self,
    ) -> &IrqSafeSpinLock<Option<crate::platform::ipc::Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(
        &self,
    ) -> &IrqSafeSpinLock<Option<crate::platform::ipc::Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> WirelessNetIface
    for Device<I, M, E>
{
    fn rts_threshold(&self) -> Option<u32> {
        (!self.removed.load(Ordering::Acquire)).then(|| self.rts_threshold.load(Ordering::Acquire))
    }
    fn set_rts_threshold(&self, threshold: u32) -> Result<(), i32> {
        if threshold != u32::MAX && threshold > 2347 {
            return Err(-22); // EINVAL, cfg80211 maximum MPDU threshold.
        }
        if self.removed.load(Ordering::Acquire) {
            return Err(-19); // ENODEV.
        }
        // Same owner -> publication order as ordinary TX. No await or
        // interrupt-disabling lock surrounds the regular owner lock.
        let storage = self.prepared.try_lock().ok_or(-16)?; // EBUSY.
        let owner = storage.as_ref().ok_or(-16)?;
        owner
            .admit_station_rts_threshold(threshold != u32::MAX, &self.environment)
            .map_err(|_| -95)?; // EOPNOTSUPP: no current exact NERT program.
        let _publication = self.admission.publication.lock();
        if self.removed.load(Ordering::Acquire) {
            return Err(-19);
        }
        self.rts_threshold.store(threshold, Ordering::Release);
        Ok(())
    }
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }
    fn supports_scan_dwell(&self) -> bool {
        true
    }
    /// RTL8821AE `base.c::_rtl_init_mac80211` WoWLAN capability
    /// (`rtl8821ae::wow::support`); the system suspend/resume owner is
    /// `system_sleep.rs` (WoWLAN `rtl8821ae_card_disable` branch).
    fn wowlan_support(&self) -> Option<narf_wireless::WowlanSupport> {
        self.lifecycle
            .wowlan_capable
            .load(Ordering::Acquire)
            .then(super::rtl8821ae::wow::support)
    }
    fn set_wowlan(&self, config: Option<narf_wireless::WowlanConfig>) -> Result<(), i32> {
        if !self.lifecycle.wowlan_capable.load(Ordering::Acquire) {
            return Err(narf_wireless::EOPNOTSUPP);
        }
        if let Some(config) = &config {
            super::rtl8821ae::wow::validate(config).map_err(|_| -22)?; // EINVAL
        }
        *self.lifecycle.wowlan.lock() = config;
        Ok(())
    }
    fn wowlan_config(&self) -> Option<narf_wireless::WowlanConfig> {
        self.lifecycle.wowlan.lock().clone()
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        if self.admission.closed.load(Ordering::Acquire) {
            return None;
        }
        let bytes = self.bssid.load(Ordering::Acquire).to_le_bytes();
        (bytes[7] != 0).then(|| bytes[..6].try_into().unwrap())
    }
    fn cipher_suites(&self) -> &'static [u32] {
        &[0x000fac04]
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.scan_ies(bssid)
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        use narf_wireless::iface::*;
        // One entry per band with an admitted channel (the RTL8821AE
        // profile's 5 GHz `NAPC` permissions add the 5000 MHz band).
        let bands = {
            let (low, high): (Vec<u32>, Vec<u32>) = self
                .available_channels()
                .into_iter()
                .partition(|&channel| channel < 36);
            let mut bands = vec![WirelessBand {
                freq_mhz: 2400,
                channels: low,
            }];
            if !high.is_empty() {
                bands.push(WirelessBand {
                    freq_mhz: 5000,
                    channels: high,
                });
            }
            bands
        };
        // VHT is a 5 GHz sband capability only (`_rtl_init_mac80211`).
        let vht_supported = bands.len() > 1
            && self.rtl8821ae_caps.load(Ordering::Acquire) & super::rtl8821ae::vht::HOST_VHT_5G
                != 0;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.factory.mac,
            bands,
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: self.ht.load(Ordering::Acquire)
                    || self.rtl8821ae_host_ht()
                    || self.rtl8192ee_host_ht()
                    || self.rtl8192ce_host_ht()
                    || self.rtl8192de_host_ht()
                    || self.rtl8723be_host_ht(),
                vht_supported,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    fn phy_capabilities(&self, band: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        let band_listed = band == 2400
            || band == 5000
                && self
                    .available_channels()
                    .iter()
                    .any(|&channel| channel >= 36);
        // RTL8821AE: per-band HT/VHT from the envelope's admitted points
        // (`_rtl_init_mac80211`: VHT only on the 5 GHz sband).
        if band_listed && self.rtl8821ae_host_ht() {
            return super::rtl8821ae::vht::host_phy(
                self.rtl8821ae_caps.load(Ordering::Acquire),
                band,
            );
        }
        // RTL8192EE: 2.4 GHz HT from the `N92E` envelope's admitted points.
        if band_listed && self.rtl8192ee_host_ht() {
            return super::rtl8192ee::ht::host_phy(
                self.rtl8192ee_caps.load(Ordering::Acquire),
                band,
            );
        }
        // RTL8192CE / 8188CE: 2.4 GHz HT from the `N92C` envelope's
        // admitted points at the board's RF type.
        if band_listed && self.rtl8192ce_host_ht() {
            return super::rtl8192ce::ht::host_phy(
                self.rtl8192ce_caps.load(Ordering::Acquire),
                band,
            );
        }
        // RTL8192DE: HT from the `N92D` envelope's admitted points on
        // 2.4 GHz and 5 GHz, at the board's RF type.
        if band_listed && self.rtl8192de_host_ht() {
            return super::rtl8192de::ht::host_phy(
                self.rtl8192de_caps.load(Ordering::Acquire),
                band,
            );
        }
        // RTL8723BE: 2.4 GHz HT from the `NAPC` envelope's admitted points.
        if band_listed && self.rtl8723be_host_ht() {
            return super::rtl8723be::ht::host_phy(
                self.rtl8723be_caps.load(Ordering::Acquire),
                band,
            );
        }
        if band == 2400 && band_listed && self.ae_ht20.load(Ordering::Acquire) {
            return Some(narf_wireless::iface::PhyCapabilities {
                ht: super::rtl8723ae::ht::capability().capability_body(),
                vht: None,
            });
        }
        (band_listed && self.ht.load(Ordering::Acquire)).then(|| {
            narf_wireless::iface::PhyCapabilities {
                ht: if self.ht40.load(Ordering::Acquire) {
                    super::ht::wide_capability()
                } else {
                    narf_wireless::association::phy::LocalHt::siso20(true, true)
                        .with_rx_amsdu_7935(true)
                }
                .capability_body(),
                vht: None,
            }
        })
    }
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        self.scan_channels(request).await
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        if !matches!(
            &request.security,
            SecurityConfig::Open | SecurityConfig::Wpa2 { .. }
        ) {
            return Err(WirelessError::NotSupported);
        }
        self.select_join_channel(&request).await?;
        let _control = self.lifecycle.control.lock().await;
        if self.admission.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if request.channel != u32::from(self.lifecycle.channel.load(Ordering::Acquire)) {
            return Err(WirelessError::Busy);
        }
        let (mode, pmk) = match &request.security {
            SecurityConfig::Open => (narf_wireless::association::SecurityMode::Open, None),
            SecurityConfig::Wpa2 { psk } => (
                narf_wireless::association::SecurityMode::Wpa2Psk,
                Some(Zeroizing::new(*psk)),
            ),
            _ => return Err(WirelessError::NotSupported),
        };
        let mut storage = self.prepared.lock().await;
        let owner = storage.as_mut().ok_or(WirelessError::Busy)?;
        self.ready(owner).await.map_err(error)?;
        if owner.station_phase() != station::Phase::Passive {
            return Err(WirelessError::Busy);
        }
        self.state.lock().await.clear();
        let mut attempt = Attempt {
            device: self,
            owner: Some(owner.station_cancellation()),
            generation: self.lifecycle.generation(),
            armed: true,
        };
        let result = async {
            self.observe_join_target(owner, &request).await?;
            owner
                .connect_station(
                    request.bssid,
                    &request.ssid,
                    mode,
                    pmk,
                    &request.ie,
                    &self.environment,
                )
                .await
        }
        .await;
        attempt.armed = false;
        if self.admission.closed.load(Ordering::Acquire) {
            owner.abort_station();
            return Err(WirelessError::HardwareError);
        }
        if result.is_err() && owner.station_phase() == station::Phase::Failed {
            self.close();
        }
        if result.is_ok() {
            if let Err(e) = owner.station_publication(&self.environment, || {
                self.link(owner.station_peer());
                Ok(())
            }) {
                owner.abort_station();
                self.close();
                return Err(error(e));
            }
        } else {
            self.link(owner.station_peer());
        }
        result.map_err(error)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.close();
        let mut attempt = Attempt {
            device: self,
            owner: None,
            generation: self.lifecycle.generation(),
            armed: true,
        };
        let _control = self.lifecycle.control.lock().await;
        attempt.generation = self.lifecycle.generation();
        let mut storage = self.prepared.lock().await;
        self.state.lock().await.clear();
        self.close();
        let owner = storage.as_mut().ok_or(WirelessError::Busy)?;
        if let Err(reason) = self.be_restore_for_lifecycle(owner).await {
            owner.abort_station();
            return Err(error(reason));
        }
        let result = owner.disconnect_station().await.map_err(error);
        // Safe rejoin: a completed disassociation leaves a Passive station
        // on the same live owner. Reopen admission under the owner and
        // publication locks; the advanced receive epoch fences every stale
        // publisher and the next station gets a new RX Narf-Ring.
        if result.is_ok()
            && owner.station_phase() == station::Phase::Passive
            && !self.removed.load(Ordering::Acquire)
        {
            if let Err(reason) = self.lifecycle.drain_publications().await {
                owner.abort_station();
                self.request_abort();
                attempt.armed = false;
                return Err(error(reason));
            }
            let _publication = self.admission.publication.lock();
            self.admission.abort.store(false, Ordering::Release);
            self.admission.closed.store(false, Ordering::Release);
            self.ae_ht20.store(owner.rtl8723ae_ht(), Ordering::Release);
            self.coex_channel.store(
                if owner.station_full_coex() {
                    // Missing power state must never widen this fixed profile.
                    owner
                        .station_grant()
                        .map_or(u8::MAX, |grant| grant.channel())
                } else {
                    0
                },
                Ordering::Release,
            );
            self.ht
                .store(owner.station_ht_capability().is_some(), Ordering::Release);
            self.ht40
                .store(owner.station_ht40_supported(), Ordering::Release);
            self.rtl8821ae_caps.store(
                owner.station_rtl8821ae_host_caps(&self.environment),
                Ordering::Release,
            );
            self.rtl8192ee_caps.store(
                owner.station_rtl8192ee_host_caps(&self.environment),
                Ordering::Release,
            );
            self.rtl8192ce_caps.store(
                owner.station_rtl8192ce_host_caps(&self.environment),
                Ordering::Release,
            );
            self.rtl8192de_caps.store(
                owner.station_rtl8192de_host_caps(&self.environment),
                Ordering::Release,
            );
            self.rtl8723be_caps.store(
                owner.station_rtl8723be_host_caps(&self.environment),
                Ordering::Release,
            );
        }
        attempt.armed = false;
        result
    }
    async fn set_config(&self, config: WirelessConfig) -> Result<(), WirelessError> {
        let channel = u8::try_from(config.channel).map_err(|_| WirelessError::NotSupported)?;
        if config.tx_power_dbm.is_some() || !super::rtl8821ae::envelope::station_channel(channel) {
            return Err(WirelessError::NotSupported);
        }
        let fixed = self.coex_channel.load(Ordering::Acquire);
        if fixed != 0 && channel != fixed {
            return Err(WirelessError::NotSupported);
        }
        if channel == self.lifecycle.channel.load(Ordering::Acquire)
            && !self.admission.closed.load(Ordering::Acquire)
        {
            return Ok(());
        }
        self.environment
            .change_channel(channel)
            .ok_or(WirelessError::NotSupported)?
            .await
            .map_err(error)
    }
}
fn scan_dwell(request: &ScanRequest) -> Result<u64, WirelessError> {
    if request.random_mac.is_some()
        || request.colocated_6ghz
        || !request.extra_ies.is_empty()
        || request.ssids.len() > 32
        || request.active && request.ssids.len() > super::probe_scan::MAX_SSIDS
        || request.ssids.iter().any(|ssid| ssid.len() > 32)
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

#[cfg(any(test, feature = "kernel-test"))]
pub(super) mod publication_test {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Waker},
    };

    /// RAM-native fixture registration only. Run the unmodified ready/start
    /// path and read the public cached PHY metadata after initial N21C bind.
    pub(in crate::rtlwifi) async fn ready_8821_capabilities<
        I: Port<Buffer = M> + 'static,
        M: Memory + 'static,
        E: Environment + 'static,
    >(
        device: &Device<I, M, E>,
    ) -> Result<narf_wireless::iface::PhyCapabilities, &'static str> {
        device.published.store(true, Ordering::Release);
        {
            let mut storage = device.prepared.lock().await;
            let owner = storage.as_mut().ok_or("8821 ready fixture owner")?;
            device
                .ready(owner)
                .await
                .map_err(|_| "8821 actual Native ready")?;
        }
        if !device.get_wireless_info().hw_caps.ht_supported {
            return Err("8821 Native ready lost public HT metadata");
        }
        device
            .phy_capabilities(2400)
            .ok_or("8821 Native ready lacks public PHY metadata")
    }

    /// Pause the real scan after Scan(true), before scan_one obtains its
    /// control mutex and constructs its narrower per-channel guard.
    pub(in crate::rtlwifi) async fn cancel_8821_scan_waiting_for_control<
        I: Port<Buffer = M> + 'static,
        M: Memory + 'static,
        E: Environment + 'static,
    >(
        device: &Device<I, M, E>,
        request: ScanRequest,
    ) -> Result<(), &'static str> {
        let _control = device.lifecycle.control.lock().await;
        {
            let mut future = pin!(device.scan(request));
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return Err("8821 scan did not await its held control mutex");
            }
            let storage = device.prepared.try_lock().ok_or("8821 paused scan owner")?;
            if !storage
                .as_ref()
                .is_some_and(Prepared::station_8821_scanning)
            {
                return Err("8821 cancelled scan never completed actual Scan(true)");
            }
        }
        let storage = device
            .prepared
            .try_lock()
            .ok_or("8821 cancelled scan owner")?;
        if !device.admission.closed.load(Ordering::Acquire)
            || !storage
                .as_ref()
                .is_some_and(|owner| owner.station_phase() == station::Phase::Failed)
        {
            return Err("8821 scan cancellation left its exact station generation live");
        }
        Ok(())
    }

    pub(in crate::rtlwifi) fn copied_then_revoke<
        I: Port<Buffer = M> + 'static,
        M: Memory + 'static,
        E: Environment + 'static,
    >(
        device: &Device<I, M, E>,
        source: crate::platform::capabilities::Cap<
            crate::platform::firmware::FirmwareBlob,
            crate::platform::capabilities::Read,
        >,
    ) -> Result<(), &'static str> {
        let frame = device
            .progress()
            .pop()
            .ok_or("EE fixture lacks real native copied RX")?;
        source.revoke();
        let mut invoked = false;
        let domain = device
            .environment
            .domain()
            .map_err(|_| "EE copied policy")?;
        let result = frame.publication.invoke(&domain, || {
            invoked = true;
            Ok(())
        });
        if invoked || matches!(result, Ok(Some(_))) {
            return Err("EE revoked source reached copied callback");
        }
        device.abort_generation(frame.generation);
        Ok(())
    }
    pub(in crate::rtlwifi) async fn old_copy_and_error_across_rebuild<
        I: Port<Buffer = M> + 'static,
        M: Memory + 'static,
        E: recovery::Rebuild<I, M> + 'static,
    >(
        device: &Arc<Device<I, M, E>>,
    ) -> Result<(), &'static str> {
        let old = device
            .progress()
            .pop()
            .ok_or("EE fixture lacks actual native copied RX")?;
        let lease = device
            .lifecycle
            .lease(&device.admission, old.generation)
            .ok_or("EE old callback could not enter publication")?;
        let attempt = Attempt {
            device: device.as_ref(),
            owner: None,
            generation: old.generation,
            armed: true,
        };
        device.request_abort();
        let mut pending = Box::pin(
            device
                .schedule(supervisor::Operation::Recover)
                .map_err(|_| "EE rebuild not scheduled")?,
        );
        if pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return Err("EE rebuild passed an active old publication lease");
        }
        if !device.admission.closed.load(Ordering::Acquire) {
            return Err("EE paused old publication reopened logical carrier");
        }
        drop(lease);
        pending
            .await
            .map_err(|_| "EE rebuild after publication retirement failed")?;
        drop(attempt); // A late error/drop belongs exclusively to the old generation.
        if device.admission.closed.load(Ordering::Acquire)
            || device
                .lifecycle
                .lease(&device.admission, old.generation)
                .is_some()
        {
            return Err("EE old copied RX or late error reached replacement generation");
        }
        Ok(())
    }

    pub(in crate::rtlwifi) async fn paused_publisher_then_close<
        I: Port<Buffer = M> + 'static,
        M: Memory + 'static,
        E: Environment + 'static,
    >(
        device: &Device<I, M, E>,
    ) -> Result<(), &'static str> {
        let publication = device.admission.publication.lock();
        let peer = device
            .connected_bssid()
            .ok_or("EE paused publisher lacks carrier")?;
        let mut close = pin!(core::future::poll_fn(|cx| {
            if let Some(publication) = device.admission.publication.try_lock() {
                device.commit_close(publication);
                core::task::Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        }));
        if close
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return Err("EE close bypassed paused publisher gate");
        }
        // Complete the already-entered peer decision and all metadata writes
        // before permitting the exact production close commit to run.
        device.update_link(Some(peer));
        drop(publication);
        close.await;
        device.link(Some(peer));
        if device.link_up()
            || device.connected_bssid().is_some()
            || crate::platform::net::iface::lookup(device.name())
                .is_none_or(|iface| !iface.link_up || iface.carrier)
        {
            return Err("EE paused publisher survived completed close");
        }
        Ok(())
    }

    pub(in crate::rtlwifi) async fn disconnect_after_old_publication<
        I: Port<Buffer = M> + 'static,
        M: Memory + 'static,
        E: Environment + 'static,
    >(
        device: &Device<I, M, E>,
        peer: [u8; 6],
    ) -> Result<(), &'static str> {
        let storage = device.prepared.try_lock().ok_or("EE fixture owner busy")?;
        if storage.as_ref().and_then(Prepared::station_peer) != Some(peer) {
            return Err("EE fixture lacks previous native station");
        }
        let mut disconnect = pin!(device.disassociate());
        if disconnect
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
            || device.link_up()
            || device.connected_bssid().is_some()
        {
            return Err("EE disconnect failed to close before waiting for native owner");
        }
        // Replay precisely progress()'s already-entered stale publication.
        device.link(storage.as_ref().and_then(Prepared::station_peer));
        if device.link_up()
            || device.connected_bssid().is_some()
            || crate::platform::net::iface::lookup(device.name())
                .is_none_or(|iface| iface.carrier || !iface.link_up)
        {
            return Err("EE stale native publisher reopened closed station");
        }
        drop(storage);
        disconnect
            .await
            .map_err(|_| "EE interleaved native disconnect failed")
    }
}

pub(super) struct NativeEnvironment {
    admission: Arc<station::Admission>,
    firmware: IrqSafeSpinLock<Arc<super::firmware_transport::Owner<super::firmware_native::PciIo>>>,
    device: IrqSafeSpinLock<Weak<Native>>,
    /// 0 active, 1 verified card-disabled, 2 unacknowledged transition,
    /// 3 RTL8821AE WoWLAN firmware armed (`rtl8821ae_card_disable`'s
    /// WoWLAN branch; MAC powered, host DMA retired).
    power_state: AtomicU8,
    /// H2C box state of the armed WoWLAN firmware (state 3 only).
    wow_mailbox: IrqSafeSpinLock<Option<super::rtl8821ae::h2c::Mailbox>>,
}
/// Live station work consumes only the current installation. The explicit
/// native preparation boundary owns signed-policy bootstrap.
pub(super) fn installed_domain(
    snapshot: Option<Arc<narf_wireless::reg::RegulatoryDomain>>,
) -> Result<narf_wireless::reg::RegulatoryDomain, Error> {
    snapshot
        .map(|domain| domain.as_ref().clone())
        .ok_or(Error::Profile)
}
impl NativeEnvironment {
    pub(super) fn new(
        firmware: Arc<super::firmware_transport::Owner<super::firmware_native::PciIo>>,
    ) -> Self {
        Self {
            firmware: IrqSafeSpinLock::new(firmware),
            admission: Arc::new(station::Admission::new()),
            device: IrqSafeSpinLock::new(Weak::new()),
            power_state: AtomicU8::new(0),
            wow_mailbox: IrqSafeSpinLock::new(None),
        }
    }
    pub(super) fn firmware(
        &self,
    ) -> Arc<super::firmware_transport::Owner<super::firmware_native::PciIo>> {
        self.firmware.lock().clone()
    }
}
impl Environment for NativeEnvironment {
    fn pcie_aspm(&self) -> bool {
        PCIE_ASPM.load(Ordering::Acquire)
    }
    async fn prepare_bus_power(&self) -> Result<(), Error> {
        let device = self.firmware().device_id();
        if matches!(
            device,
            super::regs::RTL_DEV_8821AE | super::regs::RTL_DEV_8192EE | super::regs::RTL_DEV_8723AE
        ) || super::rtl8192ce::is_8192ce(device)
        {
            // Only 8188EE/8723BE/8192DE have a source-matched native
            // internal preparation producer. AE remains parked and other
            // admitted profiles retain their disabled endpoint policy.
            return Ok(());
        }
        self.firmware()
            .native()
            .prepare_aspm(PCIE_ASPM.load(Ordering::Acquire))
            .await
            .map_err(super::prepare::Error::Access)
            .map_err(Error::from)
    }

    fn allow_channel(&self, factory: &Factory, channel: u8) -> Result<(), Error> {
        if self.firmware().device_id() == super::regs::RTL_DEV_8723AE {
            let device = self.device.lock().upgrade().ok_or(Error::State)?;
            let storage = device.prepared.try_lock().ok_or(Error::Busy)?;
            let owner = storage.as_ref().ok_or(Error::State)?;
            return owner
                .rtl8723ae_ready(factory, channel, &self.domain()?)
                .map_err(Error::Radio);
        }

        if self.firmware().device_id() == super::regs::RTL_DEV_8821AE {
            // Retuning rebuilds through the 8821AE card-disable/enable flow
            // (`rebuild_native`); admission is the `NAPC` 20 MHz permission
            // (2.4 GHz or 5 GHz) the fresh owner's `prepare_rtl8821ae`
            // re-derives.
            return super::rtl8821ae::envelope::Calibration::load_registered(factory)
                .map_err(|_| Error::Profile)?
                .permission(&self.domain()?, channel)
                .map(|_| ())
                .map_err(|_| Error::Profile);
        }
        if self.firmware().device_id() == super::regs::RTL_DEV_8192EE {
            // Retuning rebuilds through the 8192EE card-disable/enable flow
            // (`rebuild_native`); admission is the `N92E` 20 MHz permission
            // on 2.4 GHz channels 1-11 that `prepare_rtl8192ee` re-derives.
            return super::rtl8192ee::envelope::Calibration::load_registered(factory)
                .map_err(|_| Error::Profile)?
                .permission(&self.domain()?, channel)
                .map(|_| ())
                .map_err(|_| Error::Profile);
        }
        if self.firmware().device_id() == super::regs::RTL_DEV_8723BE {
            // Retuning rebuilds through `_rtl8723be_poweroff_adapter` and
            // `_rtl8723be_init_mac`'s enable (`rebuild_native`); admission
            // is the `NAPC` 20 MHz permission on 2.4 GHz channels 1-11 that
            // `prepare_rtl8723be` re-derives.
            if !(1..=11).contains(&channel) {
                return Err(Error::Profile);
            }
            return super::rtl8723be::envelope::Calibration::load_registered(factory)
                .map_err(|_| Error::Profile)?
                .permission(&self.domain()?, channel)
                .map(|_| ())
                .map_err(|_| Error::Profile);
        }
        if self.firmware().device_id() == super::regs::RTL_DEV_8192DE {
            // Retuning rebuilds through `rtl92de_card_disable` and the
            // `_rtl92de_init_mac` power prefix (`rebuild_native`);
            // admission is the `N92D` 20 MHz permission on the requested
            // channel under the current domain, gated by the
            // `native_channel` gate for the function's mode/bandset
            // (`super::rtl8192de::allow_channel`) — the same admission
            // `prepare_rtl8192de` applies, so the 5 GHz plan admitted
            // there is also admitted here.
            let mode = super::rtl8192de::mode_from_prom(
                super::rtl8192de::Interface::Pci,
                &factory.logical,
            )
            .ok_or(Error::Profile)?;
            let function = self.firmware().native().function().ok_or(Error::Profile)?;
            return super::rtl8192de::allow_channel(
                factory,
                &self.domain()?,
                mode,
                function,
                channel,
            )
            .map_err(|_| Error::Profile);
        }
        let device = self.firmware().device_id();
        if super::rtl8192ce::is_8192ce(device) {
            // Retuning rebuilds through `rtl92ce_card_disable` and a fresh
            // `rtl92ce_hw_init` (`rebuild_native`); admission is the `N92C`
            // 20 MHz permission on 2.4 GHz channels 1-11 that
            // `prepare_rtl8192ce` re-derives for the probed device and the
            // measured RF type.
            if !(1..=11).contains(&channel) {
                return Err(Error::Profile);
            }
            let rf = self
                .firmware()
                .rtl8192ce_version()
                .map_err(|_| Error::Profile)?
                .rf_type();
            return super::rtl8192ce::envelope::Calibration::load_registered(factory, device, rf)
                .map_err(|_| Error::Profile)?
                .permission(&self.domain()?, channel)
                .map(|_| ())
                .map_err(|_| Error::Profile);
        }
        let calibration = super::channel_power::Calibration::load_registered(factory)
            .map_err(|_| Error::Profile)?;
        calibration
            .permission(&self.domain()?, channel)
            .map(|_| ())
            .map_err(|_| Error::Profile)
    }
    fn change_channel(
        &self,
        channel: u8,
    ) -> Option<core::pin::Pin<Box<dyn core::future::Future<Output = Result<(), Error>> + Send>>>
    {
        let device = self.device.lock().upgrade()?;
        Some(
            match device.schedule(supervisor::Operation::Retune(channel)) {
                Ok(waiter) => Box::pin(waiter),
                Err(reason) => Box::pin(async move { Err(reason) }),
            },
        )
    }
    fn ht20(
        &self,
        base: Arc<super::channel_power::Calibration>,
    ) -> Result<Option<Arc<super::ht::Grant>>, Error> {
        let channel = self
            .device
            .lock()
            .upgrade()
            .ok_or(Error::State)?
            .lifecycle
            .channel
            .load(Ordering::Acquire);
        super::ht::Grant::registered(
            base,
            self.firmware().identity().ok_or(Error::State)?,
            channel,
        )
        .map_err(Error::Radio)
    }
    fn rts_threshold(&self) -> Option<u16> {
        self.device
            .lock()
            .upgrade()
            .and_then(|d| d.configured_rts_threshold())
    }
    fn protection(
        &self,
        base: Arc<super::channel_power::Calibration>,
        ht: Option<Arc<super::ht::Grant>>,
    ) -> Result<Option<Arc<super::protection::Grant>>, Error> {
        let channel = self
            .device
            .lock()
            .upgrade()
            .ok_or(Error::State)?
            .lifecycle
            .channel
            .load(Ordering::Acquire);
        super::protection::Grant::registered(
            base,
            self.firmware().identity().ok_or(Error::State)?,
            channel,
            ht,
        )
        .map_err(Error::Radio)
    }
    fn antenna(
        &self,
        base: Arc<super::channel_power::Calibration>,
        ht: Option<Arc<super::ht::Grant>>,
        protection: Option<Arc<super::protection::Grant>>,
        tracking: Option<Arc<super::tracking::Grant>>,
    ) -> Result<Option<Arc<super::antenna::Grant>>, Error> {
        let channel = self
            .device
            .lock()
            .upgrade()
            .ok_or(Error::State)?
            .lifecycle
            .channel
            .load(Ordering::Acquire);
        super::antenna::Grant::registered(super::antenna::Program {
            base,
            ht,
            protection,
            tracking,
            channel,
            firmware: self.firmware().identity().ok_or(Error::State)?,
        })
        .map_err(Error::Radio)
    }
    fn rtl8723be_tracking(
        &self,
        base: Arc<super::rtl8723be::envelope::Calibration>,
        facts: super::rtl8723be::tracking::Facts,
    ) -> Result<Option<Arc<super::rtl8723be::tracking::Grant>>, Error> {
        let owner = self.firmware();
        if owner.device_id() != super::regs::RTL_DEV_8723BE {
            return Err(Error::Profile);
        }
        let identity = owner.identity().ok_or(Error::State)?;
        super::rtl8723be::tracking::Grant::registered(base, identity, facts).map_err(Error::Radio)
    }
    fn tracking(
        &self,
        base: Arc<super::channel_power::Calibration>,
        ht: Option<Arc<super::ht::Grant>>,
        protection: Option<Arc<super::protection::Grant>>,
    ) -> Result<Option<Arc<super::tracking::Grant>>, Error> {
        let channel = self
            .device
            .lock()
            .upgrade()
            .ok_or(Error::State)?
            .lifecycle
            .channel
            .load(Ordering::Acquire);
        super::tracking::Grant::registered(
            base,
            self.firmware().identity().ok_or(Error::State)?,
            channel,
            ht,
            protection,
        )
        .map_err(Error::Radio)
    }
    fn ht40(
        &self,
        base: Arc<super::channel_power::Calibration>,
    ) -> Result<Vec<Arc<super::ht::Grant>>, Error> {
        let channel = self
            .device
            .lock()
            .upgrade()
            .ok_or(Error::State)?
            .lifecycle
            .channel
            .load(Ordering::Acquire);
        super::ht::Grant::registered_wide(
            base,
            self.firmware().identity().ok_or(Error::State)?,
            channel,
        )
        .map_err(Error::Radio)
    }
    fn fallback(
        &self,
        base: Arc<super::channel_power::Calibration>,
    ) -> Result<Option<Arc<super::fallback::Grant>>, Error> {
        let channel = self
            .device
            .lock()
            .upgrade()
            .ok_or(Error::State)?
            .lifecycle
            .channel
            .load(Ordering::Acquire);
        super::fallback::Grant::registered(
            base,
            self.firmware().identity().ok_or(Error::State)?,
            channel,
        )
        .map_err(Error::Radio)
    }
    fn admission(&self) -> Option<&Arc<station::Admission>> {
        Some(&self.admission)
    }
    fn now_ms(&self) -> u64 {
        crate::platform::time::wall::monotonic_ns() / 1_000_000
    }
    fn fresh_nonce(&self) -> Option<[u8; 32]> {
        let mut bytes = [0; 32];
        narf_crypto::try_fill_random_bytes(&mut bytes)
            .ok()
            .map(|()| bytes)
    }
    fn domain(&self) -> Result<narf_wireless::reg::RegulatoryDomain, Error> {
        installed_domain(crate::platform::regdb::snapshot())
    }
    async fn pause(&self) {
        crate::platform::time::sleep_cycles(crate::platform::time::wall::ns_to_cycles(1_000_000))
            .await;
    }
    fn preparation_failed(&self) -> bool {
        self.firmware().status().stage == super::firmware_transport::Stage::Failed
    }
    fn interrupt(&self) -> Option<Arc<super::irq::Signal>> {
        self.firmware().native().interrupt()
    }
    fn deliver(&self, enabled: bool) -> bool {
        self.firmware().native().deliver(enabled)
    }
    fn recovery(
        &self,
    ) -> Option<core::pin::Pin<Box<dyn core::future::Future<Output = Result<(), Error>> + Send>>>
    {
        let device = self.device.lock().upgrade()?;
        match device.schedule(supervisor::Operation::Recover) {
            Ok(waiter) => Some(Box::pin(waiter)),
            Err(error) => Some(Box::pin(async move { Err(error) })),
        }
    }
}
pub(super) type Native = Device<
    super::firmware_transport::PacketIo<super::firmware_native::PciIo>,
    super::prepare_native::Coherent,
    NativeEnvironment,
>;
trait Endpoint: Send + Sync {
    fn send(&self, bytes: &[u8], meta: crate::platform::net::TxMeta) -> Result<(), ()>;
    fn drain(&self) -> bool;
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Endpoint
    for Device<I, M, E>
{
    fn send(&self, bytes: &[u8], meta: crate::platform::net::TxMeta) -> Result<(), ()> {
        self.enqueue(bytes, meta)
    }
    fn drain(&self) -> bool {
        Device::drain(self)
    }
}
static ROUTES: IrqSafeSpinLock<endpoint_routes::Routes> =
    IrqSafeSpinLock::new(endpoint_routes::Routes::new());
pub(super) fn send(
    cookie: u64,
    bytes: &[u8],
    meta: crate::platform::net::TxMeta,
) -> Result<(), ()> {
    let owner = ROUTES.lock().get(cookie).ok_or(())?;
    owner.send(bytes, meta)
}
fn drain() -> bool {
    let owners = ROUTES.lock().snapshot();
    let mut received = false;
    for owner in owners {
        received |= owner.drain();
    }
    received
}
/// Publish the native station: the netdev and wiphy (the kernel's
/// registries built in, the netif bridge and `WIFI` host in `rtl.ko`),
/// then MSI, the watchdog and the station worker, which both builds share.
pub(super) fn publish(device: Arc<Native>) -> Result<(), Error> {
    #[cfg(feature = "builtin")]
    let authority = crate::platform::net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(Error::Profile)?;
    let cookie = device.attach_route()?;
    *device.environment.device.lock() = Arc::downgrade(&device);
    if device.environment.firmware().device_id() == super::regs::RTL_DEV_8821AE {
        device
            .lifecycle
            .wowlan_capable
            .store(true, Ordering::Release);
    }
    #[cfg(feature = "builtin")]
    let registered = crate::platform::net::registry()
        .register(&authority, Registered(device.clone()))
        .is_ok();
    #[cfg(feature = "module")]
    let registered = crate::module_netdev::attach(
        device.clone(),
        Box::new(move |bytes| send(cookie, bytes, crate::platform::net::TxMeta::default())),
    )
    .is_ok();
    if !registered {
        ROUTES
            .lock()
            .remove(cookie, Arc::as_ptr(&device) as *const ());
        device.route.store(0, Ordering::Release);
        return Err(Error::Profile);
    }
    #[cfg(feature = "builtin")]
    crate::platform::net::iface::register_with_context(
        &device.name,
        device.factory.mac,
        cookie,
        send,
    );
    device.link(None);
    device.published.store(true, Ordering::Release);
    #[cfg(feature = "builtin")]
    {
        crate::platform::net::iface::install_rx_drain(drain);
        narf_wireless::registry::register(device.clone());
        let pm = Arc::new(system_sleep::SystemPm {
            device: Arc::downgrade(&device),
            config: IrqSafeSpinLock::new(None),
            wake: IrqSafeSpinLock::new(None),
        });
        narf_power::system_pm::register_async_system_pm(&device.name, pm.clone());
        narf_power::device_pm::register_device_pm_ops(&device.name, pm);
    }
    // Linux `rtl_pci_intr_mode_decide`: MSI first. Without a vector the
    // owner keeps every IMR clear and this worker polls at 1 ms.
    device.environment.firmware().native().arm_msi();
    // `rtl_watch_dog_timer` → `rtl_watchdog_wq_callback`, every
    // `RTL_WATCH_DOG_TIME`, until `rtl_pci_remove`.
    crate::watchdog_work::start(&device, WATCHDOG_MS);
    crate::platform::scheduler::spawn(async move {
        let mut retries = 0;
        let mut retry_at = 0;
        loop {
            core::future::poll_fn(|cx| {
                device.poll_transition(cx);
                core::task::Poll::Ready(())
            })
            .await;
            device.service_sleep_rollback();
            let working = device.work.try_lock().is_none_or(|slot| slot.is_some());
            if device.removed.load(Ordering::Acquire) && !working {
                break;
            }
            if !working
                && !device.removed.load(Ordering::Acquire)
                && !device.lifecycle.suspended.load(Ordering::Acquire)
                && !device.lifecycle.inactive.load(Ordering::Acquire)
            {
                if !device.admission.closed.load(Ordering::Acquire) {
                    retries = 0;
                } else if retries < 3
                    && device.environment.now_ms() >= retry_at
                    && device.schedule(supervisor::Operation::Recover).is_ok()
                {
                    retries += 1;
                    retry_at = device.environment.now_ms().saturating_add(1000);
                }
            }
            if !working
                && !INACTIVE_PS.load(Ordering::Acquire)
                && device.lifecycle.inactive.load(Ordering::Acquire)
                && !device.lifecycle.suspended.load(Ordering::Acquire)
                && !device.removed.load(Ordering::Acquire)
            {
                let _ = device.schedule(supervisor::Operation::Resume);
            }
            if !working
                && INACTIVE_PS.load(Ordering::Acquire)
                && !device.removed.load(Ordering::Acquire)
                && !device.admission.closed.load(Ordering::Acquire)
                && device
                    .environment
                    .now_ms()
                    .saturating_sub(device.lifecycle.activity_ms.load(Ordering::Acquire))
                    >= WATCHDOG_MS
                && device.prepared.try_lock().is_some_and(|owner| {
                    owner.as_ref().is_some_and(|owner| {
                        owner.chip() != super::prepare::Chip::Rtl8723ae
                            && owner.station_phase() == station::Phase::Passive
                    })
                })
            {
                let _ = device.schedule(supervisor::Operation::Idle);
            }
            // Snapshot before servicing so a vector raised mid-pass is seen.
            let signal = device.environment.interrupt();
            let seen = signal.as_ref().map(|s| s.count());
            // Owned pending frames remain parked across this async preflight.
            // Failure/cancellation closes the station before drain can emit.
            let _ = device.coex_flush_special().await;
            device.drain();
            // The periodic steps run from the watchdog work; only a
            // data-path LPS leave is served here, without waiting for it.
            device.lps_leave(FW_LPS.load(Ordering::Acquire)).await;
            match (signal, seen) {
                (Some(signal), Some(seen)) => {
                    // Station deadlines are millisecond timers; a slow
                    // housekeeping tick replaces 1 ms polling.
                    let tick = Box::pin(crate::platform::time::sleep_cycles(
                        crate::platform::time::wall::ns_to_cycles(HOUSEKEEPING_NS),
                    ));
                    signal.wait(seen, tick).await;
                }
                _ => {
                    crate::platform::time::sleep_cycles(crate::platform::time::wall::ns_to_cycles(
                        1_000_000,
                    ))
                    .await
                }
            }
        }
    });
    Ok(())
}
/// The device's `rtl_watchdog_wq_callback` work; `rtl_pci_remove` stops it.
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static>
    crate::watchdog_work::Watchdog for Device<I, M, E>
where
    Self: Send + Sync,
{
    fn watchdog_stopped(&self) -> bool {
        self.removed.load(Ordering::Acquire)
    }
    fn watchdog_step(
        self: Arc<Self>,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = ()> + Send>> {
        Box::pin(async move { self.watchdog().await })
    }
}
/// Housekeeping tick while a bound vector drives RX/TX service.
const HOUSEKEEPING_NS: u64 = 20_000_000;
#[cfg(feature = "builtin")]
struct Registered(Arc<Native>);
#[cfg(feature = "builtin")]
impl Interface for Registered {
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
    fn rx_ring(
        &self,
    ) -> &IrqSafeSpinLock<Option<crate::platform::ipc::Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(
        &self,
    ) -> &IrqSafeSpinLock<Option<crate::platform::ipc::Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}

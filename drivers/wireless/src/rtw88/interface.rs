// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-function RTL8821CE/RTL8822CE shells and retained owners for control and packet
//! progress. Synchronous stack drains never wait for another executor task.
use super::{
    firmware_lifecycle::Lifecycle,
    firmware_transport::Io,
    station::{self, Environment},
    station_control::Admission,
};
use alloc::{boxed::Box, collections::VecDeque, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessConfig, WirelessError,
    WirelessNetIface,
};
use zeroize::Zeroizing;
type Error = station::Error;
const EINVAL: i32 = 22;
/// main.c `RTW_WATCH_DOG_DELAY_TIME` (2s).
const LPS_PERIOD_MS: u64 = 2_000;
/// ps.h `RTW_LPS_THRESHOLD`.
const LPS_THRESHOLD: u32 = 50;
/// One bounded nondeep LPS residence per period (`lps_function` maximum).
const LPS_WINDOW_MS: u32 = 100;
/// main.c `rtw_watch_dog_work`: `ps_enabled && !ps_active`, where
/// `ps_active` is `tx_cnt > RTW_LPS_THRESHOLD || rx_cnt > RTW_LPS_THRESHOLD`.
fn lps_due(enabled: bool, tx: u32, rx: u32) -> bool {
    enabled && tx <= LPS_THRESHOLD && rx <= LPS_THRESHOLD
}
const EBUSY: i32 = 16;
const ENODEV: i32 = 19;
struct Rings {
    rx: narf_ipc::Producer<Frame, RX_RING_N>,
    tx: narf_ipc::Consumer<Frame, TX_RING_N>,
    pending: Option<Frame>,
    batch: VecDeque<Frame>,
}
impl Rings {
    fn clear(&mut self) {
        self.pending = None;
        self.batch.clear();
        for _ in 0..TX_RING_N {
            if !matches!(self.tx.try_recv(), Ok(Some(_))) {
                break;
            }
        }
    }
}
pub(super) struct Device<I: Io> {
    pub(super) lifecycle: Arc<Lifecycle<I>>,
    environment: Arc<dyn Environment>,
    admission: Admission,
    rings: Mutex<Rings>,
    name: String,
    local: [u8; 6],
    published: AtomicBool,
    withdrawn: AtomicBool,
    metadata_retired: AtomicBool,
    deliveries: AtomicUsize,
    withdrawal: AtomicU8,
    keep_name: AtomicBool,
    name_retired: AtomicBool,
    activating: AtomicBool,
    admitted: AtomicBool,
    up: AtomicBool,
    port: AtomicBool,
    rts_capable: AtomicBool,
    rts: AtomicU32,
    /// Asynchronous (`!Io::SYNCHRONOUS`) backends: the RTS threshold
    /// `set_rts_threshold` accepted, applied by the station worker
    /// (`RTS_PENDING | value`; 0 = none).
    rts_pending: AtomicU64,
    bssid: AtomicU64,
    ht_capability: IrqSafeSpinLock<Option<[u8; 26]>>,
    /// 5GHz wiphy (HT, VHT) bodies the station offers on its admitted 5GHz
    /// primaries (`Owner::station_band5_capability`), set at activate.
    band5_capability: IrqSafeSpinLock<Option<super::vht::Band5Capability>>,
    /// Admitted primaries: bit N = 2.4GHz channel N (channel 1 plus every
    /// channel with a provisioned signed N2xO record over the current base),
    /// bit 16 + i = 5GHz `channel_policy::PRIMARIES5[i]` with such a record.
    channels: AtomicU64,
    receive_generation: AtomicU64,
    metadata: IrqSafeSpinLock<()>,
    rx: IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>>,
    /// cfg80211's retained `SET_WOWLAN` configuration (`wow::validate`d).
    wowlan: IrqSafeSpinLock<Option<narf_wireless::WowlanConfig>>,
    /// The WoW firmware owns the association until `wow_resume`; host
    /// control and packet paths are closed (`admitted` is down) meanwhile.
    wow_armed: AtomicBool,
    /// The last resume's `ieee80211_report_wowlan_wakeup` subset.
    wakeup: IrqSafeSpinLock<Option<super::wow::WakeReport>>,
    /// `SUPPORTS_PS` for this generation (`Owner::lps_capable` at activate).
    sleep_capable: AtomicBool,
    /// mac80211 `vif->cfg.ps` (`rtw_recalc_lps` -> `ps_enabled`).
    sleep_enabled: AtomicBool,
    /// Data frames sent / delivered since the last LPS period
    /// (`rtw_traffic_stats` `tx_cnt` / `rx_cnt`).
    ps_tx: AtomicU32,
    ps_rx: AtomicU32,
    /// Next LPS watchdog period (environment ms).
    ps_next: AtomicU64,
}
impl<I: Io> core::fmt::Debug for Device<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88Device")
            .field("name", &self.name)
            .field("admitted", &self.admitted)
            .field("up", &self.up)
            .finish_non_exhaustive()
    }
}
trait Close: Sync {
    fn close(&self);
}
struct Attempt<'a> {
    device: &'a dyn Close,
    armed: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.device.close();
        }
    }
}
impl<I: Io + 'static> Close for Device<I> {
    fn close(&self) {
        self.admission.close();
        self.clear_receive();
        self.link(None, false);
    }
}
impl<I: Io + 'static> Device<I> {
    fn clear_receive(&self) {
        if let Some(rx) = self.rx.lock().as_mut() {
            for _ in 0..RX_RING_N {
                if !matches!(rx.try_recv(), Ok(Some(_))) {
                    break;
                }
            }
        }
    }
    pub(super) fn new(
        name: &str,
        local: [u8; 6],
        lifecycle: Arc<Lifecycle<I>>,
        environment: Arc<dyn Environment>,
    ) -> Self {
        let (rx, consumer) = narf_ipc::channel();
        let (producer, tx) = narf_ipc::channel();
        Self {
            lifecycle,
            environment,
            admission: Admission::new(),
            rings: Mutex::new(Rings {
                rx,
                tx,
                pending: None,
                batch: VecDeque::new(),
            }),
            name: name.into(),
            local,
            published: AtomicBool::new(false),
            withdrawn: AtomicBool::new(false),
            metadata_retired: AtomicBool::new(false),
            deliveries: AtomicUsize::new(0),
            withdrawal: AtomicU8::new(0),
            keep_name: AtomicBool::new(false),
            name_retired: AtomicBool::new(false),
            activating: AtomicBool::new(false),
            admitted: AtomicBool::new(false),
            up: AtomicBool::new(false),
            port: AtomicBool::new(false),
            rts_capable: AtomicBool::new(false),
            rts: AtomicU32::new(u32::MAX),
            rts_pending: AtomicU64::new(0),
            bssid: AtomicU64::new(0),
            ht_capability: IrqSafeSpinLock::new(None),
            band5_capability: IrqSafeSpinLock::new(None),
            sleep_capable: AtomicBool::new(false),
            sleep_enabled: AtomicBool::new(false),
            ps_tx: AtomicU32::new(0),
            ps_rx: AtomicU32::new(0),
            ps_next: AtomicU64::new(0),
            channels: AtomicU64::new(1 << 1),
            receive_generation: AtomicU64::new(0),
            metadata: IrqSafeSpinLock::new(()),
            rx: IrqSafeSpinLock::new(Some(consumer)),
            tx: IrqSafeSpinLock::new(Some(producer)),
            wowlan: IrqSafeSpinLock::new(None),
            wow_armed: AtomicBool::new(false),
            wakeup: IrqSafeSpinLock::new(None),
        }
    }
    /// The retained WoW configuration, carried across a cold system resume
    /// into the fresh shell as cfg80211 keeps `wiphy->wowlan_config`.
    pub(super) fn wowlan(&self) -> Option<narf_wireless::WowlanConfig> {
        self.wowlan.lock().clone()
    }
    pub(super) fn restore_wowlan(
        &self,
        config: Option<narf_wireless::WowlanConfig>,
        wakeup: Option<super::wow::WakeReport>,
    ) {
        if config
            .as_ref()
            .is_none_or(|c| super::wow::validate(self.lifecycle.device_id(), c).is_ok())
        {
            *self.wowlan.lock() = config;
        }
        *self.wakeup.lock() = wakeup;
    }
    /// The last WoW resume's wake reason (`rtw_wow_show_wakeup_reason`).
    pub(super) fn wakeup(&self) -> Option<super::wow::WakeReport> {
        *self.wakeup.lock()
    }
    /// `rtw_ops_suspend` -> `rtw_wow_suspend` on the retained managed-linked
    /// station while the interface stays published. `Ok(None)`: no WoW
    /// configuration or no settled association, nothing was touched.
    /// `Err`: WoW was attempted and failed; the caller must take the cold
    /// path (`rtw_ops_suspend` returning 1 makes mac80211 fully stop).
    pub(super) async fn wow_suspend(&self) -> Result<Option<super::wow::Armed>, ()> {
        let Some(config) = self.wowlan() else {
            return Ok(None);
        };
        let mut storage = self.lifecycle.retained.lock().await;
        if self.closed()
            || self.withdrawn()
            || !self.published.load(Ordering::Acquire)
            || !self.admitted.load(Ordering::Acquire)
            || self.wow_armed.load(Ordering::Acquire)
            || self.lifecycle.removed()
            || self.lifecycle.status().stage != super::firmware_lifecycle::Stage::StationReady
        {
            return Ok(None);
        }
        let Some(owner) = storage.as_mut() else {
            return Ok(None);
        };
        if owner.station_peer().is_none() || owner.wow_plan(&config).is_err() {
            return Ok(None);
        }
        // mac80211 `ieee80211_suspend`: stop the queues and refuse host
        // control before the driver op; nothing can reach the owner while
        // `admitted` is down (`control_ready`, `enqueue`, `progress`,
        // `watchdog`), and this mutex is held for the whole sequence.
        self.wow_armed.store(true, Ordering::Release);
        self.admitted.store(false, Ordering::Release);
        {
            self.rings.lock().await.clear();
        }
        *self.wakeup.lock() = None;
        owner.wow_suspend(&config).await.map(Some).map_err(|_| ())
    }
    /// `rtw_ops_resume` -> `rtw_wow_resume`. Success reopens host control
    /// and packets over the same association; an error (including a
    /// disconnect or unknown wake reason, which Linux reports and mac80211
    /// then drops the link for) leaves it closed for the cold path.
    pub(super) async fn wow_resume(&self, armed: super::wow::Armed) -> Result<(), ()> {
        let mut storage = self.lifecycle.retained.lock().await;
        let Some(owner) = storage.as_mut() else {
            drop(armed);
            return Err(());
        };
        let (report, result) = owner.wow_resume(armed).await;
        *self.wakeup.lock() = report;
        if result.is_err()
            || !report.as_ref().is_some_and(super::wow::keeps_link)
            || self.closed()
            || self.withdrawn()
            || owner.station_peer().is_none()
            || owner.station_check().is_err()
        {
            return Err(());
        }
        self.wow_armed.store(false, Ordering::Release);
        self.admitted.store(true, Ordering::Release);
        if self.publish_link(owner).is_err() {
            self.admitted.store(false, Ordering::Release);
            return Err(());
        }
        Ok(())
    }
    pub(super) fn closed(&self) -> bool {
        self.admission.closed()
    }
    pub(super) fn cancel_control(&self) {
        self.close();
    }
    pub(super) fn withdraw_for_rebind(self: &Arc<Self>) -> Result<(), Error> {
        if self.withdrawn() {
            return Err(Error::State);
        }
        self.keep_name.store(true, Ordering::Release);
        self.withdraw();
        Ok(())
    }
    pub(super) fn rebound_name(&self) -> Option<&'static str> {
        self.name_retired
            .load(Ordering::Acquire)
            .then(|| narf_net::iface::rebind_name(&self.name))
            .flatten()
    }
    /// Removal (`rtw_unregister_hw` in `rtw_pci_remove`): close every
    /// control and packet path, drop the link and withdraw the registered
    /// netdev, wireless and stack endpoints. The owner itself is torn down
    /// by `Lifecycle::remove`.
    pub(super) fn withdraw(self: &Arc<Self>) {
        if self.withdrawn.swap(true, Ordering::AcqRel) {
            return;
        }
        self.close();
        if let Some(mut rings) = self.rings.try_lock() {
            rings.clear();
        }
        if !self.published.swap(false, Ordering::AcqRel) {
            return;
        }
        self.link_inner(None, false, true);
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        self.withdrawal.store(1, Ordering::Release);
        self.finish_withdrawal();
    }
    fn finish_withdrawal(&self) {
        if self.deliveries.load(Ordering::Acquire) != 0
            || self
                .withdrawal
                .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        if self.keep_name.load(Ordering::Acquire) {
            self.name_retired.store(
                narf_net::iface::retire_for_rebind(&self.name),
                Ordering::Release,
            );
        } else {
            narf_net::iface::unregister(&self.name);
        }
        super::endpoints::remove(self as *const Self as *const ());
        self.withdrawal.store(3, Ordering::Release);
    }
    pub(super) async fn wait_withdrawn(&self) {
        while matches!(self.withdrawal.load(Ordering::Acquire), 1 | 2) {
            self.environment.pause().await;
        }
    }
    fn begin_delivery(&self) -> Option<Delivery<'_, I>> {
        let _metadata = self.metadata.lock();
        if self.withdrawn() || self.closed() {
            return None;
        }
        self.deliveries.fetch_add(1, Ordering::AcqRel);
        Some(Delivery(self))
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn delivery_for_test(&self) -> impl Drop + '_ {
        self.begin_delivery().expect("live fixture ingress")
    }
    pub(super) fn withdrawn(&self) -> bool {
        self.withdrawn.load(Ordering::Acquire)
    }
    pub(super) fn admission(&self) -> Admission {
        self.admission.clone()
    }
    /// Freeze actual unassociated IPS eligibility and original closure under
    /// the real owner mutex. The reservation closure must not await or touch
    /// station state; a pending join cannot start after this close.
    pub(super) async fn idle_claim<T>(
        &self,
        reserve: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut retained = self.lifecycle.retained.lock().await;
        if self.closed()
            || self.lifecycle.removed()
            || self.lifecycle.status().stage != super::firmware_lifecycle::Stage::StationReady
            || retained.as_ref().is_none_or(|owner| {
                owner.station_phase() != Some(station::Phase::Passive)
                    || owner.station_peer().is_some()
            })
        {
            return Err(Error::Busy);
        }
        let claim = reserve()?;
        // ps.c `rtw_enter_ips`: `rtw_coex_ips_notify(COEX_IPS_ENTER)` before
        // `rtw_core_stop`. The fresh generation's coexistence `start`
        // (`rtw_coex_power_on_setting` + `init_hw`, scoreboard ACTIVE|ONOFF)
        // is the `COEX_IPS_LEAVE` state on resume.
        if let Some(owner) = retained.as_mut() {
            owner.station_coex_ips_enter().await;
        }
        self.cancel_control();
        Ok(claim)
    }
    /// Linux `rtw_watch_dog_work`: one dynamic-mechanism period under the
    /// retained owner mutex. A failed period closes the shell.
    pub(super) async fn watchdog(&self) -> bool {
        if self.closed() || !self.admitted.load(Ordering::Acquire) {
            return false;
        }
        let ran = match self.lifecycle.watchdog().await {
            Ok(ran) => ran,
            Err(_) => {
                self.close();
                return false;
            }
        };
        self.lps_watchdog().await;
        ran
    }
    /// main.c `rtw_watch_dog_work` LPS tail: every `RTW_WATCH_DOG_DELAY_TIME`
    /// period with power save on (`ps_enabled`), an associated station and
    /// at most `RTW_LPS_THRESHOLD` data frames each way (`!ps_active`),
    /// `rtw_enter_lps`. NARF's LPS owner is the bounded nondeep window
    /// (`Owner::lps_window`, the `lps_function` operation), so the period
    /// sleeps one [`LPS_WINDOW_MS`] window and then confirms awake. Refusal
    /// (busy peer/queues, coexistence `wl_force_lps_ctrl`, no N2xZ record on
    /// this channel) leaves the station untouched; a failed window has
    /// already closed the station, which needs reset/rejoin.
    async fn lps_watchdog(&self) {
        if !self.sleep_capable.load(Ordering::Acquire) {
            return;
        }
        let now = self.environment.now_ms();
        if now < self.ps_next.load(Ordering::Acquire) {
            return;
        }
        self.ps_next
            .store(now.saturating_add(LPS_PERIOD_MS), Ordering::Release);
        let tx = self.ps_tx.swap(0, Ordering::AcqRel);
        let rx = self.ps_rx.swap(0, Ordering::AcqRel);
        if !lps_due(self.sleep_enabled.load(Ordering::Acquire), tx, rx)
            || self.closed()
            || !self.link_up()
            || self.wow_armed.load(Ordering::Acquire)
        {
            return;
        }
        let Some(snapshot) = narf_net::iface::lookup(&self.name) else {
            return;
        };
        if snapshot.mac != self.local {
            return;
        }
        let Some(up) = narf_net::iface::OpenStopEvent::observe(&snapshot).filter(|e| e.up()) else {
            return;
        };
        let Some(host) = up.native_identity() else {
            return;
        };
        let mut retained = self.lifecycle.retained.lock().await;
        if !up.current() || self.closed() {
            return;
        }
        let Some(owner) = retained.as_mut() else {
            return;
        };
        if owner.lps_window(host, LPS_WINDOW_MS).await.is_err() && self.closed() {
            drop(retained);
            self.close();
        }
    }
    pub(super) async fn activate(&self) -> Result<(), Error> {
        if !self.published.load(Ordering::Acquire) || self.closed() {
            return Err(Error::State);
        }
        self.activating
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::State)?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        self.lifecycle
            .start_station(self.environment.clone(), self.admission.clone())
            .await?;
        let (authority, ht, channels, band5, sleep) = {
            let mut retained = self.lifecycle.retained.lock().await;
            let owner = retained.as_mut().ok_or(Error::State)?;
            (
                owner.station_publication()?,
                owner.station_ht_capability(),
                owner.station_admitted_channels(),
                owner.station_band5_capability(),
                owner.lps_capable(),
            )
        };
        self.admission.run(|| {
            authority.invoke(|| {
                self.admitted.store(true, Ordering::Release);
                *self.ht_capability.lock() = ht;
                *self.band5_capability.lock() = band5;
                self.sleep_capable.store(sleep, Ordering::Release);
                self.channels.store(channels, Ordering::Release);
                Ok(())
            })
        })?;
        attempt.armed = false;
        Ok(())
    }
    /// Admitted primaries, 2.4GHz first then 5GHz (channel numbers do not
    /// overlap between the two bands).
    fn admitted_channels(&self) -> Vec<u32> {
        let mask = self.channels.load(Ordering::Acquire);
        (1..=u32::from(super::channel_policy::LAST))
            .filter(|c| mask & (1 << c) != 0)
            .chain(
                super::channel_policy::PRIMARIES5
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << (16 + i)) != 0)
                    .map(|(_, c)| u32::from(c)),
            )
            .collect()
    }
    fn link(&self, peer: Option<[u8; 6]>, port: bool) {
        self.link_inner(peer, port, false);
    }
    fn link_inner(&self, peer: Option<[u8; 6]>, port: bool, retire: bool) {
        let _metadata = self.metadata.lock();
        if self.metadata_retired.load(Ordering::Acquire) {
            return;
        }
        if retire {
            self.metadata_retired.store(true, Ordering::Release);
        }
        if peer.is_none() {
            self.rts_capable.store(false, Ordering::Release);
        }
        let peer = peer.filter(|_| !self.closed());
        let mut packed = [0; 8];
        if let Some(peer) = peer {
            packed[..6].copy_from_slice(&peer);
            packed[7] = 1;
        }
        self.bssid
            .store(u64::from_le_bytes(packed), Ordering::Release);
        self.port.store(peer.is_some() && port, Ordering::Release);
        let up = peer.is_some();
        let was = self.up.swap(up, Ordering::AcqRel);
        // Physical carrier is independent of administrative IFF_UP. In
        // particular, do not invoke ndo_open/ndo_stop under retained locks.
        narf_net::iface::set_link_metadata(&self.name, up, None, None);
        if was && !up {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }
    fn publish_link(
        &self,
        owner: &mut super::firmware_transport::Owner<I>,
    ) -> Result<super::publication::Publication, Error> {
        let peer = owner.station_peer();
        let port = owner.station_receive_open();
        let rts = owner.station_rts_threshold();
        let authority = owner.station_publication()?;
        let generation = self.admission.receive_generation();
        self.admission.run(|| {
            authority.invoke(|| {
                if self.receive_generation.swap(generation, Ordering::AcqRel) != generation {
                    self.clear_receive();
                }
                self.link(peer, port);
                self.rts.store(rts.unwrap_or(u32::MAX), Ordering::Release);
                self.rts_capable
                    .store(rts.is_some() && peer.is_some(), Ordering::Release);
                Ok(())
            })
        })?;
        Ok(authority)
    }
    fn control_ready(&self) -> Result<(), WirelessError> {
        if self.closed() {
            Err(WirelessError::HardwareError)
        } else if !self.admitted.load(Ordering::Acquire) {
            Err(WirelessError::Busy)
        } else {
            Ok(())
        }
    }
    pub(super) fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if !self.admitted.load(Ordering::Acquire)
            || self.closed()
            || !self.up.load(Ordering::Acquire)
            || !self.port.load(Ordering::Acquire)
            || !station::admitted(bytes, self.local)
            || !offloads(meta)
        {
            return Err(());
        }
        let mut storage = self.lifecycle.retained.try_lock().ok_or(())?;
        let owner = storage.as_mut().ok_or(())?;
        let authority = owner.station_check();
        if authority.is_err() {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
            return Err(());
        }
        if !owner.station_ready() {
            return Err(());
        }
        let result = self.admission.run(|| {
            let memory = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                .map_err(|_| super::firmware_transport::Error::Memory)?;
            let mut frame = Frame::new(memory, bytes.len() as u32);
            frame.payload_mut().copy_from_slice(bytes);
            frame.set_tx_meta(meta);
            // Re-sample the retained PCI/calibration/policy authority at
            // queue publication, after allocation and the initial check.
            // Native DMA publication independently checks again.
            let authority = owner
                .station_publication()
                .map_err(|_| super::firmware_transport::Error::Access)?;
            // Outer failure is current authority/PCI loss. Keep the inner
            // ring-full result retryable without confusing the two classes.
            authority
                .invoke(|| {
                    let mut slot = self.tx.lock();
                    Ok(match slot.as_mut() {
                        Some(ring) => ring
                            .try_send(frame)
                            .map_err(|_| super::firmware_transport::Error::State),
                        None => Err(super::firmware_transport::Error::State),
                    })
                })
                .map_err(|_| super::firmware_transport::Error::Access)?
        });
        if result == Err(super::firmware_transport::Error::Access) {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
        }
        if result.is_ok() {
            self.ps_tx.fetch_add(1, Ordering::Relaxed);
        }
        result.map_err(|_| ())
    }
    /// Synchronous shell progress: only for a backend whose every register
    /// future completes in its first poll (PCI). An asynchronous (USB)
    /// backend is driven by `publish`'s worker through [`Self::step`].
    fn progress(&self) -> Vec<(Vec<u8>, super::publication::Publication)> {
        if !I::SYNCHRONOUS {
            return Vec::new();
        }
        let step = core::pin::pin!(self.step());
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        match core::future::Future::poll(step, &mut cx) {
            core::task::Poll::Ready(frames) => frames,
            // Unreachable for a synchronous backend: every owner future in
            // `step` goes through `ready_now`.
            core::task::Poll::Pending => Vec::new(),
        }
    }
    /// One station progress turn (poll, publish, one TX slot). Owner futures
    /// are `ready_now` for a synchronous backend and awaited otherwise; the
    /// shell locks are only ever `try_lock`ed, so a turn never waits on
    /// another task.
    async fn step(&self) -> Vec<(Vec<u8>, super::publication::Publication)> {
        let Some(mut storage) = self.lifecycle.retained.try_lock() else {
            return Vec::new();
        };
        let Some(owner) = storage.as_mut() else {
            return Vec::new();
        };
        let Some(mut rings) = self.rings.try_lock() else {
            return Vec::new();
        };
        if self.closed() {
            rings.clear();
            self.link(None, false);
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
            return Vec::new();
        }
        if !self.admitted.load(Ordering::Acquire) {
            return Vec::new();
        }
        let result: Result<Vec<(Vec<u8>, super::publication::Publication)>, Error> = async {
            let frames = settle::<I, _>(owner.station_poll()).await?;
            self.publish_link(owner)?;
            if self.closed() {
                rings.clear();
                return Ok(Vec::new());
            }
            if owner.station_peer().is_none() {
                rings.clear();
                return Ok(Vec::new());
            }
            if rings.pending.is_none() {
                rings.pending = rings.batch.pop_front();
            }
            if rings.pending.is_none() {
                for _ in 0..16 {
                    let Ok(Some(frame)) = rings.tx.try_recv() else {
                        break;
                    };
                    if station::admitted(frame.payload(), self.local) && offloads(frame.tx_meta()) {
                        rings.pending = Some(frame);
                        break;
                    }
                }
            }
            if owner.station_ready() {
                if owner.station_batch_active() && rings.pending.is_some() {
                    let capacity = owner.station_batch_capacity();
                    for _ in 0..16 {
                        if rings.batch.len() + 1 >= capacity {
                            break;
                        }
                        let Ok(Some(frame)) = rings.tx.try_recv() else {
                            break;
                        };
                        if station::admitted(frame.payload(), self.local)
                            && offloads(frame.tx_meta())
                        {
                            rings.batch.push_back(frame);
                        }
                    }
                    let mut frames = Vec::new();
                    if let Some(first) = rings.pending.as_ref() {
                        frames.push(first.payload());
                    }
                    frames.extend(
                        rings
                            .batch
                            .iter()
                            .take(capacity.saturating_sub(1))
                            .map(Frame::payload),
                    );
                    match settle::<I, _>(owner.station_send_batch(&frames)).await {
                        Ok(count) => {
                            if count == 0 || count > frames.len() {
                                return Err(Error::State);
                            }
                            rings.pending = None;
                            for _ in 1..count {
                                rings.batch.pop_front();
                            }
                        }
                        Err(Error::Busy)
                        | Err(Error::Transport(super::packet_core::Error::Busy)) => {}
                        Err(error) => return Err(error),
                    }
                } else if let Some(frame) = rings.pending.as_ref() {
                    match settle::<I, _>(owner.station_send(frame.payload())).await {
                        Ok(()) => rings.pending = None,
                        Err(Error::Busy)
                        | Err(Error::Transport(super::packet_core::Error::Busy)) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            let authority = self.publish_link(owner)?;
            self.admission.run(|| {
                for bytes in &frames {
                    if let Ok(memory) =
                        narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                    {
                        let mut frame = Frame::new(memory, bytes.len() as u32);
                        frame.payload_mut().copy_from_slice(bytes);
                        authority.invoke(|| {
                            let _ = rings.rx.try_send(frame);
                            Ok(())
                        })?;
                    }
                }
                Ok(())
            })?;
            Ok(frames
                .into_iter()
                .map(|frame| (frame, authority.clone()))
                .collect())
        }
        .await;
        match result {
            Ok(frames) => {
                if self.closed() {
                    rings.clear();
                    Vec::new()
                } else {
                    frames
                }
            }
            Err(_) => {
                rings.clear();
                self.close();
                if !self.admission.teardown_pending() {
                    let _ = owner.station_stop();
                }
                Vec::new()
            }
        }
    }
    pub(super) fn drain(&self) -> bool {
        if !I::SYNCHRONOUS {
            return false;
        }
        self.deliver(self.progress())
    }
    /// The station worker's turn for an asynchronous backend: apply a
    /// pending RTS threshold, run one [`Self::step`], then deliver.
    pub(super) async fn drain_async(&self) -> bool {
        self.apply_rts().await;
        let frames = self.step().await;
        self.deliver(frames)
    }
    /// Apply the RTS threshold `set_rts_threshold` accepted for an
    /// asynchronous backend (Linux `mac80211.c::rtw_ops_set_rts_threshold`
    /// records the value; the station programs it before the next TX).
    async fn apply_rts(&self) {
        let pending = self.rts_pending.swap(0, Ordering::AcqRel);
        if pending & RTS_PENDING == 0 {
            return;
        }
        let value = pending as u32;
        let Some(mut storage) = self.lifecycle.retained.try_lock() else {
            self.requeue_rts(pending);
            return;
        };
        let Some(owner) = storage.as_mut() else {
            return;
        };
        match owner.station_set_rts_threshold(value).await {
            Ok(()) => {
                let current = owner.station_rts_threshold();
                self.rts
                    .store(current.unwrap_or(u32::MAX), Ordering::Release);
                self.rts_capable.store(current.is_some(), Ordering::Release);
            }
            Err(Error::Busy | Error::State) => self.requeue_rts(pending),
            Err(Error::Profile | Error::Native(super::firmware_transport::Error::Unsupported)) => {
                self.rts_capable
                    .store(owner.station_rts_threshold().is_some(), Ordering::Release);
            }
            Err(_) => {
                self.close();
                if !self.admission.teardown_pending() {
                    let _ = owner.station_stop();
                }
            }
        }
    }
    /// Retry later unless a newer request superseded this one.
    fn requeue_rts(&self, pending: u64) {
        let _ = self
            .rts_pending
            .compare_exchange(0, pending, Ordering::AcqRel, Ordering::Acquire);
    }
    fn deliver(&self, frames: Vec<(Vec<u8>, super::publication::Publication)>) -> bool {
        let progressed = !frames.is_empty();
        // All retained-owner/ring/admission guards have dropped before the
        // stack can synchronously answer ARP/ND through this enqueue callback.
        for (mut frame, authority) in frames {
            if self.closed() {
                break;
            }
            if !authority.current() {
                continue;
            }
            // A previous callback may have reentered native progress and
            // changed the key/port epoch. Refresh the actual retained owner,
            // then release it before the callback (ARP/ND may enqueue/drain).
            let ready = {
                let Some(mut storage) = self.lifecycle.retained.try_lock() else {
                    continue;
                };
                let Some(owner) = storage.as_mut() else {
                    continue;
                };
                if owner.station_check().is_err() {
                    self.close();
                    if !self.admission.teardown_pending() {
                        let _ = owner.station_stop();
                    }
                    false
                } else {
                    owner.station_receive_open()
                }
            };
            if !ready || !authority.current() {
                continue;
            }
            let Some(_delivery) = self.begin_delivery() else {
                break;
            };
            if authority
                .invoke(|| {
                    if self.closed() || !self.port.load(Ordering::Acquire) || !authority.current() {
                        return Err(super::firmware_transport::Error::State);
                    }
                    narf_net::iface::on_rx_frame_from(&self.name, &mut frame);
                    self.ps_rx.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })
                .is_err()
            {
                if !authority.current() {
                    continue;
                }
                self.close();
                let _ = self.progress();
                break;
            }
        }
        progressed
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn admit_for_test(&self) {
        self.published.store(true, Ordering::Release);
    }
}
/// `Device::rts_pending` valid bit.
const RTS_PENDING: u64 = 1 << 32;
/// An owner future from [`Device::step`]: `ready_now` for a synchronous
/// backend (unchanged PCI semantics), awaited for an asynchronous one.
async fn settle<I: Io, T>(
    operation: impl core::future::Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    if I::SYNCHRONOUS {
        super::firmware_transport::ready_now(operation)
    } else {
        operation.await
    }
}
fn offloads(meta: narf_net::TxMeta) -> bool {
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
impl<I: Io + 'static> Interface for Device<I> {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.local
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.admitted.load(Ordering::Acquire) && !self.closed() && self.up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl<I: Io + 'static> WirelessNetIface for Device<I> {
    fn rts_threshold(&self) -> Option<u32> {
        (!self.closed() && self.rts_capable.load(Ordering::Acquire))
            .then(|| self.rts.load(Ordering::Acquire))
    }
    fn set_rts_threshold(&self, value: u32) -> Result<(), i32> {
        if value != u32::MAX && value > 2347 {
            return Err(EINVAL);
        }
        if self.closed() {
            return Err(ENODEV);
        }
        if self.wow_armed.load(Ordering::Acquire) {
            return Err(EBUSY);
        }
        if !I::SYNCHRONOUS {
            // Every register access is a transfer: the worker applies it.
            if !self.rts_capable.load(Ordering::Acquire) {
                return Err(narf_wireless::EOPNOTSUPP);
            }
            self.rts_pending
                .store(RTS_PENDING | u64::from(value), Ordering::Release);
            return Ok(());
        }
        let mut storage = self.lifecycle.retained.try_lock().ok_or(EBUSY)?;
        let owner = storage.as_mut().ok_or(EBUSY)?;
        let result = super::firmware_transport::ready_now(owner.station_set_rts_threshold(value));
        match result {
            Ok(()) => {
                let current = owner.station_rts_threshold();
                self.rts
                    .store(current.unwrap_or(u32::MAX), Ordering::Release);
                self.rts_capable.store(current.is_some(), Ordering::Release);
                Ok(())
            }
            Err(Error::Busy | Error::State) => Err(EBUSY),
            Err(Error::Profile | Error::Native(super::firmware_transport::Error::Unsupported)) => {
                Err(narf_wireless::EOPNOTSUPP)
            }
            Err(_) => {
                self.close();
                Err(ENODEV)
            }
        }
    }
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }
    /// Linux `main.c::rtw_register_hw` sets `NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR`.
    fn supports_scan_random_mac(&self) -> bool {
        true
    }
    fn supports_scan_dwell(&self) -> bool {
        true
    }
    fn max_scan_ssids(&self) -> u8 {
        super::scan::MAX_SSIDS
    }
    fn max_scan_ie_len(&self) -> u16 {
        super::scan::MAX_EXTRA_IES
    }
    /// `rtw_wowlan_stub_8822c` (`wow::support`), RTL8822CE only.
    fn wowlan_support(&self) -> Option<narf_wireless::WowlanSupport> {
        super::wow::support(self.lifecycle.device_id())
    }
    fn set_wowlan(&self, config: Option<narf_wireless::WowlanConfig>) -> Result<(), i32> {
        let did = self.lifecycle.device_id();
        super::wow::support(did).ok_or(narf_wireless::EOPNOTSUPP)?;
        if let Some(config) = &config {
            super::wow::validate(did, config).map_err(|_| EINVAL)?;
        }
        *self.wowlan.lock() = config;
        Ok(())
    }
    fn wowlan_config(&self) -> Option<narf_wireless::WowlanConfig> {
        self.wowlan()
    }
    /// main.c `SUPPORTS_PS` | `SUPPORTS_DYNAMIC_PS` (no
    /// `WIPHY_FLAG_PS_ON_BY_DEFAULT`): only with a composed LPS owner.
    fn power_save_default(&self) -> Option<bool> {
        self.sleep_capable
            .load(Ordering::Acquire)
            .then(|| self.sleep_enabled.load(Ordering::Acquire))
    }
    /// `rtw_ops_config(IEEE80211_CONF_CHANGE_PS)` -> `rtw_recalc_lps`:
    /// enabling arms the watchdog LPS entry; disabling stops further
    /// windows (every window already ends awake).
    fn set_power_save(&self, enabled: bool) -> Result<(), i32> {
        if !self.sleep_capable.load(Ordering::Acquire) {
            return Err(narf_wireless::EOPNOTSUPP);
        }
        self.sleep_enabled.store(enabled, Ordering::Release);
        Ok(())
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        if !self.link_up() {
            return None;
        }
        let bytes = self.bssid.load(Ordering::Acquire).to_le_bytes();
        (bytes[7] != 0).then(|| bytes[..6].try_into().unwrap())
    }
    fn cipher_suites(&self) -> &'static [u32] {
        &[0x000fac04]
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.lifecycle
            .retained
            .try_lock()?
            .as_ref()?
            .station_information_elements(bssid)
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.local,
            bands: {
                let (two, five): (Vec<u32>, Vec<u32>) = self
                    .admitted_channels()
                    .into_iter()
                    .partition(|c| *c <= u32::from(super::channel_policy::LAST));
                let mut bands = vec![WirelessBand {
                    freq_mhz: 2400,
                    channels: two,
                }];
                if !five.is_empty() {
                    bands.push(WirelessBand {
                        freq_mhz: 5000,
                        channels: five,
                    });
                }
                bands
            },
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: self.ht_capability.lock().is_some()
                    || self.band5_capability.lock().is_some(),
                // main.c `rtw_init_vht_cap`: only when an admitted 5GHz join
                // can actually offer the N2xV VHT80 program.
                vht_supported: self
                    .band5_capability
                    .lock()
                    .is_some_and(|(_, vht)| vht.is_some()),
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    fn phy_capabilities(&self, band: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        match band {
            2400 => Some(narf_wireless::iface::PhyCapabilities {
                ht: (*self.ht_capability.lock())?,
                vht: None,
            }),
            // The 5GHz sband (`rtw_init_ht_cap`/`rtw_init_vht_cap` in main.c
            // `rtw_set_supported_band`) carries exactly the qualified HT20 or
            // HT+VHT80 offer of an admitted 5GHz join; no admitted 5GHz HT
            // program leaves the band legacy (no capabilities).
            5000 => {
                let (ht, vht) = (*self.band5_capability.lock())?;
                Some(narf_wireless::iface::PhyCapabilities { ht, vht })
            }
            _ => None,
        }
    }
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let mut plan = super::scan::plan(&request, self.local)?;
        let admitted = self.admitted_channels();
        if plan
            .channels
            .iter()
            .any(|c| !admitted.contains(&u32::from(*c)))
        {
            return Err(WirelessError::NotSupported);
        }
        if plan.channels.is_empty() && admitted.len() > 1 {
            plan.channels = admitted.iter().map(|c| *c as u8).collect();
        }
        self.control_ready()?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let mut storage = self.lifecycle.retained.lock().await;
        self.control_ready()?;
        let owner = storage.as_mut().ok_or(WirelessError::Busy)?;
        if owner.station_phase() != Some(station::Phase::Passive) {
            attempt.armed = false;
            return Err(WirelessError::Busy);
        }
        let result = owner
            .station_scan(plan.dwell_ms, &plan.probes, plan.address, &plan.channels)
            .await;
        attempt.armed = false;
        if result.is_err() {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
        }
        let result = result.map_err(error)?;
        if self.closed() {
            self.link(None, false);
            return Err(WirelessError::HardwareError);
        }
        Ok(result
            .into_iter()
            .filter(|c| {
                request.ssids.is_empty()
                    || request
                        .ssids
                        .iter()
                        .any(|s| s.is_empty() || *s == c.bss.ssid)
            })
            .map(|c| BssInfo {
                bssid: c.bss.bssid,
                frequency_mhz: super::channel_policy::any_frequency(c.bss.channel)
                    .map_or(0, u32::from),
                channel: u32::from(c.bss.channel),
                ssid: c.bss.ssid,
                rssi: i8::MIN,
                security: if c.ap_rsne.is_some() {
                    narf_wireless::scan::BssSecurity::Wpa2
                } else if c.bss.capability & 16 != 0 {
                    narf_wireless::scan::BssSecurity::Wep
                } else {
                    narf_wireless::scan::BssSecurity::Open
                },
            })
            .collect())
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        self.control_ready()?;
        if !self.admitted_channels().contains(&request.channel)
            || super::channel_policy::any_frequency(request.channel as u8).map(u32::from)
                != Some(request.frequency_mhz)
        {
            return Err(WirelessError::NotSupported);
        }
        let pmk = match request.security {
            SecurityConfig::Open => None,
            SecurityConfig::Wpa2 { psk } => Some(Zeroizing::new(psk)),
            _ => return Err(WirelessError::NotSupported),
        };
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let mut storage = self.lifecycle.retained.lock().await;
        self.control_ready()?;
        let owner = storage.as_mut().ok_or(WirelessError::Busy)?;
        if owner.station_phase() != Some(station::Phase::Passive) {
            attempt.armed = false;
            return Err(WirelessError::Busy);
        }
        {
            self.rings.lock().await.clear();
        }
        let result = owner
            .station_associate(request.bssid, &request.ssid, pmk, &request.ie)
            .await;
        #[cfg(feature = "kernel-test")]
        if let Err(error) = &result {
            narf_console::klog!(
                "RTW native association failed {:?}, phase {:?}, peer {:?}\n",
                error,
                owner.station_phase(),
                owner.station_peer()
            );
        }
        attempt.armed = false;
        if self.closed() {
            self.link(None, false);
            return Err(WirelessError::HardwareError);
        }
        if self.publish_link(owner).is_err() {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
            return Err(WirelessError::HardwareError);
        }
        result.map_err(error)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        let _disconnect = self
            .admission
            .begin_disconnect()
            .map_err(|_| WirelessError::Busy)?;
        self.close(); // metadata is down before the retained mutex can await.
        let mut storage = self.lifecycle.retained.lock().await;
        {
            self.rings.lock().await.clear();
        }
        let result = match storage.as_mut() {
            Some(owner) if owner.station_phase().is_some() => {
                owner.station_disconnect().await.map_err(error)
            }
            _ => Ok(()),
        };
        self.link(None, false);
        result
    }
    async fn set_config(&self, config: WirelessConfig) -> Result<(), WirelessError> {
        self.control_ready()?;
        if config.channel != 1 || config.tx_power_dbm.is_some() {
            return Err(WirelessError::NotSupported);
        }
        let mut storage = self.lifecycle.retained.lock().await;
        self.control_ready()?;
        let owner = storage.as_mut().ok_or(WirelessError::Busy)?;
        let result = owner.station_check();
        if result.is_err() {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
        }
        result.map_err(error)
    }
}
pub(super) type Native = Device<super::pci_firmware::Transport>;
impl<I: Io + 'static> super::endpoints::Endpoint for Device<I> {
    fn send(&self, b: &[u8], m: narf_net::TxMeta) -> Result<(), ()> {
        self.enqueue(b, m)
    }
    fn drain(&self) -> bool {
        Device::drain(self)
    }
}
struct Delivery<'a, I: Io + 'static>(&'a Device<I>);
impl<I: Io + 'static> Drop for Delivery<'_, I> {
    fn drop(&mut self) {
        if self.0.deliveries.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.finish_withdrawal();
        }
    }
}
pub(super) fn publish<I: Io + 'static>(device: Arc<Device<I>>) -> Result<(), Error> {
    if device.withdrawn() || device.published.load(Ordering::Acquire) {
        return Err(Error::State);
    }
    let usb = matches!(
        device.lifecycle.interface(),
        super::phy8821c::Interface::Usb { .. }
    );
    let driver = match (device.lifecycle.device_id(), usb, I::SYNCHRONOUS) {
        (0xc821, false, true) => "rtw8821ce",
        (0xc822, false, true) => "rtw8822ce",
        // Linux `rtw8822be.c` `rtw_8822be_driver.name`.
        (0xb822, false, true) => "rtw8822be",
        // Linux `rtw8821cu.c` `rtw_8821cu_driver.name`; the USB backend is
        // asynchronous, so the worker drives it.
        (0xc821, true, false) => "rtw8821cu",
        // Linux `rtw8822bu.c` `rtw_8822bu_driver.name`.
        (0xb822, true, false) => "rtw8822bu",
        _ => return Err(Error::State),
    };
    let authority = narf_net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(Error::Profile)?;
    let cookie =
        super::endpoints::insert(&device.name, device.clone()).map_err(|_| Error::State)?;
    if narf_net::registry()
        .register(&authority, Registered(device.clone()))
        .is_err()
    {
        super::endpoints::remove(Arc::as_ptr(&device) as *const ());
        return Err(Error::Profile);
    }
    narf_net::iface::register_with_context(
        &device.name,
        device.local,
        cookie,
        super::endpoints::send,
    );
    narf_net::iface::set_driver_info(&device.name, driver, None, String::new());
    narf_net::iface::set_offloads(&device.name, narf_net::OffloadCapabilities::default());
    device.link(None, false);
    narf_net::iface::install_rx_drain(super::endpoints::drain);
    narf_wireless::registry::register(device.clone());
    device.published.store(true, Ordering::Release);
    start_watchdog_work(&device);
    narf_scheduler::spawn(async move {
        while !device.withdrawn() {
            if I::SYNCHRONOUS {
                device.drain();
            } else {
                device.drain_async().await;
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    });
    Ok(())
}

/// `RTW_WATCH_DOG_DELAY_TIME`: the watchdog period.
const WATCHDOG_PERIOD_MS: u64 = 2000;

/// `rtwdev->watch_dog_work`: the station's dynamic-mechanism period as
/// delayed work (Linux `rtw_watch_dog_work`, re-queued every
/// `RTW_WATCH_DOG_DELAY_TIME`). It holds the device weakly and frees itself
/// when the device is withdrawn.
#[repr(C)]
struct WatchdogWork<I: Io> {
    /// First field: the work function's `WorkRef` is this struct.
    dw: narf_scheduler::workqueue::DelayedWork,
    device: alloc::sync::Weak<Device<I>>,
}

fn start_watchdog_work<I: Io + 'static>(device: &Arc<Device<I>>) {
    let ww = alloc::boxed::Box::leak(alloc::boxed::Box::new(WatchdogWork {
        dw: narf_scheduler::workqueue::DelayedWork::new(
            narf_scheduler::workqueue::WorkFn::Async(watchdog_work_fn::<I>),
            false,
        ),
        device: Arc::downgrade(device),
    }));
    queue_watchdog(&ww.dw);
}

fn queue_watchdog(dw: &narf_scheduler::workqueue::DelayedWork) {
    let delay = narf_time::timer::ns_to_jiffies(WATCHDOG_PERIOD_MS * 1_000_000);
    // SAFETY: the delayed work is leaked until its own function frees it,
    // which it does only when it does not re-queue.
    unsafe {
        narf_scheduler::workqueue::queue_delayed_work(
            narf_scheduler::workqueue::system_wq(),
            dw,
            delay,
        )
    };
}

fn watchdog_work_fn<I: Io + 'static>(
    r: narf_scheduler::workqueue::WorkRef,
) -> narf_scheduler::workqueue::WorkFuture {
    let addr = r.as_ptr() as usize;
    // SAFETY: only `WatchdogWork<I>` uses this function; its delayed work
    // (whose `work` is first) is its first field, and it is alive until this
    // function frees it.
    let device = unsafe { &*(addr as *const WatchdogWork<I>) }
        .device
        .upgrade();
    alloc::boxed::Box::pin(async move {
        // `addr` (a usize, not a pointer) is what lives across the await.
        match device {
            Some(device) if !device.withdrawn() => {
                let _ = device.watchdog().await;
                drop(device);
                // SAFETY: as above; not freed on this path.
                queue_watchdog(unsafe { &(*(addr as *const WatchdogWork<I>)).dw });
            }
            device => {
                drop(device);
                // SAFETY: neither pending nor queued (this run is the last,
                // it does not re-queue), and the pool never touches a work
                // after calling its function: the work is ours to free.
                drop(unsafe { alloc::boxed::Box::from_raw(addr as *mut WatchdogWork<I>) });
            }
        }
    })
}
struct Registered<I: Io>(Arc<Device<I>>);
impl<I: Io + 'static> Interface for Registered<I> {
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
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "interface_tests.rs"]
mod tests;

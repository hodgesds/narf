// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-function RTL8852B shells and retained owners for control and packet
//! progress. Synchronous stack drains never wait for another executor task.
use super::{
    station::Io,
    station::{self, Environment},
    station_control::Admission,
    station_lifecycle::Lifecycle,
};
use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessConfig, WirelessError,
    WirelessNetIface,
};
use zeroize::Zeroizing;
type Error = station::Error;
struct Rings {
    rx: narf_ipc::Producer<Frame, RX_RING_N>,
    tx: narf_ipc::Consumer<Frame, TX_RING_N>,
    pending: Option<Frame>,
    /// Per-AC host backlog in `qos::Ac` order (VO, VI, BE, BK).
    backlog: [alloc::collections::VecDeque<Frame>; 4],
}
/// Frames pulled from the stack ring into the per-AC backlog per pass.
const BACKLOG: usize = 16;
impl Rings {
    /// Strict-priority service (all-AC program): refill the bounded backlog
    /// from the stack ring, then hand out the oldest frame of the highest
    /// non-empty AC. Without the program every frame is BE (FIFO).
    fn next(&mut self, local: [u8; 6], qos_all: bool) -> Option<Frame> {
        let mut queued: usize = self.backlog.iter().map(|q| q.len()).sum();
        while queued < BACKLOG {
            let Ok(Some(frame)) = self.tx.try_recv() else {
                break;
            };
            if !station::admitted(frame.payload(), local) || !offloads(frame.tx_meta()) {
                continue;
            }
            let ac = if qos_all {
                super::qos::Ac::of(super::qos::classify(frame.payload()))
            } else {
                super::qos::Ac::BestEffort
            };
            self.backlog[ac as usize].push_back(frame);
            queued += 1;
        }
        super::qos::Ac::ORDER
            .iter()
            .find_map(|ac| self.backlog[*ac as usize].pop_front())
    }
    /// Keep the exact FIFO prefix of the selected AC. The station applies
    /// actual ACM/TID/peer/size rules without skipping an ineligible member.
    fn prefix(&self, qos_all: bool) -> Vec<&[u8]> {
        let Some(first) = self.pending.as_ref() else {
            return Vec::new();
        };
        let ac = if qos_all {
            super::qos::Ac::of(super::qos::classify(first.payload()))
        } else {
            super::qos::Ac::BestEffort
        };
        core::iter::once(first.payload())
            .chain(self.backlog[ac as usize].iter().map(Frame::payload))
            .take(super::tx_amsdu::PREFIX)
            .collect()
    }
    fn consumed(&mut self, count: usize, qos_all: bool) {
        let Some(first) = self.pending.take() else {
            return;
        };
        let ac = if qos_all {
            super::qos::Ac::of(super::qos::classify(first.payload()))
        } else {
            super::qos::Ac::BestEffort
        };
        for _ in 1..count {
            self.backlog[ac as usize].pop_front();
        }
    }
    fn clear(&mut self) {
        self.pending = None;
        for queue in &mut self.backlog {
            queue.clear();
        }
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
    retired: AtomicBool,
    deliveries: AtomicUsize,
    /// 0 live; 1 remove / 2 keep name; 3 finalizing; 4 withdrawn.
    withdrawal: AtomicU8,
    activating: AtomicBool,
    admitted: AtomicBool,
    up: AtomicBool,
    port: AtomicBool,
    bssid: AtomicU64,
    metadata: IrqSafeSpinLock<()>,
    rx: IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>>,
    /// MSI deliveries and TX kicks wake the drain worker through this line.
    line: Arc<super::irq::Line>,
    interrupts: AtomicBool,
    sleep_capable: AtomicBool,
    /// RTL8852B WoW composed on this generation (sampled at activation).
    wow_capable: AtomicBool,
    /// The WoW image owns the radio; host control and packets are refused.
    wow_armed: AtomicBool,
    /// cfg80211 `wiphy->wowlan_config`, carried into later generations.
    wowlan: IrqSafeSpinLock<Option<narf_wireless::WowlanConfig>>,
    /// The last resume's `rtw89_wow_show_wakeup_reason` subset.
    wakeup: IrqSafeSpinLock<Option<super::wow_wire::WakeReport>>,
    sleep_enabled: AtomicBool,
    sleep_identity: IrqSafeSpinLock<Option<narf_net::native_emission::Lifetime>>,
    monitor_capable: AtomicBool,
    /// `operating_channel::slot` mask (2.4GHz primary n = bit n, 5GHz from
    /// bit 16) of 20MHz primaries with a current signed full program
    /// (channel1 = base N52B; others N52C). Sampled at activation.
    channels: core::sync::atomic::AtomicU64,
    /// Bands with a signed-admitted 40/80MHz operating channel the station
    /// may offer its wide capability on (bit0 2.4GHz, bit1 5GHz, bit2 an
    /// RTL8852C 5GHz 160MHz channel; requires the HT program). Sampled at
    /// activation; 0 advertises no width.
    wide: core::sync::atomic::AtomicU8,
    /// RTL8852C 6GHz primaries (bit `(primary - 1) / 4`) with an admitted
    /// signed 20MHz record under some power context, sampled at activation
    /// only under the WMM/HT/HE programs (6GHz is HE-only). 0 advertises,
    /// scans and joins no 6GHz channel.
    six: core::sync::atomic::AtomicU64,
    fragments_capable: AtomicBool,
    desired: Arc<super::monitor::Desired>,
    selection: super::monitor::Selection,
    registration: IrqSafeSpinLock<Option<narf_net::iface::OpenStopEvent>>,
    monitor_admin: IrqSafeSpinLock<Option<narf_net::iface::OpenStopEvent>>,
    capture: IrqSafeSpinLock<Option<monitor::Capture>>,
    /// RTL8852B AP owner composable on this generation (sampled at
    /// activation, before any station owner exists).
    ap_capable: AtomicBool,
    /// Host AP session (`interface_ap.rs`); never held across an await.
    ap: IrqSafeSpinLock<super::ap_host::Host>,
    /// Synchronous AP control serialization (`reserve_ap_control`).
    ap_serial: Arc<narf_wireless::ap_control::ExclusiveControl>,
}
struct SleepWake(Arc<super::irq::Line>);
impl alloc::task::Wake for SleepWake {
    fn wake(self: Arc<Self>) {
        self.0.raise();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.raise();
    }
}
struct SleepTarget<I: Io>(alloc::sync::Weak<Device<I>>);
impl<I: Io> core::fmt::Debug for SleepTarget<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Rtw89SleepOriginalTarget")
    }
}
impl<I: Io + 'static> narf_net::iface::OpenStopTarget for SleepTarget<I> {
    fn transition(&self, event: narf_net::iface::OpenStopEvent) {
        // Capture current original registration before native locks. This
        // weak denial observation grants no RF/wake/admin operation.
        let identity = event.native_identity();
        let Some(device) = self.0.upgrade() else {
            return;
        };
        if event.name() != device.name
            || event.original_snapshot().mac != device.local
            || !event.current()
        {
            return;
        }
        // The concrete target was installed only on this original registration;
        // rebind clears it. Retain its actual current transition, never a fresh
        // name lookup, so later metadata controls can observe its sealed epoch.
        *device.registration.lock() = Some(event.clone());
        let identity = identity.filter(|token| {
            token.watch(core::task::Waker::from(Arc::new(SleepWake(
                device.line.clone(),
            ))))
        });
        if device.monitor_selected() {
            if !event.up() {
                device.retire_capture();
                device.admission.close();
            }
            *device.monitor_admin.lock() = Some(event.clone());
        }
        *device.sleep_identity.lock() = identity;
        device.line.raise();
    }
}
/// Polled-mode worker period (no MSI binding).
const POLL_MS: u64 = 1;
/// Interrupt-mode safety period. Station timers (authentication/association
/// retries, EAPOL timeouts) are millisecond-granular host state; RX/RPQ
/// progress itself is interrupt-driven.
const IRQ_FALLBACK_MS: u64 = 10;
impl<I: Io> core::fmt::Debug for Device<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8852bDevice")
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
        self.link(None, false);
    }
}
impl<I: Io + 'static> Device<I> {
    /// Triggered scan with its `NL80211_ATTR_SCAN_FLAGS`.
    async fn scan_flagged(
        &self,
        request: ScanRequest,
        flags: narf_wireless::scan::ScanFlags,
    ) -> Result<Vec<BssInfo>, WirelessError> {
        let six_admitted = self.six.load(Ordering::Acquire);
        let dwell = scan_dwell(&request, six_admitted != 0)?;
        let (channels, six_frequencies) = split_scan(
            &request,
            self.channels.load(Ordering::Acquire),
            six_admitted,
        )?;
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
        let address = match (&request.random_mac, request.active) {
            (Some(random), true) => Some(random_scan_address(random)?),
            _ => None,
        };
        let probe = || {
            request.active.then(|| station::Probe {
                ssids: request.ssids.clone(),
                ies: request.extra_ies.clone(),
                address,
                random_sn: flags.random_sn,
            })
        };
        let result = async {
            if !channels.is_empty() {
                owner.station_scan_channels(&channels, dwell, probe).await?;
            }
            if !six_frequencies.is_empty() {
                // cfg80211 `cfg80211_scan_6ghz`: colocated APs from the
                // 2.4/5GHz results (RNR), then PSC/target planning.
                let colocated: Vec<narf_wireless::scan::ColocatedAp> = owner
                    .station_candidates()
                    .iter()
                    .filter(|c| c.bss.band != Some(narf_wireless::association::channel::Band::Ghz6))
                    .flat_map(|c| {
                        narf_wireless::scan::parse_colocated_aps(&c.bss.information_elements)
                    })
                    .collect();
                let six_request = with_frequencies(&request, six_frequencies, Vec::new());
                let planned = narf_wireless::scan::plan_6ghz_scan(&six_request, &colocated, None);
                let admitted = owner.io.station_six_ghz_channels()?;
                let six: Vec<_> = planned
                    .frequencies_mhz
                    .iter()
                    .filter_map(|&f| six_frequency_primary(f))
                    .filter_map(|primary| {
                        // One power context per primary, an active one first.
                        admitted
                            .iter()
                            .filter(|c| c.primary == primary)
                            .max_by_key(|c| c.active)
                            .copied()
                    })
                    .collect();
                if !six.is_empty() {
                    owner
                        .station_scan_six_ghz(&six, dwell, |c| probe().filter(|_| c.active))
                        .await?;
                }
            }
            Ok::<_, station::Error>(owner.station_candidates())
        }
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
                frequency_mhz: c.bss.frequency_mhz().unwrap_or(0),
                bssid: c.bss.bssid,
                ssid: c.bss.ssid,
                channel: u32::from(c.bss.channel),
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
    pub(super) fn bind_sleep_target(this: &Arc<Self>) -> bool {
        let Some(snapshot) = narf_net::iface::snapshot_all()
            .into_iter()
            .find(|entry| entry.name == this.name)
        else {
            return false;
        };
        *this.registration.lock() = narf_net::iface::OpenStopEvent::observe(&snapshot);
        let target = Arc::new(SleepTarget(Arc::downgrade(this)));
        if !narf_net::iface::set_open_stop_target(&snapshot, target.clone()) {
            return false;
        }
        // Rebind may preserve an existing administrative UP without an event.
        // Observe only that same sealed registration, after installation and
        // outside native/provider locks; never toggle/rebind an old owner.
        if snapshot.link_up {
            if let Some(event) = narf_net::iface::OpenStopEvent::observe(&snapshot) {
                narf_net::iface::OpenStopTarget::transition(target.as_ref(), event);
            }
        }
        true
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
                backlog: Default::default(),
            }),
            name: name.into(),
            local,
            published: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            deliveries: AtomicUsize::new(0),
            withdrawal: AtomicU8::new(0),
            activating: AtomicBool::new(false),
            admitted: AtomicBool::new(false),
            up: AtomicBool::new(false),
            port: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            metadata: IrqSafeSpinLock::new(()),
            rx: IrqSafeSpinLock::new(Some(consumer)),
            tx: IrqSafeSpinLock::new(Some(producer)),
            line: super::irq::Line::new(),
            interrupts: AtomicBool::new(false),
            sleep_capable: AtomicBool::new(false),
            wow_capable: AtomicBool::new(false),
            wow_armed: AtomicBool::new(false),
            wowlan: IrqSafeSpinLock::new(None),
            wakeup: IrqSafeSpinLock::new(None),
            sleep_enabled: AtomicBool::new(false),
            sleep_identity: IrqSafeSpinLock::new(None),
            monitor_capable: AtomicBool::new(false),
            channels: core::sync::atomic::AtomicU64::new(CHANNEL1),
            wide: core::sync::atomic::AtomicU8::new(0),
            six: core::sync::atomic::AtomicU64::new(0),
            fragments_capable: AtomicBool::new(false),
            desired: super::monitor::Desired::new(),
            selection: super::monitor::Selection {
                mode: 2,
                generation: 1,
                primary: 1,
            },
            registration: IrqSafeSpinLock::new(None),
            monitor_admin: IrqSafeSpinLock::new(None),
            capture: IrqSafeSpinLock::new(None),
            ap_capable: AtomicBool::new(false),
            ap: IrqSafeSpinLock::new(super::ap_host::Host::default()),
            ap_serial: Arc::new(narf_wireless::ap_control::ExclusiveControl::new()),
        }
    }
    /// Bind MSI delivery to this shell's worker after the station started.
    /// On failure the worker keeps its polled period.
    pub(super) async fn arm_interrupts(&self) -> Result<u8, Error> {
        let mut storage = self.lifecycle.retained.lock().await;
        if self.closed() {
            return Err(Error::State);
        }
        let owner = storage.as_mut().ok_or(Error::State)?;
        let vector = owner.station_irq(&self.line)?;
        self.interrupts.store(true, Ordering::Release);
        self.line.raise();
        Ok(vector)
    }
    /// Live AP EDCA updates need awaited H2C receipts, so the worker applies
    /// them outside the synchronous drain.
    pub(super) async fn apply_edca(&self) {
        let pending = self
            .lifecycle
            .retained
            .try_lock()
            .and_then(|owner| owner.as_ref().map(|o| o.station_edca_pending()))
            .unwrap_or(false);
        if !pending || self.closed() {
            return;
        }
        let mut storage = self.lifecycle.retained.lock().await;
        let Some(owner) = storage.as_mut() else {
            return;
        };
        if owner.station_apply_edca().await.is_err() {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
        }
    }
    pub(super) fn interrupts(&self) -> bool {
        self.interrupts.load(Ordering::Acquire) && !self.closed()
    }
    pub(super) fn line(&self) -> &Arc<super::irq::Line> {
        &self.line
    }
    /// One worker period: drain, then sleep until an MSI/TX kick or the
    /// mode's fallback period.
    pub(super) async fn service_once(&self) {
        if self.wow_armed.load(Ordering::Acquire) {
            // The WoW image owns the radio until `wow_resume`.
            let seen = self.line.raised();
            let _ =
                narf_time::timeout(narf_time::Deadline::after_ms(POLL_MS), self.line.wait(seen))
                    .await;
            return;
        }
        if self.ap_selected() {
            self.ap_service().await;
            let seen = self.line.raised();
            let _ =
                narf_time::timeout(narf_time::Deadline::after_ms(POLL_MS), self.line.wait(seen))
                    .await;
            return;
        }
        if self.monitor_selected() {
            self.monitor_service().await;
            let seen = self.line.raised();
            let _ =
                narf_time::timeout(narf_time::Deadline::after_ms(POLL_MS), self.line.wait(seen))
                    .await;
            return;
        }
        // Line movement is a scheduling hint. Actual original source/native
        // work decides whether RF wake is necessary; own consumed DONE MSIs
        // must not force a wake/enter cycle.
        let sleeping = self.sleep_service(false, false).await;
        if !sleeping {
            self.drain();
            self.apply_edca().await;
        }
        let mut sleeping = self.sleep_service(true, false).await;
        // Receipt baseline follows own awaited transition work, then a final
        // actual IRQ/HCI/host/source check. Work before the sample is caught
        // by that check; raises after it remain newer than this wait.
        let seen = self.line.raised();
        if sleeping {
            sleeping = self.sleep_service(false, false).await;
        }
        let period = if sleeping {
            100
        } else if self.interrupts() {
            IRQ_FALLBACK_MS
        } else {
            POLL_MS
        };
        let _ =
            narf_time::timeout(narf_time::Deadline::after_ms(period), self.line.wait(seen)).await;
    }
    pub(super) async fn sleep_service(&self, allow_enter: bool, kicked: bool) -> bool {
        if !self.sleep_capable.load(Ordering::Acquire) || self.wow_armed.load(Ordering::Acquire) {
            return false;
        }
        let identity = self.sleep_identity.lock().clone();
        let mut storage = self.lifecycle.retained.lock().await;
        let Some(owner) = storage.as_mut() else {
            return false;
        };
        let queued = self.rings.try_lock().is_none_or(|mut rings| {
            if rings.pending.is_none() {
                rings.pending = rings.next(self.local, owner.station_qos_all());
            }
            rings.pending.is_some() || rings.backlog.iter().any(|q| !q.is_empty())
        });
        let enabled = self.sleep_enabled.load(Ordering::Acquire) && !self.closed();
        let force = kicked || queued || owner.station_edca_pending() || !enabled;
        let idle = !queued && (allow_enter || owner.station_sleep_blocked());
        match owner
            .station_sleep_service(identity, enabled, idle, force, &self.admission)
            .await
        {
            Ok(sleeping) => sleeping,
            Err(_) => {
                self.close();
                false
            }
        }
    }
    /// The retained cfg80211 WoWLAN configuration and last wake report,
    /// handed to the next generation's shell.
    pub(super) fn wowlan(
        &self,
    ) -> (
        Option<narf_wireless::WowlanConfig>,
        Option<super::wow_wire::WakeReport>,
    ) {
        (self.wowlan.lock().clone(), *self.wakeup.lock())
    }
    pub(super) fn restore_wowlan(
        &self,
        config: Option<narf_wireless::WowlanConfig>,
        wakeup: Option<super::wow_wire::WakeReport>,
    ) {
        *self.wowlan.lock() = config;
        *self.wakeup.lock() = wakeup;
    }
    /// The last resume's wake reason (driver accessor; the shared contract
    /// has no `ieee80211_report_wowlan_wakeup` event, iwlwifi.md 3.80).
    pub(super) fn wakeup(&self) -> Option<super::wow_wire::WakeReport> {
        *self.wakeup.lock()
    }
    /// mac80211 `ieee80211_suspend` -> `rtw89_ops_suspend` with WoWLAN:
    /// refuse host control and packets, wake the station out of LPS, then
    /// `rtw89_wow_suspend` while the retained mutex is held. `Ok(false)`:
    /// not eligible (no configuration, not associated/settled, WoW not
    /// composed) and nothing was touched; `Err`: the owner failed and the
    /// caller must take the cold path (this shell is closed).
    pub(super) async fn wow_suspend(&self) -> Result<bool, ()> {
        let Some(config) = self.wowlan.lock().clone() else {
            return Ok(false);
        };
        if !self.wow_capable.load(Ordering::Acquire)
            || self.closed()
            || !self.admitted.load(Ordering::Acquire)
            || self.wow_armed.load(Ordering::Acquire)
        {
            return Ok(false);
        }
        let identity = self.sleep_identity.lock().clone();
        let mut storage = self.lifecycle.retained.lock().await;
        let Some(owner) = storage.as_mut() else {
            return Ok(false);
        };
        if owner.station_peer().is_none() || !owner.station_ready() {
            return Ok(false);
        }
        self.wow_armed.store(true, Ordering::Release);
        self.admitted.store(false, Ordering::Release);
        if let Some(mut rings) = self.rings.try_lock() {
            rings.clear();
        }
        *self.wakeup.lock() = None;
        // `rtw89_wow_leave_ps(true)`: leave LPS before the TRX halt.
        if self.sleep_capable.load(Ordering::Acquire)
            && owner
                .station_sleep_service(identity, false, false, true, &self.admission)
                .await
                .is_err()
        {
            drop(storage);
            self.close();
            return Err(());
        }
        if owner
            .station_wow_suspend(&config, &self.admission)
            .await
            .is_err()
        {
            drop(storage);
            self.close();
            return Err(());
        }
        Ok(true)
    }
    /// `rtw89_ops_resume` -> `rtw89_wow_resume`. Success reopens host
    /// control and packets over the same association; any error (including
    /// a disconnect or unknown wake reason) closes this shell for the cold
    /// path, which regenerates the station.
    pub(super) async fn wow_resume(&self) -> Result<(), ()> {
        if !self.wow_armed.load(Ordering::Acquire) {
            return Err(());
        }
        let result = {
            let mut storage = self.lifecycle.retained.lock().await;
            match storage.as_mut() {
                Some(owner) => {
                    let (report, result) = owner.station_wow_resume(&self.admission).await;
                    *self.wakeup.lock() = report;
                    result.is_ok() && !self.closed() && owner.station_peer().is_some()
                }
                None => false,
            }
        };
        if !result {
            self.close();
            return Err(());
        }
        self.wow_armed.store(false, Ordering::Release);
        self.admitted.store(true, Ordering::Release);
        self.line.raise();
        Ok(())
    }
    pub(super) fn closed(&self) -> bool {
        self.admission.closed()
    }
    pub(super) fn admission(&self) -> Admission {
        self.admission.clone()
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
        let monitor_capable = self
            .lifecycle
            .retained
            .lock()
            .await
            .as_mut()
            .ok_or(Error::State)?
            .io
            .monitor_capable()?;
        self.monitor_capable
            .store(monitor_capable, Ordering::Release);
        // No station owner exists yet: the AP owner is exclusive with it.
        let ap_capable = self
            .lifecycle
            .retained
            .lock()
            .await
            .as_mut()
            .ok_or(Error::State)?
            .io
            .ap_allowed()
            .is_ok();
        self.ap_capable.store(ap_capable, Ordering::Release);
        // Admitted primaries; a failed sample keeps only channel1.
        let channels = self
            .lifecycle
            .retained
            .lock()
            .await
            .as_mut()
            .ok_or(Error::State)?
            .io
            .station_channels()
            .unwrap_or(CHANNEL1);
        self.channels.store(channels | CHANNEL1, Ordering::Release);
        // Wide bands: an admitted 40/80MHz record under the HT/WMM programs
        // (`station::associate` offers the wide capability only then); a
        // failed sample advertises none.
        let wide = {
            let mut retained = self.lifecycle.retained.lock().await;
            let io = &mut retained.as_mut().ok_or(Error::State)?.io;
            let programs = io.station_wmm_allowed().unwrap_or(false)
                && io.station_ht_allowed().unwrap_or(false);
            let profiles = if programs {
                io.station_wide_channels().unwrap_or_default()
            } else {
                Vec::new()
            };
            // bit3 (only beside a band bit): one RF path (RTL8851B), the
            // NSS1 VHT body.
            let one_stream = if io.station_single_stream() { 8 } else { 0 };
            let mask = profiles.iter().fold(0u8, |mask, profile| {
                // bit2: an admitted 5GHz 160MHz profile (RTL8852C only;
                // RTL8852B `admitted_wide` never lists one).
                let c160 = if profile.width() == super::operating_channel::Width::Mhz160 {
                    4
                } else {
                    0
                };
                mask | c160 | if profile.is_5ghz() { 2 } else { 1 }
            });
            if mask != 0 {
                mask | one_stream
            } else {
                0
            }
        };
        self.wide.store(wide, Ordering::Release);
        // 6GHz: an admitted RTL8852C 20MHz record under the HE programs
        // (`station::six_ghz_join` requires them); a failed sample admits none.
        let six = {
            let mut retained = self.lifecycle.retained.lock().await;
            let io = &mut retained.as_mut().ok_or(Error::State)?.io;
            let programs = io.station_wmm_allowed().unwrap_or(false)
                && io.station_ht_allowed().unwrap_or(false)
                && io.station_he_allowed().unwrap_or(false);
            if programs {
                io.station_six_ghz_channels()
                    .unwrap_or_default()
                    .iter()
                    .fold(0u64, |mask, channel| mask | six_bit(channel.primary))
            } else {
                0
            }
        };
        self.six.store(six, Ordering::Release);
        if self.monitor_selected() {
            if !monitor_capable {
                return Err(Error::State);
            }
            self.admission.run(|| {
                self.admitted.store(true, Ordering::Release);
                Ok(())
            })?;
            attempt.armed = false;
            self.line.raise();
            return Ok(());
        }
        if self.ap_selected() {
            // Radio Ready without a station owner; START_AP composes the AP.
            if !ap_capable {
                return Err(Error::State);
            }
            self.admission.run(|| {
                self.admitted.store(true, Ordering::Release);
                Ok(())
            })?;
            attempt.armed = false;
            self.line.raise();
            return Ok(());
        }
        self.lifecycle
            .start_station(self.environment.clone(), self.admission.clone())
            .await?;
        let sleep_capable = self
            .lifecycle
            .retained
            .lock()
            .await
            .as_mut()
            .ok_or(Error::State)?
            .station_sleep_capable()?;
        self.sleep_capable.store(sleep_capable, Ordering::Release);
        let wow_capable = self
            .lifecycle
            .retained
            .lock()
            .await
            .as_mut()
            .is_some_and(|owner| owner.station_wow_capable());
        self.wow_capable.store(wow_capable, Ordering::Release);
        let fragments_capable = {
            let mut storage = self.lifecycle.retained.lock().await;
            let owner = storage.as_mut().ok_or(Error::State)?;
            let capable = owner.io.station_fragments_allowed()?;
            owner.station_fragment_policy(capable.then(|| self.desired.clone()));
            capable
        };
        self.fragments_capable
            .store(fragments_capable, Ordering::Release);
        self.admission.run(|| {
            self.admitted.store(true, Ordering::Release);
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
    }
    fn link(&self, peer: Option<[u8; 6]>, port: bool) {
        self.link_inner(peer, port, false);
    }
    fn link_inner(&self, peer: Option<[u8; 6]>, port: bool, retire: bool) {
        let _metadata = self.metadata.lock();
        if self.retired.load(Ordering::Acquire) {
            return;
        }
        if retire {
            self.retired.store(true, Ordering::Release);
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
        if was && !up && !self.ap_selected() {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }
    fn control_ready(&self) -> Result<(), WirelessError> {
        if self.monitor_selected() || self.ap_selected() {
            Err(WirelessError::NotSupported)
        } else if self.closed() {
            Err(WirelessError::HardwareError)
        } else if !self.admitted.load(Ordering::Acquire) {
            Err(WirelessError::Busy)
        } else {
            Ok(())
        }
    }
    pub(super) fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if self.ap_selected() {
            return self.ap_enqueue(bytes, meta);
        }
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
                .map_err(|_| super::power::Error::Access)?;
            let mut frame = Frame::new(memory, bytes.len() as u32);
            frame.payload_mut().copy_from_slice(bytes);
            frame.set_tx_meta(meta);
            // Re-sample the retained PCI/calibration/policy authority at
            // queue publication, after allocation and the initial check.
            // Native DMA publication independently checks again.
            owner
                .station_check()
                .map_err(|_| super::power::Error::Access)?;
            self.tx
                .lock()
                .as_mut()
                .ok_or(super::power::Error::Terminal)?
                .try_send(frame)
                .map_err(|_| super::power::Error::Terminal)
        });
        if result.is_ok() {
            self.line.raise();
        }
        if result == Err(super::power::Error::Access) {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
        }
        result.map_err(|_| ())
    }
    fn progress(&self) -> Vec<Vec<u8>> {
        if self.monitor_selected() {
            return Vec::new();
        }
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
            self.interrupts.store(false, Ordering::Release);
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
        if owner.station_sleep_blocked() {
            return Vec::new();
        }
        let result = (|| -> Result<Vec<Vec<u8>>, Error> {
            owner.station_fragment_policy(
                self.fragments_capable
                    .load(Ordering::Acquire)
                    .then(|| self.desired.clone()),
            );
            let frames = owner.station_poll()?;
            self.link(owner.station_peer(), owner.station_ready());
            if self.closed() {
                rings.clear();
                return Ok(Vec::new());
            }
            if owner.station_peer().is_none() {
                rings.clear();
                return Ok(frames);
            }
            if rings.pending.is_none() {
                rings.pending = rings.next(self.local, owner.station_qos_all());
            }
            if owner.station_ready() && rings.pending.is_some() {
                let qos_all = owner.station_qos_all();
                let result = owner.station_send_prefix(&rings.prefix(qos_all));
                match result {
                    Ok(count) => rings.consumed(count, qos_all),
                    Err(Error::Busy) | Err(Error::Transport(super::packet_core::Error::Busy)) => {}
                    Err(error) => return Err(error),
                }
            }
            self.link(owner.station_peer(), owner.station_ready());
            self.admission.run(|| {
                for bytes in &frames {
                    if let Ok(memory) =
                        narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                    {
                        let mut frame = Frame::new(memory, bytes.len() as u32);
                        frame.payload_mut().copy_from_slice(bytes);
                        let _ = rings.rx.try_send(frame);
                    }
                }
                Ok(())
            })?;
            Ok(frames)
        })();
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
        if self.ap_selected() {
            return self.ap_drain();
        }
        let frames = self.progress();
        let progressed = !frames.is_empty();
        // All retained-owner/ring/admission guards have dropped before the
        // stack can synchronously answer ARP/ND through this enqueue callback.
        for mut frame in frames {
            let Some(_delivery) = self.begin_delivery() else {
                break;
            };
            narf_net::iface::on_rx_frame_from(&self.name, &mut frame);
        }
        progressed
    }
    fn begin_delivery(&self) -> Option<Delivery<'_, I>> {
        let _metadata = self.metadata.lock();
        if self.retired.load(Ordering::Acquire) || self.closed() {
            return None;
        }
        self.deliveries.fetch_add(1, Ordering::AcqRel);
        Some(Delivery(self))
    }
    fn finish_withdrawal(&self) {
        if self.deliveries.load(Ordering::Acquire) != 0 {
            return;
        }
        let action = self.withdrawal.load(Ordering::Acquire);
        if !matches!(action, 1 | 2)
            || self
                .withdrawal
                .compare_exchange(action, 3, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        if action != 2 || !narf_net::iface::retire_for_rebind(&self.name) {
            narf_net::iface::unregister(&self.name);
        }
        super::endpoints::remove(self as *const Self as *const ());
        self.withdrawal.store(4, Ordering::Release);
        self.line.raise();
    }
    /// Old stack delivery holds its name until callback return. Retirement
    /// never waits with an IRQ lock held, and a same-name generation starts
    /// only after all old callbacks have left.
    pub(super) async fn wait_withdrawn(&self) {
        while matches!(self.withdrawal.load(Ordering::Acquire), 1..=3) {
            self.environment.pause().await;
        }
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn refresh_fragment_model(&self) -> bool {
        let capable = self
            .lifecycle
            .retained
            .try_lock()
            .and_then(|mut storage| {
                let owner = storage.as_mut()?;
                let capable = owner.io.station_fragments_allowed().ok()?;
                owner.station_fragment_policy(capable.then(|| self.desired.clone()));
                Some(capable)
            })
            .unwrap_or(false);
        self.fragments_capable.store(capable, Ordering::Release);
        capable
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn delivery_for_test(&self) -> impl Drop + '_ {
        self.begin_delivery().expect("live fixture ingress")
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn admit_for_test(&self) {
        self.published.store(true, Ordering::Release);
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
    fn current_iftype(&self) -> u32 {
        self.desired.snapshot().mode
    }
    fn set_iftype(&self, mode: u32) -> Result<(), WirelessError> {
        self.select_mode(mode)
    }
    fn validate_monitor_flags(&self, flags: u32) -> Result<(), WirelessError> {
        if super::monitor_wire::flags(flags) {
            Ok(())
        } else {
            Err(WirelessError::NotSupported)
        }
    }
    fn set_monitor_channel(
        &self,
        channel: narf_wireless::monitor::Channel,
    ) -> Result<(), WirelessError> {
        let original = self
            .original_snapshot()
            .ok_or(WirelessError::HardwareError)?;
        if original.link_up {
            return Err(WirelessError::Busy);
        }
        // Exact fixed-channel metadata can be acknowledged on the retiring
        // original shell after SET_INTERFACE. No native readiness/RF change is
        // claimed; only its fresh monitor generation may earn capture.
        if self.desired.snapshot().mode != super::monitor_wire::IFTYPE
            || !self.published.load(Ordering::Acquire)
            || self.retired.load(Ordering::Acquire)
        {
            return Err(WirelessError::Busy);
        }
        // Only a signed-admitted primary (the advertised set) is accepted;
        // the fresh monitor generation retunes to it before any capture.
        let primary = super::monitor_wire::channel(channel)
            .filter(|primary| {
                station::channel_admitted(self.channels.load(Ordering::Acquire), *primary)
            })
            .ok_or(WirelessError::NotSupported)?;
        let before = self.desired.snapshot();
        let selected = self
            .desired
            .select_monitor_primary(primary)
            .ok_or(WirelessError::Busy)?;
        if selected != before {
            // Like a role change: retire this shell's admission so the
            // supervisor fences it and starts a generation on `primary`.
            self.close();
            self.line.raise();
        }
        Ok(())
    }

    fn fragmentation_threshold(&self) -> Option<u32> {
        (self.fragments_capable.load(Ordering::Acquire)
            && self.desired.current(self.selection)
            && self.selection.mode == 2
            && !self.closed())
        .then(|| self.desired.fragment_threshold())
    }
    fn set_fragmentation_threshold(&self, threshold: u32) -> Result<(), i32> {
        let threshold = super::fragment_wire::threshold(threshold).ok_or(-22)?;
        if self.fragmentation_threshold().is_none() {
            return Err(-95);
        }
        // Queries/callbacks finish outside the publication/metadata locks.
        let allowed = {
            let mut storage = self.lifecycle.retained.try_lock().ok_or(-16)?;
            storage
                .as_mut()
                .ok_or(-19)?
                .io
                .station_fragments_allowed()
                .map_err(|_| -5)?
        };
        if !allowed || self.original_snapshot().is_none() {
            return Err(-19);
        }
        self.admission
            .run(|| {
                if self.closed()
                    || !self
                        .desired
                        .set_fragment_threshold(self.selection, threshold)
                {
                    return Err(super::power::Error::Terminal);
                }
                Ok(())
            })
            .map_err(|_| -19)?;
        self.line.raise();
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
    /// `NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR` (`rtw89_core_register_hw`).
    fn supports_scan_random_mac(&self) -> bool {
        true
    }
    /// `NL80211_EXT_FEATURE_SCAN_RANDOM_SN` (`rtw89_core_register_hw`).
    fn supports_scan_random_sn(&self) -> bool {
        true
    }
    /// `RTW89_SCANOFLD_MAX_SSID`.
    fn max_scan_ssids(&self) -> u8 {
        8
    }
    /// `RTW89_SCANOFLD_MAX_IE_LEN`.
    fn max_scan_ie_len(&self) -> u16 {
        512
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        if !self.link_up() {
            return None;
        }
        let bytes = self.bssid.load(Ordering::Acquire).to_le_bytes();
        (bytes[7] != 0).then(|| bytes[..6].try_into().unwrap())
    }
    /// CCMP-128 data plus host BIP-CMAC-128 for PMF group management.
    fn cipher_suites(&self) -> &'static [u32] {
        &[0x000fac04, 0x000fac06]
    }

    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.lifecycle
            .retained
            .try_lock()?
            .as_ref()?
            .station_information_elements(bssid)
    }
    /// The wide station capability (`station_control::local_ht40`, and on
    /// 5GHz `local_vht80`, or `local_vht160` when an RTL8852C 160MHz channel
    /// is admitted) of a band with an admitted 40/80MHz operating
    /// channel: core.c `rtw89_init_ht_cap`/`rtw89_init_vht_cap` as restricted
    /// for this profile. Bands without one advertise nothing (no width is
    /// promised that no signed record can program).
    fn phy_capabilities(&self, band: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        let wide = self.wide.load(Ordering::Acquire);
        let ht = super::station_control::local_ht40()?.capability_body();
        match band {
            2400 if wide & 1 != 0 => Some(narf_wireless::iface::PhyCapabilities { ht, vht: None }),
            5000 if wide & 2 != 0 => Some(narf_wireless::iface::PhyCapabilities {
                ht,
                vht: Some(
                    if wide & 4 != 0 {
                        super::station_control::local_vht160()?
                    } else if wide & 8 != 0 {
                        super::station_control::local_vht80_1ss()?
                    } else {
                        super::station_control::local_vht80()?
                    }
                    .capability_body(),
                ),
            }),
            _ => None,
        }
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.local,
            bands: {
                // Only signed-admitted 20MHz primaries, per band; the 5GHz
                // band is advertised only when one of its primaries is
                // admitted (rtw89 core.c `rtw89_core_set_supported_band`
                // registers `rtw89_sband_5ghz` for 5GHz-capable chips).
                let admitted = self.channels.load(Ordering::Acquire);
                let mut bands = vec![WirelessBand {
                    freq_mhz: 2400,
                    channels: (1..=13u8)
                        .filter(|channel| station::channel_admitted(admitted, *channel))
                        .map(u32::from)
                        .collect(),
                }];
                let five: Vec<u32> = super::operating_channel::GHZ5
                    .into_iter()
                    .filter(|channel| station::channel_admitted(admitted, *channel))
                    .map(u32::from)
                    .collect();
                if !five.is_empty() {
                    bands.push(WirelessBand {
                        freq_mhz: 5000,
                        channels: five,
                    });
                }
                // `rtw89_sband_6ghz` only with an admitted 6GHz record.
                let six = six_primaries(self.six.load(Ordering::Acquire));
                if !six.is_empty() {
                    bands.push(WirelessBand {
                        freq_mhz: 6000,
                        channels: six.into_iter().map(u32::from).collect(),
                    });
                }
                bands
            },
            modes: WirelessModes::STATION
                | if self.monitor_capable.load(Ordering::Acquire) {
                    WirelessModes::MONITOR
                } else {
                    WirelessModes::empty()
                }
                // core.c `rtw89_core_register_hw`: interface_modes AP.
                | if self.ap_capable.load(Ordering::Acquire) {
                    WirelessModes::AP
                } else {
                    WirelessModes::empty()
                },
            // HT/VHT only with an advertised wide body (`phy_capabilities`).
            hw_caps: HwCaps {
                ht_supported: self.wide.load(Ordering::Acquire) != 0,
                vht_supported: self.wide.load(Ordering::Acquire) & 2 != 0,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    /// `rtw_wowlan_stub_8852b` (`wow_wire::support`), only when this
    /// generation composed the whole WoW path (RTL8852B, an image without
    /// `WOW_CPUIO_RX`): security CAM, keep-alive, firmware swap, TRX
    /// halt/restart and the system-PM branch.
    fn wowlan_support(&self) -> Option<narf_wireless::WowlanSupport> {
        self.wow_capable
            .load(Ordering::Acquire)
            .then(super::wow_wire::support)
    }
    /// `rtw89_ops_set_wakeup` + cfg80211 `wiphy->wowlan_config`: validated
    /// against the stub and the station address before it is retained;
    /// suspend re-validates (`rtw89_wow_set_wakeups`).
    fn set_wowlan(&self, config: Option<narf_wireless::WowlanConfig>) -> Result<(), i32> {
        if !self.wow_capable.load(Ordering::Acquire) {
            return Err(narf_wireless::EOPNOTSUPP);
        }
        if let Some(config) = &config {
            super::wow_wire::validate(config, self.local).map_err(|_| 22)?;
        }
        *self.wowlan.lock() = config;
        Ok(())
    }
    fn wowlan_config(&self) -> Option<narf_wireless::WowlanConfig> {
        self.wowlan.lock().clone()
    }
    fn power_save_default(&self) -> Option<bool> {
        self.sleep_capable
            .load(Ordering::Acquire)
            .then(|| self.sleep_enabled.load(Ordering::Acquire))
    }
    fn set_power_save(&self, enabled: bool) -> Result<(), i32> {
        if !self.sleep_capable.load(Ordering::Acquire) {
            return Err(-95);
        }
        self.sleep_enabled.store(enabled, Ordering::Release);
        self.line.raise();
        Ok(())
    }
    // Host AP (`interface_ap.rs`, `ap_host.rs`): advertised only when this
    // generation composes the RTL8852B AP owner. rtw89 `WIPHY_FLAG_AP_UAPSD`
    // (core.c `rtw89_core_register_hw`) is backed by the wired host AP PS
    // owner (`ap_ps.rs`); `uapsd_max_sp_len = SP_ALL` has no nl80211 form,
    // and each peer's own Max SP is honoured.
    fn supports_ap(&self) -> bool {
        self.ap_capable.load(Ordering::Acquire)
    }
    fn supports_ap_uapsd(&self) -> bool {
        self.supports_ap()
    }
    fn supports_ap_userspace_mlme(&self) -> bool {
        self.supports_ap()
    }
    fn supports_ap_authenticator(&self) -> bool {
        self.supports_ap()
    }
    fn supports_control_port_no_preauth(&self) -> bool {
        self.supports_ap()
    }
    fn supports_control_port_tx_status(&self) -> bool {
        self.supports_ap()
    }
    // Native AP controls (`interface_ap.rs`). Only the selected AP role of
    // a live generation has a control generation.
    fn ap_control_generation(&self) -> Option<core::num::NonZeroU64> {
        self.ap_generation()
    }
    fn reserve_ap_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.ap_serial.try_reserve().map(Some)
    }
    fn ap_station_macs(&self) -> Vec<[u8; 6]> {
        self.ap
            .lock()
            .peers()
            .iter()
            .map(|peer| peer.addr)
            .collect()
    }
    fn ap_station_info(&self, peer: [u8; 6]) -> Option<narf_wireless::StationInfo> {
        self.ap
            .lock()
            .peer(peer)
            .map(|_| narf_wireless::StationInfo::default())
    }
    async fn start_ap_with_settings_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<(), WirelessError> {
        self.ap_start(authority, config, settings).await
    }
    async fn start_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        config: narf_wireless::ApConfig,
    ) -> Result<(), WirelessError> {
        self.ap_start(authority, config, Default::default()).await
    }
    async fn stop_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
    ) -> Result<(), WirelessError> {
        self.ap_stop(authority).await
    }
    async fn set_beacon_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        _probe_resp: Option<Vec<u8>>,
    ) -> Result<(), WirelessError> {
        // No probe-response offload: hostapd answers probes itself.
        self.ap_set_beacon(authority, head, tail).await
    }
    async fn add_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        station: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.ap_add_station(authority, station).await
    }
    async fn set_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        station: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.ap_set_station(authority, station).await
    }
    async fn del_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        peer: Option<[u8; 6]>,
        _reason: u16,
    ) -> Result<(), WirelessError> {
        self.ap_del_station(authority, peer).await
    }
    async fn add_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        key: narf_wireless::OwnedKey,
    ) -> Result<(), i32> {
        self.ap_add_key(authority, key).await
    }
    async fn del_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), i32> {
        self.ap_del_key(authority, index, pairwise, peer).await
    }
    async fn key_sequence_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<narf_wireless::KeySequence, i32> {
        self.ap_key_sequence(authority, index, pairwise, peer).await
    }
    async fn default_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        index: u8,
        unicast: bool,
        multicast: bool,
        management: bool,
        beacon: bool,
    ) -> Result<(), i32> {
        self.ap_default_key(authority, index, unicast, multicast, management, beacon)
            .await
    }
    async fn mgmt_tx_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        _cookie: u64,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        self.ap_management(authority, request).await
    }
    async fn register_mgmt_frame_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        frame_type: u16,
        match_prefix: Vec<u8>,
    ) -> Result<(), WirelessError> {
        self.ap_register_frame(authority, frame_type, match_prefix)
            .await
    }
    async fn tx_control_port_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        request: narf_wireless::ControlPortTxRequest,
    ) -> Result<bool, i32> {
        self.ap_control_tx(authority, request).await
    }
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        self.scan_flagged(request, narf_wireless::scan::ScanFlags::default())
            .await
    }
    async fn scan_with_flags(
        &self,
        request: ScanRequest,
        flags: narf_wireless::scan::ScanFlags,
    ) -> Result<Vec<BssInfo>, WirelessError> {
        self.scan_flagged(request, flags).await
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        self.control_ready()?;
        let primary = u8::try_from(request.channel).map_err(|_| WirelessError::NotSupported)?;
        let six = six_frequency_primary(request.frequency_mhz)
            .filter(|&p| p == primary && self.six.load(Ordering::Acquire) & six_bit(p) != 0);
        if six.is_none()
            && (!station::channel_admitted(self.channels.load(Ordering::Acquire), primary)
                || Some(request.frequency_mhz) != primary_frequency(primary))
        {
            return Err(WirelessError::NotSupported);
        }
        let credential = match request.security {
            SecurityConfig::Open => station::Credential::Open,
            SecurityConfig::Wpa2 { psk } => station::Credential::Psk(Zeroizing::new(psk)),
            // SAE password limits as wpa_supplicant/cfg80211 (1..=128).
            SecurityConfig::Wpa3 { password } if (1..=128).contains(&password.len()) => {
                station::Credential::Sae(Zeroizing::new(password))
            }
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
            .station_associate(request.bssid, &request.ssid, credential, &request.ie)
            .await;
        attempt.armed = false;
        if self.closed() {
            self.link(None, false);
            return Err(WirelessError::HardwareError);
        }
        self.link(owner.station_peer(), owner.station_ready());
        result.map_err(error)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        if self.monitor_selected() {
            return Err(WirelessError::NotSupported);
        }
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
/// Caller probe IEs: well-formed TLVs within `max_scan_ie_len`
/// (`RTW89_SCANOFLD_MAX_IE_LEN`), not duplicating driver-generated IEs.
fn probe_ies_valid(mut ies: &[u8]) -> bool {
    if ies.len() > 512 {
        return false;
    }
    while !ies.is_empty() {
        let Some(&[id, length]) = ies.get(..2) else {
            return false;
        };
        if matches!(id, 0 | 1 | 3 | 50) || ies.len() < 2 + usize::from(length) {
            return false;
        }
        ies = &ies[2 + usize::from(length)..];
    }
    true
}
/// `get_random_mask_addr`: random bits outside `mask`, `addr` bits inside.
fn random_scan_address(
    random: &narf_wireless::scan::ScanRandomMac,
) -> Result<[u8; 6], WirelessError> {
    let mut bytes = [0u8; 6];
    narf_crypto::try_fill_random_bytes(&mut bytes).map_err(|_| WirelessError::HardwareError)?;
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = *byte & !random.mask[i] | random.addr[i] & random.mask[i];
    }
    Ok(bytes)
}
const CHANNEL1: u64 = 1 << 1;
/// cfg80211 `ieee80211_channel_to_freq_khz` for a typed 2.4GHz (1..=13) or
/// 5GHz 20MHz primary.
fn primary_frequency(primary: u8) -> Option<u32> {
    if (1..=13).contains(&primary) {
        Some(2407 + 5 * u32::from(primary))
    } else if station::ghz5(primary) {
        Some(5000 + 5 * u32::from(primary))
    } else {
        None
    }
}
/// cfg80211 `ieee80211_freq_khz_to_channel` restricted to typed primaries.
fn frequency_primary(frequency: u32) -> Option<u8> {
    let channel = match frequency {
        2412..=2472 => (frequency - 2407) / 5,
        5180..=5885 => (frequency - 5000) / 5,
        _ => return None,
    };
    let primary = u8::try_from(channel).ok()?;
    (primary_frequency(primary) == Some(frequency)).then_some(primary)
}
/// Requested 20MHz primaries (channels plus frequencies, 2.4GHz then 5GHz
/// ascending, deduplicated); empty means every admitted primary like
/// cfg80211's all-channels default. Every one must have a current signed
/// program, so an unadmitted channel is refused before any retune or
/// transmission.
fn scan_channels(request: &ScanRequest, admitted: u64) -> Result<Vec<u8>, WirelessError> {
    let slot = |primary: u8| {
        super::operating_channel::slot(primary)
            .filter(|_| primary_frequency(primary).is_some())
            .map(|bit| 1u64 << bit)
            .ok_or(WirelessError::NotSupported)
    };
    let mut mask = 0u64;
    for &channel in &request.channels {
        let primary = u8::try_from(channel).map_err(|_| WirelessError::NotSupported)?;
        mask |= slot(primary)?;
    }
    for &frequency in &request.frequencies_mhz {
        mask |= slot(frequency_primary(frequency).ok_or(WirelessError::NotSupported)?)?;
    }
    if mask == 0 {
        mask = admitted | CHANNEL1;
    }
    if mask & !(admitted | CHANNEL1) != 0 {
        return Err(WirelessError::NotSupported);
    }
    Ok(super::operating_channel::primaries(mask).collect())
}
/// Bit of an RTL8852C 6GHz 20MHz primary in `Device::six` (0 otherwise).
fn six_bit(primary: u8) -> u64 {
    if super::operating_channel_c::is_6ghz_primary(primary) {
        1u64 << ((primary - 1) / 4)
    } else {
        0
    }
}
/// The 6GHz primaries of a `Device::six` mask, ascending.
fn six_primaries(mask: u64) -> Vec<u8> {
    (0..59u8)
        .filter(|bit| mask & (1u64 << bit) != 0)
        .map(|bit| 1 + 4 * bit)
        .collect()
}
/// cfg80211 `ieee80211_freq_khz_to_channel` on `NL80211_BAND_6GHZ`
/// (5955 + 5 * (n - 1)) restricted to typed 20MHz primaries.
fn six_frequency_primary(frequency: u32) -> Option<u8> {
    let channel = u8::try_from(frequency.checked_sub(5950)? / 5).ok()?;
    (5950 + 5 * u32::from(channel) == frequency
        && super::operating_channel_c::is_6ghz_primary(channel))
    .then_some(channel)
}
/// The 2.4/5GHz primaries (`scan_channels`) and the 6GHz frequencies of a
/// request. An empty request covers every admitted channel of every band
/// (cfg80211's all-channels default); a requested 6GHz frequency must be
/// admitted, like the 2.4/5GHz ones, and `channels` names 2.4/5GHz only.
fn split_scan(
    request: &ScanRequest,
    admitted: u64,
    six: u64,
) -> Result<(Vec<u8>, Vec<u32>), WirelessError> {
    if request.channels.is_empty() && request.frequencies_mhz.is_empty() {
        let all = six_primaries(six)
            .into_iter()
            .map(|p| 5950 + 5 * u32::from(p))
            .collect();
        return Ok((scan_channels(request, admitted)?, all));
    }
    let mut six_frequencies = Vec::new();
    let mut legacy_frequencies = Vec::new();
    for &frequency in &request.frequencies_mhz {
        match six_frequency_primary(frequency) {
            Some(primary) if six & six_bit(primary) != 0 => {
                if !six_frequencies.contains(&frequency) {
                    six_frequencies.push(frequency);
                }
            }
            Some(_) => return Err(WirelessError::NotSupported),
            None => legacy_frequencies.push(frequency),
        }
    }
    let legacy = with_frequencies(request, legacy_frequencies, request.channels.clone());
    let channels = if legacy.channels.is_empty() && legacy.frequencies_mhz.is_empty() {
        Vec::new()
    } else {
        scan_channels(&legacy, admitted)?
    };
    Ok((channels, six_frequencies))
}
/// `request` with only `frequencies_mhz`/`channels` replaced.
fn with_frequencies(
    request: &ScanRequest,
    frequencies: Vec<u32>,
    channels: Vec<u32>,
) -> ScanRequest {
    ScanRequest {
        ssids: request.ssids.clone(),
        frequencies_mhz: frequencies,
        channels,
        active: request.active,
        random_mac: request.random_mac,
        colocated_6ghz: request.colocated_6ghz,
        duration_tu: request.duration_tu,
        duration_mandatory: request.duration_mandatory,
        extra_ies: request.extra_ies.clone(),
    }
}
fn scan_dwell(request: &ScanRequest, six: bool) -> Result<u64, WirelessError> {
    // cfg80211 `nl80211_parse_random_mac`: the mask must keep the group bit
    // from a unicast base address.
    if request
        .random_mac
        .as_ref()
        .is_some_and(|r| r.mask[0] & 1 == 0 || r.addr[0] & 1 != 0)
        || request.colocated_6ghz && !six
        || (!request.active && !request.extra_ies.is_empty())
        || !probe_ies_valid(&request.extra_ies)
        || request.active && request.ssids.len() > 8
        || request.ssids.len() > 32
        || request.ssids.iter().any(|s| s.len() > 32)
    {
        return Err(WirelessError::NotSupported);
    }
    match request.duration_tu {
        Some(n @ 1..=1000) => Ok((u64::from(n) * 1024).div_ceil(1000)),
        Some(_) => Err(WirelessError::InvalidArgs),
        None if request.duration_mandatory => Err(WirelessError::InvalidArgs),
        None => Ok(200),
    }
}
impl<I: Io + 'static> super::endpoints::Endpoint for Device<I> {
    fn send(&self, b: &[u8], m: narf_net::TxMeta) -> Result<(), ()> {
        self.enqueue(b, m)
    }
    fn drain(&self) -> bool {
        Device::drain(self)
    }
}
pub(super) fn publish<I: Io + 'static>(device: Arc<Device<I>>) -> Result<(), Error> {
    if device.retired.load(Ordering::Acquire) || device.published.load(Ordering::Acquire) {
        return Err(Error::State);
    }
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
    let bound = Device::bind_sleep_target(&device);
    if !bound {
        super::endpoints::remove(Arc::as_ptr(&device) as *const ());
        narf_net::iface::unregister(&device.name);
        narf_net::registry().unregister(&device.name);
        return Err(Error::State);
    }
    narf_net::iface::set_driver_info(&device.name, "rtw8852b", None, String::new());
    narf_net::iface::set_offloads(&device.name, narf_net::OffloadCapabilities::default());
    device.link(None, false);
    narf_net::iface::install_rx_drain(super::endpoints::drain);
    narf_wireless::registry::register(device.clone());
    device.published.store(true, Ordering::Release);
    narf_scheduler::spawn(async move {
        while device.published.load(Ordering::Acquire) {
            device.service_once().await;
        }
    });
    Ok(())
}
/// Linux `rtw89_core_unregister` for removal: close admission and carrier,
/// unregister from the wireless/net registries and release this generation's
/// endpoint. Idempotent; the drain worker exits after its pass.
pub(super) fn withdraw<I: Io + 'static>(device: &Device<I>) {
    withdraw_inner(device, false);
}
/// Generation reset: as [`withdraw`], but the netdev is retired for rebind
/// (`narf_net::iface::retire_for_rebind`) so the next generation's shell
/// re-registers the same interface.
pub(super) fn withdraw_keep_name<I: Io + 'static>(device: &Device<I>) -> String {
    withdraw_inner(device, true);
    device.name.clone()
}
fn withdraw_inner<I: Io + 'static>(device: &Device<I>, keep: bool) {
    // A late withdrawal of an old shell may share its name with a rebound
    // generation. Close only its own admission before testing publication.
    device.admission.close();
    if !device.published.swap(false, Ordering::AcqRel) {
        return;
    }
    device.link_inner(None, false, true);
    narf_wireless::registry::unregister(&device.name);
    narf_net::registry().unregister(&device.name);
    // Preserve the name/dispatch reservation while an old ingress callback
    // is running. Its final Drop completes removal without holding locks
    // across the stack or waiting inside this synchronous hook.
    device
        .withdrawal
        .store(if keep { 2 } else { 1 }, Ordering::Release);
    device.finish_withdrawal();
    device.line.raise();
}
/// Whether the shell is still registered.
pub(super) fn published<I: Io + 'static>(device: &Device<I>) -> bool {
    device.published.load(Ordering::Acquire)
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

#[path = "interface_ap.rs"]
mod ap;
#[path = "interface_monitor.rs"]
mod monitor;

#[cfg(any(test, feature = "kernel-test"))]
mod six_ghz_scan_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// 6GHz frequency/primary mapping and the 2.4/5 + 6GHz split of a
    /// cfg80211 scan request: only admitted 6GHz primaries are scanned or
    /// advertised; an unadmitted requested 6GHz frequency is refused.
    fn smoke_rtw8852c_6ghz_scan_split_admits_only_signed_primaries() -> TestResult {
        let six = six_bit(5) | six_bit(37);
        if six_frequency_primary(5975) != Some(5)
            || six_frequency_primary(6135) != Some(37)
            || six_frequency_primary(5960).is_some()
            || six_frequency_primary(2412).is_some()
            || six_primaries(six) != [5, 37]
            || six_bit(2) != 0
        {
            return TestResult::Fail("6GHz frequency/primary mapping");
        }
        let request = |frequencies: Vec<u32>| ScanRequest {
            ssids: Vec::new(),
            frequencies_mhz: frequencies,
            channels: Vec::new(),
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        };
        // Everything: every admitted channel of both bands.
        if split_scan(&request(Vec::new()), CHANNEL1, six) != Ok((vec![1], vec![5975, 6135])) {
            return TestResult::Fail("6GHz all-channels scan");
        }
        // 6GHz only: no 2.4/5GHz retune.
        if split_scan(&request(vec![6135]), CHANNEL1, six) != Ok((Vec::new(), vec![6135])) {
            return TestResult::Fail("6GHz-only scan");
        }
        // Mixed, and an unadmitted 6GHz primary.
        if split_scan(&request(vec![2412, 5975]), CHANNEL1, six) != Ok((vec![1], vec![5975]))
            || split_scan(&request(vec![5995]), CHANNEL1, six).is_ok()
            || split_scan(&request(vec![5975]), CHANNEL1, 0).is_ok()
        {
            return TestResult::Fail("6GHz mixed/unadmitted scan");
        }
        // Colocated (RNR) 6GHz scanning is offered only with a 6GHz record.
        let mut colocated = request(Vec::new());
        colocated.colocated_6ghz = true;
        if scan_dwell(&colocated, false).is_ok() || scan_dwell(&colocated, true).is_err() {
            return TestResult::Fail("6GHz colocated scan gating");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw8852c_6ghz_scan_split_admits_only_signed_primaries
    );
}

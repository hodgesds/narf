// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained legacy RAW station shared by async control and bounded native
//! packet drains. DHCP never depends on a worker, executor poll or block_on.
use super::{
    control::Hif,
    htt_runtime::HttMemory,
    wmi_boot::HostMemory,
    wmi_runtime::{self, Radio},
};
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessConfig, WirelessError,
    WirelessNetIface,
};
type Error = wmi_runtime::Error;
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
enum Policy {
    Installed,
    #[cfg(any(test, feature = "kernel-test"))]
    Model(Arc<dyn Fn() -> Option<narf_wireless::reg::RegulatoryDomain> + Send + Sync>),
}
impl Policy {
    fn current(&self) -> Result<narf_wireless::reg::RegulatoryDomain, Error> {
        match self {
            Self::Installed => narf_wireless::reg::db::get_domain(),
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Model(current) => current(),
        }
        .ok_or(Error::Unsupported)
    }
}
struct State {
    rx: narf_ipc::Producer<Frame, RX_RING_N>,
    tx: narf_ipc::Consumer<Frame, TX_RING_N>,
    pending: Option<Frame>,
}
impl State {
    fn clear(&mut self) {
        self.pending = None;
        for _ in 0..TX_RING_N {
            if !matches!(self.tx.try_recv(), Ok(Some(_))) {
                break;
            }
        }
    }
}
pub(super) struct Device<T: Hif + HostMemory + HttMemory> {
    pub(super) radio: Arc<Mutex<Radio<T>>>,
    state: Mutex<State>,
    name: String,
    generation: u64,
    ps_supported: bool,
    ps_request: AtomicU8,
    frequencies: Vec<u16>,
    mac: [u8; 6],
    policy: Policy,
    up: AtomicBool,
    closed: AtomicBool,
    publication: IrqSafeSpinLock<()>,
    #[cfg(any(test, feature = "kernel-test"))]
    close_on_progress: AtomicBool,
    bssid: AtomicU64,
    rx: IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>>,
}
impl<T: Hif + HostMemory + HttMemory> core::fmt::Debug for Device<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath10kDevice")
            .field("name", &self.name)
            .field("up", &self.up)
            .finish_non_exhaustive()
    }
}
struct Attempt<'a> {
    device: &'a dyn HostClose,
    armed: bool,
}
trait HostClose: Sync {
    fn close(&self);
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.device.close();
        }
    }
}
impl<T: Hif + HostMemory + HttMemory + Send + 'static> HostClose for Device<T> {
    fn close(&self) {
        let _publication = self.publication.lock();
        self.closed.store(true, Ordering::Release);
        self.publish_link(None);
    }
}
impl<T: Hif + HostMemory + HttMemory + Send + 'static> Device<T> {
    pub(super) fn new(
        name: &str,
        mac: [u8; 6],
        radio: Arc<Mutex<Radio<T>>>,
        ps_supported: bool,
        frequencies: Vec<u16>,
    ) -> Self {
        Self::with_policy(
            name,
            mac,
            radio,
            Policy::Installed,
            ps_supported,
            frequencies,
        )
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn for_test(
        name: &str,
        mac: [u8; 6],
        radio: Arc<Mutex<Radio<T>>>,
        current: impl Fn() -> Option<narf_wireless::reg::RegulatoryDomain> + Send + Sync + 'static,
    ) -> Self {
        let ps_supported = radio
            .try_lock()
            .is_some_and(|radio| radio.power_save_supported());
        let frequencies = radio
            .try_lock()
            .map(|radio| radio.configured_channels().to_vec())
            .unwrap_or_default();
        Self::with_policy(
            name,
            mac,
            radio,
            Policy::Model(Arc::new(current)),
            ps_supported,
            frequencies,
        )
    }
    fn with_policy(
        name: &str,
        mac: [u8; 6],
        radio: Arc<Mutex<Radio<T>>>,
        policy: Policy,
        ps_supported: bool,
        frequencies: Vec<u16>,
    ) -> Self {
        let (rx, consumer) = narf_ipc::channel();
        let (producer, tx) = narf_ipc::channel();
        Self {
            radio,
            state: Mutex::new(State {
                rx,
                tx,
                pending: None,
            }),
            name: name.into(),
            ps_supported,
            frequencies,
            // Submit the advertised awake default before first carrier.
            ps_request: AtomicU8::new(u8::from(ps_supported)),
            generation: NEXT_GENERATION
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_add(1)
                })
                .expect("ath10k interface generations exhausted"),
            mac,
            policy,
            up: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            publication: IrqSafeSpinLock::new(()),
            #[cfg(any(test, feature = "kernel-test"))]
            close_on_progress: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            rx: IrqSafeSpinLock::new(Some(consumer)),
            tx: IrqSafeSpinLock::new(Some(producer)),
        }
    }
    fn link(&self, peer: Option<[u8; 6]>) {
        let _publication = self.publication.lock();
        self.publish_link(peer);
    }
    // Caller holds publication; close and a previously sampled peer can never
    // interleave their BSSID/carrier/netdev metadata writes.
    fn publish_link(&self, peer: Option<[u8; 6]>) {
        let peer = peer.filter(|_| !self.closed.load(Ordering::Acquire));
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
        narf_net::iface::set_link_metadata(&self.name, up, None, None);
        if was && !up {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }
    pub(super) fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if self.closed.load(Ordering::Acquire)
            || !self.up.load(Ordering::Acquire)
            || !admitted(bytes, self.mac)
            || meta.csum_l4.is_some()
            || meta.tso_mss.is_some()
            || meta.vlan_tag.is_some()
        {
            return Err(());
        }
        let memory = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        let mut frame = Frame::new(memory, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        frame.set_tx_meta(meta);
        self.tx
            .lock()
            .as_mut()
            .ok_or(())?
            .try_send(frame)
            .map_err(|_| ())
    }
    pub(super) fn enqueue_generation(
        &self,
        generation: u64,
        bytes: &[u8],
        meta: narf_net::TxMeta,
    ) -> Result<(), ()> {
        if generation != self.generation {
            return Err(());
        }
        self.enqueue(bytes, meta)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn generation_for_test(&self) -> u64 {
        self.generation
    }
    pub(super) fn retire_host(&self) {
        self.close();
        if let Some(mut state) = self.state.try_lock() {
            state.clear();
        }
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        // Reserve while still registered: another family's wlan%d allocation
        // must never take this name between unregister and reservation.
        narf_net::iface::reserve_name(&self.name);
        narf_net::iface::unregister(&self.name);
    }
    pub(super) fn request_power_save(&self, enabled: bool) -> Result<(), i32> {
        if !self.ps_supported {
            return Err(-95);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(-19);
        }
        self.ps_request
            .store(if enabled { 2 } else { 1 }, Ordering::Release);
        Ok(())
    }
    pub(super) async fn apply_power_save(&self) -> Result<(), WirelessError> {
        let request = self.ps_request.load(Ordering::Acquire);
        if request == 0 {
            return Ok(());
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let Some(mut radio) = self.radio.try_lock() else {
            return Ok(());
        };
        let enabled = request == 2;
        if radio.station_link().is_none() {
            return Ok(());
        }
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        if let Err(cause) = self
            .policy
            .current()
            .and_then(|domain| radio.check_data_policy(&domain))
        {
            radio.fail_station_data();
            return Err(error(cause));
        }
        if radio.submitted_power_save() == Some(enabled) {
            attempt.armed = false;
            return Ok(());
        }
        let result = radio
            .set_station_power_save(enabled, || {
                if self.closed.load(Ordering::Acquire) {
                    return Err(Error::Failed);
                }
                self.policy.current()
            })
            .await;
        if let Err(cause) = result {
            radio.fail_station_data();
            return Err(error(cause));
        }
        attempt.armed = false;
        Ok(())
    }
    fn progress(&self) -> Vec<Vec<u8>> {
        let Some(mut radio) = self.radio.try_lock() else {
            return Vec::new();
        };
        let Some(mut state) = self.state.try_lock() else {
            return Vec::new();
        };
        if self.closed.load(Ordering::Acquire) {
            // Host closure precedes the control path's async mutex acquire.
            // A worker here must not poison an otherwise healthy radio before
            // that path can send native DOWN/DELETE/STOP.
            state.clear();
            return Vec::new();
        }
        #[cfg(any(test, feature = "kernel-test"))]
        if self.close_on_progress.swap(false, Ordering::AcqRel) {
            self.close();
        }
        let result = {
            // Serialize actual native publication with host close, including
            // EAPOL generated by RX progress. No await or stack callback is here.
            let _publication = self.publication.lock();
            if self.closed.load(Ordering::Acquire) {
                state.clear();
                return Vec::new();
            }
            if !radio.has_station_data() {
                return Vec::new();
            }
            (|| {
                // Sampling under the publication gate precedes consuming any
                // host TX or publishing generated security replies to native
                // DMA. A changed ceiling must match the programmed channel.
                let domain = self.policy.current()?;
                let frames = radio.poll_ethernet_now(&domain)?;
                self.publish_link(radio.station_link().map(|link| link.bssid));
                if state.pending.is_none() {
                    for _ in 0..16 {
                        let Ok(Some(frame)) = state.tx.try_recv() else {
                            break;
                        };
                        if admitted(frame.payload(), self.mac)
                            && frame.tx_meta().csum_l4.is_none()
                            && frame.tx_meta().tso_mss.is_none()
                            && frame.tx_meta().vlan_tag.is_none()
                        {
                            state.pending = Some(frame);
                            break;
                        }
                    }
                }
                if let Some(frame) = state.pending.as_ref() {
                    match radio.begin_ethernet(&domain, frame.payload()) {
                        Ok(_) => state.pending = None,
                        Err(Error::Htt(super::htt_runtime::Error::Busy)) => {}
                        Err(error) => return Err(error),
                    }
                }
                for bytes in &frames {
                    if let Ok(memory) =
                        narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                    {
                        let mut frame = Frame::new(memory, bytes.len() as u32);
                        frame.payload_mut().copy_from_slice(bytes);
                        let _ = state.rx.try_send(frame);
                    }
                }
                Ok(frames)
            })()
        };
        match result {
            Ok(frames) => {
                if self.closed.load(Ordering::Acquire) {
                    Vec::new()
                } else {
                    frames
                }
            }
            Err(_) => {
                radio.fail_station_data();
                state.clear();
                self.close();
                Vec::new()
            }
        }
    }
    pub(super) fn drain(&self) -> bool {
        let frames = self.progress();
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        let progressed = !frames.is_empty();
        for mut frame in frames {
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            narf_net::iface::on_rx_frame_from(&self.name, &mut frame);
        }
        progressed
    }
    pub(super) async fn scan(
        &self,
        mut request: ScanRequest,
    ) -> Result<Vec<BssInfo>, WirelessError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if request.random_mac.is_some()
            || request.colocated_6ghz
            || request.duration_tu.is_some()
            || request.duration_mandatory
            || (!request.active && !request.extra_ies.is_empty())
            || request.ssids.len() > wmi_runtime::MAX_SCAN_SSIDS
            || request.ssids.iter().any(|s| s.len() > 32)
        {
            return Err(WirelessError::NotSupported);
        }
        wmi_runtime::validate_probe_ies(&request.extra_ies).map_err(|err| match err {
            Error::Malformed => WirelessError::InvalidArgs,
            err => error(err),
        })?;
        if request.active && request.ssids.is_empty() {
            request
                .ssids
                .try_reserve(1)
                .map_err(|_| error(Error::NoMemory))?;
            request.ssids.push(Vec::new());
        }
        let implicit = request.frequencies_mhz.is_empty() && request.channels.is_empty();
        let mut frequencies = if !request.frequencies_mhz.is_empty() {
            request
                .frequencies_mhz
                .iter()
                .map(|f| u16::try_from(*f).map_err(|_| WirelessError::InvalidArgs))
                .collect::<Result<Vec<_>, _>>()?
        } else if !request.channels.is_empty() {
            request
                .channels
                .iter()
                .map(|ch| {
                    u8::try_from(*ch)
                        .ok()
                        .and_then(narf_wireless::association::channel::frequency)
                        .and_then(|f| u16::try_from(f).ok())
                        .ok_or(WirelessError::InvalidArgs)
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            self.frequencies.clone()
        };
        if frequencies.is_empty()
            || frequencies.iter().any(|f| {
                !super::regulatory::Permission::profile_frequency(*f)
                    || !self.frequencies.contains(f)
            })
        {
            return Err(WirelessError::NotSupported);
        }
        let mut radio = self.radio.lock().await;
        if radio.prepared_peer().is_some() {
            return Err(WirelessError::Busy);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let domain = self.policy.current().map_err(error)?;
        if implicit {
            frequencies.retain(|f| {
                receive_permission(&domain, &[*f]).is_ok()
                    && (!request.active || radio.active_frequency_allowed(&domain, *f))
            });
        }
        receive_permission(&domain, &frequencies).map_err(error)?;
        let active = if request.active {
            Some(
                radio
                    .prepare_active_scan(&frequencies, &request.ssids, &domain)
                    .and_then(|plan| plan.with_extra_ies(&request.extra_ies))
                    .map_err(error)?,
            )
        } else {
            None
        };
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let report = if let Some(plan) = active {
            radio
                .active_scan(plan, || {
                    if self.closed.load(Ordering::Acquire) {
                        return Err(Error::Failed);
                    }
                    self.policy.current()
                })
                .await
        } else {
            radio.passive_scan(&frequencies).await
        }
        .map_err(error)?;
        let result = report
            .bss
            .into_iter()
            .filter(|b| {
                request.ssids.is_empty()
                    || request.ssids.iter().any(|s| s.is_empty() || *s == b.ssid)
            })
            .map(|b| {
                let secured = b.capability & 16 != 0;
                BssInfo {
                    bssid: b.bssid,
                    ssid: b.ssid,
                    channel: narf_wireless::association::channel::from_frequency(u32::from(
                        b.frequency,
                    ))
                    .map(u32::from)
                    .unwrap_or(0),
                    frequency_mhz: u32::from(b.frequency),
                    rssi: i8::MIN,
                    security: if secured {
                        narf_wireless::scan::BssSecurity::Wpa2
                    } else {
                        narf_wireless::scan::BssSecurity::Open
                    },
                }
            })
            .collect();
        attempt.armed = false;
        Ok(result)
    }
    pub(super) async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        self.associate_inner(request, || {
            let mut nonce = [0; 32];
            narf_crypto::try_fill_random_bytes(&mut nonce)
                .ok()
                .map(|()| nonce)
        })
        .await
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) async fn associate_for_test(
        &self,
        request: AssociateRequest,
        nonce: [u8; 32],
    ) -> Result<(), WirelessError> {
        self.associate_inner(request, || Some(nonce)).await
    }
    async fn associate_inner(
        &self,
        request: AssociateRequest,
        nonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<(), WirelessError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if self.up.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        if u16::try_from(request.frequency_mhz).ok().is_none_or(|f| {
            !super::regulatory::Permission::profile_frequency(f) || !self.frequencies.contains(&f)
        }) || narf_wireless::association::channel::from_frequency(request.frequency_mhz)
            .map(u32::from)
            != Some(request.channel)
        {
            return Err(WirelessError::NotSupported);
        }
        let (mode, pmk) = match request.security {
            SecurityConfig::Open => (narf_wireless::association::SecurityMode::Open, None),
            SecurityConfig::Wpa2 { psk } => (
                narf_wireless::association::SecurityMode::Wpa2Psk,
                Some(zeroize::Zeroizing::new(psk)),
            ),
            _ => return Err(WirelessError::NotSupported),
        };
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let mut radio = self.radio.lock().await;
        self.state.lock().await.clear();
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let domain = self.policy.current().map_err(error)?;
        let permission = radio
            .station_permission(&domain, request.frequency_mhz as u16)
            .map_err(error)?;
        let validate = || {
            if self.closed.load(Ordering::Acquire) {
                return Err(Error::Failed);
            }
            permission.check(&self.policy.current()?)
        };
        wmi_runtime::checked_policy(
            radio.prepare_station_checked(
                &domain,
                request.bssid,
                request.frequency_mhz as u16,
                &validate,
            ),
            &validate,
        )
        .await
        .map_err(error)?;
        wmi_runtime::checked_policy(
            radio.associate_station_checked(&domain, &request.ssid, mode, &request.ie, &validate),
            &validate,
        )
        .await
        .map_err(error)?;
        let link = wmi_runtime::checked_policy(
            radio.start_data_with_nonce_checked(&domain, pmk.as_deref(), nonce, &validate),
            &validate,
        )
        .await
        .map_err(error)?;
        let domain = self.policy.current().map_err(error)?;
        radio.check_data_policy(&domain).map_err(error)?;
        let ps_request = self.ps_request.load(Ordering::Acquire);
        if ps_request != 0 {
            let result = radio
                .set_station_power_save(ps_request == 2, || {
                    if self.closed.load(Ordering::Acquire) {
                        return Err(Error::Failed);
                    }
                    self.policy.current()
                })
                .await;
            if let Err(cause) = result {
                radio.fail_station_data();
                return Err(error(cause));
            }
        }
        if self.closed.load(Ordering::Acquire) {
            radio.fail_station_data();
            return Err(WirelessError::HardwareError);
        }
        self.link(Some(link.bssid));
        attempt.armed = false;
        Ok(())
    }
    pub(super) async fn disassociate(&self) -> Result<(), WirelessError> {
        self.close();
        let mut radio = self.radio.lock().await;
        self.state.lock().await.clear();
        radio.disconnect_station().await.map(|_| ()).map_err(error)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn close_before_lock_for_test(&self) {
        self.close();
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn close_mid_progress_for_test(&self) {
        self.close_on_progress.store(true, Ordering::Release);
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn stale_link_after_close_for_test(&self, peer: [u8; 6]) {
        self.close();
        self.link(Some(peer));
    }
}
fn receive_permission(
    domain: &narf_wireless::reg::RegulatoryDomain,
    frequencies: &[u16],
) -> Result<(), Error> {
    if !domain.country_code.iter().all(u8::is_ascii_uppercase)
        || frequencies.iter().any(|frequency| {
            let low = u32::from(*frequency) - 10;
            let high = u32::from(*frequency) + 10;
            let mut covering = false;
            for rule in &domain.rules {
                if rule.freq_end_mhz <= low || high <= rule.freq_start_mhz {
                    continue;
                }
                if rule.freq_start_mhz >= rule.freq_end_mhz || rule.max_bandwidth_mhz < 20 {
                    return true;
                }
                covering |= rule.freq_start_mhz <= low && high <= rule.freq_end_mhz;
            }
            !covering
        })
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}
fn admitted(bytes: &[u8], own: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[6..12] == own
        && bytes[..6] != [0; 6]
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && !matches!(
            u16::from_be_bytes([bytes[12], bytes[13]]),
            0x888e | 0x80f3 | 0x8137
        )
}
fn error(value: Error) -> WirelessError {
    match value {
        Error::Unsupported => WirelessError::NotSupported,
        Error::Timeout => WirelessError::Timeout,
        Error::Htt(super::htt_runtime::Error::Busy) => WirelessError::Busy,
        _ => WirelessError::HardwareError,
    }
}
impl<T: Hif + HostMemory + HttMemory + Send + 'static> Interface for Device<T> {
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
        !self.closed.load(Ordering::Acquire) && self.up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
type Native = Device<super::boot::PciBoot>;
static ACTIVE: IrqSafeSpinLock<Option<Arc<Native>>> = IrqSafeSpinLock::new(None);
fn send(generation: u64, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE.lock().clone().ok_or(())?;
    device.enqueue_generation(generation, bytes, meta)
}
/// Remove only this physical generation. Its retired name remains reserved so
/// late old-owner carrier updates cannot address a new driver's registration.
pub(super) fn retire(radio: &Arc<Mutex<Radio<super::boot::PciBoot>>>) {
    let mut active = ACTIVE.lock();
    let Some(device) = active.as_ref().filter(|d| Arc::ptr_eq(&d.radio, radio)) else {
        return;
    };
    let device = device.clone();
    *active = None;
    drop(active);
    device.retire_host();
}
fn drain() -> bool {
    let device = ACTIVE.lock().clone();
    device.is_some_and(|d| d.drain())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Admission {
    Ready,
    PendingAssets,
}
pub(super) fn classify_domain_admission(
    result: Result<narf_wireless::reg::RegulatoryDomain, narf_wireless::reg::policy::Error>,
    has_loader_authority: bool,
) -> Result<Admission, Error> {
    match result {
        Ok(_) => Ok(Admission::Ready),
        Err(narf_wireless::reg::policy::Error::Firmware(
            narf_firmware::FirmwareError::NotFound,
        )) => Ok(Admission::PendingAssets),
        Err(narf_wireless::reg::policy::Error::Authority) if !has_loader_authority => {
            Ok(Admission::PendingAssets)
        }
        Err(_) => Err(Error::Unsupported),
    }
}
fn check_admission() -> Result<Admission, Error> {
    if classify_domain_admission(
        narf_wireless::reg::db::ensure_domain(),
        narf_firmware::trusted_loader_authority().is_some(),
    )? == Admission::PendingAssets
    {
        return Ok(Admission::PendingAssets);
    }
    let Some(root) = narf_net::trusted_net_authority() else {
        return Ok(Admission::PendingAssets);
    };
    root.derive::<narf_capabilities::Write>()
        .map_err(|_| Error::Unsupported)?;
    Ok(Admission::Ready)
}
fn publish_with_mac(
    radio: Arc<Mutex<Radio<super::boot::PciBoot>>>,
    mac: [u8; 6],
    quarantine: &AtomicBool,
    ps_supported: bool,
    frequencies: Vec<u16>,
) -> Result<Arc<Native>, Error> {
    narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Unsupported)?;
    let authority = narf_net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(Error::Unsupported)?;
    let mut active = ACTIVE.lock();
    admit_generation(quarantine, || {
        if active.is_some() {
            return Err(Error::Failed);
        }
        let name = narf_net::iface::reserve_name("wlan%d");
        let device = Arc::new(Device::new(name, mac, radio, ps_supported, frequencies));
        narf_net::registry()
            .register(&authority, Registered(device.clone()))
            .map_err(|_| Error::Unsupported)?;
        *active = Some(device.clone());
        narf_net::iface::register_with_context(name, mac, device.generation, send);
        narf_net::iface::set_link_state(name, false);
        narf_net::iface::set_link_metadata(name, false, None, None);
        narf_net::iface::install_rx_drain(drain);
        narf_wireless::registry::register(device.clone());
        let worker = device.clone();
        narf_scheduler::spawn(async move {
            loop {
                if worker.closed.load(Ordering::Acquire) {
                    break;
                }
                worker.drain();
                let _ = worker.apply_power_save().await;
                narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
            }
        });
        Ok(device)
    })
}
/// Called under ACTIVE for the entire registration transaction, so retirement
/// either prevents publication or observes its complete registered generation.
pub(super) fn admit_generation<R>(
    quarantine: &AtomicBool,
    publish: impl FnOnce() -> Result<R, Error>,
) -> Result<R, Error> {
    if quarantine.load(Ordering::Acquire) {
        return Err(Error::Failed);
    }
    publish()
}
pub(super) fn publish(
    radio: Arc<Mutex<Radio<super::boot::PciBoot>>>,
    quarantine: Arc<AtomicBool>,
) -> Result<Arc<Native>, Error> {
    let r = radio.try_lock().ok_or(Error::Failed)?;
    let mac = r.station_publishable()?;
    let result = publish_with_mac(
        radio.clone(),
        mac,
        &quarantine,
        r.power_save_supported(),
        r.configured_channels()
            .iter()
            .copied()
            .filter(|f| super::regulatory::Permission::profile_frequency(*f))
            .collect(),
    );
    drop(r);
    result
}
pub(super) async fn wait_publish(
    radio: Arc<Mutex<Radio<super::boot::PciBoot>>>,
    quarantine: Arc<AtomicBool>,
) -> Result<Arc<Native>, Error> {
    loop {
        if quarantine.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        {
            let r = radio.lock().await;
            r.station_publishable()?;
        }
        if ACTIVE.lock().is_some() {
            return Err(Error::Failed);
        }
        match check_admission()? {
            Admission::Ready => {
                let r = radio.lock().await;
                let mac = r.station_publishable()?;
                let result = publish_with_mac(
                    radio.clone(),
                    mac,
                    &quarantine,
                    r.power_save_supported(),
                    r.configured_channels()
                        .iter()
                        .copied()
                        .filter(|f| super::regulatory::Permission::profile_frequency(*f))
                        .collect(),
                );
                drop(r);
                return result;
            }
            Admission::PendingAssets => super::firmware::staging_pause().await,
        }
    }
}
#[async_trait::async_trait]
impl WirelessNetIface for Native {
    fn power_save_default(&self) -> Option<bool> {
        self.ps_supported.then_some(false)
    }
    fn set_power_save(&self, enabled: bool) -> Result<(), i32> {
        self.request_power_save(enabled)
    }
    fn max_scan_ssids(&self) -> u8 {
        wmi_runtime::MAX_SCAN_SSIDS as u8
    }
    fn max_scan_ie_len(&self) -> u16 {
        wmi_runtime::MAX_SCAN_IE_LEN
    }
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let b = self.bssid.load(Ordering::Acquire).to_le_bytes();
        (b[7] != 0 && !self.closed.load(Ordering::Acquire)).then(|| b[..6].try_into().unwrap())
    }
    fn cipher_suites(&self) -> &'static [u32] {
        &[0x000fac04]
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.radio.try_lock()?.information_elements(bssid)
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac,
            bands: [2400, 5000]
                .into_iter()
                .filter_map(|band| {
                    let channels: Vec<u32> = self
                        .frequencies
                        .iter()
                        .copied()
                        .filter(|f| {
                            super::regulatory::Permission::profile_frequency(*f)
                                && (*f < 3000) == (band == 2400)
                        })
                        .filter_map(|f| {
                            narf_wireless::association::channel::from_frequency(u32::from(f))
                                .map(u32::from)
                        })
                        .collect();
                    (!channels.is_empty()).then_some(WirelessBand {
                        freq_mhz: band,
                        channels,
                    })
                })
                .collect(),
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    async fn scan(&self, r: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        Device::scan(self, r).await
    }
    async fn associate(&self, r: AssociateRequest) -> Result<(), WirelessError> {
        Device::associate(self, r).await
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        Device::disassociate(self).await
    }
    async fn set_config(&self, _: WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}
struct Registered(Arc<Native>);
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
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}

//! Retained MT76 station interface and bounded network service.
//! Registration requires real NIC/EFUSE/MAC initialization. Packet progress
//! uses the same bounded step from both the executor and synchronous waiters.
use crate::mt7921::firmware_transport::{RadioInfo, ScanBss};
use alloc::sync::Arc;
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use async_trait::async_trait;
use core::sync::atomic::Ordering;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
use narf_ipc::{Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::iface::{HwCaps, WirelessBand, WirelessIfaceInfo, WirelessModes};
use narf_wireless::{
    scan::BssInfo, AssociateRequest, ScanRequest, WirelessConfig, WirelessError, WirelessNetIface,
};

#[path = "iface_ap.rs"]
mod ap;
#[cfg(any(test, feature = "builtin"))]
#[path = "iface_ap_tests.rs"]
pub(crate) mod ap_tests;
#[path = "iface_monitor.rs"]
mod monitor;
#[path = "iface_p2p.rs"]
pub(crate) mod p2p;
#[path = "iface_p2p_go.rs"]
pub(crate) mod p2p_go;
#[path = "iface_p2p_group.rs"]
pub(crate) mod p2p_group;
#[path = "iface_wowlan.rs"]
mod wowlan;

/// Publish physical carrier while preserving operator-controlled IFF_UP.
/// No administrative open/stop callback runs under the caller's driver locks.
/// Shared by production and its composition fixture.
pub(crate) fn publish_link(name: &str, up: bool) -> bool {
    narf_net::iface::set_link_metadata(name, up, None, None)
}

/// Shared by production delivery and native reentrant-callback fixtures.
/// Each callback starts with current authority, releases all native locks,
/// then revalidates before non-reentrant IPC publication or the next frame.
pub(crate) fn deliver_received_batch(
    step: crate::mt7921::firmware_transport::PacketStep,
    mut current: impl FnMut(u64) -> Result<bool, WirelessError>,
    mut callback: impl FnMut(&mut Vec<u8>),
    mut publish: impl FnMut(Vec<u8>, u64) -> Result<(), WirelessError>,
) -> Result<(), WirelessError> {
    for mut data in step.received {
        if !current(step.receive_epoch)? {
            break;
        }
        callback(&mut data);
        if !current(step.receive_epoch)? {
            break;
        }
        publish(data, step.receive_epoch)?;
    }
    Ok(())
}

/// One retained legacy 2.4/5 GHz station, with carrier gated by association.
#[derive(Debug)]
pub struct Mt76Iface {
    name: String,
    radio: RadioInfo,
    p2p_profile: Option<crate::mt7921::firmware_transport::P2pProfile>,
    registration_cap: IrqSafeSpinLock<
        Option<narf_capabilities::Cap<narf_net::NetIface, narf_capabilities::Write>>,
    >,
    p2p_device: IrqSafeSpinLock<Option<Arc<p2p::P2pDeviceIface>>>,
    /// The one concurrent P2P-client group netdev (`NEW_INTERFACE` type 8).
    p2p_group: IrqSafeSpinLock<Option<Arc<p2p_group::P2pGroupIface>>>,
    /// The concurrent P2P GO netdev (one group netdev: client or GO).
    p2p_go: IrqSafeSpinLock<Option<Arc<p2p_go::P2pGoIface>>>,
    vif_slots: IrqSafeSpinLock<crate::mt7921::vif_slots::Slots>,
    scan_cache: IrqSafeSpinLock<Vec<ScanBss>>,
    rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    rx_prod: IrqSafeSpinLock<Option<Producer<Frame, RX_RING_N>>>,
    tx_cons: IrqSafeSpinLock<Option<Consumer<Frame, TX_RING_N>>>,
    associated_bssid: IrqSafeSpinLock<Option<[u8; 6]>>,
    pending_tx: IrqSafeSpinLock<Option<Frame>>,
    control: narf_lib::mutex::Mutex<()>,
    teardown_needed: AtomicBool,
    recovery_attempts: AtomicU32,
    recovery_after_ns: AtomicU64,
    receive_epoch: AtomicU64,
    iftype: AtomicU32,
    ap_generation: AtomicU64,
    ap_serial: Arc<narf_wireless::ap_control::ExclusiveControl>,
    ap_started: AtomicBool,
    ap_owned: AtomicBool,
    ap_host: IrqSafeSpinLock<ap::Host>,
    monitor_channel: IrqSafeSpinLock<Option<narf_wireless::monitor::Channel>>,
    monitor_started: AtomicBool,
    monitor_token: IrqSafeSpinLock<Option<narf_net::iface::MonitorRxToken>>,
    sleeping: AtomicBool,
    /// A positively proven implementation/platform profile for stable
    /// capability reporting. Every actual configuration and handoff still
    /// obtains a fresh native wake-route receipt.
    wake_reported: AtomicBool,
    wowlan: IrqSafeSpinLock<Option<narf_wireless::WowlanConfig>>,
}
impl Mt76Iface {
    /// Build from validated radio identity, without disconnected frame rings.
    pub fn new(name: String, radio: RadioInfo) -> Result<Self, WirelessError> {
        if radio.capabilities.mac == [0; 6]
            || radio.capabilities.mac[0] & 1 != 0
            || radio.capabilities.phy.bands & 3 == 0
        {
            return Err(WirelessError::InvalidArgs);
        }
        Ok(Self {
            name,
            radio,
            p2p_profile: None,
            registration_cap: IrqSafeSpinLock::new(None),
            p2p_device: IrqSafeSpinLock::new(None),
            p2p_group: IrqSafeSpinLock::new(None),
            p2p_go: IrqSafeSpinLock::new(None),
            vif_slots: IrqSafeSpinLock::new(crate::mt7921::vif_slots::Slots::default()),
            scan_cache: IrqSafeSpinLock::new(Vec::new()),
            rx_ring: IrqSafeSpinLock::new(None),
            tx_ring: IrqSafeSpinLock::new(None),
            rx_prod: IrqSafeSpinLock::new(None),
            tx_cons: IrqSafeSpinLock::new(None),
            associated_bssid: IrqSafeSpinLock::new(None),
            pending_tx: IrqSafeSpinLock::new(None),
            control: narf_lib::mutex::Mutex::new(()),
            teardown_needed: AtomicBool::new(false),
            recovery_attempts: AtomicU32::new(0),
            recovery_after_ns: AtomicU64::new(0),
            receive_epoch: AtomicU64::new(0),
            iftype: AtomicU32::new(2),
            ap_generation: AtomicU64::new(1),
            ap_serial: Arc::new(narf_wireless::ap_control::ExclusiveControl::new()),
            ap_started: AtomicBool::new(false),
            ap_owned: AtomicBool::new(false),
            ap_host: IrqSafeSpinLock::new(ap::Host::default()),
            monitor_channel: IrqSafeSpinLock::new(None),
            monitor_started: AtomicBool::new(false),
            monitor_token: IrqSafeSpinLock::new(None),
            sleeping: AtomicBool::new(false),
            wake_reported: AtomicBool::new(false),
            wowlan: IrqSafeSpinLock::new(None),
        })
    }
    /// Legacy 20 MHz channels on firmware-reported bands.
    pub fn bands(&self) -> Vec<WirelessBand> {
        let mut bands = Vec::new();
        if self.radio.capabilities.phy.bands & 1 != 0 {
            bands.push(WirelessBand {
                freq_mhz: 2400,
                channels: (1..=11).collect(),
            });
        }
        if self.radio.capabilities.phy.bands & 2 != 0 {
            bands.push(WirelessBand {
                freq_mhz: 5000,
                channels: crate::mt7921::channel::CHANNELS_5GHZ
                    .into_iter()
                    .map(u32::from)
                    .collect(),
            });
        }
        // mt7921_set_stream_he_caps: the 6 GHz sband exists only with
        // MT_NIC_CAP_6G (and inside has_5ghz).
        if crate::mt7921::six_ghz::qualified(self.radio) {
            bands.push(WirelessBand {
                freq_mhz: 6000,
                channels: crate::mt7921::channel::channels_6ghz()
                    .map(u32::from)
                    .collect(),
            });
        }
        bands
    }

    /// STATION or P2P_CLIENT: mac80211 runs both as a STATION vif
    /// (`ieee80211_setup_sdata`), sharing the native station owner.
    pub(crate) fn station_role(&self) -> bool {
        matches!(self.current_iftype(), 2 | 8)
    }
    /// AP or P2P_GO: one AP vif, `vif->p2p` only selecting the GO BSS type.
    pub(crate) fn ap_role(&self) -> bool {
        matches!(self.current_iftype(), 3 | 9)
    }

    /// Transmit an 802.3 Ethernet frame over the associated wireless datapath.
    pub async fn transmit_frame(&self, frame: &[u8]) -> Result<(), WirelessError> {
        if !self.station_role() {
            return Err(WirelessError::NotSupported);
        }
        if !self.link_up() {
            return Err(WirelessError::Denied);
        }
        {
            use crate::mt7921::firmware_transport::transmit_boot_frame;
            transmit_boot_frame(frame)
                .await
                .map_err(|_| WirelessError::HardwareError)
        }
    }

    /// Negotiate a fresh per-TID originator agreement on this registered
    /// radio under the same control mutex used for scan and association.
    pub async fn negotiate_transmit_ba_tid(&self, tid: u8) -> Result<bool, WirelessError> {
        if tid >= 8 {
            return Err(WirelessError::InvalidArgs);
        }
        let _control = self.control.lock().await;
        if !self.link_up() {
            return Err(WirelessError::Denied);
        }
        use crate::mt7921::firmware_transport::{negotiate_boot_transmit_ba_tid, Error};
        negotiate_boot_transmit_ba_tid(tid)
            .await
            .map_err(|error| match error {
                Error::Bounds => WirelessError::InvalidArgs,
                Error::Busy => WirelessError::Busy,
                Error::Authority => WirelessError::Denied,
                Error::Timeout => WirelessError::Timeout,
                _ => WirelessError::HardwareError,
            })
    }

    /// Restart an originator after real midstream traffic. The next queued
    /// user MPDU supplies the sequence sample; no extra RF traffic is made.
    pub async fn request_transmit_ba_restart_tid(&self, tid: u8) -> Result<(), WirelessError> {
        if tid >= 8 {
            return Err(WirelessError::InvalidArgs);
        }
        let _control = self.control.lock().await;
        if !self.link_up() {
            return Err(WirelessError::Denied);
        }
        use crate::mt7921::firmware_transport::{request_boot_transmit_ba_restart_tid, Error};
        request_boot_transmit_ba_restart_tid(tid)
            .await
            .map_err(|error| match error {
                Error::Bounds => WirelessError::InvalidArgs,
                Error::Busy | Error::EventOverflow => WirelessError::Busy,
                Error::Authority => WirelessError::Denied,
                Error::Timeout => WirelessError::Timeout,
                _ => WirelessError::HardwareError,
            })
    }

    /// Receive an 802.3 Ethernet frame from the wireless datapath.
    pub async fn receive_frame(&self) -> Result<Option<Vec<u8>>, WirelessError> {
        if !self.station_role() {
            return Err(WirelessError::NotSupported);
        }
        if !self.link_up() {
            return Err(WirelessError::Denied);
        }
        {
            use crate::mt7921::firmware_transport::receive_boot_data;
            receive_boot_data()
                .await
                .map_err(|_| WirelessError::HardwareError)
        }
    }

    /// Advance bounded packet work, then service authenticated rekeys. No
    /// IRQ-safe lock survives an await; hardware ownership uses a regular mutex.
    pub async fn poll_data(&self) -> Result<(), WirelessError> {
        // Retained native cleanup is independent of carrier and role. A
        // dropped callback must not strand autonomous AP beaconing.
        match crate::mt7921::firmware_transport::boot_ap::progress() {
            Ok(false) => return Ok(()),
            Ok(true) => (),
            Err(_) if self.ap_owned.load(Ordering::Acquire) => return self.poll_ap().await,
            Err(_) => (),
        }
        if !self.sleeping.load(Ordering::Acquire) && self.poll_p2p().await? {
            return Ok(());
        }
        if !self.sleeping.load(Ordering::Acquire) {
            self.poll_p2p_group().await;
            self.poll_p2p_go().await;
        }
        if self.ap_owned.load(Ordering::Acquire) || self.ap_role() {
            return self.poll_ap().await;
        }
        if self.sleeping.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.current_iftype() == 6 {
            return self.poll_monitor().await;
        }
        {
            if self.teardown_needed.load(Ordering::Acquire) || radio_needs_recovery() {
                let Some(_control) = self.control.try_lock() else {
                    return Ok(());
                };
                self.finish_teardown(false).await?;
            }
            self.drain_network()?;
            if self.link_up() {
                let Some(_control) = self.control.try_lock() else {
                    return Ok(());
                };
                use crate::mt7921::firmware_transport::{service_boot_keys, Error};
                self.refresh_receive_epoch()?;
                match service_boot_keys().await {
                    Ok(()) | Err(Error::Busy) => {}
                    Err(_) => {
                        self.lose_link();
                        return Err(WirelessError::HardwareError);
                    }
                }
                self.refresh_receive_epoch()?;
            }
        }
        Ok(())
    }

    /// The synchronous path never waits on a future or another executor task.
    fn drain_network(&self) -> Result<bool, WirelessError> {
        let progressed = crate::mt7921::firmware_transport::boot_ap::progress()
            .map_err(|_| WirelessError::HardwareError)?;
        if !progressed {
            return Ok(false);
        }
        if self.ap_owned.load(Ordering::Acquire) || self.ap_role() {
            return self.drain_ap_network();
        }
        if !self.link_up() {
            return Ok(false);
        }
        let result = {
            let mut pending = self.pending_tx.lock();
            if pending.is_none() {
                *pending = self.next_tx();
            }
            let result = crate::mt7921::firmware_transport::step_boot_network(
                pending.as_ref().map(Frame::payload),
            );
            if result.as_ref().is_ok_and(|step| step.transmitted) {
                *pending = None;
            }
            result
        };
        let step = match result {
            Ok(step) => step,
            Err(crate::mt7921::firmware_transport::Error::Busy) => return Ok(false),
            Err(_) => {
                self.lose_link();
                return Err(WirelessError::HardwareError);
            }
        };
        self.refresh_receive_epoch()?;
        let progress = step.transmitted || !step.received.is_empty();
        deliver_received_batch(
            step,
            |epoch| self.receive_current(epoch),
            |data| narf_net::iface::on_rx_frame_from(&self.name, data),
            |data, epoch| {
                crate::module_host::capture_receive(&self.name, &data, epoch);
                if let Ok(mut buffer) =
                    narf_io::alloc_coherent(data.len(), narf_lib::id::DomainId::DRIVER_0)
                {
                    buffer.as_mut_slice()[..data.len()].copy_from_slice(&data);
                    let frame = Frame::new(buffer, data.len() as u32);
                    let published =
                        crate::mt7921::firmware_transport::boot_receive_publish(epoch, || {
                            if self.link_up() {
                                self.ensure_receive_epoch(epoch);
                                if let Some(producer) = self.rx_prod.lock().as_mut() {
                                    let _ = producer.try_send(frame);
                                }
                            }
                        });
                    if published.is_err() {
                        self.lose_link();
                        return Err(WirelessError::HardwareError);
                    }
                }
                Ok(())
            },
        )?;
        Ok(progress)
    }

    fn receive_current(&self, epoch: u64) -> Result<bool, WirelessError> {
        if !self.link_up() {
            return Ok(false);
        }
        match crate::mt7921::firmware_transport::boot_receive_current(epoch) {
            Ok(current) => Ok(current),
            Err(_) => {
                self.lose_link();
                Err(WirelessError::HardwareError)
            }
        }
    }
    fn ensure_receive_epoch(&self, epoch: u64) {
        if self.receive_epoch.load(Ordering::Acquire) != epoch {
            let (producer, consumer) = narf_ipc::channel::<Frame, RX_RING_N>();
            *self.rx_ring.lock() = Some(consumer);
            *self.rx_prod.lock() = Some(producer);
            self.receive_epoch.store(epoch, Ordering::Release);
        }
    }
    fn retire_receive_ipc(&self) {
        *self.rx_ring.lock() = None;
        *self.rx_prod.lock() = None;
        self.receive_epoch.store(0, Ordering::Release);
    }
    fn refresh_receive_epoch(&self) -> Result<(), WirelessError> {
        use crate::mt7921::firmware_transport::{boot_refresh_receive_epoch, Error};
        match boot_refresh_receive_epoch(|epoch| {
            if let Some(epoch) = epoch {
                if self.link_up() {
                    self.ensure_receive_epoch(epoch);
                }
            } else {
                self.retire_receive_ipc();
            }
        }) {
            Ok(()) => {}
            Err(Error::Busy) => {}
            Err(_) => {
                self.lose_link();
                return Err(WirelessError::HardwareError);
            }
        }
        Ok(())
    }

    fn next_tx(&self) -> Option<Frame> {
        let mut slot = self.tx_cons.lock();
        let consumer = slot.as_mut()?;
        for _ in 0..16 {
            let frame = consumer.try_recv().ok().flatten()?;
            if transmit_admitted(frame.payload(), self.mac()) {
                return Some(frame);
            }
        }
        None
    }

    fn clear_link(&self) {
        let ap = self.ap_role() || self.ap_owned.load(Ordering::Acquire);
        self.close_ap_host();
        self.close_monitor();
        self.receive_epoch.store(0, Ordering::Release);
        *self.associated_bssid.lock() = None;
        if !ap {
            publish_link(&self.name, false);
        }
        *self.pending_tx.lock() = None;
        *self.tx_ring.lock() = None;
        *self.rx_ring.lock() = None;
        *self.tx_cons.lock() = None;
        *self.rx_prod.lock() = None;
    }

    fn lose_link(&self) {
        let connected = self.station_role() && self.link_up();
        if connected {
            self.teardown_needed.store(true, Ordering::Release);
        }
        self.clear_link();
        if connected {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }

    async fn finish_teardown(&self, operator_request: bool) -> Result<(), WirelessError> {
        if self.teardown_needed.load(Ordering::Acquire) {
            match crate::mt7921::firmware_transport::disassociate_boot_station().await {
                Ok(()) => {
                    self.teardown_needed.store(false, Ordering::Release);
                    self.recovery_attempts.store(0, Ordering::Release);
                    self.recovery_after_ns.store(0, Ordering::Release);
                }
                Err(_) if radio_needs_recovery() => {}
                Err(crate::mt7921::firmware_transport::Error::Busy) => {
                    return Err(WirelessError::Busy)
                }
                Err(_) => return Err(WirelessError::HardwareError),
            }
        }
        if !radio_needs_recovery() {
            return Ok(());
        }
        let now = narf_time::wall::monotonic_ns();
        let attempts = self.recovery_attempts.load(Ordering::Acquire);
        if !operator_request
            && (attempts >= 3 || now < self.recovery_after_ns.load(Ordering::Acquire))
        {
            return Err(WirelessError::Busy);
        }
        self.recovery_attempts
            .store(attempts.saturating_add(1), Ordering::Release);
        let delay = match attempts {
            0 => 1_000_000_000,
            1 => 5_000_000_000,
            _ => 30_000_000_000,
        };
        self.recovery_after_ns
            .store(now.saturating_add(delay), Ordering::Release);
        self.lose_link();
        self.teardown_needed.store(true, Ordering::Release);
        self.scan_cache.lock().clear();
        crate::mt7921::firmware_transport::recover_boot_radio(self.mac())
            .await
            .map_err(|_| WirelessError::HardwareError)?;
        self.sleeping.store(false, Ordering::Release);
        self.teardown_needed.store(false, Ordering::Release);
        self.recovery_attempts.store(0, Ordering::Release);
        self.recovery_after_ns.store(0, Ordering::Release);
        Ok(())
    }

    /// cfg80211 `wiphy_suspend` without WoWLAN: leave the BSS (locally
    /// generated DEAUTH_LEAVING), then the PCIe low-power handoff.
    async fn prepare_suspend(&self) -> Result<(), WirelessError> {
        self.prepare_suspend_target(narf_power::system_pm::SystemSleepState::S3)
            .await
    }

    async fn resume_from_suspend(&self) -> Result<(), WirelessError> {
        let _control = self.control.lock().await;
        suspend_result(crate::mt7921::firmware_transport::resume_boot_radio(self.mac()).await)?;
        self.commit_p2p_stopped();
        if self.ap_owned.load(Ordering::Acquire) {
            self.commit_ap_stopped();
        }
        self.sleeping.store(false, Ordering::Release);
        self.recovery_attempts.store(0, Ordering::Release);
        self.recovery_after_ns.store(0, Ordering::Release);
        Ok(())
    }

    /// Request validation shared by the home station and the concurrent
    /// P2P-client group netdev; returns whether the target is 6 GHz. Runs
    /// before any recovery I/O.
    pub(super) fn validate_join(&self, req: &AssociateRequest) -> Result<bool, WirelessError> {
        let channel = u8::try_from(req.channel).map_err(|_| WirelessError::InvalidArgs)?;
        // A 6 GHz request is identified by its frequency: channel numbers
        // alone collide with 2.4/5 GHz.
        let six = narf_wireless::association::channel::from_frequency_band(req.frequency_mhz)
            == Some((narf_wireless::association::channel::Band::Ghz6, channel));
        if !six && crate::mt7921::channel::frequency(channel) != Some(req.frequency_mhz) {
            return Err(WirelessError::InvalidArgs);
        }
        if six && !crate::mt7921::six_ghz::qualified(self.radio) {
            return Err(WirelessError::NotSupported);
        }
        if req.ssid.is_empty()
            || req.ssid.len() > 32
            || req.bssid == [0; 6]
            || req.bssid[0] & 1 != 0
        {
            return Err(WirelessError::InvalidArgs);
        }
        let protected = match &req.security {
            narf_wireless::SecurityConfig::Open => false,
            narf_wireless::SecurityConfig::Wpa2 { .. }
            | narf_wireless::SecurityConfig::Wpa3 { .. } => true,
            _ => return Err(WirelessError::NotSupported),
        };
        crate::mt7921::association::validate_sme_ies(&req.ie, protected).map_err(|error| {
            match error {
                crate::mt7921::association::Error::InvalidBss => WirelessError::InvalidArgs,
                _ => WirelessError::NotSupported,
            }
        })?;
        Ok(six)
    }

    /// Resolve the cached scan target and the native security owner, and
    /// require a current transmit permission for it.
    pub(super) fn resolve_join(
        &self,
        req: &AssociateRequest,
        security: narf_wireless::SecurityConfig,
        six: bool,
    ) -> Result<(ScanBss, crate::mt7921::association::Security), WirelessError> {
        let security = match security {
            narf_wireless::SecurityConfig::Open => crate::mt7921::association::Security::Open,
            narf_wireless::SecurityConfig::Wpa2 { psk } => {
                crate::mt7921::association::Security::Wpa2Psk { psk }
            }
            // WPA3-Personal: the driver runs SAE (sae_pwe=2) and PMF itself.
            narf_wireless::SecurityConfig::Wpa3 { password } => {
                crate::mt7921::association::Security::Wpa3Sae {
                    password: crate::mt7921::association::SaePassword::new(&password)
                        .ok_or(WirelessError::InvalidArgs)?,
                }
            }
            // No external-supplicant mode: mt7921's firmware path runs the
            // handshake from the PMK (nl80211 never builds this for it).
            narf_wireless::SecurityConfig::External(_) => return Err(WirelessError::NotSupported),
        };
        let bss = self
            .scan_cache
            .lock()
            .iter()
            .find(|b| {
                b.bssid == req.bssid
                    && b.ssid == req.ssid
                    && u32::from(b.channel) == req.channel
                    && crate::mt7921::association::is_six_ghz(b) == six
            })
            .cloned()
            .ok_or(WirelessError::InvalidArgs)?;

        let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| WirelessError::Denied)?;
        if six {
            crate::mt7921::association::TxPermission::from_ap(&domain, self.radio, &bss)
        } else {
            crate::mt7921::association::TxPermission::from_domain(&domain, bss.channel)
        }
        .ok_or(WirelessError::Denied)?;

        Ok((bss, security))
    }

    fn enqueue(&self, bytes: &[u8]) -> Result<(), ()> {
        let admitted = match self.current_iftype() {
            2 | 8 => transmit_admitted(bytes, self.mac()),
            3 | 9 => self.ap_transmit_admitted(bytes),
            _ => false,
        };
        if !admitted {
            return Err(());
        }
        if !self.link_up() {
            return Err(());
        }
        let mut buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        buffer.as_mut_slice()[..bytes.len()].copy_from_slice(bytes);
        self.tx_ring
            .lock()
            .as_mut()
            .ok_or(())?
            .try_send(Frame::new(buffer, bytes.len() as u32))
            .map_err(|_| ())
    }
}

fn suspend_result(
    result: Result<(), crate::mt7921::firmware_transport::Error>,
) -> Result<(), WirelessError> {
    use crate::mt7921::firmware_transport::Error;
    result.map_err(|error| match error {
        Error::Busy => WirelessError::Busy,
        Error::Timeout => WirelessError::Timeout,
        Error::Authority => WirelessError::Denied,
        _ => WirelessError::HardwareError,
    })
}

/// System-PM prepare phase (Linux `mt7921_pci_suspend` after cfg80211 and
/// mac80211 suspend). Runs in executor context with no IRQ lock held; the
/// started transition is retained across caller cancellation.
pub async fn system_prepare_suspend() -> Result<(), WirelessError> {
    system_prepare_suspend_for(narf_power::system_pm::SystemSleepState::S3).await
}

pub async fn system_prepare_suspend_for(
    target: narf_power::system_pm::SystemSleepState,
) -> Result<(), WirelessError> {
    let iface = ACTIVE.lock().clone();
    match iface {
        Some(iface) => iface.prepare_suspend_target(target).await,
        None => suspend_result(crate::mt7921::firmware_transport::suspend_boot_radio().await),
    }
}

/// System-PM resume phase, after synchronous device resume restored config
/// space. The station is idle afterwards; userspace re-scans/reconnects.
pub async fn system_resume() -> Result<(), WirelessError> {
    let iface = ACTIVE.lock().clone();
    match iface {
        Some(iface) => iface.resume_from_suspend().await,
        // A radio suspended before interface publication resumes against
        // the identity its own owner validated at initialization.
        None => {
            use crate::mt7921::firmware_transport::{boot_status, BootStatus, State};
            match boot_status() {
                BootStatus::Retained(State::Suspended(info) | State::WowSuspended { info, .. }) => {
                    suspend_result(
                        crate::mt7921::firmware_transport::resume_boot_radio(info.capabilities.mac)
                            .await,
                    )
                }
                _ => Ok(()),
            }
        }
    }
}

fn transmit_admitted(bytes: &[u8], local: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[6..12] == local
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && bytes[12..14] != [0x88, 0x8e]
}

fn radio_needs_recovery() -> bool {
    use crate::mt7921::firmware_transport::{boot_status, BootStatus, State};
    matches!(
        boot_status(),
        BootStatus::Retained(State::Failed { .. } | State::Running(_) | State::Stopped)
    )
}
impl Interface for Mt76Iface {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.radio.capabilities.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        if self.ap_role() {
            self.ap_link_up()
        } else {
            self.associated_bssid.lock().is_some()
        }
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ring
    }
}
#[async_trait]
impl WirelessNetIface for Mt76Iface {
    fn async_control_interfaces(&self) -> bool {
        self.p2p_profile.is_some()
    }
    async fn new_control_interface_async(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        if iftype != 10 {
            return Err(WirelessError::NotSupported);
        }
        self.new_p2p_device(authority, name, mac)
    }
    /// Only P2P_DEVICE (10) is a control-only WDEV; the P2P-client group
    /// netdev (8) stays on the legacy `new_virtual_interface` path.
    fn async_control_iftypes(&self) -> u32 {
        1 << 10
    }
    fn supports_virtual_interfaces(&self) -> bool {
        self.p2p_profile.is_some()
    }
    /// P2P_CLIENT (group netdev or physical role), P2P_GO (group netdev
    /// beside the home station or physical role) and P2P_DEVICE.
    fn p2p_interface_types(&self) -> Vec<u32> {
        if self.p2p_profile.is_some() {
            vec![8, 9, 10]
        } else {
            Vec::new()
        }
    }
    /// The combination NARF enforces: Linux `if_comb_chanctx_base`
    /// (mt792x_core.c) limits — at most two STATION|P2P_CLIENT, one
    /// AP|P2P_GO, one P2P_DEVICE, three interfaces — but on ONE channel.
    /// Linux advertises `num_different_channels = 2` for the GO set (CNM
    /// multi-channel concurrency); NARF keeps every owner on the home
    /// station's channel context (`shares_channel_context`,
    /// `shares_go_channel`), so it advertises 1. NARF also admits only one
    /// concurrent group netdev (client or GO) beside the home interface.
    fn interface_combinations(&self) -> Vec<narf_wireless::InterfaceCombination> {
        if self.p2p_profile.is_none() {
            return Vec::new();
        }
        vec![narf_wireless::InterfaceCombination {
            limits: vec![
                narf_wireless::InterfaceTypeLimit {
                    max: 2,
                    iftypes: vec![2, 8],
                },
                narf_wireless::InterfaceTypeLimit {
                    max: 1,
                    iftypes: vec![3, 9],
                },
                narf_wireless::InterfaceTypeLimit {
                    max: 1,
                    iftypes: vec![10],
                },
            ],
            max_interfaces: 3,
            max_channels: 1,
            sta_ap_beacon_interval_match: false,
            beacon_interval_min_gcd: None,
            radar_detect_widths: None,
        }]
    }
    fn new_virtual_interface(
        &self,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        if iftype == 9 {
            return self
                .new_p2p_go(name, mac)
                .map(|go| go as Arc<dyn WirelessNetIface>);
        }
        self.new_p2p_group(name, iftype, mac)
            .map(|group| group as Arc<dyn WirelessNetIface>)
    }
    fn radio_control_generation(&self) -> Option<core::num::NonZeroU64> {
        self.ap_generation()
    }
    fn reserve_radio_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.ap_serial.try_reserve().map(Some)
    }
    fn supports_ap(&self) -> bool {
        true
    }
    fn supports_ap_userspace_mlme(&self) -> bool {
        true
    }
    fn supports_ap_authenticator(&self) -> bool {
        true
    }
    fn supports_control_port_no_preauth(&self) -> bool {
        true
    }
    fn supports_control_port_tx_status(&self) -> bool {
        true
    }
    fn ap_station_macs(&self) -> Vec<[u8; 6]> {
        if self.ap_link_up() {
            crate::mt7921::firmware_transport::boot_ap::stations()
        } else {
            Vec::new()
        }
    }
    fn ap_station_info(&self, peer: [u8; 6]) -> Option<narf_wireless::StationInfo> {
        self.ap_station_macs()
            .contains(&peer)
            .then(narf_wireless::StationInfo::default)
    }
    fn ap_control_generation(&self) -> Option<core::num::NonZeroU64> {
        self.ap_generation()
    }
    fn reserve_ap_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.ap_serial.try_reserve().map(Some)
    }
    async fn start_ap_with_settings_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<(), WirelessError> {
        self.ap_start(authority, config, settings).await
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
        probe: Option<Vec<u8>>,
    ) -> Result<(), WirelessError> {
        self.ap_beacon(authority, head, tail, probe).await
    }
    async fn add_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        config: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.ap_add_station(authority, config).await
    }
    async fn set_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        config: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.ap_set_station(authority, config).await
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
        prefix: Vec<u8>,
    ) -> Result<(), WirelessError> {
        self.ap_register_frame(authority, frame_type, prefix).await
    }
    async fn tx_control_port_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        request: narf_wireless::ControlPortTxRequest,
    ) -> Result<bool, i32> {
        self.ap_control_tx(authority, request).await
    }
    fn wowlan_support(&self) -> Option<narf_wireless::WowlanSupport> {
        self.native_wowlan_support()
    }
    fn wowlan_net_detect_limits(&self) -> Option<narf_wireless::SchedScanSupport> {
        Some(crate::mt7921::wowlan_nlo::LIMITS)
    }
    fn set_wowlan(&self, config: Option<narf_wireless::WowlanConfig>) -> Result<(), i32> {
        self.configure_wowlan(config)
    }
    fn wowlan_config(&self) -> Option<narf_wireless::WowlanConfig> {
        self.wowlan.lock().clone()
    }
    fn supports_gtk_rekey_offload(&self) -> bool {
        self.native_wowlan_support().is_some()
    }
    fn set_gtk_rekey_data(&self, data: narf_wireless::GtkRekeyData) -> Result<(), i32> {
        self.validate_rekey_data(data)
    }
    fn current_iftype(&self) -> u32 {
        self.iftype.load(Ordering::Acquire)
    }
    fn set_iftype(&self, iftype: u32) -> Result<(), WirelessError> {
        self.change_iftype(iftype)
    }
    fn set_monitor_channel(
        &self,
        channel: narf_wireless::monitor::Channel,
    ) -> Result<(), WirelessError> {
        self.configure_monitor(channel)
    }
    fn max_scan_ssids(&self) -> u8 {
        4
    }
    fn max_scan_ie_len(&self) -> u16 {
        crate::mt7921::firmware_transport::MAX_SCAN_IE_LEN
    }
    fn supports_scan_random_mac(&self) -> bool {
        true
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac(),
            bands: self.bands(),
            modes: WirelessModes::STATION
                | WirelessModes::AP
                | WirelessModes::MONITOR
                | if self.p2p_profile.is_some() {
                    WirelessModes::P2P
                } else {
                    WirelessModes::empty()
                },
            hw_caps: HwCaps {
                ht_supported: self.radio.capabilities.phy.ht,
                vht_supported: crate::mt7921::vht::qualified(self.radio),
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    fn phy_capabilities(&self, band_mhz: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        let band = match band_mhz {
            2400 => 1,
            5000 => 2,
            _ => return None,
        };
        (self.radio.capabilities.phy.ht && self.radio.capabilities.phy.bands & band != 0).then_some(
            narf_wireless::iface::PhyCapabilities {
                ht: crate::mt7921::vht::ht_capability(self.radio),
                vht: (band == 2)
                    .then(|| crate::mt7921::vht::capability(self.radio))
                    .flatten(),
            },
        )
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.scan_cache
            .lock()
            .iter()
            .find(|entry| entry.bssid == bssid)
            .map(|entry| entry.information_elements.clone())
    }

    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        if !self.station_role() {
            return Err(WirelessError::NotSupported);
        }
        let six = crate::mt7921::six_ghz::qualified(self.radio);
        let mut channels = scan_channels(&req, self.radio.capabilities.phy.bands, six)?;
        // WIPHY_FLAG_SPLIT_SCAN_6GHZ (mt792x_core.c:711): the 2.4/5 GHz
        // channels are scanned first, then the 6 GHz channels that
        // cfg80211_scan_6ghz selects from their Reduced Neighbor Reports.
        let requested_6ghz: Vec<u8> = channels.iter().copied().filter(|&id| id > 180).collect();
        channels.retain(|&id| id <= 180);
        let ssids = if req.active && !channels.is_empty() {
            let domain =
                narf_wireless::reg::db::ensure_domain().map_err(|_| WirelessError::Denied)?;
            channels = active_channels(&req, channels, &domain)?;
            if req.ssids.is_empty() {
                vec![Vec::new()]
            } else {
                req.ssids.clone()
            }
        } else {
            Vec::new()
        };
        let _control = self.control.lock().await;
        if self.link_up() {
            if req.random_mac.is_some() {
                return Err(WirelessError::Busy);
            }
        } else {
            self.finish_teardown(true).await?;
        }
        let result = async {
            use crate::mt7921::firmware_transport::{scan_boot_with_options, Error, ScanOptions};
            let map_error = |error| match error {
                Error::Bounds => WirelessError::InvalidArgs,
                Error::Busy => WirelessError::Busy,
                Error::Timeout => WirelessError::Timeout,
                Error::Authority => WirelessError::Denied,
                _ => WirelessError::HardwareError,
            };
            let mut found = Vec::new();
            if !channels.is_empty() {
                let report = scan_boot_with_options(
                    &channels,
                    &ssids,
                    ScanOptions {
                        extra_ies: &req.extra_ies,
                        random_mac: req.random_mac,
                    },
                )
                .await
                .map_err(map_error)?;
                found = report.bss;
            }
            let six_ids = six_ghz_scan_ids(&req, &requested_6ghz, &found);
            if !six_ids.is_empty() {
                // 6 GHz channels are scanned passively under a NO_IR domain.
                let report = scan_boot_with_options(
                    &six_ids,
                    &[],
                    ScanOptions {
                        extra_ies: &[],
                        random_mac: req.random_mac,
                    },
                )
                .await
                .map_err(map_error)?;
                found.extend(report.bss);
            }
            let results = found
                .iter()
                .map(|bss| BssInfo {
                    bssid: bss.bssid,
                    ssid: bss.ssid.clone(),
                    frequency_mhz: scan_frequency(bss).unwrap_or(0),
                    channel: u32::from(bss.channel),
                    rssi: bss.signal_dbm.unwrap_or(-128),
                    security: scan_security(bss),
                })
                .collect();
            *self.scan_cache.lock() = found;
            Ok(results)
        }
        .await;
        if result.is_err() && radio_needs_recovery() {
            self.lose_link();
        }
        result
    }

    fn connected_bssid(&self) -> Option<[u8; 6]> {
        *self.associated_bssid.lock()
    }

    /// The radio-wide threshold the native station fragments under.
    fn fragmentation_threshold(&self) -> Option<u32> {
        Some(
            crate::mt7921::firmware_transport::BOOT_FRAG_THRESHOLD
                .load(core::sync::atomic::Ordering::Relaxed),
        )
    }

    /// mac80211 `ieee80211_set_wiphy_params(WIPHY_PARAM_FRAG_THRESHOLD)`:
    /// mt7921 has no `set_frag_threshold` op, so `drv_set_frag_threshold`
    /// succeeds and mac80211 itself fragments (with 802.3 encap offload off)
    /// from the next frame. nl80211 already validated the value.
    fn set_fragmentation_threshold(&self, threshold: u32) -> Result<(), i32> {
        if threshold != u32::MAX && (threshold < 256 || threshold & 1 != 0) {
            return Err(22); // EINVAL
        }
        crate::mt7921::firmware_transport::BOOT_FRAG_THRESHOLD
            .store(threshold, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    async fn associate(&self, mut req: AssociateRequest) -> Result<(), WirelessError> {
        let _control = self.control.lock().await;
        if !self.station_role() {
            return Err(WirelessError::NotSupported);
        }
        let six = self.validate_join(&req)?;
        self.finish_teardown(true).await?;
        if self.link_up() {
            return Err(WirelessError::Busy);
        }
        let security = core::mem::replace(&mut req.security, narf_wireless::SecurityConfig::Open);
        let (bss, security) = self.resolve_join(&req, security, six)?;
        {
            use crate::mt7921::firmware_transport::{associate_boot_station_as, Error};
            // Stable under `control`: SET_INTERFACE also takes that lock.
            let p2p_client = self.current_iftype() == 8;
            let aid = associate_boot_station_as(&bss, &req.ssid, security, &req.ie, p2p_client)
                .await
                .map_err(|error| match error {
                    Error::Bounds => WirelessError::InvalidArgs,
                    Error::Busy => WirelessError::Busy,
                    Error::Timeout => WirelessError::Timeout,
                    Error::Authority => WirelessError::Denied,
                    _ => WirelessError::HardwareError,
                })?;
            let _ = aid;
            let (tx_prod, tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
            let (rx_prod, rx_cons) = narf_ipc::channel::<Frame, RX_RING_N>();
            *self.tx_ring.lock() = Some(tx_prod);
            *self.rx_ring.lock() = Some(rx_cons);
            *self.tx_cons.lock() = Some(tx_cons);
            *self.rx_prod.lock() = Some(rx_prod);
            *self.associated_bssid.lock() = Some(req.bssid);
            publish_link(&self.name, true);
            Ok(())
        }
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        let _control = self.control.lock().await;
        self.finish_teardown(true).await?;
        if self.associated_bssid.lock().is_none() {
            return Ok(());
        }
        {
            use crate::mt7921::firmware_transport::{disassociate_boot_station, Error};
            self.teardown_needed.store(true, Ordering::Release);
            self.clear_link();
            disassociate_boot_station()
                .await
                .map_err(|error| match error {
                    Error::Busy => WirelessError::Busy,
                    Error::Timeout => WirelessError::Timeout,
                    Error::Authority => WirelessError::Denied,
                    _ => WirelessError::HardwareError,
                })?;
            self.teardown_needed.store(false, Ordering::Release);
            *self.tx_ring.lock() = None;
            *self.rx_ring.lock() = None;
            *self.tx_cons.lock() = None;
            *self.rx_prod.lock() = None;
            *self.associated_bssid.lock() = None;
            publish_link(&self.name, false);
            Ok(())
        }
    }

    fn supports_handshake_offload(&self) -> bool {
        true
    }

    async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}
/// Scan channel ids (`channel::rx_channel`: 2.4/5 GHz channel numbers, 6 GHz
/// RXD CH_FREQ values 181..=239). 6 GHz entries come only from 6 GHz
/// frequencies (or, for a default colocated scan, the whole 6 GHz sband):
/// a bare channel number never selects 6 GHz.
fn scan_channels(req: &ScanRequest, bands: u8, six: bool) -> Result<Vec<u8>, WirelessError> {
    use crate::mt7921::channel;
    if req.duration_mandatory || req.duration_tu.is_some() {
        return Err(WirelessError::NotSupported);
    }
    if req.colocated_6ghz && !six {
        return Err(WirelessError::NotSupported);
    }
    crate::mt7921::firmware_transport::validate_scan_options(
        crate::mt7921::firmware_transport::ScanOptions {
            extra_ies: &req.extra_ies,
            random_mac: req.random_mac,
        },
    )
    .map_err(|_| WirelessError::InvalidArgs)?;
    if !req.active && !req.extra_ies.is_empty() {
        return Err(WirelessError::InvalidArgs);
    }
    if !req.active && !req.ssids.is_empty()
        || req.ssids.len() > 4
        || req.ssids.iter().any(|ssid| ssid.len() > 32)
    {
        return Err(WirelessError::InvalidArgs);
    }
    let requested = if req.frequencies_mhz.is_empty() {
        req.channels.clone()
    } else {
        let channels = req
            .frequencies_mhz
            .iter()
            .map(|&freq| {
                if let Some((narf_wireless::association::channel::Band::Ghz6, number)) =
                    narf_wireless::association::channel::from_frequency_band(freq)
                {
                    if !six {
                        return Err(WirelessError::NotSupported);
                    }
                    return channel::rx_channel(channel::Band::Ghz6, number)
                        .map(u32::from)
                        .ok_or(WirelessError::NotSupported);
                }
                channel::from_frequency(freq)
                    .map(u32::from)
                    .ok_or(WirelessError::NotSupported)
            })
            .collect::<Result<Vec<_>, _>>()?;
        // The legacy selector names channel numbers, not scan ids.
        let numbers: Vec<u32> = channels
            .iter()
            .filter_map(|&id| {
                channel::from_rx_channel(u8::try_from(id).ok()?).map(|(_, n)| u32::from(n))
            })
            .collect();
        if !req.channels.is_empty()
            && (req.channels.len() != numbers.len()
                || !req.channels.iter().all(|channel| numbers.contains(channel)))
        {
            return Err(WirelessError::InvalidArgs);
        }
        channels
    };
    if requested.is_empty() {
        let mut channels = channel::channels(bands);
        // cfg80211 includes every 6 GHz channel; the colocated plan below
        // narrows them (cfg80211_scan_6ghz). Without the flag a default
        // scan keeps its 2.4/5 GHz profile.
        if req.colocated_6ghz {
            channels.extend(
                channel::channels_6ghz()
                    .filter_map(|number| channel::rx_channel(channel::Band::Ghz6, number)),
            );
        }
        return Ok(channels);
    }
    let mut channels = Vec::new();
    for requested in requested {
        let value = u8::try_from(requested).map_err(|_| WirelessError::InvalidArgs)?;
        let (band, _) = channel::from_rx_channel(value).ok_or(WirelessError::InvalidArgs)?;
        if band != channel::Band::Ghz6 && bands & band.capability() == 0 {
            return Err(WirelessError::NotSupported);
        }
        if band == channel::Band::Ghz6 && req.frequencies_mhz.is_empty() {
            return Err(WirelessError::InvalidArgs);
        }
        if channels.contains(&value) {
            return Err(WirelessError::InvalidArgs);
        }
        channels.push(value);
    }
    Ok(channels)
}

/// A scan result's centre frequency in its own band.
fn scan_frequency(bss: &crate::mt7921::firmware_transport::ScanBss) -> Option<u32> {
    use crate::mt7921::channel;
    if crate::mt7921::association::is_six_ghz(bss) {
        channel::frequency_in(channel::Band::Ghz6, bss.channel)
    } else {
        channel::frequency(bss.channel)
    }
}

/// cfg80211 `cfg80211_scan_6ghz` for the split 6 GHz phase: the colocated
/// APs of the 2.4/5 GHz results' Reduced Neighbor Reports
/// (`parse_colocated_aps`) select the requested 6 GHz channels through the
/// shared `plan_6ghz_scan`. Without `colocated_6ghz` every requested 6 GHz
/// channel is scanned. The result is in scan-id form, deduplicated.
///
/// Linux v7.2 mt7921 programs no per-target fields: `mt76_connac_mcu_hw_scan`
/// sends only the 6 GHz channel list (band 3), and the RNR BSSID table of
/// `mt76_connac_mcu_build_rnr_scan_param` is consumed by mt7925 alone.
pub(crate) fn six_ghz_scan_ids(
    req: &ScanRequest,
    requested: &[u8],
    found: &[crate::mt7921::firmware_transport::ScanBss],
) -> Vec<u8> {
    use crate::mt7921::channel;
    use narf_wireless::association::channel::{from_frequency_band, Band};
    if requested.is_empty() {
        return Vec::new();
    }
    let colocated: Vec<narf_wireless::scan::ColocatedAp> = found
        .iter()
        .filter(|bss| !crate::mt7921::association::is_six_ghz(bss))
        .flat_map(|bss| narf_wireless::scan::parse_colocated_aps(&bss.information_elements))
        .collect();
    let six_request = ScanRequest {
        ssids: req.ssids.clone(),
        frequencies_mhz: requested
            .iter()
            .filter_map(|&id| channel::from_rx_channel(id))
            .filter_map(|(band, number)| channel::frequency_in(band, number))
            .collect(),
        channels: Vec::new(),
        active: req.active,
        random_mac: req.random_mac,
        colocated_6ghz: req.colocated_6ghz,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    };
    let plan = narf_wireless::scan::plan_6ghz_scan(&six_request, &colocated, None);
    let mut ids = Vec::new();
    for mhz in plan.frequencies_mhz {
        if let Some((Band::Ghz6, number)) = from_frequency_band(mhz) {
            if let Some(id) = channel::rx_channel(channel::Band::Ghz6, number) {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
    }
    ids
}

fn active_channels(
    request: &ScanRequest,
    mut channels: Vec<u8>,
    domain: &narf_wireless::reg::RegulatoryDomain,
) -> Result<Vec<u8>, WirelessError> {
    let allowed = |channel: &u8| {
        crate::mt7921::association::TxPermission::from_domain(domain, *channel).is_some()
    };
    if request.channels.is_empty() && request.frequencies_mhz.is_empty() {
        channels.retain(allowed);
    } else if !channels.iter().all(allowed) {
        return Err(WirelessError::Denied);
    }
    if channels.is_empty() {
        return Err(WirelessError::Denied);
    }
    Ok(channels)
}
fn scan_security(
    bss: &crate::mt7921::firmware_transport::ScanBss,
) -> narf_wireless::scan::BssSecurity {
    use narf_wireless::{rsn, scan::BssSecurity};
    let mut ies = &bss.information_elements[..];
    let mut wpa = false;
    while ies.len() >= 2 {
        let len = usize::from(ies[1]);
        let Some(value) = ies.get(2..2 + len) else {
            break;
        };
        if ies[0] == 48 {
            if let Some(rsn) = rsn::RsnIe::decode_body(value) {
                return if !rsn.akms.contains(&rsn::Suite::standard(rsn::AKM_PSK))
                    && rsn.akms.contains(&rsn::Suite::standard(rsn::AKM_SAE))
                {
                    BssSecurity::Wpa3
                } else {
                    BssSecurity::Wpa2
                };
            }
        }
        wpa |= ies[0] == 221 && value.starts_with(&[0, 0x50, 0xf2, 1]);
        ies = &ies[2 + len..];
    }
    if wpa {
        BssSecurity::Wpa
    } else if bss.capability & 0x10 != 0 {
        BssSecurity::Wep
    } else {
        BssSecurity::Open
    }
}

/// Register one boot-owned radio with both network registries. The same
/// bounded packet step services executor and synchronous network callers.
pub(crate) fn register_scan_iface(info: RadioInfo) -> Result<Arc<Mt76Iface>, WirelessError> {
    register_scan_iface_profile(info, None)
}
pub(crate) fn register_scan_iface_profile(
    info: RadioInfo,
    profile: Option<crate::mt7921::firmware_transport::P2pProfile>,
) -> Result<Arc<Mt76Iface>, WirelessError> {
    // Reusing our retained interface grants no new registry access and must
    // not depend on the authority used for its original publication.
    if let Some(existing) = ACTIVE.lock().as_ref() {
        return if existing.radio.chip_id == info.chip_id
            && existing.radio.capabilities == info.capabilities
            && existing.radio.hardware_type == info.hardware_type
            && profile.is_none_or(|profile| existing.p2p_profile == Some(profile))
        {
            Ok(existing.clone())
        } else {
            Err(WirelessError::InvalidArgs)
        };
    }
    let authority = narf_net::trusted_net_authority()
        .and_then(|a| a.derive().ok())
        .ok_or(WirelessError::Denied)?;
    let mut iface = Mt76Iface::new(String::new(), info)?;
    iface.p2p_profile = profile;
    // Bootstrap before control-plane discovery/association can query the
    // domain. Missing deployment policy still permits the receive-only scan
    // interface; TX admission retries the same signed bootstrap and fails shut.
    if let Err(error) = narf_wireless::reg::db::ensure_domain() {
        use core::fmt::Write;
        let _ = writeln!(narf_console::Writer, "mt76: regulatory policy: {}", error);
    }
    iface.name = narf_net::iface::register("wlan%d", info.capabilities.mac, send_frame);
    let bus_info = match crate::mt7921::pci::bound_bus_addr() {
        Some(narf_bus::BusAddr::Pcie(pci)) => alloc::format!("{pci:?}"),
        _ => alloc::string::String::new(),
    };
    narf_net::iface::set_driver_info(&iface.name, "mt7921e", Some("0.1.0"), bus_info);
    publish_link(&iface.name, false);
    let iface = Arc::new(iface);
    let cap = match narf_net::registry().register(&authority, RegisteredIface(iface.clone())) {
        Ok(cap) => cap,
        Err(_) => {
            narf_net::iface::unregister(&iface.name);
            return Err(WirelessError::HardwareError);
        }
    };
    *iface.registration_cap.lock() = Some(cap);
    *ACTIVE.lock() = Some(iface.clone());
    narf_net::iface::set_device_control(
        &iface.name,
        Arc::new(EthtoolControl(Arc::downgrade(&iface))),
    );
    let version = info.firmware.version;
    let end = version
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(version.len());
    narf_net::iface::set_driver_fw_version(
        &iface.name,
        String::from_utf8_lossy(&version[..end]).into_owned(),
    );
    narf_wireless::registry::register(iface.clone());
    narf_net::iface::install_rx_drain(drain_network);
    let worker = iface.clone();
    narf_scheduler::spawn(async move {
        // Removal withdraws ACTIVE; a removed generation's worker never
        // touches a reprobed radio.
        while is_active(&worker) {
            let _ = worker.poll_data().await;
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    });
    Ok(iface)
}

static ACTIVE: IrqSafeSpinLock<Option<Arc<Mt76Iface>>> = IrqSafeSpinLock::new(None);

/// The permanent module host retains this exact publication, never a name
/// which could be reused by a later native binding.
pub(crate) fn module_active() -> Option<Arc<Mt76Iface>> {
    ACTIVE.lock().clone()
}

/// PCI removal (Linux `mt76_unregister_device` → `ieee80211_unregister_hw`):
/// close carrier, report the lost link, and withdraw every publication of
/// this generation's interface. Its service worker exits on its next turn.
/// A later probe registers a fresh interface from a fresh identity query.
pub(crate) fn remove_scan_iface() {
    let Some(iface) = ACTIVE.lock().take() else {
        return;
    };
    iface.lose_link();
    iface.withdraw_p2p_group();
    iface.withdraw_p2p_go();
    iface.withdraw_p2p_metadata();
    iface.scan_cache.lock().clear();
    narf_wireless::registry::unregister(&iface.name);
    if let Some(cap) = iface.registration_cap.lock().take() {
        narf_net::registry().unregister_for_handle(&cap);
    }
    narf_net::iface::unregister(&iface.name);
}

pub(crate) fn is_active(iface: &Arc<Mt76Iface>) -> bool {
    ACTIVE
        .lock()
        .as_ref()
        .is_some_and(|active| Arc::ptr_eq(active, iface))
}

fn send_frame(bytes: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    let iface = ACTIVE.lock().clone().ok_or(())?;
    iface.enqueue(bytes)
}

fn drain_network() -> bool {
    let iface = ACTIVE.lock().clone();
    iface.is_some_and(|iface| iface.drain_network().unwrap_or(false))
}

/// Read-only diagnostics retain the exact radio publication, never a name
/// that could be reused by a reprobed device. No MCU command runs here.
#[derive(Debug)]
struct EthtoolControl(alloc::sync::Weak<Mt76Iface>);
impl EthtoolControl {
    fn with_live<T>(
        &self,
        f: impl FnOnce(&Mt76Iface) -> narf_net::nic::Result<T>,
    ) -> narf_net::nic::Result<T> {
        let iface = self.0.upgrade().ok_or(19)?;
        let active = ACTIVE.lock();
        if !active.as_ref().is_some_and(|a| Arc::ptr_eq(a, &iface)) {
            return Err(19);
        }
        f(&iface)
    }
}
impl narf_net::iface::DeviceControl for EthtoolControl {
    fn configure(&self, _: &narf_net::iface::DeviceConfig) -> Result<(), i32> {
        Err(95)
    }
    fn nic(&self) -> Option<&dyn narf_net::nic::NicControl> {
        Some(self)
    }
}
impl narf_net::nic::NicControl for EthtoolControl {
    fn permanent_mac(&self) -> narf_net::nic::Result<[u8; 6]> {
        self.with_live(|iface| Ok(iface.radio.capabilities.mac))
    }
    fn statistics(&self) -> narf_net::nic::Result<Vec<narf_net::nic::Statistic>> {
        self.with_live(|iface| {
            let stats = narf_net::iface::lookup(&iface.name).ok_or(19)?.stats;
            Ok([
                ("rx_packets", stats.rx_packets),
                ("rx_bytes", stats.rx_bytes),
                ("rx_dropped", stats.rx_drop),
                ("tx_packets", stats.tx_packets),
                ("tx_bytes", stats.tx_bytes),
                ("tx_dropped", stats.tx_drop),
            ]
            .into_iter()
            .map(|(name, value)| narf_net::nic::Statistic {
                name: String::from(name),
                value,
            })
            .collect())
        })
    }
}

struct RegisteredIface(Arc<Mt76Iface>);
impl Interface for RegisteredIface {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        self.0.mtu()
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

#[cfg(any(test, feature = "builtin"))]
mod tests {
    use super::*;
    use crate::mt7921::firmware_transport::{NicCapabilities, PhyCapabilities, Report};
    use narf_kernel_test::{kernel_test_in, TestResult};
    static ADMIN_CALLS: AtomicU32 = AtomicU32::new(0);
    static ADMIN_BLOCKED: AtomicBool = AtomicBool::new(false);
    static DRIVER_LOCK: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());
    fn admin_hook(_: &str, _: bool) {
        ADMIN_CALLS.fetch_add(1, Ordering::AcqRel);
        if DRIVER_LOCK.try_lock().is_none() {
            ADMIN_BLOCKED.store(true, Ordering::Release);
        }
    }
    fn reject(_: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
        Err(())
    }
    struct Registration;
    impl Drop for Registration {
        fn drop(&mut self) {
            narf_net::iface::unregister("mt76-carrier-admin-model");
        }
    }
    fn mt76_physical_carrier_preserves_admin_and_never_calls_hook_under_driver_lock() -> TestResult
    {
        let name = "mt76-carrier-admin-model";
        narf_net::iface::register(name, [2, 0, 0, 0, 0, 7], reject);
        let _registration = Registration;
        ADMIN_CALLS.store(0, Ordering::Release);
        ADMIN_BLOCKED.store(false, Ordering::Release);
        if !narf_net::iface::set_open_stop(name, admin_hook) {
            return TestResult::Fail("MT76 could not install actual administrative hook");
        }
        {
            let _driver = DRIVER_LOCK.lock();
            if !publish_link(name, true) {
                return TestResult::Fail("MT76 could not publish carrier on registered interface");
            }
        }
        if narf_net::iface::lookup(name).is_none_or(|i| i.link_up || !i.carrier)
            || ADMIN_CALLS.load(Ordering::Acquire) != 0
        {
            return TestResult::Fail("MT76 carrier-up changed IFF_UP or reentered driver lock");
        }
        narf_net::iface::set_link_state(name, true); // operator transition
        if ADMIN_CALLS.load(Ordering::Acquire) != 1 || ADMIN_BLOCKED.load(Ordering::Acquire) {
            return TestResult::Fail(
                "MT76 real administrative hook could not reenter unlocked gate",
            );
        }
        {
            let _driver = DRIVER_LOCK.lock();
            if !publish_link(name, false) || !publish_link(name, false) {
                return TestResult::Fail(
                    "MT76 carrier-down failed on retained registered interface",
                );
            }
        }
        if narf_net::iface::lookup(name).is_none_or(|i| {
            !i.link_up || i.carrier || i.carrier_up_count != 1 || i.carrier_down_count != 1
        }) || ADMIN_CALLS.load(Ordering::Acquire) != 1
            || ADMIN_BLOCKED.load(Ordering::Acquire)
        {
            return TestResult::Fail(
                "MT76 carrier-down changed admin state or duplicated transition",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/scan",
        mt76_physical_carrier_preserves_admin_and_never_calls_hook_under_driver_lock
    );
    fn radio() -> RadioInfo {
        RadioInfo {
            chip_id: 0x7961,
            firmware: Report {
                version: [0; 10],
                build_date: [0; 15],
                patch_already_loaded: false,
                bytes_transferred: 0,
            },
            capabilities: NicCapabilities {
                mac: [2, 0, 0xde, 0xad, 0xbe, 0xef],
                phy: PhyCapabilities {
                    ht: true,
                    vht: true,
                    he: true,
                    max_bandwidth: 3,
                    spatial_streams: 2,
                    bands: 3,
                    tx_ldpc: true,
                    rx_ldpc: true,
                    tx_stbc: true,
                    rx_stbc: true,
                },
                has_6ghz: true,
                chip_capabilities: 0,
            },
            hardware_type: 1,
            world_limit_commands: 3,
            channel_configuration: Some(0),
        }
    }
    static REPEAT_ADMIN_CALLS: AtomicU32 = AtomicU32::new(0);
    fn repeat_admin_hook(_: &str, _: bool) {
        REPEAT_ADMIN_CALLS.fetch_add(1, Ordering::AcqRel);
    }
    struct RepeatedRegistration {
        iface: Arc<Mt76Iface>,
        name: String,
    }
    impl Drop for RepeatedRegistration {
        fn drop(&mut self) {
            {
                let mut active = ACTIVE.lock();
                if active
                    .as_ref()
                    .is_some_and(|owner| Arc::ptr_eq(owner, &self.iface))
                {
                    *active = None;
                }
            }
            narf_net::iface::unregister(&self.name);
        }
    }
    fn mt76_ethtool_uses_current_radio_publication() -> TestResult {
        use narf_net::nic::NicControl;
        if ACTIVE.lock().is_some() {
            return TestResult::Skip("live MT76 interface owns registration slot");
        }
        let info = radio();
        let name = narf_net::iface::register("mt76-ethtool%d", info.capabilities.mac, reject);
        let iface = Arc::new(Mt76Iface::new(name.clone(), info).unwrap());
        let _fixture = RepeatedRegistration {
            iface: iface.clone(),
            name: name.clone(),
        };
        let control = EthtoolControl(Arc::downgrade(&iface));
        {
            let mut active = ACTIVE.lock();
            if active.is_some() {
                return TestResult::Skip("live MT76 interface owns registration slot");
            }
            *active = Some(iface.clone());
        }
        narf_net::iface::set_device_control(
            &name,
            Arc::new(EthtoolControl(Arc::downgrade(&iface))),
        );
        let mut perm = [0u8; 14];
        perm[..4].copy_from_slice(&0x20u32.to_ne_bytes());
        perm[4..8].copy_from_slice(&6u32.to_ne_bytes());
        if narf_net::ethtool::execute(&name, &mut perm).is_err()
            || perm[8..] != info.capabilities.mac
        {
            return TestResult::Fail("MT76 ethtool permanent MAC not wired");
        }
        if control.statistics().is_err()
            || control.settings() != Err(95)
            || control.timestamp_info() != (0x1a, 1, 1)
        {
            return TestResult::Fail("MT76 diagnostics unavailable or invented wired capabilities");
        }
        *ACTIVE.lock() = None;
        if control.permanent_mac() != Err(19) || control.statistics().err() != Some(19) {
            return TestResult::Fail("removed MT76 radio still accepted ethtool diagnostics");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/ethtool",
        mt76_ethtool_uses_current_radio_publication
    );

    fn mt76_repeat_scan_registration_preserves_same_associated_owner_and_admin() -> TestResult {
        if ACTIVE.lock().is_some() {
            return TestResult::Skip("live MT76 interface owns registration slot");
        }
        let info = radio();
        let name = narf_net::iface::register("mt76-repeat-model%d", info.capabilities.mac, reject);
        let iface = match Mt76Iface::new(name.clone(), info) {
            Ok(iface) => Arc::new(iface),
            Err(_) => {
                narf_net::iface::unregister(&name);
                return TestResult::Fail("repeat-registration fixture identity");
            }
        };
        let _fixture = RepeatedRegistration {
            iface: iface.clone(),
            name: name.clone(),
        };
        {
            let mut active = ACTIVE.lock();
            if active.is_some() {
                return TestResult::Skip("MT76 interface became live before fixture installation");
            }
            *active = Some(iface.clone());
        }
        let (mut tx, tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
        let (mut rx, rx_cons) = narf_ipc::channel::<Frame, RX_RING_N>();
        for (producer, value) in [(&mut tx, 0x55u8), (&mut rx, 0xaau8)] {
            let Ok(buffer) = narf_io::alloc_coherent(32, narf_lib::id::DomainId::DRIVER_0) else {
                return TestResult::Fail("repeat-registration frame allocation");
            };
            let mut frame = Frame::new(buffer, 32);
            frame.payload_mut().fill(value);
            if producer.try_send(frame).is_err() {
                return TestResult::Fail("repeat-registration sentinel queue");
            }
        }
        *iface.tx_ring.lock() = Some(tx);
        *iface.tx_cons.lock() = Some(tx_cons);
        *iface.rx_prod.lock() = Some(rx);
        *iface.rx_ring.lock() = Some(rx_cons);
        let peer = [2, 0, 0, 0, 0, 9];
        *iface.associated_bssid.lock() = Some(peer);
        REPEAT_ADMIN_CALLS.store(0, Ordering::Release);
        if !narf_net::iface::set_open_stop(&name, repeat_admin_hook) {
            return TestResult::Fail("repeat-registration administrative hook");
        }
        narf_net::iface::set_link_state(&name, true); // actual operator IFF_UP
        publish_link(&name, true);
        let before = narf_net::iface::lookup(&name).unwrap();
        let admin_calls = REPEAT_ADMIN_CALLS.load(Ordering::Acquire);
        for _ in 0..2 {
            match register_scan_iface(info) {
                Ok(existing) if Arc::ptr_eq(&existing, &iface) => {}
                _ => {
                    return TestResult::Fail(
                        "repeat registration replaced/refused the same retained interface",
                    )
                }
            }
        }
        for changed in [
            RadioInfo {
                hardware_type: info.hardware_type ^ 1,
                ..info
            },
            RadioInfo {
                capabilities: NicCapabilities {
                    mac: [2, 0, 0, 0, 0, 10],
                    ..info.capabilities
                },
                ..info
            },
        ] {
            if !matches!(
                register_scan_iface(changed),
                Err(WirelessError::InvalidArgs)
            ) {
                return TestResult::Fail("changed radio identity reused existing registration");
            }
        }
        let after = narf_net::iface::lookup(&name).unwrap();
        if !iface.link_up()
            || iface.connected_bssid() != Some(peer)
            || !after.link_up
            || !after.carrier
            || after.link_up != before.link_up
            || after.carrier != before.carrier
            || after.carrier_changes != before.carrier_changes
            || REPEAT_ADMIN_CALLS.load(Ordering::Acquire) != admin_calls
            || !ACTIVE
                .lock()
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &iface))
        {
            return TestResult::Fail(
                "repeat registration changed association/admin/carrier or called admin hook",
            );
        }
        let tx = iface.tx_cons.lock().as_mut().unwrap().try_recv();
        let rx = iface.rx_ring.lock().as_mut().unwrap().try_recv();
        if !matches!(tx, Ok(Some(frame)) if frame.payload() == [0x55;32])
            || !matches!(rx, Ok(Some(frame)) if frame.payload() == [0xaa;32])
            || iface.tx_ring.lock().is_none()
            || iface.rx_prod.lock().is_none()
        {
            return TestResult::Fail(
                "repeat registration discarded/recreated retained frame rings",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/scan",
        mt76_repeat_scan_registration_preserves_same_associated_owner_and_admin
    );
    fn mt76_wow_capability_busy_reporting_does_not_cache_authority() -> TestResult {
        use crate::mt7921::firmware_transport::Error;
        let iface = Mt76Iface::new(String::from("mt76-wake-report"), radio()).unwrap();
        let config = narf_wireless::WowlanConfig {
            magic_packet: true,
            ..narf_wireless::WowlanConfig::default()
        };
        if iface.wowlan_support_with(|| Ok(false)).is_some()
            || iface.wowlan_support_with(|| Err(Error::Busy)).is_some()
            || iface.wake_reported.load(Ordering::Acquire)
        {
            return TestResult::Fail("absent/busy route invented a wake capability");
        }
        let Some(expected) = iface.wowlan_support_with(|| Ok(true)) else {
            return TestResult::Fail("actual positive route was not reported");
        };
        let mut calls = 0;
        let reported = iface.wowlan_support_with(|| {
            calls += 1;
            Err(Error::Busy)
        });
        if reported != Some(expected) || calls != 0 {
            return TestResult::Fail("temporary transport ownership changed reported capability");
        }
        iface.iftype.store(6, Ordering::Release);
        if iface.wowlan_support_with(|| Ok(true)).is_some() {
            return TestResult::Fail("station wake profile leaked into monitor mode");
        }
        iface.iftype.store(2, Ordering::Release);
        for (receipt, expected_errno) in [
            (Err(Error::Busy), -16),
            (Err(Error::Authority), -1),
            (Ok(false), -95),
        ] {
            if iface.configure_wowlan_with(Some(config.clone()), || receipt) != Err(expected_errno)
                || iface.wowlan.lock().is_some()
            {
                return TestResult::Fail("capability cache authorized stale wake configuration");
            }
        }
        if iface.configure_wowlan_with(Some(config.clone()), || Ok(true)) != Ok(())
            || *iface.wowlan.lock() != Some(config.clone())
        {
            return TestResult::Fail("fresh wake route did not admit host configuration");
        }
        iface.sleeping.store(true, Ordering::Release);
        if iface.configure_wowlan_with(None, || Ok(true)) != Err(-16)
            || *iface.wowlan.lock() != Some(config)
        {
            return TestResult::Fail("sleeping owner allowed a configuration replacement");
        }
        iface.sleeping.store(false, Ordering::Release);
        if iface.configure_wowlan_with(None, || Err(Error::Authority)) != Ok(())
            || iface.wowlan.lock().is_some()
        {
            return TestResult::Fail("host wake configuration could not be cleared without arming");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/wowlan",
        mt76_wow_capability_busy_reporting_does_not_cache_authority
    );
    fn mt76_scan_interface_reports_implemented_profile() -> TestResult {
        let iface = Mt76Iface::new(String::from("wlan7"), radio()).unwrap();
        let info = iface.get_wireless_info();
        if iface.name() != "wlan7"
            || iface.mac() != radio().capabilities.mac
            || iface.link_up()
            || iface.rx_ring().lock().is_some()
            || iface.tx_ring().lock().is_some()
            || info.base_name != "wlan7"
            // MT_NIC_CAP_6G is reported: the 6 GHz band (1, 5, ..., 233).
            || info.bands.len() != 3
            || info.bands[2].freq_mhz != 6000
            || info.bands[2].channels != (1..=233).step_by(4).collect::<Vec<_>>()
            || info.bands[0].channels != (1..=11).collect::<Vec<_>>()
            || !info.hw_caps.ht_supported
            || iface
                .phy_capabilities(2400)
                .is_none_or(|caps| caps.ht[..5] != [255, 1, 28, 255, 255] || caps.vht.is_some())
            || iface.phy_capabilities(6000).is_some()
            || !info.hw_caps.vht_supported
            || iface.phy_capabilities(5000).is_none_or(|caps| {
                caps.vht != Some([176, 113, 16, 0, 250, 255, 0, 0, 250, 255, 0, 32])
            })
            || info.hw_caps.he_supported
            || info.hw_caps.eht_supported
            || !iface.supports_handshake_offload()
            || !iface.supports_ap()
            || !iface.supports_ap_authenticator()
            || !iface.supports_ap_userspace_mlme()
            || iface.supports_ap_uapsd()
            || iface.supports_external_supplicant()
            || iface.supports_userspace_mlme()
            || !info.modes.contains(WirelessModes::AP)
            || iface.supports_sae_offload()
            || iface.max_scan_ssids() != 4
            || iface.max_scan_ie_len() != 600
            || !iface.supports_scan_random_mac()
        {
            return TestResult::Fail("passive interface claims unfinished data/PHY support");
        }
        let mut invalid = radio();
        invalid.capabilities.mac = [0; 6];
        if Mt76Iface::new(String::new(), invalid).is_ok() {
            return TestResult::Fail("zero MAC registered");
        }
        invalid.capabilities.mac = [1; 6];
        if Mt76Iface::new(String::new(), invalid).is_ok() {
            return TestResult::Fail("multicast MAC registered");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/scan",
        mt76_scan_interface_reports_implemented_profile
    );

    fn mt76_receive_ipc_preserves_current_epoch_and_retires_queued_old_frames() -> TestResult {
        fn frame(value: u8) -> Frame {
            let mut buffer = narf_io::alloc_coherent(60, narf_lib::id::DomainId::DRIVER_0).unwrap();
            buffer.as_mut_slice()[..60].fill(value);
            Frame::new(buffer, 60)
        }
        let iface = Mt76Iface::new(String::from("mt76-ipc-epoch"), radio()).unwrap();
        iface.ensure_receive_epoch(41);
        if iface
            .rx_prod
            .lock()
            .as_mut()
            .unwrap()
            .try_send(frame(1))
            .is_err()
        {
            return TestResult::Fail("current epoch native IPC fixture publication");
        }
        iface.ensure_receive_epoch(41);
        if iface
            .rx_ring
            .lock()
            .as_mut()
            .unwrap()
            .try_recv()
            .ok()
            .flatten()
            .is_none_or(|frame| frame.payload() != [1; 60])
        {
            return TestResult::Fail("unchanged receive epoch dropped a current packet");
        }
        let _ = iface.rx_prod.lock().as_mut().unwrap().try_send(frame(2));
        iface.ensure_receive_epoch(42);
        if iface
            .rx_ring
            .lock()
            .as_mut()
            .unwrap()
            .try_recv()
            .ok()
            .flatten()
            .is_some()
        {
            return TestResult::Fail("new receive epoch inherited an old queued IPC frame");
        }
        let _ = iface.rx_prod.lock().as_mut().unwrap().try_send(frame(3));
        iface.retire_receive_ipc();
        if iface.rx_ring.lock().is_some()
            || iface.rx_prod.lock().is_some()
            || iface.receive_epoch.load(Ordering::Acquire) != 0
        {
            return TestResult::Fail(
                "closed receive epoch retained an IPC producer or queued frame",
            );
        }
        iface.ensure_receive_epoch(43);
        if iface
            .rx_ring
            .lock()
            .as_mut()
            .unwrap()
            .try_recv()
            .ok()
            .flatten()
            .is_some()
        {
            return TestResult::Fail("reopened IPC receive owner inherited a closed epoch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/receive_epoch",
        mt76_receive_ipc_preserves_current_epoch_and_retires_queued_old_frames
    );
    fn mt76_scan_policy_validates_active_ssids_and_channel_geometry() -> TestResult {
        let mut req = ScanRequest {
            ssids: Vec::new(),
            frequencies_mhz: Vec::new(),
            channels: vec![1, 6, 11],
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        };
        if scan_channels(&req, 3, false) != Ok(vec![1, 6, 11]) {
            return TestResult::Fail("valid passive request");
        }
        req.active = true;
        if scan_channels(&req, 3, false) != Ok(vec![1, 6, 11]) {
            return TestResult::Fail("active wildcard geometry rejected");
        }
        req.extra_ies = vec![221, 3, 0x50, 0x6f, 0x9a];
        if scan_channels(&req, 3, false) != Ok(vec![1, 6, 11]) {
            return TestResult::Fail("native active probe IE profile rejected");
        }
        req.active = false;
        if scan_channels(&req, 3, false) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("passive scan accepted probe IEs");
        }
        req.extra_ies.clear();
        req.random_mac = Some(narf_wireless::ScanRandomMac {
            addr: [2, 0, 0, 0, 0, 0],
            mask: [3, 0, 0, 0, 0, 0],
        });
        if scan_channels(&req, 3, false) != Ok(vec![1, 6, 11]) {
            return TestResult::Fail("native passive random scan geometry rejected");
        }
        req.random_mac.as_mut().unwrap().mask[0] = 0;
        if scan_channels(&req, 3, false) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("unbounded multicast random address mask accepted");
        }
        req.random_mac = None;
        req.ssids.push(Vec::new());
        if scan_channels(&req, 3, false) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("inconsistent passive request with probe SSIDs accepted");
        }
        req.ssids.clear();
        req.channels = vec![35];
        if scan_channels(&req, 3, false) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("unimplemented band exposed");
        }
        req.channels = vec![1, 1];
        if scan_channels(&req, 3, false) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("duplicate channel");
        }
        req.channels.clear();
        if scan_channels(&req, 3, false) != Ok(crate::mt7921::channel::channels(3))
            || scan_channels(&req, 3, true) != Ok(crate::mt7921::channel::channels(3))
        {
            return TestResult::Fail("default scan channels");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/scan",
        mt76_scan_policy_validates_active_ssids_and_channel_geometry
    );

    /// cfg80211_scan_6ghz / WIPHY_FLAG_SPLIT_SCAN_6GHZ policy: 6 GHz scan
    /// ids, the colocated flag and the RNR-selected 6 GHz phase.
    fn mt76_colocated_6ghz_scan_selects_rnr_and_psc_channels() -> TestResult {
        use crate::mt7921::firmware_transport::ScanBss;
        let mut req = ScanRequest {
            ssids: Vec::new(),
            frequencies_mhz: Vec::new(),
            channels: Vec::new(),
            active: false,
            random_mac: None,
            colocated_6ghz: true,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        };
        // A default colocated scan adds the whole 6 GHz sband (ids 181..).
        let Ok(all) = scan_channels(&req, 3, true) else {
            return TestResult::Fail("default colocated scan refused");
        };
        if all.len() != 39 + 59 || all[39] != 181 || all[97] != 239 {
            return TestResult::Fail("colocated default 6 GHz sband");
        }
        if scan_channels(&req, 3, false) != Err(WirelessError::NotSupported) {
            return TestResult::Fail("colocated scan without MT_NIC_CAP_6G");
        }
        // 6 GHz is selected by frequency (6 GHz channel 37 = 6135 MHz) only.
        req.colocated_6ghz = false;
        req.frequencies_mhz = vec![2437, 6135];
        if scan_channels(&req, 3, true) != Ok(vec![6, 190])
            || scan_channels(&req, 3, false) != Err(WirelessError::NotSupported)
        {
            return TestResult::Fail("6 GHz frequency to scan id");
        }
        req.channels = vec![6, 37];
        if scan_channels(&req, 3, true) != Ok(vec![6, 190]) {
            return TestResult::Fail("legacy selector names 6 GHz channel numbers");
        }
        req.frequencies_mhz.clear();
        req.channels = vec![190];
        if scan_channels(&req, 3, true) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("a bare number selected a 6 GHz scan id");
        }
        // A 2.4 GHz beacon whose RNR names a colocated AP on 6 GHz channel 33
        // (operating class 131, TBTT length 13, colocated + same SSID).
        let mut ies = vec![0, 4];
        ies.extend_from_slice(b"narf");
        ies.extend_from_slice(&[201, 17, 0x00, 13, 131, 33, 0]);
        ies.extend_from_slice(&[2, 9, 8, 7, 6, 5]);
        ies.extend_from_slice(&[0, 0, 0, 0, 0x42, 0xfe]);
        let found = [ScanBss {
            bssid: [2, 1, 2, 3, 4, 5],
            ssid: b"narf".to_vec(),
            channel: 6,
            band: None,
            signal_dbm: Some(-40),
            capability: 0x11,
            beacon_interval: 100,
            information_elements: ies,
        }];
        let six: Vec<u8> = crate::mt7921::channel::channels_6ghz()
            .filter_map(|n| {
                crate::mt7921::channel::rx_channel(crate::mt7921::channel::Band::Ghz6, n)
            })
            .collect();
        req.channels.clear();
        req.colocated_6ghz = true;
        let ids = six_ghz_scan_ids(&req, &six, &found);
        // PSC channels (5, 21, ..., 229) are scanned blind, plus the RNR's non-PSC 33.
        let psc: Vec<u8> = (0..15u8).map(|k| 181 + (5 + 16 * k - 1) / 4).collect();
        if !ids.contains(&189)
            || !psc.iter().all(|id| ids.contains(id))
            || ids.len() != psc.len() + 1
        {
            return TestResult::Fail("cfg80211_scan_6ghz colocated selection");
        }
        // Without the flag every requested 6 GHz channel is scanned, and
        // nothing is scanned when no 6 GHz channel was requested.
        req.colocated_6ghz = false;
        if six_ghz_scan_ids(&req, &six, &found) != six
            || !six_ghz_scan_ids(&req, &[], &found).is_empty()
        {
            return TestResult::Fail("non-colocated 6 GHz phase");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/scan",
        mt76_colocated_6ghz_scan_selects_rnr_and_psc_channels
    );

    fn mt76_active_scan_default_filters_policy_and_explicit_denial_is_closed() -> TestResult {
        use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
        let mut request = ScanRequest {
            ssids: vec![b"hidden".to_vec()],
            frequencies_mhz: Vec::new(),
            channels: Vec::new(),
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        };
        let mut domain = RegulatoryDomain {
            country_code: *b"US",
            rules: vec![
                RegRule {
                    freq_start_mhz: 2402,
                    freq_end_mhz: 2472,
                    max_bandwidth_mhz: 20,
                    max_power_dbm: 17,
                    flags: RegFlags::empty(),
                },
                RegRule {
                    freq_start_mhz: 5170,
                    freq_end_mhz: 5895,
                    max_bandwidth_mhz: 20,
                    max_power_dbm: 14,
                    flags: RegFlags::empty(),
                },
                RegRule {
                    freq_start_mhz: 5250,
                    freq_end_mhz: 5730,
                    max_bandwidth_mhz: 20,
                    max_power_dbm: 14,
                    flags: RegFlags::DFS,
                },
            ],
        };
        let hardware = scan_channels(&request, 3, false).unwrap();
        let channels = active_channels(&request, hardware, &domain).unwrap();
        if channels.len() != 23
            || !channels.contains(&6)
            || !channels.contains(&36)
            || channels.contains(&52)
            || channels.contains(&144)
        {
            return TestResult::Fail(
                "implicit active scan did not select current non-DFS hardware channels",
            );
        }
        request.channels = vec![52];
        if active_channels(&request, vec![52], &domain) != Err(WirelessError::Denied) {
            return TestResult::Fail("explicit DFS scan was silently widened or downgraded");
        }
        domain.rules[2] = RegRule {
            freq_start_mhz: 2427,
            freq_end_mhz: 2447,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::NO_IR,
        };
        request.channels = vec![6];
        if active_channels(&request, vec![6], &domain) != Err(WirelessError::Denied) {
            return TestResult::Fail("explicit NO_IR scan obtained probe authority");
        }
        request.active = false;
        request.ssids.clear();
        if scan_channels(&request, 3, false) != Ok(vec![6]) {
            return TestResult::Fail(
                "NO_IR deployment restriction disabled passive receive geometry",
            );
        }
        request.active = true;
        request.ssids = vec![Vec::new(); 5];
        if scan_channels(&request, 3, false) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("active scan accepted more than Linux's four SSIDs");
        }
        request.ssids = vec![vec![0; 33]];
        if scan_channels(&request, 3, false) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("oversized active scan SSID accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/scan",
        mt76_active_scan_default_filters_policy_and_explicit_denial_is_closed
    );
    fn mt76_iface_association_validation_and_link_state() -> TestResult {
        let iface = Mt76Iface::new(String::from("wlan0"), radio()).unwrap();
        if iface.link_up() || iface.connected_bssid().is_some() {
            return TestResult::Fail("initial state should be unassociated");
        }
        let bad_req = AssociateRequest {
            bssid: [0; 6],
            ssid: Vec::new(),
            frequency_mhz: 2437,
            channel: 6,
            security: narf_wireless::SecurityConfig::Open,
            ie: Vec::new(),
        };
        let err = narf_scheduler::block_on_spin(iface.associate(bad_req));
        if err != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("invalid BSSID/SSID accepted");
        }
        let req = AssociateRequest {
            bssid: [2, 0, 0, 0, 0, 2],
            ssid: b"narf".to_vec(),
            frequency_mhz: 2437,
            channel: 6,
            security: narf_wireless::SecurityConfig::Open,
            ie: Vec::new(),
        };
        let err = narf_scheduler::block_on_spin(iface.associate(req));
        if err != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("non-scanned BSS accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/association",
        mt76_iface_association_validation_and_link_state
    );
    fn mt76_iface_rejects_frequency_and_security_before_recovery_io() -> TestResult {
        let iface = Mt76Iface::new(String::from("wlan0"), radio()).unwrap();
        iface.teardown_needed.store(true, Ordering::Release);
        for (frequency_mhz, ie, expected) in [
            (5180, Vec::new(), WirelessError::InvalidArgs),
            (2437, vec![244, 1, 0], WirelessError::NotSupported),
            (2437, vec![48, 20, 1], WirelessError::InvalidArgs),
        ] {
            let req = AssociateRequest {
                bssid: [2, 1, 2, 3, 4, 5],
                ssid: b"narf".to_vec(),
                frequency_mhz,
                channel: 6,
                security: narf_wireless::SecurityConfig::Open,
                ie,
            };
            if narf_scheduler::block_on_spin(iface.associate(req)) != Err(expected)
                || !iface.teardown_needed.load(Ordering::Acquire)
                || iface.link_up()
            {
                return TestResult::Fail("invalid association reached recovery or opened carrier");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/association",
        mt76_iface_rejects_frequency_and_security_before_recovery_io
    );
    fn mt76_iface_ring_admission_and_link_cleanup() -> TestResult {
        let iface = Mt76Iface::new(String::from("wlan0"), radio()).unwrap();
        if iface.link_up() || iface.rx_ring().lock().is_some() || iface.tx_ring().lock().is_some() {
            return TestResult::Fail("initial datapath state");
        }
        let (tx_p, tx_c) = narf_ipc::channel::<Frame, TX_RING_N>();
        let (rx_p, rx_c) = narf_ipc::channel::<Frame, RX_RING_N>();
        *iface.tx_ring.lock() = Some(tx_p);
        *iface.rx_ring.lock() = Some(rx_c);
        *iface.tx_cons.lock() = Some(tx_c);
        *iface.rx_prod.lock() = Some(rx_p);
        *iface.associated_bssid.lock() = Some([2, 0, 0, 0, 0, 2]);

        if !iface.link_up() || iface.rx_ring().lock().is_none() || iface.tx_ring().lock().is_none()
        {
            return TestResult::Fail("associated datapath ring state");
        }

        let tx_payload = [2, 0, 0, 0, 0, 2, 2, 0, 0xde, 0xad, 0xbe, 0xef, 0x08, 0x00];
        // Capability ring producers bypass enqueue(). Their malformed frames
        // must be discarded without closing carrier or blocking the next one.
        let mut forged_source = tx_payload;
        forged_source[6] = 4;
        let mut eapol = tx_payload;
        eapol[12..14].copy_from_slice(&[0x88, 0x8e]);
        let mut length_frame = tx_payload;
        length_frame[12..14].copy_from_slice(&[0, 8]);
        for bytes in [
            forged_source.as_slice(),
            &eapol,
            &length_frame,
            &tx_payload[..13],
        ] {
            let Ok(mut buffer) =
                narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            else {
                return TestResult::Skip("alloc_coherent unavailable");
            };
            buffer.as_mut_slice()[..bytes.len()].copy_from_slice(bytes);
            if iface
                .tx_ring()
                .lock()
                .as_mut()
                .unwrap()
                .try_send(Frame::new(buffer, bytes.len() as u32))
                .is_err()
            {
                return TestResult::Fail("malformed fixture ring push");
            }
        }
        let mut tx_buf =
            match narf_io::alloc_coherent(tx_payload.len(), narf_lib::id::DomainId::DRIVER_0) {
                Ok(b) => b,
                Err(_) => return TestResult::Skip("alloc_coherent unavailable"),
            };
        tx_buf.as_mut_slice()[..tx_payload.len()].copy_from_slice(&tx_payload);
        let frame = Frame::new(tx_buf, tx_payload.len() as u32);
        if iface
            .tx_ring()
            .lock()
            .as_mut()
            .unwrap()
            .try_send(frame)
            .is_err()
        {
            return TestResult::Fail("tx_ring push failed");
        }
        let Some(popped_frame) = iface.next_tx() else {
            return TestResult::Fail("tx_cons pop failed");
        };
        if popped_frame.len() != 14
            || popped_frame.payload() != tx_payload
            || !iface.link_up()
            || iface.next_tx().is_some()
        {
            return TestResult::Fail("tx_cons pop mismatch");
        }

        let rx_payload = [2, 0, 0xde, 0xad, 0xbe, 0xef, 2, 0, 0, 0, 0, 2, 0x08, 0x00];
        let mut rx_buf =
            match narf_io::alloc_coherent(rx_payload.len(), narf_lib::id::DomainId::DRIVER_0) {
                Ok(b) => b,
                Err(_) => return TestResult::Skip("alloc_coherent unavailable"),
            };
        rx_buf.as_mut_slice()[..rx_payload.len()].copy_from_slice(&rx_payload);
        let rx_frame = Frame::new(rx_buf, rx_payload.len() as u32);
        if iface
            .rx_prod
            .lock()
            .as_mut()
            .unwrap()
            .try_send(rx_frame)
            .is_err()
        {
            return TestResult::Fail("rx_prod push failed");
        }
        let received = iface.rx_ring().lock().as_mut().unwrap().try_recv();
        let Ok(Some(received_frame)) = received else {
            return TestResult::Fail("rx_ring pop failed");
        };
        if received_frame.len() != 14 || received_frame.payload() != rx_payload {
            return TestResult::Fail("rx_ring pop mismatch");
        }

        *iface.tx_ring.lock() = None;
        *iface.rx_ring.lock() = None;
        *iface.tx_cons.lock() = None;
        *iface.rx_prod.lock() = None;
        *iface.associated_bssid.lock() = None;

        if iface.link_up() || iface.rx_ring().lock().is_some() || iface.tx_ring().lock().is_some() {
            return TestResult::Fail("post-disassociate datapath cleanup");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/association",
        mt76_iface_ring_admission_and_link_cleanup
    );
}

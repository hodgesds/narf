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
        bands
    }

    /// Transmit an 802.3 Ethernet frame over the associated wireless datapath.
    pub async fn transmit_frame(&self, frame: &[u8]) -> Result<(), WirelessError> {
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

    /// Receive an 802.3 Ethernet frame from the wireless datapath.
    pub async fn receive_frame(&self) -> Result<Option<Vec<u8>>, WirelessError> {
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
        self.receive_epoch.store(0, Ordering::Release);
        *self.associated_bssid.lock() = None;
        publish_link(&self.name, false);
        *self.pending_tx.lock() = None;
        *self.tx_ring.lock() = None;
        *self.rx_ring.lock() = None;
        *self.tx_cons.lock() = None;
        *self.rx_prod.lock() = None;
    }

    fn lose_link(&self) {
        let connected = self.link_up();
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
        self.teardown_needed.store(false, Ordering::Release);
        self.recovery_attempts.store(0, Ordering::Release);
        self.recovery_after_ns.store(0, Ordering::Release);
        Ok(())
    }

    fn enqueue(&self, bytes: &[u8]) -> Result<(), ()> {
        if !self.link_up() || !transmit_admitted(bytes, self.mac()) {
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
        self.associated_bssid.lock().is_some()
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
            modes: WirelessModes::STATION,
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
        let mut channels = scan_channels(&req, self.radio.capabilities.phy.bands)?;
        let ssids = if req.active {
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
            return Err(WirelessError::Busy);
        }
        self.finish_teardown(true).await?;
        {
            use crate::mt7921::firmware_transport::{scan_boot_with_options, Error, ScanOptions};
            let result = scan_boot_with_options(
                &channels,
                &ssids,
                ScanOptions {
                    extra_ies: &req.extra_ies,
                    random_mac: req.random_mac,
                },
            )
            .await;
            let report = result.map_err(|error| match error {
                Error::Bounds => WirelessError::InvalidArgs,
                Error::Busy => WirelessError::Busy,
                Error::Timeout => WirelessError::Timeout,
                Error::Authority => WirelessError::Denied,
                _ => WirelessError::HardwareError,
            })?;
            let results = report
                .bss
                .iter()
                .map(|bss| BssInfo {
                    bssid: bss.bssid,
                    ssid: bss.ssid.clone(),
                    frequency_mhz: crate::mt7921::channel::frequency(bss.channel).unwrap_or(0),
                    channel: u32::from(bss.channel),
                    rssi: bss.signal_dbm.unwrap_or(-128),
                    security: scan_security(bss),
                })
                .collect();
            *self.scan_cache.lock() = report.bss;
            Ok(results)
        }
    }

    fn connected_bssid(&self) -> Option<[u8; 6]> {
        *self.associated_bssid.lock()
    }

    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        let _control = self.control.lock().await;
        let channel = u8::try_from(req.channel).map_err(|_| WirelessError::InvalidArgs)?;
        if crate::mt7921::channel::frequency(channel) != Some(req.frequency_mhz) {
            return Err(WirelessError::InvalidArgs);
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
            narf_wireless::SecurityConfig::Wpa2 { .. } => true,
            _ => return Err(WirelessError::NotSupported),
        };
        crate::mt7921::association::validate_sme_ies(&req.ie, protected).map_err(|error| {
            match error {
                crate::mt7921::association::Error::InvalidBss => WirelessError::InvalidArgs,
                _ => WirelessError::NotSupported,
            }
        })?;
        self.finish_teardown(true).await?;
        if self.link_up() {
            return Err(WirelessError::Busy);
        }
        let security = match req.security {
            narf_wireless::SecurityConfig::Open => crate::mt7921::association::Security::Open,
            narf_wireless::SecurityConfig::Wpa2 { psk } => {
                crate::mt7921::association::Security::Wpa2Psk { psk }
            }
            narf_wireless::SecurityConfig::Wpa3 { .. } => return Err(WirelessError::NotSupported),
            // No external-supplicant mode: mt7921's firmware path runs the
            // handshake from the PMK (nl80211 never builds this for it).
            narf_wireless::SecurityConfig::External(_) => return Err(WirelessError::NotSupported),
        };
        let bss = self
            .scan_cache
            .lock()
            .iter()
            .find(|b| {
                b.bssid == req.bssid && b.ssid == req.ssid && u32::from(b.channel) == req.channel
            })
            .cloned()
            .ok_or(WirelessError::InvalidArgs)?;

        let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| WirelessError::Denied)?;
        crate::mt7921::association::TxPermission::from_domain(&domain, bss.channel)
            .ok_or(WirelessError::Denied)?;

        {
            use crate::mt7921::firmware_transport::{associate_boot_station, Error};
            let aid = associate_boot_station(&bss, &req.ssid, security, &req.ie)
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
fn scan_channels(req: &ScanRequest, bands: u8) -> Result<Vec<u8>, WirelessError> {
    use crate::mt7921::channel;
    if req.colocated_6ghz || req.duration_mandatory || req.duration_tu.is_some() {
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
                channel::from_frequency(freq)
                    .map(u32::from)
                    .ok_or(WirelessError::NotSupported)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !req.channels.is_empty()
            && (req.channels.len() != channels.len()
                || !req
                    .channels
                    .iter()
                    .all(|channel| channels.contains(channel)))
        {
            return Err(WirelessError::InvalidArgs);
        }
        channels
    };
    if requested.is_empty() {
        return Ok(channel::channels(bands));
    }
    let mut channels = Vec::new();
    for requested in requested {
        let value = u8::try_from(requested).map_err(|_| WirelessError::InvalidArgs)?;
        let band = channel::band(value).ok_or(WirelessError::InvalidArgs)?;
        if bands & band.capability() == 0 {
            return Err(WirelessError::NotSupported);
        }
        if channels.contains(&value) {
            return Err(WirelessError::InvalidArgs);
        }
        channels.push(value);
    }
    Ok(channels)
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
    // Reusing our retained interface grants no new registry access and must
    // not depend on the authority used for its original publication.
    if let Some(existing) = ACTIVE.lock().as_ref() {
        return if existing.radio.chip_id == info.chip_id
            && existing.radio.capabilities == info.capabilities
            && existing.radio.hardware_type == info.hardware_type
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
    // Bootstrap before control-plane discovery/association can query the
    // domain. Missing deployment policy still permits the receive-only scan
    // interface; TX admission retries the same signed bootstrap and fails shut.
    if let Err(error) = narf_wireless::reg::db::ensure_domain() {
        use core::fmt::Write;
        let _ = writeln!(narf_console::Writer, "mt76: regulatory policy: {}", error);
    }
    iface.name = narf_net::iface::register("wlan%d", info.capabilities.mac, send_frame);
    publish_link(&iface.name, false);
    let iface = Arc::new(iface);
    if narf_net::registry()
        .register(&authority, RegisteredIface(iface.clone()))
        .is_err()
    {
        narf_net::iface::unregister(&iface.name);
        return Err(WirelessError::HardwareError);
    }
    *ACTIVE.lock() = Some(iface.clone());
    narf_wireless::registry::register(iface.clone());
    narf_net::iface::install_rx_drain(drain_network);
    let worker = iface.clone();
    narf_scheduler::spawn(async move {
        loop {
            let _ = worker.poll_data().await;
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    });
    Ok(iface)
}

static ACTIVE: IrqSafeSpinLock<Option<Arc<Mt76Iface>>> = IrqSafeSpinLock::new(None);

fn send_frame(bytes: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    let iface = ACTIVE.lock().clone().ok_or(())?;
    iface.enqueue(bytes)
}

fn drain_network() -> bool {
    let iface = ACTIVE.lock().clone();
    iface.is_some_and(|iface| iface.drain_network().unwrap_or(false))
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
    fn mt76_scan_interface_reports_implemented_profile() -> TestResult {
        let iface = Mt76Iface::new(String::from("wlan7"), radio()).unwrap();
        let info = iface.get_wireless_info();
        if iface.name() != "wlan7"
            || iface.mac() != radio().capabilities.mac
            || iface.link_up()
            || iface.rx_ring().lock().is_some()
            || iface.tx_ring().lock().is_some()
            || info.base_name != "wlan7"
            || info.bands.len() != 2
            || info.bands[0].channels != (1..=11).collect::<Vec<_>>()
            || !info.hw_caps.ht_supported
            || iface
                .phy_capabilities(2400)
                .is_none_or(|caps| caps.ht[..5] != [127, 1, 28, 255, 255] || caps.vht.is_some())
            || iface.phy_capabilities(6000).is_some()
            || !info.hw_caps.vht_supported
            || iface
                .phy_capabilities(5000)
                .is_none_or(|caps| caps.vht != Some([48, 1, 0, 0, 250, 255, 0, 0, 250, 255, 0, 0]))
            || info.hw_caps.he_supported
            || info.hw_caps.eht_supported
            || !iface.supports_handshake_offload()
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
        if scan_channels(&req, 3) != Ok(vec![1, 6, 11]) {
            return TestResult::Fail("valid passive request");
        }
        req.active = true;
        if scan_channels(&req, 3) != Ok(vec![1, 6, 11]) {
            return TestResult::Fail("active wildcard geometry rejected");
        }
        req.extra_ies = vec![221, 3, 0x50, 0x6f, 0x9a];
        if scan_channels(&req, 3) != Ok(vec![1, 6, 11]) {
            return TestResult::Fail("native active probe IE profile rejected");
        }
        req.active = false;
        if scan_channels(&req, 3) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("passive scan accepted probe IEs");
        }
        req.extra_ies.clear();
        req.random_mac = Some(narf_wireless::ScanRandomMac {
            addr: [2, 0, 0, 0, 0, 0],
            mask: [3, 0, 0, 0, 0, 0],
        });
        if scan_channels(&req, 3) != Ok(vec![1, 6, 11]) {
            return TestResult::Fail("native passive random scan geometry rejected");
        }
        req.random_mac.as_mut().unwrap().mask[0] = 0;
        if scan_channels(&req, 3) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("unbounded multicast random address mask accepted");
        }
        req.random_mac = None;
        req.ssids.push(Vec::new());
        if scan_channels(&req, 3) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("inconsistent passive request with probe SSIDs accepted");
        }
        req.ssids.clear();
        req.channels = vec![35];
        if scan_channels(&req, 3) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("unimplemented band exposed");
        }
        req.channels = vec![1, 1];
        if scan_channels(&req, 3) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("duplicate channel");
        }
        req.channels.clear();
        if scan_channels(&req, 3) != Ok(crate::mt7921::channel::channels(3)) {
            return TestResult::Fail("default scan channels");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/scan",
        mt76_scan_policy_validates_active_ssids_and_channel_geometry
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
        let hardware = scan_channels(&request, 3).unwrap();
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
        if scan_channels(&request, 3) != Ok(vec![6]) {
            return TestResult::Fail(
                "NO_IR deployment restriction disabled passive receive geometry",
            );
        }
        request.active = true;
        request.ssids = vec![Vec::new(); 5];
        if scan_channels(&request, 3) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("active scan accepted more than Linux's four SSIDs");
        }
        request.ssids = vec![vec![0; 33]];
        if scan_channels(&request, 3) != Err(WirelessError::InvalidArgs) {
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

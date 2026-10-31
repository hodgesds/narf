// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual Device/firmware/USB/MLME/RSNA/DHCP over a channel-sensitive device.
//! The AP stays on6. Hardware FIFOs survive USB Stop and are cleared only by
//! the actual observed cold NIC reset, never by a channel-label assignment.
use super::super::super::super::{
    firmware_transport::{Owner, Stage as FirmwareStage},
    firmware_transport_tests::initialized_registered_firmware,
    wmm_runtime::Proof,
};
use super::super::{factory_bytes, Calibration, HEADER, UNKNOWN};
use super::*;
use core::sync::atomic::AtomicBool;
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;

#[derive(Clone)]
struct ChannelLink {
    bulk: Link,
    control: Fake,
    seen_reset: Arc<AtomicU64>,
    beacon: Arc<AtomicBool>,
    beacon_generation: Arc<AtomicU64>,
}
impl ChannelLink {
    fn synchronize_reset(&self) -> Result<(), UsbError> {
        let generation = self.control.0.lock().cold_generation;
        if self.seen_reset.swap(generation, Ordering::AcqRel) != generation {
            let mut peer = self.bulk.0.lock();
            if peer.rx.is_some() || peer.tx.is_some() {
                return Err(UsbError::Stall);
            }
            peer.queue.clear();
            peer.raw_queue.clear();
        }
        Ok(())
    }
    fn physical(&self) -> (u8, bool, bool) {
        let model = self.control.0.lock();
        (
            (model.rf[0x18] & 0xff) as u8,
            model.regs[0x100] & 0x80 != 0,
            model.regs[0x100] & 0xc0 == 0xc0,
        )
    }
}
#[async_trait::async_trait]
impl Io for ChannelLink {
    type Receipt = u64;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<u64, UsbError> {
        self.synchronize_reset()?;
        self.bulk.begin_receive(dci, length)
    }
    fn poll_receive(&self, receipt: &u64, out: &mut [u8]) -> Result<Option<usize>, UsbError> {
        self.synchronize_reset()?;
        let (channel, receiving, _) = self.physical();
        let generation = self.control.0.lock().cold_generation;
        if channel == 6
            && receiving
            && self.beacon.load(Ordering::Acquire)
            && self.beacon_generation.load(Ordering::Acquire) != generation
        {
            let mut peer = self.bulk.0.lock();
            if peer.queue.is_empty() && peer.raw_queue.is_empty() {
                // A finite beacon on each physical receive stream leaves an
                // actual quiet poll after EAPOL delivery. An infinite beacon
                // on every empty poll would never retire that RX prefix.
                let beacon = peer.ap.beacon();
                peer.queue.push_back(beacon);
                self.beacon_generation.store(generation, Ordering::Release);
            }
        }
        self.bulk.poll_receive(receipt, out)
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<u64, UsbError> {
        let (channel, _, transmitting) = self.physical();
        if channel != 6 || !transmitting {
            return Err(UsbError::Stall);
        }
        self.bulk.begin_send(dci, bytes)
    }
    fn poll_send(&self, receipt: &u64) -> Result<Option<usize>, UsbError> {
        self.bulk.poll_send(receipt)
    }
    async fn stop(&self, receipt: &u64) -> Result<(), UsbError> {
        self.bulk.stop(receipt).await
    }
}

type ChannelDevice = Device<Fake, ChannelLink, Env>;
static ACTIVE_CHANNEL: IrqSafeSpinLock<Option<Arc<ChannelDevice>>> = IrqSafeSpinLock::new(None);
fn send_channel(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE_CHANNEL.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain_channel() -> bool {
    let device = ACTIVE_CHANNEL.lock().clone();
    device.is_some_and(|device| device.drain())
}
fn drive<T>(future: impl Future<Output = T>) -> Result<T, &'static str> {
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..10_000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return Ok(value);
        }
    }
    Err("EU channel fixture exceeded its bounded native poll budget")
}
fn calibration(factory: super::super::super::super::device_init::Factory) -> Calibration {
    let original = super::super::fixture();
    let mut bytes = original[..HEADER].to_vec();
    for channel in [1, 6, 11, 13] {
        let mut row = original[HEADER..].to_vec();
        row[0] = channel;
        for offset in [4 + 31 * 2, 132 + 21 * 2] {
            row[offset..offset + 2].copy_from_slice(&UNKNOWN.to_le_bytes());
        }
        bytes.extend_from_slice(&row);
    }
    let length = bytes.len() as u32;
    bytes[8..12].copy_from_slice(&length.to_le_bytes());
    bytes[12..41].copy_from_slice(&factory_bytes(factory, 0x0bda, 0x8179));
    bytes[46..48].copy_from_slice(&4u16.to_le_bytes());
    Calibration::from_verified(
        &bytes,
        Some([0x55; 32]),
        [0x77; 32],
        factory,
        0x0bda,
        0x8179,
    )
    .unwrap()
}
struct Fixture {
    device: Arc<ChannelDevice>,
    link: ChannelLink,
    control: Fake,
    source: Cap<FirmwareBlob, Read>,
    firmware: Arc<Owner<Fake>>,
    name: String,
}
impl Fixture {
    #[inline(never)]
    fn new(protected: bool) -> Result<Box<Self>, &'static str> {
        let (control, firmware) = initialized_registered_firmware();
        let factory = firmware.factory().ok_or("EU channel factory")?;
        let domain = Arc::new(IrqSafeSpinLock::new(narf_wireless::reg::RegulatoryDomain {
            country_code: *b"US",
            rules: vec![narf_wireless::reg::RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2482,
                max_bandwidth_mhz: 20,
                max_power_dbm: 17,
                flags: narf_wireless::reg::RegFlags::empty(),
            }],
        }));
        let calibration = calibration(factory);
        let power = calibration
            .permission(&domain.lock(), 1)
            .map_err(|_| "EU channel power")?;
        let source = Cap::<FirmwareBlob, Read>::bootstrap();
        let proof = Proof::model(calibration, power, source, domain.clone());
        let network = plan(factory.mac);
        let mut peer = Peer::new(network, protected);
        peer.ap = if protected {
            FakeAp::wpa2(network, SSID, 6, 42, PMK, ANONCE)
        } else {
            FakeAp::open(network, SSID, 6, 42)
        }
        .unwrap()
        .with_basic_1mbps()
        .unwrap();
        let link = ChannelLink {
            bulk: Link(Arc::new(IrqSafeSpinLock::new(peer))),
            control: control.clone(),
            seen_reset: Arc::new(AtomicU64::new(control.0.lock().cold_generation)),
            beacon: Arc::new(AtomicBool::new(true)),
            beacon_generation: Arc::new(AtomicU64::new(u64::MAX)),
        };
        let mut receiver = Receiver::new(
            firmware.clone(),
            link.clone(),
            ReceivePermission::from_domain(&domain.lock())
                .map_err(|_| "EU channel receive policy")?,
        )
        .map_err(|_| "EU channel retained receiver")?;
        receiver.install_wmm_model(proof);
        let service = drive(Service::start(receiver, power, Env::default()))?
            .map_err(|_| "EU channel native service")?;
        let name = narf_net::iface::register("wlan%d", factory.mac, send_channel);
        narf_net::iface::set_link_state(&name, true);
        let device = Arc::new(Device::new(&name, service));
        *ACTIVE_CHANNEL.lock() = Some(device.clone());
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain_channel);
        Ok(Box::new(Self {
            device,
            link,
            control,
            source,
            firmware,
            name,
        }))
    }
    fn scan(&self) -> ScanRequest {
        ScanRequest {
            ssids: vec![SSID.to_vec()],
            channels: vec![1, 6, 11, 13],
            frequencies_mhz: Vec::new(),
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(2),
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }
    }
    fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: AP,
            ssid: SSID.to_vec(),
            channel: 6,
            frequency_mhz: 2437,
            security: if self.link.bulk.0.lock().ap.protected() {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        *ACTIVE_CHANNEL.lock() = None;
        narf_net::iface::set_link_state(&self.name, false);
        narf_net::iface::set_link_metadata(&self.name, false, None, None);
        narf_net::iface::unregister(&self.name);
    }
}

fn conversation(protected: bool) -> Result<(), &'static str> {
    let h = Fixture::new(protected)?;
    // A queued pre-reset beacon advertises6 even though it was copied on1.
    // It must not gain a new physical channel from a stopped USB receipt.
    let old_beacon = h.link.bulk.0.lock().ap.beacon();
    h.link.bulk.0.lock().queue.push_back(old_beacon);
    let old = h.link.bulk.0.lock().rx.ok_or("EU old native RX receipt")?;
    let results = drive(h.device.scan(h.scan()))?.map_err(|_| "EU expanded native scan")?;
    ensure!(
        results.len() == 1 && results[0].channel == 6 && results[0].frequency_mhz == 2437,
        "EU physical per-channel discovery or metadata differs"
    );
    ensure!(
        h.control.0.lock().rf[0x18] & 0xff == 1
            && h.control.0.lock().cold_generation >= 4
            && h.link.bulk.0.lock().rx != Some(old),
        "EU scan did not restore home through actual fresh NIC/USB ownership"
    );
    drive(h.device.associate(h.request()))?.map_err(|_| "EU native off-home association/RSNA")?;
    ensure!(
        h.control.0.lock().rf[0x18] & 0xff == 6 && h.device.link_up(),
        "EU selected channel6 did not own carrier"
    );
    let network = h.link.bulk.0.lock().network;
    let lease = narf_net::dhcp::dhcp_acquire(&h.name, 0).map_err(|_| "EU off-home actual DHCP")?;
    ensure!(
        network.matches_lease(&lease),
        "EU off-home DHCP lease identity"
    );
    ensure!(
        h.control.0.lock().unsafe_reuses == 0,
        "EU retune reused an unretired native EP0 transfer"
    );
    Ok(())
}
fn smoke_rtl8188eu_channels_open_cold_retune_scan_and_native_dhcp() -> TestResult {
    conversation(false).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
fn smoke_rtl8188eu_channels_wpa2_cold_retune_scan_and_native_dhcp() -> TestResult {
    conversation(true).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/channels",
    smoke_rtl8188eu_channels_open_cold_retune_scan_and_native_dhcp
);
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/channels",
    smoke_rtl8188eu_channels_wpa2_cold_retune_scan_and_native_dhcp
);

fn stale_observation() -> Result<(), &'static str> {
    let h = Fixture::new(false)?;
    drive(h.device.scan(h.scan()))?.map_err(|_| "EU stale observation initial scan")?;
    h.link.beacon.store(false, Ordering::Release);
    ensure!(
        drive(h.device.associate(h.request()))?.is_err()
            && h.link.bulk.0.lock().sent == 0
            && !h.device.link_up(),
        "EU old-stream beacon authorized a fresh native join"
    );
    Ok(())
}
fn smoke_rtl8188eu_channels_require_fresh_target_observation_after_restart() -> TestResult {
    stale_observation().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/channels",
    smoke_rtl8188eu_channels_require_fresh_target_observation_after_restart
);

fn cancellation() -> Result<(), &'static str> {
    for revoked in [false, true] {
        let h = Fixture::new(false)?;
        h.control.0.lock().pending_write = Some(0x284);
        let mut scan = Box::pin(h.device.scan(h.scan()));
        let mut published = false;
        for _ in 0..64 {
            ensure!(
                scan.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "EU retune ended before its held EP0 publication"
            );
            if h.control.0.lock().active_td {
                published = true;
                break;
            }
        }
        ensure!(
            published && h.control.0.lock().active_td,
            "EU retune did not retain its published EP0 wait"
        );
        if revoked {
            h.source.revoke();
            ensure!(
                drive(scan.as_mut())?.is_err(),
                "EU revoked retune source resumed a pending transfer"
            );
        }
        drop(scan);
        let operations = h.control.0.lock().ops.len();
        ensure!(
            drive(h.device.scan(h.scan()))?.is_err()
                && h.control.0.lock().ops.len() == operations
                && h.control.0.lock().unsafe_reuses == 0
                && h.control.0.lock().cold_generation == 0
                && h.link.bulk.0.lock().rx.is_some(),
            "EU cancelled/source-lost transition reused EP0 or released its old USB claim"
        );
    }
    let h = Fixture::new(false)?;
    h.source.revoke();
    let operations = h.control.0.lock().ops.len();
    let mut request = h.scan();
    request.channels.clear();
    ensure!(
        drive(h.device.scan(request))?.is_err()
            && h.firmware.status().stage == FirmwareStage::Failed
            && h.control.0.lock().ops.len() == operations
            && h.link.bulk.0.lock().rx.is_some(),
        "EU default scan hid current-source loss as an empty qualified set"
    );
    Ok(())
}
fn smoke_rtl8188eu_channels_cancel_and_source_loss_keep_native_receipts_retained() -> TestResult {
    cancellation().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/channels",
    smoke_rtl8188eu_channels_cancel_and_source_loss_keep_native_receipts_retained
);

fn refused() -> Result<(), &'static str> {
    let h = Fixture::new(false)?;
    let before = h.control.0.lock().ops.len();
    let mut request = h.scan();
    request.channels = vec![5]; // Genuine missing signed row.
    ensure!(
        drive(h.device.scan(request))?.is_err() && h.control.0.lock().ops.len() == before,
        "EU unmeasured requested channel touched the physical radio"
    );
    h.control.0.lock().rx_dma_stalled = true;
    ensure!(
        drive(h.device.scan(h.scan()))?.is_err()
            && h.control.0.lock().cold_generation == 0
            && h.link.bulk.0.lock().rx.is_some(),
        "EU missing actual RXDMA idle receipt became a cold-reset permission"
    );
    Ok(())
}
fn smoke_rtl8188eu_channels_missing_row_and_dma_receipt_fail_before_retune() -> TestResult {
    refused().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/channels",
    smoke_rtl8188eu_channels_missing_row_and_dma_receipt_fail_before_retune
);

fn old_fifo() -> Result<(), &'static str> {
    let h = Fixture::new(false)?;
    h.link.beacon.store(false, Ordering::Release);
    let old_copy = h.link.bulk.0.lock().ap.beacon();
    h.link.bulk.0.lock().queue.push_back(old_copy);
    let mut request = h.scan();
    request.channels = vec![6];
    let result = drive(h.device.scan(request))?.map_err(|_| "EU old-FIFO scan")?;
    ensure!(
        result.is_empty()
            && h.control.0.lock().cold_generation == 2
            && h.control.0.lock().rf[0x18] & 0xff == 1,
        "EU old device FIFO bytes inherited a new channel/capture generation"
    );
    Ok(())
}
fn smoke_rtl8188eu_channels_cold_mac_reset_retires_queued_device_fifo_copies() -> TestResult {
    old_fifo().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/channels",
    smoke_rtl8188eu_channels_cold_mac_reset_retires_queued_device_fifo_copies
);

fn factory_groups() -> Result<(), &'static str> {
    let mut factory = super::super::factory();
    factory.cck_power = [20, 21, 22, 23, 24, 25];
    factory.ht40_power = [25, 26, 27, 28, 29];
    let original = super::super::fixture();
    let mut bytes = original[..HEADER].to_vec();
    for channel in 1..=13 {
        let mut row = original[HEADER..].to_vec();
        row[0] = channel;
        row[4..].fill(0); // Independent dimensional bounds, never physical qualification.
        bytes.extend_from_slice(&row);
    }
    let length = bytes.len() as u32;
    bytes[8..12].copy_from_slice(&length.to_le_bytes());
    bytes[12..41].copy_from_slice(&factory_bytes(factory, 0x0bda, 0x8179));
    bytes[46..48].copy_from_slice(&13u16.to_le_bytes());
    let calibration = Calibration::from_verified(
        &bytes,
        Some([0x55; 32]),
        [0x77; 32],
        factory,
        0x0bda,
        0x8179,
    )
    .map_err(|_| "EU literal multi-channel qualification geometry")?;
    let mut domain = super::super::domain(17);
    domain.rules[0].freq_end_mhz = 2482;
    for (channel, gains) in [
        (1, (20, 25)),
        (2, (20, 25)),
        (3, (21, 26)),
        (5, (21, 26)),
        (6, (22, 27)),
        (8, (22, 27)),
        (9, (23, 28)),
        (11, (23, 28)),
        (12, (24, 29)),
        (13, (24, 29)),
    ] {
        let selected = calibration
            .permission(&domain, channel)
            .map_err(|_| "EU source factory group selected no qualified gain")?;
        ensure!(
            selected.gains(factory, 0x0bda, 0x8179, channel) == Ok(gains),
            "EU selected channel exceeded or used another group's factory ceiling"
        );
    }
    domain.rules.push(narf_wireless::reg::RegRule {
        freq_start_mhz: 2430,
        freq_end_mhz: 2431,
        max_bandwidth_mhz: 20,
        max_power_dbm: 17,
        flags: narf_wireless::reg::RegFlags::NO_IR,
    });
    ensure!(
        calibration.permission(&domain, 6).is_err() && calibration.permission(&domain, 1).is_ok(),
        "EU target occupied-band restriction was lost or applied to another channel"
    );
    Ok(())
}
fn smoke_rtl8188eu_channels_literal_factory_groups_and_occupied_band_restrictions() -> TestResult {
    factory_groups().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/channels",
    smoke_rtl8188eu_channels_literal_factory_groups_and_occupied_band_restrictions
);

fn mac_off_receipt() -> Result<(), &'static str> {
    let h = Fixture::new(false)?;
    let stale = h.link.bulk.0.lock().ap.beacon();
    h.link.bulk.0.lock().queue.push_back(stale);
    h.control.0.lock().mac_off_stalled = true;
    let mut request = h.scan();
    request.channels = vec![6];
    ensure!(
        drive(h.device.scan(request))?.is_err()
            && h.firmware.status().stage == FirmwareStage::Failed
            && h.control.0.lock().cold_generation == 0
            && h.control.0.lock().regs[0x5] & 2 != 0
            && !h.link.bulk.0.lock().queue.is_empty()
            && h.link.bulk.0.lock().rx.is_none()
            && !h.device.link_up(),
        "EU RF/LDO or MCU-only reset substituted for missing native MAC-off terminal"
    );
    let operations = h.control.0.lock().ops.len();
    h.control.0.lock().mac_off_stalled = false;
    ensure!(
        drive(h.device.scan(h.scan()))?.is_err()
            && h.control.0.lock().ops.len() == operations
            && h.control.0.lock().unsafe_reuses == 0,
        "EU timed-out card reset reacquired or reused the retained native owner"
    );
    Ok(())
}
fn smoke_rtl8188eu_channels_require_actual_mac_off_state_machine_terminal() -> TestResult {
    mac_off_receipt().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/channels",
    smoke_rtl8188eu_channels_require_actual_mac_off_state_machine_terminal
);

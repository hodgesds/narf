// SPDX-License-Identifier: GPL-2.0-or-later
//! Independent AP/probe observer around actual native firmware/USB/Device.
use super::*;

#[derive(Default)]
struct Probes {
    packets: Vec<(u8, Vec<u8>)>,
    hold: bool,
    short: bool,
    responses: bool,
    air: Option<Air>,
    air_held: bool,
    consumed: usize,
    truncated: usize,
}
struct Air {
    channel: u8,
    ready_ms: u64,
    response: Option<Vec<u8>>,
}
#[derive(Clone)]
struct ProbeLink {
    radio: ChannelLink,
    probes: Arc<IrqSafeSpinLock<Probes>>,
    clock: Env,
}
impl ProbeLink {
    fn advance_air(&self) {
        let (channel, receiving, transmitting) = self.radio.physical();
        let now = self.clock.now_ms();
        let mut probes = self.probes.lock();
        let Some(air) = &probes.air else {
            return;
        };
        if !transmitting || air.channel != channel {
            // NIC accepted the host packet, but the PHY never consumed it
            // while its actual channel/TX gate stayed valid. No AP response.
            probes.truncated += 1;
            probes.air = None;
            return;
        }
        if probes.air_held || now < air.ready_ms {
            return;
        }
        let air = probes.air.take().unwrap();
        if let Some(response) = air.response {
            if receiving {
                self.radio.bulk.0.lock().queue.push_back(response);
            }
        }
        self.radio.control.0.lock().regs[0x5f8..0x5fc].fill(0);
        probes.consumed += 1;
    }
}
#[async_trait::async_trait]
impl Io for ProbeLink {
    type Receipt = u64;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<u64, UsbError> {
        self.radio.begin_receive(dci, length)
    }
    fn poll_receive(&self, receipt: &u64, out: &mut [u8]) -> Result<Option<usize>, UsbError> {
        self.advance_air();
        self.radio.poll_receive(receipt, out)
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<u64, UsbError> {
        if bytes.get(TX_DESC) != Some(&0x40) {
            return self.radio.begin_send(dci, bytes);
        }
        let (channel, _, transmitting) = self.radio.physical();
        let mut probes = self.probes.lock();
        let mut peer = self.radio.bulk.0.lock();
        if !transmitting
            || peer.tx.is_some()
            || dci != 4
            || bytes.len() < TX_DESC + 26
            || usize::from(u16::from_le_bytes([bytes[0], bytes[1]])) != bytes.len() - TX_DESC
            || bytes[2] != 32
            || bytes[3] & 1 != 1
            || bytes[..32]
                .chunks_exact(2)
                .fold(0u16, |sum, b| sum ^ u16::from_le_bytes([b[0], b[1]]))
                != 0
            || u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != 0x1200
            || u32::from_le_bytes(bytes[16..20].try_into().unwrap()) != 0x100
            || u32::from_le_bytes(bytes[20..24].try_into().unwrap()) & 0x7f != 0
        {
            return Err(UsbError::Stall);
        }
        let frame = &bytes[TX_DESC..];
        if frame[1..4] != [0; 3]
            || frame[4..10] != [255; 6]
            || frame[10..16] != peer.network.station
            || frame[16..22] != [255; 6]
            || frame[22] & 15 != 0
            || frame[24] != 0
            || frame[25] > 32
        {
            return Err(UsbError::Stall);
        }
        let ssid = frame
            .get(26..26 + usize::from(frame[25]))
            .ok_or(UsbError::Stall)?;
        if probes.air.is_some() {
            return Err(UsbError::Stall);
        }
        probes.packets.push((channel, bytes.to_vec()));
        let response = if probes.responses && channel == 6 && (ssid.is_empty() || ssid == SSID) {
            let mut response = peer.ap.beacon();
            response[0] = 0x50;
            response[4..10].copy_from_slice(&peer.network.station);
            Some(response)
        } else {
            None
        };
        // Independent device-air clock: long-preamble CCK1 PPDU +FCS.
        // Completion of the host USB TD deliberately does not consume it.
        let ready_ms = self.clock.now_ms() + (192 + 8 * (frame.len() as u64 + 4)).div_ceil(1000);
        probes.air = Some(Air {
            channel,
            ready_ms,
            response,
        });
        self.radio.control.0.lock().regs[0x5f8..0x5fc].copy_from_slice(&1u32.to_le_bytes());
        peer.native_tx.push(bytes.to_vec());
        peer.next_receipt += 1;
        let id = peer.next_receipt;
        peer.tx = Some(Tx {
            id,
            bytes: bytes.len(),
            m4: false,
            data: false,
            control: true,
        });
        peer.sent += 1;
        Ok(id)
    }
    fn poll_send(&self, receipt: &u64) -> Result<Option<usize>, UsbError> {
        let probe = self
            .radio
            .bulk
            .0
            .lock()
            .tx
            .as_ref()
            .is_some_and(|tx| tx.id == *receipt && tx.control);
        if probe && self.probes.lock().hold {
            return Ok(None);
        }
        let result = self.radio.poll_send(receipt)?;
        Ok(result.map(|length| {
            if probe && self.probes.lock().short {
                length - 1
            } else {
                length
            }
        }))
    }
    async fn stop(&self, receipt: &u64) -> Result<(), UsbError> {
        self.radio.stop(receipt).await
    }
}
type ProbeDevice = Device<Fake, ProbeLink, Env>;
static ACTIVE_PROBE: IrqSafeSpinLock<Option<Arc<ProbeDevice>>> = IrqSafeSpinLock::new(None);
fn send_probe_device(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE_PROBE.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain_probe_device() -> bool {
    let device = ACTIVE_PROBE.lock().clone();
    device.is_some_and(|device| device.drain())
}
struct Harness {
    device: Arc<ProbeDevice>,
    link: ProbeLink,
    control: Fake,
    source: Cap<FirmwareBlob, Read>,
    firmware: Arc<Owner<Fake>>,
    name: String,
    domain: Arc<IrqSafeSpinLock<narf_wireless::reg::RegulatoryDomain>>,
}
impl Harness {
    #[inline(never)]
    fn new(protected: bool) -> Result<Box<Self>, &'static str> {
        let (control, firmware) = initialized_registered_firmware();
        let factory = firmware.factory().ok_or("probe original factory")?;
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
            .map_err(|_| "probe qualified power")?;
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
        let radio = ChannelLink {
            bulk: Link(Arc::new(IrqSafeSpinLock::new(peer))),
            control: control.clone(),
            seen_reset: Arc::new(AtomicU64::new(control.0.lock().cold_generation)),
            beacon: Arc::new(AtomicBool::new(false)),
            beacon_generation: Arc::new(AtomicU64::new(u64::MAX)),
        };
        let clock = Env::default();
        let link = ProbeLink {
            radio,
            probes: Arc::new(IrqSafeSpinLock::new(Probes {
                responses: true,
                ..Probes::default()
            })),
            clock: clock.clone(),
        };
        let mut receiver = Receiver::new(
            firmware.clone(),
            link.clone(),
            ReceivePermission::from_domain(&domain.lock()).map_err(|_| "probe receive policy")?,
        )
        .map_err(|_| "probe retained receiver")?;
        receiver.install_wmm_model(proof);
        let mut service = drive(Service::start(receiver, power, clock))?
            .map_err(|_| "probe actual native service")?;
        drive(service.park())?.map_err(|_| "probe initial administrative park")?;
        let name = narf_net::iface::register("wlan%d", factory.mac, send_probe_device);
        let device = Arc::new(Device::new(&name, service));
        device
            .bind_admin(narf_net::iface::lookup(&name).ok_or("probe actual registration")?)
            .map_err(|_| "probe actual admin target")?;
        *ACTIVE_PROBE.lock() = Some(device.clone());
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain_probe_device);
        narf_net::stack::kernel_admin(&name)
            .ok_or("probe current admin")?
            .set_link(true)
            .map_err(|_| "probe actual UP")?;
        for _ in 0..64 {
            narf_scheduler::poll_one_round();
            if !device.admin_pending() {
                return Ok(Box::new(Self {
                    device,
                    link,
                    control,
                    source,
                    firmware,
                    name,
                    domain,
                }));
            }
        }
        Err("probe administrative wake did not complete")
    }
    fn scan(&self, ssid: &[u8]) -> ScanRequest {
        ScanRequest {
            ssids: vec![ssid.to_vec()],
            channels: vec![1, 6, 11, 13],
            frequencies_mhz: Vec::new(),
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(64),
            duration_mandatory: true,
            extra_ies: Vec::new(),
        }
    }
    fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: AP,
            ssid: SSID.to_vec(),
            channel: 6,
            frequency_mhz: 2437,
            security: if self.link.radio.bulk.0.lock().ap.protected() {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        }
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        *ACTIVE_PROBE.lock() = None;
        narf_net::iface::unregister(&self.name);
    }
}
fn conversation(protected: bool) -> Result<(), &'static str> {
    let h = Harness::new(protected)?;
    let request = h.scan(if protected { SSID } else { &[] });
    let results = drive(h.device.scan(request))?.map_err(|_| "probe actual multi-channel scan")?;
    ensure!(
        results.len() == 1
            && results[0].channel == 6
            && h.link.probes.lock().packets.len() == 4
            && h.control.0.lock().rf[0x18] & 0xff == 1
            && !h.device.link_up(),
        "probe discovery did not use four native probes and restore home without carrier"
    );
    drive(h.device.associate(h.request()))?.map_err(|_| "probe fresh target response/MLME/RSNA")?;
    ensure!(
        h.link.probes.lock().packets.len() == 5 && h.device.link_up(),
        "probe cold join transition reused old display metadata instead of a fresh response"
    );
    let lease = narf_net::dhcp::dhcp_acquire(&h.name, 0).map_err(|_| "probe actual native DHCP")?;
    ensure!(
        h.link.radio.bulk.0.lock().network.matches_lease(&lease)
            && h.control.0.lock().unsafe_reuses == 0,
        "probe actual DHCP identity or retained EP0 ownership"
    );
    let before = h.link.probes.lock().packets.len();
    ensure!(
        drive(h.device.scan(h.scan(SSID)))?.is_err()
            && h.link.probes.lock().packets.len() == before,
        "probe scan emitted while associated"
    );
    Ok(())
}
fn smoke_rtl8188eu_active_probe_open_native_scan_and_dhcp() -> TestResult {
    conversation(false).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
fn smoke_rtl8188eu_active_probe_wpa2_native_scan_fresh_response_and_dhcp() -> TestResult {
    conversation(true).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/active_scan",
    smoke_rtl8188eu_active_probe_open_native_scan_and_dhcp
);
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/active_scan",
    smoke_rtl8188eu_active_probe_wpa2_native_scan_fresh_response_and_dhcp
);

fn literal() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    for ssid in [&[][..], SSID] {
        let mut request = h.scan(ssid);
        request.channels = vec![6];
        request.extra_ies = vec![221, 4, 0, 0x50, 0xf2, 4];
        ensure!(
            drive(h.device.scan(request))?.is_ok(),
            "probe literal native request failed"
        );
    }
    let probes = h.link.probes.lock();
    ensure!(probes.packets.len() == 2, "probe literal request count");
    for (sequence, (channel, packet)) in probes.packets.iter().enumerate() {
        let ssid = if sequence == 0 { &[][..] } else { SSID };
        let frame = &packet[32..];
        let mut expected = vec![0x40, 0, 0, 0];
        expected.extend_from_slice(&[255; 6]);
        expected.extend_from_slice(&h.device.mac());
        expected.extend_from_slice(&[255; 6]);
        expected.extend_from_slice(&((sequence as u16) << 4).to_le_bytes());
        expected.extend_from_slice(&[0, ssid.len() as u8]);
        expected.extend_from_slice(ssid);
        expected.extend_from_slice(&[
            1, 8, 2, 4, 11, 22, 12, 18, 24, 36, 50, 4, 48, 72, 96, 108, 3, 1, 6, 221, 4, 0, 0x50,
            0xf2, 4,
        ]);
        ensure!(
            *channel == 6
                && frame == expected
                && packet[3] & 1 == 1
                && u32::from_le_bytes(packet[4..8].try_into().unwrap()) == 0x1200
                && u32::from_le_bytes(packet[16..20].try_into().unwrap()) == 0x100,
            "probe wildcard/directed native bytes or MGNT/basic1/broadcast descriptor differ"
        );
        ensure!(
            super::super::super::super::super::packet_codec::transmit(
                frame,
                super::super::super::super::super::packet_codec::Kind::Management
            )
            .is_err(),
            "probe widened ordinary management transmission"
        );
    }
    ensure!(
        h.device.max_scan_ssids() == 1 && h.device.max_scan_ie_len() == 2048,
        "probe advertised native limits differ"
    );
    drop(probes);
    let mut extra = Vec::new();
    for _ in 0..8 {
        extra.extend_from_slice(&[221, 254]);
        extra.extend_from_slice(&[0x55; 254]);
    }
    let mut request = h.scan(SSID);
    request.channels = vec![6];
    request.extra_ies = extra.clone();
    request.duration_tu = Some(2);
    let before = h.control.0.lock().ops.len();
    ensure!(
        drive(h.device.scan(request))?.is_err() && h.control.0.lock().ops.len() == before,
        "probe mandatory dwell admitted less than source timing/2048-byte airtime"
    );
    let mut request = h.scan(SSID);
    request.channels = vec![6];
    request.extra_ies = extra.clone();
    ensure!(
        drive(h.device.scan(request))?.is_ok_and(|bss| bss.len() == 1),
        "probe maximum IE frame did not survive actual device-air consumption"
    );
    let probes = h.link.probes.lock();
    ensure!(
        probes.packets.len() == 3
            && probes.packets[2].1.ends_with(&extra)
            && probes.consumed == 3
            && probes.truncated == 0,
        "probe TX closed before delayed device-air completion or omitted max IEs"
    );
    Ok(())
}
fn smoke_rtl8188eu_active_probe_literal_wildcard_directed_and_private_descriptor() -> TestResult {
    literal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/active_scan",
    smoke_rtl8188eu_active_probe_literal_wildcard_directed_and_private_descriptor
);

fn invalid() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    let before = h.control.0.lock().ops.len();
    for operation in 0..6 {
        let mut request = h.scan(SSID);
        match operation {
            0 => request.ssids.push(Vec::new()),
            1 => request.ssids = vec![vec![0; 33]],
            2 => request.extra_ies = vec![221, 2, 0],
            3 => request.extra_ies = vec![0, 1, 0],
            4 => request.channels = vec![5],
            _ => request.duration_tu = Some(2),
        }
        ensure!(
            drive(h.device.scan(request))?.is_err()
                && h.control.0.lock().ops.len() == before
                && h.link.probes.lock().packets.is_empty(),
            "probe invalid plan touched native hardware"
        );
    }
    h.domain.lock().rules.push(narf_wireless::reg::RegRule {
        freq_start_mhz: 2430,
        freq_end_mhz: 2431,
        max_bandwidth_mhz: 20,
        max_power_dbm: 17,
        flags: narf_wireless::reg::RegFlags::NO_IR,
    });
    ensure!(
        drive(h.device.scan(h.scan(SSID)))?.is_err()
            && h.control.0.lock().ops.len() == before
            && h.link.probes.lock().packets.is_empty(),
        "probe occupied-band NO_IR was overridden by another rule"
    );
    Ok(())
}
fn smoke_rtl8188eu_active_probe_prevalidates_ssid_ies_missing_rows_and_no_ir() -> TestResult {
    invalid().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/active_scan",
    smoke_rtl8188eu_active_probe_prevalidates_ssid_ies_missing_rows_and_no_ir
);

fn held() -> Result<(), &'static str> {
    for operation in 0..3 {
        let h = Harness::new(false)?;
        h.link.probes.lock().hold = true;
        let mut request = h.scan(SSID);
        request.channels = vec![6];
        let mut scan = Box::pin(h.device.scan(request));
        let mut published = false;
        for _ in 0..256 {
            ensure!(
                scan.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "probe scan ended before its held native publication"
            );
            if h.link.radio.bulk.0.lock().tx.is_some() {
                published = true;
                break;
            }
        }
        ensure!(
            published
                && h.link.radio.bulk.0.lock().tx.is_some()
                && h.link.probes.lock().packets.len() == 1
                && !h.device.link_up(),
            "probe scan finished before its real native TX terminal"
        );
        if operation == 0 {
            h.link.probes.lock().hold = false;
            ensure!(
                drive(scan)?.is_ok_and(|result| result.len() == 1),
                "probe native terminal did not complete scan"
            );
        } else {
            let before = h.control.0.lock().ops.len();
            if operation == 2 {
                h.source.revoke();
                ensure!(
                    drive(scan.as_mut())?.is_err(),
                    "probe lost-source scan continued"
                );
            }
            drop(scan);
            ensure!(
                drive(h.device.scan(h.scan(SSID)))?.is_err()
                    && h.link.radio.bulk.0.lock().tx.is_some()
                    && h.control.0.lock().ops.len() == before
                    && h.control.0.lock().unsafe_reuses == 0,
                "probe cancelled/source-lost scan released a pending native TX or reused EP0"
            );
        }
    }
    Ok(())
}
fn smoke_rtl8188eu_active_probe_terminal_wait_cancel_and_source_loss_keep_receipts() -> TestResult {
    held().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/active_scan",
    smoke_rtl8188eu_active_probe_terminal_wait_cancel_and_source_loss_keep_receipts
);

fn short() -> Result<(), &'static str> {
    for air_held in [false, true] {
        let h = Harness::new(false)?;
        h.link.probes.lock().short = !air_held;
        h.link.probes.lock().air_held = air_held;
        ensure!(
            drive(h.device.scan(h.scan(SSID)))?.is_err()
                && h.firmware.status().stage == FirmwareStage::Failed,
            "probe short USB or missing device TX-state terminal completed scan"
        );
        if air_held {
            ensure!(
                h.control.0.lock().regs[0x100] & 0xc0 == 0xc0
                    && h.control.0.lock().regs[0x5f8] != 0
                    && h.link.probes.lock().air.is_some()
                    && h.link.probes.lock().truncated == 0,
                "probe host completion substituted for held device-air/TX-state terminal"
            );
        }
        let before = h.control.0.lock().ops.len();
        ensure!(
            drive(h.device.scan(h.scan(SSID)))?.is_err() && h.control.0.lock().ops.len() == before,
            "probe failed native owner was reused"
        );
    }
    Ok(())
}
fn smoke_rtl8188eu_active_probe_short_native_terminal_is_terminal() -> TestResult {
    short().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/active_scan",
    smoke_rtl8188eu_active_probe_short_native_terminal_is_terminal
);

fn policy_loss() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    h.link.probes.lock().hold = true;
    let mut request = h.scan(SSID);
    request.channels = vec![6];
    let mut scan = Box::pin(h.device.scan(request));
    let mut published = false;
    for _ in 0..256 {
        ensure!(
            scan.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "probe policy scan ended before actual native publication"
        );
        if h.link.radio.bulk.0.lock().tx.is_some() {
            published = true;
            break;
        }
    }
    ensure!(
        published && h.link.radio.bulk.0.lock().tx.is_some(),
        "probe policy fixture lacks actual published TX"
    );
    let before = h.control.0.lock().ops.len();
    h.domain.lock().rules.push(narf_wireless::reg::RegRule {
        freq_start_mhz: 2430,
        freq_end_mhz: 2431,
        max_bandwidth_mhz: 20,
        max_power_dbm: 17,
        flags: narf_wireless::reg::RegFlags::NO_IR,
    });
    ensure!(
        drive(scan)?.is_err()
            && h.link.radio.bulk.0.lock().tx.is_some()
            && h.control.0.lock().ops.len() == before
            && h.control.0.lock().unsafe_reuses == 0,
        "probe current occupied-channel policy loss was ignored across a native wait"
    );
    Ok(())
}
fn smoke_rtl8188eu_active_probe_policy_loss_during_native_wait_keeps_original_tx() -> TestResult {
    policy_loss().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/active_scan",
    smoke_rtl8188eu_active_probe_policy_loss_during_native_wait_keeps_original_tx
);

fn old_fifo() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    h.link.probes.lock().responses = false;
    let mut old = h.link.radio.bulk.0.lock().ap.beacon();
    old[0] = 0x50;
    old[4..10].copy_from_slice(&h.device.mac());
    h.link.radio.bulk.0.lock().queue.push_back(old);
    let mut request = h.scan(SSID);
    request.channels = vec![6];
    ensure!(
        drive(h.device.scan(request))?.is_ok_and(|result| result.is_empty())
            && h.control.0.lock().cold_generation == 3
            && h.control.0.lock().rf[0x18] & 0xff == 1,
        "probe old device FIFO response acquired a fresh RF channel label"
    );
    Ok(())
}
fn smoke_rtl8188eu_active_probe_old_fifo_response_cannot_cross_cold_channel_boundary() -> TestResult
{
    old_fifo().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/active_scan",
    smoke_rtl8188eu_active_probe_old_fifo_response_cannot_cross_cold_channel_boundary
);

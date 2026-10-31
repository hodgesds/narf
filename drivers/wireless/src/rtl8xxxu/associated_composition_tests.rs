// SPDX-License-Identifier: GPL-2.0-or-later
//! Real retained Device/USB/MLME/RSNA across associated passive visits.
use super::*;
use crate::rtl8xxxu::{ht_runtime::Grant, packet_codec, ps_null};

#[derive(Default)]
struct PowerIndications {
    packets: Vec<Vec<u8>>,
    air: Option<(u64, bool)>,
    asleep: bool,
    hold: bool,
    air_held: bool,
    ignore: bool,
    consumed: usize,
    truncated: usize,
    away_generation: u64,
    home_generation: u64,
    inject_away_data: Option<Vec<u8>>,
    buffered: VecDeque<Vec<u8>>,
}
#[derive(Clone)]
struct AssociatedLink {
    radio: ChannelLink,
    power: Arc<IrqSafeSpinLock<PowerIndications>>,
    clock: Env,
}
impl AssociatedLink {
    fn advance_air(&self) {
        let (channel, _, tx) = self.radio.physical();
        let mut power = self.power.lock();
        let Some((ready, asleep)) = power.air else {
            return;
        };
        if channel != 1 || !tx {
            power.truncated += 1;
            power.air = None;
            return;
        }
        if power.air_held || self.clock.now_ms() < ready {
            return;
        }
        power.air = None;
        power.consumed += 1;
        if !power.ignore {
            power.asleep = asleep;
            if !asleep {
                self.radio
                    .bulk
                    .0
                    .lock()
                    .queue
                    .extend(power.buffered.drain(..));
            }
        }
        self.radio.control.0.lock().regs[0x5f8..0x5fc].fill(0);
    }
}
#[async_trait::async_trait]
impl Io for AssociatedLink {
    type Receipt = u64;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<u64, UsbError> {
        self.radio.begin_receive(dci, length)
    }
    fn poll_receive(&self, receipt: &u64, bytes: &mut [u8]) -> Result<Option<usize>, UsbError> {
        self.radio.synchronize_reset()?;
        self.advance_air();
        let (channel, rx, _) = self.radio.physical();
        let generation = self.radio.control.0.lock().cold_generation;
        if rx {
            let mut power = self.power.lock();
            let mut peer = self.radio.bulk.0.lock();
            if channel == 1 && power.home_generation != generation {
                let mut beacon = peer.ap.beacon();
                if peer.ht {
                    beacon.extend_from_slice(&super::super::super::ht_tests::WMM);
                    beacon.extend_from_slice(&super::super::super::ht_tests::elements(255));
                }
                peer.queue.push_back(beacon);
                power.home_generation = generation;
            } else if channel == 6 && power.away_generation != generation {
                let mut beacon = peer.ap.beacon();
                // Another real BSS on this physical channel, not a relabel
                // of the home AP's retained receive buffer.
                beacon[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 3]);
                beacon[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 3]);
                let ds = beacon
                    .windows(3)
                    .position(|w| w == [3, 1, 1])
                    .ok_or(UsbError::Stall)?;
                beacon[ds + 2] = 6;
                peer.queue.push_back(beacon);
                if let Some(frame) = power.inject_away_data.take() {
                    let mut raw = vec![0; 24 + frame.len()];
                    let d0 = frame.len() as u32 | 1 << 27 | 1 << 28 | 1 << 29 | 1 << 23;
                    raw[..4].copy_from_slice(&d0.to_le_bytes());
                    raw[4..8].copy_from_slice(&(u32::from(frame[24] & 15) << 5).to_le_bytes());
                    raw[8..12].copy_from_slice(&(1u32 << 16).to_le_bytes());
                    raw[24..].copy_from_slice(&frame);
                    peer.raw_queue.push_back(raw);
                }
                power.away_generation = generation;
            }
        }
        self.radio.bulk.poll_receive(receipt, bytes)
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<u64, UsbError> {
        let (channel, _, tx) = self.radio.physical();
        if channel != 1 || !tx {
            return Err(UsbError::Stall);
        }
        if !matches!(bytes.get(TX_DESC), Some(0x48 | 0xc8)) {
            return self.radio.bulk.begin_send(dci, bytes);
        }
        let frame = &bytes[TX_DESC..];
        let qos = frame[0] == 0xc8;
        let mut power = self.power.lock();
        let mut peer = self.radio.bulk.0.lock();
        let queue = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let flags = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        if power.air.is_some()
            || peer.tx.is_some()
            || bytes.len() != TX_DESC + if qos { 26 } else { 24 }
            || frame[1] & !0x10 != 1
            || frame[2..4] != [0, 0]
            || frame[4..10] != AP
            || frame[10..16] != peer.network.station
            || frame[16..22] != AP
            || flags != 0x100 | if qos { 0x40 } else { 0 }
            || queue != if qos { 7 << 8 } else { 0 }
            || bytes[20..24] != 0x0001ff00u32.to_le_bytes()
            || qos && (frame[22..26] != [0, 0, 7, 0] || dci != 4)
            || !qos && dci != 8
            || bytes[..TX_DESC]
                .chunks_exact(2)
                .fold(0u16, |sum, b| sum ^ u16::from_le_bytes([b[0], b[1]]))
                != 0
            || u32::from_le_bytes(bytes[12..16].try_into().unwrap()) >> 16
                != u32::from(u16::from_le_bytes([frame[22], frame[23]]) >> 4)
        {
            return Err(UsbError::Stall);
        }
        power.packets.push(bytes.to_vec());
        // Host delivery is independent of the device consuming this PPDU.
        // 192us long preamble plus exact CCK1 MPDU/FCS time rounds to1ms.
        let air_ms = (192 + 8 * (frame.len() as u64 + 4)).div_ceil(1000);
        power.air = Some((self.clock.now_ms() + air_ms, frame[1] & 0x10 != 0));
        self.radio.control.0.lock().regs[0x5f8] = 1;
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
        if self.power.lock().hold
            && self
                .radio
                .bulk
                .0
                .lock()
                .tx
                .as_ref()
                .is_some_and(|tx| tx.control)
        {
            return Ok(None);
        }
        self.radio.bulk.poll_send(receipt)
    }
    async fn stop(&self, receipt: &u64) -> Result<(), UsbError> {
        self.radio.bulk.stop(receipt).await
    }
}

type AssociatedDevice = Device<Fake, AssociatedLink, Env>;
static ACTIVE_ASSOCIATED: IrqSafeSpinLock<Option<Arc<AssociatedDevice>>> =
    IrqSafeSpinLock::new(None);
fn send_associated(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE_ASSOCIATED.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain_associated() -> bool {
    let device = ACTIVE_ASSOCIATED.lock().clone();
    device.is_some_and(|device| device.drain())
}
struct AssociatedFixture {
    device: Arc<AssociatedDevice>,
    link: AssociatedLink,
    source: Cap<FirmwareBlob, Read>,
    ht_source: Cap<FirmwareBlob, Read>,
    domain: Arc<IrqSafeSpinLock<narf_wireless::reg::RegulatoryDomain>>,
    firmware: Arc<Owner<Fake>>,
    name: String,
}
impl AssociatedFixture {
    #[inline(never)]
    fn new(protected: bool, ht: bool) -> Result<Box<Self>, &'static str> {
        let (control, firmware) = initialized_registered_firmware();
        let factory = firmware.factory().ok_or("EU associated factory")?;
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
        let source = Cap::bootstrap();
        let ht_source = Cap::bootstrap();
        let calibration = calibration(factory);
        let power = calibration
            .permission(&domain.lock(), 1)
            .map_err(|_| "EU associated power")?;
        let proof = Proof::model(calibration, power, source, domain.clone());
        let clock = Env::default();
        let mut peer = Peer::new(plan(factory.mac), protected);
        peer.ht = ht;
        peer.response_ht = ht.then(|| super::super::super::ht_tests::elements(255));
        let radio = ChannelLink {
            bulk: Link(Arc::new(IrqSafeSpinLock::new(peer))),
            control: control.clone(),
            seen_reset: Arc::new(AtomicU64::new(control.0.lock().cold_generation)),
            beacon: Arc::new(AtomicBool::new(false)),
            beacon_generation: Arc::new(AtomicU64::new(u64::MAX)),
        };
        let link = AssociatedLink {
            radio,
            clock: clock.clone(),
            power: Arc::new(IrqSafeSpinLock::new(PowerIndications {
                home_generation: u64::MAX,
                away_generation: u64::MAX,
                ..Default::default()
            })),
        };
        let mut receiver = Receiver::new(
            firmware.clone(),
            link.clone(),
            ReceivePermission::from_domain(&domain.lock()).map_err(|_| "EU associated RX")?,
        )
        .map_err(|_| "EU associated owner")?;
        receiver.install_wmm_model(proof.clone());
        if ht {
            let executable = firmware.executable().ok_or("EU associated executable")?;
            let artifact = super::super::super::ht_tests::artifact(&proof, executable);
            let grant = Arc::new(
                Grant::parse(
                    proof,
                    executable,
                    factory.ht40_power[0],
                    &artifact,
                    Some([7; 32]),
                    ht_source,
                )
                .map_err(|_| "EU associated HT")?,
            );
            drive(receiver.install_ht(grant))?.map_err(|_| "EU associated actual HT program")?;
        }
        let service =
            drive(Service::start(receiver, power, clock))?.map_err(|_| "EU associated service")?;
        let name = narf_net::iface::register("wlan%d", factory.mac, send_associated);
        narf_net::iface::set_link_state(&name, true);
        let device = Arc::new(Device::new(&name, service));
        *ACTIVE_ASSOCIATED.lock() = Some(device.clone());
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain_associated);
        Ok(Box::new(Self {
            device,
            link,
            source,
            ht_source,
            domain,
            firmware,
            name,
        }))
    }
    fn scan(&self, channels: &[u32]) -> ScanRequest {
        ScanRequest {
            channels: channels.to_vec(),
            frequencies_mhz: Vec::new(),
            ssids: Vec::new(),
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(2),
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }
    }
    fn join(&self) -> Result<(), &'static str> {
        drive(self.device.scan(self.scan(&[1])))?
            .map_err(|_| "EU associated initial native scan")?;
        drive(self.device.associate(AssociateRequest {
            bssid: AP,
            ssid: SSID.to_vec(),
            channel: 1,
            frequency_mhz: 2412,
            security: if self.link.radio.bulk.0.lock().ap.protected() {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        }))?
        .map_err(|_| "EU associated native MLME/RSNA")
    }
    fn pump(&self) {
        for _ in 0..16 {
            self.device.drain();
        }
    }
}
impl Drop for AssociatedFixture {
    fn drop(&mut self) {
        *ACTIVE_ASSOCIATED.lock() = None;
        narf_net::iface::set_link_state(&self.name, false);
        narf_net::iface::set_link_metadata(&self.name, false, None, None);
        narf_net::iface::unregister(&self.name);
    }
}

fn associated_conversation(protected: bool) -> Result<(), &'static str> {
    let h = AssociatedFixture::new(protected, false)?;
    h.join()?;
    let network = h.link.radio.bulk.0.lock().network;
    let first =
        narf_net::dhcp::dhcp_acquire(&h.name, 0).map_err(|_| "EU associated initial DHCP")?;
    ensure!(
        network.matches_lease(&first),
        "EU associated DHCP identity before scan"
    );
    h.pump();
    let original = h
        .link
        .radio
        .bulk
        .0
        .lock()
        .rx
        .ok_or("EU associated original native RX")?;
    let replay = h.link.radio.bulk.0.lock().replay.last_seen_pn;
    let last_data_sn = {
        let peer = h.link.radio.bulk.0.lock();
        let packet = peer
            .native_tx
            .iter()
            .rev()
            .find(|packet| packet.get(TX_DESC) == Some(&8))
            .ok_or("EU original non-QoS native DATA")?;
        u16::from_le_bytes([packet[TX_DESC + 22], packet[TX_DESC + 23]]) >> 4
    };
    let native_before = h.link.radio.bulk.0.lock().native_tx.len();
    let buffered = udp_ipv4(
        h.device.mac(),
        AP,
        [10, 88, 0, 1],
        [10, 88, 0, 42],
        8,
        7,
        b"AP buffered during actual EU power save",
    );
    let native_buffered = {
        let mut peer = h.link.radio.bulk.0.lock();
        peer.downlink(&buffered)?;
        peer.queue
            .pop_back()
            .ok_or("EU real AP buffered native DATA")?
    };
    h.link.power.lock().buffered.push_back(native_buffered);
    let frame = udp_ipv4(
        AP,
        h.device.mac(),
        [10, 88, 0, 42],
        [10, 88, 0, 1],
        7,
        8,
        b"queued across EU associated scan",
    );
    h.device
        .enqueue(&frame, Default::default())
        .map_err(|_| "EU associated enqueue retained host ring")?;
    let uplink_before = h.link.radio.bulk.0.lock().uplink.len();
    let results =
        drive(h.device.scan(h.scan(&[6])))?.map_err(|_| "EU associated cold passive visit")?;
    ensure!(
        results
            .iter()
            .any(|bss| bss.channel == 6 && bss.bssid == [2, 0, 0, 0, 0, 3]),
        "EU actual away BSS discovery"
    );
    {
        let peer = h.link.radio.bulk.0.lock();
        ensure!(
            peer.uplink.len() == uplink_before
                && peer.replay.last_seen_pn == replay
                && peer.rx != Some(original)
                && peer.ap.phase() == ApPhase::Authorized,
            "EU associated scan replaced key owner, consumed queued DATA or reused old RX"
        );
    }
    {
        let power = h.link.power.lock();
        ensure!(
            power.packets.len() == 2
                && power.consumed == 2
                && power.truncated == 0
                && !power.asleep,
            "EU PM1/PM0 did not reach independent device air boundary"
        );
        let a = &power.packets[0];
        let b = &power.packets[1];
        ensure!(
            a[TX_DESC..TX_DESC + 2] == [0x48, 0x11]
                && b[TX_DESC..TX_DESC + 2] == [0x48, 1]
                && a[16] & 0x80 == 0
                && b[16] & 0x80 == 0,
            "EU non-QoS Null plaintext or host sequence descriptor"
        );
        ensure!(
            u16::from_le_bytes([a[TX_DESC + 22], a[TX_DESC + 23]]) >> 4
                == (last_data_sn + 1) & 4095
                && u16::from_le_bytes([b[TX_DESC + 22], b[TX_DESC + 23]]) >> 4
                    == (last_data_sn + 2) & 4095,
            "EU physical non-QoS Null did not reserve DATA/EAPOL sequence slots"
        );
    }
    ensure!(
        h.device.progress().contains(&buffered),
        "EU home PM0 did not deliver AP-buffered original CCMP DATA"
    );
    h.pump();
    ensure!(
        h.link
            .radio
            .bulk
            .0
            .lock()
            .uplink
            .iter()
            .any(|(sent, _)| sent == &frame),
        "EU associated scan dropped original host TX ring owner"
    );
    {
        let peer = h.link.radio.bulk.0.lock();
        let packet = peer.native_tx[native_before..]
            .iter()
            .find(|packet| packet.get(TX_DESC) == Some(&8))
            .ok_or("EU restored native DATA")?;
        ensure!(
            u16::from_le_bytes([packet[TX_DESC + 22], packet[TX_DESC + 23]]) >> 4
                == (last_data_sn + 3) & 4095,
            "EU restored DATA did not follow plaintext Null sequence reservations"
        );
        ensure!(
            peer.native_tx.iter().all(|packet| packet[16] & 0x80 == 0
                && u32::from_le_bytes(packet[12..16].try_into().unwrap()) >> 16
                    == u32::from(
                        u16::from_le_bytes([packet[TX_DESC + 22], packet[TX_DESC + 23]]) >> 4
                    )),
            "EU DATA/Null descriptor enabled hardware SN override across cold restart"
        );
    }
    let second = narf_net::dhcp::dhcp_acquire(&h.name, 0)
        .map_err(|_| "EU associated DHCP after home restore")?;
    ensure!(
        network.matches_lease(&second)
            && h.device.link_up()
            && h.device.connected_bssid() == Some(AP)
            && h.link.radio.control.0.lock().rf[0x18] & 0xff == 1,
        "EU associated home/data/key continuity"
    );
    ensure!(
        h.link.radio.bulk.0.lock().error.is_none(),
        "EU associated AP CCMP/replay rejected restored station"
    );
    Ok(())
}
fn smoke_rtl8188eu_associated_open_null_home_queue_and_native_dhcp() -> TestResult {
    associated_conversation(false).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
fn smoke_rtl8188eu_associated_wpa2_retains_keys_pn_and_native_dhcp() -> TestResult {
    associated_conversation(true).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_scan",
    smoke_rtl8188eu_associated_open_null_home_queue_and_native_dhcp
);
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_scan",
    smoke_rtl8188eu_associated_wpa2_retains_keys_pn_and_native_dhcp
);

fn null_literals() -> Result<(), &'static str> {
    for qos in [false, true] {
        let prepared = ps_null::Prepared::new(
            [2, 0, 0, 0, 0, 1],
            AP,
            true,
            qos,
            if qos { 0 } else { 4095 },
        )
        .map_err(|_| "EU prepared Null")?;
        let bytes = packet_codec::transmit_null(&prepared);
        ensure!(
            bytes[16] == if qos { 0x40 } else { 0 } && bytes[17] == 1 && bytes[16] & 0x80 == 0,
            "EU HW sequence override or QoS Null descriptor bit"
        );
        ensure!(
            packet_codec::transmit(prepared.bytes(), packet_codec::Kind::Data).is_err()
                && packet_codec::transmit(prepared.bytes(), packet_codec::Kind::Management)
                    .is_err(),
            "EU ordinary entry accepted private Null"
        );
        ensure!(
            bytes[TX_DESC..TX_DESC + 2] == [if qos { 0xc8 } else { 0x48 }, 0x11]
                && bytes.len() == TX_DESC + if qos { 26 } else { 24 },
            "EU private Null subtype/PM/payload geometry"
        );
    }
    let h = AssociatedFixture::new(true, true)?;
    h.join()?;
    let before = h.link.radio.bulk.0.lock().sent;
    let mut active = h.scan(&[6]);
    active.active = true;
    ensure!(
        drive(h.device.scan(active))?.is_err()
            && h.link.radio.bulk.0.lock().sent == before
            && h.device.link_up(),
        "EU connected active scan widened private idle probe admission"
    );
    let mut request = h.scan(&[6]);
    request.duration_mandatory = true;
    request.duration_tu = Some(200);
    ensure!(
        drive(h.device.scan(request))?.is_err()
            && h.link.radio.bulk.0.lock().sent == before
            && h.device.link_up(),
        "EU associated mandatory dwell refused after native effects"
    );
    drive(h.device.scan(h.scan(&[6])))?.map_err(|_| "EU associated QoS Null visit")?;
    let power = h.link.power.lock();
    ensure!(
        power.packets.len() == 2
            && power
                .packets
                .iter()
                .all(|p| p[TX_DESC + 22..] == [0, 0, 7, 0])
            && power.packets[0][TX_DESC..TX_DESC + 2] == [0xc8, 0x11]
            && power.packets[1][TX_DESC..TX_DESC + 2] == [0xc8, 1],
        "EU real QoS Null TID7/SN0/plaintext differs"
    );
    Ok(())
}
fn smoke_rtl8188eu_associated_qos_null_literal_and_pure_timing_admission() -> TestResult {
    null_literals().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_scan",
    smoke_rtl8188eu_associated_qos_null_literal_and_pure_timing_admission
);

fn retained_null(source_lost: bool) -> Result<(), &'static str> {
    let h = AssociatedFixture::new(true, true)?;
    h.join()?;
    h.link.power.lock().hold = true;
    let mut scan = Box::pin(h.device.scan(h.scan(&[6])));
    let mut published = false;
    for _ in 0..64 {
        ensure!(
            scan.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "EU held Null returned before native wait"
        );
        if !h.link.power.lock().packets.is_empty() {
            published = true;
            break;
        }
    }
    ensure!(published, "EU associated Null was not actually published");
    let original = h.link.radio.bulk.0.lock().rx;
    let original_tx = h.link.radio.bulk.0.lock().tx.as_ref().map(|tx| tx.id);
    let stops = h.link.radio.bulk.0.lock().stops;
    if source_lost {
        h.source.revoke();
        ensure!(
            drive(scan)?.is_err(),
            "EU source loss reopened associated Null wait"
        );
    } else {
        drop(scan);
    }
    ensure!(
        !h.device.link_up()
            && h.link.radio.bulk.0.lock().rx == original
            && h.link.radio.bulk.0.lock().tx.as_ref().map(|tx| tx.id) == original_tx
            && h.link.radio.bulk.0.lock().stops == stops
            && h.firmware.claim_receive().is_err(),
        "EU lost associated caller/source reclaimed published native ownership"
    );
    Ok(())
}
fn smoke_rtl8188eu_associated_cancel_retains_native_null_and_rx() -> TestResult {
    retained_null(false).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
fn smoke_rtl8188eu_associated_source_loss_retains_native_null_and_rx() -> TestResult {
    retained_null(true).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_scan",
    smoke_rtl8188eu_associated_cancel_retains_native_null_and_rx
);
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_scan",
    smoke_rtl8188eu_associated_source_loss_retains_native_null_and_rx
);

fn best_effort_null() -> Result<(), &'static str> {
    let h = AssociatedFixture::new(true, true)?;
    h.join()?;
    h.link.power.lock().ignore = true;
    drive(h.device.scan(h.scan(&[6])))?.map_err(|_| "EU no-ACK Null best-effort visit")?;
    ensure!(
        h.link.power.lock().consumed == 2 && !h.link.power.lock().asleep && h.device.link_up(),
        "EU Null required imaginary AP ACK"
    );
    h.link.power.lock().air_held = true;
    ensure!(
        drive(h.device.scan(h.scan(&[6])))?.is_err()
            && !h.device.link_up()
            && h.link.power.lock().air.is_some()
            && h.link.radio.bulk.0.lock().rx.is_some()
            && h.link.radio.control.0.lock().regs[0x100] & 0xc0 == 0xc0,
        "EU held real device scheduler was confused with USB completion"
    );
    Ok(())
}
fn smoke_rtl8188eu_associated_no_air_ack_and_held_scheduler_terminal() -> TestResult {
    best_effort_null().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_scan",
    smoke_rtl8188eu_associated_no_air_ack_and_held_scheduler_terminal
);

fn cold_cancellation() -> Result<(), &'static str> {
    for source_lost in [false, true] {
        let h = AssociatedFixture::new(true, true)?;
        h.join()?;
        h.link.radio.control.0.lock().pending_write = Some(0x284);
        let mut scan = Box::pin(h.device.scan(h.scan(&[6])));
        let mut published = false;
        for _ in 0..1024 {
            ensure!(
                scan.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "EU cold scan returned before held EP0"
            );
            if h.link.radio.control.0.lock().active_td {
                published = true;
                break;
            }
        }
        ensure!(
            published && h.link.power.lock().consumed == 1,
            "EU associated leave lacked real PM1/EP0 publication"
        );
        let original = h.link.radio.bulk.0.lock().rx;
        let stops = h.link.radio.bulk.0.lock().stops;
        let generation = h.link.radio.control.0.lock().cold_generation;
        if source_lost {
            h.ht_source.revoke();
            ensure!(
                drive(scan)?.is_err(),
                "EU HT source loss crossed cold retune"
            );
        } else {
            drop(scan);
        }
        ensure!(
            !h.device.link_up()
                && h.link.radio.bulk.0.lock().rx == original
                && h.link.radio.bulk.0.lock().stops == stops
                && h.link.radio.control.0.lock().active_td
                && h.link.radio.control.0.lock().cold_generation == generation
                && h.link.radio.control.0.lock().unsafe_reuses == 0,
            "EU cold cancellation/source loss reclaimed RX or published EP0"
        );
    }
    Ok(())
}
fn smoke_rtl8188eu_associated_cold_cancel_and_ht_source_loss_keep_ep0_rx() -> TestResult {
    cold_cancellation().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_scan",
    smoke_rtl8188eu_associated_cold_cancel_and_ht_source_loss_keep_ep0_rx
);

fn action(own: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0xd0, 0, 0, 0];
    frame.extend_from_slice(&own);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(body);
    frame
}
fn downlink(
    h: &AssociatedFixture,
    seq: u16,
    tid: u8,
    pn: u64,
    fill: u8,
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let peer = h.link.radio.bulk.0.lock();
    let mut header = vec![0x88, 0x42, 0, 0];
    header.extend_from_slice(&peer.network.station);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&(seq << 4).to_le_bytes());
    header.extend_from_slice(&[tid, 0]);
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0, 8, 0];
    body.resize(72, fill);
    let wire = narf_wireless::ccmp::protect(
        &Ccm,
        &header,
        peer.ptk
            .as_ref()
            .ok_or("EU associated actual PTK")?
            .tk
            .as_slice()
            .try_into()
            .map_err(|_| "EU associated TK extent")?,
        pn,
        0,
        tid,
        false,
        &mut body,
    )
    .map_err(|_| "EU associated native downlink CCMP")?;
    header.extend_from_slice(&wire);
    let mut ethernet = peer.network.station.to_vec();
    ethernet.extend_from_slice(&AP);
    ethernet.extend_from_slice(&[8, 0]);
    ethernet.resize(78, fill);
    Ok((header, ethernet))
}
fn ba_and_away_crypto() -> Result<(), &'static str> {
    let h = AssociatedFixture::new(true, true)?;
    h.join()?;
    let params = 2u16 | 5 << 2 | 32 << 6;
    let mut body = vec![3, 0, 7];
    body.extend_from_slice(&params.to_le_bytes());
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&(100u16 << 4).to_le_bytes());
    h.link
        .radio
        .bulk
        .0
        .lock()
        .queue
        .push_back(action(h.device.mac(), &body));
    h.pump();
    ensure!(
        h.link
            .radio
            .bulk
            .0
            .lock()
            .actions
            .iter()
            .any(|frame| frame.get(24..29) == Some(&[3, 1, 7, 0, 0])),
        "EU associated recipient BA did not open"
    );
    let (first, e_first) = downlink(&h, 100, 5, 1, 0x51)?;
    h.link
        .radio
        .bulk
        .0
        .lock()
        .raw_queue
        .push_back(ba_record(&first, true));
    ensure!(
        h.device.progress() == vec![e_first],
        "EU associated initial native RX BA/CCMP"
    );
    h.link.radio.bulk.0.lock().next_pn = 2;
    let ethernet = udp_ipv4(
        AP,
        h.device.mac(),
        [10, 88, 0, 42],
        [10, 88, 0, 1],
        7,
        8,
        b"EU retained operational TX BA",
    );
    h.device
        .enqueue(&ethernet, Default::default())
        .map_err(|_| "EU associated TX BA enqueue")?;
    h.pump();
    drive(h.device.maintain())?;
    h.pump();
    let request = h
        .link
        .radio
        .bulk
        .0
        .lock()
        .actions
        .iter()
        .rev()
        .find(|frame| frame.get(24..26) == Some(&[3, 0]))
        .cloned()
        .ok_or("EU associated actual originator ADDBA")?;
    let mut response = vec![3, 1, request[26], 0, 0];
    response.extend_from_slice(&request[27..31]);
    h.link
        .radio
        .bulk
        .0
        .lock()
        .queue
        .push_back(action(h.device.mac(), &response));
    h.pump();
    // A high-PN packet copied on the away RF channel must never mutate the
    // retained home replay window, even with the home peer's native addresses.
    let (foreign, _) = downlink(&h, 999, 5, 1000, 0x66)?;
    h.link.power.lock().inject_away_data = Some(foreign);
    drive(h.device.scan(h.scan(&[6])))?.map_err(|_| "EU associated HT/BA passive visit")?;
    // SN is masked from CCMP AAD. Replaying the original encrypted bytes
    // with the next BA SN reaches crypto rather than duplicate-SN rejection,
    // so a reset home replay window would wrongly deliver the old payload.
    let mut replayed = first.clone();
    replayed[22..24].copy_from_slice(&(101u16 << 4).to_le_bytes());
    h.link
        .radio
        .bulk
        .0
        .lock()
        .raw_queue
        .push_back(ba_record(&replayed, false));
    ensure!(
        h.device.progress().is_empty(),
        "EU scan reset original home CCMP replay window"
    );
    let (second, e_second) = downlink(&h, 102, 5, 3, 0x52)?;
    h.link
        .radio
        .bulk
        .0
        .lock()
        .raw_queue
        .push_back(ba_record(&second, false));
    ensure!(
        h.device.progress() == vec![e_second],
        "EU scan reset RX BA session or adopted away CCMP PN"
    );
    replayed[22..24].copy_from_slice(&(103u16 << 4).to_le_bytes());
    h.link
        .radio
        .bulk
        .0
        .lock()
        .raw_queue
        .push_back(ba_record(&replayed, false));
    ensure!(
        h.device.progress().is_empty(),
        "EU scan revived replayed original home BA MPDU"
    );
    h.device
        .enqueue(&ethernet, Default::default())
        .map_err(|_| "EU restored operational TX BA enqueue")?;
    h.pump();
    let peer = h.link.radio.bulk.0.lock();
    let packet = peer
        .native_tx
        .iter()
        .rev()
        .find(|packet| packet.get(TX_DESC) == Some(&0x88))
        .ok_or("EU restored native QoS DATA")?;
    let dw2 = u32::from_le_bytes(packet[8..12].try_into().unwrap());
    ensure!(
        dw2 & (1 << 12) != 0
            && dw2 & (1 << 16) == 0
            && peer.error.is_none()
            && peer
                .actions
                .iter()
                .filter(|f| f.get(24..26) == Some(&[3, 0]))
                .count()
                == 1,
        "EU scan lost operational TX BA or restarted association/keys"
    );
    drop(peer);
    // Removing the current policy while the actual next native Null is
    // published must retain ownership and close the same registration.
    h.link.power.lock().hold = true;
    let mut scan = Box::pin(h.device.scan(h.scan(&[6])));
    for _ in 0..64 {
        ensure!(
            scan.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "EU current policy native wait"
        );
        if h.link
            .radio
            .bulk
            .0
            .lock()
            .tx
            .as_ref()
            .is_some_and(|tx| tx.control)
        {
            break;
        }
    }
    h.domain.lock().rules.clear();
    ensure!(
        drive(scan)?.is_err() && !h.device.link_up() && h.link.radio.bulk.0.lock().rx.is_some(),
        "EU associated current policy loss reopened owner"
    );
    Ok(())
}
fn smoke_rtl8188eu_associated_preserves_ba_and_replay_across_away_copies() -> TestResult {
    ba_and_away_crypto().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_scan",
    smoke_rtl8188eu_associated_preserves_ba_and_replay_across_away_copies
);

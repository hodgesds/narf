//! Live MLD device, serialized with an async mutex. Firmware command
//! waits drain RX themselves and never depend on another executor task.

use super::connection::{Beacon, Connection};
use super::{runtime::Hardware, scan_api, station_api};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_ipc::{Consumer, Producer};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, WirelessConfig, WirelessError, WirelessIfaceInfo,
    WirelessNetIface,
};

pub struct Device {
    state: Mutex<State>,
    mac: [u8; 6],
    irq_vector: Option<u8>,
    channels: Vec<u8>,
    tx_chains: u32,
    phy: super::ht_vht::Local,
    firmware: Vec<u8>,
    pnvm: Option<Vec<u8>>,
    up: AtomicBool,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: [IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>; 4],
}

impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IwlMldDevice")
            .field("mac", &self.mac)
            .field("up", &self.up)
            .finish()
    }
}

struct State {
    hardware: Hardware,
    scan_uid: u32,
    beacons: Vec<Beacon>,
    connection: Option<Connection>,
    needs_reset: bool,
    producer: Option<Producer<Frame, RX_RING_N>>,
    eapol: VecDeque<Vec<u8>>,
}

impl Device {
    pub async fn initialize(
        mut hardware: Hardware,
        parsed: &super::ParsedUcode<'_>,
        firmware: &[u8],
    ) -> Result<Arc<Self>, &'static str> {
        for (group, command, version) in [
            (3, 8, 3),
            (3, 9, 8),
            (3, 10, 2),
            (1, 8, 6),
            (5, 0x17, 3),
            (1, 0xc, 5),
        ] {
            if hardware.version(group, command).map(|v| v.0) != Some(version) {
                return Err("unsupported MLD station command version");
            }
        }
        let mac = hardware.start(parsed).await?;
        let nvm = Self::configure(&mut hardware, mac).await?;
        let irq_vector = hardware.irq_vector();
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                hardware,
                scan_uid: 0,
                beacons: Vec::new(),
                connection: None,
                needs_reset: false,
                producer: None,
                eapol: VecDeque::new(),
            }),
            mac,
            irq_vector,
            channels: nvm.channels,
            tx_chains: nvm.tx_chains,
            phy: nvm.phy,
            firmware: firmware.to_vec(),
            pnvm: parsed.api.pnvm.map(|bytes| bytes.to_vec()),
            up: AtomicBool::new(false),
            rx: IrqSafeSpinLock::new(None),
            tx: core::array::from_fn(|_| IrqSafeSpinLock::new(None)),
        }))
    }

    async fn configure(
        hardware: &mut Hardware,
        mac: [u8; 6],
    ) -> Result<station_api::Nvm, &'static str> {
        let nvm_packet = hardware.command(0xc, 2, &[0; 4]).await?;
        let nvm = station_api::Nvm::parse(
            hardware.version(0xc, 2).ok_or("missing NVM version")?.1,
            &nvm_packet.payload,
        )?;
        if nvm.phy.ht {
            hardware.check_aggregation_api()?;
        }
        hardware
            .command(1, 0x98, &nvm.tx_chains.to_le_bytes())
            .await?;
        hardware
            .command(1, 0xc, &station_api::scan_config(&nvm))
            .await?;
        hardware
            .command(3, 8, &station_api::mac(1, mac, None))
            .await?;
        hardware
            .command(3, 9, &station_api::link(1, mac, false, 1, 0, 1))
            .await?;
        Ok(nvm)
    }

    async fn recover(&self, state: &mut State) -> Result<(), WirelessError> {
        self.set_link(false);
        state.needs_reset = true;
        state.connection = None;
        state.eapol.clear();
        let mut parsed =
            super::parse_ucode(&self.firmware).map_err(|_| WirelessError::HardwareError)?;
        parsed.api.pnvm = self.pnvm.as_deref();
        let mac = state
            .hardware
            .restart(&parsed)
            .await
            .map_err(|_| WirelessError::HardwareError)?;
        if mac != self.mac {
            state.hardware.fail();
            return Err(WirelessError::HardwareError);
        }
        let nvm = Self::configure(&mut state.hardware, mac)
            .await
            .map_err(|_| WirelessError::HardwareError)?;
        if nvm.tx_chains != self.tx_chains || nvm.channels != self.channels || nvm.phy != self.phy {
            state.hardware.fail();
            return Err(WirelessError::HardwareError);
        }
        state.needs_reset = false;
        Ok(())
    }

    pub fn start_pumps(self: &Arc<Self>) -> Result<(), &'static str> {
        let (rx_producer, rx_consumer) = narf_ipc::channel::<Frame, RX_RING_N>();
        *self.rx.lock() = Some(rx_consumer);
        let tx_consumers = narf_wireless::AccessCategory::ALL.map(|category| {
            let (producer, consumer) = narf_ipc::channel::<Frame, TX_RING_N>();
            *self.tx[category as usize].lock() = Some(producer);
            (category, consumer)
        });
        {
            let mut state = self.state.try_lock().expect("unpublished interface");
            state.producer = Some(rx_producer);
        }
        {
            let mut active = ACTIVE.lock();
            if active.is_some() {
                return Err("wlan0 already registered");
            }
            *active = Some(self.clone());
        }
        narf_net::iface::register(self.name(), self.mac, send_frame);
        narf_net::iface::set_link_state(self.name(), false);
        narf_net::iface::install_rx_drain(drain_network);
        if let Some(authority) = narf_net::trusted_net_authority().and_then(|a| a.derive().ok()) {
            let _ = narf_net::registry().register(&authority, RegisteredDevice(self.clone()));
        }
        let device = self.clone();
        narf_scheduler::spawn(async move {
            device.pump().await;
        });
        for (category, consumer) in tx_consumers {
            let device = self.clone();
            narf_scheduler::spawn(async move {
                device.transmit_pump(consumer, category as usize).await;
            });
        }
        Ok(())
    }

    fn set_link(&self, up: bool) {
        let was_up = self.up.swap(up, Ordering::AcqRel);
        narf_net::iface::set_link_state(self.name(), up);
        if was_up && !up {
            narf_wireless::nl80211::notify_disconnect(self.name(), 1);
        }
    }

    /// Nonblocking drain used both by the executor and synchronous IP
    /// waits. Dispatch to the network stack only after releasing state:
    /// an ARP/ICMP response can call send_frame synchronously.
    fn step(&self) -> Vec<Vec<u8>> {
        let mut output = Vec::new();
        let Some(mut state) = self.state.try_lock() else {
            return output;
        };
        if state.needs_reset {
            state.hardware.fail();
        }
        let State {
            hardware,
            connection,
            producer,
            eapol,
            ..
        } = &mut *state;
        if hardware.poll().is_err() {
            self.set_link(false);
            return output;
        }
        hardware.retire_transmits();
        if let Some(connection) = connection {
            for _ in 0..64 {
                let Some(packet) = hardware.notifications.pop_front() else {
                    break;
                };
                match connection.receive_packet(&packet) {
                    Ok(frames) => {
                        for bytes in frames {
                            queue_ethernet(
                                bytes,
                                connection.authorized,
                                producer,
                                eapol,
                                &mut output,
                            );
                        }
                    }
                    Err(_) => {
                        connection.authorized = false;
                        self.set_link(false);
                    }
                }
            }
            match connection.reorder_tick() {
                Ok(frames) => {
                    for bytes in frames {
                        queue_ethernet(bytes, connection.authorized, producer, eapol, &mut output);
                    }
                }
                Err(_) => {
                    connection.authorized = false;
                    self.set_link(false);
                }
            }
            if narf_time::now_cycles().wrapping_sub(connection.last_beacon)
                > narf_time::wall::ns_to_cycles(10_000_000_000)
            {
                connection.authorized = false;
                self.set_link(false);
            }
        } else {
            hardware.notifications.clear();
        }
        output
    }

    async fn transmit_pump(
        self: Arc<Self>,
        mut consumer: Consumer<Frame, TX_RING_N>,
        category: usize,
    ) {
        // recv registers the ring waker; queued Ethernet frames need no
        // timer tick or radio interrupt to start transmission.
        while let Ok(frame) = consumer.recv().await {
            let mut state = self.state.lock().await;
            if state.needs_reset {
                continue;
            }
            let State {
                hardware,
                connection,
                ..
            } = &mut *state;
            if let Some(connection) = connection {
                let _ = connection
                    .enqueue_wait_for_ac(hardware, frame.payload(), category)
                    .await;
            }
        }
    }

    async fn pump(self: Arc<Self>) {
        loop {
            let activity = super::iwl_msix::Activity::new(self.irq_vector, 100);
            for mut frame in self.step() {
                narf_net::iface::on_rx_frame_from(self.name(), &mut frame);
            }
            {
                let mut state = self.state.lock().await;
                let State {
                    hardware,
                    connection,
                    eapol,
                    ..
                } = &mut *state;
                if let Some(connection) = connection {
                    for _ in 0..16 {
                        let Some(frame) = eapol.pop_front() else {
                            break;
                        };
                        if connection.handle_eapol(hardware, &frame).await.is_err() {
                            connection.authorized = false;
                            self.set_link(false);
                        }
                    }
                    if connection.service_aggregation(hardware).await.is_err() {
                        connection.authorized = false;
                        self.set_link(false);
                    }
                } else {
                    eapol.clear();
                }
            }
            let pending = {
                let state = self.state.lock().await;
                !state.hardware.is_failed()
                    && (state.hardware.has_pending_rx() || !state.hardware.notifications.is_empty())
            };
            if pending {
                narf_scheduler::yield_now().await;
            } else {
                activity.await;
            }
        }
    }
}

fn queue_ethernet(
    bytes: Vec<u8>,
    authorized: bool,
    producer: &mut Option<Producer<Frame, RX_RING_N>>,
    eapol: &mut VecDeque<Vec<u8>>,
    output: &mut Vec<Vec<u8>>,
) {
    if bytes[12..14] == [0x88, 0x8e] {
        if eapol.len() < 16 {
            eapol.push_back(bytes);
        }
    } else if authorized {
        if let (Some(producer), Ok(buffer)) =
            (producer.as_mut(), super::runtime::dma_alloc(bytes.len()))
        {
            let mut frame = Frame::new(buffer, bytes.len() as u32);
            frame.payload_mut().copy_from_slice(&bytes);
            let _ = producer.try_send(frame);
        }
        output.push(bytes);
    }
}

impl Interface for Device {
    fn name(&self) -> &str {
        "wlan0"
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
        &self.tx[1]
    }
}

#[async_trait::async_trait]
impl WirelessNetIface for Device {
    fn phy_capabilities(&self, band_mhz: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        self.phy.capabilities(band_mhz)
    }
    fn tx_ring_for_ac(
        &self,
        category: narf_wireless::AccessCategory,
    ) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx[category as usize]
    }

    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }

    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.state
            .try_lock()?
            .beacons
            .iter()
            .find(|b| b.bssid == bssid)
            .map(|b| b.information_elements.clone())
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name().into(),
            base_mac: self.mac,
            bands: [2400, 5000]
                .into_iter()
                .map(|freq_mhz| WirelessBand {
                    freq_mhz,
                    channels: self
                        .channels
                        .iter()
                        .copied()
                        .filter(|&ch| (ch <= 14) == (freq_mhz == 2400))
                        .map(u32::from)
                        .collect(),
                })
                .collect(),
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: self.phy.ht,
                vht_supported: self.phy.vht,
                he_supported: false,
                eht_supported: false,
            },
        }
    }

    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        if request.ssids.len() > 20 || request.ssids.iter().any(|ssid| ssid.len() > 32) {
            return Err(WirelessError::InvalidArgs);
        }
        let channels = if request.channels.is_empty() {
            self.channels.clone()
        } else {
            let mut channels = Vec::new();
            for channel in &request.channels {
                let channel = u8::try_from(*channel).map_err(|_| WirelessError::InvalidArgs)?;
                if !self.channels.contains(&channel) {
                    return Err(WirelessError::InvalidArgs);
                }
                if !channels.contains(&channel) {
                    channels.push(channel);
                }
            }
            channels
        };
        let mut state = self.state.lock().await;
        if state.needs_reset
            || state.hardware.is_failed()
            || state
                .connection
                .as_ref()
                .is_some_and(|connection| !connection.authorized)
        {
            self.recover(&mut state).await?;
        }
        if state.connection.is_some() {
            return Err(WirelessError::Busy);
        }
        state.needs_reset = true;
        // Only one scan runs at a time; firmware scan slot zero.
        state.scan_uid = 0;
        let uid = state.scan_uid;
        let outcome = async {
            let State {
                hardware: hw,
                beacons,
                ..
            } = &mut *state;
            let version = hw.version(1, 0xd).ok_or(WirelessError::NotSupported)?.0;
            let mut body = scan_api::passive(version, uid, &channels)
                .map_err(|_| WirelessError::NotSupported)?;
            if request.active {
                if let Some(domain) = narf_wireless::reg::db::get_domain() {
                    let permissions = super::connection::regulatory_channels(hw)
                        .await
                        .map_err(|_| WirelessError::HardwareError)?;
                    let powers: Vec<_> = channels
                        .iter()
                        .map(|&channel| {
                            super::connection::channel_power(&domain, channel, &permissions, true)
                        })
                        .collect();
                    if let Some(power) = powers.iter().flatten().min() {
                        let power_command = station_api::tx_power(
                            hw.version(1, 0x9f).ok_or(WirelessError::NotSupported)?.0,
                            *power,
                        )
                        .map_err(|_| WirelessError::NotSupported)?;
                        hw.command(1, 0x9f, &power_command)
                            .await
                            .map_err(|_| WirelessError::HardwareError)?;
                    }
                    body = scan_api::active(
                        version,
                        uid,
                        &channels,
                        &powers.iter().map(Option::is_some).collect::<Vec<_>>(),
                        self.mac,
                        &request.ssids,
                    )
                    .map_err(|_| WirelessError::InvalidArgs)?;
                    scan_api::with_phy_capabilities(version, &mut body, self.phy)
                        .map_err(|_| WirelessError::InvalidArgs)?;
                }
            }
            hw.notifications
                .retain(|p| !(p.header.group_id == 0 && matches!(p.header.cmd, 0xf | 0xc1)));
            hw.command(1, 0xd, &body)
                .await
                .map_err(|_| WirelessError::HardwareError)?;
            let deadline = narf_time::Deadline::after_ms(15_000);
            let mut result: Vec<BssInfo> = Vec::new();
            loop {
                let activity = hw.activity();
                hw.poll().map_err(|_| WirelessError::HardwareError)?;
                while let Some(packet) = hw.notifications.pop_front() {
                    if packet.header.group_id != 0 {
                        continue;
                    }
                    if packet.header.cmd == 0xf {
                        if packet.payload.len() != 16 {
                            return Err(WirelessError::HardwareError);
                        }
                        if packet.payload[..4] != uid.to_le_bytes() {
                            continue;
                        }
                        return if packet.payload[6] == 1 {
                            Ok(result)
                        } else {
                            Err(WirelessError::HardwareError)
                        };
                    }
                    if packet.header.cmd != 0xc1 {
                        continue;
                    }
                    let Some(mpdu) = scan_api::mpdu(&packet.payload) else {
                        continue;
                    };
                    if mpdu.frame.len() < 36 || !matches!(mpdu.frame[0], 0x80 | 0x50) {
                        continue;
                    }
                    let bssid = mpdu.frame[16..22].try_into().unwrap();
                    let Some(body) = mpdu.body(24, 0) else {
                        continue;
                    };
                    let Some(beacon) = super::mlme::parse_beacon_to_bss(bssid, body) else {
                        continue;
                    };
                    if !request.ssids.is_empty()
                        && !request.ssids.iter().any(Vec::is_empty)
                        && !request.ssids.contains(&beacon.ssid)
                    {
                        continue;
                    }
                    let record = Beacon {
                        bssid,
                        ssid: beacon.ssid.clone(),
                        channel: mpdu.channel,
                        interval: u16::from_le_bytes([body[8], body[9]]),
                        dtim: super::scan_api::dtim_period(body),
                        rsn: beacon.rsn_ie_body.clone(),
                        privacy: body[10] & 0x10 != 0,
                        capabilities: u16::from_le_bytes([body[10], body[11]]),
                        information_elements: body[12..].to_vec(),
                    };
                    if let Some(old) = beacons.iter_mut().find(|old| old.bssid == bssid) {
                        *old = record;
                    } else if beacons.len() < 256 {
                        beacons.push(record);
                    }
                    let security = if beacon.rsn_ie_body.is_some() {
                        narf_wireless::scan::BssSecurity::Wpa2
                    } else if u16::from_le_bytes(mpdu.frame[34..36].try_into().unwrap()) & 0x10 != 0
                    {
                        narf_wireless::scan::BssSecurity::Wep
                    } else {
                        narf_wireless::scan::BssSecurity::Open
                    };
                    let bss = BssInfo {
                        bssid,
                        ssid: beacon.ssid,
                        channel: mpdu.channel as u32,
                        rssi: mpdu.rssi,
                        security,
                    };
                    if let Some(old) = result.iter_mut().find(|entry| entry.bssid == bssid) {
                        *old = bss;
                    } else if result.len() < 256 {
                        result.push(bss);
                    }
                }
                if deadline.expired() {
                    let mut abort = [0; 8];
                    super::boot_context::put32(&mut abort, 0, uid);
                    hw.command(1, 0xe, &abort)
                        .await
                        .map_err(|_| WirelessError::HardwareError)?;
                    hw.wait_notification(0, 0xf, 2000)
                        .await
                        .map_err(|_| WirelessError::HardwareError)?;
                    return Err(WirelessError::Timeout);
                }
                activity.await;
            }
        }
        .await;
        state.needs_reset = outcome.is_err();
        outcome
    }

    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        let psk = match request.security {
            narf_wireless::SecurityConfig::Open => None,
            narf_wireless::SecurityConfig::Wpa2 { psk } => Some(psk),
            narf_wireless::SecurityConfig::Wpa3 { .. } => return Err(WirelessError::NotSupported),
        };
        if request.ssid.len() > 32 || request.bssid[0] & 1 != 0 {
            return Err(WirelessError::InvalidArgs);
        }
        let mut state = self.state.lock().await;
        if state.needs_reset
            || state.hardware.is_failed()
            || state
                .connection
                .as_ref()
                .is_some_and(|connection| !connection.authorized)
        {
            self.recover(&mut state).await?;
        }
        if state.connection.is_some() {
            return Err(WirelessError::Busy);
        }
        let beacon = state
            .beacons
            .iter()
            .find(|b| {
                b.bssid == request.bssid
                    && b.ssid == request.ssid
                    && b.channel as u32 == request.channel
            })
            .cloned()
            .ok_or(WirelessError::InvalidArgs)?;
        // Cancellation leaves this set. The pump fails closed rather
        // than driving partially configured station/queue state.
        state.needs_reset = true;
        match Connection::associate(
            &mut state.hardware,
            self.mac,
            beacon,
            psk,
            self.tx_chains,
            self.phy,
        )
        .await
        {
            Ok(connection) => {
                state.connection = Some(connection);
                state.needs_reset = false;
                self.set_link(true);
                Ok(())
            }
            Err(error) => {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "iwlwifi: association failed: {}",
                    error
                );
                state.hardware.fail();
                Err(WirelessError::HardwareError)
            }
        }
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.set_link(false);
        let mut state = self.state.lock().await;
        if let Some(connection) = state.connection.take() {
            state.needs_reset = true;
            connection
                .disconnect(&mut state.hardware)
                .await
                .map_err(|_| WirelessError::HardwareError)?;
            state.needs_reset = false;
        }
        Ok(())
    }

    async fn set_config(&self, config: WirelessConfig) -> Result<(), WirelessError> {
        if config.tx_power_dbm.is_some() {
            return Err(WirelessError::NotSupported);
        }
        let state = self.state.lock().await;
        if state
            .connection
            .as_ref()
            .is_some_and(|c| c.beacon.channel as u32 == config.channel)
        {
            Ok(())
        } else {
            Err(WirelessError::InvalidArgs)
        }
    }
}

// The kernel's routing API uses function pointers. Keep the interface
// owner alive; the PCI function remains bound until kernel shutdown.
static ACTIVE: IrqSafeSpinLock<Option<Arc<Device>>> = IrqSafeSpinLock::new(None);

fn send_frame(bytes: &[u8]) -> Result<(), ()> {
    let device = ACTIVE.lock().clone().ok_or(())?;
    if !device.link_up() {
        return Err(());
    }
    if let Some(mut state) = device.state.try_lock() {
        let State {
            hardware,
            connection,
            ..
        } = &mut *state;
        if let Some(connection) = connection {
            return connection.enqueue(hardware, bytes).map_err(|_| ());
        }
        return Err(());
    }
    // Control commands can briefly own state across await. Queue the
    // packet without blocking an IRQ-disabled network caller.
    let buffer = super::runtime::dma_alloc(bytes.len()).map_err(|_| ())?;
    let mut frame = Frame::new(buffer, bytes.len() as u32);
    frame.payload_mut().copy_from_slice(bytes);
    let category = super::qos::Parameters::default()
        .classify(bytes)
        .ok_or(())?;
    let result = device.tx[category]
        .lock()
        .as_mut()
        .ok_or(())?
        .try_send(frame)
        .map_err(|_| ());
    result
}

fn drain_network() -> bool {
    let Some(device) = ACTIVE.lock().clone() else {
        return false;
    };
    let frames = device.step();
    let progress = !frames.is_empty();
    for mut frame in frames {
        narf_net::iface::on_rx_frame_from(device.name(), &mut frame);
    }
    progress
}

struct RegisteredDevice(Arc<Device>);
impl Interface for RegisteredDevice {
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

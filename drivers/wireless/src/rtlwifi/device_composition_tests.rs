//! Composed native firmware/PacketIo/Prepared/Device with the actual kernel
//! DHCP client. Only MMIO, DMA and the peer are inert. No test installs a
//! physical firmware or board-calibration registry entry.
use super::super::super::super::super::{
    firmware_transport::{Owner as Firmware, PacketIo, Stage},
    interface::Device,
};
use super::super::super::super::station::Admission;
use super::*;
use narf_lib::mutex::Mutex;
use narf_net::{Frame, Interface, TxMeta};
use narf_wireless::{AssociateRequest, ScanRequest, SecurityConfig, WirelessNetIface};

#[derive(Clone)]
struct BootPort {
    packet: PacketPort,
    pages: Arc<IrqSafeSpinLock<Vec<Vec<u8>>>>,
}
#[async_trait::async_trait]
impl Io for BootPort {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        self.packet.read8(reg)
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        if reg == 0x80 {
            let mut value = self.packet.radio.hardware_read8(reg);
            if value & 1 == 0 && self.pages.lock().iter().any(|page| !page.is_empty()) {
                value |= 4;
            }
            if value & 2 != 0 {
                value |= 0x40;
            }
            self.packet.radio.hardware_byte(reg, value);
        }
        self.packet.read32(reg)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        self.packet.write8(reg, value)?;
        if reg == 0x80 && value & 4 != 0 {
            self.packet.radio.hardware_byte(reg, value & !4);
        }
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError> {
        self.packet.write32(reg, value)
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), AccessError> {
        if reg >= 0x1000 {
            self.packet.check()?;
            let page = usize::from(self.packet.radio.hardware_read8(0x82) & 7);
            let mut pages = self.pages.lock();
            if pages[page].len() != usize::from(reg - 0x1000) {
                return Err(AccessError::Access);
            }
            pages[page].extend_from_slice(bytes);
            Ok(())
        } else {
            self.packet.write_bytes(reg, bytes)
        }
    }
    async fn delay_us(&self, micros: u64) {
        self.packet.delay_us(micros).await;
    }
}
impl Port for PacketIo<BootPort> {
    fn publication(&self) -> Result<Publication, Error> {
        self.with_io(|io| Ok(io.packet.publication()))?
    }
    type Buffer = Block;
    fn authority<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.with_io(|io| Ok(io.packet.authority(active, operation)))?
    }
    fn allocate_packet(&self, bytes: usize) -> Result<Block, Error> {
        self.with_io(|io| Ok(io.packet.allocate_packet(bytes)))?
    }
    fn master(&self, enabled: bool) -> Result<(), Error> {
        self.with_io(|io| Ok(io.packet.master(enabled)))?
    }
    fn kick(&self, bit: u16) -> Result<(), Error> {
        self.with_io(|io| Ok(io.packet.kick(bit)))?
    }
}
type HtFixtureSource = (
    Arc<IrqSafeSpinLock<Vec<u8>>>,
    narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    super::super::super::super::super::firmware_transport::Identity,
);
/// Inert MSI binding: the vector "fires" only when a test raises it.
struct IrqFixture {
    signal: IrqSafeSpinLock<Option<Arc<super::super::super::super::super::irq::Signal>>>,
    refuse: AtomicBool,
    delivered: IrqSafeSpinLock<Vec<bool>>,
}
impl Default for IrqFixture {
    fn default() -> Self {
        Self {
            signal: IrqSafeSpinLock::new(None),
            refuse: AtomicBool::new(false),
            delivered: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}
struct DeviceEnvironment {
    irq: Arc<IrqFixture>,
    admission: Arc<Admission>,
    base: Arc<Env>,
    packet: PacketPort,
    beacon: AtomicBool,
    ht: Option<HtFixtureSource>,
}
impl Environment for DeviceEnvironment {
    fn fallback(
        &self,
        base: Arc<super::super::super::super::super::channel_power::Calibration>,
    ) -> Result<Option<Arc<super::super::super::super::super::fallback::Grant>>, StationError> {
        self.base.fallback(base)
    }
    fn ht20(
        &self,
        base: Arc<super::super::super::super::super::channel_power::Calibration>,
    ) -> Result<Option<Arc<super::super::super::super::super::ht::Grant>>, StationError> {
        self.ht
            .as_ref()
            .map(|(b, cap, firmware)| {
                super::super::super::super::super::ht::Grant::parse(
                    base,
                    *firmware,
                    &b.lock(),
                    Some([0x77; 32]),
                    *cap,
                )
                .map(Arc::new)
                .map_err(StationError::Radio)
            })
            .transpose()
    }
    fn admission(&self) -> Option<&Arc<Admission>> {
        Some(&self.admission)
    }
    fn interrupt(&self) -> Option<Arc<super::super::super::super::super::irq::Signal>> {
        self.irq.signal.lock().clone()
    }
    fn deliver(&self, enabled: bool) -> bool {
        self.irq.delivered.lock().push(enabled);
        if enabled && !self.irq.refuse.load(Ordering::Acquire) {
            return true;
        }
        *self.irq.signal.lock() = None;
        false
    }
    fn now_ms(&self) -> u64 {
        self.base.now_ms()
    }
    fn fresh_nonce(&self) -> Option<[u8; 32]> {
        self.base.fresh_nonce()
    }
    fn domain(&self) -> Result<narf_wireless::reg::RegulatoryDomain, StationError> {
        self.base.domain()
    }
    async fn pause(&self) {
        // The AP beacon is injected only after native packet gates opened,
        // in response to actual service progress. Nothing fills scan cache.
        let active = { self.packet.model.lock().master };
        if active && !self.beacon.swap(true, Ordering::AcqRel) {
            let peer = self.packet.model.lock().peer.clone().unwrap();
            let beacon = {
                let p = peer.lock();
                let mut b = p.ap.beacon();
                if let Some(w) = &p.wmm {
                    b.extend_from_slice(w);
                }
                if let Some(ht) = &p.ht {
                    b[35] |= 4; // Source HT peer uses the standard short-slot capability.
                    b.extend_from_slice(ht);
                }
                b
            };
            self.packet.emit(&beacon).unwrap();
        }
        self.base.pause().await;
    }
}
type TestDevice = Device<PacketIo<BootPort>, Block, DeviceEnvironment>;
static ACTIVE_TEST: IrqSafeSpinLock<Option<Arc<TestDevice>>> = IrqSafeSpinLock::new(None);
fn send(bytes: &[u8], meta: TxMeta) -> Result<(), ()> {
    let device = ACTIVE_TEST.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain() -> bool {
    let device = ACTIVE_TEST.lock().clone();
    device.is_some_and(|device| device.drain())
}
struct Harness {
    device: Arc<TestDevice>,
    packet: PacketPort,
    peer: Arc<IrqSafeSpinLock<Peer>>,
    env: Arc<Env>,
    firmware: Arc<Firmware<BootPort>>,
    base_cap: Option<narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>>,
    ht_source: Option<HtFixtureSource>,
    irq: Arc<IrqFixture>,
}
impl Harness {
    fn new(protected: bool) -> Self {
        Self::new_profile(protected, false)
    }
    fn new_profile(protected: bool, ht: bool) -> Self {
        Self::with_policy(protected, ht, None)
    }
    fn with_policy(
        protected: bool,
        ht: bool,
        policy: Option<Arc<narf_wireless::reg::db::Database>>,
    ) -> Self {
        assert!(ACTIVE_TEST.lock().is_none());
        let packet = PacketPort::new();
        let factory = Arc::new(power::factory());
        packet.radio.w1c(0x20a);
        packet.radio.hardware_word(0x6c, 1 << 31);
        packet.radio.hardware_byte(3, 0xff);
        packet.radio.hardware_byte(0x82, 0xf8);
        let pages = Arc::new(IrqSafeSpinLock::new(vec![Vec::new(); 8]));
        let firmware = Arc::new(Firmware::new(
            BootPort {
                packet: packet.clone(),
                pages: pages.clone(),
            },
            super::super::super::super::super::regs::RTL_DEV_8188EE,
        ));
        // Supplied bytes use the same exact firmware protocol as production;
        // authentication and the selected EE filename have separate coverage.
        let mut image = vec![0; 32 + 4099];
        image[..2].copy_from_slice(&[0xe1, 0x88]);
        image[12..14].copy_from_slice(&4099u16.to_le_bytes());
        for (index, byte) in image[32..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        if ht {
            static NEXT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
            let name: &'static str = Box::leak(
                alloc::format!(
                    "narf-test/rtlwifi/ht20-fw-{}.bin",
                    NEXT.fetch_add(1, Ordering::AcqRel)
                )
                .into_boxed_str(),
            ); // The registered fixture retains this name for the kernel lifetime.
            let (write, read) = narf_firmware::bootstrap_authority();
            crate::firmware_asset::tests::install(&write, name, &image, true).unwrap();
            complete(firmware.initialize_registered_from(&read, name)).unwrap();
        } else {
            complete(firmware.initialize(&image)).unwrap();
        }
        assert_eq!(firmware.status().stage, Stage::Ready);
        assert_eq!(pages.lock()[0], image[32..4128]);
        assert_eq!(pages.lock()[1], [image[4128..].to_vec(), vec![0]].concat());
        let io = firmware.claim_packet_io().unwrap();
        assert!(firmware.claim_packet_io().is_err());
        let mut owner = Prepared::allocate(io, 4, |bytes| Ok(packet.allocate(bytes))).unwrap();
        complete(owner.prepare()).unwrap();
        complete(owner.configure_radio(radio::Profile::from_factory(&factory).unwrap())).unwrap();
        let base_cap = ht.then(narf_capabilities::Cap::bootstrap);
        let calibration = base_cap.map_or_else(
            || power::calibration(&factory),
            |cap| power::calibration_with_cap(&factory, cap),
        );
        let ht_source = ht.then(|| {
            (
                Arc::new(IrqSafeSpinLock::new(
                    super::super::super::super::super::ht::tests::artifact(
                        &calibration,
                        firmware.identity().unwrap(),
                    ),
                )),
                narf_capabilities::Cap::bootstrap(),
                firmware.identity().unwrap(),
            )
        });
        let domain = power::domain(17);
        complete(owner.configure_channel(calibration.permission(&domain, 1).unwrap())).unwrap();
        owner.configure_mac(&factory).unwrap();
        owner
            .stage_station_calibration(calibration, &domain)
            .unwrap();
        let mut environment = Env::new();
        environment.policy = policy;
        let env = Arc::new(environment);
        let peer = Arc::new(IrqSafeSpinLock::new(Peer::new(protected)));
        if ht {
            let mut p = peer.lock();
            p.wmm = Some(WMM.to_vec());
            p.ht = Some(super::super::super::super::super::ht::tests::ap_elements(
                255,
            ));
        }
        packet.model.lock().peer = Some(peer.clone());
        let name = narf_net::iface::reserve_name("ee-native%d");
        let irq = Arc::new(IrqFixture::default());
        let device = Arc::new(Device::new(
            name,
            Arc::new(Mutex::new(Some(owner))),
            factory,
            DeviceEnvironment {
                irq: irq.clone(),
                admission: Arc::new(Admission::new()),
                base: env.clone(),
                packet: packet.clone(),
                beacon: AtomicBool::new(false),
                ht: ht_source.clone(),
            },
        ));
        device.admit_for_test();
        *ACTIVE_TEST.lock() = Some(device.clone());
        narf_net::iface::register(name, device.mac(), send);
        narf_net::iface::set_link_state(name, true); // operator IFF_UP
        narf_net::iface::set_link_metadata(name, false, None, None);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Self {
            device,
            packet,
            peer,
            env,
            firmware,
            base_cap,
            ht_source,
            irq,
        }
    }
    fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: PEER,
            ssid: SSID.to_vec(),
            frequency_mhz: 2412,
            channel: 1,
            security: if self.peer.lock().ap.protected() {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        }
    }
    fn scan(&self) {
        let result = complete(self.device.scan(ScanRequest {
            ssids: vec![SSID.to_vec()],
            frequencies_mhz: vec![2412],
            channels: vec![1],
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(1),
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }))
        .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].bssid, PEER);
        assert_eq!(result[0].ssid, SSID);
    }
    fn join(&self) {
        self.scan();
        complete(self.device.associate(self.request())).unwrap();
        assert!(self.device.link_up());
        assert_eq!(self.device.connected_bssid(), Some(PEER));
        assert_eq!(self.peer.lock().ap.phase(), ApPhase::Authorized);
        narf_net::iface::set_link_state(self.device.name(), false);
        self.device.drain();
        assert!(narf_net::iface::lookup(self.device.name())
            .is_some_and(|iface| !iface.link_up && iface.carrier));
        narf_net::iface::set_link_state(self.device.name(), true);
    }
    fn pump(&self) {
        for _ in 0..16 {
            self.device.drain();
        }
    }
    /// The live owner returned to Passive scanning (safe rejoin).
    fn passive(&self) -> bool {
        self.packet.model.lock().master
            && self.device.prepared.try_lock().is_some_and(|owner| {
                owner.as_ref().is_some_and(|owner| {
                    owner.phase() == Phase::Running
                        && owner.station_phase()
                            == super::super::super::super::station::Phase::Passive
                })
            })
    }
    fn closed(&self) -> bool {
        !self.device.link_up()
            && self.device.connected_bssid().is_none()
            && narf_net::iface::lookup(self.device.name())
                .is_some_and(|iface| iface.link_up && !iface.carrier)
    }
    fn received(&self) -> Vec<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut slot = self.device.rx_ring().lock();
        let Some(ring) = slot.as_mut() else {
            return bytes;
        };
        while let Ok(Some(frame)) = ring.try_recv() {
            bytes.push(frame.payload().to_vec());
        }
        bytes
    }
    fn rx_count(&self) -> u64 {
        narf_net::iface::snapshot_counters()
            .iter()
            .find(|iface| iface.name == self.device.name())
            .map_or(0, |iface| iface.rx_packets)
    }
}
#[path = "ht_composition_tests.rs"]
mod ht_tests;
impl Drop for Harness {
    fn drop(&mut self) {
        *ACTIVE_TEST.lock() = None;
        narf_net::iface::unregister(self.device.name());
    }
}
fn composition(protected: bool) -> TestResult {
    let h = Harness::new(protected);
    let plan = h.peer.lock().plan;
    if !h.closed() || narf_net::dhcp::acquire(h.device.name(), 100).is_ok() {
        return TestResult::Fail("EE DHCP admitted before native association");
    }
    h.join();
    let lease = match narf_net::dhcp::dhcp_acquire(h.device.name(), 0) {
        Ok(lease) => lease,
        Err(_) => return TestResult::Fail("EE actual kernel DHCP failed"),
    };
    if !plan.matches_lease(&lease) {
        return TestResult::Fail("EE lease differs from real AP DHCP terms");
    }
    {
        let peer = h.peer.lock();
        let seen = peer.server.observations();
        if seen.discovers != 1 || seen.requests != 1 || peer.uplink.len() != 2 {
            return TestResult::Fail("EE native DORA publication/receipt mismatch");
        }
    }
    let uplink = udp_ipv4(
        PEER,
        plan.station,
        plan.lease_ip,
        plan.server_ip,
        49152,
        7,
        b"native-ee-device-uplink",
    );
    if narf_net::iface::send_on(h.device.name(), &uplink).is_err() {
        return TestResult::Fail("EE native Device rejected IP uplink");
    }
    h.pump();
    if h.peer.lock().uplink.last() != Some(&uplink) {
        return TestResult::Fail("EE real Device IP uplink/MIC differs");
    }
    let downlink = udp_ipv4(
        plan.station,
        PEER,
        plan.server_ip,
        plan.lease_ip,
        7,
        49152,
        b"native-ee-device-downlink",
    );
    let before = h.rx_count();
    let frame = { h.peer.lock().downlink(&downlink).unwrap() };
    h.packet.emit(&frame).unwrap();
    h.pump();
    if !h.received().contains(&downlink) || h.rx_count() <= before {
        return TestResult::Fail("EE exact IP downlink missed native RX ring or real stack");
    }
    if h.packet.model.lock().error.is_some() || h.firmware.claim_packet_io().is_ok() {
        return TestResult::Fail("EE device failed native wire or reopened firmware owner");
    }
    let reports = h.packet.model.lock().commands.len();
    if complete(h.device.disassociate()).is_err() || !h.closed() || !h.passive() {
        return TestResult::Fail("EE disconnect retained carrier or left Passive");
    }
    if h.packet.model.lock().commands[reports..] != [(1, vec![0])]
        || narf_net::iface::send_on(h.device.name(), &uplink).is_ok()
    {
        return TestResult::Fail("EE disconnect skipped JOINBSSRPT or kept data admission");
    }
    // Safe rejoin on the same live owner: a fresh AP session, a new
    // reserved-page upload on the reused beacon descriptor, and data.
    {
        let mut p = h.peer.lock();
        let fresh = Peer::new(protected);
        p.ap = fresh.ap;
        p.ptk = fresh.ptk;
        p.replay = fresh.replay;
        p.pn = fresh.pn;
    }
    let uploads = h.packet.model.lock().reserved.len();
    h.scan();
    if complete(h.device.associate(h.request())).is_err()
        || !h.device.link_up()
        || h.packet.model.lock().reserved.len() != uploads + 1
    {
        return TestResult::Fail("EE Passive owner refused a second association");
    }
    let again = udp_ipv4(
        PEER,
        plan.station,
        plan.lease_ip,
        plan.server_ip,
        49153,
        7,
        b"native-ee-device-rejoin",
    );
    if narf_net::iface::send_on(h.device.name(), &again).is_err() {
        return TestResult::Fail("EE rejoined Device rejected IP uplink");
    }
    h.pump();
    if h.peer.lock().uplink.last() != Some(&again) {
        return TestResult::Fail("EE rejoined Device uplink/MIC differs");
    }
    if complete(h.device.disassociate()).is_err() || !h.passive() {
        return TestResult::Fail("EE second disconnect did not return to Passive");
    }
    let before = h.packet.drops.load(Ordering::SeqCst);
    let packet = h.packet.clone();
    drop(h);
    if packet.drops.load(Ordering::SeqCst) != before {
        return TestResult::Fail(
            "EE terminal Device released published native DMA without quiescence",
        );
    }
    TestResult::Pass
}
/// The publisher binds the running owner to its vector, recognizes W1C
/// causes per wake, wakes on stack TX, and masks before releasing the
/// vector at close. A refused bind falls back to masked polling.
pub(crate) fn smoke_rtl8188ee_native_device_irq_worker_binds_and_releases_vector() -> TestResult {
    use super::super::super::super::super::irq::{Signal, IRQ_MASK0_88E, IRQ_MASK1_88E};
    let h = Harness::new(false);
    let signal = Signal::new();
    *h.irq.signal.lock() = Some(signal.clone());
    h.join();
    h.pump();
    if h.packet.radio.word(0xb0) != IRQ_MASK0_88E
        || h.packet.radio.word(0xb8) != IRQ_MASK1_88E
        || *h.irq.delivered.lock() != [true]
    {
        return TestResult::Fail("EE publisher did not bind the running owner to its vector");
    }
    // A pending ROK is recognized (W1C) by the next woken pass.
    h.packet.radio.hardware_word(0xb4, 1);
    signal.raise();
    h.device.drain();
    if h.packet.radio.word(0xb4) != 0 || h.packet.radio.word(0xb0) != IRQ_MASK0_88E {
        return TestResult::Fail("EE woken pass skipped _rtl_pci_interrupt recognition");
    }
    let plan = h.peer.lock().plan;
    let uplink = udp_ipv4(
        PEER,
        plan.station,
        plan.lease_ip,
        plan.server_ip,
        49152,
        7,
        b"ee-irq-wake",
    );
    let seen = signal.count();
    let _ = narf_net::iface::send_on(h.device.name(), &uplink);
    if signal.count() == seen {
        return TestResult::Fail("EE stack TX did not wake the interrupt worker");
    }
    if complete(h.device.disassociate()).is_err() {
        return TestResult::Fail("EE IRQ-bound disassociate failed");
    }
    // Disassociation keeps the live owner (Linux keeps interrupts on);
    // removal masks the chip before releasing the vector.
    let _ = complete(h.device.remove());
    h.pump();
    if h.packet.radio.word(0xb0) != 0
        || h.packet.radio.word(0xb8) != 0
        || h.irq.delivered.lock().last() != Some(&false)
        || h.irq.signal.lock().is_some()
    {
        return TestResult::Fail("EE close released the vector before masking HIMR");
    }
    drop(h);
    // Refused delivery: masks return to zero and service keeps polling.
    let h = Harness::new(false);
    *h.irq.signal.lock() = Some(Signal::new());
    h.irq.refuse.store(true, Ordering::Release);
    h.join();
    h.pump();
    if h.packet.radio.word(0xb0) != 0
        || h.packet.radio.word(0xb8) != 0
        || h.irq.signal.lock().is_some()
        || !h.device.link_up()
    {
        return TestResult::Fail("EE refused vector did not fall back to masked polling");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_irq_worker_binds_and_releases_vector
);
/// Linux watchdog LPS policy on the composed device: enter after five
/// idle linked periods, wake before special (DHCP) TX, leave on busy
/// traffic, stay awake while fwlps is off, and leave before disconnect.
pub(crate) fn smoke_rtl8188ee_native_device_leisure_policy_follows_linux_watchdog() -> TestResult {
    let h = Harness::new(false);
    h.join();
    h.pump();
    let leisure = |h: &Harness| {
        h.device
            .prepared
            .try_lock()
            .is_some_and(|owner| owner.as_ref().is_some_and(|owner| owner.leisure()))
    };
    // One watchdog period: the AP keeps beaconing (the firmware wakes for
    // DTIM beacons in LPS), so the station's peer-loss timer stays fed.
    let period = |h: &Harness, enabled: bool| {
        h.env.now.fetch_add(2_000, Ordering::AcqRel);
        let beacon = { h.peer.lock().ap.beacon() };
        h.packet.emit(&beacon).unwrap();
        h.device.drain();
        complete(h.device.power_save(enabled));
    };
    h.packet.model.lock().commands.clear();
    for _ in 0..4 {
        period(&h, true);
    }
    if leisure(&h) {
        return TestResult::Fail("EE dozed before cnt_after_linked reached five");
    }
    period(&h, true);
    if !leisure(&h)
        || !h
            .packet
            .model
            .lock()
            .commands
            .contains(&(0x20, vec![1, 0x10, 5, 0, 0]))
    {
        return TestResult::Fail("EE idle linked station did not enter firmware LPS");
    }
    // fwlps off (upstream default): leave at once and never re-enter.
    complete(h.device.power_save(false));
    for _ in 0..4 {
        period(&h, false);
    }
    if leisure(&h) {
        return TestResult::Fail("EE dozed with fwctrl_lps disabled");
    }
    period(&h, true);
    if !leisure(&h) {
        return TestResult::Fail("EE did not re-enter LPS when fwlps was enabled");
    }
    // DHCP (UDP 68->67) is rtl_is_special_data: held until awake.
    let arp = {
        let plan = h.peer.lock().plan;
        udp_ipv4(
            PEER,
            plan.station,
            plan.lease_ip,
            plan.server_ip,
            68,
            67,
            b"ee-lps-special",
        )
    };
    let before = h.peer.lock().uplink.len();
    if narf_net::iface::send_on(h.device.name(), &arp).is_err() {
        return TestResult::Fail("EE rejected DHCP while dozing");
    }
    h.device.drain();
    if h.peer.lock().uplink.len() != before {
        return TestResult::Fail("EE sent special data before leaving LPS");
    }
    complete(h.device.power_save(true));
    if leisure(&h) {
        return TestResult::Fail("EE did not wake for the held DHCP frame");
    }
    h.pump();
    // The stack pads short frames to the Ethernet minimum.
    if !h.peer.lock().uplink[before..].contains(&arp) {
        let ready = h.device.prepared.try_lock().map(|o| {
            o.as_ref().map(|o| {
                (
                    o.station_transmit_ready(),
                    o.transmit_ready(),
                    o.station_linked(),
                )
            })
        });
        return TestResult::Fail(match (h.device.pending_for_test(), ready) {
            (Some(false), _) if h.closed() => "EE held DHCP frame closed the station",
            (Some(false), _) => "EE held DHCP frame vanished (not pending, not sent)",
            (Some(true), Some(Some((false, true, _)))) => "EE held DHCP: station not ready",
            (Some(true), Some(Some((false, false, _)))) => "EE held DHCP: packet not ready",
            (Some(true), Some(Some((true, _, _)))) => "EE held DHCP: ready but unsent",
            _ => "EE did not send the held DHCP frame after waking",
        });
    }
    // Busy RX in a period (num_rx > 2) leaves, idle periods re-enter.
    period(&h, true);
    period(&h, true);
    if !leisure(&h) {
        return TestResult::Fail("EE did not re-enter LPS after an idle period");
    }
    for _ in 0..3 {
        let downlink = {
            let plan = h.peer.lock().plan;
            udp_ipv4(
                plan.station,
                PEER,
                plan.server_ip,
                plan.lease_ip,
                7,
                49152,
                b"ee-lps-busy",
            )
        };
        let frame = { h.peer.lock().downlink(&downlink).unwrap() };
        h.packet.emit(&frame).unwrap();
        h.device.drain();
    }
    complete(h.device.power_save(true));
    if leisure(&h) {
        return TestResult::Fail("EE stayed in LPS through busy RX");
    }
    period(&h, true);
    period(&h, true);
    if !leisure(&h) {
        return TestResult::Fail("EE did not re-enter LPS after busy traffic");
    }
    h.packet.model.lock().commands.clear();
    if complete(h.device.disassociate()).is_err() || !h.closed() {
        return TestResult::Fail("EE dozing disassociate failed");
    }
    let woke = {
        let model = h.packet.model.lock();
        model.commands.first() == Some(&(0x20, vec![0, 0x10, 5, 0, 0x0c]))
    };
    if !woke || leisure(&h) {
        return TestResult::Fail("EE disconnect left the firmware dozing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_leisure_policy_follows_linux_watchdog
);
pub(crate) fn smoke_rtl8188ee_native_device_open_kernel_dhcp_exact_ip() -> TestResult {
    composition(false)
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_open_kernel_dhcp_exact_ip
);
pub(crate) fn smoke_rtl8188ee_native_device_wpa2_kernel_dhcp_exact_ip() -> TestResult {
    composition(true)
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_wpa2_kernel_dhcp_exact_ip
);

pub(crate) fn smoke_rtl8188ee_native_device_m4_cancel_and_dma_bytes_cannot_authorize() -> TestResult
{
    for cancel in [true, false] {
        let h = Harness::new(true);
        h.scan();
        h.peer.lock().hold_m4 = true;
        let mut future = Box::pin(h.device.associate(h.request()));
        for _ in 0..200 {
            if h.packet.model.lock().held.is_some() {
                break;
            }
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("EE held M4 opened Device association");
            }
        }
        if h.packet.model.lock().held.is_none()
            || !h.closed()
            || narf_net::dhcp::acquire(h.device.name(), 100).is_ok()
        {
            return TestResult::Fail(
                "EE M4 fixture lacked actual DMA hold or controlled port stayed open",
            );
        }
        if cancel {
            drop(future);
            h.packet.release_held();
            h.pump();
        } else {
            // Same retained address/length, different actually read DMA body.
            // The AP verified original M4; that cannot authorize a mismatched
            // host receipt or publish this station's controlled port.
            let (queue, slot, _) = h.packet.model.lock().held.unwrap();
            let descriptor = h.packet.descriptor(queue, slot);
            let payload = h.packet.region(u64::from(word(&descriptor, 32)));
            let mut bytes = payload.bytes.lock();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            drop(bytes);
            h.packet.release_held();
            if complete(future).is_ok() {
                return TestResult::Fail("EE same-size modified M4 DMA receipt authorized keys");
            }
            h.pump();
        }
        if !h.closed() || h.packet.model.lock().master || !h.peer.lock().uplink.is_empty() {
            return TestResult::Fail("EE failed M4 retained data/carrier/native gates");
        }
        let before = h.packet.drops.load(Ordering::SeqCst);
        let packet = h.packet.clone();
        drop(h);
        if packet.drops.load(Ordering::SeqCst) != before {
            return TestResult::Fail("EE failed M4 Device released published mappings");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_m4_cancel_and_dma_bytes_cannot_authorize
);

fn direct(device: &TestDevice, bytes: &[u8], meta: TxMeta) {
    let buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0).unwrap();
    let mut frame = Frame::new(buffer, bytes.len() as u32);
    frame.payload_mut().copy_from_slice(bytes);
    frame.set_tx_meta(meta);
    device
        .tx_ring()
        .lock()
        .as_mut()
        .unwrap()
        .try_send(frame)
        .unwrap();
}
pub(crate) fn smoke_rtl8188ee_native_device_direct_ipc_metadata_and_policy_are_enforced(
) -> TestResult {
    let h = Harness::new(true);
    h.join();
    let plan = h.peer.lock().plan;
    let bytes = udp_ipv4(
        PEER,
        plan.station,
        plan.lease_ip,
        plan.server_ip,
        49152,
        7,
        b"ee-direct-ipc",
    );
    for meta in [
        TxMeta::with_csum(narf_net::L4CsumKind::Udp),
        TxMeta {
            tso_mss: Some(512),
            ..TxMeta::default()
        },
        TxMeta {
            vlan_tag: Some(3),
            ..TxMeta::default()
        },
    ] {
        if h.device.enqueue(&bytes, meta).is_ok() {
            return TestResult::Fail("EE accepted unsupported callback metadata");
        }
        direct(&h.device, &bytes, meta);
    }
    let mut wrong = bytes.clone();
    wrong[6] ^= 2;
    direct(&h.device, &wrong, TxMeta::default());
    let mut eapol = bytes.clone();
    eapol[12..14].copy_from_slice(&[0x88, 0x8e]);
    direct(&h.device, &eapol, TxMeta::default());
    h.pump();
    if !h.peer.lock().uplink.is_empty() || !h.device.link_up() {
        return TestResult::Fail(
            "EE direct IPC bypassed metadata/source/EAPOL admission or poisoned healthy station",
        );
    }
    direct(&h.device, &bytes, TxMeta::default());
    h.pump();
    if h.peer.lock().uplink != vec![bytes.clone()] {
        return TestResult::Fail("EE admitted direct Narf-Ring data did not reach native DMA");
    }
    h.env.power.store(10, Ordering::Release);
    h.pump();
    if !h.closed()
        || h.packet.model.lock().master
        || h.device.enqueue(&bytes, TxMeta::default()).is_ok()
    {
        return TestResult::Fail(
            "EE current signed-policy change retained carrier or transmission",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_direct_ipc_metadata_and_policy_are_enforced
);

pub(crate) fn smoke_rtl8188ee_native_device_rx_reports_do_not_hide_terminal_peer_loss() -> TestResult
{
    let h = Harness::new(false);
    h.join();
    let plan = h.peer.lock().plan;
    let bytes = udp_ipv4(
        plan.station,
        PEER,
        plan.server_ip,
        plan.lease_ip,
        7,
        49152,
        b"must-not-escape-terminal-rx-burst",
    );
    let data = { h.peer.lock().downlink(&bytes).unwrap() };
    h.packet.emit(&data).unwrap();
    let report = { h.packet.model.lock().rx_next };
    h.packet.emit(&[0; 28]).unwrap();
    let ring = h
        .packet
        .region(u64::from(h.packet.radio.word(LINUX_RX_BASE)));
    put(&mut ring.bytes.lock(), report * 32 + 12, 1 << 14);
    let mut deauth = vec![0xc0, 0, 0, 0];
    deauth.extend_from_slice(&plan.station);
    deauth.extend_from_slice(&PEER);
    deauth.extend_from_slice(&PEER);
    deauth.extend_from_slice(&[0, 0, 3, 0]);
    h.packet.emit(&deauth).unwrap();
    let before = h.rx_count();
    h.pump();
    if !h.closed()
        || !h.received().is_empty()
        || h.rx_count() != before
        || h.packet.model.lock().master
    {
        return TestResult::Fail("EE consumed RX report was mistaken for idle before peer loss");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_rx_reports_do_not_hide_terminal_peer_loss
);

pub(crate) fn smoke_rtl8188ee_native_device_disconnect_fences_stale_publisher_and_dma() -> TestResult
{
    let h = Harness::new(true);
    h.join();
    let plan = h.peer.lock().plan;
    let frame = udp_ipv4(
        PEER,
        plan.station,
        plan.lease_ip,
        plan.server_ip,
        49152,
        7,
        b"held-native-data-before-disconnect",
    );
    h.peer.lock().hold_data = true;
    h.device.enqueue(&frame, TxMeta::default()).unwrap();
    h.pump();
    if h.packet.model.lock().held.is_none() {
        return TestResult::Fail("EE fixture lacks published held native data");
    }
    if let Err(reason)=complete(super::super::super::super::super::interface::publication_test::disconnect_after_old_publication(&h.device,PEER)){return TestResult::Fail(reason);}
    if !h.closed()
        || h.packet.model.lock().master
        || h.device.enqueue(&frame, TxMeta::default()).is_ok()
    {
        return TestResult::Fail("EE terminal disconnect left native data admitted");
    }
    let before = h.packet.drops.load(Ordering::SeqCst);
    let packet = h.packet.clone();
    drop(h);
    if packet.drops.load(Ordering::SeqCst) != before {
        return TestResult::Fail("EE held packet/body rings released before reset quiescence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_disconnect_fences_stale_publisher_and_dma
);

pub(crate) fn smoke_rtl8188ee_native_device_rekey_reply_gates_data_without_carrier_flap(
) -> TestResult {
    let h = Harness::new(true);
    h.join();
    let plan = h.peer.lock().plan;
    let mut m1 = KeyFrame::empty(16);
    m1.key_information = narf_wireless::eapol::KI_KEY_TYPE_PAIRWISE
        | narf_wireless::eapol::KI_KEY_ACK
        | narf_wireless::eapol::KI_VERSION_HMAC_SHA1_AES;
    m1.key_length = 16;
    m1.replay_counter = 3;
    m1.key_nonce = [0xbb; 32];
    let mut ethernet = plan.station.to_vec();
    ethernet.extend_from_slice(&PEER);
    ethernet.extend_from_slice(&[0x88, 0x8e]);
    ethernet.extend_from_slice(&m1.into_eapol());
    let wire = { h.peer.lock().downlink(&ethernet).unwrap() };
    h.peer.lock().hold_data = true;
    h.packet.emit(&wire).unwrap();
    h.pump();
    if h.packet.model.lock().held.is_none()
        || !h.device.link_up()
        || h.device.connected_bssid() != Some(PEER)
    {
        return TestResult::Fail("EE native rekey reply failed or flapped established carrier");
    }
    let data = udp_ipv4(
        PEER,
        plan.station,
        plan.lease_ip,
        plan.server_ip,
        49152,
        7,
        b"ee-rekey-backpressure",
    );
    h.device.enqueue(&data, TxMeta::default()).unwrap();
    h.pump();
    if h.peer.lock().uplink.iter().any(|bytes| bytes == &data) {
        return TestResult::Fail("EE data bypassed pending native rekey reply");
    }
    h.peer.lock().hold_data = false;
    h.packet.release_held();
    h.pump();
    let snapshot = narf_net::iface::lookup(h.device.name()).unwrap();
    if !h.device.link_up()
        || snapshot.carrier_up_count != 1
        || snapshot.carrier_down_count != 0
        || !h.peer.lock().uplink.contains(&data)
    {
        return TestResult::Fail(
            "EE terminal rekey host receipt lost queued data or carrier continuity",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_rekey_reply_gates_data_without_carrier_flap
);

pub(crate) fn smoke_rtl8188ee_native_rekey_missing_m3_expires_despite_fresh_beacons() -> TestResult
{
    let h = Harness::new(true);
    h.join();
    let plan = h.peer.lock().plan;
    let mut m1 = KeyFrame::empty(16);
    m1.key_information = narf_wireless::eapol::KI_KEY_TYPE_PAIRWISE
        | narf_wireless::eapol::KI_KEY_ACK
        | narf_wireless::eapol::KI_VERSION_HMAC_SHA1_AES;
    m1.key_length = 16;
    m1.replay_counter = 3;
    m1.key_nonce = [0xbb; 32];
    let mut ethernet = plan.station.to_vec();
    ethernet.extend_from_slice(&PEER);
    ethernet.extend_from_slice(&[0x88, 0x8e]);
    ethernet.extend_from_slice(&m1.into_eapol());
    let wire = h.peer.lock().downlink(&ethernet).unwrap();
    h.packet.emit(&wire).unwrap();
    h.pump();
    let m2 = h.peer.lock().uplink.last().cloned().unwrap_or_default();
    let reply = m2.get(18..).and_then(|bytes| KeyFrame::decode(bytes, 16));
    if reply.is_none_or(|key| {
        key.replay_counter != 3 || key.key_information & narf_wireless::eapol::KI_KEY_MIC == 0
    }) || m2.get(12..14) != Some(&[0x88, 0x8e])
        || h.packet.model.lock().held.is_some()
        || !h
            .device
            .prepared
            .try_lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .station_transmit_ready()
        || !h.device.link_up()
    {
        return TestResult::Fail(
            "EE rekey lacks real terminal old-key M2 and reopened old-key port",
        );
    }
    let start = h.env.now.load(Ordering::Acquire);
    for delta in [1000, 2000, 3000, 4000, 4999] {
        h.env.now.store(start + delta, Ordering::Release);
        let beacon = h.peer.lock().ap.beacon();
        h.packet.emit(&beacon).unwrap();
        h.pump();
        if !h.device.link_up()
            || !h
                .device
                .prepared
                .try_lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .station_transmit_ready()
        {
            return TestResult::Fail(
                "EE valid beacons failed to retain the pre-deadline old-key station",
            );
        }
    }
    h.env.now.store(start + 5001, Ordering::Release);
    let beacon = h.peer.lock().ap.beacon();
    h.packet.emit(&beacon).unwrap();
    h.pump();
    let probe = udp_ipv4(
        PEER,
        plan.station,
        plan.lease_ip,
        plan.server_ip,
        49152,
        7,
        b"ee-missing-rekey-m3",
    );
    if !h.closed()
        || h.packet.model.lock().master
        || h.device.enqueue(&probe, TxMeta::default()).is_ok()
        || h.device
            .prepared
            .try_lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .station_transmit_ready()
    {
        return TestResult::Fail("EE fresh beacons hid M3 timeout or left native data admitted");
    }
    let before = h.packet.drops.load(Ordering::SeqCst);
    let packet = h.packet.clone();
    drop(h);
    if packet.drops.load(Ordering::SeqCst) != before {
        return TestResult::Fail(
            "EE terminal M3 timeout released native DMA before reset quiescence",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_rekey_missing_m3_expires_despite_fresh_beacons
);

pub(crate) fn smoke_rtl8188ee_native_device_paused_publisher_cannot_outlive_close() -> TestResult {
    let h = Harness::new(false);
    h.join();
    if let Err(reason) = complete(
        super::super::super::super::super::interface::publication_test::paused_publisher_then_close(
            &h.device,
        ),
    ) {
        return TestResult::Fail(reason);
    }
    if complete(h.device.disassociate()).is_err() {
        return TestResult::Fail("EE paused publisher final native teardown failed");
    }
    h.pump();
    // Safe rejoin: carrier closed, owner live and Passive (DMA not stopped).
    if !h.closed() || !h.passive() {
        return TestResult::Fail("EE paused publisher teardown did not return to Passive");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_paused_publisher_cannot_outlive_close
);

pub(crate) fn smoke_rtl8188ee_native_device_close_during_async_peer_prerequisite_blocks_dma(
) -> TestResult {
    for reserved in [false, true] {
        let h = Harness::new(false);
        h.scan();
        {
            let mut model = h.packet.model.lock();
            model.wait = true;
            if reserved {
                model.hold_command = Some(3);
            }
        }
        let mut association = Box::pin(h.device.associate(h.request()));
        let mut paused = false;
        for _ in 0..200 {
            if association
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail(
                    "EE prerequisite fixture did not pause native association",
                );
            }
            paused = if reserved {
                h.packet
                    .model
                    .lock()
                    .commands
                    .iter()
                    .any(|(id, _)| *id == 3)
            } else {
                h.packet.radio.word(0x670) & 0x8000_0000 != 0
            };
            if paused {
                break;
            }
        }
        if !paused {
            return TestResult::Fail("EE asynchronous CAM/mailbox wait not observed");
        }
        let mut disconnect = Box::pin(h.device.disassociate());
        if disconnect
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
            || !h.closed()
        {
            return TestResult::Fail("EE close did not precede retained-owner wait");
        }
        h.packet.radio.hardware_word(0x670, 0);
        h.packet.radio.hardware_byte(0x1cc, 0);
        {
            let mut model = h.packet.model.lock();
            model.wait = false;
            model.hold_command = None;
        }
        if complete(association).is_ok() {
            return TestResult::Fail("EE async prerequisite resumed association after host close");
        }
        let _ = complete(disconnect);
        h.pump();
        let model = h.packet.model.lock();
        if model.master || model.kicks.contains(&16) || !reserved && !model.kicks.is_empty() {
            return TestResult::Fail(
                "EE native MLME/BCN DMA published after asynchronous host close",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_close_during_async_peer_prerequisite_blocks_dma
);

pub(crate) fn smoke_rtl8188ee_native_device_cancelled_disconnect_wait_stops_owner() -> TestResult {
    let h = Harness::new(true);
    h.join();
    let owner = h.device.prepared.try_lock().unwrap();
    let mut disconnect = Box::pin(h.device.disassociate());
    if disconnect
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
        || !h.closed()
    {
        return TestResult::Fail("EE disconnect did not close before native-owner wait");
    }
    drop(disconnect);
    drop(owner);
    h.pump();
    if !h.closed() || h.packet.model.lock().master {
        return TestResult::Fail("EE cancelled owner-lock disconnect left native DMA active");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_cancelled_disconnect_wait_stops_owner
);

/// Linux `rtl88e_dm_watchdog` RA: the association installs the level-0
/// mask (`update_rate_tbl(sta, 0)`), BSSID-matching RX PHY status feeds
/// `undec_sm_pwdb`, and each 2 s refresh re-sends the mask only when the
/// hysteresis level changes. DATA after the mask carries fallback under
/// the separately signed NEFB grant.
pub(crate) fn smoke_rtl8188ee_native_device_rate_mask_follows_rx_pwdb() -> TestResult {
    let h = Harness::new(false);
    *h.env.fallback.lock() = Some((
        narf_capabilities::Cap::bootstrap(),
        h.firmware.identity().unwrap(),
        true,
    ));
    {
        // All 12 legacy rates: WIRELESS_MODE_G (supp_rates > 0xf).
        let mut p = h.peer.lock();
        let ap = core::mem::replace(&mut p.ap, Peer::new(false).ap);
        p.ap = ap.with_legacy_rates(&LEGACY_RATES).unwrap();
    }
    h.join();
    h.pump();
    let masks = |h: &Harness| -> Vec<Vec<u8>> {
        h.packet
            .model
            .lock()
            .commands
            .iter()
            .filter(|(id, _)| *id == 0x84)
            .map(|(_, payload)| payload.clone())
            .collect()
    };
    let state = |h: &Harness| {
        h.device.prepared.try_lock().and_then(|owner| {
            owner
                .as_ref()
                .map(|o| (o.station_rate_state(), o.rate_mask()))
        })
    };
    let initial = masks(&h);
    // A legacy (non-HT) AP: WIRELESS_MODE_G, ratr_index 4, level 0 &0xff5.
    if initial != [vec![0xf5, 0x0f, 0x00, 0x40, 0x80]] || state(&h).map(|s| s.1) != Some(Some(4)) {
        return TestResult::Fail("association did not install the level-0 RA mask");
    }
    // Ordinary DATA after the mask: RATE_ID 4 and DISDATAFB clear.
    let downlink = {
        let plan = h.peer.lock().plan;
        udp_ipv4(
            PEER,
            plan.station,
            plan.lease_ip,
            plan.server_ip,
            49152,
            7,
            b"ee-ra-data",
        )
    };
    let sent = h.packet.model.lock().descriptors.len();
    if narf_net::iface::send_on(h.device.name(), &downlink).is_err() {
        return TestResult::Fail("EE refused ordinary DATA");
    }
    h.pump();
    let data = {
        let model = h.packet.model.lock();
        (sent..model.descriptors.len())
            .find(|&n| model.observed[n][0] & 0x0c == 8 && model.observed[n].len() > 32)
            .map(|n| model.descriptors[n].clone())
    };
    let Some(data) = data else {
        return TestResult::Fail("EE ordinary DATA never reached a descriptor");
    };
    if word(&data, 16) & (1 << 10) != 0 || (word(&data, 4) >> 16) & 15 != 4 {
        return TestResult::Fail("DATA TXD kept DISDATAFB after the RA mask");
    }
    // Strong beacons: OFDM pwdb_all 0xa0 -> -30 dBm -> 70%.
    let period = |h: &Harness, pwdb_all: u8, count: usize| {
        let mut phy = [0u8; 28];
        phy[4] = pwdb_all;
        for _ in 0..count {
            let beacon = { h.peer.lock().ap.beacon() };
            h.packet.emit_native(&beacon, 11, 0, Some(&phy)).unwrap();
            h.device.drain();
        }
        h.env.now.fetch_add(2_000, Ordering::AcqRel);
        complete(h.device.rate_adaptive());
    };
    period(&h, 0xa0, 60);
    let high = masks(&h);
    if high.len() != 2
        || high[1] != [0, initial[0][1] & 0x0f, 0, 0x40, 0x80]
        || state(&h).map(|s| s.0 .1) != Some(1)
        || state(&h).map(|s| s.0 .0 > 50) != Some(true)
    {
        return TestResult::Fail("strong RX PWDB did not move the RA mask to HIGH");
    }
    // Same level: no new H2C; within the 2 s period: no refresh at all.
    period(&h, 0xa0, 4);
    complete(h.device.rate_adaptive());
    if masks(&h).len() != 2 {
        return TestResult::Fail("unchanged RA level re-sent the mask");
    }
    // Weak beacons: 0x28 -> -90 dBm -> 10%. HIGH -> MIDDLE -> LOW.
    let mut levels = Vec::new();
    for _ in 0..6 {
        period(&h, 0x28, 30);
        levels.push(state(&h).map(|s| s.0 .1).unwrap_or(0));
    }
    // LOW and level 0 share the G default branch (& 0xff5).
    if levels.last() != Some(&3) || masks(&h).len() < 3 || masks(&h).last() != initial.first() {
        return TestResult::Fail("weak RX PWDB did not reach the LOW RA mask");
    }
    // Teardown: disassociate withdraws the mask with the stopped owner.
    if complete(h.device.disassociate()).is_err() || !h.closed() {
        return TestResult::Fail("EE RA disassociate failed");
    }
    let count = masks(&h).len();
    complete(h.device.rate_adaptive());
    if masks(&h).len() != count || state(&h).and_then(|s| s.1).is_some() {
        return TestResult::Fail("RA refresh ran on a closed station");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_rate_mask_follows_rx_pwdb
);

/// Linux `rtl_pci_remove` on the composed Device: the linked station sends
/// its disconnect report, the chip is masked before the vector is released,
/// and the rings are freed only after the card-disable quiescence proof.
pub(crate) fn smoke_rtl8188ee_native_device_remove_releases_after_quiescence() -> TestResult {
    use super::super::super::super::super::irq::{Signal, IRQ_MASK0_88E};
    let owner_present = |h: &Harness| {
        h.device
            .prepared
            .try_lock()
            .map(|storage| storage.is_some())
    };
    // Success: bound vector, linked station, idle TX buffer and RXDMA.
    let h = Harness::new(false);
    let signal = Signal::new();
    *h.irq.signal.lock() = Some(signal.clone());
    h.join();
    h.pump();
    if h.packet.radio.word(0xb0) != IRQ_MASK0_88E {
        return TestResult::Fail("EE removal fixture did not bind its vector");
    }
    h.packet.radio.hardware_byte(0x286, 2);
    h.packet.model.lock().commands.clear();
    if !complete(h.device.remove()) || !h.device.removed_for_test() {
        return TestResult::Fail("EE idle removal did not reclaim DMA");
    }
    {
        let model = h.packet.model.lock();
        if model.commands.first() != Some(&(1, vec![0])) || model.master {
            return TestResult::Fail("EE removal skipped the disconnect report or kept BME");
        }
    }
    if h.packet.radio.word(0xb0) != 0
        || h.irq.delivered.lock().last() != Some(&false)
        || h.irq.signal.lock().is_some()
    {
        return TestResult::Fail("EE removal released the vector before masking");
    }
    if owner_present(&h) != Some(false)
        || !h.packet.live_regions().is_empty()
        || h.device.link_up()
        || h.device.connected_bssid().is_some()
        || narf_net::iface::lookup(h.device.name()).is_some()
    {
        return TestResult::Fail("EE removal kept the owner, DMA, carrier or netdev");
    }
    if !complete(h.device.remove()) || complete(h.device.associate(h.request())).is_ok() {
        return TestResult::Fail("EE removed Device was not idempotent or reopened");
    }
    drop(h);
    // Failure: RXDMA never idles -> the owner and every mapping stay pinned.
    let h = Harness::new(false);
    h.join();
    h.pump();
    h.packet.radio.hardware_byte(0x286, 0);
    if complete(h.device.remove()) || owner_present(&h) != Some(true) {
        return TestResult::Fail("EE busy RXDMA removal released the owner");
    }
    let regions = h.packet.live_regions();
    let drops = h.packet.drops.load(Ordering::SeqCst);
    let packet = h.packet.clone();
    drop(h);
    if regions.iter().any(|r| !r.live.load(Ordering::Acquire))
        || packet.drops.load(Ordering::SeqCst) != drops
    {
        return TestResult::Fail("EE unproven removal freed pinned DMA");
    }
    // Teardown before any association: the never-started owner is stopped
    // and proven idle, without a disconnect report.
    let h = Harness::new(false);
    h.packet.radio.hardware_byte(0x286, 2);
    h.packet.model.lock().commands.clear();
    if !complete(h.device.remove())
        || owner_present(&h) != Some(false)
        || !h.packet.model.lock().commands.is_empty()
    {
        return TestResult::Fail("EE never-associated removal differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/device",
    smoke_rtl8188ee_native_device_remove_releases_after_quiescence
);

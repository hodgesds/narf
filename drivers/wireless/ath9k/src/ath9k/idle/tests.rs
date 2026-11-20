// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual Device/Radio/Packet/DMA retirement followed by the same D0 sleep
//! helper and fresh reset/EEPROM/PHY/calibration/MAC generation. Model
//! register behavior and synthetic H assets are not physical qualification.
use super::*;
use crate::ath9k::identity::RegisterIo as _;
use crate::ath9k::{
    calibration::tests::{channel_receipt_image, wide_image, ChannelReceipt},
    interface::Device,
    packet::{tests::Model, Packet},
    station::{
        tests::{self as station_tests, Env, Peer, AP, PMK, SSID},
        Radio,
    },
};
use core::{
    sync::atomic::{AtomicBool, AtomicU64},
    task::Waker,
};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::Interface;
use narf_wifi_fixtures::udp_ipv4;
use narf_wireless::{AssociateRequest, ScanRequest, SecurityConfig, WirelessNetIface};

fn policy() -> ht::tests::Policy {
    let saved = ht::tests::Policy::install();
    narf_wireless::reg::db::set_domain(narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: alloc::vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2482,
            max_bandwidth_mhz: 40,
            max_power_dbm: 20,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    });
    saved
}
type TestDevice = Device<Arc<Model>, Arc<Env>>;
static ACTIVE: IrqSafeSpinLock<Option<Arc<TestDevice>>> = IrqSafeSpinLock::new(None);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain() -> bool {
    let device = ACTIVE.lock().clone();
    device.is_some_and(|device| device.drain())
}
macro_rules! check {
    ($condition:expr, $message:literal) => {
        if !$condition {
            return Err($message);
        }
    };
}
fn verdict(case: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    match case() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
struct Generation {
    device: Arc<TestDevice>,
    model: Arc<Model>,
    peer: Arc<IrqSafeSpinLock<Peer>>,
    image: [u8; EEPROM_4K_BYTES],
    identity: Identity,
    report: RadioCalibration,
}
#[inline(never)]
fn peer(protected: bool, channel: u8) -> Arc<IrqSafeSpinLock<Peer>> {
    Arc::new(IrqSafeSpinLock::new(Peer::new_channel(
        protected, None, channel,
    )))
}
impl Generation {
    #[inline(never)]
    fn cold(frequency: u16, protected: bool, qualified: bool) -> Result<Self, &'static str> {
        let receipt = channel_receipt_image(frequency, 40, wide_image())
            .map_err(|_| "idle fresh native reset/EEPROM/PHY/calibration")?;
        let model = Model::new();
        model.frequency.set(receipt.report.frequency_mhz);
        model.channels.set(0x1fff);
        *model.registers.borrow_mut() = receipt.registers.clone();
        // Device-side RTC state actually observed ON by the reset/calibration
        // fixture. Packet reads use this same register map, not a sleep ACK.
        model.registers.borrow_mut().insert(0x7044, 2);
        mac::prepare(&model, &receipt.image, receipt.identity.mac)
            .map_err(|_| "idle fresh complete MAC/key-cache preparation")?;
        if qualified {
            let facts = ht::Facts::new(
                ht::tests::model_device(),
                receipt.identity,
                receipt.prepared,
                receipt.report,
                &receipt.image,
            )
            .map_err(|_| "idle fresh H facts")?;
            let grant = ht::Source::Verified {
                bytes: ht::tests::record(&facts, 255),
                signer: Some([0x85; 32]),
                cap: Cap::<FirmwareBlob, Read>::bootstrap(),
            }
            .load(facts)
            .map_err(|_| "idle fresh H source")?;
            grant
                .readback(&model)
                .map_err(|_| "idle fresh actual H readback")?;
            *model.ht.borrow_mut() = Some(grant);
        }
        Self::finish(model, receipt, protected)
    }
    #[inline(never)]
    fn wide(width: channel_width::Width) -> Result<Self, &'static str> {
        let nominal = channel_receipt_image(2437, 40, wide_image())
            .map_err(|_| "idle wide nominal full reset")?;
        let base_facts = ht::Facts::new(
            ht::tests::model_device(),
            nominal.identity,
            nominal.prepared,
            nominal.report,
            &nominal.image,
        )
        .map_err(|_| "idle wide nominal H facts")?;
        let base = ht::Source::Verified {
            bytes: ht::tests::record(&base_facts, 255),
            signer: Some([0x85; 32]),
            cap: Cap::<FirmwareBlob, Read>::bootstrap(),
        }
        .load(base_facts)
        .map_err(|_| "idle wide nominal source")?;
        let geometry = channel_width::Geometry::new(6, width).map_err(|_| "idle wide geometry")?;
        let facts = ht40::Facts::new(
            ht::tests::model_device(),
            nominal.identity,
            nominal.prepared,
            nominal.report,
            &nominal.image,
            base,
            geometry,
        )
        .map_err(|_| "idle complete40 facts")?;
        // Offline synthetic qualification input: the live program below must
        // still run a separate actual full40 calibration and match its digest.
        let oracle = calibration::tests::wide_receipt(geometry, 40, nominal.image, None)
            .map_err(|_| "idle offline model full40 source")?;
        let request = facts.request();
        let mut bytes = alloc::vec![0; 384];
        bytes[..8].copy_from_slice(&[b'N', b'8', b'5', b'H', 3, 0, 0, 1]);
        bytes[8..12].copy_from_slice(&384u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&[0x8c, 0x16, 0x2b, 0]);
        bytes[16..48].copy_from_slice(&request.identity);
        bytes[48..54].copy_from_slice(&request.mac);
        bytes[54..58].copy_from_slice(&geometry.body());
        bytes[58..60].copy_from_slice(&4i16.to_le_bytes());
        bytes[60..62].copy_from_slice(&40i16.to_le_bytes());
        bytes[62..64].copy_from_slice(&[255, 3]);
        bytes[64..96].copy_from_slice(&oracle.report.digest());
        bytes[96..128].copy_from_slice(&facts.base_digest());
        for index in 0..64 {
            if !(56..59).contains(&index) {
                bytes[256 + index * 2..258 + index * 2].copy_from_slice(&20i16.to_le_bytes());
            }
        }
        let grant = ht40::Source::Verified {
            bytes,
            signer: Some([0x85; 32]),
            cap: Cap::<FirmwareBlob, Read>::bootstrap(),
        }
        .load(facts)
        .map_err(|_| "idle current full40 source")?;
        let actual = calibration::tests::wide_receipt(geometry, 40, nominal.image, None)
            .map_err(|_| "idle live full40 calibration")?;
        grant
            .accept(actual.report)
            .map_err(|_| "idle actual40 receipt match")?;
        let model = Model::new();
        model.frequency.set(2437);
        model.channels.set(0x1fff);
        *model.registers.borrow_mut() = actual.registers;
        model.registers.borrow_mut().insert(0x7044, 2);
        *model.wide.borrow_mut() = Some(actual.report);
        mac::prepare(&model, &actual.image, nominal.identity.mac)
            .map_err(|_| "idle full40 MAC preparation")?;
        let wrapped = ht::Grant::from_wide(grant, actual.report)
            .map_err(|_| "idle actual40 installed source")?;
        wrapped
            .readback(&model)
            .map_err(|_| "idle actual40 physical readback")?;
        *model.ht.borrow_mut() = Some(wrapped);
        Self::finish(
            model,
            ChannelReceipt {
                image: actual.image,
                identity: nominal.identity,
                prepared: actual.prepared,
                report: actual.report.report,
                registers: Default::default(),
            },
            true,
        )
    }
    #[inline(never)]
    fn finish(
        model: Arc<Model>,
        receipt: ChannelReceipt,
        protected: bool,
    ) -> Result<Self, &'static str> {
        let channel = ((receipt.report.frequency_mhz - 2407) / 5) as u8;
        let peer = peer(protected, channel);
        if model.ht.borrow().is_some() {
            let mut ies = ht::tests::elements();
            ies[30] = channel;
            peer.lock().ht = Some(ies);
        }
        let reaction = peer.clone();
        *model.reaction.borrow_mut() = Some(Arc::new(move |bytes| {
            reaction
                .lock()
                .react(bytes)
                .map_err(|_| packet::Error::Packet)
        }));
        let environment = Arc::new(Env {
            now: AtomicU64::new(0),
            entropy: AtomicBool::new(true),
        });
        // SAFETY: same model just ran actual full reset, identical factory,
        // PHY/calibration and MAC preparation with no inherited live DMA.
        let packet = unsafe { Packet::prepare(model.clone(), receipt.identity.mac) }
            .map_err(|_| "idle native packet prepare")?;
        let mut radio = Radio::new(
            packet,
            receipt.identity.mac,
            receipt.report.noise_dbm,
            environment,
        );
        radio.start().map_err(|_| "idle actual native start")?;
        let beacon = { peer.lock().beacon() };
        model
            .inject(&beacon, 0)
            .map_err(|_| "idle actual initial beacon DMA")?;
        radio.poll().map_err(|_| "idle actual initial RX poll")?;
        let name = narf_net::iface::reserve_name("ar9-idle%d");
        let device = Arc::new(
            Device::new(name, Arc::new(Mutex::new(radio))).map_err(|_| "idle native Device")?,
        );
        device.admit_for_test();
        Ok(Self {
            device,
            model,
            peer,
            image: receipt.image,
            identity: receipt.identity,
            report: receipt.report,
        })
    }
    fn activate(&self) {
        *ACTIVE.lock() = Some(self.device.clone());
        narf_net::iface::register(self.device.name(), self.identity.mac, send);
        narf_net::iface::set_link_state(self.device.name(), true);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
    }
    fn join(&self) -> Result<(), &'static str> {
        let frequency = self.report.frequency_mhz;
        station_tests::complete(self.device.scan(ScanRequest {
            ssids: alloc::vec![SSID.to_vec()],
            frequencies_mhz: alloc::vec![u32::from(frequency)],
            channels: alloc::vec![u32::from((frequency - 2407) / 5)],
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(1),
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }))
        .map_err(|_| "idle successor actual native discovery")?;
        let protected = { self.peer.lock().ap.protected() };
        station_tests::complete(self.device.associate(AssociateRequest {
            bssid: AP,
            ssid: SSID.to_vec(),
            frequency_mhz: u32::from(frequency),
            channel: u32::from((frequency - 2407) / 5),
            ie: Vec::new(),
            security: if protected {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
        }))
        .map_err(|_| "idle successor actual native Open/WPA2 MLME/RSNA")?;
        for _ in 0..16 {
            self.device.drain();
        }
        check!(
            self.device.link_up() && self.device.connected_bssid() == Some(AP),
            "idle successor native carrier"
        );
        Ok(())
    }
}
impl Drop for Generation {
    fn drop(&mut self) {
        self.device.retire_host();
        if let Some(mut radio) = self.device.radio.try_lock() {
            radio.retire();
        }
        let mut active = ACTIVE.lock();
        if active
            .as_ref()
            .is_some_and(|device| Arc::ptr_eq(device, &self.device))
        {
            *active = None;
        }
    }
}

/// Raw original-controller access after complete native retirement. Emulate
/// only silicon RTC state, never the driver's count/quiet/terminal receipts.
struct Chip {
    model: Arc<Model>,
    trace: Vec<(u64, u32)>,
    shutdown: u32,
    ignored: Option<u64>,
    delays: u64,
}
impl Chip {
    fn new(model: Arc<Model>) -> Self {
        Self {
            model,
            trace: Vec::new(),
            shutdown: 1,
            ignored: None,
            delays: 0,
        }
    }
}
impl identity::RegisterIo for Chip {
    fn authorized(&self) -> bool {
        self.model.authority.get()
    }
    fn read32(&mut self, register: u64) -> u32 {
        if !self.authorized() {
            return u32::MAX;
        }
        self.model
            .registers
            .borrow()
            .get(&register)
            .copied()
            .unwrap_or(0)
    }
    fn write32(&mut self, register: u64, value: u32) {
        if !self.authorized() {
            return;
        }
        self.trace.push((register, value));
        if self.ignored == Some(register) {
            return;
        }
        self.model.registers.borrow_mut().insert(register, value);
        if register == 0x7040 && value & 1 == 0 {
            let actual_reset =
                { self.model.registers.borrow().get(&0x4000).copied() == Some(0x101) };
            let force_off = {
                self.model
                    .registers
                    .borrow()
                    .get(&0x704c)
                    .copied()
                    .unwrap_or(0)
                    & 1
                    == 0
            };
            if actual_reset && force_off {
                self.model
                    .registers
                    .borrow_mut()
                    .insert(0x7044, self.shutdown);
            }
        }
    }
    fn delay_us(&mut self, us: u64) {
        self.delays += us;
    }
    fn wait(&mut self, register: u64, mask: u32, expected: u32) -> Result<u32, BringUpError> {
        let value = self.read32(register);
        if value == u32::MAX {
            Err(BringUpError::DeviceGone)
        } else if value & mask == expected {
            Ok(value)
        } else {
            Err(BringUpError::Timeout)
        }
    }
}
impl hardware::Io for Chip {
    fn bus_master(&mut self) -> Result<bool, BringUpError> {
        if !self.authorized() {
            return Err(BringUpError::DeviceGone);
        }
        Ok(self.model.master.get())
    }
}
fn request(owner: &Owner, generation: &Generation) -> Result<(), Error> {
    let radio = generation.device.radio.try_lock().ok_or(Error::Busy)?;
    admit(owner, &radio, 1)
}
fn retire(
    owner: &Owner,
    generation: &Generation,
    guard: &mut Option<WakeGuard>,
) -> Result<(), Error> {
    owner.phase(State::Quiescing);
    if !station_tests::complete(retire_station(&generation.device.radio, guard, || {
        generation.device.retire_host()
    })) {
        owner.phase(State::Failed);
        return Err(Error::Hardware(BringUpError::BadState));
    }
    owner.armed()
}
fn retire_and_sleep(
    owner: &Owner,
    generation: &Generation,
    guard: &mut Option<WakeGuard>,
) -> Result<Chip, Error> {
    request(owner, generation)?;
    retire(owner, generation, guard)?;
    let mut chip = Chip::new(generation.model.clone());
    owner.enter(&mut chip)?;
    Ok(chip)
}

fn counted() -> Result<(), &'static str> {
    for qualified in [false, true] {
        let generation = Generation::cold(2437, false, qualified)?;
        let owner = Owner::new();
        let mut station = Some(owner.use_awake(true).map_err(|_| "idle station count")?);
        let control = owner
            .use_awake(false)
            .map_err(|_| "idle queued control count")?;
        let before = generation.model.count.get();
        check!(
            request(&owner, &generation) == Err(Error::Busy),
            "counted control did not refuse idle"
        );
        check!(
            before == generation.model.count.get() && owner.status(7).users == 2,
            "idle refusal touched native IO or lost a counted use"
        );
        drop(control);
        let tail = generation
            .model
            .last_rx
            .get()
            .ok_or("idle completed native tail")?;
        check!(
            generation
                .model
                .word(tail + 48)
                .is_ok_and(|word| word & 1 != 0)
                && generation.model.released.borrow().is_empty(),
            "idle preflight recycled retained RX tail"
        );
        let chip = retire_and_sleep(&owner, &generation, &mut station)
            .map_err(|_| "idle full physical entry")?;
        let status = owner.status(7);
        check!(
            status.desired
                && status.state == State::Asleep
                && status.users == 0
                && !generation.model.master.get()
                && !generation.model.released.borrow().is_empty()
                && generation.model.word(tail + 48).is_err(),
            "idle count released before actual terminal stop"
        );
        check!(
            chip.trace
                .iter()
                .map(|(r, _)| *r)
                .eq([0x8004, 0x704c, 0x4000, 0x7040])
                && chip.delays == 2
                && generation.model.registers.borrow().get(&0x7044) == Some(&1),
            "D0 FULL_SLEEP source order or actual SHUTDOWN receipt differs"
        );
        check!(
            owner.use_awake(false).is_err() && owner.use_awake(true).is_err(),
            "sleeping count supplied IO/wake admission"
        );
    }
    Ok(())
}
fn smoke_ar9285_idle_counted_controls_retained_tail_and_actual_full_sleep() -> TestResult {
    let _policy = policy();
    verdict(counted)
}
kernel_test_in!(
    "drivers/wireless/ath9k/idle-full-sleep",
    smoke_ar9285_idle_counted_controls_retained_tail_and_actual_full_sleep
);

fn associated() -> Result<(), &'static str> {
    for protected in [false, true] {
        let generation = Generation::cold(2412, protected, true)?;
        generation.activate();
        generation.join()?;
        let owner = Owner::new();
        let _station = owner
            .use_awake(true)
            .map_err(|_| "idle live station count")?;
        let before = generation.model.count.get();
        let epoch = { generation.device.radio.try_lock().unwrap().receive_epoch() };
        check!(
            request(&owner, &generation) == Err(Error::Busy)
                && before == generation.model.count.get(),
            "associated idle request touched hardware or was admitted"
        );
        let plan = { generation.peer.lock().plan };
        let frame = udp_ipv4(
            AP,
            plan.station,
            plan.lease_ip,
            plan.server_ip,
            4950,
            7,
            b"idle denied while associated",
        );
        generation
            .device
            .enqueue(&frame, Default::default())
            .map_err(|_| "idle refusal closed real DATA")?;
        for _ in 0..16 {
            generation.device.drain();
        }
        let delivered = { generation.peer.lock().uplink.last() == Some(&frame) };
        let after_epoch = { generation.device.radio.try_lock().unwrap().receive_epoch() };
        check!(
            delivered
                && epoch == after_epoch
                && generation.device.link_up()
                && generation.model.master.get(),
            "idle refusal changed native link/key/PN ownership"
        );
        let lease = narf_net::dhcp::dhcp_acquire(generation.device.name(), 0)
            .map_err(|_| "idle denied live kernel DHCP")?;
        check!(plan.matches_lease(&lease), "idle denied live DHCP lease");
    }
    Ok(())
}
fn smoke_ar9285_idle_associated_open_wpa2_refusal_preserves_native_keys_and_dhcp() -> TestResult {
    let _policy = policy();
    verdict(associated)
}
kernel_test_in!(
    "drivers/wireless/ath9k/idle-full-sleep",
    smoke_ar9285_idle_associated_open_wpa2_refusal_preserves_native_keys_and_dhcp
);

fn cancelled_timer() -> Result<(), &'static str> {
    for protected in [false, true] {
        let old = Generation::cold(2462, protected, true)?;
        old.activate();
        let owner = Owner::new();
        let mut station = Some(
            owner
                .use_awake(true)
                .map_err(|_| "idle cancel station count")?,
        );
        request(&owner, &old).map_err(|_| "idle cancel request")?;
        retire(&owner, &old, &mut station).map_err(|_| "idle cancel native retirement")?;
        let mut delay = Box::pin(owner.wait_armed(core::future::pending()));
        let mut cx = Context::from_waker(Waker::noop());
        check!(
            delay.as_mut().poll(&mut cx).is_pending() && owner.status(9).state == State::Armed,
            "idle timer completed without elapsed timer receipt"
        );
        owner
            .set_desired(false)
            .map_err(|_| "idle leaving request")?;
        check!(
            delay.as_mut().poll(&mut cx) == Poll::Ready(false),
            "leaving idle did not cancel retained delay"
        );
        drop(delay);
        check!(
            old.model.registers.borrow().get(&0x7044) == Some(&2) && !old.model.master.get(),
            "cancelled timer clocked off or resurrected old DMA"
        );
        owner.phase(State::Waking);
        // Same actual cold reset/EEPROM/PHY/calibration and current H loader
        // primitives as the physical controller. No old native ring is reused.
        let fresh = Generation::cold(old.report.frequency_mhz, protected, true)?;
        check!(
            fresh.identity == old.identity
                && fresh.image == old.image
                && fresh.report.frequency_mhz == 2462
                && fresh.device.name() != old.device.name(),
            "idle wake lost primary/factory or reused old public generation"
        );
        let _station = owner
            .use_awake(true)
            .map_err(|_| "idle fresh station count while Waking")?;
        owner.phase(State::Operational);
        check!(
            !fresh.device.link_up()
                && fresh.device.connected_bssid().is_none()
                && fresh.device.radio.try_lock().unwrap().idle_admissible(),
            "cold wake claimed old association/key state"
        );
        fresh.activate();
        fresh.join()?;
        let plan = { fresh.peer.lock().plan };
        let lease = narf_net::dhcp::dhcp_acquire(fresh.device.name(), 0)
            .map_err(|_| "idle fresh native kernel DHCP")?;
        check!(
            plan.matches_lease(&lease)
                && !old.device.link_up()
                && old.device.enqueue(&[0; 60], Default::default()).is_err(),
            "cold wake reopened retired public endpoint"
        );
    }
    Ok(())
}
fn smoke_ar9285_idle_cancelled_delay_cold_generation_and_fresh_open_wpa2_dhcp() -> TestResult {
    let _policy = policy();
    verdict(cancelled_timer)
}
kernel_test_in!(
    "drivers/wireless/ath9k/idle-full-sleep",
    smoke_ar9285_idle_cancelled_delay_cold_generation_and_fresh_open_wpa2_dhcp
);

fn wedged() -> Result<(), &'static str> {
    for rx in [false, true] {
        let generation = Generation::cold(2412, false, true)?;
        let owner = Owner::new();
        let mut station = Some(
            owner
                .use_awake(true)
                .map_err(|_| "idle wedge station count")?,
        );
        request(&owner, &generation).map_err(|_| "idle wedge request")?;
        if rx {
            generation.model.stuck_rx.set(true);
        } else {
            generation.model.stuck_tx.set(true);
            generation
                .model
                .registers
                .borrow_mut()
                .insert(0x840, 1 << 9);
            generation.model.registers.borrow_mut().insert(0xa24, 1);
        }
        check!(
            retire(&owner, &generation, &mut station).is_err()
                && station.is_some()
                && owner.status(3).users == 1
                && owner.status(3).state == State::Failed
                && generation.model.released.borrow().is_empty(),
            "wedged native engine released full-sleep count or mappings"
        );
        let mut chip = Chip::new(generation.model.clone());
        check!(
            owner.enter(&mut chip) == Err(Error::Busy)
                && chip.trace.is_empty()
                && generation.model.registers.borrow().get(&0x7044) == Some(&2),
            "unproved terminal DMA authorized a full-sleep request or receipt"
        );
    }
    Ok(())
}
fn smoke_ar9285_idle_wedged_all_qcu_or_rx_pins_original_owner_before_clock_off() -> TestResult {
    let _policy = policy();
    verdict(wedged)
}
kernel_test_in!(
    "drivers/wireless/ath9k/idle-full-sleep",
    smoke_ar9285_idle_wedged_all_qcu_or_rx_pins_original_owner_before_clock_off
);

fn physical_failures() -> Result<(), &'static str> {
    for status in [0, 2, 4, u32::MAX] {
        let generation = Generation::cold(2412, false, false)?;
        let owner = Owner::new();
        let mut station = Some(owner.use_awake(true).map_err(|_| "idle physical count")?);
        request(&owner, &generation).map_err(|_| "idle physical request")?;
        retire(&owner, &generation, &mut station).map_err(|_| "idle physical stop")?;
        let mut chip = Chip::new(generation.model.clone());
        chip.shutdown = status;
        check!(
            owner.enter(&mut chip).is_err()
                && owner.status(2).state == State::Failed
                && !generation.model.master.get(),
            "request/non-SHUTDOWN bit became an asleep receipt"
        );
    }
    for register in [0x8004, 0x704c, 0x4000, 0x7040] {
        let generation = Generation::cold(2412, false, false)?;
        let owner = Owner::new();
        let mut station = Some(owner.use_awake(true).map_err(|_| "idle ignored count")?);
        request(&owner, &generation).map_err(|_| "idle ignored request")?;
        retire(&owner, &generation, &mut station).map_err(|_| "idle ignored stop")?;
        // Ensure the exact request would change a bit, including RC whose
        // terminal native stop does not itself perform a cold reset.
        let prior = if register == 0x7040 {
            1
        } else if register == 0x704c {
            3
        } else {
            0
        };
        generation
            .model
            .registers
            .borrow_mut()
            .insert(register, prior);
        let mut chip = Chip::new(generation.model.clone());
        chip.ignored = Some(register);
        check!(
            owner.enter(&mut chip).is_err() && owner.status(2).state == State::Failed,
            "ignored source FULL_SLEEP write was accepted"
        );
    }
    Ok(())
}
fn smoke_ar9285_idle_shutdown_actual_readback_and_ignored_request_fail_closed() -> TestResult {
    let _policy = policy();
    verdict(physical_failures)
}
kernel_test_in!(
    "drivers/wireless/ath9k/idle-full-sleep",
    smoke_ar9285_idle_shutdown_actual_readback_and_ignored_request_fail_closed
);

fn revoked_and_blocked() -> Result<(), &'static str> {
    let generation = Generation::cold(2412, false, true)?;
    let owner = Owner::new();
    let mut station = Some(owner.use_awake(true).map_err(|_| "idle revoked count")?);
    request(&owner, &generation).map_err(|_| "idle revoked request")?;
    retire(&owner, &generation, &mut station).map_err(|_| "idle revoked stop")?;
    generation.model.authority.set(false);
    let mut chip = Chip::new(generation.model.clone());
    check!(
        owner.enter(&mut chip) == Err(Error::Hardware(BringUpError::DeviceGone))
            && chip.trace.is_empty(),
        "revoked original authority reached physical idle writes"
    );
    owner.block(true);
    check!(
        owner.set_desired(false) == Err(Error::Removed)
            && owner.use_awake(false).is_err()
            && owner.status(4).state == State::Removed,
        "removed owner or old waiter reopened full-sleep authority"
    );
    let normal = Owner::new();
    let use_guard = normal
        .use_awake(false)
        .map_err(|_| "idle original counted use")?;
    check!(
        !normal.system_block(0),
        "system suspend ignored a live counted control"
    );
    drop(use_guard);
    check!(
        normal.system_block(0) && normal.use_awake(true).is_err(),
        "system suspend did not fence future native users"
    );
    Ok(())
}
fn smoke_ar9285_idle_revocation_removal_and_system_suspend_usecount_barriers() -> TestResult {
    let _policy = policy();
    verdict(revoked_and_blocked)
}
kernel_test_in!(
    "drivers/wireless/ath9k/idle-full-sleep",
    smoke_ar9285_idle_revocation_removal_and_system_suspend_usecount_barriers
);

fn actual_twenty_wake() -> Result<(), &'static str> {
    for width in [
        channel_width::Width::FortyAbove,
        channel_width::Width::FortyBelow,
    ] {
        let old = Generation::wide(width)?;
        let original = {
            old.model
                .ht
                .borrow()
                .clone()
                .ok_or("idle original actual40 source")?
        };
        let geometry = original.geometry();
        let owner = Owner::new();
        let mut station = Some(
            owner
                .use_awake(true)
                .map_err(|_| "idle full40 station count")?,
        );
        let _chip = retire_and_sleep(&owner, &old, &mut station)
            .map_err(|_| "idle full40 physical retirement/SHUTDOWN")?;
        owner
            .set_desired(false)
            .map_err(|_| "idle full40 leaving request")?;
        owner.phase(State::Waking);
        let fresh = Generation::cold(geometry.twenty().control(), true, true)?;
        let next = {
            fresh
                .model
                .ht
                .borrow()
                .clone()
                .ok_or("idle fresh actual20 source")?
        };
        let fresh_synth = { fresh.model.registers.borrow().get(&0x9874).copied() };
        let no_wide_receipt = { fresh.model.wide.borrow().is_none() };
        let old_denied = old.device.enqueue(&[0; 60], Default::default()).is_err();
        check!(
            fresh.identity == old.identity
                && fresh.image == old.image
                && next.geometry() == geometry.twenty()
                && fresh_synth
                    == Some(0x3000_0000 | (u32::from(geometry.control()) * 0x10000 / 15))
                && next.ba_identity().1 != original.ba_identity().1
                && no_wide_receipt
                && old_denied,
            "idle wake reused40 report/center/source/copy or old native generation"
        );
        let _station = owner
            .use_awake(true)
            .map_err(|_| "idle fresh20 counted owner")?;
        owner.phase(State::Operational);
        fresh.activate();
        fresh.join()?;
        let plan = { fresh.peer.lock().plan };
        let lease = narf_net::dhcp::dhcp_acquire(fresh.device.name(), 0)
            .map_err(|_| "idle full40 to actual20 native WPA2/kernel DHCP")?;
        check!(
            plan.matches_lease(&lease) && !old.device.link_up() && !old.model.master.get(),
            "idle actual20 successor lost secure DATA or resurrected full40 predecessor"
        );
    }
    Ok(())
}
fn smoke_ar9285_idle_full40_both_extensions_cold_wake_uses_fresh_primary20_and_wpa2_dhcp(
) -> TestResult {
    let _policy = policy();
    verdict(actual_twenty_wake)
}
kernel_test_in!(
    "drivers/wireless/ath9k/idle-full-sleep",
    smoke_ar9285_idle_full40_both_extensions_cold_wake_uses_fresh_primary20_and_wpa2_dhcp
);

/// The production idle predicate (`idle_wanted`, mac80211
/// `IEEE80211_CONF_IDLE`) and the leave-idle half of `activity`: a pending
/// idle request is cancelled and the use is counted before the request runs.
fn policy_and_activity() -> Result<(), &'static str> {
    let owner = Owner::new();
    let status = owner.status(7);
    check!(
        idle_wanted(true, true, status, 0),
        "unassociated quiet station idles"
    );
    check!(
        !idle_wanted(false, true, status, 0),
        "associated/pending station stays awake"
    );
    check!(
        !idle_wanted(true, false, status, 0),
        "recent scan/connect stays awake"
    );
    {
        let _use = owner.use_awake(false).map_err(|_| "counted use")?;
        check!(
            !idle_wanted(true, true, owner.status(7), 0),
            "in-flight netdev request stays awake"
        );
    }
    check!(
        !idle_wanted(true, true, owner.status(1), 1),
        "a missing station pin is not the expected use count"
    );
    owner.begin_idle(0).map_err(|_| "idle admission")?;
    check!(
        !idle_wanted(true, true, owner.status(7), 0),
        "already-desired idle is not re-entered"
    );
    check!(
        owner.use_awake(false).is_err(),
        "desired idle refuses a plain use"
    );
    owner.set_desired(false).map_err(|_| "leave idle")?;
    check!(
        owner.use_awake(false).is_ok(),
        "activity counts the use after leaving idle"
    );
    Ok(())
}
fn smoke_ath9k_idle_policy_and_activity_leave_idle() -> TestResult {
    verdict(policy_and_activity)
}
kernel_test_in!(
    "drivers/wireless/ath9k/idle",
    smoke_ath9k_idle_policy_and_activity_leave_idle
);

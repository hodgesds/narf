// SPDX-License-Identifier: GPL-2.0-or-later
//! Native full20/40 fixtures. Synthetic offline qualification assets target
//! only these isolated models; actual current hardware generations separately
//! run reset/EEPROM/PHY/PA/NF/ADC/IQ before MAC/Packet/Radio/Device creation.
use super::*;
use crate::ath9k::{
    calibration::{
        self,
        tests::{channel_receipt_image, wide_image, wide_receipt},
    },
    channel_width::{Geometry, Width},
    ht, ht40, mac,
    packet::{self, tests::Model, Packet},
    station::tests::{self as station_tests, Env, Peer, AP, PMK, SSID},
};
use alloc::sync::Weak;
use core::{
    future::Future,
    sync::atomic::AtomicU32,
    task::{Context, Poll, Waker},
};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::udp_ipv4;
use narf_wireless::reg::{self, RegFlags, RegRule, RegulatoryDomain};
type TestDevice = Device<Arc<Model>, WideEnvironment>;
static ACTIVE: IrqSafeSpinLock<Option<Arc<TestDevice>>> = IrqSafeSpinLock::new(None);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain() -> bool {
    let device = ACTIVE.lock().clone();
    device.is_some_and(|device| device.drain())
}
#[derive(Clone, Copy)]
struct Spec {
    geometry: Geometry,
    gi: u8,
    mask: u8,
    protected: bool,
    narrow_response: bool,
    wrong_receipt: bool,
    missing: bool,
    large: bool,
    factory: Option<calibration::tests::factory::Selection>,
    power_save: bool,
    periodic: bool,
    periodic_low_child: bool,
}
struct Nominal {
    image: [u8; crate::ath9k::EEPROM_4K_BYTES],
    identity: crate::ath9k::Identity,
    prepared: crate::ath9k::BasebandPrepared,
    report: calibration::Report,
}
struct Owner {
    spec: Spec,
    current: Mutex<Option<Arc<TestDevice>>>,
    reference: Mutex<Option<Nominal>>,
    generation: AtomicU32,
    physical_calibrations: AtomicU32,
    devices: IrqSafeSpinLock<Vec<Arc<TestDevice>>>,
    models: IrqSafeSpinLock<Vec<Arc<Model>>>,
    peers: IrqSafeSpinLock<Vec<Arc<IrqSafeSpinLock<Peer>>>>,
    clocks: IrqSafeSpinLock<Vec<Arc<Env>>>,
    qualification: IrqSafeSpinLock<Option<Cap<FirmwareBlob, Read>>>,
}
struct WideEnvironment {
    owner: Weak<Owner>,
    generation: u32,
    clock: Arc<Env>,
}
impl Environment for WideEnvironment {
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }
    fn nonce(&self) -> Option<[u8; 32]> {
        self.clock
            .entropy
            .load(Ordering::Acquire)
            .then_some([0x33u8.wrapping_add(self.generation as u8); 32])
    }
    async fn pause(&self) {
        self.clock.pause().await;
    }
    fn wide_qualification(
        &self,
        base: Arc<ht::Grant>,
        geometry: Geometry,
    ) -> Result<Option<Arc<ht40::Grant>>, Error> {
        let owner = self.owner.upgrade().ok_or(Error::State)?;
        if owner.generation.load(Ordering::Acquire) != self.generation {
            return Err(Error::State);
        }
        if owner.spec.missing {
            return Ok(None);
        }
        let reference = owner.reference.try_lock().ok_or(Error::Busy)?;
        let reference = reference.as_ref().ok_or(Error::State)?;
        let facts = ht40::Facts::new(
            ht::tests::model_device(),
            reference.identity,
            reference.prepared,
            reference.report,
            &reference.image,
            base,
            geometry,
        )
        .map_err(|_| Error::Profile)?;
        // An offline isolated model supplies a synthetic fixture asset. This
        // is not the live generation and never proves its actual calibration.
        let oracle = match owner.spec.factory {
            Some(factory) => calibration::tests::wide_receipt_factory(
                geometry,
                40,
                reference.image,
                None,
                factory.swapped,
                factory.xe2,
            ),
            None => wide_receipt(geometry, 40, reference.image, None),
        }
        .map_err(|_| Error::State)?;
        let mut bytes = record(&facts, oracle.report, owner.spec.mask, owner.spec.gi);
        if owner.spec.wrong_receipt {
            bytes[64] ^= 1;
        }
        let cap = Cap::<FirmwareBlob, Read>::bootstrap();
        let grant = match (ht40::Source::Verified {
            bytes,
            signer: Some([0x85; 32]),
            cap,
        })
        .load(facts)
        {
            Ok(grant) => grant,
            Err(_) => return Ok(None),
        };
        *owner.qualification.lock() = Some(cap);
        Ok(Some(grant))
    }
    fn retune(&self, frequency: u16) -> Option<crate::ath9k::channels::Transition> {
        self.retune_geometry(Geometry::from_frequency(frequency).ok()?, None)
    }
    fn retune_geometry(
        &self,
        geometry: Geometry,
        grant: Option<Arc<ht40::Grant>>,
    ) -> Option<crate::ath9k::channels::Transition> {
        let owner = self.owner.upgrade()?;
        let expected = self.generation;
        Some(Box::pin(async move {
            if owner.generation.load(Ordering::Acquire) != expected {
                return Err(Error::State);
            }
            let old = owner.device();
            old.retire_host();
            if !old.radio.lock().await.retire() {
                return Err(Error::Transport(packet::Error::Timeout));
            }
            old.rings.state.lock().await.clear();
            let next = match grant {
                Some(grant) => match owner.prepare_wide(grant) {
                    Ok(device) => device,
                    Err(_) => owner.prepare_twenty(geometry.control())?,
                },
                None => owner.prepare_twenty(geometry.control())?,
            };
            *owner.current.lock().await = Some(next.clone());
            Ok(next as crate::ath9k::channels::Successor)
        }))
    }
}
impl Owner {
    fn new(spec: Spec) -> Arc<Self> {
        assert!(ACTIVE.lock().is_none());
        let owner = Arc::new(Self {
            spec,
            current: Mutex::new(None),
            reference: Mutex::new(None),
            generation: AtomicU32::new(0),
            physical_calibrations: AtomicU32::new(0),
            devices: IrqSafeSpinLock::new(Vec::new()),
            models: IrqSafeSpinLock::new(Vec::new()),
            peers: IrqSafeSpinLock::new(Vec::new()),
            clocks: IrqSafeSpinLock::new(Vec::new()),
            qualification: IrqSafeSpinLock::new(None),
        });
        let device = owner.prepare_twenty(spec.geometry.control()).unwrap();
        *owner.current.try_lock().unwrap() = Some(device);
        owner
    }
    fn device(&self) -> Arc<TestDevice> {
        self.current.try_lock().unwrap().as_ref().unwrap().clone()
    }
    fn model(&self) -> Arc<Model> {
        self.models.lock().last().unwrap().clone()
    }
    fn peer(&self) -> Arc<IrqSafeSpinLock<Peer>> {
        self.peers.lock().last().unwrap().clone()
    }
    fn prepare_twenty(self: &Arc<Self>, frequency: u16) -> Result<Arc<TestDevice>, Error> {
        self.physical_calibrations.fetch_add(1, Ordering::AcqRel);
        let receipt = match self.spec.factory {
            Some(factory) => calibration::tests::channel_receipt_factory(
                frequency,
                40,
                calibration::tests::factory::image(factory),
                factory.swapped,
                factory.xe2,
            ),
            None => channel_receipt_image(frequency, 40, wide_image()),
        }
        .map_err(|_| Error::State)?;
        let model = Model::new();
        model.frequency.set(receipt.report.frequency_mhz);
        model.channels.set(0x1fff);
        *model.registers.borrow_mut() = receipt.registers;
        mac::prepare(&model, &receipt.image, receipt.identity.mac)?;
        let facts = ht::Facts::new(
            ht::tests::model_device(),
            receipt.identity,
            receipt.prepared,
            receipt.report,
            &receipt.image,
        )
        .map_err(|_| Error::State)?;
        let grant = ht::Source::Verified {
            bytes: ht::tests::record(&facts, self.spec.mask),
            signer: Some([0x85; 32]),
            cap: Cap::<FirmwareBlob, Read>::bootstrap(),
        }
        .load(facts)?;
        grant.readback(&model)?;
        *model.ht.borrow_mut() = Some(grant);
        *self.reference.try_lock().ok_or(Error::Busy)? = Some(Nominal {
            image: receipt.image,
            identity: receipt.identity,
            prepared: receipt.prepared,
            report: receipt.report,
        });
        self.finish(model, receipt.identity.mac, receipt.report.noise_dbm, false)
    }
    fn prepare_wide(self: &Arc<Self>, grant: Arc<ht40::Grant>) -> Result<Arc<TestDevice>, Error> {
        grant.check()?;
        self.physical_calibrations.fetch_add(1, Ordering::AcqRel);
        let receipt = match self.spec.factory {
            Some(factory) => calibration::tests::wide_receipt_factory(
                grant.geometry(),
                40,
                calibration::tests::factory::image(factory),
                None,
                factory.swapped,
                factory.xe2,
            ),
            None => wide_receipt(grant.geometry(), 40, wide_image(), None),
        }
        .map_err(|_| Error::State)?;
        grant.accept(receipt.report)?;
        let model = Model::new();
        model.frequency.set(receipt.report.report.frequency_mhz);
        model.channels.set(0x1fff);
        *model.wide.borrow_mut() = Some(receipt.report);
        *model.registers.borrow_mut() = receipt.registers;
        mac::prepare(&model, &receipt.image, receipt.identity.mac)?;
        let wrapped = ht::Grant::from_wide(grant, receipt.report)?;
        wrapped.readback(&model)?;
        *model.ht.borrow_mut() = Some(wrapped);
        crate::ath9k::rx_ba::tests::qualify(&model, 64);
        if self.spec.large {
            crate::ath9k::tx_ba::large_tests::qualify(&model, 8, 65535, 64);
        } else {
            crate::ath9k::tx_ba::tests::qualify(&model, 64);
        }
        crate::ath9k::qos::tests::qualify(&model);
        if self.spec.power_save {
            crate::ath9k::ps::tests::qualify(&model);
        }
        self.finish(
            model,
            receipt.identity.mac,
            receipt.report.report.noise_dbm,
            true,
        )
    }
    fn finish(
        self: &Arc<Self>,
        model: Arc<Model>,
        local: [u8; 6],
        noise: i16,
        wide: bool,
    ) -> Result<Arc<TestDevice>, Error> {
        if self.spec.periodic {
            if wide && self.spec.periodic_low_child {
                let base = { model.ht.borrow().clone().ok_or(Error::State)? };
                let mut bytes = crate::ath9k::tx_ba::large_tests::record(&base, 8, 65535, 64);
                bytes[62..64].copy_from_slice(&24i16.to_le_bytes());
                let source = crate::ath9k::tx_ba::Source::Verified {
                    bytes,
                    signer: Some([0x85; 32]),
                    cap: Cap::bootstrap(),
                }
                .load(base)?;
                *model.tx_ba.borrow_mut() = Some(source);
            }
            crate::ath9k::periodic::tests::qualify_peak(
                &model,
                if self.spec.periodic_low_child { 30 } else { 18 },
            );
        }
        let peer = Arc::new(IrqSafeSpinLock::new(Peer::new_channel(
            self.spec.protected,
            None,
            self.spec.geometry.primary(),
        )));
        let mut offer = elements(self.spec.geometry, self.spec.gi != 0);
        if self.spec.large {
            offer[4] = (offer[4] & 3) | 28;
        } //16us density.
        peer.lock().ht = Some(offer);
        peer.lock().qos_tids = true;
        peer.lock().ps_test = self.spec.power_save;
        if wide {
            peer.lock().expected_ht_cap = [14 | if self.spec.gi & 2 != 0 { 64 } else { 0 }, 1];
        }
        if self.spec.narrow_response {
            peer.lock().ht_response = Some(elements(self.spec.geometry.twenty(), false));
        }
        let reacting = peer.clone();
        *model.reaction.borrow_mut() = Some(Arc::new(move |bytes| {
            reacting
                .lock()
                .react(bytes)
                .map_err(|_| packet::Error::Packet)
        }));
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let clock = Arc::new(Env {
            now: AtomicU64::new(0),
            entropy: AtomicBool::new(true),
        });
        // SAFETY: the actual same isolated model reset/PHY/calibration/MAC
        // chain completed above, before its first real DMA allocation/start.
        let packet = unsafe { Packet::prepare(model.clone(), local) }?;
        let mut radio = Radio::new(
            packet,
            local,
            noise,
            WideEnvironment {
                owner: Arc::downgrade(self),
                generation,
                clock: clock.clone(),
            },
        );
        radio.start()?;
        model.inject(&peer.lock().beacon(), 0)?;
        radio.poll()?;
        let name = narf_net::iface::reserve_name("ar9-wide%d");
        let device = Arc::new(Device::new(name, Arc::new(Mutex::new(radio)))?);
        device.admit_for_test();
        narf_net::iface::register(name, local, send);
        narf_net::iface::set_link_state(name, true);
        device.link(None);
        *ACTIVE.lock() = Some(device.clone());
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        self.models.lock().push(model);
        self.peers.lock().push(peer);
        self.clocks.lock().push(clock);
        self.devices.lock().push(device.clone());
        Ok(device)
    }
    fn join(&self) -> Result<(), WirelessError> {
        let device = self.device();
        station_tests::complete(device.scan(scan(self.spec.geometry.control())))?;
        station_tests::complete(device.associate(AssociateRequest {
            bssid: AP,
            ssid: SSID.to_vec(),
            frequency_mhz: u32::from(self.spec.geometry.control()),
            channel: u32::from(self.spec.geometry.primary()),
            security: if self.spec.protected {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        }))
    }
    fn pump(&self) {
        for _ in 0..24 {
            self.device().drain();
        }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        *ACTIVE.lock() = None;
        let devices = self.devices.lock().clone();
        for device in devices {
            device.retire_host();
            if let Some(mut radio) = device.radio.try_lock() {
                radio.retire();
            }
        }
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
    }
}
fn policy() -> ht::tests::Policy {
    let saved = ht::tests::Policy::install();
    reg::db::set_domain(RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2482,
            max_bandwidth_mhz: 40,
            max_power_dbm: 20,
            flags: RegFlags::empty(),
        }],
    });
    saved
}
fn scan(frequency: u16) -> ScanRequest {
    ScanRequest {
        ssids: vec![SSID.to_vec()],
        frequencies_mhz: vec![u32::from(frequency)],
        channels: vec![u32::from((frequency - 2407) / 5)],
        active: true,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: Some(20),
        duration_mandatory: false,
        extra_ies: Vec::new(),
    }
}
fn elements(geometry: Geometry, sgi: bool) -> Vec<u8> {
    let mut elements = ht::tests::elements();
    elements[30] = geometry.primary();
    if geometry.is_wide() {
        elements[2] |= 2 | if sgi { 64 } else { 0 };
        elements[31] = 4 | geometry.body()[3];
    }
    elements
}
fn record(facts: &ht40::Facts, actual: calibration::wide::WideReport, mask: u8, gi: u8) -> Vec<u8> {
    let request = facts.request();
    let mut bytes = vec![0; 384];
    bytes[..8].copy_from_slice(&[b'N', b'8', b'5', b'H', 3, 0, 0, 1]);
    bytes[8..12].copy_from_slice(&384u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&[0x8c, 0x16, 0x2b, 0]);
    bytes[16..48].copy_from_slice(&request.identity);
    bytes[48..54].copy_from_slice(&request.mac);
    bytes[54..58].copy_from_slice(&actual.geometry.body());
    bytes[58..60].copy_from_slice(&4i16.to_le_bytes());
    bytes[60..62].copy_from_slice(&40i16.to_le_bytes());
    bytes[62] = mask;
    bytes[63] = gi;
    bytes[64..96].copy_from_slice(&actual.digest());
    bytes[96..128].copy_from_slice(&facts.base_digest());
    for index in 0..64 {
        if (56..59).contains(&index) || gi & 1 == 0 && (48..56).contains(&index) {
            continue;
        }
        bytes[256 + index * 2..258 + index * 2].copy_from_slice(&20i16.to_le_bytes());
    }
    bytes
}
fn spec(width: Width, gi: u8, protected: bool) -> Spec {
    Spec {
        geometry: Geometry::new(6, width).unwrap(),
        gi,
        mask: 255,
        protected,
        narrow_response: false,
        wrong_receipt: false,
        missing: false,
        large: false,
        factory: None,
        power_save: false,
        periodic: false,
        periodic_low_child: false,
    }
}
fn network(owner: &Owner) -> Result<(), &'static str> {
    let device = owner.device();
    let peer = owner.peer();
    let (plan, previous_dora) = {
        let peer = peer.lock();
        let seen = peer.server.observations();
        (peer.plan, (seen.discovers, seen.requests))
    };
    let lease =
        narf_net::dhcp::dhcp_acquire(device.name(), 0).map_err(|_| "wide native kernel DHCP")?;
    let observed = {
        let peer = peer.lock();
        let seen = peer.server.observations();
        (seen.discovers, seen.requests)
    };
    if !plan.matches_lease(&lease) || observed != (previous_dora.0 + 1, previous_dora.1 + 1) {
        return Err("wide real native DORA receipts");
    }
    let bytes = udp_ipv4(
        AP,
        plan.station,
        plan.lease_ip,
        plan.server_ip,
        4801,
        4802,
        b"actual wide native IP",
    );
    let before_uplink = { peer.lock().uplink.len() };
    narf_net::iface::send_on(device.name(), &bytes).map_err(|_| "wide netdev enqueue")?;
    let mut uplink_done = false;
    for _ in 0..24 {
        device.drain();
        let original = {
            let peer = peer.lock();
            peer.uplink.len() > before_uplink && peer.uplink.last() == Some(&bytes)
        };
        let native_done = { device.radio.try_lock().is_some_and(|radio| radio.ready()) };
        if original && native_done {
            uplink_done = true;
            break;
        }
    }
    if !uplink_done || peer.lock().uplink.last() != Some(&bytes) {
        return Err("wide exact native DMA uplink");
    }
    let down = udp_ipv4(
        plan.station,
        AP,
        plan.server_ip,
        plan.lease_ip,
        4802,
        4801,
        b"actual wide native downlink",
    );
    let wire = peer.lock().downlink(&down)?;
    let model = owner.model();
    let wide = device
        .channel_geometry()
        .ok_or("wide physical geometry missing")?
        .is_wide();
    model.rx_flags.set(if wide {
        if owner.spec.gi & 2 != 0 {
            3
        } else {
            2
        }
    } else {
        0
    });
    let previous = model.last_rx.get().ok_or("wide prior RX DMA tail")?;
    model.inject(&wire, 0).map_err(|_| "wide RX DMA")?;
    let mut received = false;
    for _ in 0..24 {
        device.drain();
        if model.word(previous + 48).is_ok_and(|word| word & 1 == 0) {
            received = true;
            break;
        }
    }
    if !received {
        return Err("wide RX lacks actual prior-tail rearm");
    }
    let mut ring = device.rx_ring().lock();
    let ring = ring.as_mut().ok_or("wide RX ring absent")?;
    let mut found = false;
    while let Ok(Some(frame)) = ring.try_recv() {
        found |= frame.payload() == down;
    }
    if !found {
        return Err("wide exact original downlink/Narf-Ring");
    }
    Ok(())
}
fn smoke_ar9285_ht40_sgi40_both_extensions_native_open_wpa2_dhcp_ip() -> TestResult {
    let _policy = policy();
    for width in [Width::FortyAbove, Width::FortyBelow] {
        for gi in [0, 3] {
            for protected in [false, true] {
                let owner = Owner::new(spec(width, gi, protected));
                if owner.join().is_err()
                    || owner.device().channel_geometry() != Some(owner.spec.geometry)
                {
                    return TestResult::Fail("qualified actual40 native association");
                }
                if let Err(error) = network(&owner) {
                    return TestResult::Fail(error);
                }
                let model = owner.model();
                let descriptor = model.registers.borrow()[&0x800];
                let flags = model.word(descriptor + 36).unwrap();
                let original = owner.models.lock()[0].clone();
                if flags & 3 != 1 | (u32::from(gi & 1 != 0) << 1)
                    || model.registers.borrow()[&0x8318] != 1
                    || model.registers.borrow()[&0x9874] & 0x3fff_ffff
                        != (0x3000_0000 | (u32::from(owner.spec.geometry.center()) * 0x10000 / 15))
                    || original.released.borrow().is_empty()
                    || original.master.get()
                {
                    return TestResult::Fail("actual native40 series/geometry/retirement bits");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht40",
    smoke_ar9285_ht40_sgi40_both_extensions_native_open_wpa2_dhcp_ip
);
fn smoke_ar9285_ht40_real20_peer_fallback_before_m2_and_fresh_dhcp() -> TestResult {
    let _policy = policy();
    for protected in [false, true] {
        let mut selected = spec(Width::FortyAbove, 3, protected);
        selected.narrow_response = true;
        let owner = Owner::new(selected);
        if owner.join().is_err()
            || owner.device().channel_geometry() != Some(selected.geometry.twenty())
            || owner.physical_calibrations.load(Ordering::Acquire) != 3
            || owner.models.lock().len() != 3
        {
            return TestResult::Fail("peer20 response did not cause real fresh20 fallback");
        }
        let wide = owner.models.lock()[1].clone();
        let old_peer = owner.peers.lock()[1].clone();
        if wide
            .transmitted
            .borrow()
            .iter()
            .any(|frame| frame.first() == Some(&0x88))
            || old_peer.lock().ptk.is_some()
            || wide.master.get()
            || wide.released.borrow().is_empty()
        {
            return TestResult::Fail("wide peer downgrade crossed M2/DATA or lacked old DMA proof");
        }
        if let Err(error) = network(&owner) {
            return TestResult::Fail(error);
        }
        let model = owner.model();
        let descriptor = model.registers.borrow()[&0x800];
        if model.word(descriptor + 36).unwrap() & 3 != 0
            || model.registers.borrow()[&0x8318] != 0
            || model.registers.borrow()[&0x9804] & 0x7ff != 0x3c0
        {
            return TestResult::Fail("forced20 used host metadata without actual20 hardware");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht40",
    smoke_ar9285_ht40_real20_peer_fallback_before_m2_and_fresh_dhcp
);
fn smoke_ar9285_ht40_expected_receipt_unknown_record_and_ignored_writes_fail_closed() -> TestResult
{
    let _policy = policy();
    let geometry = Geometry::new(6, Width::FortyAbove).unwrap();
    for ignored in [0x9874, 0x8318, 0xa3cc, 0xa3d0, 0xa3d4, 0x99b4] {
        if wide_receipt(geometry, 40, wide_image(), Some(ignored)).is_ok() {
            return TestResult::Fail("ignored real40 source programming produced a receipt");
        }
    }
    {
        let owner = Owner::new(spec(Width::FortyAbove, 3, true));
        let model = owner.model();
        let base = model.ht.borrow().clone().unwrap();
        let reference = owner.reference.try_lock().unwrap();
        let reference = reference.as_ref().unwrap();
        let facts = ht40::Facts::new(
            ht::tests::model_device(),
            reference.identity,
            reference.prepared,
            reference.report,
            &reference.image,
            base,
            geometry,
        )
        .unwrap();
        let oracle = wide_receipt(geometry, 40, reference.image, None).unwrap();
        if oracle.prepared.geometry != geometry
            || oracle.prepared.reference_frequency != geometry.control()
        {
            return TestResult::Fail(
                "wide calibration preparation lost actual primary/center identity",
            );
        }
        let bytes = record(&facts, oracle.report, 255, 3);
        for at in [0, 4, 6, 8, 12, 16, 48, 54, 55, 56, 57, 62, 63, 96, 128, 256] {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            if at == 62 {
                bad[at] = 0;
            }
            if at == 63 {
                bad[at] = 4;
            }
            if at == 256 {
                bad[at..at + 2].copy_from_slice(&i16::MAX.to_le_bytes());
            }
            if (ht40::Source::Verified {
                bytes: bad,
                signer: Some([0x85; 32]),
                cap: Cap::bootstrap(),
            })
            .load(facts.clone())
            .is_ok()
            {
                return TestResult::Fail("unknown/foreign/v1/v2 full40 qualification accepted");
            }
        }
        if (ht40::Source::Verified {
            bytes,
            signer: None,
            cap: Cap::bootstrap(),
        })
        .load(facts)
        .is_ok()
        {
            return TestResult::Fail("unsigned full40 program accepted");
        }
    }
    {
        let mut selected = spec(Width::FortyAbove, 3, true);
        selected.missing = true;
        let owner = Owner::new(selected);
        if owner.join().is_ok()
            || owner.physical_calibrations.load(Ordering::Acquire) != 1
            || owner.models.lock().len() != 1
        {
            return TestResult::Fail("missing H3 emitted40 or replaced narrow behavior");
        }
    }
    let mut selected = spec(Width::FortyAbove, 3, true);
    selected.wrong_receipt = true;
    let owner = Owner::new(selected);
    if owner.join().is_err()
        || owner.device().channel_geometry() != Some(selected.geometry.twenty())
        || owner.physical_calibrations.load(Ordering::Acquire) != 3
        || owner.models.lock().len() != 2
    {
        return TestResult::Fail(
            "wrong external expected40 receipt published40 instead of actual20 fallback",
        );
    }
    if let Err(error) = network(&owner) {
        return TestResult::Fail(error);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht40",
    smoke_ar9285_ht40_expected_receipt_unknown_record_and_ignored_writes_fail_closed
);
fn smoke_ar9285_ht40_full_span_extension_policy_and_primary_factory_center_plans() -> TestResult {
    let _policy = policy();
    let image = wide_image();
    let plus = Geometry::new(6, Width::FortyAbove).unwrap();
    let minus = Geometry::new(6, Width::FortyBelow).unwrap();
    let a = crate::ath9k::phy::rates::wide::wide_plan(&image, plus, 40).unwrap();
    let b = crate::ath9k::phy::rates::wide::wide_plan(&image, minus, 40).unwrap();
    // Independently decoded source fixture: world-SKU minima are primary
    // CCK15/OFDM17/HT2019; center2447 HT40 is[19,20,21..], center2427
    // is CTL16; extension2457 is CCK35/OFDM36, extension2417 is12/14.
    let common = [
        (0x9934, 0x1b1b1b1b),
        (0x9938, 0x1b1b1b1b),
        (0xa234, 0x19191b19),
        (0xa238, 0x19191919),
        (0xa38c, 0x1d1d1d1d),
        (0xa390, 0x1d1d1d1d),
    ];
    if a.registers[..6] != common
        || b.registers[..6] != common
        || a.registers[6..]
            != [
                (0xa3cc, 0x2121201f),
                (0xa3d0, 0x21212121),
                (0xa3d4, 0x2e2d1d1d),
                (0x993c, 63),
            ]
        || b.registers[6..]
            != [
                (0xa3cc, 0x1c1c1c1c),
                (0xa3d0, 0x1c1c1c1c),
                (0xa3d4, 0x18161a1a),
                (0x993c, 63),
            ]
    {
        return TestResult::Fail(
            "complete primary/extension/center factory/CTL/increment source fixture",
        );
    }
    let actual = wide_receipt(plus, 40, image, None).unwrap();
    if a.registers
        .iter()
        .any(|(register, value)| actual.registers.get(register) != Some(value))
    {
        return TestResult::Fail("actual fresh40 calibration changed source power program");
    }
    if a.registers[..6] != b.registers[..6]
        || a.registers[6..9] == b.registers[6..9]
        || a.geometry.control() != b.geometry.control()
        || a.geometry.center() == b.geometry.center()
    {
        return TestResult::Fail(
            "primary target power was substituted by RF center or extension/HT40 CTL was ignored",
        );
    }
    let owner = Owner::new(spec(Width::FortyAbove, 3, true));
    let original = owner.device();
    station_tests::complete(original.scan(scan(plus.control()))).unwrap();
    let mut domain = reg::db::get_domain().unwrap();
    domain.rules.push(RegRule {
        freq_start_mhz: 2466,
        freq_end_mhz: 2468,
        max_bandwidth_mhz: 40,
        max_power_dbm: 10,
        flags: RegFlags::NO_IR,
    });
    reg::db::set_domain(domain);
    if original
        .radio
        .try_lock()
        .unwrap()
        .preferred_width(AP)
        .unwrap()
        .is_some()
        || owner.physical_calibrations.load(Ordering::Acquire) != 1
    {
        return TestResult::Fail("extension-edge host rule reached40 calibration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht40",
    smoke_ar9285_ht40_full_span_extension_policy_and_primary_factory_center_plans
);
fn smoke_ar9285_ht40_all_mcs_native_timing_and_current_copy_epoch() -> TestResult {
    let _policy = policy();
    for mcs in 0..8 {
        for gi in [0, 3] {
            let mut selected = spec(Width::FortyAbove, gi, true);
            selected.mask = 1 << mcs;
            let owner = Owner::new(selected);
            if owner.join().is_err() {
                return TestResult::Fail("single-MCS qualified native40 join");
            }
            let device = owner.device();
            let peer = owner.peer();
            let plan = peer.lock().plan;
            let bytes = udp_ipv4(
                AP,
                plan.station,
                plan.lease_ip,
                plan.server_ip,
                4811,
                4812,
                b"full40 MCS duration",
            );
            if device.enqueue(&bytes, narf_net::TxMeta::default()).is_err() {
                return TestResult::Fail("full40 queued DATA");
            }
            owner.pump();
            let model = owner.model();
            let descriptor = model.registers.borrow()[&0x800];
            let sent = model
                .transmitted
                .borrow()
                .iter()
                .rev()
                .find(|frame| frame.first() == Some(&0x88))
                .unwrap()
                .len();
            let symbols =
                ((sent as u32 + 4) * 8 + 22).div_ceil([54, 108, 162, 216, 324, 432, 486, 540][mcs]);
            let duration = 36
                + if gi != 0 {
                    (symbols * 18).div_ceil(5)
                } else {
                    symbols * 4
                };
            if model.word(descriptor + 24).unwrap() & 0x7fff != duration
                || model.word(descriptor + 20).unwrap() & 255 != 0x80 + mcs as u32
            {
                return TestResult::Fail(
                    "native40 descriptor duration/GI/MCS differs from source formula",
                );
            }
            if !device.radio.try_lock().unwrap().can_aggregate() {
                return TestResult::Fail("wide sender BA did not negotiate actual air receipts");
            }
            let pair_a = udp_ipv4(
                AP,
                plan.station,
                plan.lease_ip,
                plan.server_ip,
                4811,
                4812,
                b"wide pair first",
            );
            let pair_b = udp_ipv4(
                AP,
                plan.station,
                plan.lease_ip,
                plan.server_ip,
                4811,
                4812,
                b"wide pair second",
            );
            if device
                .enqueue(&pair_a, narf_net::TxMeta::default())
                .is_err()
                || device
                    .enqueue(&pair_b, narf_net::TxMeta::default())
                    .is_err()
            {
                return TestResult::Fail("wide native two-frame queue");
            }
            owner.pump();
            let Some((head, tail)) = model.last_pair.get() else {
                return TestResult::Fail("wide actual linked two-map aggregate missing");
            };
            let air = model.word(head + 32).unwrap() & 0xffff;
            let symbols = (air * 8 + 22).div_ceil([54, 108, 162, 216, 324, 432, 486, 540][mcs]);
            let duration = 36
                + if gi != 0 {
                    (symbols * 18).div_ceil(5)
                } else {
                    symbols * 4
                };
            if model.word(head + 24).unwrap() & 0x7fff != duration
                || model.word(head + 36).unwrap() & 3 != if gi != 0 { 3 } else { 1 }
                || model.word(head).unwrap() != tail
                || model.word(tail).unwrap() != 0
            {
                return TestResult::Fail("wide aggregate duration/GI/native NULL tail");
            }
            let cap = owner.qualification.lock().unwrap();
            *device.receive_hook.lock() = Some(Arc::new(move |point| {
                if point == ReceivePoint::AfterFrameAllocation {
                    cap.revoke();
                }
            }));
            let down = udp_ipv4(
                plan.station,
                AP,
                plan.server_ip,
                plan.lease_ip,
                4812,
                4811,
                b"revoked40 copied packet",
            );
            let wire = peer.lock().downlink(&down).unwrap();
            model.rx_flags.set(if gi != 0 { 3 } else { 2 });
            model.inject(&wire, 0).unwrap();
            owner.pump();
            let no_rx = {
                let mut rx = device.rx_ring().lock();
                matches!(rx.as_mut().unwrap().try_recv(), Ok(None))
            };
            if !no_rx || device.link_up() || !device.closed.load(Ordering::Acquire) {
                return TestResult::Fail("revoked H3 crossed copied native publication");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht40",
    smoke_ar9285_ht40_all_mcs_native_timing_and_current_copy_epoch
);
fn smoke_ar9285_ht40_rx_gi_direction_cancel_and_signed_child_versions() -> TestResult {
    let _policy = policy();
    for gi in [0, 1, 2, 3] {
        let owner = Owner::new(spec(Width::FortyBelow, gi, true));
        if owner.join().is_err() {
            return TestResult::Fail("directional GI40 native join");
        }
        let device = owner.device();
        let model = owner.model();
        let peer = owner.peer();
        let plan = peer.lock().plan;
        let base = model.ht.borrow().clone().unwrap();
        if base.version() != 3
            || !crate::ath9k::rx_ba::request(&base).filename.contains("v3")
            || !crate::ath9k::tx_ba::request(&base).filename.contains("v3")
            || !crate::ath9k::qos::request(&base).filename.contains("v3")
        {
            return TestResult::Fail("wide owner reused narrow child qualification");
        }
        let down = udp_ipv4(
            plan.station,
            AP,
            plan.server_ip,
            plan.lease_ip,
            4822,
            4821,
            b"RX GI direction",
        );
        for flags in [1u32, 2, 3] {
            let wire = peer.lock().downlink(&down).unwrap();
            model.rx_flags.set(flags);
            model.inject(&wire, 0).unwrap();
            owner.pump();
            let accepted = {
                let mut rx = device.rx_ring().lock();
                matches!(rx.as_mut().unwrap().try_recv(), Ok(Some(_)))
            };
            if accepted != (flags == 2 || flags == 3 && gi & 2 != 0) {
                return TestResult::Fail(
                    "native RX accepted SGI20/unqualified SGI40 or dropped valid width",
                );
            }
        }
    }
    let owner = Owner::new(spec(Width::FortyAbove, 3, true));
    let original = owner.device();
    station_tests::complete(original.scan(scan(owner.spec.geometry.control()))).unwrap();
    let mut future = Box::pin(original.associate(AssociateRequest {
        bssid: AP,
        ssid: SSID.to_vec(),
        frequency_mhz: 2437,
        channel: 6,
        security: SecurityConfig::Wpa2 { psk: PMK },
        ie: Vec::new(),
    }));
    let mut cx = Context::from_waker(Waker::noop());
    if future.as_mut().poll(&mut cx) != Poll::Pending {
        return TestResult::Fail("wide cancellation fixture had no actual async scan wait");
    }
    drop(future);
    let successor = owner.device();
    successor.drain();
    if !original.closed.load(Ordering::Acquire)
        || successor.link_up()
        || !successor.closed.load(Ordering::Acquire)
        || owner.peer().lock().ptk.is_some()
    {
        return TestResult::Fail("cancelled wide join published a key/data port");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht40",
    smoke_ar9285_ht40_rx_gi_direction_cancel_and_signed_child_versions
);

#[path = "interface_aggregate_wide_tests.rs"]
mod aggregate_tests;

#[path = "interface_factory_tests.rs"]
mod factory_tests;

#[path = "interface_ps_wide_tests.rs"]
mod ps_tests;

#[path = "interface_periodic_wide_tests.rs"]
mod periodic_tests;

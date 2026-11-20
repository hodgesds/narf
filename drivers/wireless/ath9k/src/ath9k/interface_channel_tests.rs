// SPDX-License-Identifier: GPL-2.0-or-later
//! Native Device/Radio/Packet generations, real DMA and reactive Open/WPA2
//! peers. Every new model channel runs the production cold reset, EEPROM read,
//! INI/modal/detector/CTL and analog calibration before MAC/ring preparation.
//! Synthetic signed records are model inputs, never physical RF evidence.
use super::*;
use crate::ath9k::{
    calibration::{self, tests::channel_receipt},
    ht, mac,
    packet::{self, tests::Model, Packet},
    station::tests::{self as station_tests, Env, Peer, AP, PMK, SSID},
};
use alloc::sync::Weak;
use core::sync::atomic::AtomicU32;
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::udp_ipv4;
use narf_wireless::reg::{self, RegFlags, RegRule, RegulatoryDomain};
type TestDevice = Device<Arc<Model>, ChannelEnvironment>;
struct ChannelEnvironment {
    owner: Weak<Owner>,
    generation: u32,
    clock: Arc<Env>,
}
impl Environment for ChannelEnvironment {
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }
    fn nonce(&self) -> Option<[u8; 32]> {
        self.clock.nonce()
    }
    async fn pause(&self) {
        self.clock.pause().await;
    }
    fn retune(&self, frequency: u16) -> Option<super::super::channels::Transition> {
        let owner = self.owner.upgrade()?;
        let expected = self.generation;
        Some(Box::pin(async move {
            if owner.generation.load(Ordering::Acquire) != expected {
                return Err(Error::State);
            }
            let old = owner.current.lock().await.clone().ok_or(Error::State)?;
            old.close();
            if !old.radio.lock().await.retire() {
                return Err(Error::Transport(packet::Error::Timeout));
            }
            old.rings.state.lock().await.clear();
            // No new source/hardware preparation precedes the actual old DMA
            // proof. A wedged TX/RX engine leaves this sole owner terminal.
            let next = owner.prepare(frequency)?;
            *owner.current.lock().await = Some(next.clone());
            Ok(next as super::super::channels::Successor)
        }))
    }
}
struct Owner {
    current: Mutex<Option<Arc<TestDevice>>>,
    generation: AtomicU32,
    models: IrqSafeSpinLock<Vec<Arc<Model>>>,
    peers: IrqSafeSpinLock<Vec<Arc<IrqSafeSpinLock<Peer>>>>,
    protected: bool,
    qualified: bool,
}
impl Owner {
    fn new(protected: bool, qualified: bool) -> Arc<Self> {
        let owner = Arc::new(Self {
            current: Mutex::new(None),
            generation: AtomicU32::new(0),
            models: IrqSafeSpinLock::new(Vec::new()),
            peers: IrqSafeSpinLock::new(Vec::new()),
            protected,
            qualified,
        });
        let device = owner.prepare(2412).unwrap();
        *owner.current.try_lock().unwrap() = Some(device);
        owner
    }
    fn device(&self) -> Arc<TestDevice> {
        self.current.try_lock().unwrap().clone().unwrap()
    }
    fn model(&self) -> Arc<Model> {
        self.models.lock().last().unwrap().clone()
    }
    fn peer(&self) -> Arc<IrqSafeSpinLock<Peer>> {
        self.peers.lock().last().unwrap().clone()
    }
    fn prepare(self: &Arc<Self>, frequency: u16) -> Result<Arc<TestDevice>, Error> {
        let receipt = channel_receipt(frequency, 40).map_err(|_| Error::State)?;
        let channel = ((frequency - 2407) / 5) as u8;
        let model = Model::new();
        model.frequency.set(receipt.report.frequency_mhz);
        let mut channels = 0;
        for channel in 1..=13 {
            if super::super::phy::rates::checked_plan_at(&receipt.image, 2407 + 5 * channel, 40)
                .is_ok()
            {
                channels |= 1 << (channel - 1);
            }
        }
        model.channels.set(channels);
        *model.registers.borrow_mut() = receipt.registers;
        mac::prepare(&model, &receipt.image, receipt.identity.mac)?;
        if self.qualified {
            let facts = ht::Facts::new(
                ht::tests::model_device(),
                receipt.identity,
                receipt.prepared,
                receipt.report,
                &receipt.image,
            )
            .map_err(|_| Error::State)?;
            let bytes = ht::tests::record(&facts, 255);
            let grant = ht::Source::Verified {
                bytes,
                signer: Some([0x85; 32]),
                cap: Cap::<FirmwareBlob, Read>::bootstrap(),
            }
            .load(facts)?;
            grant.readback(&model)?;
            *model.ht.borrow_mut() = Some(grant);
            crate::ath9k::rx_ba::tests::qualify(&model, 64);
            crate::ath9k::tx_ba::tests::qualify(&model, 64);
            crate::ath9k::qos::tests::qualify(&model);
        }
        let peer = Arc::new(IrqSafeSpinLock::new(Peer::new_channel(
            self.protected,
            None,
            channel,
        )));
        if self.qualified {
            let mut elements = ht::tests::elements();
            elements[30] = channel; // Actual HT Operation primary field.
            peer.lock().ht = Some(elements);
            peer.lock().qos_tids = true;
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
        // SAFETY: the same model state was fully reset, actually calibrated
        // and MAC/key-cache prepared above. No inherited or live DMA exists.
        let packet = unsafe { Packet::prepare(model.clone(), receipt.identity.mac) }?;
        let mut radio = Radio::new(
            packet,
            receipt.identity.mac,
            receipt.report.noise_dbm,
            ChannelEnvironment {
                owner: Arc::downgrade(self),
                generation,
                clock,
            },
        );
        radio.start()?;
        model.inject(&peer.lock().beacon(), 0)?;
        radio.poll()?;
        let device = Arc::new(Device::new(
            narf_net::iface::reserve_name("ar9-channel%d"),
            Arc::new(Mutex::new(radio)),
        )?);
        device.admit_for_test();
        self.models.lock().push(model);
        self.peers.lock().push(peer);
        Ok(device)
    }
}
fn policy() -> ht::tests::Policy {
    let saved = ht::tests::Policy::install();
    reg::db::set_domain(RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2482,
            max_bandwidth_mhz: 20,
            max_power_dbm: 20,
            flags: RegFlags::empty(),
        }],
    });
    saved
}
fn request(frequency: u16, active: bool) -> ScanRequest {
    ScanRequest {
        ssids: vec![SSID.to_vec()],
        frequencies_mhz: vec![u32::from(frequency)],
        channels: vec![u32::from((frequency - 2407) / 5)],
        active,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: Some(20),
        duration_mandatory: false,
        extra_ies: Vec::new(),
    }
}
fn join(owner: &Owner) -> Result<(), WirelessError> {
    let device = owner.device();
    let frequency = device.radio.try_lock().unwrap().frequency_mhz();
    station_tests::complete(device.scan(request(frequency, true)))?;
    station_tests::complete(device.associate(AssociateRequest {
        bssid: AP,
        ssid: SSID.to_vec(),
        frequency_mhz: u32::from(frequency),
        channel: u32::from((frequency - 2407) / 5),
        ie: Vec::new(),
        security: if owner.protected {
            SecurityConfig::Wpa2 { psk: PMK }
        } else {
            SecurityConfig::Open
        },
    }))?;
    // MLME/controlled-port completion does not release a qualified sender's
    // actual ADDBA publication/ACK/response credit. Settle those real native
    // receipts before a test claims DATA is available to wedge or retune.
    let mut radio = device.radio.try_lock().ok_or(WirelessError::Busy)?;
    for _ in 0..16 {
        radio.poll().map_err(wireless)?;
        if radio.ready() {
            return Ok(());
        }
    }
    Err(WirelessError::Busy)
}
fn smoke_ar9285_channels_full_reset_calibration_receipts_and_native_open_wpa2_ip() -> TestResult {
    let _policy = policy();
    for protected in [false, true] {
        for qualified in [false, true] {
            let owner = Owner::new(protected, qualified);
            for channel in [1, 6, 11, 13] {
                let old = owner.device();
                let frequency = 2407 + channel * 5;
                if station_tests::complete(old.set_config(WirelessConfig {
                    channel: u32::from(channel),
                    tx_power_dbm: None,
                }))
                .is_err()
                {
                    return TestResult::Fail("actual public channel transition refused");
                }
                let device = owner.device();
                if device.radio.try_lock().unwrap().frequency_mhz() != frequency
                    || join(&owner).is_err()
                {
                    return TestResult::Fail("new calibrated native channel Open/WPA2 join");
                }
                let peer = owner.peer();
                let plan = peer.lock().plan;
                let bytes = udp_ipv4(
                    AP,
                    plan.station,
                    plan.lease_ip,
                    plan.server_ip,
                    4701,
                    4702,
                    b"cold channel native IP",
                );
                {
                    let mut radio = device.radio.try_lock().unwrap();
                    if radio.send(&bytes).is_err() {
                        return TestResult::Fail("native DATA publication after retune");
                    }
                    for _ in 0..16 {
                        if radio.poll().is_err() {
                            return TestResult::Fail("native DATA receipt after retune");
                        }
                    }
                }
                if peer.lock().uplink.last() != Some(&bytes) {
                    return TestResult::Fail("real DMA/AP exact DATA after retune");
                }
                if !Arc::ptr_eq(&old, &device)
                    && (!old.closed.load(Ordering::Acquire)
                        || old.link_up()
                        || old.connected_bssid().is_some()
                        || old.radio.try_lock().unwrap().peer().is_some())
                {
                    return TestResult::Fail(
                        "retired key/link generation reopened after channel change",
                    );
                }
            }
            let device = owner.device();
            if !device.radio.try_lock().unwrap().retire() {
                return TestResult::Fail("final channel DMA proof");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/channels",
    smoke_ar9285_channels_full_reset_calibration_receipts_and_native_open_wpa2_ip
);
fn smoke_ar9285_multichannel_scan_uses_real_successors_and_restores_rf() -> TestResult {
    let _policy = policy();
    for active in [false, true] {
        let owner = Owner::new(true, true);
        let original = owner.device();
        let mut scan = request(2412, active);
        scan.frequencies_mhz = vec![2412, 2437, 2462];
        scan.channels = vec![1, 6, 11];
        let result = station_tests::complete(original.scan(scan));
        if !matches!(result, Ok(ref bss) if bss.len() == 3 && bss.iter().map(|b| b.frequency_mhz).collect::<Vec<_>>() == [2412, 2437, 2462])
            || !original.closed.load(Ordering::Acquire)
            || original.scan_information_elements(AP).is_none()
            || owner.device().radio.try_lock().unwrap().frequency_mhz() != 2412
            || owner.models.lock().len() != 4
        {
            return TestResult::Fail(
                "multichannel scan did not cold-retune/discover/restore actual RF",
            );
        }
        for model in owner.models.lock().iter().take(3) {
            if model.master.get() || model.released.borrow().is_empty() {
                return TestResult::Fail("scanned generation retained old DMA");
            }
        }
        if station_tests::complete(original.associate(AssociateRequest {
            bssid: AP,
            ssid: SSID.to_vec(),
            frequency_mhz: 2412,
            channel: 1,
            security: SecurityConfig::Wpa2 { psk: PMK },
            ie: Vec::new(),
        }))
        .is_ok()
        {
            return TestResult::Fail("retired scan cache authorized association");
        }
        if join(&owner).is_err() {
            return TestResult::Fail("restored generation could not rediscover/rejoin");
        }
        owner.device().radio.try_lock().unwrap().retire();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/channels",
    smoke_ar9285_multichannel_scan_uses_real_successors_and_restores_rf
);
fn smoke_ar9285_channel_retune_wedged_dma_and_bad_policy_do_not_prepare_successor() -> TestResult {
    let _policy = policy();
    for receive in [false, true] {
        let owner = Owner::new(true, true);
        if join(&owner).is_err() {
            return TestResult::Fail("channel retirement fixture join");
        }
        let old = owner.device();
        let model = owner.model();
        if receive {
            model.stuck_rx.set(true);
        } else {
            owner.peer().lock().hold_data = true;
            let plan = owner.peer().lock().plan;
            let bytes = udp_ipv4(
                AP,
                plan.station,
                plan.lease_ip,
                plan.server_ip,
                4701,
                4702,
                b"retune held DATA",
            );
            if old.radio.try_lock().unwrap().send(&bytes).is_err() {
                return TestResult::Fail("wedged TX fixture publication");
            }
            model.stuck_tx.set(true);
        }
        if station_tests::complete(old.set_config(WirelessConfig {
            channel: 6,
            tx_power_dbm: None,
        }))
        .is_ok()
            || owner.models.lock().len() != 1
            || !Arc::ptr_eq(&old, &owner.device())
            || !old.closed.load(Ordering::Acquire)
            || old.link_up()
        {
            return TestResult::Fail("wedged DMA retune created an unsafe successor");
        }
        model.stuck_rx.set(false);
        model.stuck_tx.set(false);
        old.radio.try_lock().unwrap().retire();
    }
    let owner = Owner::new(false, false);
    let original = owner.device();
    let mut domain = reg::db::get_domain().unwrap();
    domain.rules[0].freq_end_mhz = 2446; // channel6's upper occupied edge is2447.
    reg::db::set_domain(domain);
    if station_tests::complete(original.set_config(WirelessConfig {
        channel: 6,
        tx_power_dbm: None,
    }))
    .is_ok()
        || original.closed.load(Ordering::Acquire)
        || owner.models.lock().len() != 1
    {
        return TestResult::Fail("partial-span channel policy reached retirement/calibration");
    }
    original.radio.try_lock().unwrap().retire();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/channels",
    smoke_ar9285_channel_retune_wedged_dma_and_bad_policy_do_not_prepare_successor
);
fn smoke_ar9285_channel_v2_grants_bind_actual_calibration_and_all_occupied_rules() -> TestResult {
    let _policy = policy();
    let a = channel_receipt(2437, 40).unwrap();
    let b = channel_receipt(2462, 40).unwrap();
    let facts = |r: &calibration::tests::ChannelReceipt| {
        ht::Facts::new(
            ht::tests::model_device(),
            r.identity,
            r.prepared,
            r.report,
            &r.image,
        )
        .unwrap()
    };
    let fa = facts(&a);
    let fb = facts(&b);
    let bytes = ht::tests::record(&fa, 255);
    let cap = Cap::<FirmwareBlob, Read>::bootstrap();
    if (ht::Source::Verified {
        bytes: bytes.clone(),
        signer: Some([0x85; 32]),
        cap,
    })
    .load(fb)
    .is_ok()
    {
        return TestResult::Fail("different current channel/calibration accepted v2 record");
    }
    for at in [4, 54, 55, 57, 106] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        if (ht::Source::Verified {
            bytes: changed,
            signer: Some([0x85; 32]),
            cap,
        })
        .load(fa.clone())
        .is_ok()
        {
            return TestResult::Fail("v1/foreign-channel/width/GI/reserved record accepted");
        }
    }
    let grant = ht::Source::Verified {
        bytes,
        signer: Some([0x85; 32]),
        cap,
    }
    .load(fa)
    .unwrap();
    if grant.version() != 2
        || grant.channel() != 6
        || !grant.ba_identity().0.iter().any(|b| *b != 0)
    {
        return TestResult::Fail("v2 actual channel identity missing");
    }
    let mut domain = reg::db::get_domain().unwrap();
    domain.rules.push(RegRule {
        freq_start_mhz: 2446,
        freq_end_mhz: 2448,
        max_bandwidth_mhz: 20,
        max_power_dbm: 7,
        flags: RegFlags::empty(),
    });
    reg::db::set_domain(domain);
    if grant.check().is_ok() {
        return TestResult::Fail("edge-overlapping host limit ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/channels",
    smoke_ar9285_channel_v2_grants_bind_actual_calibration_and_all_occupied_rules
);

fn smoke_ar9285_cross_channel_association_rediscovery_and_stale_generation_rejection() -> TestResult
{
    let _policy = policy();
    for protected in [false, true] {
        let owner = Owner::new(protected, true);
        let original = owner.device();
        // The only original cache entry is channel1. Joining channel6 must
        // obtain a new calibration and an actual fresh Probe Response.
        if station_tests::complete(original.associate(AssociateRequest {
            bssid: AP,
            ssid: SSID.to_vec(),
            frequency_mhz: 2437,
            channel: 6,
            security: if protected {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        }))
        .is_err()
            || owner.models.lock().len() != 2
            || !owner.device().link_up()
            || owner
                .model()
                .transmitted
                .borrow()
                .first()
                .and_then(|frame| frame.first())
                != Some(&0x40)
        {
            return TestResult::Fail(
                "cross-channel join skipped fresh physical generation/discovery",
            );
        }
        if station_tests::complete(original.set_config(WirelessConfig {
            channel: 11,
            tx_power_dbm: None,
        }))
        .is_ok()
            || owner.models.lock().len() != 2
            || owner.device().radio.try_lock().unwrap().channel() != 6
        {
            return TestResult::Fail("stale public generation retuned its successor");
        }
        let current = owner.device();
        if station_tests::complete(current.scan(request(2462, true))).is_ok() || !current.link_up()
        {
            return TestResult::Fail(
                "associated multichannel scan lost current peer instead of rejecting",
            );
        }
        if !current.radio.try_lock().unwrap().retire() {
            return TestResult::Fail("cross-channel join final DMA proof");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/channels",
    smoke_ar9285_cross_channel_association_rediscovery_and_stale_generation_rejection
);

fn smoke_ar9285_all_admitted_channels_calibrate_source_geometry_and_power_before_dma() -> TestResult
{
    let _policy = policy();
    for channel in 1..=13u16 {
        let frequency = 2407 + 5 * channel;
        let receipt = channel_receipt(frequency, 40).unwrap();
        let powers =
            super::super::phy::rates::checked_plan_at(&receipt.image, frequency, 40).unwrap();
        let read = |register| receipt.registers.get(&register).copied().unwrap_or(0);
        if receipt.report.frequency_mhz != frequency
            || receipt.prepared.reference_frequency != frequency
            || read(0x9874) & 0x3fff_ffff != (0x3000_0000 | (u32::from(frequency) * 0x10000 / 15))
            || read(0x9804) & 0x7ff != 0x3c0
            || read(0x981c) & 1 != 1
            || read(8) & 4 != 0
            || read(0x840) & 0x3ff != 0
            || read(0x24) & 1 != 0
            || powers
                .registers
                .iter()
                .any(|(register, value)| read(*register) != *value)
        {
            return TestResult::Fail("per-channel analog receipt disagrees with actual source geometry/power or exposed DMA");
        }
        let facts = ht::Facts::new(
            ht::tests::model_device(),
            receipt.identity,
            receipt.prepared,
            receipt.report,
            &receipt.image,
        )
        .unwrap();
        let bytes = ht::tests::record(&facts, 255);
        if bytes[4] != if channel == 1 { 1 } else { 2 } || bytes[54] != channel as u8 {
            return TestResult::Fail("v1 reference or v2 exact channel record shape changed");
        }
    }
    for frequency in [0, 2411, 2413, 2473, 2484, 5180, u16::MAX] {
        if calibration::Permission::from_domain_at(&reg::db::get_domain().unwrap(), frequency)
            .is_ok()
        {
            return TestResult::Fail(
                "unadvertised channel14/off-grid/foreign band acquired permission",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/channels",
    smoke_ar9285_all_admitted_channels_calibrate_source_geometry_and_power_before_dma
);

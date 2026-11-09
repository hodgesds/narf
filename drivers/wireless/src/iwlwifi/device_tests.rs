//! Common Device::step regression over the actual RFH and native TX queues.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fixture {
    device: Option<Arc<Device>>,
    firmware: super::super::runtime::model::Firmware,
    producer: Producer<Frame, TX_RING_N>,
    policy_db: Arc<narf_wireless::reg::db::Database>,
}
impl Fixture {
    fn new(full: bool) -> Self {
        Self::new_inner(full, false)
    }
    /// The model device has no EHT PHY by default; tests for EHT-gated
    /// behavior build it with one. (`Arc::get_mut` cannot enable EHT
    /// after the fact: the device is built with `Arc::new_cyclic`, so
    /// its self-`Weak` always defeats `get_mut` — see #1863.)
    fn new_with_eht(full: bool) -> Self {
        Self::new_inner(full, true)
    }
    fn new_inner(full: bool, eht: bool) -> Self {
        let (mut hardware, firmware) = super::super::runtime::model::create(full);
        let source = hardware.source_fence().unwrap();
        let (producer, consumer) = narf_ipc::channel();
        let mut consumers = core::array::from_fn(|_| None);
        consumers[1] = Some(consumer);
        let policy_db = Arc::new(narf_wireless::reg::db::Database::new());
        policy_db.install(Connection::model_policy_domain());
        let policy = super::super::mld_policy::Source::database(policy_db.clone());
        let connection = Connection::open_model();
        let fence = policy.bind(connection.regulatory_program()).unwrap();
        hardware
            .install_rf_policy(super::super::mld_policy::Authority::Station(fence.clone()))
            .unwrap();
        let mut phy = super::super::ht_vht::Local::from_nvm(0, 1, 1);
        phy.eht = eht;
        let device = Arc::new_cyclic(|me| Device {
            test_name: None,
            me: me.clone(),
            radio_control: Arc::new(narf_wireless::ap_control::ExclusiveControl::new()),
            scan_generation: Arc::new(super::super::scheduled_epoch::Epoch::new()),
            mode: AtomicU32::new(2),
            mode_generation: AtomicU64::new(1),
            ap_capable: false,
            go_capable: false,
            ap_host: ap::Host::new(),
            p2p: p2p::Host::new(),
            state: Mutex::new(State {
                hardware,
                scan_uid: 0,
                scheduled: None,
                beacons: Vec::new(),
                scan_seen: Vec::new(),
                connection: Some(connection),
                ap: None,
                ap_probes: VecDeque::new(),
                needs_reset: false,
                stop_completed: false,
                producer: None,
                receive_ipc: None,
                receive_ap_data: None,
                eapol: VecDeque::new(),
                tx: consumers,
                pending: core::array::from_fn(|_| None),
                pending_next: core::array::from_fn(|_| None),
                tx_progress: false,
            }),
            control: Mutex::new(None),
            publication: AtomicBool::new(false),
            source,
            policy,
            policy_fence: IrqSafeSpinLock::new(Some(fence)),
            generation: Arc::new(AtomicU64::new(0)),
            quarantined: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            admission: IrqSafeSpinLock::new(()),
            mac: [2; 6],
            irq_vector: None,
            channels: alloc::vec![1],
            six_channels: Vec::new(),
            tx_chains: 1,
            rx_chains: 1,
            phy,
            firmware: Vec::new(),
            pnvm: None,
            up: AtomicBool::new(true),
            bssid: AtomicU64::new(0),
            mlo_report: IrqSafeSpinLock::new(None),
            rx: IrqSafeSpinLock::new(None),
            tx: core::array::from_fn(|_| IrqSafeSpinLock::new(None)),
        });
        Self {
            device: Some(device),
            firmware,
            producer,
            policy_db,
        }
    }
    fn enqueue(&mut self) {
        let mut bytes = alloc::vec![6; 16];
        bytes[6..12].copy_from_slice(&[2; 6]);
        bytes[12..].copy_from_slice(&[8, 0, 0x45, 9]);
        let buffer = super::super::runtime::dma_alloc(bytes.len()).unwrap();
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(&bytes);
        self.producer.try_send(frame).unwrap();
    }
    fn receive_data(&mut self) {
        // Independent FromDS Data MPDU, unencrypted with CRC/overrun OK.
        let mut mpdu = alloc::vec![0; 64+34];
        super::super::boot_context::put16(&mut mpdu, 0, 34);
        super::super::boot_context::put32(&mut mpdu, 12, 3);
        mpdu[42] = 1;
        mpdu[64..66].copy_from_slice(&[8, 2]);
        mpdu[68..74].copy_from_slice(&[2; 6]);
        mpdu[74..80].copy_from_slice(&[4; 6]);
        mpdu[80..86].copy_from_slice(&[6; 6]);
        mpdu[88..].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 0x45, 1]);
        self.firmware.inject(0xc1, 0, 0x8000, &mpdu);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let Some(device) = self.device.take() else {
            return;
        };
        *device.control.try_lock().unwrap() = None;
        let device = Arc::try_unwrap(device).expect("private fixture owner");
        let state = device.state.into_inner();
        // SAFETY: only model::create produced this unarmed hardware. No
        // future or device reference remains, and firmware storage is live
        // until this fixture finishes dropping.
        unsafe { super::super::runtime::model::destroy(state.hardware) };
    }
}

fn smoke_iwl_device_sync_credit_wait_drains_real_rfh_and_retries_original() -> TestResult {
    let mut fixture = Fixture::new(true);
    fixture.enqueue();
    fixture.receive_data();
    let device = fixture.device.as_ref().unwrap();
    let frames = device.step(None);
    if frames.len() != 1
        || frames[0][..6] != [2; 6]
        || frames[0][6..12] != [6; 6]
        || frames[0][12..] != [8, 0, 0x45, 1]
    {
        return TestResult::Fail("full native TX queue prevented actual RFH/802.11 RX delivery");
    }
    {
        let state = device.state.try_lock().unwrap();
        if state.pending[1].is_none() || state.connection.as_ref().unwrap().sequence_for_test() != 0
        {
            return TestResult::Fail("busy native queue lost original frame or advanced sequence");
        }
    }
    fixture.firmware.tx_complete(17, 1);
    if !device.step(None).is_empty() {
        return TestResult::Fail("TX completion became a network frame");
    }
    let state = device.state.try_lock().unwrap();
    if state.pending[1].is_some()
        || state.hardware.is_failed()
        || state.connection.as_ref().unwrap().sequence_for_test() != 1
    {
        return TestResult::Fail("sync drain failed to reclaim credit and submit pending original");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/progress",
    smoke_iwl_device_sync_credit_wait_drains_real_rfh_and_retries_original
);

fn smoke_iwl_device_disconnect_clears_pending_and_queued_native_tx() -> TestResult {
    let mut fixture = Fixture::new(true);
    fixture.enqueue();
    fixture.enqueue();
    let device = fixture.device.as_ref().unwrap();
    let _ = device.step(None);
    if device.state.try_lock().unwrap().pending[1].is_none() {
        return TestResult::Fail("disconnect fixture did not reach retained busy frame");
    }
    // Close the same admission flag used before disconnect/recovery. The
    // next common drain may retire completions, but cannot submit old data.
    device.up.store(false, Ordering::Release);
    fixture.firmware.tx_complete(17, 1);
    let _ = device.step(None);
    let mut state = device.state.try_lock().unwrap();
    if state.pending.iter().any(Option::is_some)
        || !matches!(state.tx[1].as_mut().unwrap().try_recv(), Ok(None))
        || state.connection.as_ref().unwrap().sequence_for_test() != 0
    {
        return TestResult::Fail("closed carrier retained or submitted prior-session packets");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/progress",
    smoke_iwl_device_disconnect_clears_pending_and_queued_native_tx
);

fn smoke_iwl_device_retained_eapol_waiter_drop_native_credit_and_receipt() -> TestResult {
    let mut fixture = Fixture::new(true);
    fixture.enqueue();
    let device = fixture.device.as_ref().unwrap();
    device.state.try_lock().unwrap().connection = Some(Connection::secure_model());
    // Independent WPA2 M1 wire fixture (the security suite also checks its
    // response against independent cryptographic vectors). The AP transmits
    // an ordinary unprotected EAPOL MPDU through the actual RFH parser.
    let m1: Vec<u8> = b"0203005f02008a0010000000000000000122222222222222222222222222222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        .chunks_exact(2).map(|p| {
            let nibble = |c| if c <= b'9' { c-b'0' } else { c-b'a'+10 };
            nibble(p[0])*16+nibble(p[1])
        }).collect();
    let mut mpdu = alloc::vec![0;64+24+8+m1.len()];
    super::super::boot_context::put16(&mut mpdu, 0, (24 + 8 + m1.len()) as u16);
    super::super::boot_context::put32(&mut mpdu, 12, 3);
    mpdu[42] = 1;
    mpdu[64..66].copy_from_slice(&[8, 2]);
    mpdu[68..74].copy_from_slice(&[2; 6]);
    mpdu[74..80].copy_from_slice(&[4; 6]);
    mpdu[80..86].copy_from_slice(&[4; 6]);
    mpdu[88..96].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    mpdu[96..].copy_from_slice(&m1);
    fixture.firmware.inject(0xc1, 0, 0x8000, &mpdu);
    let _ = device.step(None);
    {
        let mut waiter = core::pin::pin!(device.finish_control());
        if waiter
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("native EAPOL fixture did not suspend on full TX queue");
        }
    }
    if device.state.try_lock().is_some() || device.control.try_lock().unwrap().is_none() {
        return TestResult::Fail("dropping control waiter discarded the actual EAPOL owner");
    }
    fixture.firmware.tx_complete(17, 1);
    if !narf_scheduler::responsive_spin_until(
        || {
            let _ = device.step(None);
            fixture.firmware.tx_write() == super::super::tx_gen2::tx_doorbell(17, 128)
        },
        narf_time::Deadline::after_ms(100),
    ) {
        return TestResult::Fail("sync drain could not drive native EAPOL credit completion");
    }
    if device.state.try_lock().is_some() {
        return TestResult::Fail("ordinary TX gained ownership before the EAPOL terminal receipt");
    }
    fixture.firmware.tx_complete(17, 128);
    if !narf_scheduler::responsive_spin_until(
        || {
            let _ = device.step(None);
            device.state.try_lock().is_some_and(|state| {
                !state.needs_reset
                    && !state.hardware.is_failed()
                    && state.connection.as_ref().unwrap().sequence_for_test() == 2
            })
        },
        narf_time::Deadline::after_ms(100),
    ) {
        return TestResult::Fail("retained native EAPOL completion did not resume ordinary TX");
    }
    if fixture.firmware.tx_write() != super::super::tx_gen2::tx_doorbell(17, 129) {
        return TestResult::Fail("queued ordinary data overtook EAPOL or was submitted twice");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/progress",
    smoke_iwl_device_retained_eapol_waiter_drop_native_credit_and_receipt
);

fn smoke_iwl_publication_revocation_and_missing_authority_leave_endpoints_private() -> TestResult {
    use narf_capabilities::{Cap, Grant};
    for revoked in [false, true] {
        let fixture = Fixture::new(false);
        let device = fixture.device.as_ref().unwrap();
        let before = device.state.try_lock().unwrap().tx[1]
            .as_ref()
            .unwrap()
            .__ring_ptr_for_test();
        let authority = Cap::<narf_net::NetIface, Grant>::bootstrap();
        if revoked {
            authority.revoke();
        }
        let result = device.start_pumps_with_authority(revoked.then_some(&authority));
        if result.is_ok()
            || !device.publication.load(Ordering::Acquire)
            || device.rx.lock().is_some()
            || device.tx.iter().any(|tx| tx.lock().is_some())
            || device.state.try_lock().unwrap().producer.is_some()
            || device.state.try_lock().unwrap().tx[1]
                .as_ref()
                .unwrap()
                .__ring_ptr_for_test()
                != before
        {
            return TestResult::Fail(
                "failed network authority replaced/published private endpoints",
            );
        }
        if device
            .start_pumps_with_authority(Some(&Cap::bootstrap()))
            .is_ok()
        {
            return TestResult::Fail(
                "failed publication attempt was reusable without a fresh owner",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/progress",
    smoke_iwl_publication_revocation_and_missing_authority_leave_endpoints_private
);

fn smoke_iwl_duplicate_publication_rejected_before_endpoint_replacement() -> TestResult {
    let fixture = Fixture::new(false);
    let device = fixture.device.as_ref().unwrap();
    let before = device.state.try_lock().unwrap().tx[1]
        .as_ref()
        .unwrap()
        .__ring_ptr_for_test();
    device.publication.store(true, Ordering::Release);
    if device.start_pumps_with_authority(None) != Err("iwlwifi publication already attempted")
        || device.rx.lock().is_some()
        || device.tx.iter().any(|tx| tx.lock().is_some())
        || device.state.try_lock().unwrap().tx[1]
            .as_ref()
            .unwrap()
            .__ring_ptr_for_test()
            != before
    {
        return TestResult::Fail("duplicate publication replaced live ring endpoints");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/progress",
    smoke_iwl_duplicate_publication_rejected_before_endpoint_replacement
);

fn smoke_iwl_registry_revocation_after_staging_does_not_publish_endpoints() -> TestResult {
    use narf_capabilities::{Cap, Grant};
    let fixture = Fixture::new(false);
    let device = fixture.device.as_ref().unwrap();
    let authority = Cap::<narf_net::NetIface, Grant>::bootstrap();
    let mut called = false;
    let result = device.publish_with_registration(Some(&authority), |authority, interface| {
        called = true;
        // Revoke after the outer admission check, then exercise the actual
        // capability registry's failure path. No entry is inserted globally.
        authority.revoke();
        narf_net::registry()
            .register(authority, interface)
            .map_err(|_| "revoked during registry publication")
    });
    if result != Err("revoked during registry publication")
        || !called
        || device.rx.lock().is_some()
        || device.tx.iter().any(|tx| tx.lock().is_some())
        || device.state.try_lock().unwrap().producer.is_some()
    {
        return TestResult::Fail("registry failure committed staged endpoint ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/progress",
    smoke_iwl_registry_revocation_after_staging_does_not_publish_endpoints
);

fn smoke_iwl_device_current_policy_closes_queued_tx_copied_rx_and_retains_stop() -> TestResult {
    let mut fixture = Fixture::new(false);
    fixture.receive_data();
    let device = fixture.device.as_ref().unwrap().clone();
    let deliveries = device.step(None);
    if deliveries.len() != 1 {
        return TestResult::Fail("policy fixture lacks original RFH delivery");
    }
    // A same-country safe replacement remains valid after configuration.
    fixture.policy_db.install(Connection::model_policy_domain());
    if !device.link_up() {
        return TestResult::Fail("safe current policy replacement closed native link");
    }
    fixture.enqueue();
    let before = fixture.firmware.tx_write();
    let mut tight = Connection::model_policy_domain();
    tight.rules[0].max_power_dbm = 9;
    fixture.policy_db.install(tight);
    if device.link_up() {
        return TestResult::Fail("tightened policy retained carrier");
    }
    let mut callbacks = 0;
    device.dispatch_with(deliveries, |_| callbacks += 1);
    if callbacks != 0 {
        return TestResult::Fail("copied native RX crossed policy tightening");
    }
    for _ in 0..4 {
        let _ = device.step(None);
    }
    let state = device.state.try_lock().unwrap();
    if fixture.firmware.tx_write() != before
        || !state.needs_reset
        || !state.stop_completed
        || !state.hardware.is_failed()
        || state.pending.iter().any(Option::is_some)
        || super::super::runtime::model::retained(&state.hardware).1 != 1
    {
        return TestResult::Fail(
            "policy loss emitted queued TX or released native stop/DMA ownership",
        );
    }
    drop(state);
    drop(device);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/policy",
    smoke_iwl_device_current_policy_closes_queued_tx_copied_rx_and_retains_stop
);

fn smoke_iwl_device_mld_capa_advertises_negotiated_ttlm_and_link_reconf() -> TestResult {
    // The station MLD Capabilities and Operations field advertises
    // negotiated TTLM (SAME, #1553 verified) and link reconfiguration
    // (0x2000, wire layout verified #1553) and nothing else.
    // `supports_mlo` keys off `phy.eht`, so build the fixture device
    // with an EHT PHY.
    let fixture = Fixture::new_with_eht(false);
    let device = fixture.device.as_ref().unwrap();
    let caps = narf_wireless::WirelessNetIface::iftype_extended_capabilities(&**device);
    if caps.len() != 1 {
        return TestResult::Fail(
            "MLO device did not report exactly one station extended-capability record",
        );
    }
    let cap = &caps[0];
    if cap.iftype != 2
        || cap.mld_capa_and_ops
            != super::super::sc_ttlm_neg::MLD_CAP_OP_TTLM_NEG_SAME
                | super::super::sc_ttlm_neg::MLD_CAP_OP_LINK_RECONF_SUPPORT
        || cap.ext_mld_capa_and_ops != 0
    {
        return TestResult::Fail(
            "station MLD capabilities do not advertise TTLM negotiation and link reconfiguration",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_device_mld_capa_advertises_negotiated_ttlm_and_link_reconf
);

//! Common Device::step regression over the actual RFH and native TX queues.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fixture {
    device: Option<Arc<Device>>,
    firmware: super::super::runtime::model::Firmware,
    producer: Producer<Frame, TX_RING_N>,
}
impl Fixture {
    fn new(full: bool) -> Self {
        let (hardware, firmware) = super::super::runtime::model::create(full);
        let (producer, consumer) = narf_ipc::channel();
        let mut consumers = core::array::from_fn(|_| None);
        consumers[1] = Some(consumer);
        let device = Arc::new(Device {
            state: Mutex::new(State {
                hardware,
                scan_uid: 0,
                beacons: Vec::new(),
                connection: Some(Connection::open_model()),
                needs_reset: false,
                producer: None,
                eapol: VecDeque::new(),
                tx: consumers,
                pending: core::array::from_fn(|_| None),
                tx_progress: false,
            }),
            control: Mutex::new(None),
            mac: [2; 6],
            irq_vector: None,
            channels: alloc::vec![1],
            tx_chains: 1,
            phy: super::super::ht_vht::Local::from_nvm(0, 1, 1),
            firmware: Vec::new(),
            pnvm: None,
            up: AtomicBool::new(true),
            bssid: AtomicU64::new(0),
            rx: IrqSafeSpinLock::new(None),
            tx: core::array::from_fn(|_| IrqSafeSpinLock::new(None)),
        });
        Self {
            device: Some(device),
            firmware,
            producer,
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
